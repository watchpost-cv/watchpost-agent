package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	coreauth "github.com/gantry-tools/gantry-core/auth"
	"github.com/watchpost-cv/watchpost-agent/internal/state"
)

// ErrAuditPersistence reports that a security event could not be recorded
// durably. Callers must not hand out or revoke a session when it is returned.
var ErrAuditPersistence = errors.New("audit persistence failed")

const MinimumPasswordLength = 7

// passwordIterations is the PBKDF2-HMAC-SHA256 work factor used for local
// account password hashes, matching the central server's established KDF.
// Derived-key and work-factor bounds for verifyPassword. A stored hash must
// use the expected algorithm, an acceptable bounded work factor, and exactly
// the expected derived-key length; empty, truncated, oversized or excessively
// expensive encodings are rejected before PBKDF2 runs.
type contextKey struct{}

// Session carries the authenticated local account.
type Session struct {
	Token string
	CSRF  string
	User  Account
}

type Account struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Role  string `json:"role"`
}

type sessionRecord struct {
	CSRF    string
	Expires time.Time
	User    Account
}

type Manager struct {
	state    *state.Store
	model    *coreauth.Model
	mu       sync.Mutex
	sessions map[string]sessionRecord
	failures []time.Time
	// bootstrapTokenRequired gates first-administrator setup behind a
	// short-lived single-use token when agent management is remotely exposed.
	bootstrapTokenRequired bool
}

type accountPersistence struct{ state *state.Store }

func (p accountPersistence) LoadAccounts() (coreauth.AccountsFile, error) {
	return p.state.Snapshot().LocalAuth.Accounts, nil
}
func (p accountPersistence) LoadRoles() (coreauth.RolesFile, error) {
	return p.state.Snapshot().LocalAuth.Roles, nil
}
func (p accountPersistence) SaveAccounts(value coreauth.AccountsFile) error {
	return p.state.Update(func(current *state.State) error {
		current.LocalAuth.Accounts = value
		return nil
	})
}
func (p accountPersistence) SaveRoles(value coreauth.RolesFile) error {
	return p.state.Update(func(current *state.State) error {
		current.LocalAuth.Roles = value
		return nil
	})
}

func accountPolicy() coreauth.AccountPolicy {
	return coreauth.AccountPolicy{SchemaVersion: 1, ProductName: "Watchpost Agent", KnownCapability: func(key string) bool {
		return key == "agent.read" || key == "agent.manage"
	}}
}

func accountView(account coreauth.Account) Account {
	email := account.DisplayName
	for _, identity := range account.Identities {
		if identity.Email != "" {
			email = identity.Email
			break
		}
		if identity.Username != "" {
			email = identity.Username
		}
	}
	role := "viewer"
	for _, assigned := range account.Roles {
		switch assigned {
		case "administrator":
			return Account{ID: account.ID, Email: email, Role: "admin"}
		case "technician":
			role = "technician"
		}
	}
	return Account{ID: account.ID, Email: email, Role: role}
}

func New(store *state.Store) *Manager {
	model, err := coreauth.NewModel(accountPersistence{state: store}, accountPolicy())
	if err != nil {
		panic(err)
	}
	manager := &Manager{state: store, model: model, sessions: map[string]sessionRecord{}}
	current := store.Snapshot()
	accounts := map[string]Account{}
	for _, account := range model.Accounts() {
		accounts[account.ID] = accountView(account)
	}
	for _, session := range current.LocalAuth.Sessions {
		if user, ok := accounts[session.AccountID]; ok && model.SessionPrincipalActive(session.AccountID, session.IdentityID) && time.Now().Before(session.ExpiresAt) {
			manager.sessions[session.TokenHash] = sessionRecord{CSRF: session.CSRF, Expires: session.ExpiresAt, User: user}
		}
	}
	return manager
}

func (m *Manager) SetBootstrapTokenRequired(required bool) { m.bootstrapTokenRequired = required }
func (m *Manager) BootstrapTokenRequired() bool            { return m.bootstrapTokenRequired }

// StoreBootstrapToken persists only a hash of the setup token.
func (m *Manager) StoreBootstrapToken(raw string, expiresAt time.Time) error {
	if raw == "" {
		return errors.New("bootstrap token required")
	}
	return m.state.Update(func(current *state.State) error {
		current.LocalAuth.Bootstrap = state.BootstrapToken{Hash: tokenHash(raw), ExpiresAt: expiresAt.UTC()}
		return nil
	})
}

// GenerateBootstrapToken issues a fresh token and returns the raw value
// exactly once for printing.
func (m *Manager) GenerateBootstrapToken(lifetime time.Duration) (string, error) {
	raw, err := token(32)
	if err != nil {
		return "", err
	}
	if err := m.StoreBootstrapToken(raw, time.Now().Add(lifetime)); err != nil {
		return "", err
	}
	return raw, nil
}

func (m *Manager) SetupRequired() bool {
	_ = m.model.Reload()
	return m.model.Empty()
}

// NormalizeEmail canonicalises an account identity. Login and account creation
// compare normalized identities, so case differences cannot create duplicate
// accounts or resolve to the wrong one.
func NormalizeEmail(email string) string { return strings.ToLower(strings.TrimSpace(email)) }

func (m *Manager) Setup(username, email, password, setupToken string) error {
	username = strings.TrimSpace(username)
	if username == "" || !strings.Contains(email, "@") || len(password) < MinimumPasswordLength {
		return errors.New("valid username, email and password of at least 7 characters required")
	}
	email = NormalizeEmail(email)
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.model.Reload(); err != nil {
		return err
	}
	if m.bootstrapTokenRequired {
		bootstrap := m.state.Snapshot().LocalAuth.Bootstrap
		if bootstrap.Consumed || !time.Now().Before(bootstrap.ExpiresAt) || subtle.ConstantTimeCompare([]byte(tokenHash(setupToken)), []byte(bootstrap.Hash)) != 1 {
			return errors.New("bootstrap token required or invalid")
		}
	}
	if _, err := m.model.CreateInitialAdministrator(username, username, email, password); err != nil {
		return err
	}
	return m.state.Update(func(current *state.State) error {
		if m.bootstrapTokenRequired {
			current.LocalAuth.Bootstrap.Consumed = true
		}
		current.LocalAuth.AppendAudit(email, "setup", "first administrator created")
		return nil
	})
}

func (m *Manager) Login(email, password string) (Session, error) {
	email = NormalizeEmail(email)
	m.mu.Lock()
	cutoff := time.Now().Add(-5 * time.Minute)
	recent := m.failures[:0]
	for _, failure := range m.failures {
		if failure.After(cutoff) {
			recent = append(recent, failure)
		}
	}
	m.failures = recent
	blocked := len(m.failures) >= 5
	m.mu.Unlock()
	if blocked {
		return Session{}, errors.New("login temporarily throttled")
	}
	if err := m.model.Reload(); err != nil {
		return Session{}, err
	}
	account, identity, valid := m.model.AuthenticatePassword(email, password)
	if valid {
		sessionToken, err := token(32)
		if err != nil {
			return Session{}, err
		}
		csrf, err := token(24)
		if err != nil {
			return Session{}, err
		}
		user := accountView(account)
		expires := time.Now().Add(24 * time.Hour)
		hash := tokenHash(sessionToken)
		if err := m.state.Update(func(current *state.State) error {
			current.LocalAuth.AppendAudit(user.Email, "login", "login")
			current.LocalAuth.Sessions = append(current.LocalAuth.Sessions, state.AuthSession{TokenHash: hash, CSRF: csrf, ExpiresAt: expires, AccountID: account.ID, IdentityID: identity.ID})
			return nil
		}); err != nil {
			return Session{}, fmt.Errorf("%w: %v", ErrAuditPersistence, err)
		}
		m.mu.Lock()
		m.failures = nil
		m.sessions[hash] = sessionRecord{CSRF: csrf, Expires: expires, User: user}
		m.mu.Unlock()
		return Session{Token: sessionToken, CSRF: csrf, User: user}, nil
	}
	m.mu.Lock()
	m.failures = append(m.failures, time.Now())
	m.mu.Unlock()
	return Session{}, errors.New("invalid credentials")
}

func (m *Manager) Authenticate(token string) (Session, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	hash := tokenHash(token)
	record, ok := m.sessions[hash]
	if !ok || time.Now().After(record.Expires) {
		delete(m.sessions, hash)
		_ = m.removeStoredSessions(func(session state.AuthSession) bool { return session.TokenHash == hash })
		return Session{}, false
	}
	return Session{Token: token, CSRF: record.CSRF, User: record.User}, true
}

// Logout atomically records the audit event and removes the durable session.
func (m *Manager) Logout(token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	hash := tokenHash(token)
	record, ok := m.sessions[hash]
	if !ok {
		// Nothing to revoke; a stale token is an idempotent no-op.
		return nil
	}
	if err := m.state.Update(func(current *state.State) error {
		current.LocalAuth.AppendAudit(record.User.Email, "logout", "logout")
		current.LocalAuth.Sessions = filterSessions(current.LocalAuth.Sessions, func(session state.AuthSession) bool { return session.TokenHash == hash })
		return nil
	}); err != nil {
		return fmt.Errorf("%w: %v", ErrAuditPersistence, err)
	}
	delete(m.sessions, hash)
	return nil
}

func (m *Manager) ClearSessions() {
	m.mu.Lock()
	_ = m.state.Update(func(current *state.State) error {
		current.LocalAuth.Sessions = nil
		return nil
	})
	m.sessions = map[string]sessionRecord{}
	m.failures = nil
	m.mu.Unlock()
}

// RevokeUserSessions atomically records the audit event and removes every
// durable session for a local account.
//
// Lock ordering: the session lock is held while the audit state save runs
// (session → state). No code path takes the state lock and then the session
// lock, so this single-direction ordering cannot deadlock.
func (m *Manager) RevokeUserSessions(actor, accountID string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	targets := []string{}
	for token, record := range m.sessions {
		if record.User.ID == accountID {
			targets = append(targets, token)
		}
	}
	if err := m.state.Update(func(current *state.State) error {
		current.LocalAuth.AppendAudit(actor, "account_revoke_sessions", "account="+accountID)
		current.LocalAuth.Sessions = filterSessions(current.LocalAuth.Sessions, func(session state.AuthSession) bool { return session.AccountID == accountID })
		return nil
	}); err != nil {
		return 0, fmt.Errorf("%w: %v", ErrAuditPersistence, err)
	}
	for _, token := range targets {
		delete(m.sessions, token)
	}
	return len(targets), nil
}

// ChangePassword rotates an account's own password and revokes every other
// session for it, keeping the one identified by keepToken.
func (m *Manager) ChangePassword(accountID, currentPassword, newPassword, keepToken string) error {
	if len(newPassword) < MinimumPasswordLength {
		return errors.New("password must contain at least 7 characters")
	}
	keepHash := tokenHash(keepToken)
	account, found := m.model.Account(accountID)
	if !found {
		return errors.New("account not found")
	}
	var passwordIdentity coreauth.Identity
	for _, identity := range account.Identities {
		if identity.Type == "password" && identity.Enabled {
			passwordIdentity = identity
			break
		}
	}
	if passwordIdentity.ID == "" || !coreauth.VerifyPassword(passwordIdentity.PasswordHash, currentPassword) {
		return errors.New("current password incorrect")
	}
	if err := m.model.SetPassword(accountID, passwordIdentity.ID, newPassword); err != nil {
		return err
	}
	if err := m.state.Update(func(current *state.State) error {
		current.LocalAuth.AppendAudit(accountView(account).Email, "password_change", "password rotated")
		current.LocalAuth.Sessions = filterSessions(current.LocalAuth.Sessions, func(session state.AuthSession) bool {
			return session.AccountID == accountID && session.TokenHash != keepHash
		})
		return nil
	}); err != nil {
		return err
	}
	m.mu.Lock()
	for token, record := range m.sessions {
		if record.User.ID == accountID && token != keepHash {
			delete(m.sessions, token)
		}
	}
	m.mu.Unlock()
	return nil
}

// CreateAccount adds a technician or viewer account (administrator only).
// Identities are normalized and compared case-insensitively. The authenticated
// administrator's email is recorded as the actor in the same state save.
func (m *Manager) CreateAccount(actor, username, email, password, role string) (Account, error) {
	username = strings.TrimSpace(username)
	email = NormalizeEmail(email)
	if username == "" || email == "" || !strings.Contains(email, "@") || len(password) < MinimumPasswordLength || (role != "admin" && role != "technician" && role != "viewer") {
		return Account{}, errors.New("valid username, email, password of at least 7 characters, and role required")
	}
	roleID := role
	if role == "admin" {
		roleID = "administrator"
	}
	if err := m.model.Reload(); err != nil {
		return Account{}, err
	}
	created, err := m.model.CreateAccount(username, username, email, password, []string{roleID})
	if err != nil {
		return Account{}, err
	}
	if err := m.persistAudit(actor, "account_create", email+" role="+role); err != nil {
		return Account{}, err
	}
	return accountView(created), nil
}

func (m *Manager) ListAccounts() []Account {
	_ = m.model.Reload()
	items := []Account{}
	for _, account := range m.model.Accounts() {
		items = append(items, accountView(account))
	}
	return items
}

func (m *Manager) ListAudit() []state.AuditEntry {
	return m.state.Snapshot().LocalAuth.Audit
}

// persistAudit durably records a security event and propagates the
// persistence result. Security-sensitive callers must not ignore it; the
// error is wrapped so they can distinguish a storage failure.
func (m *Manager) persistAudit(actor, action, detail string) error {
	if err := m.state.Update(func(current *state.State) error {
		current.LocalAuth.AppendAudit(actor, action, detail)
		return nil
	}); err != nil {
		return fmt.Errorf("%w: %v", ErrAuditPersistence, err)
	}
	return nil
}

func filterSessions(sessions []state.AuthSession, remove func(state.AuthSession) bool) []state.AuthSession {
	kept := sessions[:0]
	for _, session := range sessions {
		if !remove(session) {
			kept = append(kept, session)
		}
	}
	return kept
}

func (m *Manager) removeStoredSessions(remove func(state.AuthSession) bool) error {
	return m.state.Update(func(current *state.State) error {
		current.LocalAuth.Sessions = filterSessions(current.LocalAuth.Sessions, remove)
		return nil
	})
}

func WithSession(ctx context.Context, session Session) context.Context {
	return context.WithValue(ctx, contextKey{}, session)
}

func FromContext(ctx context.Context) (Session, bool) {
	session, ok := ctx.Value(contextKey{}).(Session)
	return session, ok
}

// hashPassword derives a versioned PBKDF2-HMAC-SHA256 hash. The iteration
// count is embedded so future work-factor changes remain verifiable.
func hashPassword(password, salt string) (string, error) {
	return coreauth.HashPassword(password)
}

// verifyPassword checks a versioned hash. Legacy unversioned hashes from the
// previous custom iterated-SHA-256 construction cannot be verified and fail
// closed; those accounts require re-setup after upgrade. Malformed encodings,
// out-of-bound work factors and unexpected derived-key lengths are rejected
// before any PBKDF2 work is performed.
func verifyPassword(password, salt, encoded string) bool {
	return coreauth.VerifyPassword(encoded, password)
}

func token(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func Cookie(r *http.Request, session Session, secure bool) *http.Cookie {
	return &http.Cookie{Name: "watchpost_agent_session", Value: session.Token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil || secure, MaxAge: 86400}
}
