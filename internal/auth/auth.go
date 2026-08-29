package auth

import (
	"context"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"hash"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/watchpost-ops/watchpost-agent/internal/state"
)

const MinimumPasswordLength = 7

// passwordIterations is the PBKDF2-HMAC-SHA256 work factor used for local
// account password hashes, matching the central server's established KDF.
const passwordIterations = 210000

// Derived-key and work-factor bounds for verifyPassword. A stored hash must
// use the expected algorithm, an acceptable bounded work factor, and exactly
// the expected derived-key length; empty, truncated, oversized or excessively
// expensive encodings are rejected before PBKDF2 runs.
const (
	minVerifyIterations = 10000
	maxVerifyIterations = 10000000
	keyLength           = 32
)

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
	mu       sync.Mutex
	sessions map[string]sessionRecord
	failures []time.Time
	// bootstrapTokenRequired gates first-administrator setup behind a
	// short-lived single-use token when agent management is remotely exposed.
	bootstrapTokenRequired bool
}

func New(store *state.Store) *Manager {
	return &Manager{state: store, sessions: map[string]sessionRecord{}}
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
	return len(m.state.Snapshot().LocalAuth.Accounts) == 0
}

// NormalizeEmail canonicalises an account identity. Login and account creation
// compare normalized identities, so case differences cannot create duplicate
// accounts or resolve to the wrong one.
func NormalizeEmail(email string) string { return strings.ToLower(strings.TrimSpace(email)) }

func (m *Manager) Setup(email, password, setupToken string) error {
	if !strings.Contains(email, "@") || len(password) < MinimumPasswordLength {
		return errors.New("valid email and password of at least 7 characters required")
	}
	email = NormalizeEmail(email)
	return m.state.Update(func(current *state.State) error {
		if len(current.LocalAuth.Accounts) != 0 {
			return errors.New("local setup already completed")
		}
		// Bootstrap-token consumption and first-admin creation are one atomic
		// state update: replaying a consumed or expired token fails closed.
		if m.bootstrapTokenRequired {
			bootstrap := current.LocalAuth.Bootstrap
			if bootstrap.Consumed || !time.Now().Before(bootstrap.ExpiresAt) || subtle.ConstantTimeCompare([]byte(tokenHash(setupToken)), []byte(bootstrap.Hash)) != 1 {
				return errors.New("bootstrap token required or invalid")
			}
			current.LocalAuth.Bootstrap.Consumed = true
		}
		salt, err := token(16)
		if err != nil {
			return err
		}
		id, err := token(8)
		if err != nil {
			return err
		}
		hash, err := hashPassword(password, salt)
		if err != nil {
			return err
		}
		current.LocalAuth.Salt = salt
		current.LocalAuth.PasswordHash = hash
		current.LocalAuth.Accounts = []state.Account{{ID: id, Email: email, Salt: salt, PasswordHash: hash, Role: "admin", CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}}
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
	configured := m.state.Snapshot().LocalAuth
	for _, account := range configured.Accounts {
		if account.Email != email {
			continue
		}
		if !verifyPassword(password, account.Salt, account.PasswordHash) {
			break
		}
		sessionToken, err := token(32)
		if err != nil {
			return Session{}, err
		}
		csrf, err := token(24)
		if err != nil {
			return Session{}, err
		}
		user := Account{ID: account.ID, Email: account.Email, Role: account.Role}
		m.mu.Lock()
		m.failures = nil
		m.sessions[sessionToken] = sessionRecord{CSRF: csrf, Expires: time.Now().Add(24 * time.Hour), User: user}
		m.mu.Unlock()
		m.recordAudit(account.Email, "login", "login")
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
	record, ok := m.sessions[token]
	if !ok || time.Now().After(record.Expires) {
		delete(m.sessions, token)
		return Session{}, false
	}
	return Session{Token: token, CSRF: record.CSRF, User: record.User}, true
}

func (m *Manager) Logout(token string) {
	m.mu.Lock()
	delete(m.sessions, token)
	m.mu.Unlock()
}

func (m *Manager) ClearSessions() {
	m.mu.Lock()
	m.sessions = map[string]sessionRecord{}
	m.failures = nil
	m.mu.Unlock()
}

// RevokeUserSessions removes every session for a local account and records the
// change in the same state save.
func (m *Manager) RevokeUserSessions(actor, accountID string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	removed := 0
	for token, record := range m.sessions {
		if record.User.ID == accountID {
			delete(m.sessions, token)
			removed++
		}
	}
	m.recordAudit(actor, "account_revoke_sessions", "account="+accountID)
	return removed
}

// ChangePassword rotates an account's own password and revokes every other
// session for it, keeping the one identified by keepToken.
func (m *Manager) ChangePassword(accountID, currentPassword, newPassword, keepToken string) error {
	if len(newPassword) < MinimumPasswordLength {
		return errors.New("password must contain at least 7 characters")
	}
	var errOut error
	m.state.Update(func(current *state.State) error {
		for index, account := range current.LocalAuth.Accounts {
			if account.ID != accountID {
				continue
			}
			if !verifyPassword(currentPassword, account.Salt, account.PasswordHash) {
				errOut = errors.New("current password incorrect")
				return errOut
			}
			salt, err := token(16)
			if err != nil {
				return err
			}
			hash, err := hashPassword(newPassword, salt)
			if err != nil {
				return err
			}
			current.LocalAuth.Accounts[index].Salt = salt
			current.LocalAuth.Accounts[index].PasswordHash = hash
			current.LocalAuth.AppendAudit(account.Email, "password_change", "password rotated")
			return nil
		}
		errOut = errors.New("account not found")
		return errOut
	})
	if errOut != nil {
		return errOut
	}
	m.mu.Lock()
	for token, record := range m.sessions {
		if record.User.ID == accountID && token != keepToken {
			delete(m.sessions, token)
		}
	}
	m.mu.Unlock()
	return nil
}

// CreateAccount adds a technician or viewer account (administrator only).
// Identities are normalized and compared case-insensitively. The authenticated
// administrator's email is recorded as the actor in the same state save.
func (m *Manager) CreateAccount(actor, email, password, role string) (Account, error) {
	email = NormalizeEmail(email)
	if email == "" || !strings.Contains(email, "@") || len(password) < MinimumPasswordLength || (role != "admin" && role != "technician" && role != "viewer") {
		return Account{}, errors.New("valid email, password of at least 7 characters, and role required")
	}
	var created Account
	err := m.state.Update(func(current *state.State) error {
		for _, account := range current.LocalAuth.Accounts {
			if account.Email == email {
				return errors.New("account already exists")
			}
		}
		salt, err := token(16)
		if err != nil {
			return err
		}
		id, err := token(8)
		if err != nil {
			return err
		}
		hash, err := hashPassword(password, salt)
		if err != nil {
			return err
		}
		current.LocalAuth.Accounts = append(current.LocalAuth.Accounts, state.Account{ID: id, Email: email, Salt: salt, PasswordHash: hash, Role: role, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)})
		created = Account{ID: id, Email: email, Role: role}
		current.LocalAuth.AppendAudit(actor, "account_create", email+" role="+role)
		return nil
	})
	return created, err
}

func (m *Manager) ListAccounts() []Account {
	current := m.state.Snapshot()
	items := []Account{}
	for _, account := range current.LocalAuth.Accounts {
		items = append(items, Account{ID: account.ID, Email: account.Email, Role: account.Role})
	}
	return items
}

func (m *Manager) ListAudit() []state.AuditEntry {
	return m.state.Snapshot().LocalAuth.Audit
}

func (m *Manager) recordAudit(actor, action, detail string) {
	_ = m.state.Update(func(current *state.State) error {
		current.LocalAuth.AppendAudit(actor, action, detail)
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
	key, err := pbkdf2.Key[hash.Hash](sha256.New, password, []byte(salt), passwordIterations, 32)
	if err != nil {
		return "", err
	}
	return "pbkdf2$" + strconv.Itoa(passwordIterations) + "$" + hex.EncodeToString(key), nil
}

// verifyPassword checks a versioned hash. Legacy unversioned hashes from the
// previous custom iterated-SHA-256 construction cannot be verified and fail
// closed; those accounts require re-setup after upgrade. Malformed encodings,
// out-of-bound work factors and unexpected derived-key lengths are rejected
// before any PBKDF2 work is performed.
func verifyPassword(password, salt, encoded string) bool {
	parts := strings.SplitN(encoded, "$", 3)
	if len(parts) != 3 || parts[0] != "pbkdf2" {
		return false
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations < minVerifyIterations || iterations > maxVerifyIterations {
		return false
	}
	expected, err := hex.DecodeString(parts[2])
	if err != nil || len(expected) != keyLength {
		return false
	}
	key, err := pbkdf2.Key[hash.Hash](sha256.New, password, []byte(salt), iterations, len(expected))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(key, expected) == 1
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
