package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/watchpost-ops/watchpost-agent/internal/state"
)

const MinimumPasswordLength = 7

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
}

func New(store *state.Store) *Manager {
	return &Manager{state: store, sessions: map[string]sessionRecord{}}
}

func (m *Manager) SetupRequired() bool {
	return len(m.state.Snapshot().LocalAuth.Accounts) == 0
}

func (m *Manager) Setup(password string) error {
	if len(password) < MinimumPasswordLength {
		return errors.New("password must contain at least 7 characters")
	}
	return m.state.Update(func(current *state.State) error {
		if len(current.LocalAuth.Accounts) != 0 {
			return errors.New("local setup already completed")
		}
		salt, err := token(16)
		if err != nil {
			return err
		}
		id, err := token(8)
		if err != nil {
			return err
		}
		current.LocalAuth.Salt = salt
		current.LocalAuth.PasswordHash = passwordHash(password, salt)
		current.LocalAuth.Accounts = []state.Account{{ID: id, Email: "admin@local", Salt: salt, PasswordHash: current.LocalAuth.PasswordHash, Role: "admin", CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}}
		current.LocalAuth.AppendAudit("admin@local", "setup", "first administrator created")
		return nil
	})
}

func (m *Manager) Login(password string) (Session, error) {
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
		if subtle.ConstantTimeCompare([]byte(passwordHash(password, account.Salt)), []byte(account.PasswordHash)) == 1 {
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

// RevokeUserSessions removes every session for a local account.
func (m *Manager) RevokeUserSessions(accountID string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	removed := 0
	for token, record := range m.sessions {
		if record.User.ID == accountID {
			delete(m.sessions, token)
			removed++
		}
	}
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
			if subtle.ConstantTimeCompare([]byte(passwordHash(currentPassword, account.Salt)), []byte(account.PasswordHash)) != 1 {
				errOut = errors.New("current password incorrect")
				return errOut
			}
			salt, err := token(16)
			if err != nil {
				return err
			}
			current.LocalAuth.Accounts[index].Salt = salt
			current.LocalAuth.Accounts[index].PasswordHash = passwordHash(newPassword, salt)
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
func (m *Manager) CreateAccount(email, password, role string) (Account, error) {
	if email == "" || len(password) < MinimumPasswordLength || (role != "admin" && role != "technician" && role != "viewer") {
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
		current.LocalAuth.Accounts = append(current.LocalAuth.Accounts, state.Account{ID: id, Email: email, Salt: salt, PasswordHash: passwordHash(password, salt), Role: role, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)})
		created = Account{ID: id, Email: email, Role: role}
		current.LocalAuth.AppendAudit("admin", "account_create", email+" role="+role)
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

func passwordHash(password, salt string) string {
	value := []byte(salt + "\x00" + password)
	for i := 0; i < 210000; i++ {
		sum := sha256.Sum256(value)
		value = sum[:]
	}
	return hex.EncodeToString(value)
}

func token(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func tokenHash(token string) string { sum := sha256.Sum256([]byte(token)); return hex.EncodeToString(sum[:]) }

func Cookie(r *http.Request, session Session, secure bool) *http.Cookie {
	return &http.Cookie{Name: "watchpost_agent_session", Value: session.Token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil || secure, MaxAge: 86400}
}