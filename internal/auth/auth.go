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

type Session struct {
	Token string
	CSRF  string
}

type Manager struct {
	state    *state.Store
	mu       sync.Mutex
	sessions map[string]sessionRecord
	failures []time.Time
}

type sessionRecord struct {
	CSRF    string
	Expires time.Time
}

func New(store *state.Store) *Manager {
	return &Manager{state: store, sessions: map[string]sessionRecord{}}
}

func (m *Manager) SetupRequired() bool {
	return m.state.Snapshot().LocalAuth.PasswordHash == ""
}

func (m *Manager) Setup(password string) error {
	if len(password) < MinimumPasswordLength {
		return errors.New("password must contain at least 7 characters")
	}
	return m.state.Update(func(current *state.State) error {
		if current.LocalAuth.PasswordHash != "" {
			return errors.New("local setup already completed")
		}
		salt, err := token(16)
		if err != nil {
			return err
		}
		current.LocalAuth = state.LocalAuth{Salt: salt, PasswordHash: passwordHash(password, salt)}
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
	if configured.PasswordHash == "" || subtle.ConstantTimeCompare([]byte(passwordHash(password, configured.Salt)), []byte(configured.PasswordHash)) != 1 {
		m.mu.Lock()
		m.failures = append(m.failures, time.Now())
		m.mu.Unlock()
		return Session{}, errors.New("invalid credentials")
	}
	sessionToken, err := token(32)
	if err != nil {
		return Session{}, err
	}
	csrf, err := token(24)
	if err != nil {
		return Session{}, err
	}
	m.mu.Lock()
	m.failures = nil
	m.sessions[sessionToken] = sessionRecord{CSRF: csrf, Expires: time.Now().Add(24 * time.Hour)}
	m.mu.Unlock()
	return Session{Token: sessionToken, CSRF: csrf}, nil
}

func (m *Manager) Authenticate(token string) (Session, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	record, ok := m.sessions[token]
	if !ok || time.Now().After(record.Expires) {
		delete(m.sessions, token)
		return Session{}, false
	}
	return Session{Token: token, CSRF: record.CSRF}, true
}

func (m *Manager) Logout(token string) {
	m.mu.Lock()
	delete(m.sessions, token)
	m.mu.Unlock()
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

func Cookie(r *http.Request, session Session) *http.Cookie {
	return &http.Cookie{Name: "watchpost_agent_session", Value: session.Token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil, MaxAge: 86400}
}
