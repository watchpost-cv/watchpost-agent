package state

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const Version = 1

type Connection struct {
	WatchpostURL       string `json:"watchpost_url,omitempty"`
	PostID             string `json:"post_id,omitempty"`
	Credential         string `json:"credential,omitempty"`
	PreviousCredential string `json:"previous_credential,omitempty"`
	RevocationPending  bool   `json:"revocation_pending,omitempty"`
}

type PendingPairing struct {
	WatchpostURL  string    `json:"watchpost_url,omitempty"`
	RequestID     string    `json:"request_id,omitempty"`
	RequestSecret string    `json:"request_secret,omitempty"`
	Phrase        string    `json:"phrase,omitempty"`
	ExpiresAt     time.Time `json:"expires_at,omitempty"`
}

type LocalAuth struct {
	Salt         string         `json:"salt,omitempty"`
	PasswordHash string         `json:"password_hash,omitempty"`
	Accounts     []Account      `json:"accounts,omitempty"`
	Audit        []AuditEntry   `json:"audit,omitempty"`
	Bootstrap    BootstrapToken `json:"bootstrap_token,omitempty"`
	Sessions     []AuthSession   `json:"sessions,omitempty"`
}

// AuthSession stores only a hash of the browser token. Sessions survive
// service restarts without writing bearer credentials to disk.
type AuthSession struct {
	TokenHash string    `json:"token_hash"`
	CSRF      string    `json:"csrf"`
	ExpiresAt time.Time `json:"expires_at"`
	UserID    string    `json:"user_id"`
}

// BootstrapToken gates first-administrator setup when agent management is
// remotely exposed. Only a hash is stored; the raw value is printed once at
// startup or supplied through a protected file.
type BootstrapToken struct {
	Hash      string    `json:"hash,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	Consumed  bool      `json:"consumed,omitempty"`
}

// Account is a local administrator/technician/viewer account. Only the first
// administrator is created by setup; the administrator manages the rest.
type Account struct {
	ID           string `json:"id"`
	Email        string `json:"email"`
	Salt         string `json:"salt"`
	PasswordHash string `json:"password_hash"`
	Role         string `json:"role"`
	CreatedAt    string `json:"created_at"`
}

// AuditEntry records an attributed local state change. The list is bounded to
// the most recent entries so it can never exhaust disk.
type AuditEntry struct {
	At     string `json:"at"`
	Actor  string `json:"actor"`
	Action string `json:"action"`
	Detail string `json:"detail"`
}

const MaxAuditEntries = 200

// AppendAudit records an attributed local operation, keeping the newest
// MaxAuditEntries.
func (a *LocalAuth) AppendAudit(actor, action, detail string) {
	a.Audit = append(a.Audit, AuditEntry{At: time.Now().UTC().Format(time.RFC3339Nano), Actor: actor, Action: action, Detail: detail})
	if len(a.Audit) > MaxAuditEntries {
		a.Audit = a.Audit[len(a.Audit)-MaxAuditEntries:]
	}
}

type CollectorConfig struct {
	IntervalSeconds int      `json:"interval_seconds"`
	CPU             bool     `json:"cpu"`
	Memory          bool     `json:"memory"`
	Load            bool     `json:"load"`
	Uptime          bool     `json:"uptime"`
	Filesystems     []string `json:"filesystems"`
}

type DeliveryState struct {
	Queue               []json.RawMessage `json:"queue"`
	ConsecutiveFailures int               `json:"consecutive_failures"`
	NextRetryAt         time.Time         `json:"next_retry_at,omitempty"`
	LastSuccessAt       time.Time         `json:"last_success_at,omitempty"`
	LastError           string            `json:"last_error,omitempty"`
	DroppedCollections  uint64            `json:"dropped_collections"`
}

func DefaultCollectorConfig() CollectorConfig {
	return CollectorConfig{IntervalSeconds: 60, CPU: true, Memory: true, Load: true, Uptime: true, Filesystems: []string{"/"}}
}
func (c CollectorConfig) Validate() error {
	if c.IntervalSeconds < 15 || c.IntervalSeconds > 3600 {
		return errors.New("interval must be between 15 and 3600 seconds")
	}
	if !c.CPU && !c.Memory && !c.Load && !c.Uptime && len(c.Filesystems) == 0 {
		return errors.New("at least one collector must be enabled")
	}
	if len(c.Filesystems) > 8 {
		return errors.New("at most eight filesystems may be monitored")
	}
	seen := map[string]bool{}
	for _, path := range c.Filesystems {
		if !filepath.IsAbs(path) || len(path) > 255 || seen[path] {
			return errors.New("filesystem paths must be unique absolute paths")
		}
		seen[path] = true
	}
	return nil
}

type State struct {
	Version        int             `json:"version"`
	InstallationID string          `json:"installation_id"`
	CreatedAt      time.Time       `json:"created_at"`
	Connection     Connection      `json:"connection"`
	PendingPairing PendingPairing  `json:"pending_pairing"`
	NextSequence   int64           `json:"next_sequence"`
	Collectors     CollectorConfig `json:"collectors"`
	Delivery       DeliveryState   `json:"delivery"`
	LocalAuth      LocalAuth       `json:"local_auth"`
}

type Store struct {
	path string
	mu   sync.RWMutex
	data State
}

func Open(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("state path required")
	}
	s := &Store{path: path}
	data, err := os.ReadFile(path)
	if err == nil {
		if json.Unmarshal(data, &s.data) != nil || s.data.Version != Version || s.data.InstallationID == "" {
			return nil, errors.New("invalid agent state")
		}
		// Migrate the legacy single-admin form into the account list.
		if s.data.LocalAuth.PasswordHash != "" && len(s.data.LocalAuth.Accounts) == 0 {
			s.data.LocalAuth.Accounts = []Account{{ID: "admin", Email: "admin@local", Salt: s.data.LocalAuth.Salt, PasswordHash: s.data.LocalAuth.PasswordHash, Role: "admin", CreatedAt: s.data.CreatedAt.Format(time.RFC3339Nano)}}
			if err = s.saveLocked(); err != nil {
				return nil, err
			}
		}
		if s.data.Collectors.IntervalSeconds == 0 {
			s.data.Collectors = DefaultCollectorConfig()
			if err = s.saveLocked(); err != nil {
				return nil, err
			}
		}
		return s, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	id, err := installationID()
	if err != nil {
		return nil, err
	}
	s.data = State{Version: Version, InstallationID: id, CreatedAt: time.Now().UTC(), Collectors: DefaultCollectorConfig()}
	if err = s.saveLocked(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Snapshot() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data
}

func (s *Store) Update(update func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.cloneData()
	if err := update(&next); err != nil {
		return err
	}
	if err := s.saveState(next); err != nil {
		return err
	}
	s.data = next
	return nil
}

// cloneData returns a deep copy of the mutable slice-backed fields so an update
// callback can never mutate slice storage the store still owns. A failed save
// therefore leaves both the in-memory snapshot and the on-disk file unchanged.
func (s *Store) cloneData() State {
	src := s.data
	next := src
	next.LocalAuth.Accounts = append([]Account(nil), src.LocalAuth.Accounts...)
	next.LocalAuth.Audit = append([]AuditEntry(nil), src.LocalAuth.Audit...)
	next.LocalAuth.Sessions = append([]AuthSession(nil), src.LocalAuth.Sessions...)
	next.Delivery.Queue = make([]json.RawMessage, len(src.Delivery.Queue))
	for index, item := range src.Delivery.Queue {
		copy := append([]byte(nil), item...)
		next.Delivery.Queue[index] = json.RawMessage(copy)
	}
	next.Collectors.Filesystems = append([]string(nil), src.Collectors.Filesystems...)
	return next
}

func (s *Store) Unpair() error {
	return s.Update(func(value *State) error {
		value.Connection = Connection{}
		value.PendingPairing = PendingPairing{}
		value.NextSequence = 1
		value.Delivery = DeliveryState{}
		return nil
	})
}
func (s *Store) Reset(confirm string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if confirm != s.data.InstallationID {
		return errors.New("installation ID confirmation does not match")
	}
	next := State{Version: Version, InstallationID: s.data.InstallationID, CreatedAt: s.data.CreatedAt, Collectors: DefaultCollectorConfig(), NextSequence: 1}
	if err := s.saveState(next); err != nil {
		return err
	}
	s.data = next
	return nil
}

func (s *Store) saveState(value State) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(s.path), ".agent-state-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err = temporary.Chmod(0600); err == nil {
		_, err = temporary.Write(append(data, '\n'))
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, s.path)
}

func (s *Store) saveLocked() error { return s.saveState(s.data) }

func installationID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(value)
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:], nil
}
