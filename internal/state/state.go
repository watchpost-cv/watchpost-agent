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
}

type PendingPairing struct {
	WatchpostURL  string    `json:"watchpost_url,omitempty"`
	RequestID     string    `json:"request_id,omitempty"`
	RequestSecret string    `json:"request_secret,omitempty"`
	Phrase        string    `json:"phrase,omitempty"`
	ExpiresAt     time.Time `json:"expires_at,omitempty"`
}

type LocalAuth struct {
	Salt         string `json:"salt,omitempty"`
	PasswordHash string `json:"password_hash,omitempty"`
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
	next := s.data
	if err := update(&next); err != nil {
		return err
	}
	previous := s.data
	s.data = next
	if err := s.saveLocked(); err != nil {
		s.data = previous
		return err
	}
	return nil
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
	previous := s.data
	s.data = State{Version: Version, InstallationID: previous.InstallationID, CreatedAt: previous.CreatedAt, Collectors: DefaultCollectorConfig(), NextSequence: 1}
	if err := s.saveLocked(); err != nil {
		s.data = previous
		return err
	}
	return nil
}

func (s *Store) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s.data, "", "  ")
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
