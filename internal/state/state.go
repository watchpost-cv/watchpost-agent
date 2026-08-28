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
	WatchpostURL string `json:"watchpost_url,omitempty"`
	PostID       string `json:"post_id,omitempty"`
	Credential   string `json:"credential,omitempty"`
}

type PendingPairing struct {
	WatchpostURL string `json:"watchpost_url,omitempty"`
	RequestID string `json:"request_id,omitempty"`
	RequestSecret string `json:"request_secret,omitempty"`
	Phrase string `json:"phrase,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

type LocalAuth struct {
	Salt         string `json:"salt,omitempty"`
	PasswordHash string `json:"password_hash,omitempty"`
}

type State struct {
	Version        int        `json:"version"`
	InstallationID string     `json:"installation_id"`
	CreatedAt      time.Time  `json:"created_at"`
	Connection     Connection `json:"connection"`
	PendingPairing PendingPairing `json:"pending_pairing"`
	LocalAuth      LocalAuth  `json:"local_auth"`
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
		return s, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	id, err := installationID()
	if err != nil {
		return nil, err
	}
	s.data = State{Version: Version, InstallationID: id, CreatedAt: time.Now().UTC()}
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
