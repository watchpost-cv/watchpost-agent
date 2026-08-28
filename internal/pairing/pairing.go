package pairing

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/watchpost-ops/watchpost-agent/internal/state"
	"github.com/watchpost-ops/watchpost-agent/internal/telemetry"
)

type Client struct {
	state   *state.Store
	version string
	http    *http.Client
}
type Status struct {
	State     string    `json:"state"`
	Phrase    string    `json:"phrase,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	PostID    string    `json:"post_id,omitempty"`
}

func New(store *state.Store, version string) *Client {
	return &Client{state: store, version: version, http: &http.Client{Timeout: 10 * time.Second}}
}

func (c *Client) Request(ctx context.Context, server string) (Status, error) {
	server = strings.TrimRight(server, "/")
	if err := safeURL(server); err != nil {
		return Status{}, err
	}
	secret, err := random(32)
	if err != nil {
		return Status{}, err
	}
	current := c.state.Snapshot()
	hostname, _ := os.Hostname()
	body, _ := json.Marshal(map[string]string{"installation_id": current.InstallationID, "request_secret": secret, "hostname": hostname, "platform": runtime.GOOS + "/" + runtime.GOARCH, "agent_version": c.version})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, server+"/api/agent/v2/pairing-requests", bytes.NewReader(body))
	if err != nil {
		return Status{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return Status{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		return Status{}, fmt.Errorf("Watchpost rejected pairing request (%d)", response.StatusCode)
	}
	var result struct {
		ID        string    `json:"id"`
		Phrase    string    `json:"phrase"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err = json.NewDecoder(response.Body).Decode(&result); err != nil {
		return Status{}, err
	}
	if result.ID == "" || result.Phrase == "" {
		return Status{}, errors.New("invalid pairing response")
	}
	err = c.state.Update(func(value *state.State) error {
		value.PendingPairing = state.PendingPairing{WatchpostURL: server, RequestID: result.ID, RequestSecret: secret, Phrase: result.Phrase, ExpiresAt: result.ExpiresAt}
		return nil
	})
	if err != nil {
		return Status{}, err
	}
	return Status{State: "pending", Phrase: result.Phrase, ExpiresAt: result.ExpiresAt}, nil
}

func (c *Client) Poll(ctx context.Context) (Status, error) {
	current := c.state.Snapshot()
	pending := current.PendingPairing
	if pending.RequestID == "" || pending.RequestSecret == "" {
		return Status{}, errors.New("no pairing request is pending")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, pending.WatchpostURL+"/api/agent/v2/pairing-requests/"+url.PathEscape(pending.RequestID), nil)
	if err != nil {
		return Status{}, err
	}
	request.Header.Set("Authorization", "Bearer "+pending.RequestSecret)
	response, err := c.http.Do(request)
	if err != nil {
		return Status{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Status{}, fmt.Errorf("Watchpost pairing status failed (%d)", response.StatusCode)
	}
	var result struct {
		State       string `json:"state"`
		PostID      string `json:"post_id"`
		CollectorID string `json:"collector_id"`
		Credential  string `json:"credential"`
	}
	if err = json.NewDecoder(response.Body).Decode(&result); err != nil {
		return Status{}, err
	}
	if result.State == "approved" {
		if result.PostID == "" || result.Credential == "" {
			return Status{}, errors.New("invalid pairing approval")
		}
		err = c.state.Update(func(value *state.State) error {
			value.Connection = state.Connection{WatchpostURL: pending.WatchpostURL, PostID: result.PostID, Credential: result.Credential}
			value.PendingPairing = state.PendingPairing{}
			value.NextSequence = 1
			return nil
		})
		if err != nil {
			return Status{}, err
		}
		if err = telemetry.Send(ctx, c.state); err != nil {
			return Status{}, fmt.Errorf("paired, but first telemetry failed: %w", err)
		}
	}
	return Status{State: result.State, Phrase: pending.Phrase, ExpiresAt: pending.ExpiresAt, PostID: result.PostID}, nil
}
func (c *Client) Rotate(ctx context.Context) error {
	current := c.state.Snapshot()
	if current.Connection.Credential == "" {
		return errors.New("agent is not paired")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, current.Connection.WatchpostURL+"/api/agent/v2/rotate", nil)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+current.Connection.Credential)
	request.Header.Set("X-Watchpost-Installation", current.InstallationID)
	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("Watchpost rejected credential rotation (%d)", response.StatusCode)
	}
	var result struct {
		Credential string `json:"credential"`
	}
	if err = json.NewDecoder(response.Body).Decode(&result); err != nil || result.Credential == "" {
		return errors.New("invalid rotation response")
	}
	return c.state.Update(func(value *state.State) error { value.Connection.Credential = result.Credential; return nil })
}

func safeURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" {
		return errors.New("valid Watchpost URL required")
	}
	host := parsed.Hostname()
	if parsed.Scheme == "https" {
		return nil
	}
	if parsed.Scheme == "http" && (host == "localhost" || net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()) {
		return nil
	}
	return errors.New("HTTPS is required except for a loopback Watchpost URL")
}
func random(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}
