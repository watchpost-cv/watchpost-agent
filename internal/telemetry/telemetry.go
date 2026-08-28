package telemetry

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/watchpost-ops/watchpost-agent/internal/state"
)

type Sample struct {
	Sequence   int64             `json:"sequence"`
	ObservedAt time.Time         `json:"observed_at"`
	Signal     string            `json:"signal"`
	Value      *float64          `json:"value"`
	Unit       string            `json:"unit"`
	Quality    string            `json:"quality"`
	Labels     map[string]string `json:"labels"`
}
type Batch struct {
	Version     int       `json:"version"`
	PostID      string    `json:"post_id"`
	CollectorID string    `json:"collector_id"`
	BatchID     string    `json:"batch_id"`
	SentAt      time.Time `json:"sent_at"`
	Samples     []Sample  `json:"samples"`
}

func Send(ctx context.Context, store *state.Store) error {
	current := store.Snapshot()
	if current.Connection.Credential == "" {
		return errors.New("agent is not paired")
	}
	if !current.Delivery.NextRetryAt.IsZero() && time.Now().UTC().Before(current.Delivery.NextRetryAt) {
		return nil
	}
	if err := enqueue(store, current); err != nil {
		return err
	}
	return flush(ctx, store)
}

func enqueue(store *state.Store, current state.State) error {
	if len(current.Delivery.Queue) >= 256 {
		_ = store.Update(func(value *state.State) error {
			value.Delivery.DroppedCollections++
			value.Delivery.LastError = "delivery queue full; collection skipped"
			return nil
		})
		return errors.New("delivery queue full")
	}
	now := time.Now().UTC()
	values, err := snapshot(current.Collectors)
	if err != nil {
		return err
	}
	sequence := current.NextSequence
	if sequence < 1 {
		sequence = 1
	}
	samples := make([]Sample, 0, len(values))
	for _, value := range values {
		copy := value.value
		samples = append(samples, Sample{Sequence: sequence, ObservedAt: now, Signal: value.signal, Value: &copy, Unit: value.unit, Quality: "good", Labels: value.labels})
		sequence++
	}
	batch := Batch{Version: 1, PostID: current.Connection.PostID, CollectorID: current.InstallationID, BatchID: fmt.Sprintf("agent-%d", now.UnixNano()), SentAt: now, Samples: samples}
	body, err := json.Marshal(batch)
	if err != nil {
		return err
	}
	return store.Update(func(value *state.State) error {
		size := len(body)
		for _, queued := range value.Delivery.Queue {
			size += len(queued)
		}
		if size > 8<<20 {
			value.Delivery.DroppedCollections++
			value.Delivery.LastError = "delivery queue byte limit reached; collection skipped"
			return errors.New("delivery queue byte limit reached")
		}
		value.Delivery.Queue = append(value.Delivery.Queue, json.RawMessage(body))
		value.NextSequence = sequence
		return nil
	})
}

func flush(ctx context.Context, store *state.Store) error {
	for {
		current := store.Snapshot()
		if len(current.Delivery.Queue) == 0 {
			return nil
		}
		var batch Batch
		if err := json.Unmarshal(current.Delivery.Queue[0], &batch); err != nil {
			return err
		}
		body := current.Delivery.Queue[0]
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(current.Connection.WatchpostURL, "/")+"/api/collector/v1/observations", bytes.NewReader(body))
		if err != nil {
			return err
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer "+current.Connection.Credential)
		response, err := (&http.Client{Timeout: 10 * time.Second}).Do(request)
		if err != nil {
			markFailure(store, err)
			return err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusAccepted {
			err = fmt.Errorf("telemetry rejected (%d)", response.StatusCode)
			markFailure(store, err)
			return err
		}
		if err = store.Update(func(value *state.State) error {
			if len(value.Delivery.Queue) > 0 {
				value.Delivery.Queue = value.Delivery.Queue[1:]
			}
			value.Delivery.ConsecutiveFailures = 0
			value.Delivery.NextRetryAt = time.Time{}
			value.Delivery.LastError = ""
			value.Delivery.LastSuccessAt = time.Now().UTC()
			return nil
		}); err != nil {
			return err
		}
	}
}

func markFailure(store *state.Store, cause error) {
	_ = store.Update(func(value *state.State) error {
		value.Delivery.ConsecutiveFailures++
		shift := value.Delivery.ConsecutiveFailures - 1
		if shift > 8 {
			shift = 8
		}
		delay := time.Duration(1<<shift) * time.Second
		if delay > 5*time.Minute {
			delay = 5 * time.Minute
		}
		value.Delivery.NextRetryAt = time.Now().UTC().Add(delay)
		value.Delivery.LastError = cause.Error()
		return nil
	})
}

type metric struct {
	signal, unit string
	value        float64
	labels       map[string]string
}

func snapshot(config state.CollectorConfig) ([]metric, error) {
	if config.IntervalSeconds == 0 {
		config = state.DefaultCollectorConfig()
	}
	result := []metric{}
	if config.CPU {
		value, err := cpuPercent()
		if err != nil {
			return nil, err
		}
		result = append(result, metric{"cpu.percent", "percent", value, map[string]string{}})
	}
	if config.Memory {
		value, err := memoryPercent()
		if err != nil {
			return nil, err
		}
		result = append(result, metric{"memory.percent", "percent", value, map[string]string{}})
	}
	if config.Load {
		data, err := os.ReadFile("/proc/loadavg")
		if err != nil {
			return nil, err
		}
		value, _ := strconv.ParseFloat(strings.Fields(string(data))[0], 64)
		result = append(result, metric{"load.one", "load", value, map[string]string{}})
	}
	if config.Uptime {
		data, err := os.ReadFile("/proc/uptime")
		if err != nil {
			return nil, err
		}
		value, _ := strconv.ParseFloat(strings.Fields(string(data))[0], 64)
		result = append(result, metric{"uptime.seconds", "seconds", value, map[string]string{}})
	}
	for _, path := range config.Filesystems {
		var disk syscall.Statfs_t
		if err := syscall.Statfs(path, &disk); err != nil {
			return nil, fmt.Errorf("filesystem %s: %w", path, err)
		}
		value := 0.0
		if disk.Blocks > 0 {
			value = 100 * float64(disk.Blocks-disk.Bfree) / float64(disk.Blocks)
		}
		signal := "filesystem.percent"
		if path == "/" {
			signal = "disk.percent"
		}
		result = append(result, metric{signal, "percent", value, map[string]string{"path": path}})
	}
	return result, nil
}
func cpuPercent() (float64, error) {
	idle1, total1, err := cpuTimes()
	if err != nil {
		return 0, err
	}
	time.Sleep(100 * time.Millisecond)
	idle2, total2, err := cpuTimes()
	if err != nil {
		return 0, err
	}
	delta := total2 - total1
	if delta == 0 {
		return 0, nil
	}
	return 100 * (1 - float64(idle2-idle1)/float64(delta)), nil
}
func cpuTimes() (uint64, uint64, error) {
	file, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		return 0, 0, errors.New("cpu telemetry unavailable")
	}
	fields := strings.Fields(scanner.Text())
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, 0, errors.New("invalid cpu telemetry")
	}
	var total, idle uint64
	for index, text := range fields[1:] {
		value, parseErr := strconv.ParseUint(text, 10, 64)
		if parseErr != nil {
			return 0, 0, parseErr
		}
		total += value
		if index == 3 || index == 4 {
			idle += value
		}
	}
	return idle, total, nil
}
func memoryPercent() (float64, error) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	values := map[string]float64{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 {
			values[strings.TrimSuffix(fields[0], ":")], _ = strconv.ParseFloat(fields[1], 64)
		}
	}
	total := values["MemTotal"]
	if total <= 0 {
		return 0, errors.New("invalid memory telemetry")
	}
	available := values["MemAvailable"]
	return 100 * (total - available) / total, nil
}
