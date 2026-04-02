package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Logger struct {
	enabled bool
	path    string
	mu      sync.Mutex
}

type Event struct {
	Timestamp          time.Time      `json:"timestamp"`
	Command            string         `json:"command"`
	Status             string         `json:"status"`
	DurationMillis     int64          `json:"duration_ms"`
	SensitiveOperation bool           `json:"sensitive_operation"`
	Params             map[string]any `json:"params,omitempty"`
	ParamsHash         string         `json:"params_hash,omitempty"`
	Error              string         `json:"error,omitempty"`
}

func New(path string, enabled bool) *Logger {
	return &Logger{
		enabled: enabled,
		path:    strings.TrimSpace(path),
	}
}

func (l *Logger) Enabled() bool {
	return l.enabled
}

func (l *Logger) Record(event Event) error {
	if !l.enabled {
		return nil
	}
	if strings.TrimSpace(l.path) == "" {
		return fmt.Errorf("audit log path is empty")
	}

	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	event.Command = strings.TrimSpace(event.Command)
	if event.Command == "" {
		return fmt.Errorf("audit command is required")
	}
	if event.Status == "" {
		event.Status = "success"
	}
	if len(event.Params) > 0 && event.ParamsHash == "" {
		event.ParamsHash = HashParams(event.Params)
	}

	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal audit event: %w", err)
	}
	payload = append(payload, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(l.path), 0o755); err != nil {
		return fmt.Errorf("create audit log directory: %w", err)
	}

	file, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open audit log file %q: %w", l.path, err)
	}
	defer file.Close()

	if _, err := file.Write(payload); err != nil {
		return fmt.Errorf("append audit event: %w", err)
	}
	return nil
}

func HashParams(params map[string]any) string {
	if len(params) == 0 {
		return ""
	}
	canonical := canonicalizeMap(params)
	payload, err := json.Marshal(canonical)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func canonicalizeMap(input map[string]any) map[string]any {
	keys := make([]string, 0, len(input))
	for key := range input {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	out := make(map[string]any, len(input))
	for _, key := range keys {
		value := input[key]
		switch typed := value.(type) {
		case map[string]any:
			out[key] = canonicalizeMap(typed)
		default:
			out[key] = value
		}
	}
	return out
}
