package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRecordWritesJSONLine(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	logger := New(path, true)

	err := logger.Record(Event{
		Timestamp:          time.Date(2026, time.April, 2, 10, 0, 0, 0, time.UTC),
		Command:            "search",
		Status:             "success",
		DurationMillis:     42,
		SensitiveOperation: true,
		Params: map[string]any{
			"limit": 20,
			"match": "all",
		},
	})
	if err != nil {
		t.Fatalf("Record() error = %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 1 {
		t.Fatalf("log lines = %d, want 1", len(lines))
	}

	var event Event
	if err := json.Unmarshal([]byte(lines[0]), &event); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if event.Command != "search" {
		t.Fatalf("Command = %q, want search", event.Command)
	}
	if event.ParamsHash == "" {
		t.Fatalf("ParamsHash = empty, want non-empty")
	}
}

func TestRecordDisabledNoFileCreated(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	logger := New(path, false)

	if err := logger.Record(Event{Command: "search"}); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("Stat(%q) err = %v, want not exists", path, err)
	}
}

func TestHashParamsStableForDifferentMapOrders(t *testing.T) {
	t.Parallel()

	a := map[string]any{"z": 1, "a": "x"}
	b := map[string]any{"a": "x", "z": 1}

	if gotA, gotB := HashParams(a), HashParams(b); gotA != gotB {
		t.Fatalf("HashParams() mismatch: %q != %q", gotA, gotB)
	}
}
