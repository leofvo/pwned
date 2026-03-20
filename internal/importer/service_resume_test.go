package importer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/leofvo/pwned/internal/config"
)

func TestInitializeManifestResume(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	ingestID := "20260320T120000Z-abcd1234"
	startedAt := time.Date(2026, time.March, 20, 12, 0, 0, 0, time.UTC)
	completedAt := startedAt.Add(5 * time.Minute)

	seed := Manifest{
		IngestID:          ingestID,
		Source:            "breach-a",
		Tag:               "initial",
		InputPath:         "/tmp/leaks/breach-a",
		Format:            "csv",
		MaxMemory:         "256MiB",
		StartedAt:         startedAt,
		CompletedAt:       completedAt,
		Status:            "failed",
		Files:             []ManifestFile{{RelativePath: "dump.csv", Status: "failed"}},
		RawStorage:        "s3",
		NormalizedStorage: "s3+local",
		Parser:            "streaming-v3",
		ParserVer:         "0.3.0",
		ErrorMessage:      "previous failure",
	}
	writeManifestFixture(t, filepath.Join(dir, ingestID+".json"), seed)

	svc := &Service{
		cfg: config.Config{
			ManifestLocalDir: dir,
		},
	}

	now := time.Date(2026, time.March, 20, 13, 0, 0, 0, time.UTC)
	got, err := svc.initializeManifest(Options{
		ResumeIngestID: ingestID,
		Tag:            "retry",
		Format:         "auto",
		MaxMemory:      "512MiB",
	}, now)
	if err != nil {
		t.Fatalf("initializeManifest() error = %v", err)
	}

	if got.IngestID != ingestID {
		t.Fatalf("IngestID = %q, want %q", got.IngestID, ingestID)
	}
	if got.Status != "running" {
		t.Fatalf("Status = %q, want running", got.Status)
	}
	if got.ErrorMessage != "" {
		t.Fatalf("ErrorMessage = %q, want empty", got.ErrorMessage)
	}
	if got.ResumedAt == nil || !got.ResumedAt.Equal(now) {
		t.Fatalf("ResumedAt = %v, want %v", got.ResumedAt, now)
	}
	if !got.CompletedAt.IsZero() {
		t.Fatalf("CompletedAt = %v, want zero time", got.CompletedAt)
	}
	if got.Tag != "retry" {
		t.Fatalf("Tag = %q, want retry", got.Tag)
	}
	if got.MaxMemory != "512MiB" {
		t.Fatalf("MaxMemory = %q, want 512MiB", got.MaxMemory)
	}
	if got.Source != "breach-a" {
		t.Fatalf("Source = %q, want breach-a", got.Source)
	}
	if got.InputPath != "/tmp/leaks/breach-a" {
		t.Fatalf("InputPath = %q, want /tmp/leaks/breach-a", got.InputPath)
	}
}

func TestInitializeManifestResumeSourceMismatch(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	ingestID := "20260320T120000Z-abcd1234"
	writeManifestFixture(t, filepath.Join(dir, ingestID+".json"), Manifest{
		IngestID:  ingestID,
		Source:    "breach-a",
		InputPath: "/tmp/leaks/breach-a",
		Format:    "csv",
		MaxMemory: "256MiB",
	})

	svc := &Service{
		cfg: config.Config{
			ManifestLocalDir: dir,
		},
	}

	_, err := svc.initializeManifest(Options{
		ResumeIngestID: ingestID,
		Source:         "breach-b",
	}, time.Now().UTC())
	if err == nil {
		t.Fatalf("initializeManifest() expected error, got nil")
	}
}

func writeManifestFixture(t *testing.T, path string, manifest Manifest) {
	t.Helper()

	payload, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal manifest fixture: %v", err)
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("write manifest fixture: %v", err)
	}
}
