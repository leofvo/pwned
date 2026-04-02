package storagestats

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/leofvo/pwned/internal/config"
	"github.com/leofvo/pwned/internal/importer"
)

func TestStatsAggregatesBySourceAndMonth(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	manifestA := importer.Manifest{
		IngestID:  "ing-1",
		Source:    "source-a",
		StartedAt: time.Date(2026, time.January, 10, 12, 0, 0, 0, time.UTC),
		Files: []importer.ManifestFile{
			{
				RelativePath:     "a.csv",
				SizeBytes:        100,
				RecordsProcessed: 10,
				NormalizedChunks: []importer.ManifestChunk{{SizeBytes: 50}, {SizeBytes: 70}},
			},
		},
	}
	manifestB := importer.Manifest{
		IngestID:  "ing-2",
		Source:    "source-b",
		StartedAt: time.Date(2026, time.February, 2, 7, 0, 0, 0, time.UTC),
		Files: []importer.ManifestFile{
			{
				RelativePath:     "b.csv",
				SizeBytes:        200,
				RecordsProcessed: 20,
				NormalizedChunks: []importer.ManifestChunk{{SizeBytes: 80}},
			},
		},
	}

	sizeA := writeManifestFixture(t, dir, manifestA)
	sizeB := writeManifestFixture(t, dir, manifestB)

	svc := NewService(config.Config{ManifestLocalDir: dir}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	result, err := svc.Stats(context.Background(), Options{BySource: true, ByMonth: true})
	if err != nil {
		t.Fatalf("Stats() error = %v", err)
	}

	if result.Summary.Ingests != 2 {
		t.Fatalf("Summary.Ingests = %d, want 2", result.Summary.Ingests)
	}
	if result.Summary.Files != 2 {
		t.Fatalf("Summary.Files = %d, want 2", result.Summary.Files)
	}
	if result.Summary.Chunks != 3 {
		t.Fatalf("Summary.Chunks = %d, want 3", result.Summary.Chunks)
	}
	if result.Summary.Records != 30 {
		t.Fatalf("Summary.Records = %d, want 30", result.Summary.Records)
	}
	if result.Summary.RawBytes != 300 {
		t.Fatalf("Summary.RawBytes = %d, want 300", result.Summary.RawBytes)
	}
	if result.Summary.NormalizedBytes != 200 {
		t.Fatalf("Summary.NormalizedBytes = %d, want 200", result.Summary.NormalizedBytes)
	}
	if result.Summary.ManifestBytes != sizeA+sizeB {
		t.Fatalf("Summary.ManifestBytes = %d, want %d", result.Summary.ManifestBytes, sizeA+sizeB)
	}
	if result.Summary.TotalBytes != result.Summary.RawBytes+result.Summary.NormalizedBytes+result.Summary.ManifestBytes {
		t.Fatalf("Summary.TotalBytes = %d, formula mismatch", result.Summary.TotalBytes)
	}

	if len(result.BySource) != 2 {
		t.Fatalf("len(BySource) = %d, want 2", len(result.BySource))
	}
	if result.BySource[0].Key != "source-a" || result.BySource[0].Totals.RawBytes != 100 {
		t.Fatalf("BySource[0] = %+v, want source-a raw=100", result.BySource[0])
	}
	if result.BySource[1].Key != "source-b" || result.BySource[1].Totals.RawBytes != 200 {
		t.Fatalf("BySource[1] = %+v, want source-b raw=200", result.BySource[1])
	}

	if len(result.ByMonth) != 2 {
		t.Fatalf("len(ByMonth) = %d, want 2", len(result.ByMonth))
	}
	if result.ByMonth[0].Key != "2026-01" || result.ByMonth[0].Totals.Ingests != 1 {
		t.Fatalf("ByMonth[0] = %+v, want key=2026-01 ingests=1", result.ByMonth[0])
	}
	if result.ByMonth[1].Key != "2026-02" || result.ByMonth[1].Totals.Ingests != 1 {
		t.Fatalf("ByMonth[1] = %+v, want key=2026-02 ingests=1", result.ByMonth[1])
	}
}

func TestStatsSourceFilter(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeManifestFixture(t, dir, importer.Manifest{
		IngestID:  "ing-1",
		Source:    "a",
		StartedAt: time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
		Files:     []importer.ManifestFile{{SizeBytes: 11}},
	})
	writeManifestFixture(t, dir, importer.Manifest{
		IngestID:  "ing-2",
		Source:    "b",
		StartedAt: time.Date(2026, time.January, 2, 0, 0, 0, 0, time.UTC),
		Files:     []importer.ManifestFile{{SizeBytes: 22}},
	})

	svc := NewService(config.Config{ManifestLocalDir: dir}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	result, err := svc.Stats(context.Background(), Options{Source: "b"})
	if err != nil {
		t.Fatalf("Stats() error = %v", err)
	}
	if result.Summary.Ingests != 1 {
		t.Fatalf("Summary.Ingests = %d, want 1", result.Summary.Ingests)
	}
	if result.Summary.RawBytes != 22 {
		t.Fatalf("Summary.RawBytes = %d, want 22", result.Summary.RawBytes)
	}
}

func TestStatsNoMatchingManifests(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeManifestFixture(t, dir, importer.Manifest{
		IngestID:  "ing-1",
		Source:    "a",
		StartedAt: time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
		Files:     []importer.ManifestFile{{SizeBytes: 11}},
	})

	svc := NewService(config.Config{ManifestLocalDir: dir}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	_, err := svc.Stats(context.Background(), Options{Source: "z"})
	if err == nil || !strings.Contains(err.Error(), "no matching manifests found") {
		t.Fatalf("Stats() err = %v, want no matching manifests found", err)
	}
}

func writeManifestFixture(t *testing.T, dir string, manifest importer.Manifest) int64 {
	t.Helper()

	if manifest.IngestID == "" {
		t.Fatalf("manifest ingest id is required")
	}
	path := filepath.Join(dir, manifest.IngestID+".json")
	payload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", path, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%q) error = %v", path, err)
	}
	return info.Size()
}
