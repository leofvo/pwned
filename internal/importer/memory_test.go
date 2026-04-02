package importer

import (
	"testing"

	"github.com/leofvo/pwned/internal/config"
)

func TestParseByteSize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want int64
	}{
		{name: "bytes", raw: "1024", want: 1024},
		{name: "kib", raw: "1KiB", want: 1024},
		{name: "mib", raw: "256MiB", want: 256 * 1024 * 1024},
		{name: "mb", raw: "10MB", want: 10 * 1000 * 1000},
		{name: "decimal", raw: "1.5GiB", want: 1610612736},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseByteSize(tc.raw)
			if err != nil {
				t.Fatalf("parseByteSize(%q) error = %v", tc.raw, err)
			}
			if got != tc.want {
				t.Fatalf("parseByteSize(%q) = %d, want %d", tc.raw, got, tc.want)
			}
		})
	}
}

func TestParseByteSizeRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	invalid := []string{"", "0", "foo", "1XB"}
	for _, raw := range invalid {
		raw := raw
		t.Run(raw, func(t *testing.T) {
			t.Parallel()
			if _, err := parseByteSize(raw); err == nil {
				t.Fatalf("parseByteSize(%q) error = nil, want error", raw)
			}
		})
	}
}

func TestDeriveRuntimeLimitsRespectsBudget(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		ChunkMaxBytes:      8 * 1024 * 1024,
		ChunkMaxRecords:    50000,
		ParserMaxLineBytes: 16 * 1024 * 1024,
	}

	limits, err := deriveRuntimeLimits("12MiB", cfg)
	if err != nil {
		t.Fatalf("deriveRuntimeLimits() error = %v", err)
	}

	if limits.MaxMemoryBytes != 12*1024*1024 {
		t.Fatalf("MaxMemoryBytes = %d, want %d", limits.MaxMemoryBytes, 12*1024*1024)
	}
	if limits.ChunkMaxBytes != 6*1024*1024 {
		t.Fatalf("ChunkMaxBytes = %d, want %d", limits.ChunkMaxBytes, 6*1024*1024)
	}
	if limits.ParserMaxLineBytes != 3*1024*1024 {
		t.Fatalf("ParserMaxLineBytes = %d, want %d", limits.ParserMaxLineBytes, 3*1024*1024)
	}
	if limits.ChunkMaxRecords >= cfg.ChunkMaxRecords {
		t.Fatalf("ChunkMaxRecords = %d, want < %d", limits.ChunkMaxRecords, cfg.ChunkMaxRecords)
	}
	if limits.WriterBufferBytes < 8*1024 || limits.WriterBufferBytes > 64*1024 {
		t.Fatalf("WriterBufferBytes = %d, want between 8KiB and 64KiB", limits.WriterBufferBytes)
	}
}

func TestDeriveRuntimeLimitsRejectsTooSmallBudget(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		ChunkMaxBytes:      8 * 1024 * 1024,
		ChunkMaxRecords:    50000,
		ParserMaxLineBytes: 16 * 1024 * 1024,
	}

	if _, err := deriveRuntimeLimits("4MiB", cfg); err == nil {
		t.Fatalf("deriveRuntimeLimits() error = nil, want error")
	}
}
