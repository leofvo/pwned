package importer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/leofvo/pwned/internal/config"
)

func TestStreamCSVHeaderOverrideSkipsFirstLine(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "dump.csv")
	content := "bad_col_a,bad_col_b\n0611223344,John\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write csv fixture: %v", err)
	}

	svc := &Service{
		cfg: config.Config{
			ParserMaxLineBytes: 1024,
		},
	}

	var (
		fieldsList  []map[string]any
		checkpoints []string
	)
	limits := runtimeLimits{
		WriterBufferBytes: 8 * 1024,
	}
	err := svc.streamCSV(path, Options{
		CSVHeaders: []string{"phone", "firstname"},
	}, limits, func(fields map[string]any, checkpoint string) error {
		fieldsList = append(fieldsList, fields)
		checkpoints = append(checkpoints, checkpoint)
		return nil
	})
	if err != nil {
		t.Fatalf("streamCSV() error = %v", err)
	}

	if len(fieldsList) != 1 {
		t.Fatalf("records = %d, want 1", len(fieldsList))
	}
	if got := fieldsList[0]["phone"]; got != "0611223344" {
		t.Fatalf("phone = %v, want 0611223344", got)
	}
	if got := fieldsList[0]["firstname"]; got != "John" {
		t.Fatalf("firstname = %v, want John", got)
	}
	if len(checkpoints) != 1 || checkpoints[0] != "line:2" {
		t.Fatalf("checkpoints = %v, want [line:2]", checkpoints)
	}
}

func TestStreamCSVAllowsLazyQuotes(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "dump.csv")
	content := "phone,firstname\n+33\"66,John\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write csv fixture: %v", err)
	}

	svc := &Service{
		cfg: config.Config{
			ParserMaxLineBytes: 1024,
		},
	}

	var fieldsList []map[string]any
	err := svc.streamCSV(path, Options{}, runtimeLimits{WriterBufferBytes: 8 * 1024}, func(fields map[string]any, _ string) error {
		fieldsList = append(fieldsList, fields)
		return nil
	})
	if err != nil {
		t.Fatalf("streamCSV() error = %v", err)
	}

	if len(fieldsList) != 1 {
		t.Fatalf("records = %d, want 1", len(fieldsList))
	}
	if got := fieldsList[0]["phone"]; got != `+33"66` {
		t.Fatalf("phone = %v, want +33\"66", got)
	}
}

func TestNormalizeRecordDerivesAddressFromSplitFields(t *testing.T) {
	t.Parallel()

	normalized, keep := normalizeRecord(
		"facebook",
		"france01.txt",
		"ing-1",
		1,
		"csv",
		map[string]any{
			"street":      "221B Baker Street",
			"postal_code": "NW1",
			"city":        "London",
			"country":     "UK",
		},
	)

	if !keep {
		t.Fatalf("keep = false, want true")
	}
	if got := normalized["address"]; got != "221B Baker Street, NW1, London, UK" {
		t.Fatalf("address = %v, want full combined address", got)
	}
}
