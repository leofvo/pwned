package app

import (
	"bytes"
	"strings"
	"testing"

	"github.com/leofvo/pwned/internal/storagestats"
)

func TestParseCSVHeaders(t *testing.T) {
	t.Parallel()

	headers := parseCSVHeaders(" email, password, , firstname ")
	if len(headers) != 3 {
		t.Fatalf("len(headers) = %d, want 3", len(headers))
	}
	if headers[0] != "email" || headers[1] != "password" || headers[2] != "firstname" {
		t.Fatalf("headers = %#v, unexpected values", headers)
	}
}

func TestMultiStringFlagSet(t *testing.T) {
	t.Parallel()

	var flag multiStringFlag
	if err := flag.Set(" a=b "); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	if err := flag.Set(""); err == nil {
		t.Fatalf("Set() error = nil, want error")
	}
	if got := flag.String(); got != "a=b" {
		t.Fatalf("String() = %q, want a=b", got)
	}
}

func TestSanitizeAuditParamsRedactsSensitiveKeys(t *testing.T) {
	t.Parallel()

	params := sanitizeAuditParams(map[string]any{
		"token":     "abc",
		"secretKey": "def",
		"password":  "ghi",
		"source":    "dump-a",
	})

	if params["token"] != "***redacted***" {
		t.Fatalf("token = %v, want redacted", params["token"])
	}
	if params["secretKey"] != "***redacted***" {
		t.Fatalf("secretKey = %v, want redacted", params["secretKey"])
	}
	if params["password"] != "***redacted***" {
		t.Fatalf("password = %v, want redacted", params["password"])
	}
	if params["source"] != "dump-a" {
		t.Fatalf("source = %v, want dump-a", params["source"])
	}
}

func TestWriteStorageStatsResult(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	result := storagestats.Result{
		Summary: storagestats.Totals{
			Ingests:         2,
			Files:           3,
			Chunks:          4,
			Records:         5,
			RawBytes:        6,
			NormalizedBytes: 7,
			ManifestBytes:   8,
			TotalBytes:      21,
		},
		BySource: []storagestats.Bucket{{
			Key: "alpha",
			Totals: storagestats.Totals{
				Ingests:    1,
				Files:      1,
				Chunks:     1,
				Records:    2,
				RawBytes:   3,
				TotalBytes: 3,
			},
		}},
	}

	if err := writeStorageStatsResult(&out, result); err != nil {
		t.Fatalf("writeStorageStatsResult() error = %v", err)
	}
	text := out.String()
	if !strings.Contains(text, "ingests: 2") {
		t.Fatalf("output missing ingests line: %q", text)
	}
	if !strings.Contains(text, "by_source:") {
		t.Fatalf("output missing by_source block: %q", text)
	}
}
