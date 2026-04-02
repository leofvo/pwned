package storagestats

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"

	"github.com/leofvo/pwned/internal/config"
	"github.com/leofvo/pwned/internal/importer"
)

type Options struct {
	Source   string
	BySource bool
	ByMonth  bool
}

type Totals struct {
	Ingests         int   `json:"ingests"`
	Files           int   `json:"files"`
	Chunks          int   `json:"chunks"`
	Records         int64 `json:"records"`
	RawBytes        int64 `json:"raw_bytes"`
	NormalizedBytes int64 `json:"normalized_bytes"`
	ManifestBytes   int64 `json:"manifest_bytes"`
	TotalBytes      int64 `json:"total_bytes"`
}

type Bucket struct {
	Key    string `json:"key"`
	Totals Totals `json:"totals"`
}

type Result struct {
	Summary  Totals   `json:"summary"`
	BySource []Bucket `json:"by_source,omitempty"`
	ByMonth  []Bucket `json:"by_month,omitempty"`
}

type Service struct {
	cfg    config.Config
	logger *slog.Logger
}

func NewService(cfg config.Config, logger *slog.Logger) *Service {
	return &Service{cfg: cfg, logger: logger}
}

func (s *Service) Stats(_ context.Context, opts Options) (Result, error) {
	paths, err := importer.ListManifestPaths(s.cfg.ManifestLocalDir)
	if err != nil {
		return Result{}, err
	}
	if len(paths) == 0 {
		return Result{}, fmt.Errorf("no manifests found in %s", s.cfg.ManifestLocalDir)
	}

	sourceFilter := strings.TrimSpace(opts.Source)
	summary := Totals{}
	bySource := map[string]Totals{}
	byMonth := map[string]Totals{}

	for _, path := range paths {
		manifest, err := importer.LoadManifest(path)
		if err != nil {
			return Result{}, err
		}
		if sourceFilter != "" && manifest.Source != sourceFilter {
			continue
		}

		info, err := os.Stat(path)
		if err != nil {
			return Result{}, fmt.Errorf("stat manifest %q: %w", path, err)
		}

		totals := totalsForManifest(manifest, info.Size())
		summary = mergeTotals(summary, totals)

		if opts.BySource {
			key := strings.TrimSpace(manifest.Source)
			if key == "" {
				key = "_unknown"
			}
			bySource[key] = mergeTotals(bySource[key], totals)
		}
		if opts.ByMonth {
			month := manifest.StartedAt.UTC().Format("2006-01")
			if month == "0001-01" {
				month = "unknown"
			}
			byMonth[month] = mergeTotals(byMonth[month], totals)
		}
	}

	if summary.Ingests == 0 {
		return Result{}, fmt.Errorf("no matching manifests found")
	}

	result := Result{Summary: summary}
	if opts.BySource {
		result.BySource = flattenBuckets(bySource)
	}
	if opts.ByMonth {
		result.ByMonth = flattenBuckets(byMonth)
	}
	return result, nil
}

func totalsForManifest(manifest importer.Manifest, manifestSize int64) Totals {
	totals := Totals{
		Ingests:       1,
		ManifestBytes: manifestSize,
	}

	for _, file := range manifest.Files {
		totals.Files++
		totals.RawBytes += file.SizeBytes
		totals.Records += file.RecordsProcessed
		totals.Chunks += len(file.NormalizedChunks)
		for _, chunk := range file.NormalizedChunks {
			totals.NormalizedBytes += chunk.SizeBytes
		}
	}
	return mergeTotals(Totals{}, totals)
}

func mergeTotals(base Totals, add Totals) Totals {
	base.Ingests += add.Ingests
	base.Files += add.Files
	base.Chunks += add.Chunks
	base.Records += add.Records
	base.RawBytes += add.RawBytes
	base.NormalizedBytes += add.NormalizedBytes
	base.ManifestBytes += add.ManifestBytes
	base.TotalBytes = base.RawBytes + base.NormalizedBytes + base.ManifestBytes
	return base
}

func flattenBuckets(index map[string]Totals) []Bucket {
	keys := make([]string, 0, len(index))
	for key := range index {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	out := make([]Bucket, 0, len(keys))
	for _, key := range keys {
		out = append(out, Bucket{Key: key, Totals: index[key]})
	}
	return out
}
