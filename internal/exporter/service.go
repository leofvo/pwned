package exporter

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/leofvo/pwned/internal/config"
	searchsvc "github.com/leofvo/pwned/internal/search"
)

type Options struct {
	RawQuery        string
	Filters         []string
	Match           string
	Limit           int
	Offset          int
	RevealSensitive bool
	Format          string
	OutputPath      string
	CreateIndex     bool
}

type Result struct {
	OutputPath   string `json:"output_path"`
	Format       string `json:"format"`
	Query        string `json:"query"`
	NumHits      int64  `json:"num_hits"`
	ExportedHits int    `json:"exported_hits"`
}

type Service struct {
	cfg    config.Config
	logger *slog.Logger
	search *searchsvc.Service
}

func NewService(cfg config.Config, logger *slog.Logger) *Service {
	return &Service{
		cfg:    cfg,
		logger: logger,
		search: searchsvc.NewService(cfg, logger),
	}
}

func (s *Service) Export(ctx context.Context, opts Options) (Result, error) {
	outputPath := strings.TrimSpace(opts.OutputPath)
	if outputPath == "" {
		return Result{}, fmt.Errorf("output path is required")
	}

	format := strings.ToLower(strings.TrimSpace(opts.Format))
	if format != "json" && format != "csv" {
		return Result{}, fmt.Errorf("format must be json or csv")
	}

	searchResult, err := s.search.Search(ctx, searchsvc.Options{
		RawQuery:        opts.RawQuery,
		Filters:         opts.Filters,
		Match:           opts.Match,
		Limit:           opts.Limit,
		Offset:          opts.Offset,
		RevealSensitive: opts.RevealSensitive,
		CreateIndex:     opts.CreateIndex,
		IndexConfigPath: s.cfg.QuickwitIndexConfig,
	})
	if err != nil {
		return Result{}, err
	}

	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return Result{}, fmt.Errorf("create output directory: %w", err)
	}

	switch format {
	case "json":
		if err := writeJSON(outputPath, searchResult); err != nil {
			return Result{}, err
		}
	case "csv":
		if err := writeCSV(outputPath, searchResult.Hits); err != nil {
			return Result{}, err
		}
	}

	s.logger.Info(
		"export completed",
		"format", format,
		"output_path", outputPath,
		"query", searchResult.Query,
		"num_hits", searchResult.NumHits,
		"exported_hits", len(searchResult.Hits),
	)

	return Result{
		OutputPath:   outputPath,
		Format:       format,
		Query:        searchResult.Query,
		NumHits:      searchResult.NumHits,
		ExportedHits: len(searchResult.Hits),
	}, nil
}

func writeJSON(path string, payload any) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create export file %q: %w", path, err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(payload); err != nil {
		return fmt.Errorf("write json export %q: %w", path, err)
	}
	return nil
}

func writeCSV(path string, hits []map[string]any) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create export file %q: %w", path, err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	headers := collectCSVHeaders(hits)
	if err := writer.Write(headers); err != nil {
		return fmt.Errorf("write csv header: %w", err)
	}

	for _, hit := range hits {
		row := make([]string, len(headers))
		for i, header := range headers {
			row[i] = strings.TrimSpace(fmt.Sprintf("%v", hit[header]))
		}
		if err := writer.Write(row); err != nil {
			return fmt.Errorf("write csv row: %w", err)
		}
	}

	if err := writer.Error(); err != nil {
		return fmt.Errorf("flush csv writer: %w", err)
	}
	return nil
}

func collectCSVHeaders(hits []map[string]any) []string {
	keySet := map[string]struct{}{}
	for _, hit := range hits {
		for key := range hit {
			keySet[key] = struct{}{}
		}
	}
	headers := make([]string, 0, len(keySet))
	for key := range keySet {
		headers = append(headers, key)
	}
	sort.Strings(headers)
	return headers
}
