package search

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/leofvo/pwned/internal/config"
	"github.com/leofvo/pwned/internal/importer"
	"github.com/leofvo/pwned/internal/indexer/quickwit"
)

type Options struct {
	RawQuery        string
	Filters         []string
	Match           string
	Limit           int
	Offset          int
	RevealSensitive bool
	CreateIndex     bool
	IndexConfigPath string
}

type Result struct {
	IndexID           string           `json:"index_id"`
	Query             string           `json:"query"`
	NumHits           int64            `json:"num_hits"`
	ReturnedHits      int              `json:"returned_hits"`
	ElapsedTimeMicros int64            `json:"elapsed_time_micros"`
	Hits              []map[string]any `json:"hits"`
	Errors            []string         `json:"errors"`
}

type Service struct {
	cfg     config.Config
	logger  *slog.Logger
	quickwt *quickwit.Client
}

func NewService(cfg config.Config, logger *slog.Logger) *Service {
	return &Service{
		cfg:     cfg,
		logger:  logger,
		quickwt: quickwit.New(cfg.QuickwitBaseURL),
	}
}

func (s *Service) Search(ctx context.Context, opts Options) (Result, error) {
	if err := validateOptions(opts); err != nil {
		return Result{}, err
	}

	query, err := buildQuery(opts.RawQuery, opts.Filters, opts.Match)
	if err != nil {
		return Result{}, err
	}

	if opts.CreateIndex {
		if err := s.quickwt.CreateIndexFromConfigFile(ctx, opts.IndexConfigPath); err != nil {
			return Result{}, err
		}
	}

	resp, err := s.quickwt.Search(ctx, s.cfg.QuickwitIndexID, query, opts.Limit, opts.Offset)
	if err != nil {
		return Result{}, err
	}

	hits := resp.Hits
	if !opts.RevealSensitive {
		maskSensitiveFields(hits)
	}

	s.logger.Info(
		"search completed",
		"index_id", s.cfg.QuickwitIndexID,
		"query", query,
		"num_hits", resp.NumHits,
		"returned_hits", len(hits),
	)

	return Result{
		IndexID:           s.cfg.QuickwitIndexID,
		Query:             query,
		NumHits:           resp.NumHits,
		ReturnedHits:      len(hits),
		ElapsedTimeMicros: resp.ElapsedTimeMicros,
		Hits:              hits,
		Errors:            resp.Errors,
	}, nil
}

func validateOptions(opts Options) error {
	if strings.TrimSpace(opts.RawQuery) == "" && len(opts.Filters) == 0 {
		return fmt.Errorf("provide --query and/or at least one --where key=value filter")
	}
	if opts.Limit <= 0 {
		return fmt.Errorf("--limit must be > 0")
	}
	if opts.Offset < 0 {
		return fmt.Errorf("--offset must be >= 0")
	}
	match := strings.ToLower(strings.TrimSpace(opts.Match))
	if match != "all" && match != "any" {
		return fmt.Errorf("--match must be all or any")
	}
	return nil
}

func buildQuery(rawQuery string, filters []string, match string) (string, error) {
	clauses := make([]string, 0, len(filters))
	for _, filter := range filters {
		key, value, err := parseFilter(filter)
		if err != nil {
			return "", err
		}

		canonical, ok := importer.ResolveCanonicalField(key)
		if !ok {
			return "", fmt.Errorf("unknown mapped field %q. run `pwned mapping` to list fields", key)
		}

		clauses = append(clauses, fmt.Sprintf("%s:%s", canonical, formatQueryValue(value)))
	}

	var filterQuery string
	if len(clauses) > 0 {
		joiner := " AND "
		if strings.EqualFold(strings.TrimSpace(match), "any") {
			joiner = " OR "
		}
		filterQuery = strings.Join(clauses, joiner)
	}

	raw := strings.TrimSpace(rawQuery)
	switch {
	case raw == "" && filterQuery == "":
		return "", fmt.Errorf("empty query")
	case raw == "":
		return filterQuery, nil
	case filterQuery == "":
		return raw, nil
	default:
		return fmt.Sprintf("(%s) AND (%s)", raw, filterQuery), nil
	}
}

func parseFilter(input string) (string, string, error) {
	parts := strings.SplitN(input, "=", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid --where %q. expected key=value", input)
	}

	key := strings.TrimSpace(parts[0])
	value := strings.TrimSpace(parts[1])
	if key == "" || value == "" {
		return "", "", fmt.Errorf("invalid --where %q. expected non-empty key and value", input)
	}
	return key, value, nil
}

func formatQueryValue(value string) string {
	v := strings.TrimSpace(value)
	if v == "" {
		return "\"\""
	}

	if strings.ContainsAny(v, " \t\n\r\"'()[]{}:") {
		v = strings.ReplaceAll(v, `\`, `\\`)
		v = strings.ReplaceAll(v, `"`, `\"`)
		return `"` + v + `"`
	}
	return v
}

var sensitiveFields = map[string]struct{}{
	"password":      {},
	"password_hash": {},
	"email":         {},
	"phone":         {},
	"address":       {},
}

func maskSensitiveFields(hits []map[string]any) {
	for _, hit := range hits {
		for key, value := range hit {
			if _, ok := sensitiveFields[strings.ToLower(strings.TrimSpace(key))]; !ok {
				continue
			}
			hit[key] = maskValue(strings.TrimSpace(fmt.Sprintf("%v", value)))
		}
	}
}

func maskValue(value string) string {
	if value == "" || value == "<nil>" {
		return value
	}
	runes := []rune(value)
	if len(runes) <= 2 {
		return "***"
	}
	return string(runes[0]) + strings.Repeat("*", len(runes)-2) + string(runes[len(runes)-1])
}
