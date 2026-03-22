package provenance

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/leofvo/pwned/internal/config"
	"github.com/leofvo/pwned/internal/importer"
	"github.com/leofvo/pwned/internal/indexer/quickwit"
)

type Options struct {
	RecordID        string
	Limit           int
	RevealSensitive bool
}

type Result struct {
	Query        string   `json:"query"`
	NumHits      int64    `json:"num_hits"`
	ReturnedHits int      `json:"returned_hits"`
	Records      []Record `json:"records"`
}

type Record struct {
	Hit            map[string]any         `json:"hit"`
	ManifestPath   string                 `json:"manifest_path,omitempty"`
	ManifestFound  bool                   `json:"manifest_found"`
	FileFound      bool                   `json:"file_found"`
	FileProvenance *importer.ManifestFile `json:"file_provenance,omitempty"`
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
		quickwt: quickwit.New(cfg.QuickwitBaseURL, cfg.QuickwitHTTPTimeout),
	}
}

func (s *Service) Lookup(ctx context.Context, opts Options) (Result, error) {
	recordID := strings.TrimSpace(opts.RecordID)
	if recordID == "" {
		return Result{}, fmt.Errorf("record_id is required")
	}
	if opts.Limit <= 0 {
		opts.Limit = 20
	}

	query := fmt.Sprintf(`record_id:%s`, formatQueryValue(recordID))
	searchResp, err := s.quickwt.Search(ctx, s.cfg.QuickwitIndexID, query, opts.Limit, 0)
	if err != nil {
		return Result{}, err
	}

	records := make([]Record, 0, len(searchResp.Hits))
	for _, hit := range searchResp.Hits {
		if !opts.RevealSensitive {
			maskSensitiveFields([]map[string]any{hit})
		}

		record := Record{
			Hit: hit,
		}

		ingestID := asString(hit["ingest_id"])
		sourceFile := filepath.ToSlash(asString(hit["source_file"]))
		if ingestID != "" {
			manifestPath := filepath.Join(s.cfg.ManifestLocalDir, ingestID+".json")
			manifest, err := importer.LoadManifest(manifestPath)
			if err == nil {
				record.ManifestFound = true
				record.ManifestPath = manifestPath
				for _, file := range manifest.Files {
					if filepath.ToSlash(file.RelativePath) == sourceFile {
						fileCopy := file
						record.FileFound = true
						record.FileProvenance = &fileCopy
						break
					}
				}
			}
		}

		records = append(records, record)
	}

	s.logger.Info(
		"provenance lookup completed",
		"record_id", recordID,
		"query", query,
		"num_hits", searchResp.NumHits,
		"returned_hits", len(records),
	)

	return Result{
		Query:        query,
		NumHits:      searchResp.NumHits,
		ReturnedHits: len(records),
		Records:      records,
	}, nil
}

func asString(value any) string {
	if value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case []byte:
		return strings.TrimSpace(string(typed))
	default:
		rendered := strings.TrimSpace(fmt.Sprintf("%v", typed))
		if rendered == "<nil>" {
			return ""
		}
		return rendered
	}
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
