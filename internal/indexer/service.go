package indexer

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/leofvo/pwned/internal/config"
	"github.com/leofvo/pwned/internal/importer"
	"github.com/leofvo/pwned/internal/indexer/quickwit"
)

type Options struct {
	IngestID    string
	Source      string
	All         bool
	CreateIndex bool
}

type Result struct {
	IndexID          string   `json:"index_id"`
	IngestIDs        []string `json:"ingest_ids"`
	ManifestsIndexed int      `json:"manifests_indexed"`
	FilesIndexed     int      `json:"files_indexed"`
	ChunksIndexed    int      `json:"chunks_indexed"`
	RecordsIndexed   int64    `json:"records_indexed"`
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

func (s *Service) Index(ctx context.Context, opts Options) (Result, error) {
	manifests, err := s.selectManifests(opts)
	if err != nil {
		return Result{}, err
	}
	if len(manifests) == 0 {
		return Result{}, fmt.Errorf("no matching manifests found for indexing")
	}

	if opts.CreateIndex {
		if err := s.quickwt.CreateIndexFromConfigFile(ctx, s.cfg.QuickwitIndexConfig); err != nil {
			return Result{}, err
		}
	}

	result := Result{
		IndexID:   s.cfg.QuickwitIndexID,
		IngestIDs: make([]string, 0, len(manifests)),
	}

	for _, manifest := range manifests {
		result.IngestIDs = append(result.IngestIDs, manifest.IngestID)
		result.ManifestsIndexed++

		for _, file := range manifest.Files {
			if len(file.NormalizedChunks) == 0 {
				continue
			}
			result.FilesIndexed++

			for _, chunk := range file.NormalizedChunks {
				if strings.TrimSpace(chunk.LocalPath) == "" {
					return result, fmt.Errorf("manifest %s has empty local chunk path", manifest.IngestID)
				}

				if _, err := os.Stat(chunk.LocalPath); err != nil {
					return result, fmt.Errorf("chunk file missing %q: %w", chunk.LocalPath, err)
				}

				docs, err := s.quickwt.IngestNDJSONFile(ctx, s.cfg.QuickwitIndexID, chunk.LocalPath, s.cfg.QuickwitCommitMode)
				if err != nil {
					return result, fmt.Errorf("index ingest %s (chunk %s): %w", manifest.IngestID, chunk.LocalPath, err)
				}

				result.ChunksIndexed++
				if docs > 0 {
					result.RecordsIndexed += docs
				} else {
					result.RecordsIndexed += chunk.RecordCount
				}
			}
		}

		s.logger.Info(
			"manifest indexed",
			"ingest_id", manifest.IngestID,
			"index_id", s.cfg.QuickwitIndexID,
			"files", len(manifest.Files),
		)
	}

	return result, nil
}

func (s *Service) selectManifests(opts Options) ([]importer.Manifest, error) {
	if strings.TrimSpace(opts.IngestID) != "" {
		path := filepathForIngestID(s.cfg.ManifestLocalDir, opts.IngestID)
		manifest, err := importer.LoadManifest(path)
		if err != nil {
			return nil, err
		}
		if !isCompleted(manifest) {
			return nil, fmt.Errorf("ingest %s is not completed", opts.IngestID)
		}
		return []importer.Manifest{manifest}, nil
	}

	paths, err := importer.ListManifestPaths(s.cfg.ManifestLocalDir)
	if err != nil {
		return nil, err
	}

	manifests := make([]importer.Manifest, 0, len(paths))
	for _, path := range paths {
		manifest, err := importer.LoadManifest(path)
		if err != nil {
			return nil, err
		}
		if !isCompleted(manifest) {
			continue
		}
		if strings.TrimSpace(opts.Source) != "" && manifest.Source != strings.TrimSpace(opts.Source) {
			continue
		}
		if !hasChunks(manifest) {
			continue
		}
		manifests = append(manifests, manifest)
	}

	sort.Slice(manifests, func(i int, j int) bool {
		return manifests[i].StartedAt.Before(manifests[j].StartedAt)
	})

	if len(manifests) == 0 {
		return nil, nil
	}
	if opts.All {
		return manifests, nil
	}
	return manifests[len(manifests)-1:], nil
}

func filepathForIngestID(manifestDir string, ingestID string) string {
	return filepath.Join(manifestDir, ingestID+".json")
}

func isCompleted(manifest importer.Manifest) bool {
	return strings.EqualFold(strings.TrimSpace(manifest.Status), "completed")
}

func hasChunks(manifest importer.Manifest) bool {
	for _, file := range manifest.Files {
		if len(file.NormalizedChunks) > 0 {
			return true
		}
	}
	return false
}
