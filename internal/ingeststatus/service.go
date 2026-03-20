package ingeststatus

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/leofvo/pwned/internal/config"
	"github.com/leofvo/pwned/internal/importer"
)

type Options struct {
	IngestID string
	Source   string
	All      bool
}

type Result struct {
	Items []Item `json:"items"`
}

type Item struct {
	IngestID       string     `json:"ingest_id"`
	Source         string     `json:"source"`
	Status         string     `json:"status"`
	StartedAt      time.Time  `json:"started_at"`
	ResumedAt      *time.Time `json:"resumed_at,omitempty"`
	CompletedAt    time.Time  `json:"completed_at"`
	FilesTotal     int        `json:"files_total"`
	FilesCompleted int        `json:"files_completed"`
	FilesFailed    int        `json:"files_failed"`
	FilesRunning   int        `json:"files_running"`
	TotalBytes     int64      `json:"total_bytes"`
	TotalRecords   int64      `json:"total_records"`
	TotalChunks    int        `json:"total_chunks"`
	ErrorMessage   string     `json:"error_message,omitempty"`
	ManifestPath   string     `json:"manifest_path"`
}

type Service struct {
	cfg    config.Config
	logger *slog.Logger
}

func NewService(cfg config.Config, logger *slog.Logger) *Service {
	return &Service{
		cfg:    cfg,
		logger: logger,
	}
}

func (s *Service) Status(_ context.Context, opts Options) (Result, error) {
	manifests, err := s.selectManifests(opts)
	if err != nil {
		return Result{}, err
	}

	items := make([]Item, 0, len(manifests))
	for _, m := range manifests {
		item := Item{
			IngestID:     m.Manifest.IngestID,
			Source:       m.Manifest.Source,
			Status:       m.Manifest.Status,
			StartedAt:    m.Manifest.StartedAt,
			ResumedAt:    m.Manifest.ResumedAt,
			CompletedAt:  m.Manifest.CompletedAt,
			TotalBytes:   m.Manifest.TotalBytes,
			TotalRecords: m.Manifest.TotalRecords,
			TotalChunks:  m.Manifest.TotalChunks,
			ErrorMessage: m.Manifest.ErrorMessage,
			ManifestPath: m.Path,
		}

		for _, file := range m.Manifest.Files {
			item.FilesTotal++
			switch strings.ToLower(strings.TrimSpace(file.Status)) {
			case "completed":
				item.FilesCompleted++
			case "failed":
				item.FilesFailed++
			default:
				item.FilesRunning++
			}
		}
		items = append(items, item)
	}

	sort.Slice(items, func(i int, j int) bool {
		return items[i].StartedAt.After(items[j].StartedAt)
	})
	return Result{Items: items}, nil
}

type manifestWithPath struct {
	Path     string
	Manifest importer.Manifest
}

func (s *Service) selectManifests(opts Options) ([]manifestWithPath, error) {
	if strings.TrimSpace(opts.IngestID) != "" {
		path := filepath.Join(s.cfg.ManifestLocalDir, strings.TrimSpace(opts.IngestID)+".json")
		manifest, err := importer.LoadManifest(path)
		if err != nil {
			return nil, err
		}
		return []manifestWithPath{{Path: path, Manifest: manifest}}, nil
	}

	paths, err := importer.ListManifestPaths(s.cfg.ManifestLocalDir)
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no manifests found in %s", s.cfg.ManifestLocalDir)
	}

	sourceFilter := strings.TrimSpace(opts.Source)
	out := make([]manifestWithPath, 0, len(paths))
	for _, path := range paths {
		manifest, err := importer.LoadManifest(path)
		if err != nil {
			return nil, err
		}
		if sourceFilter != "" && manifest.Source != sourceFilter {
			continue
		}
		out = append(out, manifestWithPath{Path: path, Manifest: manifest})
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("no matching manifests found")
	}

	sort.Slice(out, func(i int, j int) bool {
		return out[i].Manifest.StartedAt.Before(out[j].Manifest.StartedAt)
	})
	if opts.All {
		return out, nil
	}
	return out[len(out)-1:], nil
}
