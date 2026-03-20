package importer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/leofvo/pwned/internal/config"
	"github.com/leofvo/pwned/internal/storage"
	"github.com/leofvo/pwned/internal/storage/miniostore"
)

type Service struct {
	cfg     config.Config
	logger  *slog.Logger
	storage storage.Client
	nowFn   func() time.Time
}

func NewService(cfg config.Config, logger *slog.Logger) (*Service, error) {
	store, err := miniostore.New(cfg)
	if err != nil {
		return nil, err
	}

	return &Service{
		cfg:     cfg,
		logger:  logger,
		storage: store,
		nowFn:   time.Now,
	}, nil
}

func (s *Service) Import(ctx context.Context, opts Options) (Result, error) {
	if err := opts.validate(); err != nil {
		return Result{}, err
	}

	files, err := discoverFiles(opts.InputPath, opts.Recursive)
	if err != nil {
		return Result{}, err
	}
	if len(files) == 0 {
		return Result{}, fmt.Errorf("no files found for input %q", opts.InputPath)
	}

	if err := s.storage.EnsureBucket(ctx); err != nil {
		return Result{}, err
	}

	ingestID, err := newIngestID(s.nowFn().UTC())
	if err != nil {
		return Result{}, err
	}

	manifest := Manifest{
		IngestID:          ingestID,
		Source:            strings.TrimSpace(opts.Source),
		Tag:               strings.TrimSpace(opts.Tag),
		InputPath:         opts.InputPath,
		Format:            strings.TrimSpace(opts.Format),
		MaxMemory:         strings.TrimSpace(opts.MaxMemory),
		StartedAt:         s.nowFn().UTC(),
		Status:            "running",
		Files:             make([]ManifestFile, 0, len(files)),
		RawStorage:        "s3",
		NormalizedStorage: "s3+local",
		Parser:            "streaming-v2",
		ParserVer:         "0.2.0",
	}

	year := manifest.StartedAt.Format("2006")
	month := manifest.StartedAt.Format("01")

	for _, file := range files {
		entry := ManifestFile{
			RelativePath: filepath.ToSlash(file.relPath),
			SizeBytes:    file.size,
			Status:       "running",
			StartedAt:    s.nowFn().UTC(),
		}

		rawKey := rawObjectKey(opts.Source, year, month, ingestID, entry.RelativePath)
		sha256Sum, uploadErr := s.uploadWithChecksum(ctx, file.absPath, rawKey, file.size)
		if uploadErr != nil {
			entry.Status = "failed"
			entry.ErrorMessage = uploadErr.Error()
			entry.CompletedAt = s.nowFn().UTC()
			manifest.Files = append(manifest.Files, entry)
			return s.failImport(ingestID, opts.Source, manifest, uploadErr)
		}

		entry.RawObjectKey = rawKey
		entry.SHA256 = sha256Sum

		normalizedResult, normalizeErr := s.normalizeAndUploadFile(ctx, opts, ingestID, file, year, month)
		if normalizeErr != nil {
			entry.Status = "failed"
			entry.DetectedFormat = normalizedResult.DetectedFormat
			entry.RecordsProcessed = normalizedResult.RecordsProcessed
			entry.LastCheckpoint = normalizedResult.LastCheckpoint
			entry.NormalizedChunks = normalizedResult.Chunks
			entry.ErrorMessage = normalizeErr.Error()
			entry.CompletedAt = s.nowFn().UTC()
			manifest.Files = append(manifest.Files, entry)
			return s.failImport(ingestID, opts.Source, manifest, normalizeErr)
		}

		entry.Status = "completed"
		entry.DetectedFormat = normalizedResult.DetectedFormat
		entry.RecordsProcessed = normalizedResult.RecordsProcessed
		entry.LastCheckpoint = normalizedResult.LastCheckpoint
		entry.NormalizedChunks = normalizedResult.Chunks
		entry.CompletedAt = s.nowFn().UTC()

		manifest.Files = append(manifest.Files, entry)
		manifest.TotalFiles++
		manifest.TotalBytes += file.size
		manifest.TotalRecords += normalizedResult.RecordsProcessed
		manifest.TotalChunks += len(normalizedResult.Chunks)
	}

	manifest.Status = "completed"
	manifest.CompletedAt = s.nowFn().UTC()

	manifestObjectKey, localManifestPath, err := s.persistManifestAndUpload(ctx, ingestID, manifest)
	if err != nil {
		return Result{}, err
	}

	s.logger.Info(
		"import completed",
		"ingest_id", ingestID,
		"source", opts.Source,
		"files", manifest.TotalFiles,
		"bytes", manifest.TotalBytes,
		"records", manifest.TotalRecords,
		"chunks", manifest.TotalChunks,
		"manifest_key", manifestObjectKey,
	)

	return Result{
		IngestID:          ingestID,
		Source:            opts.Source,
		FilesProcessed:    manifest.TotalFiles,
		BytesProcessed:    manifest.TotalBytes,
		RecordsProcessed:  manifest.TotalRecords,
		NormalizedObjects: manifest.TotalChunks,
		ManifestObjectKey: manifestObjectKey,
		LocalManifestPath: localManifestPath,
	}, nil
}

func (s *Service) failImport(ingestID string, source string, manifest Manifest, rootErr error) (Result, error) {
	manifest.Status = "failed"
	manifest.ErrorMessage = rootErr.Error()
	manifest.CompletedAt = s.nowFn().UTC()

	localPath, persistErr := s.persistManifest(ingestID, manifest)
	if persistErr != nil {
		s.logger.Error("persist failed manifest", "error", persistErr, "ingest_id", ingestID)
	}

	return Result{
		IngestID:          ingestID,
		Source:            source,
		FilesProcessed:    manifest.TotalFiles,
		BytesProcessed:    manifest.TotalBytes,
		RecordsProcessed:  manifest.TotalRecords,
		NormalizedObjects: manifest.TotalChunks,
		ManifestObjectKey: "",
		LocalManifestPath: localPath,
	}, rootErr
}

func (s *Service) persistManifestAndUpload(ctx context.Context, ingestID string, manifest Manifest) (string, string, error) {
	manifestPayload, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", "", fmt.Errorf("marshal manifest: %w", err)
	}

	localManifestPath, err := s.persistManifestBytes(ingestID, manifestPayload)
	if err != nil {
		return "", "", err
	}

	manifestObjectKey := fmt.Sprintf("manifests/%s.json", ingestID)
	if err := s.storage.PutObject(
		ctx,
		manifestObjectKey,
		bytes.NewReader(manifestPayload),
		int64(len(manifestPayload)),
		"application/json",
	); err != nil {
		return "", "", err
	}

	return manifestObjectKey, localManifestPath, nil
}

func (s *Service) uploadWithChecksum(ctx context.Context, filePath string, objectKey string, size int64) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("open %q: %w", filePath, err)
	}
	defer file.Close()

	hasher := sha256.New()
	body := io.TeeReader(file, hasher)

	if err := s.storage.PutObject(ctx, objectKey, body, size, "application/octet-stream"); err != nil {
		return "", err
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func (s *Service) persistManifest(ingestID string, manifest Manifest) (string, error) {
	payload, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal manifest: %w", err)
	}
	return s.persistManifestBytes(ingestID, payload)
}

func (s *Service) persistManifestBytes(ingestID string, payload []byte) (string, error) {
	if err := os.MkdirAll(s.cfg.ManifestLocalDir, 0o755); err != nil {
		return "", fmt.Errorf("create manifest dir %q: %w", s.cfg.ManifestLocalDir, err)
	}
	path := filepath.Join(s.cfg.ManifestLocalDir, ingestID+".json")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		return "", fmt.Errorf("write manifest file %q: %w", path, err)
	}
	return path, nil
}
