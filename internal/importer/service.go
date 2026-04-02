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
	"sort"
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

	now := s.nowFn().UTC()
	manifest, err := s.initializeManifest(opts, now)
	if err != nil {
		return Result{}, err
	}
	ingestID := manifest.IngestID
	limits, err := deriveRuntimeLimits(manifest.MaxMemory, s.cfg)
	if err != nil {
		return Result{}, fmt.Errorf("resolve runtime limits from max memory %q: %w", manifest.MaxMemory, err)
	}

	recursive := opts.Recursive
	if strings.TrimSpace(opts.ResumeIngestID) != "" {
		recursive = true
	}

	files, err := discoverFiles(manifest.InputPath, recursive)
	if err != nil {
		return Result{}, err
	}
	if len(files) == 0 {
		return Result{}, fmt.Errorf("no files found for input %q", manifest.InputPath)
	}

	if err := s.storage.EnsureBucket(ctx); err != nil {
		return Result{}, err
	}

	year := manifest.StartedAt.Format("2006")
	month := manifest.StartedAt.Format("01")
	effectiveOpts := opts
	effectiveOpts.Source = manifest.Source
	effectiveOpts.Format = manifest.Format
	effectiveOpts.MaxMemory = manifest.MaxMemory

	existingByPath := mapManifestFilesByPath(manifest.Files)

	for _, file := range files {
		relativePath := filepath.ToSlash(file.relPath)
		previous, hadPrevious := existingByPath[relativePath]
		if hadPrevious && strings.EqualFold(previous.Status, "completed") {
			s.logger.Info("skipping already completed file during import/resume", "ingest_id", ingestID, "file", relativePath)
			continue
		}

		entry := ManifestFile{
			RelativePath: relativePath,
			SizeBytes:    file.size,
			Status:       "running",
			StartedAt:    now,
		}

		var resumeEntry *ManifestFile
		if hadPrevious {
			entry.RawObjectKey = previous.RawObjectKey
			entry.SHA256 = previous.SHA256
			entry.NormalizedChunks = append(entry.NormalizedChunks, previous.NormalizedChunks...)
			entry.RecordsProcessed = previous.RecordsProcessed
			entry.LastCheckpoint = previous.LastCheckpoint

			previousCopy := previous
			resumeEntry = &previousCopy
		}

		if entry.RawObjectKey == "" || entry.SHA256 == "" {
			rawKey := rawObjectKey(manifest.Source, year, month, ingestID, entry.RelativePath)
			sha256Sum, uploadErr := s.uploadWithChecksum(ctx, file.absPath, rawKey, file.size)
			if uploadErr != nil {
				entry.Status = "failed"
				entry.ErrorMessage = uploadErr.Error()
				entry.CompletedAt = s.nowFn().UTC()
				upsertManifestFile(&manifest, entry)
				return s.failImport(ingestID, manifest.Source, manifest, uploadErr)
			}
			entry.RawObjectKey = rawKey
			entry.SHA256 = sha256Sum
		}

		normalizedResult, normalizeErr := s.normalizeAndUploadFile(ctx, effectiveOpts, ingestID, file, year, month, resumeEntry, limits)
		if normalizeErr != nil {
			entry.Status = "failed"
			entry.DetectedFormat = normalizedResult.DetectedFormat
			entry.RecordsProcessed = normalizedResult.RecordsProcessed
			entry.LastCheckpoint = normalizedResult.LastCheckpoint
			entry.NormalizedChunks = normalizedResult.Chunks
			entry.ErrorMessage = normalizeErr.Error()
			entry.CompletedAt = s.nowFn().UTC()
			upsertManifestFile(&manifest, entry)
			return s.failImport(ingestID, manifest.Source, manifest, normalizeErr)
		}

		entry.Status = "completed"
		entry.DetectedFormat = normalizedResult.DetectedFormat
		entry.RecordsProcessed = normalizedResult.RecordsProcessed
		entry.LastCheckpoint = normalizedResult.LastCheckpoint
		entry.NormalizedChunks = normalizedResult.Chunks
		entry.CompletedAt = s.nowFn().UTC()
		entry.ErrorMessage = ""
		upsertManifestFile(&manifest, entry)
	}

	manifest.Status = "completed"
	manifest.ErrorMessage = ""
	manifest.CompletedAt = s.nowFn().UTC()
	recomputeManifestTotals(&manifest)

	manifestObjectKey, localManifestPath, err := s.persistManifestAndUpload(ctx, ingestID, manifest)
	if err != nil {
		return Result{}, err
	}

	s.logger.Info(
		"import completed",
		"ingest_id", ingestID,
		"source", manifest.Source,
		"files", manifest.TotalFiles,
		"bytes", manifest.TotalBytes,
		"records", manifest.TotalRecords,
		"chunks", manifest.TotalChunks,
		"manifest_key", manifestObjectKey,
	)

	return Result{
		IngestID:          ingestID,
		Source:            manifest.Source,
		FilesProcessed:    manifest.TotalFiles,
		BytesProcessed:    manifest.TotalBytes,
		RecordsProcessed:  manifest.TotalRecords,
		NormalizedObjects: manifest.TotalChunks,
		ManifestObjectKey: manifestObjectKey,
		LocalManifestPath: localManifestPath,
	}, nil
}

func (s *Service) initializeManifest(opts Options, now time.Time) (Manifest, error) {
	resumeID := strings.TrimSpace(opts.ResumeIngestID)
	if resumeID == "" {
		ingestID, err := newIngestID(now)
		if err != nil {
			return Manifest{}, err
		}
		return Manifest{
			IngestID:          ingestID,
			Source:            strings.TrimSpace(opts.Source),
			Tag:               strings.TrimSpace(opts.Tag),
			InputPath:         strings.TrimSpace(opts.InputPath),
			Format:            strings.TrimSpace(opts.Format),
			MaxMemory:         strings.TrimSpace(opts.MaxMemory),
			StartedAt:         now,
			Status:            "running",
			Files:             make([]ManifestFile, 0),
			RawStorage:        "s3",
			NormalizedStorage: "s3+local",
			Parser:            "streaming-v3",
			ParserVer:         "0.3.0",
		}, nil
	}

	manifestPath := filepath.Join(s.cfg.ManifestLocalDir, resumeID+".json")
	manifest, err := LoadManifest(manifestPath)
	if err != nil {
		return Manifest{}, fmt.Errorf("load resume manifest: %w", err)
	}

	requestedSource := strings.TrimSpace(opts.Source)
	if requestedSource != "" && manifest.Source != requestedSource {
		return Manifest{}, fmt.Errorf("resume source mismatch: manifest source=%q request source=%q", manifest.Source, requestedSource)
	}
	requestedInput := strings.TrimSpace(opts.InputPath)
	if requestedInput != "" && filepath.Clean(requestedInput) != filepath.Clean(manifest.InputPath) {
		return Manifest{}, fmt.Errorf("resume input path mismatch: manifest input=%q request input=%q", manifest.InputPath, requestedInput)
	}

	if requestedSource != "" {
		manifest.Source = requestedSource
	}
	if requestedInput != "" {
		manifest.InputPath = requestedInput
	}
	if strings.TrimSpace(opts.Tag) != "" {
		manifest.Tag = strings.TrimSpace(opts.Tag)
	}
	if strings.TrimSpace(opts.Format) != "" && strings.TrimSpace(opts.Format) != "auto" {
		manifest.Format = strings.TrimSpace(opts.Format)
	}
	if strings.TrimSpace(opts.MaxMemory) != "" {
		manifest.MaxMemory = strings.TrimSpace(opts.MaxMemory)
	}
	if strings.TrimSpace(manifest.InputPath) == "" {
		return Manifest{}, fmt.Errorf("resume manifest has empty input_path")
	}
	if strings.TrimSpace(manifest.Source) == "" {
		return Manifest{}, fmt.Errorf("resume manifest has empty source")
	}

	manifest.Status = "running"
	manifest.ErrorMessage = ""
	resumedAt := now
	manifest.ResumedAt = &resumedAt
	manifest.CompletedAt = time.Time{}
	return manifest, nil
}

func (s *Service) failImport(ingestID string, source string, manifest Manifest, rootErr error) (Result, error) {
	manifest.Status = "failed"
	manifest.ErrorMessage = rootErr.Error()
	manifest.CompletedAt = s.nowFn().UTC()
	recomputeManifestTotals(&manifest)

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
	if err := s.uploadBytesWithRetry(ctx, manifestPayload, manifestObjectKey, "application/json"); err != nil {
		return "", "", err
	}

	return manifestObjectKey, localManifestPath, nil
}

func (s *Service) uploadWithChecksum(ctx context.Context, filePath string, objectKey string, size int64) (string, error) {
	var sha256Sum string
	err := runWithRetry(ctx, s.retryPolicy(), s.logRetry("upload raw object", objectKey), func() error {
		file, err := os.Open(filePath)
		if err != nil {
			return fmt.Errorf("open %q: %w", filePath, err)
		}
		defer file.Close()

		hasher := sha256.New()
		body := io.TeeReader(file, hasher)

		if err := s.storage.PutObject(ctx, objectKey, body, size, "application/octet-stream"); err != nil {
			return err
		}
		sha256Sum = hex.EncodeToString(hasher.Sum(nil))
		return nil
	})
	if err != nil {
		return "", err
	}
	return sha256Sum, nil
}

func (s *Service) uploadLocalFileWithRetry(ctx context.Context, localPath string, objectKey string, contentType string) (int64, error) {
	info, err := os.Stat(localPath)
	if err != nil {
		return 0, fmt.Errorf("stat local file %q: %w", localPath, err)
	}

	err = runWithRetry(ctx, s.retryPolicy(), s.logRetry("upload normalized chunk", objectKey), func() error {
		file, err := os.Open(localPath)
		if err != nil {
			return fmt.Errorf("open local file %q: %w", localPath, err)
		}
		defer file.Close()

		return s.storage.PutObject(ctx, objectKey, file, info.Size(), contentType)
	})
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

func (s *Service) uploadBytesWithRetry(ctx context.Context, payload []byte, objectKey string, contentType string) error {
	size := int64(len(payload))
	return runWithRetry(ctx, s.retryPolicy(), s.logRetry("upload object", objectKey), func() error {
		reader := bytes.NewReader(payload)
		return s.storage.PutObject(ctx, objectKey, reader, size, contentType)
	})
}

func (s *Service) retryPolicy() retryPolicy {
	return retryPolicy{
		MaxRetries: s.cfg.UploadMaxRetries,
		BaseDelay:  s.cfg.UploadRetryBaseDelay,
		MaxDelay:   s.cfg.UploadRetryMaxDelay,
	}
}

func (s *Service) logRetry(action string, objectKey string) func(attempt int, delay time.Duration, err error) {
	return func(attempt int, delay time.Duration, err error) {
		s.logger.Warn(
			"retrying storage operation",
			"action", action,
			"object_key", objectKey,
			"attempt", attempt,
			"delay", delay.String(),
			"error", err,
		)
	}
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

func mapManifestFilesByPath(files []ManifestFile) map[string]ManifestFile {
	out := make(map[string]ManifestFile, len(files))
	for _, file := range files {
		relativePath := filepath.ToSlash(strings.TrimSpace(file.RelativePath))
		if relativePath == "" {
			continue
		}
		out[relativePath] = file
	}
	return out
}

func upsertManifestFile(manifest *Manifest, entry ManifestFile) {
	for i := range manifest.Files {
		if filepath.ToSlash(manifest.Files[i].RelativePath) == filepath.ToSlash(entry.RelativePath) {
			manifest.Files[i] = entry
			sort.Slice(manifest.Files, func(a int, b int) bool {
				return manifest.Files[a].RelativePath < manifest.Files[b].RelativePath
			})
			return
		}
	}
	manifest.Files = append(manifest.Files, entry)
	sort.Slice(manifest.Files, func(a int, b int) bool {
		return manifest.Files[a].RelativePath < manifest.Files[b].RelativePath
	})
}

func recomputeManifestTotals(manifest *Manifest) {
	manifest.TotalFiles = 0
	manifest.TotalBytes = 0
	manifest.TotalRecords = 0
	manifest.TotalChunks = 0

	for _, file := range manifest.Files {
		if strings.EqualFold(file.Status, "completed") {
			manifest.TotalFiles++
			manifest.TotalBytes += file.SizeBytes
		}
		manifest.TotalRecords += file.RecordsProcessed
		manifest.TotalChunks += len(file.NormalizedChunks)
	}
}
