package importer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type Options struct {
	InputPath      string
	Source         string
	Format         string
	Tag            string
	Recursive      bool
	MaxMemory      string
	CSVNoHeader    bool
	CSVHeaders     []string
	ResumeIngestID string
	RawStorage     string
}

type Result struct {
	IngestID          string `json:"ingest_id"`
	Source            string `json:"source"`
	FilesProcessed    int    `json:"files_processed"`
	BytesProcessed    int64  `json:"bytes_processed"`
	RecordsProcessed  int64  `json:"records_processed"`
	NormalizedObjects int    `json:"normalized_objects"`
	ManifestObjectKey string `json:"manifest_object_key"`
	LocalManifestPath string `json:"local_manifest_path"`
}

type Manifest struct {
	IngestID          string         `json:"ingest_id"`
	Source            string         `json:"source"`
	Tag               string         `json:"tag,omitempty"`
	InputPath         string         `json:"input_path"`
	Format            string         `json:"format"`
	MaxMemory         string         `json:"max_memory"`
	StartedAt         time.Time      `json:"started_at"`
	ResumedAt         *time.Time     `json:"resumed_at,omitempty"`
	CompletedAt       time.Time      `json:"completed_at"`
	Status            string         `json:"status"`
	Files             []ManifestFile `json:"files"`
	TotalFiles        int            `json:"total_files"`
	TotalBytes        int64          `json:"total_bytes"`
	TotalRecords      int64          `json:"total_records"`
	TotalChunks       int            `json:"total_chunks"`
	RawStorage        string         `json:"raw_storage"`
	NormalizedStorage string         `json:"normalized_storage"`
	Parser            string         `json:"parser"`
	ParserVer         string         `json:"parser_version"`
	ErrorMessage      string         `json:"error_message,omitempty"`
}

type ManifestFile struct {
	RelativePath     string          `json:"relative_path"`
	SizeBytes        int64           `json:"size_bytes"`
	DetectedFormat   string          `json:"detected_format"`
	RawObjectKey     string          `json:"raw_object_key,omitempty"`
	SHA256           string          `json:"sha256,omitempty"`
	RecordsProcessed int64           `json:"records_processed"`
	LastCheckpoint   string          `json:"last_checkpoint,omitempty"`
	NormalizedChunks []ManifestChunk `json:"normalized_chunks,omitempty"`
	Status           string          `json:"status"`
	StartedAt        time.Time       `json:"started_at,omitempty"`
	CompletedAt      time.Time       `json:"completed_at,omitempty"`
	ErrorMessage     string          `json:"error_message,omitempty"`
}

type ManifestChunk struct {
	Part        int    `json:"part"`
	LocalPath   string `json:"local_path"`
	ObjectKey   string `json:"object_key"`
	RecordCount int64  `json:"record_count"`
	SizeBytes   int64  `json:"size_bytes"`
}

type inputFile struct {
	absPath string
	relPath string
	size    int64
}

func (o Options) validate() error {
	resumeMode := strings.TrimSpace(o.ResumeIngestID) != ""
	if strings.TrimSpace(o.InputPath) == "" && !resumeMode {
		return fmt.Errorf("input path is required")
	}
	if strings.TrimSpace(o.Source) == "" && !resumeMode {
		return fmt.Errorf("source is required")
	}
	if strings.TrimSpace(o.Format) == "" {
		return fmt.Errorf("format is required")
	}
	if strings.TrimSpace(o.MaxMemory) == "" {
		return fmt.Errorf("max memory is required")
	}
	if len(o.CSVHeaders) > 0 && !o.CSVNoHeader {
		return fmt.Errorf("--csv-headers requires --csv-no-header")
	}
	if o.CSVNoHeader && len(o.CSVHeaders) == 0 {
		return fmt.Errorf("--csv-no-header requires --csv-headers")
	}
	return nil
}

func LoadManifest(path string) (Manifest, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("read manifest %q: %w", path, err)
	}

	var manifest Manifest
	if err := json.Unmarshal(payload, &manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode manifest %q: %w", path, err)
	}
	return manifest, nil
}

func ListManifestPaths(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read manifest directory %q: %w", dir, err)
	}

	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		paths = append(paths, filepath.Join(dir, entry.Name()))
	}

	sort.Strings(paths)
	return paths, nil
}
