package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Env                  string
	LogLevel             string
	AuditEnabled         bool
	AuditLogPath         string
	S3Endpoint           string
	S3AccessKey          string
	S3SecretKey          string
	S3Region             string
	S3Bucket             string
	S3UseSSL             bool
	S3AutoCreateBucket   bool
	ManifestLocalDir     string
	NormalizedLocalDir   string
	ChunkMaxBytes        int64
	ChunkMaxRecords      int
	ParserMaxLineBytes   int
	QuickwitBaseURL      string
	QuickwitIndexID      string
	QuickwitIndexConfig  string
	QuickwitCommitMode   string
	QuickwitAutoCreate   bool
	QuickwitHTTPTimeout  time.Duration
	UploadMaxRetries     int
	UploadRetryBaseDelay time.Duration
	UploadRetryMaxDelay  time.Duration
	CommandTimeout       time.Duration
}

func LoadFromEnv() (Config, error) {
	cfg := Config{
		Env:                  getEnv("PWNED_ENV", "dev"),
		LogLevel:             strings.ToLower(getEnv("PWNED_LOG_LEVEL", "info")),
		AuditEnabled:         mustParseBool("PWNED_AUDIT_ENABLED", true),
		AuditLogPath:         strings.TrimSpace(getEnv("PWNED_AUDIT_LOG_PATH", ".state/audit/events.jsonl")),
		S3Endpoint:           strings.TrimSpace(getEnv("PWNED_S3_ENDPOINT", "http://127.0.0.1:9000")),
		S3AccessKey:          strings.TrimSpace(getEnv("PWNED_S3_ACCESS_KEY", "minio")),
		S3SecretKey:          strings.TrimSpace(getEnv("PWNED_S3_SECRET_KEY", "minio123")),
		S3Region:             strings.TrimSpace(getEnv("PWNED_S3_REGION", "us-east-1")),
		S3Bucket:             strings.TrimSpace(getEnv("PWNED_S3_BUCKET", "leaks")),
		S3UseSSL:             mustParseBool("PWNED_S3_USE_SSL", false),
		S3AutoCreateBucket:   mustParseBool("PWNED_S3_AUTO_CREATE_BUCKET", true),
		ManifestLocalDir:     strings.TrimSpace(getEnv("PWNED_MANIFEST_LOCAL_DIR", ".state/manifests")),
		NormalizedLocalDir:   strings.TrimSpace(getEnv("PWNED_NORMALIZED_LOCAL_DIR", ".state/normalized")),
		ChunkMaxBytes:        mustParseInt64("PWNED_CHUNK_MAX_BYTES", 8*1024*1024),
		ChunkMaxRecords:      mustParseInt("PWNED_CHUNK_MAX_RECORDS", 50000),
		ParserMaxLineBytes:   mustParseInt("PWNED_PARSER_MAX_LINE_BYTES", 16*1024*1024),
		QuickwitBaseURL:      strings.TrimSpace(getEnv("PWNED_QUICKWIT_BASE_URL", "http://127.0.0.1:7280")),
		QuickwitIndexID:      strings.TrimSpace(getEnv("PWNED_QUICKWIT_INDEX_ID", "leaks")),
		QuickwitIndexConfig:  strings.TrimSpace(getEnv("PWNED_QUICKWIT_INDEX_CONFIG", "leaks.yml")),
		QuickwitCommitMode:   strings.TrimSpace(getEnv("PWNED_QUICKWIT_COMMIT_MODE", "wait_for")),
		QuickwitAutoCreate:   mustParseBool("PWNED_QUICKWIT_AUTO_CREATE_INDEX", true),
		QuickwitHTTPTimeout:  mustParseDuration("PWNED_QUICKWIT_HTTP_TIMEOUT", 5*time.Minute),
		UploadMaxRetries:     mustParseInt("PWNED_UPLOAD_MAX_RETRIES", 3),
		UploadRetryBaseDelay: mustParseDuration("PWNED_UPLOAD_RETRY_BASE_DELAY", 250*time.Millisecond),
		UploadRetryMaxDelay:  mustParseDuration("PWNED_UPLOAD_RETRY_MAX_DELAY", 3*time.Second),
		CommandTimeout:       mustParseDuration("PWNED_COMMAND_TIMEOUT", 30*time.Minute),
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func (c Config) Validate() error {
	if c.S3Endpoint == "" {
		return fmt.Errorf("missing PWNED_S3_ENDPOINT")
	}
	if c.AuditEnabled && c.AuditLogPath == "" {
		return fmt.Errorf("missing PWNED_AUDIT_LOG_PATH")
	}
	if c.S3AccessKey == "" {
		return fmt.Errorf("missing PWNED_S3_ACCESS_KEY")
	}
	if c.S3SecretKey == "" {
		return fmt.Errorf("missing PWNED_S3_SECRET_KEY")
	}
	if c.S3Bucket == "" {
		return fmt.Errorf("missing PWNED_S3_BUCKET")
	}
	if c.ManifestLocalDir == "" {
		return fmt.Errorf("missing PWNED_MANIFEST_LOCAL_DIR")
	}
	if c.NormalizedLocalDir == "" {
		return fmt.Errorf("missing PWNED_NORMALIZED_LOCAL_DIR")
	}
	if c.ChunkMaxBytes <= 0 {
		return fmt.Errorf("PWNED_CHUNK_MAX_BYTES must be > 0")
	}
	if c.ChunkMaxBytes > 9*1024*1024 {
		return fmt.Errorf("PWNED_CHUNK_MAX_BYTES must be <= 9437184 to stay below Quickwit ingest 10MB limit")
	}
	if c.ChunkMaxRecords <= 0 {
		return fmt.Errorf("PWNED_CHUNK_MAX_RECORDS must be > 0")
	}
	if c.ParserMaxLineBytes <= 0 {
		return fmt.Errorf("PWNED_PARSER_MAX_LINE_BYTES must be > 0")
	}
	if c.QuickwitBaseURL == "" {
		return fmt.Errorf("missing PWNED_QUICKWIT_BASE_URL")
	}
	if c.QuickwitIndexID == "" {
		return fmt.Errorf("missing PWNED_QUICKWIT_INDEX_ID")
	}
	if c.QuickwitIndexConfig == "" {
		return fmt.Errorf("missing PWNED_QUICKWIT_INDEX_CONFIG")
	}
	switch c.QuickwitCommitMode {
	case "auto", "wait_for", "force":
	default:
		return fmt.Errorf("PWNED_QUICKWIT_COMMIT_MODE must be one of auto|wait_for|force")
	}
	if c.QuickwitHTTPTimeout <= 0 {
		return fmt.Errorf("PWNED_QUICKWIT_HTTP_TIMEOUT must be > 0")
	}
	if c.UploadMaxRetries < 0 {
		return fmt.Errorf("PWNED_UPLOAD_MAX_RETRIES must be >= 0")
	}
	if c.UploadRetryBaseDelay <= 0 {
		return fmt.Errorf("PWNED_UPLOAD_RETRY_BASE_DELAY must be > 0")
	}
	if c.UploadRetryMaxDelay < c.UploadRetryBaseDelay {
		return fmt.Errorf("PWNED_UPLOAD_RETRY_MAX_DELAY must be >= PWNED_UPLOAD_RETRY_BASE_DELAY")
	}
	if c.CommandTimeout <= 0 {
		return fmt.Errorf("PWNED_COMMAND_TIMEOUT must be > 0")
	}
	return nil
}

func getEnv(key string, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func mustParseBool(key string, fallback bool) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback
	}
	return parsed
}

func mustParseDuration(key string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil {
		return fallback
	}
	return parsed
}

func mustParseInt(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return parsed
}

func mustParseInt64(key string, fallback int64) int64 {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	parsed, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return fallback
	}
	return parsed
}
