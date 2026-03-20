package miniostore

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/leofvo/pwned/internal/config"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

type Client struct {
	client *minio.Client
	bucket string
	autoMk bool
	region string
}

func New(cfg config.Config) (*Client, error) {
	endpoint, secure, err := normalizeEndpoint(cfg.S3Endpoint, cfg.S3UseSSL)
	if err != nil {
		return nil, err
	}

	minioClient, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.S3AccessKey, cfg.S3SecretKey, ""),
		Secure: secure,
		Region: cfg.S3Region,
	})
	if err != nil {
		return nil, fmt.Errorf("create minio client: %w", err)
	}

	return &Client{
		client: minioClient,
		bucket: cfg.S3Bucket,
		autoMk: cfg.S3AutoCreateBucket,
		region: cfg.S3Region,
	}, nil
}

func (c *Client) EnsureBucket(ctx context.Context) error {
	exists, err := c.client.BucketExists(ctx, c.bucket)
	if err != nil {
		return fmt.Errorf("check bucket %q: %w", c.bucket, err)
	}
	if exists {
		return nil
	}
	if !c.autoMk {
		return fmt.Errorf("bucket %q does not exist and auto-create is disabled", c.bucket)
	}

	if err := c.client.MakeBucket(ctx, c.bucket, minio.MakeBucketOptions{Region: c.region}); err != nil {
		return fmt.Errorf("create bucket %q: %w", c.bucket, err)
	}

	return nil
}

func (c *Client) PutObject(ctx context.Context, objectKey string, body io.Reader, size int64, contentType string) error {
	_, err := c.client.PutObject(ctx, c.bucket, objectKey, body, size, minio.PutObjectOptions{
		ContentType: contentType,
	})
	if err != nil {
		return fmt.Errorf("put object %q: %w", objectKey, err)
	}
	return nil
}

func normalizeEndpoint(endpoint string, fallbackSecure bool) (string, bool, error) {
	raw := strings.TrimSpace(endpoint)
	raw = strings.TrimSuffix(raw, "/")
	if raw == "" {
		return "", false, fmt.Errorf("empty endpoint")
	}

	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		parsed, err := url.Parse(raw)
		if err != nil {
			return "", false, fmt.Errorf("parse endpoint %q: %w", raw, err)
		}
		if parsed.Host == "" {
			return "", false, fmt.Errorf("invalid endpoint %q: missing host", raw)
		}
		return parsed.Host, parsed.Scheme == "https", nil
	}

	return raw, fallbackSecure, nil
}
