package storage

import (
	"context"
	"io"
)

type Client interface {
	EnsureBucket(ctx context.Context) error
	PutObject(ctx context.Context, objectKey string, body io.Reader, size int64, contentType string) error
}
