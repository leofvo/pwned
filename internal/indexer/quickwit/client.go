package quickwit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type Client struct {
	baseURL string
	client  *http.Client
}

type SearchResponse struct {
	NumHits           int64            `json:"num_hits"`
	Hits              []map[string]any `json:"hits"`
	ElapsedTimeMicros int64            `json:"elapsed_time_micros"`
	Errors            []string         `json:"errors"`
}

func New(baseURL string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	return &Client{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

func (c *Client) CreateIndexFromConfigFile(ctx context.Context, indexConfigPath string) error {
	payload, err := os.ReadFile(indexConfigPath)
	if err != nil {
		return fmt.Errorf("read quickwit index config %q: %w", indexConfigPath, err)
	}

	u := c.baseURL + "/api/v1/indexes"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build create index request: %w", err)
	}
	req.Header.Set("Content-Type", "application/yaml")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("create index request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	msg := strings.ToLower(string(body))
	if resp.StatusCode == http.StatusConflict || strings.Contains(msg, "already exists") || strings.Contains(msg, "already exist") {
		return nil
	}

	return fmt.Errorf("create index failed with status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
}

func (c *Client) IngestNDJSONFile(ctx context.Context, indexID string, ndjsonPath string, commitMode string) (int64, error) {
	payload, err := os.ReadFile(ndjsonPath)
	if err != nil {
		return 0, fmt.Errorf("read chunk %q: %w", ndjsonPath, err)
	}
	return c.IngestNDJSONBytes(ctx, indexID, payload, commitMode)
}

func (c *Client) IngestNDJSONBytes(ctx context.Context, indexID string, payload []byte, commitMode string) (int64, error) {
	if len(payload) == 0 {
		return 0, nil
	}

	endpoint := fmt.Sprintf(
		"%s/api/v1/%s/ingest?commit=%s",
		c.baseURL,
		url.PathEscape(indexID),
		url.QueryEscape(commitMode),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return 0, fmt.Errorf("build ingest request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-ndjson")

	resp, err := c.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("send ingest request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, fmt.Errorf("ingest failed with status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return 0, nil
	}

	for _, key := range []string{"num_docs_for_processing", "num_docs", "num_ingested_docs"} {
		if value, ok := parsed[key]; ok {
			switch typed := value.(type) {
			case float64:
				return int64(typed), nil
			case int64:
				return typed, nil
			}
		}
	}
	return 0, nil
}

func (c *Client) Search(ctx context.Context, indexID string, query string, limit int, offset int) (SearchResponse, error) {
	requestBody := map[string]any{
		"query":        strings.TrimSpace(query),
		"max_hits":     limit,
		"start_offset": offset,
	}
	payload, err := json.Marshal(requestBody)
	if err != nil {
		return SearchResponse{}, fmt.Errorf("marshal search request: %w", err)
	}

	endpoint := fmt.Sprintf("%s/api/v1/%s/search", c.baseURL, url.PathEscape(indexID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return SearchResponse{}, fmt.Errorf("build search request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return SearchResponse{}, fmt.Errorf("send search request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return SearchResponse{}, fmt.Errorf("search failed with status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var out SearchResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return SearchResponse{}, fmt.Errorf("decode search response: %w", err)
	}
	return out, nil
}
