package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/leofvo/pwned/internal/config"
	"github.com/leofvo/pwned/internal/exporter"
	"github.com/leofvo/pwned/internal/importer"
	"github.com/leofvo/pwned/internal/indexer"
	"github.com/leofvo/pwned/internal/ingeststatus"
	"github.com/leofvo/pwned/internal/provenance"
	searchsvc "github.com/leofvo/pwned/internal/search"
)

const version = "0.1.0"

type App struct {
	cfg    config.Config
	logger *slog.Logger
	stdout io.Writer
	stderr io.Writer
}

func New(cfg config.Config, logger *slog.Logger, stdout io.Writer, stderr io.Writer) *App {
	return &App{
		cfg:    cfg,
		logger: logger,
		stdout: stdout,
		stderr: stderr,
	}
}

func (a *App) Run(args []string) error {
	if len(args) == 0 {
		return a.printUsage(nil)
	}

	switch args[0] {
	case "import":
		return a.runImport(args[1:])
	case "index":
		return a.runIndex(args[1:])
	case "search":
		return a.runSearch(args[1:])
	case "export":
		return a.runExport(args[1:])
	case "provenance":
		return a.runProvenance(args[1:])
	case "ingest":
		return a.runIngest(args[1:])
	case "ingest-status":
		return a.runIngestStatus(args[1:])
	case "mapping":
		return a.runMapping(args[1:])
	case "version":
		_, err := fmt.Fprintf(a.stdout, "pwned %s\n", version)
		return err
	case "help", "-h", "--help":
		return a.printUsage(nil)
	default:
		return a.printUsage(fmt.Errorf("unknown command %q", args[0]))
	}
}

func (a *App) runImport(args []string) error {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	fs.SetOutput(a.stderr)

	inputPath := fs.String("input", "", "File or folder path to import")
	source := fs.String("source", "", "Source name for provenance tracking")
	format := fs.String("format", "auto", "Input format: auto|csv|txt|json|ndjson")
	tag := fs.String("tag", "", "Optional source tag")
	recursive := fs.Bool("recursive", false, "Enable recursive walk when --input is a directory")
	maxMemory := fs.String("max-memory", "256MiB", "Memory budget hint for ingestion pipeline")
	csvNoHeader := fs.Bool("csv-no-header", false, "Treat CSV input as data-only rows without header line")
	csvHeaders := fs.String("csv-headers", "", "Comma-separated CSV column names; with header row this overrides bad headers, with --csv-no-header this defines headers")
	csvHeader := fs.String("csv-header", "", "Alias of --csv-headers")
	resumeIngestID := fs.String("resume-ingest-id", "", "Resume a failed import from an existing ingest id")

	if err := fs.Parse(args); err != nil {
		return err
	}

	resumeMode := strings.TrimSpace(*resumeIngestID) != ""
	if strings.TrimSpace(*inputPath) == "" && !resumeMode {
		return errors.New("missing required --input")
	}
	if strings.TrimSpace(*source) == "" && !resumeMode {
		return errors.New("missing required --source")
	}
	headersValue := strings.TrimSpace(*csvHeaders)
	singularHeadersValue := strings.TrimSpace(*csvHeader)
	if headersValue != "" && singularHeadersValue != "" && headersValue != singularHeadersValue {
		return errors.New("use either --csv-headers or --csv-header with the same value")
	}
	if headersValue == "" {
		headersValue = singularHeadersValue
	}

	svc, err := importer.NewService(a.cfg, a.logger)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), a.cfg.CommandTimeout)
	defer cancel()

	result, err := svc.Import(ctx, importer.Options{
		InputPath:      *inputPath,
		Source:         *source,
		Format:         *format,
		Tag:            *tag,
		Recursive:      *recursive,
		MaxMemory:      *maxMemory,
		CSVNoHeader:    *csvNoHeader,
		CSVHeaders:     parseCSVHeaders(headersValue),
		ResumeIngestID: *resumeIngestID,
		RawStorage:     "s3",
	})
	if err != nil {
		return err
	}

	return writeJSON(a.stdout, result)
}

func (a *App) runIndex(args []string) error {
	fs := flag.NewFlagSet("index", flag.ContinueOnError)
	fs.SetOutput(a.stderr)

	ingestID := fs.String("ingest-id", "", "Index a specific ingest id")
	source := fs.String("source", "", "Index all completed ingests for a source")
	all := fs.Bool("all", false, "Index all matching completed ingests")
	rebuild := fs.Bool("rebuild", false, "Reserved flag for future full reindex flow")
	createIndex := fs.Bool("create-index", a.cfg.QuickwitAutoCreate, "Create Quickwit index from config if needed")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *rebuild {
		a.logger.Warn("rebuild flag is currently a no-op in v1 scaffold")
	}

	svc := indexer.NewService(a.cfg, a.logger)

	ctx, cancel := context.WithTimeout(context.Background(), a.cfg.CommandTimeout)
	defer cancel()

	result, err := svc.Index(ctx, indexer.Options{
		IngestID:    *ingestID,
		Source:      *source,
		All:         *all,
		CreateIndex: *createIndex,
	})
	if err != nil {
		return err
	}

	return writeJSON(a.stdout, result)
}

func (a *App) runSearch(args []string) error {
	fs := flag.NewFlagSet("search", flag.ContinueOnError)
	fs.SetOutput(a.stderr)

	rawQuery := fs.String("query", "", "Optional raw Quickwit query expression")
	match := fs.String("match", "all", "How to combine filters: all|any")
	limit := fs.Int("limit", 20, "Maximum number of hits")
	offset := fs.Int("offset", 0, "Pagination start offset")
	revealSensitive := fs.Bool("reveal-sensitive", false, "Reveal sensitive fields in output")
	jsonOut := fs.Bool("json", false, "Print response as JSON")
	createIndex := fs.Bool("create-index", false, "Create index from config before search")

	var filters multiStringFlag
	fs.Var(&filters, "where", "Mapped filter expression key=value (repeatable)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	svc := searchsvc.NewService(a.cfg, a.logger)
	ctx, cancel := context.WithTimeout(context.Background(), a.cfg.CommandTimeout)
	defer cancel()

	result, err := svc.Search(ctx, searchsvc.Options{
		RawQuery:        *rawQuery,
		Filters:         []string(filters),
		Match:           *match,
		Limit:           *limit,
		Offset:          *offset,
		RevealSensitive: *revealSensitive,
		CreateIndex:     *createIndex,
		IndexConfigPath: a.cfg.QuickwitIndexConfig,
	})
	if err != nil {
		return err
	}

	if *jsonOut {
		return writeJSON(a.stdout, result)
	}
	return writeSearchResult(a.stdout, result)
}

func (a *App) runExport(args []string) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	fs.SetOutput(a.stderr)

	rawQuery := fs.String("query", "", "Optional raw Quickwit query expression")
	match := fs.String("match", "all", "How to combine filters: all|any")
	limit := fs.Int("limit", 1000, "Maximum number of hits to export")
	offset := fs.Int("offset", 0, "Pagination start offset")
	revealSensitive := fs.Bool("reveal-sensitive", false, "Reveal sensitive fields in export output")
	format := fs.String("format", "json", "Export format: json|csv")
	outputPath := fs.String("output", "", "Required output file path")
	createIndex := fs.Bool("create-index", false, "Create index from config before export")

	var filters multiStringFlag
	fs.Var(&filters, "where", "Mapped filter expression key=value (repeatable)")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*outputPath) == "" {
		return errors.New("missing required --output")
	}

	svc := exporter.NewService(a.cfg, a.logger)
	ctx, cancel := context.WithTimeout(context.Background(), a.cfg.CommandTimeout)
	defer cancel()

	result, err := svc.Export(ctx, exporter.Options{
		RawQuery:        *rawQuery,
		Filters:         []string(filters),
		Match:           *match,
		Limit:           *limit,
		Offset:          *offset,
		RevealSensitive: *revealSensitive,
		Format:          *format,
		OutputPath:      *outputPath,
		CreateIndex:     *createIndex,
	})
	if err != nil {
		return err
	}

	return writeJSON(a.stdout, result)
}

func (a *App) runProvenance(args []string) error {
	fs := flag.NewFlagSet("provenance", flag.ContinueOnError)
	fs.SetOutput(a.stderr)

	recordID := fs.String("record-id", "", "Record id to inspect")
	limit := fs.Int("limit", 20, "Maximum number of hits")
	revealSensitive := fs.Bool("reveal-sensitive", false, "Reveal sensitive fields in output")
	jsonOut := fs.Bool("json", false, "Print response as JSON")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*recordID) == "" {
		return errors.New("missing required --record-id")
	}

	svc := provenance.NewService(a.cfg, a.logger)
	ctx, cancel := context.WithTimeout(context.Background(), a.cfg.CommandTimeout)
	defer cancel()

	result, err := svc.Lookup(ctx, provenance.Options{
		RecordID:        *recordID,
		Limit:           *limit,
		RevealSensitive: *revealSensitive,
	})
	if err != nil {
		return err
	}

	if *jsonOut {
		return writeJSON(a.stdout, result)
	}
	return writeProvenanceResult(a.stdout, result)
}

func (a *App) runIngest(args []string) error {
	if len(args) == 0 {
		return a.runIngestStatus(nil)
	}

	switch strings.TrimSpace(args[0]) {
	case "status":
		return a.runIngestStatus(args[1:])
	default:
		if strings.HasPrefix(args[0], "-") {
			return a.runIngestStatus(args)
		}
		return fmt.Errorf("unknown ingest subcommand %q", args[0])
	}
}

func (a *App) runIngestStatus(args []string) error {
	fs := flag.NewFlagSet("ingest-status", flag.ContinueOnError)
	fs.SetOutput(a.stderr)

	ingestID := fs.String("ingest-id", "", "Show one ingest by id")
	source := fs.String("source", "", "Filter by source")
	all := fs.Bool("all", false, "Show all matching manifests")
	jsonOut := fs.Bool("json", false, "Print response as JSON")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*ingestID) != "" && (strings.TrimSpace(*source) != "" || *all) {
		return errors.New("--ingest-id cannot be combined with --source or --all")
	}

	svc := ingeststatus.NewService(a.cfg, a.logger)
	ctx, cancel := context.WithTimeout(context.Background(), a.cfg.CommandTimeout)
	defer cancel()

	result, err := svc.Status(ctx, ingeststatus.Options{
		IngestID: *ingestID,
		Source:   *source,
		All:      *all,
	})
	if err != nil {
		return err
	}

	if *jsonOut {
		return writeJSON(a.stdout, result)
	}
	return writeIngestStatusResult(a.stdout, result)
}

func (a *App) runMapping(args []string) error {
	fs := flag.NewFlagSet("mapping", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	asJSON := fs.Bool("json", false, "Print mapping in JSON format")
	if err := fs.Parse(args); err != nil {
		return err
	}

	mappings := importer.CanonicalFieldMappings()
	if *asJSON {
		return writeJSON(a.stdout, mappings)
	}

	for _, mapping := range mappings {
		if _, err := fmt.Fprintf(a.stdout, "%s: %s\n", mapping.Canonical, strings.Join(mapping.Aliases, ", ")); err != nil {
			return err
		}
	}
	return nil
}

func (a *App) printUsage(baseErr error) error {
	if baseErr != nil {
		if _, err := fmt.Fprintf(a.stderr, "%v\n\n", baseErr); err != nil {
			return err
		}
	}

	usage := `Usage:
  pwned import --input <path> --source <name> [--format auto] [--tag <tag>] [--recursive] [--max-memory 256MiB] [--csv-headers col1,col2,...] [--csv-no-header] [--resume-ingest-id <id>]
  pwned index [--ingest-id <id>] [--source <name>] [--all] [--create-index=true]
  pwned search [--where key=value ...] [--match all|any] [--limit N] [--reveal-sensitive] [--json]
  pwned export --output <path> [--format json|csv] [--where key=value ...] [--match all|any] [--limit N] [--reveal-sensitive]
  pwned provenance --record-id <id> [--limit N] [--reveal-sensitive] [--json]
  pwned ingest status [--ingest-id <id> | --source <name> [--all]] [--json]
  pwned ingest-status [--ingest-id <id> | --source <name> [--all]] [--json]
  pwned mapping [--json]
  pwned version
  pwned help

Environment:
  PWNED_S3_ENDPOINT
  PWNED_S3_ACCESS_KEY
  PWNED_S3_SECRET_KEY
  PWNED_S3_BUCKET
  PWNED_QUICKWIT_BASE_URL
  PWNED_QUICKWIT_INDEX_ID
  PWNED_QUICKWIT_HTTP_TIMEOUT
`

	_, err := io.WriteString(a.stdout, usage)
	return err
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func writeSearchResult(w io.Writer, result searchsvc.Result) error {
	if _, err := fmt.Fprintf(w, "query: %s\n", result.Query); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "num_hits: %d\n", result.NumHits); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "returned_hits: %d\n", len(result.Hits)); err != nil {
		return err
	}
	if len(result.Errors) > 0 {
		if _, err := fmt.Fprintf(w, "errors: %s\n", strings.Join(result.Errors, " | ")); err != nil {
			return err
		}
	}

	for i, hit := range result.Hits {
		if _, err := fmt.Fprintf(w, "\n[%d]\n", i+1); err != nil {
			return err
		}

		keys := make([]string, 0, len(hit))
		for key := range hit {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		for _, key := range keys {
			if _, err := fmt.Fprintf(w, "%s: %v\n", key, hit[key]); err != nil {
				return err
			}
		}
	}

	return nil
}

func writeProvenanceResult(w io.Writer, result provenance.Result) error {
	if _, err := fmt.Fprintf(w, "query: %s\n", result.Query); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "num_hits: %d\n", result.NumHits); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "returned_hits: %d\n", result.ReturnedHits); err != nil {
		return err
	}

	for i, record := range result.Records {
		if _, err := fmt.Fprintf(w, "\n[%d]\n", i+1); err != nil {
			return err
		}

		keys := make([]string, 0, len(record.Hit))
		for key := range record.Hit {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		for _, key := range keys {
			if _, err := fmt.Fprintf(w, "%s: %v\n", key, record.Hit[key]); err != nil {
				return err
			}
		}

		if _, err := fmt.Fprintf(w, "manifest_found: %t\n", record.ManifestFound); err != nil {
			return err
		}
		if record.ManifestPath != "" {
			if _, err := fmt.Fprintf(w, "manifest_path: %s\n", record.ManifestPath); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(w, "file_found: %t\n", record.FileFound); err != nil {
			return err
		}
		if record.FileProvenance != nil {
			if _, err := fmt.Fprintf(w, "source_file_status: %s\n", record.FileProvenance.Status); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, "source_file_chunks: %d\n", len(record.FileProvenance.NormalizedChunks)); err != nil {
				return err
			}
		}
	}

	return nil
}

func writeIngestStatusResult(w io.Writer, result ingeststatus.Result) error {
	if len(result.Items) == 0 {
		_, err := fmt.Fprintln(w, "no ingest manifests found")
		return err
	}

	for i, item := range result.Items {
		if i > 0 {
			if _, err := fmt.Fprintln(w); err != nil {
				return err
			}
		}

		if _, err := fmt.Fprintf(w, "ingest_id: %s\n", item.IngestID); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "source: %s\n", item.Source); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "status: %s\n", item.Status); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "started_at: %s\n", item.StartedAt.Format(time.RFC3339)); err != nil {
			return err
		}
		if item.ResumedAt != nil {
			if _, err := fmt.Fprintf(w, "resumed_at: %s\n", item.ResumedAt.Format(time.RFC3339)); err != nil {
				return err
			}
		}
		if !item.CompletedAt.IsZero() {
			if _, err := fmt.Fprintf(w, "completed_at: %s\n", item.CompletedAt.Format(time.RFC3339)); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(w, "files: total=%d completed=%d failed=%d running=%d\n", item.FilesTotal, item.FilesCompleted, item.FilesFailed, item.FilesRunning); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "totals: bytes=%d records=%d chunks=%d\n", item.TotalBytes, item.TotalRecords, item.TotalChunks); err != nil {
			return err
		}
		if item.ErrorMessage != "" {
			if _, err := fmt.Fprintf(w, "error: %s\n", item.ErrorMessage); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(w, "manifest_path: %s\n", item.ManifestPath); err != nil {
			return err
		}
	}

	return nil
}

func parseCSVHeaders(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	headers := make([]string, 0, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value == "" {
			continue
		}
		headers = append(headers, value)
	}
	if len(headers) == 0 {
		return nil
	}
	return headers
}

type multiStringFlag []string

func (m *multiStringFlag) String() string {
	if m == nil {
		return ""
	}
	return strings.Join(*m, ",")
}

func (m *multiStringFlag) Set(value string) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return fmt.Errorf("empty value is not allowed")
	}
	*m = append(*m, trimmed)
	return nil
}
