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

	"github.com/leofvo/pwned/internal/config"
	"github.com/leofvo/pwned/internal/importer"
	"github.com/leofvo/pwned/internal/indexer"
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
	csvHeaders := fs.String("csv-headers", "", "Comma-separated CSV column names when --csv-no-header is set")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if strings.TrimSpace(*inputPath) == "" {
		return errors.New("missing required --input")
	}
	if strings.TrimSpace(*source) == "" {
		return errors.New("missing required --source")
	}

	svc, err := importer.NewService(a.cfg, a.logger)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), a.cfg.CommandTimeout)
	defer cancel()

	result, err := svc.Import(ctx, importer.Options{
		InputPath:   *inputPath,
		Source:      *source,
		Format:      *format,
		Tag:         *tag,
		Recursive:   *recursive,
		MaxMemory:   *maxMemory,
		CSVNoHeader: *csvNoHeader,
		CSVHeaders:  parseCSVHeaders(*csvHeaders),
		RawStorage:  "s3",
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
  pwned import --input <path> --source <name> [--format auto] [--tag <tag>] [--recursive] [--max-memory 256MiB] [--csv-no-header --csv-headers col1,col2,...]
  pwned index [--ingest-id <id>] [--source <name>] [--all] [--create-index=true]
  pwned search [--where key=value ...] [--match all|any] [--limit N] [--reveal-sensitive] [--json]
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
