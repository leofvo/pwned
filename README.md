# Pwned (Rebuild v1)

CLI-first leak ingestion and search engine for personal cybersecurity research.

## Status

- Rebuild in progress.
- Phase 0 specs are in `./specs`.
- Phase 1 + Phase 2 scaffold is implemented:
  - Go CLI entrypoint
  - environment-based config (12-factor style)
  - structured JSON logging
  - streaming raw ingest to S3-compatible storage (MinIO)
  - format adapters (`csv`, `txt`, `json`, `ndjson`)
  - canonical normalization + chunked NDJSON outputs
  - Quickwit indexing command from local ingestion manifests
  - mapped search command with combinable filters
  - local + remote ingestion manifest creation

## Important

- `./leaks` and `./bot` are preserved.
- Legacy root files were backed up to `./old/legacy-20260320-162135`.

## Commands

Build:

```bash
just build
```

Show CLI help:

```bash
just run-help
```

Start local MinIO + Quickwit:

```bash
just infra-start
```

Import a single file:

```bash
./bin/pwned import --input ./some-dump.csv --source breach-2026
```

Import a folder recursively:

```bash
./bin/pwned import --input ./dumps --source multi-source --recursive
```

Import CSV without header row:

```bash
./bin/pwned import \
  --input ./dump-no-header.csv \
  --source breach-2026 \
  --format csv \
  --csv-no-header \
  --csv-headers email,password,firstname,lastname,phone,address
```

Index latest completed ingest:

```bash
./bin/pwned index
```

Index all completed ingests for a source:

```bash
./bin/pwned index --source multi-source --all
```

Search with one mapped field:

```bash
./bin/pwned search --where firstname=john
```

Search with combined mapped fields:

```bash
./bin/pwned search --where firstname=john --where lastname=doe --match all
```

Search and reveal sensitive fields:

```bash
./bin/pwned search --where email=john@doe.com --reveal-sensitive --json
```

Show canonical field mapping:

```bash
./bin/pwned mapping
./bin/pwned mapping --json
```

## Environment

Copy and adjust values from `.env.example`.

Required keys:

- `PWNED_S3_ENDPOINT`
- `PWNED_S3_ACCESS_KEY`
- `PWNED_S3_SECRET_KEY`
- `PWNED_S3_BUCKET`
- `PWNED_QUICKWIT_BASE_URL`
- `PWNED_QUICKWIT_INDEX_ID`

## CSV Without Headers

If the file has no header line, pass:

- `--csv-no-header`
- `--csv-headers col1,col2,col3,...`

The order in `--csv-headers` must match the order of values in each CSV row.

## Canonical Mapping

`import` normalizes input fields into canonical keys used for indexing.
Use `./bin/pwned mapping` to print supported canonical keys and accepted aliases.

Important canonical fields include:

- `email`
- `phone`
- `username`
- `firstname`
- `lastname`
- `address`
- `password`
- `password_hash`
- `ip`

## Meaning Of `index`

`index` reads completed local ingest manifests from `.state/manifests`, then sends each normalized NDJSON chunk listed in those manifests to Quickwit ingest API.

Behavior:

- default: index the most recent completed ingest
- `--ingest-id`: index one specific ingest
- `--source --all`: index all completed ingests for a source
- `--create-index=true`: create the Quickwit index from `leaks.yml` before ingesting chunks

## Notes

- Use only data you are legally authorized to process.
