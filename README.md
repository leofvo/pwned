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
  - provenance lookup by `record_id`
  - export command (`json` / `csv`)
  - ingest status command
  - resumable import (`--resume-ingest-id`) with upload retry policy
  - local + remote ingestion manifest creation

## Important

- `./leaks` and `./bot` are preserved.
- Legacy root files were backed up to `./old/legacy-20260320-162135`.

## Installation

### Option 1: Download prebuilt binaries from GitHub Releases

New tags automatically trigger a release with these binaries:

- `pwned-<tag>-linux-amd64`
- `pwned-<tag>-linux-aarch64`
- `pwned-<tag>-darwin-amd64`
- `pwned-<tag>-darwin-aarch64`

Install from a specific tag:

```bash
TAG=v0.1.0
OS=linux      # linux or darwin
ARCH=amd64    # amd64 or aarch64

curl -fL "https://github.com/LeoFVO/pwned/releases/download/${TAG}/pwned-${TAG}-${OS}-${ARCH}" -o pwned
chmod +x pwned
sudo mv pwned /usr/local/bin/pwned
pwned help
```

### Option 2: Install with Go

Requires Go 1.23+.

Install latest:

```bash
go install github.com/leofvo/pwned/cmd/pwned@latest
```

Install a specific version:

```bash
go install github.com/leofvo/pwned/cmd/pwned@v0.1.0
```

Ensure your Go bin directory is on `PATH`:

```bash
export PATH="$(go env GOPATH)/bin:$PATH"
```

## Commands

Build:

```bash
just build
```

Show CLI help:

```bash
just run-help
```

Start Telegram bot (uses `TELEGRAM_BOT_TOKEN` env or `--token`):

```bash
./bin/pwned bot start --platform telegram --token "<your-token>"
```

Check bot status:

```bash
./bin/pwned bot status --platform telegram
```

Stop Telegram bot:

```bash
./bin/pwned bot stop --platform telegram
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

Import CSV with existing header row but force your own mapping:

```bash
./bin/pwned import \
  --input ./dump-with-bad-header.csv \
  --source breach-2026 \
  --format csv \
  --csv-headers phone,id,firstname,lastname,gender,address
```

Resume a failed import:

```bash
./bin/pwned import --resume-ingest-id <ingest-id>
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

Lookup provenance by `record_id`:

```bash
./bin/pwned provenance --record-id <record-id> --json
```

Show ingest status:

```bash
./bin/pwned ingest status --all --json
# alias
./bin/pwned ingest-status --all --json
```

Export query results to CSV:

```bash
./bin/pwned export --where firstname=john --where lastname=doe --match all --format csv --output ./exports/john-doe.csv
```

Show canonical field mapping:

```bash
./bin/pwned mapping
./bin/pwned mapping --json
```

`just` shortcuts:

```bash
just bot-start
just bot-status
just bot-stop
```

Legacy standalone bot notes remain in `./bot/README.md`.

## Environment

Copy and adjust values from `.env.example`.

Required keys:

- `PWNED_S3_ENDPOINT`
- `PWNED_S3_ACCESS_KEY`
- `PWNED_S3_SECRET_KEY`
- `PWNED_S3_BUCKET`
- `PWNED_QUICKWIT_BASE_URL`
- `PWNED_QUICKWIT_INDEX_ID`
- `PWNED_QUICKWIT_HTTP_TIMEOUT`
- `PWNED_UPLOAD_MAX_RETRIES`
- `PWNED_UPLOAD_RETRY_BASE_DELAY`
- `PWNED_UPLOAD_RETRY_MAX_DELAY`

Optional for bot:

- `TELEGRAM_BOT_TOKEN`

## Local Directories

- `.cache/`: local build caches (`go build`, `go test`, module downloads).
- `.state/`: runtime ingestion state (manifests + normalized local chunks).

Default runtime paths:

- `PWNED_MANIFEST_LOCAL_DIR=.state/manifests`
- `PWNED_NORMALIZED_LOCAL_DIR=.state/normalized`

## CSV Without Headers

If the file has no header line, pass:

- `--csv-no-header`
- `--csv-headers col1,col2,col3,...`

The order in `--csv-headers` must match the order of values in each CSV row.

If a file has a header row but names are wrong, pass only `--csv-headers ...` (without `--csv-no-header`).
The importer will still skip the first line and use your provided names.

`--csv-header` (singular) is accepted as an alias of `--csv-headers`.

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

Address handling:

- if `address` (or aliases like `street_address`, `address_line1`) exists, it is used directly
- if not, importer tries to compose `address` from split fields (`street`, `postal_code`/`zip`, `city`, `state`, `country`, etc.)

## Meaning Of `index`

`index` reads completed local ingest manifests from `.state/manifests`, then sends each normalized NDJSON chunk listed in those manifests to Quickwit ingest API.

Behavior:

- default: index the most recent completed ingest
- `--ingest-id`: index one specific ingest
- `--source --all`: index all completed ingests for a source
- `--create-index=true`: create the Quickwit index from `leaks.yml` before ingesting chunks

For large backfills, set `PWNED_QUICKWIT_COMMIT_MODE=auto` and increase `PWNED_QUICKWIT_HTTP_TIMEOUT` (for example `5m`).

## Notes

- Use only data you are legally authorized to process.
