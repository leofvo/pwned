# Technical Plan (v1 Draft)

## Locked Stack

- Engine language: Go.
- Search backend: Quickwit.
- Blob storage backend in v1: MinIO (S3-compatible).
- Deployment target: containerized, Raspberry Pi compatible.
- Future migration target: AWS S3 with backend-compatible object storage abstraction.

## Recommended v1 Architecture

CLI-first modular engine with explicit pipeline stages:

1. `collector`:
   - validates input files or folders
   - computes checksums
   - captures source metadata
2. `raw-store`:
   - uploads immutable raw dumps to blob storage
   - applies compression and encryption policy
3. `parser-normalizer`:
   - format-specific parsers
   - canonical schema mapping
   - PII field standardization (email/phone/name/domain/ip)
4. `indexer`:
   - batches normalized records into search backend
   - tracks index version and parser version
5. `query`:
   - unified cross-dump search
   - structured filters and relevance options
6. `audit`:
   - operation logs (import/search/export)
   - provenance lookup for each matched record
   - explicit logging when sensitive-field reveal flags are used
7. `interface-adapters`:
   - CLI adapter (primary)
   - Telegram bot adapter (secondary)
   - both use the same query service APIs

## Ingestion Design For Large Files

- Stream-only parsing (no full-file in-memory load).
- Bounded worker pools with fixed-size channels to prevent memory spikes.
- Chunked normalized output written to temporary NDJSON segments, then uploaded.
- Backpressure between parser -> normalizer -> indexer stages.
- Folder ingestion via recursive walk with per-file manifests.
- Resumable ingest checkpoints:
  - per-file byte offset or line checkpoints where format permits
  - failed ingestion can resume without restarting the entire source set
- Safety limits:
  - configurable max open files
  - configurable max concurrency
  - memory budget flag for low-RAM hardware profiles

## Canonical Data Model (Initial)

- `record_id`: deterministic hash
- `source_id`: source dump identifier
- `source_name`
- `ingested_at`
- `parser_version`
- `ingest_id`
- `record_offset`
- `raw_object_uri`
- normalized identity/contact fields:
  - `email`
  - `phone_e164` and `phone_raw`
  - `username`
  - `first_name`
  - `last_name`
  - `ip`
  - `domain`
  - `country`
  - `city`
- `extra`: flexible JSON object for non-canonical fields

## CLI Contract (Proposed)

- `engine import --input <path> --source <name> [--format auto] [--tag <tag>] [--recursive] [--max-memory 256MiB]`
- `engine index [--source <name>] [--rebuild]`
- `engine search --query '<expr>' [--source <name>] [--limit N] [--json] [--reveal-sensitive]`
- `engine provenance --record-id <id>`
- `engine export --query '<expr>' --format csv --out <file> [--reveal-sensitive]`
- `engine storage stats [--by source] [--by month]`
- `engine ingest status --ingest-id <id>`
- Output policy:
  - default: mask `password`, `password_hash`, `email`, `phone`, `address`
  - override: explicit `--reveal-sensitive` flag

## Storage Strategy (v1)

- Blob layout:
  - `raw/<source>/<yyyy>/<mm>/<file>`
  - `normalized/<source>/<ingest-id>.ndjson.zst`
  - `manifests/<ingest-id>.json`
- Manifest fields (minimum):
  - source metadata, parser version, checksum, sizes, timestamps, status
- Compression default: `zstd`.
- Encryption:
  - server-side encryption enabled where backend supports it.
- Lifecycle:
  - keep raw dumps forever in v1
  - keep normalized artifacts forever in v1
  - lifecycle tuning introduced only when migration to AWS S3 is planned.

## Quickwit Strategy

- Keep Quickwit for v1 and optimize schema/mapping around common leak fields.
- Avoid direct Quickwit coupling in CLI command handlers:
  - use internal `SearchRepository` interface
  - keep index and query translation in backend module
- This preserves migration path to Elasticsearch/OpenSearch later if required.

## Testing Strategy

- Unit tests:
  - parser correctness
  - field normalization
  - chunking/checkpoint behavior
  - query builder
- Integration tests:
  - import -> index -> search flow on fixture dumps
  - Telegram adapter query flow against same backend contract
- Regression fixtures:
  - fixed sample dumps with expected matches
- Performance smoke:
  - ingest throughput baseline
  - search latency baseline
  - memory profile baseline on Raspberry Pi-like limits

## Security Baseline

- Secrets from env files excluded from git.
- Optional local key wrapping for sensitive exports.
- Audit logs append-only (timestamp + command + actor + parameters hash).
- Clear separation between raw sensitive data and derived indexes.
- Sensitive data masking enabled by default on user-facing outputs.

## 12-Factor Alignment (Practical)

- Config in environment variables.
- Stateless CLI commands with externalized state (MinIO + Quickwit + manifests).
- Logs as event streams (stdout + structured audit files).
- One codebase, multiple deploy profiles (local dev and Raspberry Pi).
