# Current State Audit

## Snapshot

- Repository currently contains a Quickwit + MinIO local setup.
- Main documented flow is: ingest CSV-derived NDJSON into Quickwit, then search via Quickwit CLI/API.
- A separate Go Telegram bot exists in `bot/` and performs direct file scanning in `./leaks/*.txt` instead of querying Quickwit.

## Existing Components

- Infra runtime:
  - `docker-compose.yml` defines `minio`, `bucket-creator`, and `quickwit`.
  - `config/quickwit.yaml` configures S3-backed metastore/index root (`s3://leaks/indexes`).
  - `leaks.yml` defines Quickwit index mapping (`leaks` index).
- Utilities:
  - legacy `Makefile` for start/stop/clean.
  - `Dockerfile` packaging Quickwit config.
- Bot:
  - `bot/main.go` parses `/identify` filters (`phone`, `firstname`, `lastname`) and scans local leak text files line by line.

## Technical Gaps

- No unified CLI engine for import/search lifecycle.
- Data ingestion and query paths are split across two models:
  - Quickwit index ingestion.
  - Local text scanning in bot.
- No explicit dump pipeline:
  - format detection
  - normalization
  - schema management
  - deduplication
  - provenance tracking
- Storage lifecycle and cost controls are missing:
  - retention policies
  - compression/encryption standards
  - hot/cold storage strategy
- No testing strategy for parser quality, search relevance, or performance regressions.
- No clear trust/safety controls (access control, audit logs, sensitive data handling policy).

## Operational Gaps

- Hardcoded local paths in bot (`/Users/leofvo/.../leaks/*.txt`).
- `terraform/` files are referenced in your IDE context but are not present in this workspace at the moment.
- `bot/` is currently untracked in git (`git status --short` shows `?? bot/`).

## Reusable Assets

- Quickwit knowledge and baseline mapping (`leaks.yml`) can inform the new schema strategy.
- Dockerized local infra is useful for deterministic local development.
- Existing sample dataset and query examples can seed acceptance tests.

## Rebuild Direction (High Level)

- Keep project goal: ingest breach dumps, store cost-efficiently, search across full corpus.
- Rebuild around one CLI-first engine with modular pipeline stages.
- Add explicit governance layer (legal/safety constraints, traceability, auditability).
- Keep Telegram as an integration target, but backed by the same core query service as CLI.
- Defer web UI until the core engine contract is stable.
