# Objectives And Scope (v1 Draft)

## Product Intent

Build a CLI-first cybersecurity data engine for personal security research that:

1. imports heterogeneous database dumps,
2. stores raw and normalized artifacts in blob storage with cost controls,
3. provides fast cross-dump search for leak investigation.

Secondary interface goals:

1. Telegram bot integration for fast lookups.
2. Optional web app only after v1.

## Scope In

- Local or self-hosted CLI workflows.
- Raspberry Pi-compatible deployment (containerized).
- Dump ingestion pipeline:
  - file discovery
  - file and folder inputs
  - parsing/transformation
  - normalization
  - indexing
- Blob storage integration for raw and processed artifacts (S3-compatible).
- Search workflows over normalized/indexed data.
- Metadata and provenance tracking per source dump.
- Export of matched records for analyst workflows.
- Telegram adapter backed by the same search service contract.

## Scope Out (Phase 1)

- Public SaaS/multi-tenant deployment.
- Real-time web UI.
- Automated OSINT crawling/acquisition.
- Full case-management platform features.

## Users

- Primary user: you (single operator).
- Secondary future user: trusted collaborators with explicit access.

## Functional Requirements (Draft)

1. `import` accepts file path or folder path input.
2. `import` supports at least CSV, TXT line dumps, JSON, and NDJSON.
3. `import` stores original dump unchanged in blob storage with integrity checksum.
4. `import` produces normalized output using a canonical schema.
5. Ingestion is streaming and memory-bounded, and must process 1GB+ files on constrained hardware.
6. `index` builds/updates Quickwit searchable index from normalized records.
7. `search` supports:
   - exact match
   - partial match
   - multi-field filters (`email`, `phone`, `username`, names, IP, domain)
8. `search` can target all dumps or selected sources/tags/date ranges.
9. `show-source` (or equivalent) returns provenance: source dump, ingest time, parser version, and checksum.
10. `export` writes results to a local file (CSV/JSON) for further analysis.
11. Telegram bot queries rely on the same backend query contract used by CLI.
12. Sensitive fields are masked by default in search/export output:
   - `password`
   - `password_hash`
   - `email`
   - `phone`
   - `address`
13. CLI supports explicit reveal flags for sensitive output when needed.

## Non-Functional Requirements (Draft)

- Reproducible local setup (one command dev bootstrap).
- 12-factor aligned app configuration and runtime behavior.
- Containerized services for local and Raspberry Pi environments.
- Deterministic parsing outcomes for same input + parser version.
- Resilience target:
  - no process OOM when ingesting very large files (target: at least 10GB inputs by streaming/chunking).
- Reasonable performance target:
  - initial baseline: search in < 2 seconds for medium corpus (to define precisely).
- Cost control:
  - compressed storage by default
  - lifecycle policy support (default raw retention: keep forever in v1)
- Durability:
  - append-only ingestion manifests
  - resumable ingestion checkpoints
  - checksum verification for raw objects
- Security:
  - encryption at rest
  - secret management via env or vault-compatible mechanism
  - local audit logs for sensitive operations

## Safety And Legal Guardrails (Draft)

- Use only data you are legally authorized to store/process.
- Maintain local access controls and encrypted storage.
- Do not include automated offensive capabilities.
- Keep audit trail for imports and queries.

## Success Criteria (Draft)

- You can ingest multiple dump formats through one CLI interface.
- You can ingest large files and folders without OOM on your target hardware profile.
- Raw + normalized data are persisted with traceable lineage.
- A single search query can find records across all imported dumps.
- Cost posture is measurable (storage size by tier/source/time).
- CLI and Telegram both query the same index/search backend.

## Locked Decisions

1. Blob storage target: local S3-compatible only in v1 (MinIO), with planned migration path to AWS S3.
2. Engine implementation language: Go.
3. Search backend for v1: Quickwit.
4. Target runtime environment: Raspberry Pi capable of running containers.
5. Priority order for v1:
   - first: reliability under constrained memory (no OOM on large dumps)
   - second: minimal infra complexity
   - third: query flexibility and performance tuning
6. v1 interfaces: CLI + Telegram; web app excluded from v1 scope.
7. Retention default in v1: keep raw dumps forever.
8. Redaction policy in v1: mask sensitive fields by default and allow explicit reveal via CLI flags.
