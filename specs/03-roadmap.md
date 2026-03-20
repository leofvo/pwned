# Roadmap (v1 Draft)

## Phase 0: Spec Lock

- Finalize scope, architecture, and data model.
- Lock language, storage backend, and search backend.
- Define acceptance test corpus and success metrics.

Deliverable:
- Approved specs in `./specs`.

## Phase 1: Foundation CLI

- Create Go project skeleton and CLI framework.
- Implement 12-factor config management and structured logging.
- Implement `import` (file + folder support) with raw MinIO upload + manifest creation.

Deliverable:
- Working `import` command with provenance metadata.

## Phase 2: Normalization + Indexing

- Implement format adapters (CSV, TXT rows, JSON/NDJSON).
- Implement streaming canonical schema normalizer.
- Implement checkpoint/chunk logic for large-file processing.
- Implement Quickwit backend adapter through repository abstraction.

Deliverable:
- `import` and `index` pipeline passing integration tests.

## Phase 3: Search + Provenance

- Implement `search`, `provenance`, and `export` commands.
- Add query filters and cross-source search support.
- Add audit logging for query/export operations.
- Implement default sensitive-field masking with explicit reveal flags.
- Integrate Telegram bot adapter against the same query service.

Deliverable:
- End-to-end analyst flow from ingest to export on CLI and Telegram.

## Phase 4: Hardening

- Performance profiling and batching optimization.
- Storage lifecycle and cost reports.
- Security hardening and operational runbook.
- Raspberry Pi deployment validation and tuning.

Deliverable:
- v1 release candidate with measurable performance and cost posture.

## Phase 5: Optional Extensions

- Evaluate lightweight web app for search UX.
- Plan MinIO -> AWS S3 production migration runbook.
- Add optional advanced relevance/ranking improvements.

## Initial Milestone Exit Criteria

1. M1:
   - Import any sample dump into raw blob storage.
2. M2:
   - Normalize and index at least three heterogeneous dump formats.
3. M3:
   - Query across all indexed dumps and retrieve source provenance.
4. M4:
   - Produce monthly storage usage report by source and tier.
5. M5:
   - Process at least one 10GB+ fixture without OOM.
6. M6:
   - Validate containerized run on Raspberry Pi profile.
