# Bot Build And Usage (v1 Draft)

## Goal

Define a stable operator workflow for building and running the Telegram bot, and lock how users are expected to use it before backend integration work starts.

## Scope

In scope for this document:

- build flow
- runtime flow
- command usage contract
- current operational limitations
- migration target

Out of scope for this document:

- implementation details of backend integration
- audit/event schema
- authorization model

## Runtime Contract

Build CLI once:

```bash
just build
```

Start bot:

```bash
pwned bot start --platform telegram --token "<your-token>"
```

Status:

```bash
pwned bot status --platform telegram
```

Stop:

```bash
pwned bot stop --platform telegram
```

## Command Contract

Supported CLI subcommands:

- `pwned bot start --platform telegram [--token <token>] [--leaks-glob <glob>]`
- `pwned bot status --platform telegram`
- `pwned bot stop --platform telegram [--timeout <duration>]`

Platform support:

- only `telegram` is supported in v1
- `--platform` is still mandatory in contract shape to keep extension path stable

Token behavior:

- `--token` is accepted on `start`
- if omitted, runtime uses `TELEGRAM_BOT_TOKEN`

## Current Known Limitation

For telegram runtime behavior:

- command parser is in the main CLI codebase
- queries still use local leak file scanning for now
- default leak glob is `./leaks/*.txt` unless overridden with `--leaks-glob`

This is intentionally treated as legacy behavior.

## Next Target Contract

The `pwned bot` command UX should remain stable while query execution is switched to the same backend service contract used by CLI search.

Target properties:

- same data source and query behavior as CLI
- no direct local leak file scanning in bot process
- config-driven backend endpoint behavior
- audit events for bot query actions
