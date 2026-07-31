# Agent Notes for OETP

## Project Scope

This is a **single-tenant pilot** of the Open Exam Transparency Protocol. Do not add national-scale features, multi-tenant orchestration (ledger anchoring beyond the existing mock if thought important), Prometheus metrics, GitHub Actions, or production deployment automation unless explicitly asked.

## Architecture

```
oetp-core/    - business logic, crypto primitives, validation, traits
oetp-edge/    - per-exam-center daemon (fetch/release/unlock/submit)
oetp-ledger/  - central ledger, verification API, packet generator CLI
oetp-beacon/  - authority beacon that issues time-bound release tokens
```

## Build & Test

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Both must pass before any task is considered complete.

## Dev Scripts

- `dev/setup.sh` - generate keys, salt, tenant master key, API key, and write `dev/.env`.
- `dev/start.sh` - build and start ledger + beacon + edge, generate sample packets, load them.
- `dev/check.sh` - quick HTTP health check for all three services.
- `dev/curl-tests.sh` - 44 smoke-test assertions.
- `dev/national-e2e.sh` - 120-student, 4-center, 12-edge end-to-end stress test.
- `dev/stop.sh` - stop services; `dev/stop.sh --clean` also removes generated artifacts.

Run the full verification sequence after any change:

```bash
./dev/stop.sh --clean
./dev/setup.sh
./dev/start.sh
./dev/check.sh
./dev/curl-tests.sh
./dev/national-e2e.sh
```

## Coding Conventions

- Rust 2024 edition, `cargo clippy --workspace --all-targets -- -D warnings` must be clean.
- Prefer minimal changes. Do not change existing logic in tests; fix only compile/runtime errors caused by interface changes.
- Keep secrets out of logs. Use the existing `short_uuid()` helper for UUID logging.
- Use `tokio::task::spawn_blocking` for SQLite, file I/O, and any blocking operations.
- Structured JSON errors: return `(StatusCode, Json<ErrorResponse>)`, never raw strings.
- Input validation goes in `oetp-core/src/validation.rs`; return `oetp_core::error::Error::InvalidInput`.

## Auth & Rate Limiting

- Every mutating endpoint requires `x-api-key` (minimum 32 characters).
- Public read endpoints (`/health`, `/v1/ledger/proof`, `/v1/ledger/verify`, `/v1/ledger/anchors`) do not require a key.
- Rate limiting uses `tower_governor` with `PeerIpKeyExtractor`. Servers must be started with `into_make_service_with_connect_info::<SocketAddr>()` or the extractor fails with "Unable To Extract Key".
- Defaults: 10 req/s, burst 1000. Configurable via `OETP_RATE_LIMIT_PER_SECOND` and `OETP_RATE_LIMIT_BURST`. Dev scripts set a high ceiling (1000 req/s, burst 100000) to avoid throttling localhost tests.

## Crypto & Secrets

- Ed25519 for signing, X25519 for envelope key agreement.
- Device key files must be mode `0600`; the edge config loader enforces this.
- `OETP_EXAM_SALT` and `OETP_SERVER_PEPPER` must be exactly 32-byte hex.
- `OETP_TENANT_MASTER_KEY` is required and must be exactly 32-byte hex (no deterministic fallback).
- `aes-gcm` 0.11: use `Aes256Gcm::new_from_slice` and `Nonce::from_slice` (deprecated APIs were already migrated).

## Storage

- `MemStore` is the default in-memory ledger store.
- `SqliteStore` is selected automatically when `OETP_LEDGER_DB_PATH` is set to a non-empty path.
- National-scale storage requires implementing the `Store` trait from `oetp-core/src/platform.rs`.

## Known Pitfalls

- `BeaconClient` must send `x-api-key` when requesting a token; otherwise the beacon returns 401 and the edge reports "beacon rejected request".
- The beacon verifies release-token signatures against `OETP_BEACON_PUBLIC_KEY`. A mismatch causes release to fail.
- System clock is global per process; the `/v1/system/clock` endpoint overrides it for testing.
- `dev/national-e2e.sh` accumulates ledger state across runs because it does not restart the ledger. The baseline/total-leaf assertions are relative (`baseline + 120`), so this is intentional for stress testing.

## Relevant Files

- `oetp-core/src/validation.rs` - shared input validation.
- `oetp-core/src/error.rs` - shared error types.
- `oetp-core/src/release.rs` - release-token signing/verification.
- `oetp-core/src/clock.rs` - overridable system clock.
- `oetp-edge/src/config.rs`, `oetp-edge/src/state.rs`, `oetp-edge/src/beacon.rs`, `oetp-edge/src/queue.rs`.
- `oetp-ledger/src/config.rs`, `oetp-ledger/src/api.rs`, `oetp-ledger/src/sqlite_store.rs`, `oetp-ledger/src/generator.rs`.
- `oetp-beacon/src/api.rs`, `oetp-beacon/src/main.rs`.
- `dev/setup.sh`, `dev/start.sh`, `dev/check.sh`, `dev/curl-tests.sh`, `dev/national-e2e.sh`.

## License

MIT
