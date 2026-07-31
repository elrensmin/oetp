# Open Exam Transparency Protocol (OETP)

Cryptographic middleware that eliminates systemic exam fraud by making leaked papers economically worthless and tampering mathematically detectable.

This repository is a **single-tenant pilot** implementation. It is designed to run one exam for one tenant at a time, with all services co-located or on a small set of trusted machines. National-scale multi-tenant orchestration, horizontal scaling, and blockchain anchoring are explicitly out of scope for this codebase.

## Architecture

Four crates:

```
oetp-core/    - pure business logic, crypto primitives, trait definitions, validation
oetp-edge/    - edge daemon running on each exam-center machine
oetp-ledger/  - central ledger, public verification API, packet generator CLI
oetp-beacon/  - authority beacon that issues time-bound release tokens
```

## Data Flow

```
question bank → packet → envelope → Merkle commitment → release token → decryption → answer sealing → receipt → ledger append → verification
```

Please see dev/national-e2e.sh for detailed info of how the system works (multi-center exam flow).

## How OETP Prevents Cheating, Bribery, and Hacking

### Anti-Cheating

| Attack                  | Defense                                                                                                                                                                                                                                                                               |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Paper leak**          | Per-student deterministic variant selection from `variant_seed`; leaked questions don't match any specific student's paper. Correct answers (`correct_index`) are **never shipped** in the exam packet - they are anchored separately and released only after the exam window closes. |
| **Answer sharing**      | Options are shuffled per-question using a per-question seed derived from `variant_seed`. Two students with the same variant see different option orderings, so "option B is correct" is meaningless across students.                                                                  |
| **Pre-exam decryption** | Release tokens are bound to `device_id`, time-windowed (max 5 minutes), and single-use (nonce persisted to disk). A token obtained for one device cannot unlock another device's packet.                                                                                              |
| **Answer substitution** | The submission leaf cryptographically binds `student_uuid + packet_hash + answers_hash + timestamp + tenant_id + exam_id`. Any change to the answers produces a different leaf, which breaks the Merkle chain.                                                                        |
| **Double submission**   | The edge enforces one submission per student; the ledger rejects duplicate `student_uuid` leaves.                                                                                                                                                                                     |
| **Late submission**     | The submission timestamp is included in the leaf hash. The release token's time window bounds the exam period.                                                                                                                                                                        |

### Anti-Bribery

| Attack                        | Defense                                                                                                                                                                                                                                                                          |
| ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Bribed generator operator** | The generator's signing key is kept separate from the output directory. The manifest is signed and verified at runtime. `correct_index` is not in the packet - the answer key is anchored separately and released post-exam.                                                     |
| **Bribed center operator**    | Each center has its own release key. A stolen key only unlocks that center's devices. Release tokens are bound to `device_id`.                                                                                                                                                   |
| **Bribed ledger operator**    | The ledger uses an append-only SQLite store with signed Merkle checkpoints. Any modification to stored data changes the Merkle root, which is anchored. The `MockAnchorBackend` is for development only - production deployments must use a real transparency log or blockchain. |
| **Bribed proctor**            | The proctor cannot decrypt packets without the release token from the beacon. The beacon is a separate, authority-controlled process.                                                                                                                                            |

### Anti-Hacking

| Attack                    | Defense                                                                                                                                              |
| ------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Memory scraping**       | `LockedBuffer` with mlock + zeroize-on-drop. Device private keys are zeroized on drop. Ephemeral envelope keys are explicitly zeroized after use.    |
| **Network interception**  | All inter-service communication should use mTLS behind a reverse proxy (see `PRODUCTION.md`). API keys are required and validated on every endpoint. |
| **Replay attacks**        | Release token nonces are persisted to a file-backed log and rejected on restart. Ledger ingest is idempotent by `receipt_id`.                        |
| **API key brute-force**   | API keys are required (minimum 32 hex chars). Rate limiting should be added in production.                                                           |
| **Forged receipts**       | Receipts are signed by both the edge (Ed25519) and the ledger. The verification payload includes the Merkle proof root, leaf, and `qr_payload`.      |
| **Fake Merkle proofs**    | The edge fetches the real Merkle proof from the ledger after successful ingestion. The receipt's proof is verifiable against the anchored root.      |
| **Device key compromise** | Devices have separate Ed25519 (signing) and X25519 (envelope encryption) keypairs. Compromise of one does not compromise the other.                  |

### Fault Tolerance

| Scenario                       | Behavior                                                                                                                                          |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Network outage during exam** | Encrypted packets are cached locally. Signed submissions are queued to an encrypted file and flushed when connectivity returns.                   |
| **Ledger restart**             | SQLite-backed persistent store preserves all leaves, roots, and checkpoints. The Merkle worker recomputes roots on restart.                       |
| **Edge daemon restart**        | Consumed nonces are persisted to disk. The offline queue survives restart. Cached packets must be re-fetched.                                     |
| **Beacon unreachable**         | Release tokens cannot be obtained, so packets cannot be decrypted. This is by design - no exam can proceed without the authority's authorization. |

## Quick Start

### Prerequisites

- Rust 2024 edition (1.85+)
- Linux (for mlock/core dump hardening)
- `python3` with `cryptography` package (`pip install cryptography`)
- `jq` for JSON processing

### One-Time Setup

```bash
cd oetp
./dev/setup.sh
```

This generates Ed25519 and X25519 device keys, a ledger signing key, a center beacon key, an exam salt, a tenant master key, and an API key. All secrets are written to `dev/.env` with restricted permissions (600).

### Start All Services

```bash
./dev/start.sh
```

This builds all crates, starts the ledger (port 8081), beacon (port 9090), and edge daemon (port 8080), generates sample exam packets, and loads them into the ledger.

### Check Service Health

```bash
./dev/check.sh
```

### Run Smoke Tests

```bash
./dev/curl-tests.sh
```

Runs 44+ assertions against all endpoints: health checks, auth rejection, packet fetch, release token, unlock, submit, Merkle proof, verify, answer key commit, anchors, and beacon token.

### Run National-Level Mock Simulation

```bash
./dev/national-e2e.sh
```

Simulates 4 centers, 12 edge devices, and 120 students end-to-end, including attack/failure scenarios.

### Stop All Services

```bash
./dev/stop.sh
```

Stop and remove all generated runtime artifacts:

```bash
./dev/stop.sh --clean
```

### Run Unit Tests

```bash
cargo test --workspace
```

## API Reference

### Edge Daemon (localhost:8080)

| Endpoint              | Method | Description                                                 |
| --------------------- | ------ | ----------------------------------------------------------- |
| `/v1/exam/fetch`      | POST   | Download encrypted packet + key envelope                    |
| `/v1/exam/release`    | POST   | Obtain release token from local beacon (bound to device_id) |
| `/v1/exam/unlock`     | POST   | Decrypt and return questions (requires release token)       |
| `/v1/exam/submit`     | POST   | Seal answers, return receipt + personal copy                |
| `/v1/system/clock`   | POST   | Operational: set system clock for testing (authenticated)   |
| `/v1/system/flush`   | POST   | Operational: flush offline queue to ledger (authenticated)  |
| `/health`             | GET    | Health check                                                |

### Ledger API (port 8081)

| Endpoint                | Method | Description                                                    |
| ----------------------- | ------ | -------------------------------------------------------------- |
| `/v1/ledger/commit`     | POST   | Pre-exam Merkle root commitment                                |
| `/v1/ledger/ingest`     | POST   | Submission ingestion (includes receipt_id for proof lookup)    |
| `/v1/ledger/proof`      | POST   | Full Merkle proof by receipt (leaf, index, siblings, root)     |
| `/v1/ledger/key`        | POST   | Answer-key hash commitment                                     |
| `/v1/ledger/fetch`      | POST   | Fetch packet + envelope for edge                               |
| `/v1/ledger/verify`     | POST   | Verify submission: leaf hash, edge signature, ledger inclusion |
| `/v1/ledger/anchors`   | POST   | List all blockchain anchors for a tenant/exam                  |
| `/v1/ledger/load`       | POST   | Load generated packets (pre-exam, authenticated)               |
| `/v1/system/clock`      | POST   | Operational: set system clock for testing (authenticated)      |
| `/health`               | GET    | Health check                                                   |

### Beacon API (port 9090)

| Endpoint              | Method | Description                                              |
| --------------------- | ------ | -------------------------------------------------------- |
| `/v1/beacon/token`    | POST   | Issue a time-bound release token for a device            |
| `/v1/system/clock`    | POST   | Operational: set system clock for testing (authenticated) |
| `/health`             | GET    | Health check                                             |

## Benchmarks

```bash
cargo bench -p oetp-core
```

Measures latency for all core cryptographic operations: packet encrypt/decrypt (90 questions), answer hashing, submission leaf, Ed25519 sign/verify, envelope seal/open, Merkle proof (100K leaves), receipt generation. Results output to `target/criterion/`.

## Storage

The ledger uses an in-memory `MemStore` by default for the pilot. A SQLite-backed `SqliteStore` is available in `oetp-ledger/src/sqlite_store.rs` and is selected automatically when `OETP_LEDGER_DB_PATH` is set to a non-empty path. For national scale, implement the `Store` trait from `oetp-core/src/platform.rs` with a distributed database.

## Environment Variables

### Edge Daemon

| Variable                 | Default                 | Required | Description                              |
| ------------------------ | ----------------------- | -------- | ---------------------------------------- |
| `OETP_TENANT_ID`         | -                       | Yes      | Tenant identifier                        |
| `OETP_EXAM_ID`           | -                       | Yes      | Exam identifier                          |
| `OETP_DEVICE_ID`         | -                       | Yes      | Device identifier                        |
| `OETP_CENTER_ID`         | -                       | Yes      | Center identifier                        |
| `OETP_LEDGER_URL`        | `http://localhost:8081` | No       | Ledger URL                               |
| `OETP_BEACON_URL`        | `http://localhost:9090` | No       | Beacon URL                               |
| `OETP_LISTEN_ADDR`       | `127.0.0.1:8080`        | No       | Edge listen address                      |
| `OETP_DEVICE_KEY`        | `/etc/oetp/device.key`  | No       | Ed25519 device key path                  |
| `OETP_CACHE_DIR`         | `/var/cache/oetp`       | No       | Packet cache directory                   |
| `OETP_QUEUE_DIR`         | `/var/spool/oetp`       | No       | Offline queue directory                  |
| `OETP_BEACON_PUBLIC_KEY` | -                       | Yes      | Center beacon Ed25519 public key (hex)   |
| `OETP_EXAM_SALT`         | -                       | Yes      | Per-exam random salt (32-byte hex)       |
| `OETP_SERVER_PEPPER`     | -                       | Yes      | Server pepper for Argon2id (32-byte hex) |
| `OETP_API_KEY`           | -                       | Yes      | API key for edge endpoints               |
| `OETP_RATE_LIMIT_PER_SECOND` | `10`                 | No       | Rate-limit replenish per second          |
| `OETP_RATE_LIMIT_BURST`  | `1000`                  | No       | Rate-limit burst bucket size             |

### Ledger

| Variable                  | Default                 | Required | Description                      |
| ------------------------- | ----------------------- | -------- | -------------------------------- |
| `OETP_TENANT_ID`          | -                       | Yes      | Tenant identifier                |
| `OETP_EXAM_ID`            | -                       | Yes      | Exam identifier                  |
| `OETP_SIGNING_KEY`        | -                       | Yes      | Ledger Ed25519 signing key (hex) |
| `OETP_API_KEY`            | -                       | Yes      | API key for ledger endpoints     |
| `OETP_LEDGER_LISTEN_ADDR` | `0.0.0.0:8081`          | No       | Ledger listen address            |
| `OETP_LEDGER_DB_PATH`     | `/var/lib/oetp/ledger`  | No       | Database path                    |
| `OETP_ANCHOR_RPC_URL`     | `http://localhost:8545` | No       | Blockchain RPC URL               |

### Beacon

| Variable                  | Default                 | Required | Description                       |
| ------------------------- | ----------------------- | -------- | --------------------------------- |
| `OETP_BEACON_LISTEN_ADDR` | `0.0.0.0:9090`          | No       | Beacon listen address             |
| `OETP_BEACON_SIGNING_KEY` | -                       | Yes      | Beacon Ed25519 signing key (hex)  |
| `OETP_EXAM_WINDOW_START`  | `0`                     | No       | Exam window start (Unix seconds)  |
| `OETP_EXAM_WINDOW_END`    | `u64::MAX`              | No       | Exam window end (Unix seconds)    |
| `OETP_API_KEY`            | -                       | Yes      | API key for beacon endpoints      |
| `OETP_RATE_LIMIT_PER_SECOND` | `10`                 | No       | Rate-limit replenish per second   |
| `OETP_RATE_LIMIT_BURST`   | `1000`                  | No       | Rate-limit burst bucket size      |

## Key Files

- `/etc/oetp/device.key` - Ed25519 private key hex (32 bytes, 64 hex chars), mode 0600
- `/etc/oetp/device_x25519.key` - X25519 private key hex (32 bytes, 64 hex chars), mode 0600
- `question_bank.json` - JSON array of `QuestionItem` objects
- `students.csv` - CSV with `uuid,device_id` per line

## Security Properties

| Attack                 | Defense                                                                                          |
| ---------------------- | ------------------------------------------------------------------------------------------------ |
| Paper leak             | Per-student deterministic variant selection; `correct_index` never shipped in packet             |
| Answer substitution    | Submission leaf binds student + packet + answers + tenant + exam; any change breaks Merkle chain |
| Retroactive key change | Answer key anchored before results; any change detectable                                        |
| Memory scraping        | mlock + zeroize-on-drop; explicit zeroization of ephemeral keys                                  |
| Network outage         | Encrypted packets cached locally; signed submissions queue and flush later                       |
| Center bribery         | Release tokens bound to `device_id`; stolen key only unlocks that device                         |
| Replay attacks         | Release-token nonces persisted to disk; ledger ingest idempotent by `receipt_id`               |
| Forged receipts        | Receipts signed by edge + ledger; verification payload includes Merkle proof                     |
| API key brute-force    | API key required (minimum 32 characters); rate limiting keyed by peer IP                       |


## License

MIT
