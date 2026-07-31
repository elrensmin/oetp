# OETP Developer Integration Guide

How to integrate OETP into existing exam infrastructure.

## Overview

OETP wraps your existing exam portal as a **transparent middleware layer**. Your legacy UI continues to work unchanged - it talks to OETP's edge daemon via localhost instead of directly to your backend. OETP handles all cryptography, and your scoring engine receives raw answers through its existing channel.

## Touch Points

### 1. Legacy Exam UI → Edge Daemon (localhost:8080)

Your existing exam front-end makes 4 HTTP calls to `http://localhost:8080` instead of your backend. All endpoints require the `x-api-key` header.

```
Legacy UI                    Edge Daemon (localhost:8080)
   │                                │
   ├-- POST /v1/exam/fetch --------►│  Download encrypted packet
   │◄------ { packet_hash } --------┤
   │                                │
   ├-- POST /v1/exam/release ------►│  Get release token from beacon
   │◄------ { status: "released" } -┤
   │                                │
   ├-- POST /v1/exam/unlock -------►│  Decrypt and serve questions
   │◄------ { questions: [...] } ---┤
   │                                │
   ├-- POST /v1/exam/submit -------►│  Seal answers
   │◄------ { receipt, copy } -----┤
```

**What changes in your UI:**
- Replace direct API calls with calls to `localhost:8080`
- Add `x-api-key: dev-api-key-12345678` header to all requests
- On submit, display the `receipt` (QR code + receipt ID) to the student
- Deliver the `personal_copy` to the student (download or print)

**No changes needed:**
- Question rendering, timers, navigation
- Student identity verification
- Proctoring / biometrics

### 2. Edge Daemon → Local Beacon

Each exam center runs a **beacon** (a small authority-signed process) that issues release tokens. The beacon is a separate HTTP server at `http://localhost:9090`:

```
POST /v1/beacon/token
{
  "center_id": "center-01",
  "exam_id": "jee-2027",
  "device_id": "device-01"
}

Response:
{
  "center_id": "center-01",
  "exam_id": "jee-2027",
  "device_id": "device-01",
  "window_start": 1700000000,
  "window_end":   1700000300,
  "nonce": [16 bytes],
  "signature": [Ed25519 signature bytes]
}
```

**Beacon implementation:** The beacon holds the center's Ed25519 signing key. It issues tokens with a max 5-minute lifetime (300s), bound to the requesting `device_id`. The edge daemon validates the signature, time window, device binding, and center binding before decrypting any packet.

### 3. Edge Daemon → Ledger

The edge daemon fetches encrypted packets from the ledger and submits sealed answers. These are internal calls (not exposed to the UI) and require the `x-api-key` header:

```
POST /v1/ledger/fetch
x-api-key: <key>
{
  "tenant_id": "nta",
  "exam_id": "jee-2027",
  "student_uuid": "uuid"
}

Response:
{
  "encrypted_packet": { ... },
  "key_envelope": { ... }
}
```

On submission, the edge queues the signed leaf and flushes to:

```
POST /v1/ledger/ingest
x-api-key: <key>
{
  "tenant_id": "nta",
  "exam_id": "jee-2027",
  "student_uuid": "uuid",
  "packet_hash": [32 bytes],
  "answers_hash": [32 bytes],
  "merkle_leaf": [32 bytes],
  "timestamp": 1700000000,
  "signature": [Ed25519 sig bytes],
  "receipt_id": "receipt-uuid"
}
```

### 4. Generator → Ledger

Before the exam, the generator:
1. Reads the question bank (JSON array of `QuestionItem`)
2. Reads the student list (CSV: `uuid,device_id`)
3. Generates per-student encrypted packets + key envelopes
4. Builds a Merkle tree of all packet hashes
5. Produces a signed manifest
6. Commits the Merkle root to the ledger

```bash
cargo run -p oetp-ledger -- generate \
  --bank question_bank.json \
  --students students.csv \
  --num-questions 90 \
  --output ./output \
  --tenant-master-key "abababababababababababababababababababababababababababababababab" \
  --exam-id "jee-2027" \
  --tenant-id "nta" \
  --device-x25519-pub "<device_x25519_public_key_hex>"
```

The `--device-x25519-pub` flag is **required** in production - it seals the key envelope to the device's actual X25519 public key. Without it, the generator creates a random keypair that won't match the edge daemon's key.

Output files:
- `packet_{uuid}.enc` - encrypted exam packet per student (no `correct_index`)
- `envelope_{uuid}.enc` - key envelope per student
- `manifest.json` - signed manifest with Merkle root
- `signing_key.hex` - generator signing key (keep separate, restrict permissions)

### 5. Ledger → ledger (if thought important to port rpoject to a publis ledger)

The ledger anchors Merkle roots to a ledger (Polygon PoS in v1). Anchors happen at:

| When                         | Type        | Purpose                                |
| ---------------------------- | ----------- | -------------------------------------- |
| 1+ hour before exam          | `PreExam`   | Prove packets existed before exam      |
| Every 10K submissions or 60s | `Rolling`   | Prove submission integrity during exam |
| After exam closes            | `Final`     | Prove final state of all submissions   |
| Before results               | `AnswerKey` | Prove answer key used for scoring      |

The `AnchorBackend` trait abstracts ledger interaction. Implement it for any chain:

```rust
#[async_trait]
impl AnchorBackend for PolygonBackend {
    async fn anchor(&self, root: &[u8; 32], anchor_type: AnchorType) -> Result<Anchor> {
        // Call Polygon smart contract
    }
    async fn verify(&self, anchor: &Anchor) -> Result<bool> {
        // Verify on-chain
    }
}
```

### 6. Scoring Engine

OETP does **not** replace your scoring engine. Your scoring engine continues to receive raw answers through its existing channel. OETP only guarantees that:

- Any score attributed to a student must correspond to a committed `answers_hash`
- If the score uses different answers, the mismatch is detectable
- The authority can decrypt packets using the `exam_master_key` + `variant_seed` to score independently

### 7. Student Verification

Students can verify their submission using the receipt:

1. **Public verification portal** (Phase 2): Enter receipt ID, see Merkle proof, anchored root, signatures
2. **Offline verification**: The receipt contains all data needed for independent verification
3. **Personal answer copy**: Decrypt with application number + DOB + exam salt + server pepper to prove exact selections

## API Reference

### Edge Daemon (port 8080)

All endpoints require `x-api-key` header.

| Endpoint           | Method | Auth | Description                             |
| ------------------ | ------ | ---- | --------------------------------------- |
| `/health`          | GET    | No   | Health check                            |
| `/v1/exam/fetch`   | POST   | Yes  | Download encrypted packet for a student |
| `/v1/exam/release` | POST   | Yes  | Get release token from beacon           |
| `/v1/exam/unlock`  | POST   | Yes  | Decrypt and return questions            |
| `/v1/exam/submit`  | POST   | Yes  | Seal and submit answers                 |

**`POST /v1/exam/fetch`**
```json
// Request
{ "student_uuid": "uuid", "application_number": "APP123" }
// Response
{ "status": "cached", "packet_hash": [32 bytes] }
```

**`POST /v1/exam/release`**
```json
// Request
{ "student_uuid": "uuid" }
// Response
{ "status": "released" }
```

**`POST /v1/exam/unlock`**
```json
// Request
{ "student_uuid": "uuid" }
// Response
{ "questions": [{ "bank_item_id": 1, "variant_id": 0, "stem": "...", "options": [...], "question_ref": "q_1" }] }
```

**`POST /v1/exam/submit`**
```json
// Request
{ "student_uuid": "uuid", "application_number": "APP123", "dob": "2000-01-01", "answers": { "q_1": "Paris", "q_2": "4" } }
// Response
{ "receipt_id": "...", "receipt": { ... }, "personal_copy": { ... } }
```

### Ledger (port 8081)

| Endpoint             | Method | Auth | Description                                        |
| -------------------- | ------ | ---- | -------------------------------------------------- |
| `/health`            | GET    | No   | Health check                                       |
| `/v1/ledger/commit`  | POST   | Yes  | Commit Merkle root of packet hashes (PreExam)      |
| `/v1/ledger/load`    | POST   | Yes  | Load generated packets into memory                 |
| `/v1/ledger/fetch`   | POST   | Yes  | Fetch encrypted packet + key envelope              |
| `/v1/ledger/ingest`  | POST   | Yes  | Ingest a signed submission leaf                    |
| `/v1/ledger/key`     | POST   | Yes  | Commit answer key hash (AnswerKey)                 |
| `/v1/ledger/proof`   | POST   | No   | Get Merkle proof by receipt ID                     |
| `/v1/ledger/verify`  | POST   | No   | Verify a submission's leaf + signature + inclusion |
| `/v1/ledger/anchors` | POST   | No   | List all ledger anchors                            |

### Beacon (port 9090)

| Endpoint           | Method | Auth | Description                      |
| ------------------ | ------ | ---- | -------------------------------- |
| `/health`          | GET    | No   | Health check                     |
| `/v1/beacon/token` | POST   | No   | Issue a time-bound release token |

## Key Cryptographic Concepts

### Key Hierarchy

```
Tenant Master Key (32 bytes, held by authority)
  └-- HKDF → Exam Master Key (per exam)
        └-- HKDF → Ephemeral Packet Key (per student, per packet)
              └-- AES-256-GCM → Encrypted Packet

Tenant Secret (held by authority)
  └-- HKDF → Variant Seed (per student, deterministic)
        └-- Seeded RNG → Question selection + option shuffling
```

### Key Envelope (ECDH + HKDF + AES-GCM with AAD)

```
Generator:                          Device:
  Ephemeral X25519 Secret --ECDH--► Device X25519 Public Key
       │                              │
       ▼                              ▼
  Shared Secret                  Shared Secret
       │                              │
   HKDF(shared, context)          HKDF(shared, context)
       │                              │
       ▼                              ▼
  Envelope Key                   Envelope Key
       │                              │
  AES-GCM(packet_key, AAD) ----► AES-GCM⁻¹ → packet_key
```

AAD = version || len(device_id) || device_id || student_uuid || len(exam_id) || exam_id

### Submission Chain

```
answers_hash = SHA3("oetp-answers-v1" || packet_hash || canonical_json(answers) || student_uuid || variant_seed || timestamp || tenant_id || exam_id)
merkle_leaf = SHA3("oetp-submission-leaf-v1" || student_uuid || packet_hash || answers_hash || timestamp || tenant_id || exam_id)
```

### Personal Answer Copy (Argon2id)

```
salt = HKDF(exam_salt, "application_number:dob:tenant_id:exam_id")
key = Argon2id(password=server_pepper, salt=salt, m=64MiB, t=3, p=4)
PersonalAnswerCopy = AES-GCM(key, AAD=receipt_id || student_uuid || tenant_id || exam_id)
```

## Data Formats

### Question Bank JSON

```json
[
  {
    "id": 1,
    "difficulty": "Easy",
    "stem": "What is 2+2?",
    "variants": [
      {
        "id": 0,
        "substitutions": {},
        "options": ["3", "4", "5", "6"],
        "correct_index": 1
      }
    ]
  }
]
```

### Students CSV

```csv
550e8400-e29b-41d4-a716-446655440000,device-01
550e8400-e29b-41d4-a716-446655440001,device-02
```

### Device Key Files

Two separate keypairs per device:

```bash
# Ed25519 signing key
openssl genpkey -algorithm ed25519 -outform DER | tail -c 32 | xxd -p > /etc/oetp/device.key
chmod 600 /etc/oetp/device.key

# X25519 encryption key
openssl genpkey -algorithm x25519 -outform DER | tail -c 32 | xxd -p > /etc/oetp/device_x25519.key
chmod 600 /etc/oetp/device_x25519.key
```

## Development

### Quick Start

```bash
cd oetp
./dev/setup.sh          # generates keys, writes dev/.env, creates sample data
./dev/start.sh          # builds, then launches ledger + beacon + edge
./dev/curl-tests.sh     # runs 44+ assertions against all endpoints
./dev/stop.sh           # stops all services
```

### Testing

```bash
# All unit tests
cargo test --workspace

# Core library only
cargo test -p oetp-core

# Edge daemon
cargo test -p oetp-edge

# Ledger
cargo test -p oetp-ledger

# Full lifecycle smoke tests (requires running services)
./dev/curl-tests.sh
```

### Environment Variables

See `dev/.env` (auto-generated by `setup.sh`):

| Variable                  | Service      | Purpose                               |
| ------------------------- | ------------ | ------------------------------------- |
| `OETP_TENANT_ID`          | Edge, Ledger | Tenant identifier                     |
| `OETP_EXAM_ID`            | Edge, Ledger | Exam identifier                       |
| `OETP_DEVICE_ID`          | Edge         | Device identifier                     |
| `OETP_CENTER_ID`          | Edge         | Exam center identifier                |
| `OETP_LEDGER_URL`         | Edge         | Ledger base URL                       |
| `OETP_BEACON_URL`         | Edge         | Beacon base URL                       |
| `OETP_LISTEN_ADDR`        | Edge         | Edge listen address                   |
| `OETP_DEVICE_KEY`         | Edge         | Path to Ed25519 device key            |
| `OETP_DEVICE_X25519_KEY`  | Edge         | Path to X25519 device key             |
| `OETP_BEACON_PUBLIC_KEY`  | Edge         | Beacon's Ed25519 public key (hex)     |
| `OETP_EXAM_SALT`          | Edge         | Salt for personal answer copy         |
| `OETP_SERVER_PEPPER`      | Edge         | Pepper for personal answer copy       |
| `OETP_API_KEY`            | Edge, Ledger | Shared API key for inter-service auth |
| `OETP_LEDGER_LISTEN_ADDR` | Ledger       | Ledger listen address                 |
| `OETP_LEDGER_DB_PATH`     | Ledger       | SQLite database path                  |
| `OETP_SIGNING_KEY`        | Ledger       | Ledger Ed25519 signing key (hex)      |
| `OETP_BEACON_LISTEN_ADDR` | Beacon       | Beacon listen address                 |
| `OETP_BEACON_SIGNING_KEY` | Beacon       | Beacon Ed25519 signing key (hex)      |

## Deployment Architecture

```
┌---------------------------------------------------------┐
│                    Exam Authority                       │
│  ┌--------------┐  ┌--------------┐  ┌---------------┐  │
│  │   Generator  │  │    Ledger    │  │  ledger   │  │
│  │  (CLI tool)  │  │  (HTTP API)  │  │  (Polygon)    │  │
│  └------┬-------┘  └------┬-------┘  └-------┬-------┘  │
│         │                 │                  │          │
└---------┼-----------------┼------------------┼----------┘
          │                 │                  │
          ▼                 ▼                  │
┌----------------------------------------------┘
│  Internet / WAN
└----------------------------------------------┐
                                               │
┌----------------------------------------------┘
│  Exam Center LAN
│  ┌--------------┐    ┌----------------------┐
│  │    Beacon    │    │   Edge Daemon x N    │
│  │  (HTTP API)  │◄--►│  (one per machine)   │
│  └--------------┘    └----------┬-----------┘
│                                 │ localhost:8080
│                        ┌--------▼-----------┐
│                        │   Legacy Exam UI   │
│                        │  (browser/app)     │
│                        └--------------------┘
└----------------------------------------------┘
```

## Phase 2 Integration Points

See `PRODUCTION.md` for:
- Kafka ingestion pipeline for 2M+ submissions
- ScyllaDB hot store for horizontal scaling
- Multi-chain anchoring (Bitcoin + IndiaChain)
- Public web verification portal
- HSM-backed release key ceremonies
- TPM/TEE remote attestation

## Storage Upgrade Path

The ledger currently uses `MemStore` (in-memory `DashMap`) for fast development. A SQLite-backed `SqliteStore` is available in `oetp-ledger/src/sqlite_store.rs`. To enable it:

```rust
// oetp-ledger/src/main.rs
let store = Arc::new(sqlite_store::SqliteStore::new(&cfg.db_path)?);
```

For national scale, implement the `Store` trait from `oetp-core/src/platform.rs` with ScyllaDB or Cassandra.

## Benchmarks

```bash
cargo bench -p oetp-core
```

This measures:
- Packet encryption/decryption (90 questions) - target <100ms
- Answer hashing (90 questions) - target <10ms
- Submission leaf computation - target <1ms
- Ed25519 sign/verify - target <1ms
- Envelope seal/open (ECDH + HKDF + AES-GCM) - target <5ms
- Merkle proof from 100K leaves - target <1ms
- Receipt generation - target <50ms

Results output to `target/criterion/report/`.

## Public Verification API

The ledger exposes endpoints for anyone to verify submissions without trusting the authority's database:

| Endpoint             | Method | Auth | Description                                                           |
| -------------------- | ------ | ---- | --------------------------------------------------------------------- |
| `/v1/ledger/proof`   | POST   | No   | Full Merkle proof: leaf, index, siblings, root                        |
| `/v1/ledger/verify`  | POST   | No   | Verify submission: checks leaf hash, edge signature, ledger inclusion |
| `/v1/ledger/anchors` | POST   | No   | List all ledger anchors for a tenant/exam                             |

The verification portal (Phase 2) calls these endpoints and cross-references against ledger RPCs.
