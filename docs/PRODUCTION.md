# OETP Production Deployment & Expansion Guide

This document covers how to take OETP from development to a hardened, national-scale, legally defensible exam infrastructure.

---

## 1. Current State of the Codebase

### What's Already Built (162+ tests passing)

| Component                   | Modules                                                                                                                                                                                | Status   |
| --------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- |
| **oetp-core** (17 modules)  | `error`, `tenant`, `device`, `device_x25519`, `zeroize`, `hashing`, `signing`, `question_bank`, `packet`, `envelope`, `release`, `merkle`, `receipt`, `manifest`, `platform`, `verify` | Complete |
| **oetp-edge** (7 modules)   | `main`, `config`, `state`, `api`, `beacon`, `queue`, `platform_impl`                                                                                                                   | Complete |
| **oetp-ledger** (8 modules) | `main`, `config`, `api`, `storage`, `sqlite_store`, `generator`, `merkle_worker`, `anchor_worker`                                                                                      | Complete |

### Production-Ready Features

- **Separate X25519 device keys** for envelope encryption (distinct from Ed25519 signing keys)
- **Canonical AAD** in envelope (version-prefixed, length-delimited identity fields)
- **Release tokens bound to `device_id`** with max 5-minute lifetime and persisted nonce replay protection
- **`correct_index` removed from exam packets** - answer key anchored separately and released post-exam
- **Argon2id** for personal answer copy key derivation (memory-hard, server pepper)
- **Receipt verification payload** includes Merkle proof root, leaf, and `qr_payload`
- **Ledger `/ingest`** accepts `receipt_id` and populates `receipt_index` for proof lookup
- **`/proof`** returns error for unknown receipt IDs (no fallback to last leaf)
- **API keys required** on all endpoints (no empty default)
- **Persistent nonce tracking** via append-only log file
- **SQLite-backed store** available (`sqlite_store.rs`) - swap `MemStore` for production
- **Merkle worker persists roots** via `Store::set_root()`
- **Ed25519/X25519 public key validation** (reject all-zero keys)

### What's Still Skeleton / Needs Production Hardening

| Gap                                      | Where                              | Action Needed                                                              |
| ---------------------------------------- | ---------------------------------- | -------------------------------------------------------------------------- |
| `MemStore` (in-memory)                   | `oetp-ledger/src/storage.rs`       | Swap for `SqliteStore` (built) or RocksDB/ScyllaDB                         |
| `MockAnchorBackend`                      | `oetp-ledger/src/anchor_worker.rs` | Implement real Polygon/IndiaChain backend                                  |
| No metrics                               | Everywhere                         | Add Prometheus metrics via `prometheus` crate                              |
| No TLS                                   | Both daemons                       | Deploy behind reverse proxy (nginx, haproxy) with mTLS between edge↔ledger |
| No rate limiting                         | Both daemons                       | Add `tower` rate-limit layer                                               |
| No CI/CD                                 | Workspace root                     | Add `.github/workflows/ci.yml`                                             |
| No supply-chain auditing                 | Workspace root                     | Run `cargo audit`, `cargo deny`                                            |
| `reqwest` uses `native-tls`              | Both Cargo.toml                    | Switch to `rustls-tls` for reproducible builds                             |
| No structured audit logging              | Both daemons                       | Add separate audit log channel                                             |
| Logs leak PII (student UUIDs)            | Both `api.rs`                      | Redact/hash student UUIDs in production logs                               |
| CORS is localhost-prefix based           | Both `main.rs`                     | Restrict to exact origin or disable in production                          |
| Queue file permissions not set           | `oetp-edge/src/queue.rs`           | Set `0600` on queue file, `0700` on queue dir                              |
| Generator writes signing key to output   | `oetp-ledger/src/generator.rs`     | Separate public output from private key storage                            |
| No per-tenant API keys                   | Both daemons                       | Replace single shared key with per-role credentials                        |
| No input validation on tenant/exam IDs   | Both daemons                       | Restrict to safe character set                                             |
| Serialization structs lack version field | `oetp-core/src/*.rs`               | Add `version: u16` to persistent structs                                   |

---

## 2. TLS / Reverse Proxy

OETP daemons do **not** terminate TLS themselves. In production, deploy behind a reverse proxy (nginx, haproxy, or a cloud LB):

```
Student Browser --HTTPS--► Reverse Proxy --HTTP--► Edge Daemon (127.0.0.1:8080)
Edge Daemon     --mTLS--► Reverse Proxy --HTTPS--► Ledger (127.0.0.1:8081)
```

### mTLS between Edge and Ledger

For production, configure mutual TLS:

1. Issue a client certificate to each edge device
2. Configure the ledger to require client certificates
3. Configure the edge to verify the ledger's server certificate
4. Pin the CA certificate in both daemons

The `reqwest::Client` in `AppState` should be built with a custom `rustls` configuration:

```rust
let root_certs = rustls::RootCertStore::from_iter(ca_certs);
let tls_config = rustls::ClientConfig::builder()
    .with_root_certificates(root_certs)
    .with_client_auth_cert(client_cert, client_key)?;
let client = reqwest::Client::builder()
    .use_preconfigured_tls(tls_config)
    .build()?;
```

### Reverse Proxy Configuration (nginx example)

```nginx
server {
    listen 443 ssl;
    server_name edge.exam-authority.in;

    ssl_certificate /etc/ssl/certs/edge.crt;
    ssl_certificate_key /etc/ssl/private/edge.key;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

## 3. Storage: MemStore → SqliteStore → RocksDB → ScyllaDB

### Step 1: SQLite (single-node, small tenants)

The `SqliteStore` is already built in `oetp-ledger/src/sqlite_store.rs`. To enable it:

```rust
// oetp-ledger/src/main.rs
let store = Arc::new(sqlite_store::SqliteStore::new(&cfg.db_path)?);
```

### Step 2: RocksDB (single-node, larger tenants)

```toml
# oetp-ledger/Cargo.toml
rocksdb = "0.22"
```

Implement the `Store` trait from `oetp-core/src/platform.rs`.

### Step 3: ScyllaDB (multi-node, national scale)

Implement the `Store` trait with the `scylla` crate. Key schema: partition by `(tenant_id, exam_id)`, clustering by leaf index.

### Step 4: Kafka ingestion pipeline

Replace direct HTTP ingestion with Kafka. The edge publishes to Kafka; the ledger consumes, batches, and appends.

---

## 4. Blockchain Anchoring: Mock → Polygon → Multi-Chain

### Implement Polygon AnchorBackend

```rust
// oetp-ledger/src/anchor_worker.rs
use alloy::providers::{Provider, ProviderBuilder};

pub struct PolygonBackend {
    contract: OETPAnchor::OETPAnchorInstance<...>,
}

#[async_trait]
impl AnchorBackend for PolygonBackend {
    async fn anchor(&self, root: &[u8; 32], anchor_type: AnchorType) -> Result<Anchor> {
        let tx = self.contract.anchor(*root, anchor_type as u8).send().await?;
        let receipt = tx.get_receipt().await?;
        Ok(Anchor {
            chain_id: "polygon".into(),
            tx_hash: format!("0x{:x}", receipt.transaction_hash),
            anchored_root: *root,
            anchor_type,
            timestamp: current_timestamp_secs(),
            signature: vec![],
        })
    }
}
```

### Multi-chain strategy

| Chain       | When                        | Crate                  |
| ----------- | --------------------------- | ---------------------- |
| Polygon PoS | Rolling anchors (every 60s) | `alloy`                |
| Bitcoin     | Pre-exam + final roots      | `rust-bitcoin` + RPC   |
| IndiaChain  | Compliance mirror           | Custom `AnchorBackend` |

---

## 5. Server Pepper Management

The `OETP_SERVER_PEPPER` is a 32-byte secret used as the Argon2id password for personal answer copy derivation. In production:

1. **Do not store in `.env`** - load from a restricted file (`chmod 600`) or an HSM
2. **Rotate per exam** - generate a new pepper for each exam
3. **Never log or expose** - the pepper is a high-value secret

```bash
# Generate
openssl rand -hex 32 > /etc/oetp/server_pepper.hex
chmod 600 /etc/oetp/server_pepper.hex

# Load
export OETP_SERVER_PEPPER=$(cat /etc/oetp/server_pepper.hex)
```

---

## 6. Edge Daemon Hardening

### Automatic queue flush

Already wired in `oetp-edge/src/main.rs` - background task flushes every 30 seconds.

### Signal handler zeroize

The `AppState::drop` implementation clears cached data and consumed nonces. For production, add explicit zeroization of all sensitive fields (device keys, queue key, cached packets).

### seccomp-bpf syscall filtering

```rust
// oetp-edge/src/platform_impl.rs
use seccompiler::*;

pub fn apply_seccomp() -> Result<()> {
    let filter = BpfProgram::try_from(SeccompCmpArg::new(SeccompAction::Allow)?)?;
    seccompiler::apply_filter(&filter)?;
    Ok(())
}
```

---

## 7. Monitoring & Observability

### Key metrics to track

| Metric                          | Type    | Where                      |
| ------------------------------- | ------- | -------------------------- |
| `oetp_packets_fetched_total`    | Counter | Edge `/v1/exam/fetch`      |
| `oetp_submissions_sealed_total` | Counter | Edge `/v1/exam/submit`     |
| `oetp_queue_depth`              | Gauge   | Edge queue                 |
| `oetp_ledger_ingest_total`      | Counter | Ledger `/v1/ledger/ingest` |
| `oetp_anchor_success_total`     | Counter | Ledger anchor worker       |
| `oetp_anchor_failure_total`     | Counter | Ledger anchor worker       |

### Alerting thresholds

- Queue depth > 1000 → possible network outage
- Anchor failure > 3 consecutive → blockchain RPC down
- Packet fetch failure rate > 5% → ledger unreachable

---

## 8. Security Hardening

### Release key ceremony

Production: Generate per-center release keys inside **HSMs** or **TPMs**:

```rust
use tss_esapi::Context;
let mut context = Context::new(Tcti::from_str("device:/dev/tpmrm0")?)?;
let key = context.create_primary_key(...)?;
```

### Edge device attestation

Before issuing a release token, the beacon should verify:
1. Device ID matches a known whitelist
2. OS image hash matches expected value
3. No debugger attached (`/proc/self/status` → `TracerPid: 0`)
4. Signed boot chain (if UEFI/SecureBoot)

### Build pipeline

```yaml
# .github/workflows/ci.yml
- name: cargo audit
  run: cargo audit
- name: cargo deny
  run: cargo deny check
- name: cargo clippy
  run: cargo clippy -- -D warnings
- name: cargo test
  run: cargo test --workspace
- name: cargo build --release
  run: cargo build --release
- name: Generate SBOM
  run: cargo cyclonedx > sbom.json
- name: Sign binary
  run: gpg --detach-sign --armor target/release/oetp-edge
```

---

## 9. Public Verification Portal

A lightweight web UI that reads directly from the ledger and blockchain:

```
Student enters receipt_id
  → GET /v1/ledger/proof { receipt_id }
  → Verify Merkle proof against anchored root
  → Fetch anchor from blockchain RPC
  → Display: packet_hash, answers_hash, timestamp, Merkle proof, anchor tx
```

### Court-admissible evidence bundle

```rust
pub struct EvidenceBundle {
    pub receipt: StudentReceipt,
    pub personal_copy: PersonalAnswerCopy,
    pub merkle_proof: MerkleProof,
    pub blockchain_anchors: Vec<Anchor>,
    pub answer_key_anchor: Anchor,
    pub tenant_public_key: [u8; 32],
}
```

Verifiable offline with only the tenant public key.

---

## 10. Extension Points (Traits)

Every major extension point is a trait in `oetp-core/src/platform.rs`:

| Trait           | Purpose              | Implementations                                                                    |
| --------------- | -------------------- | ---------------------------------------------------------------------------------- |
| `MemoryLocker`  | OS memory locking    | `LinuxMemoryLocker` (built)                                                        |
| `ProcessGuard`  | OS hardening         | `LinuxProcessGuard` (built)                                                        |
| `AnchorBackend` | Blockchain anchoring | `MockAnchorBackend` (test), `PolygonBackend` (todo)                                |
| `Store`         | Persistent storage   | `MemStore` (dev), `SqliteStore` (built), `RocksStore` (todo), `ScyllaStore` (todo) |

---

## 11. Recommended Crates for Production

| Concern              | Crate                              | Notes                             |
| -------------------- | ---------------------------------- | --------------------------------- |
| Blockchain (Polygon) | `alloy`                            | Modern Ethereum Rust client       |
| Blockchain (Bitcoin) | `rust-bitcoin` + `bitcoincore-rpc` | For pre-exam/final anchors        |
| Storage (RocksDB)    | `rocksdb`                          | Single-node, small tenants        |
| Storage (ScyllaDB)   | `scylla`                           | CQL driver, national scale        |
| Messaging (Kafka)    | `rdkafka`                          | High-throughput ingestion         |
| Metrics              | `prometheus` + `axum-prometheus`   | `/metrics` endpoint               |
| TLS                  | `rustls`                           | Reproducible builds, no OpenSSL   |
| seccomp              | `seccompiler`                      | Syscall filtering on Linux        |
| TPM                  | `tss-esapi`                        | Hardware key storage              |
| SBOM                 | `cargo-cyclonedx`                  | Supply chain compliance           |
| Audit                | `cargo-audit`                      | Dependency vulnerability scanning |

---

## 12. Phased Implementation Roadmap

### Phase 1 - Skeleton (✅ Complete)
- Linux edge daemon with 4 API endpoints
- In-memory ledger with 5 API endpoints
- Per-center release tokens with time-bound windows
- Student receipts + encrypted personal answer copy
- Offline queue with AES-GCM encryption
- Merkle tree proofs and verification
- 162+ passing tests

### Phase 2 - Production Hardening (Next)
- [ ] Swap `MemStore` for `SqliteStore` (built, just wire it)
- [ ] Implement real `PolygonBackend` (alloy crate)
- [ ] Add Prometheus metrics to both daemons
- [ ] Add TLS via reverse proxy (documented above)
- [ ] Add rate limiting middleware
- [ ] Add CI/CD pipeline
- [ ] Switch `reqwest` to `rustls-tls`
- [ ] Add structured audit logging
- [ ] Redact PII from logs
- [ ] Restrict CORS to exact origin
- [ ] Set queue file permissions
- [ ] Add input validation for tenant/exam IDs

### Phase 3 - Scale
- [ ] Kafka ingestion pipeline
- [ ] ScyllaDB hot store
- [ ] Stateless ledger workers
- [ ] 99.9% SLA operational target

### Phase 4 - Hardened Anchoring & Transparency
- [ ] Multi-chain anchoring (Polygon + Bitcoin + IndiaChain)
- [ ] Public web verification portal
- [ ] Court-admissible evidence bundle
- [ ] Answer-key challenge workflow

### Phase 5 - Cross-Platform & Hardware Security
- [ ] Extract `oetp-linux`, `oetp-windows`, `oetp-android` crates
- [ ] TPM/TEE attestation for release
- [ ] HSM-backed center keys
- [ ] seccomp-bpf syscall filtering

---

## 13. Engineering Principles

- **Keep the core small.** All operational complexity lives in `oetp-edge` and `oetp-ledger`, not `oetp-core`.
- **Use traits for extension points.** New storage, chains, or OS features plug into existing traits in `platform.rs`.
- **Tests before code.** The skeleton's TDD rules apply to every new feature.
- **Prefer proven crates over custom code.** Do not hand-roll crypto, consensus, or distributed systems.
- **Document every deferred decision.** If something is hard now, explain why and when to revisit it.
