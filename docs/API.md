# OETP API Reference - Postman / curl Testing Guide

All endpoints require `x-api-key: dev-api-key-12345678` header unless noted.

## Services

| Service | Port | Base URL                |
| ------- | ---- | ----------------------- |
| Ledger  | 8081 | `http://localhost:8081` |
| Beacon  | 9090 | `http://localhost:9090` |
| Edge    | 8080 | `http://localhost:8080` |

## Quick Start

```bash
# 1. One-time setup
cd oetp
./dev/setup.sh          # generates keys, writes dev/.env, creates sample data

# 2. Start all services
./dev/start.sh          # builds, then launches ledger + beacon + edge

# 3. Run the full lifecycle smoke tests
./dev/curl-tests.sh

# 4. Stop all services
./dev/stop.sh
```

---

## 1. Health Checks

```bash
curl -s http://localhost:8081/health | jq .
curl -s http://localhost:9090/health | jq .
curl -s http://localhost:8080/health | jq .
```

**Response:** `{"status":"ok"}`

---

## 2. Ledger: Commit Packet Hashes (Pre-Exam)

Commits the Merkle root of all packet hashes before the exam starts.

```bash
curl -s -X POST http://localhost:8081/v1/ledger/commit \
  -H "x-api-key: dev-api-key-12345678" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "nta",
    "exam_id": "jee-2027",
    "packet_hashes": [
      [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32],
      [33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64]
    ]
  }' | jq .
```

**Response:**
```json
{
  "merkle_root": [32 bytes array],
  "anchor": {
    "chain_id": "polygon",
    "tx_hash": "0x...",
    "anchored_root": [32 bytes array],
    "anchor_type": "PreExam",
    "timestamp": 1700000000,
    "signature": []
  }
}
```

---

## 3. Ledger: Load Generated Packets

Loads pre-generated encrypted packets and key envelopes into the ledger for serving to edge daemons.

```bash
# Load a single packet (use the actual UUID from dev/output/)
curl -s -X POST http://localhost:8081/v1/ledger/load \
  -H "x-api-key: dev-api-key-12345678" \
  -H "Content-Type: application/json" \
  -d '{
    "key": "nta:jee-2027:550e8400-e29b-41d4-a716-446655440000",
    "encrypted_packet": {
      "tenant_id": "nta",
      "student_uuid": "550e8400-e29b-41d4-a716-446655440000",
      "exam_id": "jee-2027",
      "ciphertext": [1,2,3],
      "nonce": [0,0,0,0,0,0,0,0,0,0,0,0],
      "packet_hash": [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32]
    },
    "key_envelope": {
      "version": 1,
      "device_id": "device-01",
      "student_uuid": "550e8400-e29b-41d4-a716-446655440000",
      "exam_id": "jee-2027",
      "sender_public_key": [32 bytes],
      "encrypted_ephemeral_key": [bytes],
      "nonce": [12 bytes]
    }
  }' | jq .
```

**Response:** `{"status":"loaded"}`

---

## 4. Ledger: Fetch Packet (for Edge)

The edge daemon calls this to download a student's encrypted packet and key envelope.

```bash
curl -s -X POST http://localhost:8081/v1/ledger/fetch \
  -H "x-api-key: dev-api-key-12345678" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "nta",
    "exam_id": "jee-2027",
    "student_uuid": "550e8400-e29b-41d4-a716-446655440000"
  }' | jq .
```

**Response:**
```json
{
  "encrypted_packet": { ... },
  "key_envelope": { ... }
}
```

---

## 5. Ledger: Ingest Submission

Receives a signed submission leaf from the edge daemon.

```bash
curl -s -X POST http://localhost:8081/v1/ledger/ingest \
  -H "x-api-key: dev-api-key-12345678" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "nta",
    "exam_id": "jee-2027",
    "student_uuid": "550e8400-e29b-41d4-a716-446655440000",
    "packet_hash": [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32],
    "answers_hash": [32 bytes],
    "merkle_leaf": [32 bytes],
    "timestamp": 1700000000,
    "signature": [64 bytes],
    "receipt_id": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
  }' | jq .
```

**Response:**
```json
{
  "leaf_index": 0,
  "status": "ingested"
}
```

---

## 6. Ledger: Get Merkle Proof

Retrieve a Merkle proof for a submission by receipt ID.

```bash
curl -s -X POST http://localhost:8081/v1/ledger/proof \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "nta",
    "exam_id": "jee-2027",
    "receipt_id": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
  }' | jq .
```

**Response:**
```json
{
  "merkle_leaf": [32 bytes or null],
  "leaf_index": 0,
  "total_leaves": 1,
  "siblings": [[32 bytes], ...],
  "root": [32 bytes or null]
}
```

---

## 7. Ledger: Verify Submission

Verify a submission's leaf hash, edge signature, and ledger inclusion.

```bash
curl -s -X POST http://localhost:8081/v1/ledger/verify \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "nta",
    "exam_id": "jee-2027",
    "student_uuid": "550e8400-e29b-41d4-a716-446655440000",
    "packet_hash": [32 bytes],
    "answers_hash": [32 bytes],
    "timestamp": 1700000000,
    "merkle_leaf": [32 bytes],
    "edge_signature": [64 bytes],
    "edge_public_key": [32 bytes]
  }' | jq .
```

**Response:**
```json
{
  "valid": true,
  "reason": "verified",
  "leaf_index": 0,
  "total_leaves": 1,
  "anchored_root": [32 bytes]
}
```

---

## 8. Ledger: Commit Answer Key

Anchor the answer key hash after the exam closes.

```bash
curl -s -X POST http://localhost:8081/v1/ledger/key \
  -H "x-api-key: dev-api-key-12345678" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "nta",
    "exam_id": "jee-2027",
    "answer_key_hash": [239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239]
  }' | jq .
```

**Response:**
```json
{
  "anchor": {
    "chain_id": "polygon",
    "tx_hash": "0x...",
    "anchored_root": [32 bytes],
    "anchor_type": "AnswerKey",
    "timestamp": 1700000000,
    "signature": []
  }
}
```

---

## 9. Ledger: List Anchors

List all ledger anchors for a tenant/exam.

```bash
curl -s -X POST http://localhost:8081/v1/ledger/anchors \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "nta",
    "exam_id": "jee-2027"
  }' | jq .
```

**Response:**
```json
{
  "anchors": [ ... ]
}
```

---

## 10. Beacon: Get Release Token

The edge daemon calls this to get a time-bound, device-bound release token.

```bash
curl -s -X POST http://localhost:9090/v1/beacon/token \
  -H "Content-Type: application/json" \
  -d '{
    "center_id": "center-01",
    "exam_id": "jee-2027",
    "device_id": "device-01"
  }' | jq .
```

**Response:**
```json
{
  "center_id": "center-01",
  "exam_id": "jee-2027",
  "device_id": "device-01",
  "window_start": 1700000000,
  "window_end": 1700000300,
  "nonce": [16 random bytes],
  "signature": [64 bytes]
}
```

---

## 11. Edge: Fetch Packet

The legacy UI calls this to download the encrypted packet for a student.

```bash
curl -s -X POST http://localhost:8080/v1/exam/fetch \
  -H "x-api-key: dev-api-key-12345678" \
  -H "Content-Type: application/json" \
  -d '{
    "student_uuid": "550e8400-e29b-41d4-a716-446655440000",
    "application_number": "APP123"
  }' | jq .
```

**Response:**
```json
{
  "status": "cached",
  "packet_hash": [32 bytes]
}
```

---

## 12. Edge: Get Release Token

The legacy UI calls this to trigger the release token flow (edge talks to beacon internally).

```bash
curl -s -X POST http://localhost:8080/v1/exam/release \
  -H "x-api-key: dev-api-key-12345678" \
  -H "Content-Type: application/json" \
  -d '{
    "student_uuid": "550e8400-e29b-41d4-a716-446655440000"
  }' | jq .
```

**Response:**
```json
{
  "status": "released"
}
```

---

## 13. Edge: Unlock / Decrypt Packet

Decrypts the packet and returns plaintext questions (requires release token first).

```bash
curl -s -X POST http://localhost:8080/v1/exam/unlock \
  -H "x-api-key: dev-api-key-12345678" \
  -H "Content-Type: application/json" \
  -d '{
    "student_uuid": "550e8400-e29b-41d4-a716-446655440000"
  }' | jq .
```

**Response:**
```json
{
  "questions": [
    {
      "bank_item_id": 1,
      "variant_id": 0,
      "stem": "What is the capital of France?",
      "options": ["London", "Paris", "Berlin", "Madrid"],
      "question_ref": "q_1"
    }
  ]
}
```

---

## 14. Edge: Submit Answers

Seals answers and returns a receipt + personal answer copy.

```bash
curl -s -X POST http://localhost:8080/v1/exam/submit \
  -H "x-api-key: dev-api-key-12345678" \
  -H "Content-Type: application/json" \
  -d '{
    "student_uuid": "550e8400-e29b-41d4-a716-446655440000",
    "application_number": "APP123",
    "dob": "2000-01-01",
    "answers": {
      "q_1": "Paris",
      "q_2": "4",
      "q_3": "Mars",
      "q_4": "H2O",
      "q_5": "7"
    }
  }' | jq .
```

**Response:**
```json
{
  "receipt_id": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
  "receipt": {
    "receipt_id": "...",
    "tenant_id": "nta",
    "exam_id": "jee-2027",
    "application_number": "APP123",
    "student_uuid": "550e8400-...",
    "packet_hash": [32 bytes],
    "answers_hash": [32 bytes],
    "timestamp": 1700000000,
    "merkle_proof": { "leaf_index": 0, "leaf": [32], "siblings": [], "root": [32] },
    "edge_signature": [64 bytes],
    "ledger_signature": [],
    "qr_payload": "oetp:receipt:a1b2c3d4..."
  },
  "personal_copy": {
    "receipt_id": "...",
    "encrypted_answers": [bytes],
    "nonce": [12 bytes],
    "answers_hash": [32 bytes]
  }
}
```

---

## Full Lifecycle Test (one-liner)

```bash
# 1. Health
curl -s http://localhost:8081/health && echo ""

# 2. Commit packet hashes
curl -s -X POST http://localhost:8081/v1/ledger/commit \
  -H "x-api-key: dev-api-key-12345678" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id":"nta","exam_id":"jee-2027","packet_hashes":[[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32]]}' | jq .merkle_root

# 3. Fetch packet via edge
curl -s -X POST http://localhost:8080/v1/exam/fetch \
  -H "x-api-key: dev-api-key-12345678" \
  -H "Content-Type: application/json" \
  -d '{"student_uuid":"550e8400-e29b-41d4-a716-446655440000","application_number":"APP123"}' | jq .

# 4. Get release token via edge
curl -s -X POST http://localhost:8080/v1/exam/release \
  -H "x-api-key: dev-api-key-12345678" \
  -H "Content-Type: application/json" \
  -d '{"student_uuid":"550e8400-e29b-41d4-a716-446655440000"}' | jq .

# 5. Unlock/decrypt
curl -s -X POST http://localhost:8080/v1/exam/unlock \
  -H "x-api-key: dev-api-key-12345678" \
  -H "Content-Type: application/json" \
  -d '{"student_uuid":"550e8400-e29b-41d4-a716-446655440000"}' | jq .

# 6. Submit answers
curl -s -X POST http://localhost:8080/v1/exam/submit \
  -H "x-api-key: dev-api-key-12345678" \
  -H "Content-Type: application/json" \
  -d '{"student_uuid":"550e8400-e29b-41d4-a716-446655440000","application_number":"APP123","dob":"2000-01-01","answers":{"q_1":"Paris","q_2":"4"}}' | jq .
```

---

## Postman Import

Copy the JSON below into Postman → Import → Raw Text to get a full collection:

```json
{
  "info": { "name": "OETP API", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json" },
  "item": [
    { "name": "Health (Ledger)", "request": { "method": "GET", "url": "http://localhost:8081/health" } },
    { "name": "Health (Beacon)", "request": { "method": "GET", "url": "http://localhost:9090/health" } },
    { "name": "Health (Edge)", "request": { "method": "GET", "url": "http://localhost:8080/health" } },
    { "name": "Commit Packet Hashes", "request": { "method": "POST", "header": [{ "key": "x-api-key", "value": "dev-api-key-12345678" }], "url": "http://localhost:8081/v1/ledger/commit", "body": { "mode": "raw", "raw": "{\"tenant_id\":\"nta\",\"exam_id\":\"jee-2027\",\"packet_hashes\":[[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32]]}" } } },
    { "name": "Fetch Packet (Edge)", "request": { "method": "POST", "header": [{ "key": "x-api-key", "value": "dev-api-key-12345678" }], "url": "http://localhost:8080/v1/exam/fetch", "body": { "mode": "raw", "raw": "{\"student_uuid\":\"550e8400-e29b-41d4-a716-446655440000\",\"application_number\":\"APP123\"}" } } },
    { "name": "Release Token (Edge)", "request": { "method": "POST", "header": [{ "key": "x-api-key", "value": "dev-api-key-12345678" }], "url": "http://localhost:8080/v1/exam/release", "body": { "mode": "raw", "raw": "{\"student_uuid\":\"550e8400-e29b-41d4-a716-446655440000\"}" } } },
    { "name": "Unlock Packet (Edge)", "request": { "method": "POST", "header": [{ "key": "x-api-key", "value": "dev-api-key-12345678" }], "url": "http://localhost:8080/v1/exam/unlock", "body": { "mode": "raw", "raw": "{\"student_uuid\":\"550e8400-e29b-41d4-a716-446655440000\"}" } } },
    { "name": "Submit Answers (Edge)", "request": { "method": "POST", "header": [{ "key": "x-api-key", "value": "dev-api-key-12345678" }], "url": "http://localhost:8080/v1/exam/submit", "body": { "mode": "raw", "raw": "{\"student_uuid\":\"550e8400-e29b-41d4-a716-446655440000\",\"application_number\":\"APP123\",\"dob\":\"2000-01-01\",\"answers\":{\"q_1\":\"Paris\",\"q_2\":\"4\"}}" } } },
    { "name": "Ingest Submission (Ledger)", "request": { "method": "POST", "header": [{ "key": "x-api-key", "value": "dev-api-key-12345678" }], "url": "http://localhost:8081/v1/ledger/ingest", "body": { "mode": "raw", "raw": "{\"tenant_id\":\"nta\",\"exam_id\":\"jee-2027\",\"student_uuid\":\"550e8400-e29b-41d4-a716-446655440000\",\"packet_hash\":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32],\"answers_hash\":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32],\"merkle_leaf\":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32],\"timestamp\":1700000000,\"signature\":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64],\"receipt_id\":\"test-receipt-001\"}" } } },
    { "name": "Get Merkle Proof", "request": { "method": "POST", "url": "http://localhost:8081/v1/ledger/proof", "body": { "mode": "raw", "raw": "{\"tenant_id\":\"nta\",\"exam_id\":\"jee-2027\",\"receipt_id\":\"test-receipt-001\"}" } } },
    { "name": "Verify Submission", "request": { "method": "POST", "url": "http://localhost:8081/v1/ledger/verify", "body": { "mode": "raw", "raw": "{\"tenant_id\":\"nta\",\"exam_id\":\"jee-2027\",\"student_uuid\":\"550e8400-e29b-41d4-a716-446655440000\",\"packet_hash\":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32],\"answers_hash\":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32],\"timestamp\":1700000000,\"merkle_leaf\":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32],\"edge_signature\":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64],\"edge_public_key\":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32]}" } } },
    { "name": "Commit Answer Key", "request": { "method": "POST", "header": [{ "key": "x-api-key", "value": "dev-api-key-12345678" }], "url": "http://localhost:8081/v1/ledger/key", "body": { "mode": "raw", "raw": "{\"tenant_id\":\"nta\",\"exam_id\":\"jee-2027\",\"answer_key_hash\":[239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239]}" } } },
    { "name": "List Anchors", "request": { "method": "POST", "url": "http://localhost:8081/v1/ledger/anchors", "body": { "mode": "raw", "raw": "{\"tenant_id\":\"nta\",\"exam_id\":\"jee-2027\"}" } } },
    { "name": "Beacon Token", "request": { "method": "POST", "url": "http://localhost:9090/v1/beacon/token", "body": { "mode": "raw", "raw": "{\"center_id\":\"center-01\",\"exam_id\":\"jee-2027\",\"device_id\":\"device-01\"}" } } }
  ]
}
```

---

## Development Scripts

| Script                | Purpose                                                                                                                               |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `./dev/setup.sh`      | Generates Ed25519/X25519 keys, creates `dev/.env`, and writes sample `question_bank.json` + `students.csv`.                           |
| `./dev/start.sh`      | Builds all crates, kills leftover processes, starts ledger + beacon + edge, generates sample packets, and loads them into the ledger. |
| `./dev/stop.sh`       | Stops the services started by `start.sh` using saved PIDs.                                                                            |
| `./dev/curl-tests.sh` | Runs a full lifecycle smoke test via curl against the running dev environment.                                                        |

## Environment / Key Permissions

- Key files (`dev/device.key`, `dev/device_x25519.key`, `dev/ledger.key`, `dev/beacon.key`, `dev/.env`) are created with mode `0600`.
- The edge daemon refuses to load a device key file whose mode is more permissive than `0600`.
- The beacon public key is injected into `dev/.env` at setup time so the edge daemon can verify release-token signatures.
- The ledger and beacon bind to `0.0.0.0` so they can be reached from Postman/curl on the same machine.
- The edge binds to `127.0.0.1:8080` and is the only service the legacy UI talks to.

## Troubleshooting

- **Port already in use:** `start.sh` tries to kill any process listening on `8080`, `8081`, or `9090` before launching new services. Run `./dev/stop.sh` and try again.
- **No cached packet on unlock:** call `/v1/exam/fetch` for the student first.
- **No release token on unlock:** call `/v1/exam/release` before `/v1/exam/unlock`.
- **Proof returns nulls:** the receipt has not been ingested into the ledger yet; the edge queues submissions and retries automatically every 30s.
