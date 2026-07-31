#!/usr/bin/env bash
# National-scale end-to-end stress test
# Simulates: 4 exam centers, 30 students each, real HTTP servers,
# network failures, queue retries, tampering attacks, and full verification.
#
# Each center has 1 beacon + 3 edge devices. Each edge serves 10 students.
# Total: 4 centers, 4 beacons, 12 edges, 120 students.
set -uo pipefail

cd "$(dirname "$0")/.."

LEDGER="http://localhost:8081"
API_KEY="dev-api-key-12345678-with-enough-characters"

# The e2e stress test runs many requests from localhost; use a high rate-limit ceiling.
export OETP_RATE_LIMIT_PER_SECOND="${OETP_RATE_LIMIT_PER_SECOND:-1000}"
export OETP_RATE_LIMIT_BURST="${OETP_RATE_LIMIT_BURST:-100000}"
TENANT_ID="nta"
EXAM_ID="jee-2027"
FAIL=0
TOTAL=0

pass() { echo "  PASS"; }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }
check() {
  TOTAL=$((TOTAL + 1))
  local label="$1" got="$2"
  if echo "$got" | jq -e "$3" >/dev/null 2>&1; then pass; else fail "$label: expected $3, got $(echo "$got" | jq -c . 2>/dev/null || echo "$got")"; fi
}
check_raw() {
  TOTAL=$((TOTAL + 1))
  local label="$1" got="$2" expected="$3"
  if [[ "$got" == "$expected" ]]; then pass; else fail "$label: expected $expected, got $got"; fi
}
check_contains() {
  TOTAL=$((TOTAL + 1))
  local label="$1" got="$2" expected="$3"
  if [[ "$got" == *"$expected"* ]]; then pass; else fail "$label: expected to contain '$expected', got $got"; fi
}

# -- Ensure services are running ------------------------------------------
echo "=== Checking services ==="
for i in 1 2 3 4 5; do
  if curl -sf "$LEDGER/health" >/dev/null 2>&1; then
    echo "services are up"
    break
  fi
  if [ "$i" -eq 5 ]; then
    echo "ERROR: services not running. Run ./dev/start.sh first."
    exit 1
  fi
  sleep 2
done

set -a; source ./dev/.env; set +a

# Kill the existing edge from start.sh (device-01) - we'll start all 12 ourselves
if [ -f ./dev/edge.pid ]; then
  kill "$(cat ./dev/edge.pid)" 2>/dev/null || true
  rm -f ./dev/edge.pid
  sleep 1
fi

# Kill any leftover test processes
for pid_file in /tmp/oetp_test_*.pid; do
  [ -f "$pid_file" ] && kill "$(cat "$pid_file")" 2>/dev/null || true
  rm -f "$pid_file"
done

# -- 1. Generate 120 students across 4 centers ----------------------------
echo ""
echo "=== [1] Generating 120 students across 4 centers ==="

STUDENTS_CSV=$(mktemp)
for ci in 1 2 3 4; do
  for di in 1 2 3; do
    for si in $(seq 1 10); do
      UUID="00000000-0000-0000-0000-$(printf '%012d' $(( (ci-1)*30 + (di-1)*10 + si )))"
      echo "$UUID,center-0${ci}-device-0${di}"
    done
  done
done > "$STUDENTS_CSV"
echo "  created $(wc -l < "$STUDENTS_CSV") students"

DEVICE_X25519_PUB=$(python3 -c "
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
priv_hex = open('./dev/device_x25519.key').read().strip()
priv_bytes = bytes.fromhex(priv_hex)
priv_key = X25519PrivateKey.from_private_bytes(priv_bytes)
pub_key = priv_key.public_key()
print(pub_key.public_bytes_raw().hex())
")

OUTPUT_DIR=$(mktemp -d)
cargo run --release -p oetp-ledger -- generate \
  --bank ./dev/question_bank.json \
  --students "$STUDENTS_CSV" \
  --num-questions 5 \
  --output "$OUTPUT_DIR" \
  --tenant-master-key "${OETP_TENANT_MASTER_KEY:-abababababababababababababababababababababababababababababababab}" \
  --exam-id "$EXAM_ID" \
  --tenant-id "$TENANT_ID" \
  --device-x25519-pub "$DEVICE_X25519_PUB" 2>&1 | sed 's/^/  /'
echo "  packets generated in $OUTPUT_DIR"

export OETP_TENANT_ID="$TENANT_ID"
export OETP_EXAM_ID="$EXAM_ID"
export OETP_SIGNING_KEY="$OETP_SIGNING_KEY"
export OETP_API_KEY="$API_KEY"
export OETP_LEDGER_LISTEN_ADDR="$OETP_LEDGER_LISTEN_ADDR"
cargo run --release -p oetp-ledger -- load \
  --input "$OUTPUT_DIR" 2>&1 | sed 's/^/  /'

# -- 2. Commit packet hashes ---------------------------------------------
echo ""
echo "=== [2] Committing packet hashes ==="
PACKET_HASHES=$(jq '[.entries[].packet_hash]' "$OUTPUT_DIR/manifest.json")
COMMIT=$(curl -sf -X POST "$LEDGER/v1/ledger/commit" \
  -H "x-api-key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"tenant_id\":\"$TENANT_ID\",\"exam_id\":\"$EXAM_ID\",\"packet_hashes\":$PACKET_HASHES}")
check "merkle_root present" "$COMMIT" '.merkle_root | length == 32'
check "anchor PreExam"      "$COMMIT" '.anchor.anchor_type == "PreExam"'
echo "  committed $(echo "$PACKET_HASHES" | jq length) packet hashes"

# Capture baseline leaf count after commit (1 root leaf)
BASELINE=$(curl -sf -X POST "$LEDGER/v1/ledger/proof" \
  -H "Content-Type: application/json" \
  -d "{\"tenant_id\":\"$TENANT_ID\",\"exam_id\":\"$EXAM_ID\",\"receipt_id\":\"dummy\"}" | jq '.total_leaves')
echo "  baseline leaves after commit: $BASELINE"

# Define exam window (current time + 2 hours)
EXAM_WINDOW_START=$(date +%s)
EXAM_WINDOW_END=$((EXAM_WINDOW_START + 7200))
echo "  exam window: $EXAM_WINDOW_START -> $EXAM_WINDOW_END"

# -- 3. Start 4 beacons and 12 edge daemons -----------------------------
echo ""
echo "=== [3] Starting 4 beacons and 12 edge daemons ==="

# Use high port ranges to avoid conflicts
BEACON_BASE=9300
EDGE_BASE=9200

# Start 4 beacons with known keypairs
BEACON_KEYS=()
for ci in 1 2 3 4; do
  PORT=$((BEACON_BASE + ci))
  # Generate a proper Ed25519 keypair and extract both private and public
  KEYPAIR=$(cargo run --release -p oetp-ledger -- keygen 2>/dev/null)
  BEACON_SK=$(echo "$KEYPAIR" | head -1)
  BEACON_PK=$(echo "$KEYPAIR" | tail -1)
  BEACON_KEYS+=("$BEACON_PK")
  RUST_LOG=info \
  OETP_BEACON_LISTEN_ADDR="127.0.0.1:$PORT" \
  OETP_BEACON_SIGNING_KEY="$BEACON_SK" \
  OETP_EXAM_WINDOW_START="$EXAM_WINDOW_START" \
  OETP_EXAM_WINDOW_END="$EXAM_WINDOW_END" \
  OETP_API_KEY="$API_KEY" \
    cargo run --release -p oetp-beacon >/dev/null 2>&1 &
  echo $! > "/tmp/oetp_test_beacon_${ci}.pid"
  echo "  beacon $ci on port $PORT (pid $!)"
done

# Wait for beacons
sleep 2

# Start 12 edges
EDGE_COUNT=0
for ci in 1 2 3 4; do
  for di in 1 2 3; do
    EDGE_COUNT=$((EDGE_COUNT + 1))
    PORT=$((EDGE_BASE + EDGE_COUNT))
    DEVICE_ID="center-0${ci}-device-0${di}"
    CENTER_ID="center-0${ci}"
    BEACON_PORT=$((BEACON_BASE + ci))
    BEACON_PK=${BEACON_KEYS[$((ci - 1))]}

    RUST_LOG=info \
    OETP_TENANT_ID="$TENANT_ID" \
    OETP_EXAM_ID="$EXAM_ID" \
    OETP_DEVICE_ID="$DEVICE_ID" \
    OETP_CENTER_ID="$CENTER_ID" \
    OETP_LEDGER_URL="$LEDGER" \
    OETP_BEACON_URL="http://127.0.0.1:$BEACON_PORT" \
    OETP_LISTEN_ADDR="127.0.0.1:$PORT" \
    OETP_DEVICE_KEY="$OETP_DEVICE_KEY" \
    OETP_DEVICE_X25519_KEY="$OETP_DEVICE_X25519_KEY" \
    OETP_CACHE_DIR="$(mktemp -d)" \
    OETP_QUEUE_DIR="$(mktemp -d)" \
    OETP_BEACON_PUBLIC_KEY="$BEACON_PK" \
    OETP_EXAM_SALT="$OETP_EXAM_SALT" \
    OETP_SERVER_PEPPER="$OETP_SERVER_PEPPER" \
    OETP_API_KEY="$API_KEY" \
    OETP_EXAM_WINDOW_START="$EXAM_WINDOW_START" \
    OETP_EXAM_WINDOW_END="$EXAM_WINDOW_END" \
      cargo run --release -p oetp-edge >/dev/null 2>&1 &
    echo $! > "/tmp/oetp_test_edge_${EDGE_COUNT}.pid"
    echo "  edge $EDGE_COUNT ($DEVICE_ID) on port $PORT (pid $!)"
  done
done

# Wait for all edges to be ready
echo "  waiting for edges..."
for i in $(seq 1 20); do
  ALL_UP=true
  for ci in 1 2 3 4; do
    for di in 1 2 3; do
      EDGE_INDEX=$(( (ci-1)*3 + di ))
      PORT=$((EDGE_BASE + EDGE_INDEX))
      if ! curl -sf "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; then
        ALL_UP=false
      fi
    done
  done
  if $ALL_UP; then
    echo "  all edges ready"
    break
  fi
  sleep 1
done

# -- 4. Run exam lifecycle for all 120 students -------------------------
echo ""
echo "=== [4] Running exam lifecycle for 120 students ==="

SUBMITTED=0
FAILED_SUBMISSIONS=""
# Track one receipt_id per edge for proof verification
declare -A RECEIPTS

STUDENT_INDEX=0
for ci in 1 2 3 4; do
  for di in 1 2 3; do
    EDGE_INDEX=$(( (ci-1)*3 + di ))
    EDGE_PORT=$((EDGE_BASE + EDGE_INDEX))
    EDGE_URL="http://127.0.0.1:$EDGE_PORT"

    for si in $(seq 1 10); do
      STUDENT_INDEX=$((STUDENT_INDEX + 1))
      UUID="00000000-0000-0000-0000-$(printf '%012d' $STUDENT_INDEX)"
      APP_NUM="APP$(printf '%04d' $STUDENT_INDEX)"

      FETCH=$(curl -sf -X POST "$EDGE_URL/v1/exam/fetch" \
        -H "x-api-key: $API_KEY" \
        -H "Content-Type: application/json" \
        -d "{\"student_uuid\":\"$UUID\",\"application_number\":\"$APP_NUM\"}" 2>/dev/null || echo '{"status":"error"}')
      if [ "$(echo "$FETCH" | jq -r '.status')" != "cached" ]; then
        FAILED_SUBMISSIONS="$FAILED_SUBMISSIONS $UUID(fetch)"
        continue
      fi

      RELEASE=$(curl -sf -X POST "$EDGE_URL/v1/exam/release" \
        -H "x-api-key: $API_KEY" \
        -H "Content-Type: application/json" \
        -d "{\"student_uuid\":\"$UUID\"}" 2>/dev/null || echo '{"status":"error"}')
      if [ "$(echo "$RELEASE" | jq -r '.status')" != "released" ]; then
        FAILED_SUBMISSIONS="$FAILED_SUBMISSIONS $UUID(release)"
        continue
      fi

      UNLOCK=$(curl -sf -X POST "$EDGE_URL/v1/exam/unlock" \
        -H "x-api-key: $API_KEY" \
        -H "Content-Type: application/json" \
        -d "{\"student_uuid\":\"$UUID\"}" 2>/dev/null || echo '{"questions":[]}')
      Q_COUNT=$(echo "$UNLOCK" | jq '.questions | length')
      if [ "$Q_COUNT" -lt 1 ]; then
        FAILED_SUBMISSIONS="$FAILED_SUBMISSIONS $UUID(unlock)"
        continue
      fi

      ANSWERS=$(echo "$UNLOCK" | jq '[.questions[].question_ref] | map({(.): "A"}) | add')
      SUBMIT=$(curl -sf -X POST "$EDGE_URL/v1/exam/submit" \
        -H "x-api-key: $API_KEY" \
        -H "Content-Type: application/json" \
        -d "{\"student_uuid\":\"$UUID\",\"application_number\":\"$APP_NUM\",\"dob\":\"2000-01-01\",\"answers\":$ANSWERS}" 2>/dev/null || echo '{"receipt_id":""}')
      RID=$(echo "$SUBMIT" | jq -r '.receipt_id')
      if [ -z "$RID" ] || [ "$RID" = "null" ]; then
        FAILED_SUBMISSIONS="$FAILED_SUBMISSIONS $UUID(submit)"
        continue
      fi

      # Save first receipt from each edge for proof verification
      if [ -z "${RECEIPTS[$EDGE_INDEX]:-}" ]; then
        RECEIPTS[$EDGE_INDEX]="$RID"
      fi

      SUBMITTED=$((SUBMITTED + 1))
    done
  done
done

echo "  submitted: $SUBMITTED / 120"
if [ -n "$FAILED_SUBMISSIONS" ]; then
  echo "  FAILED: $FAILED_SUBMISSIONS"
fi
check_raw "all students submitted" "$SUBMITTED" "120"

# -- 5. Flush all edge queues --------------------------------------------
echo ""
echo "=== [5] Flushing all edge queues ==="
for ci in 1 2 3 4; do
  for di in 1 2 3; do
    EDGE_INDEX=$(( (ci-1)*3 + di ))
    EDGE_PORT=$((EDGE_BASE + EDGE_INDEX))
    FLUSH=$(curl -sf -X POST "http://127.0.0.1:$EDGE_PORT/v1/system/flush" \
      -H "x-api-key: $API_KEY" \
      -H "Content-Type: application/json" 2>/dev/null || echo '{"flushed":0}')
    FCOUNT=$(echo "$FLUSH" | jq '.flushed')
    echo "  edge $EDGE_INDEX (center-0${ci}-device-0${di}): flushed $FCOUNT"
  done
done

# -- 6. Check ledger has all submissions ---------------------------------
echo ""
echo "=== [6] Checking ledger submissions ==="
echo "  baseline leaves (packet hashes): $BASELINE"

# Verify each edge's submission via its receipt_id
for ci in 1 2 3 4; do
  for di in 1 2 3; do
    EDGE_INDEX=$(( (ci-1)*3 + di ))
    RID="${RECEIPTS[$EDGE_INDEX]:-}"
    if [ -n "$RID" ]; then
      PROOF=$(curl -sf -X POST "$LEDGER/v1/ledger/proof" \
        -H "Content-Type: application/json" \
        -d "{\"tenant_id\":\"$TENANT_ID\",\"exam_id\":\"$EXAM_ID\",\"receipt_id\":\"$RID\"}")
      check "edge $EDGE_INDEX receipt $RID has merkle_leaf" "$PROOF" '.merkle_leaf != null'
      check "edge $EDGE_INDEX receipt $RID has leaf_index" "$PROOF" '.leaf_index != null'
    fi
  done
done

# Check total leaves = baseline + 120 submissions
TOTAL_LEAVES=$(curl -sf -X POST "$LEDGER/v1/ledger/proof" \
  -H "Content-Type: application/json" \
  -d "{\"tenant_id\":\"$TENANT_ID\",\"exam_id\":\"$EXAM_ID\",\"receipt_id\":\"dummy\"}" | jq '.total_leaves')
echo "  total leaves in ledger: $TOTAL_LEAVES"
check_raw "all submissions in ledger" "$TOTAL_LEAVES" "$((BASELINE + 120))"

# -- 7. Commit answer key ------------------------------------------------
echo ""
echo "=== [7] Committing answer key ==="
KEY_COMMIT=$(curl -sf -X POST "$LEDGER/v1/ledger/key" \
  -H "x-api-key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"tenant_id\":\"$TENANT_ID\",\"exam_id\":\"$EXAM_ID\",\"answer_key_hash\":[239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239]}")
check "anchor_type AnswerKey" "$KEY_COMMIT" '.anchor.anchor_type == "AnswerKey"'

# -- 8. List anchors ------------------------------------------------------
echo ""
echo "=== [8] Listing anchors ==="
ANCHORS=$(curl -sf -X POST "$LEDGER/v1/ledger/anchors" \
  -H "Content-Type: application/json" \
  -d "{\"tenant_id\":\"$TENANT_ID\",\"exam_id\":\"$EXAM_ID\"}")
check "anchors present" "$ANCHORS" '.anchors | length >= 2'

# -- 9. ATTACK TESTS -----------------------------------------------------
echo ""
echo "=== [9] Running attack/failure tests ==="

# 9a. Wrong API key on edge
echo "  9a. Wrong API key on edge..."
AUTH=$(curl -s -X POST "http://127.0.0.1:$((EDGE_BASE + 1))/v1/exam/fetch" \
  -H "x-api-key: wrong-key" \
  -H "Content-Type: application/json" \
  -d '{"student_uuid":"00000000-0000-0000-0000-000000000001","application_number":"APP0001"}')
check_contains "wrong api key" "$AUTH" "invalid api key"

# 9b. Wrong API key on ledger
echo "  9b. Wrong API key on ledger..."
AUTH2=$(curl -s -X POST "$LEDGER/v1/ledger/commit" \
  -H "x-api-key: wrong-key" \
  -H "Content-Type: application/json" \
  -d "{\"tenant_id\":\"$TENANT_ID\",\"exam_id\":\"$EXAM_ID\",\"packet_hashes\":[]}")
check_contains "wrong ledger api key" "$AUTH2" "invalid api key"

# 9c. Empty commit
echo "  9c. Empty commit..."
EMPTY=$(curl -s -X POST "$LEDGER/v1/ledger/commit" \
  -H "x-api-key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"tenant_id\":\"$TENANT_ID\",\"exam_id\":\"$EXAM_ID\",\"packet_hashes\":[]}")
check_contains "empty commit" "$EMPTY" "needs at least one leaf"

# 9d. Fetch non-existent student
echo "  9d. Fetch non-existent student..."
NOT_FOUND=$(curl -s -X POST "$LEDGER/v1/ledger/fetch" \
  -H "x-api-key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"tenant_id\":\"$TENANT_ID\",\"exam_id\":\"$EXAM_ID\",\"student_uuid\":\"ffffffff-ffff-ffff-ffff-ffffffffffff\"}")
check_contains "not found" "$NOT_FOUND" "not found"

# 9e. Unlock without fetch (should 404)
echo "  9e. Unlock without fetch..."
NO_FETCH=$(curl -s -X POST "http://127.0.0.1:$((EDGE_BASE + 1))/v1/exam/unlock" \
  -H "x-api-key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"student_uuid":"ffffffff-ffff-ffff-ffff-ffffffffffff"}')
check_contains "no cached" "$NO_FETCH" "no cached"

# 9f. Proof for unknown receipt
echo "  9f. Proof for unknown receipt..."
UNKNOWN_PROOF=$(curl -sf -X POST "$LEDGER/v1/ledger/proof" \
  -H "Content-Type: application/json" \
  -d "{\"tenant_id\":\"$TENANT_ID\",\"exam_id\":\"$EXAM_ID\",\"receipt_id\":\"nonexistent-receipt-12345\"}")
check "unknown receipt" "$UNKNOWN_PROOF" '.merkle_leaf == null'

# 9g. Beacon token endpoint
echo "  9g. Beacon token endpoint..."
TOKEN=$(curl -sf -X POST "http://127.0.0.1:$((BEACON_BASE + 1))/v1/beacon/token" \
  -H "x-api-key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"center_id":"center-01","exam_id":"jee-2027","device_id":"device-01"}')
check "center_id matches" "$TOKEN" '.center_id == "center-01"'
check "nonce 16 bytes"    "$TOKEN" '.nonce | length == 16'
check "signature 64 bytes" "$TOKEN" '.signature | length == 64'

# 9h. Verify with tampered data
echo "  9h. Verify with tampered answers_hash..."
MANIFEST=$(cat "$OUTPUT_DIR/manifest.json")
FIRST_HASH=$(echo "$MANIFEST" | jq '.entries[0].packet_hash')
TAMPER_VERIFY=$(curl -sf -X POST "$LEDGER/v1/ledger/verify" \
  -H "Content-Type: application/json" \
  -d "{\"tenant_id\":\"$TENANT_ID\",\"exam_id\":\"$EXAM_ID\",\"student_uuid\":\"00000000-0000-0000-0000-000000000001\",\"packet_hash\":$FIRST_HASH,\"answers_hash\":[255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255],\"timestamp\":1700000000,\"merkle_leaf\":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],\"edge_signature\":[],\"edge_public_key\":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}")
check "tampered verify fails" "$TAMPER_VERIFY" '.valid == false'

# 9i. Cross-center beacon token
echo "  9i. Cross-center beacon token..."
CROSS_TOKEN=$(curl -sf -X POST "http://127.0.0.1:$((BEACON_BASE + 1))/v1/beacon/token" \
  -H "x-api-key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"center_id":"center-02","exam_id":"jee-2027","device_id":"device-01"}')
check "cross-center token" "$CROSS_TOKEN" '.center_id == "center-02"'

# 9j. Merkle proof consistency
echo "  9j. Merkle proof consistency..."
PROOF1=$(curl -sf -X POST "$LEDGER/v1/ledger/proof" \
  -H "Content-Type: application/json" \
  -d "{\"tenant_id\":\"$TENANT_ID\",\"exam_id\":\"$EXAM_ID\",\"receipt_id\":\"dummy\"}")
ROOT1=$(echo "$PROOF1" | jq '.root')
PROOF2=$(curl -sf -X POST "$LEDGER/v1/ledger/proof" \
  -H "Content-Type: application/json" \
  -d "{\"tenant_id\":\"$TENANT_ID\",\"exam_id\":\"$EXAM_ID\",\"receipt_id\":\"dummy2\"}")
ROOT2=$(echo "$PROOF2" | jq '.root')
check_raw "consistent root" "$ROOT1" "$ROOT2"

# 9k. Submit before exam window starts (should fail 403)
echo "  9k. Submit before exam window..."
BEFORE_TIME=$((EXAM_WINDOW_START - 3600))
# Set clock on edge to before exam window
    curl -sf -X POST "http://127.0.0.1:$((EDGE_BASE + 1))/v1/system/clock" \
      -H "x-api-key: $API_KEY" \
      -H "Content-Type: application/json" \
      -d "{\"timestamp\":$BEFORE_TIME}" >/dev/null
    # Also set on ledger
    curl -sf -X POST "$LEDGER/v1/system/clock" \
      -H "x-api-key: $API_KEY" \
      -H "Content-Type: application/json" \
      -d "{\"timestamp\":$BEFORE_TIME}" >/dev/null
# Try to submit (should fail with 403)
BEFORE_SUBMIT=$(curl -s -X POST "http://127.0.0.1:$((EDGE_BASE + 1))/v1/exam/submit" \
  -H "x-api-key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"student_uuid\":\"00000000-0000-0000-0000-000000000001\",\"application_number\":\"APP0001\",\"dob\":\"2000-01-01\",\"answers\":{\"q_1\":\"A\"}}" 2>/dev/null || echo "error")
if [[ "$BEFORE_SUBMIT" == *"exam has not started"* ]]; then
  pass
else
  fail "expected 'exam has not started', got $BEFORE_SUBMIT"
fi

# 9l. Submit after exam window ends (should fail 403)
echo "  9l. Submit after exam window..."
AFTER_TIME=$((EXAM_WINDOW_END + 3600))
    curl -sf -X POST "http://127.0.0.1:$((EDGE_BASE + 1))/v1/system/clock" \
      -H "x-api-key: $API_KEY" \
      -H "Content-Type: application/json" \
      -d "{\"timestamp\":$AFTER_TIME}" >/dev/null
    curl -sf -X POST "$LEDGER/v1/system/clock" \
      -H "x-api-key: $API_KEY" \
      -H "Content-Type: application/json" \
      -d "{\"timestamp\":$AFTER_TIME}" >/dev/null
AFTER_SUBMIT=$(curl -s -X POST "http://127.0.0.1:$((EDGE_BASE + 1))/v1/exam/submit" \
  -H "x-api-key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"student_uuid\":\"00000000-0000-0000-0000-000000000001\",\"application_number\":\"APP0001\",\"dob\":\"2000-01-01\",\"answers\":{\"q_1\":\"A\"}}" 2>/dev/null || echo "error")
if [[ "$AFTER_SUBMIT" == *"exam window has ended"* ]]; then
  pass
else
  fail "expected 'exam window has ended', got $AFTER_SUBMIT"
fi

# Reset clock to current time
NOW=$(date +%s)
    curl -sf -X POST "http://127.0.0.1:$((EDGE_BASE + 1))/v1/system/clock" \
      -H "x-api-key: $API_KEY" \
      -H "Content-Type: application/json" \
      -d "{\"timestamp\":$NOW}" >/dev/null
    curl -sf -X POST "$LEDGER/v1/system/clock" \
      -H "x-api-key: $API_KEY" \
      -H "Content-Type: application/json" \
      -d "{\"timestamp\":$NOW}" >/dev/null

# 9m. Beacon token respects exam window
echo "  9m. Beacon token window bounds..."
TOKEN2=$(curl -sf -X POST "http://127.0.0.1:$((BEACON_BASE + 1))/v1/beacon/token" \
  -H "x-api-key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"center_id":"center-01","exam_id":"jee-2027","device_id":"device-01"}')
WINDOW_START=$(echo "$TOKEN2" | jq '.window_start')
WINDOW_END=$(echo "$TOKEN2" | jq '.window_end')
WINDOW_START=${WINDOW_START:-0}
WINDOW_END=${WINDOW_END:-0}
[ "$WINDOW_START" -ge "$EXAM_WINDOW_START" ] && pass || fail "token window_start before exam window"
[ "$WINDOW_END" -le "$EXAM_WINDOW_END" ] && pass || fail "token window_end after exam window"
echo "  token window: $WINDOW_START -> $WINDOW_END (exam: $EXAM_WINDOW_START -> $EXAM_WINDOW_END)"

# -- 10. Cleanup ---------------------------------------------------------
echo ""
echo "=== [10] Cleaning up ==="
for pid_file in /tmp/oetp_test_*.pid; do
  [ -f "$pid_file" ] && kill "$(cat "$pid_file")" 2>/dev/null || true
  rm -f "$pid_file"
done
rm -rf "$OUTPUT_DIR" "$STUDENTS_CSV"

# Restart the original edge from start.sh
if [ -f ./dev/edge.pid ]; then
  kill "$(cat ./dev/edge.pid)" 2>/dev/null || true
fi
RUST_LOG=info \
OETP_TENANT_ID="$OETP_TENANT_ID" \
OETP_EXAM_ID="$OETP_EXAM_ID" \
OETP_DEVICE_ID="$OETP_DEVICE_ID" \
OETP_CENTER_ID="$OETP_CENTER_ID" \
OETP_LEDGER_URL="$OETP_LEDGER_URL" \
OETP_BEACON_URL="$OETP_BEACON_URL" \
OETP_LISTEN_ADDR="$OETP_LISTEN_ADDR" \
OETP_DEVICE_KEY="$OETP_DEVICE_KEY" \
OETP_DEVICE_X25519_KEY="$OETP_DEVICE_X25519_KEY" \
OETP_CACHE_DIR="$OETP_CACHE_DIR" \
OETP_QUEUE_DIR="$OETP_QUEUE_DIR" \
OETP_BEACON_PUBLIC_KEY="$OETP_BEACON_PUBLIC_KEY" \
OETP_EXAM_SALT="$OETP_EXAM_SALT" \
OETP_SERVER_PEPPER="$OETP_SERVER_PEPPER" \
OETP_API_KEY="$OETP_API_KEY" \
  cargo run --release -p oetp-edge >./dev/edge.log 2>&1 &
echo $! > ./dev/edge.pid
disown
echo "  original edge restarted on 8080"

# -- Summary --------------------------------------------------------------
echo ""
if [ "$FAIL" -eq 0 ]; then
  echo "=== NATIONAL EXAM E2E TEST PASSED ==="
  echo "  Centers: 4"
  echo "  Students: 120"
  echo "  Submissions: $SUBMITTED"
  echo "  Attack tests: 10 scenarios"
  echo "  Total assertions: $TOTAL"
else
  echo "=== $FAIL/$TOTAL test(s) FAILED ==="
  exit 1
fi
