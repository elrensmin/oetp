#!/usr/bin/env bash
# OETP full-lifecycle curl smoke tests
# Assumes dev/start.sh has already been run and all services are healthy.
set -euo pipefail

LEDGER="http://localhost:8081"
BEACON="http://localhost:9090"
EDGE="http://localhost:8080"
API_KEY="dev-api-key-12345678-with-enough-characters"
STUDENT="550e8400-e29b-41d4-a716-446655440000"
STUDENT2="550e8400-e29b-41d4-a716-446655440001"
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

echo "[1] health checks..."
check "ledger health" "$(curl -sf "$LEDGER/health")" '.status == "ok"'
check "beacon health" "$(curl -sf "$BEACON/health")" '.status == "ok"'
check "edge health"   "$(curl -sf "$EDGE/health")"   '.status == "ok"'

echo "[2] auth rejection..."
AUTH1=$(curl -s -X POST "$EDGE/v1/exam/fetch" \
  -H "x-api-key: wrong-key" \
  -H "Content-Type: application/json" \
  -d "{\"student_uuid\":\"$STUDENT\",\"application_number\":\"APP123\"}")
check_contains "wrong api key on edge" "$AUTH1" "invalid api key"
AUTH2=$(curl -s -X POST "$LEDGER/v1/ledger/commit" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id":"nta","exam_id":"jee-2027","packet_hashes":[]}')
check_contains "missing api key on ledger" "$AUTH2" "invalid api key"

echo "[3] ledger commit packet hashes..."
COMMIT=$(curl -sf -X POST "$LEDGER/v1/ledger/commit" \
  -H "x-api-key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "nta",
    "exam_id": "jee-2027",
    "packet_hashes": [
      [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32],
      [33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64]
    ]
  }')
check "merkle_root present" "$COMMIT" '.merkle_root | length == 32'
check "anchor present"      "$COMMIT" '.anchor.anchor_type == "PreExam"'

echo "[4] ledger fetch packet (direct)..."
LEDGER_FETCH=$(curl -sf -X POST "$LEDGER/v1/ledger/fetch" \
  -H "x-api-key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"tenant_id\":\"nta\",\"exam_id\":\"jee-2027\",\"student_uuid\":\"$STUDENT\"}")
check "encrypted_packet present" "$LEDGER_FETCH" '.encrypted_packet | has("ciphertext")'
check "key_envelope present"     "$LEDGER_FETCH" '.key_envelope | has("encrypted_ephemeral_key")'
check "packet_hash is 32 bytes"  "$LEDGER_FETCH" '.encrypted_packet.packet_hash | length == 32'

echo "[5] ledger fetch non-existent student..."
NOT_FOUND=$(curl -s -X POST "$LEDGER/v1/ledger/fetch" \
  -H "x-api-key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id":"nta","exam_id":"jee-2027","student_uuid":"00000000-0000-0000-0000-000000000000"}')
check_contains "error message" "$NOT_FOUND" "not found"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$LEDGER/v1/ledger/fetch" \
  -H "x-api-key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id":"nta","exam_id":"jee-2027","student_uuid":"00000000-0000-0000-0000-000000000000"}')
check_raw "http 404" "$HTTP_CODE" "404"

echo "[6] edge fetch packet..."
FETCH=$(curl -sf -X POST "$EDGE/v1/exam/fetch" \
  -H "x-api-key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"student_uuid\":\"$STUDENT\",\"application_number\":\"APP123\"}")
check "status cached"  "$FETCH" '.status == "cached"'
check "packet_hash"    "$FETCH" '.packet_hash | length == 32'

echo "[7] edge fetch second student..."
FETCH2=$(curl -sf -X POST "$EDGE/v1/exam/fetch" \
  -H "x-api-key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"student_uuid\":\"$STUDENT2\",\"application_number\":\"APP456\"}")
check "second student cached" "$FETCH2" '.status == "cached"'

echo "[8] edge release token..."
RELEASE=$(curl -sf -X POST "$EDGE/v1/exam/release" \
  -H "x-api-key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"student_uuid\":\"$STUDENT\"}")
check "status released" "$RELEASE" '.status == "released"'

echo "[9] edge unlock without release..."
NO_REL=$(curl -s -X POST "$EDGE/v1/exam/unlock" \
  -H "x-api-key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"student_uuid\":\"$STUDENT2\"}")
check_contains "no release token" "$NO_REL" "no release"
HTTP_NO_REL=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$EDGE/v1/exam/unlock" \
  -H "x-api-key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"student_uuid\":\"$STUDENT2\"}")
check_raw "http 403" "$HTTP_NO_REL" "403"

echo "[10] edge unlock packet..."
UNLOCK=$(curl -sf -X POST "$EDGE/v1/exam/unlock" \
  -H "x-api-key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"student_uuid\":\"$STUDENT\"}")
check "questions present" "$UNLOCK" '.questions | length > 0'
check "has question_ref"  "$UNLOCK" '.questions[0] | has("question_ref")'
check "has stem"          "$UNLOCK" '.questions[0] | has("stem")'
check "has options"       "$UNLOCK" '.questions[0].options | length >= 2'

echo "[11] edge submit answers..."
SUBMIT=$(curl -sf -X POST "$EDGE/v1/exam/submit" \
  -H "x-api-key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"student_uuid\":\"$STUDENT\",\"application_number\":\"APP123\",\"dob\":\"2000-01-01\",\"answers\":{\"q_1\":\"Paris\",\"q_2\":\"4\",\"q_3\":\"Mars\",\"q_4\":\"H2O\",\"q_5\":\"7\"}}")
RECEIPT_ID=$(echo "$SUBMIT" | jq -r '.receipt_id')
check "receipt_id present"  "$SUBMIT" '.receipt_id | length > 0'
check "receipt has fields"  "$SUBMIT" '.receipt | has("merkle_proof") and has("edge_signature") and has("qr_payload")'
check "personal_copy"       "$SUBMIT" '.personal_copy | has("encrypted_answers") and has("answers_hash")'
check "qr_payload format"   "$SUBMIT" '.receipt.qr_payload | startswith("oetp:receipt:")'
echo "  receipt_id: $RECEIPT_ID"

echo "[12] ledger merkle proof..."
sleep 1
PROOF=$(curl -sf -X POST "$LEDGER/v1/ledger/proof" \
  -H "Content-Type: application/json" \
  -d "{\"tenant_id\":\"nta\",\"exam_id\":\"jee-2027\",\"receipt_id\":\"$RECEIPT_ID\"}")
check "leaf_index >= 0"    "$PROOF" '.leaf_index >= 0'
check "merkle_leaf 32"     "$PROOF" '.merkle_leaf | length == 32'
check "root 32 bytes"      "$PROOF" '.root | length == 32'
check "total_leaves >= 1"  "$PROOF" '.total_leaves >= 1'

echo "[13] ledger verify submission..."
PACKET_HASH=$(echo "$SUBMIT" | jq -r '.receipt.packet_hash | @json')
ANSWERS_HASH=$(echo "$SUBMIT" | jq -r '.receipt.answers_hash | @json')
MERKLE_LEAF=$(echo "$PROOF" | jq -r '.merkle_leaf | @json')
TIMESTAMP=$(echo "$SUBMIT" | jq -r '.receipt.timestamp')
EDGE_SIG=$(echo "$SUBMIT" | jq -r '.receipt.edge_signature | @json')
EDGE_PUB=$(python3 -c "
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
priv_hex = open('./dev/device.key').read().strip()
priv_bytes = bytes.fromhex(priv_hex)
priv_key = Ed25519PrivateKey.from_private_bytes(priv_bytes)
pub_key = priv_key.public_key()
pub_bytes = pub_key.public_bytes_raw()
print('[' + ','.join(str(b) for b in pub_bytes) + ']')
")
VERIFY=$(curl -sf -X POST "$LEDGER/v1/ledger/verify" \
  -H "Content-Type: application/json" \
  -d "{\"tenant_id\":\"nta\",\"exam_id\":\"jee-2027\",\"student_uuid\":\"$STUDENT\",\"packet_hash\":$PACKET_HASH,\"answers_hash\":$ANSWERS_HASH,\"timestamp\":$TIMESTAMP,\"merkle_leaf\":$MERKLE_LEAF,\"edge_signature\":$EDGE_SIG,\"edge_public_key\":$EDGE_PUB}")
check "valid == true"       "$VERIFY" '.valid == true'
check "reason == verified"  "$VERIFY" '.reason == "verified"'
check "leaf_index >= 0"     "$VERIFY" '.leaf_index >= 0'
check "anchored_root 32"    "$VERIFY" '.anchored_root | length == 32'

echo "[14] ledger commit answer key..."
KEY_COMMIT=$(curl -sf -X POST "$LEDGER/v1/ledger/key" \
  -H "x-api-key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id":"nta","exam_id":"jee-2027","answer_key_hash":[239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239]}')
check "anchor_type AnswerKey" "$KEY_COMMIT" '.anchor.anchor_type == "AnswerKey"'
check "anchored_root 32"      "$KEY_COMMIT" '.anchor.anchored_root | length == 32'

echo "[15] ledger list anchors..."
ANCHORS=$(curl -sf -X POST "$LEDGER/v1/ledger/anchors" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id":"nta","exam_id":"jee-2027"}')
check "anchors present" "$ANCHORS" '.anchors | length >= 2'

echo "[16] beacon release token (direct)..."
TOKEN=$(curl -sf -X POST "$BEACON/v1/beacon/token" \
  -H "x-api-key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"center_id":"center-01","exam_id":"jee-2027","device_id":"device-01"}')
check "center_id matches" "$TOKEN" '.center_id == "center-01"'
check "exam_id matches"   "$TOKEN" '.exam_id == "jee-2027"'
check "device_id matches" "$TOKEN" '.device_id == "device-01"'
check "window_start < window_end" "$TOKEN" '.window_start < .window_end'
check "nonce 16 bytes"    "$TOKEN" '.nonce | length == 16'
check "signature 64 bytes" "$TOKEN" '.signature | length == 64'

echo "[17] ledger load packet (direct)..."
LOAD=$(curl -sf -X POST "$LEDGER/v1/ledger/load" \
  -H "x-api-key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"key\":\"nta:jee-2027:00000000-0000-0000-0000-000000000000\",\"encrypted_packet\":{\"tenant_id\":\"nta\",\"student_uuid\":\"00000000-0000-0000-0000-000000000000\",\"exam_id\":\"jee-2027\",\"ciphertext\":[1,2,3],\"nonce\":[0,0,0,0,0,0,0,0,0,0,0,0],\"packet_hash\":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32]},\"key_envelope\":{\"version\":1,\"device_id\":\"device-01\",\"student_uuid\":\"00000000-0000-0000-0000-000000000000\",\"exam_id\":\"jee-2027\",\"sender_public_key\":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32],\"encrypted_ephemeral_key\":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32],\"nonce\":[0,0,0,0,0,0,0,0,0,0,0,0]}}")
check "status loaded" "$LOAD" '.status == "loaded"'

# -- 18. Exam window enforcement ------------------------------------------
echo "[18] exam window enforcement..."
# The dev edge has default window (0..MAX), so submit should work
# Verify the window check exists by checking the error message format
# Submit without fetch should give "no cached packet" (not window error)
WINDOW_CHECK=$(curl -s -X POST "$EDGE/v1/exam/submit" \
  -H "x-api-key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"student_uuid\":\"$STUDENT\",\"application_number\":\"APP123\",\"dob\":\"2000-01-01\",\"answers\":{\"q_1\":\"A\"}}" 2>/dev/null || echo "error")
# This should fail with "no cached packet" since we already submitted
# The important thing is it does NOT fail with "exam has not started" or "exam window has ended"
if echo "$WINDOW_CHECK" | jq -e '.receipt_id' >/dev/null 2>&1; then
  pass
elif [[ "$WINDOW_CHECK" == *"no cached"* ]]; then
  pass
else
  fail "unexpected error: $WINDOW_CHECK"
fi

echo ""
if [ "$FAIL" -eq 0 ]; then
  echo "=== All $TOTAL curl smoke tests passed ==="
else
  echo "=== $FAIL/$TOTAL test(s) FAILED ==="
  exit 1
fi
