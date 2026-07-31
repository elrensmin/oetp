#!/usr/bin/env bash
# OETP dev environment start script
# Sources dev/.env, builds binaries, starts ledger + beacon + edge,
# generates sample packets, loads them into the ledger, then waits for services.
set -euo pipefail

cd "$(dirname "$0")/.."

ENV_FILE="./dev/.env"
if [ ! -f "$ENV_FILE" ]; then
  echo "ERROR: $ENV_FILE not found. Run ./dev/setup.sh first."
  exit 1
fi

# shellcheck disable=SC1090
source "$ENV_FILE"

# Dev/stress tests run from localhost and may burst many requests; keep a high ceiling.
export OETP_RATE_LIMIT_PER_SECOND="${OETP_RATE_LIMIT_PER_SECOND:-1000}"
export OETP_RATE_LIMIT_BURST="${OETP_RATE_LIMIT_BURST:-100000}"

echo "building all crates..."
cargo build --release -p oetp-ledger -p oetp-beacon -p oetp-edge 2>&1

# Kill any leftover processes on our ports
for port in 8081 9090 8080; do
  pid=$(lsof -ti tcp:"$port" 2>/dev/null || true)
  if [ -n "$pid" ]; then
    echo "killing process on port $port (pid $pid)..."
    kill "$pid" 2>/dev/null || true
    sleep 1
  fi
done

echo "starting ledger on $OETP_LEDGER_LISTEN_ADDR..."
RUST_LOG=info \
OETP_TENANT_ID="$OETP_TENANT_ID" \
OETP_EXAM_ID="$OETP_EXAM_ID" \
OETP_SIGNING_KEY="$OETP_SIGNING_KEY" \
OETP_API_KEY="$OETP_API_KEY" \
OETP_LEDGER_LISTEN_ADDR="$OETP_LEDGER_LISTEN_ADDR" \
OETP_LEDGER_DB_PATH="$OETP_LEDGER_DB_PATH" \
  cargo run --release -p oetp-ledger -- serve >./dev/ledger.log 2>&1 &
echo $! > ./dev/ledger.pid
disown

echo "starting beacon on $OETP_BEACON_LISTEN_ADDR..."
RUST_LOG=info \
OETP_BEACON_LISTEN_ADDR="$OETP_BEACON_LISTEN_ADDR" \
OETP_BEACON_SIGNING_KEY="$OETP_BEACON_SIGNING_KEY" \
OETP_API_KEY="$OETP_API_KEY" \
  cargo run --release -p oetp-beacon >./dev/beacon.log 2>&1 &
echo $! > ./dev/beacon.pid
disown

echo "waiting for ledger and beacon..."
for i in $(seq 1 30); do
  if curl -sf http://localhost:8081/health >/dev/null 2>&1 && \
     curl -sf http://localhost:9090/health >/dev/null 2>&1; then
    echo "ledger and beacon are up"
    break
  fi
  sleep 1
done

echo "generating sample exam packets..."
# Derive X25519 public key from the device's X25519 private key
DEVICE_X25519_PUB=$(python3 -c "
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
priv_hex = open('./dev/device_x25519.key').read().strip()
priv_bytes = bytes.fromhex(priv_hex)
priv_key = X25519PrivateKey.from_private_bytes(priv_bytes)
pub_key = priv_key.public_key()
print(pub_key.public_bytes_raw().hex())
")
echo "device X25519 public key: $DEVICE_X25519_PUB"
cargo run --release -p oetp-ledger -- generate \
  --bank ./dev/question_bank.json \
  --students ./dev/students.csv \
  --num-questions 5 \
  --output ./dev/output \
  --tenant-master-key "$OETP_TENANT_MASTER_KEY" \
  --exam-id "$OETP_EXAM_ID" \
  --tenant-id "$OETP_TENANT_ID" \
  --device-x25519-pub "$DEVICE_X25519_PUB" 2>&1

echo "loading packets into ledger..."
OETP_TENANT_ID="$OETP_TENANT_ID" \
OETP_EXAM_ID="$OETP_EXAM_ID" \
OETP_SIGNING_KEY="$OETP_SIGNING_KEY" \
OETP_API_KEY="$OETP_API_KEY" \
OETP_LEDGER_LISTEN_ADDR="$OETP_LEDGER_LISTEN_ADDR" \
  cargo run --release -p oetp-ledger -- load \
  --input ./dev/output 2>&1

echo "starting edge on $OETP_LISTEN_ADDR..."
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

echo "waiting for edge..."
for i in $(seq 1 30); do
  if curl -sf http://localhost:8080/health >/dev/null 2>&1; then
    echo "edge is up"
    break
  fi
  sleep 1
done

echo ""
echo "=== All services running ==="
echo "  Ledger:  http://localhost:8081"
echo "  Beacon:  http://localhost:9090"
echo "  Edge:    http://localhost:8080"
echo "  API key: $OETP_API_KEY"
echo "  PIDs:    ./dev/ledger.pid, ./dev/beacon.pid, ./dev/edge.pid"
echo ""
echo "To stop all services:"
echo "  ./dev/stop.sh"
echo ""
echo "To run the full lifecycle curl tests:"
echo "  ./dev/curl-tests.sh"
echo ""
echo "Health checks:"
echo "  curl -s http://localhost:8081/health"
echo "  curl -s http://localhost:9090/health"
echo "  curl -s http://localhost:8080/health"
