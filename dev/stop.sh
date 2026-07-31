#!/usr/bin/env bash
# OETP dev environment stop script
# Stops services and optionally cleans up generated artifacts.
set -euo pipefail

cd "$(dirname "$0")/.."

CLEAN="${1:-}"

for pid_file in ./dev/ledger.pid ./dev/beacon.pid ./dev/edge.pid; do
  if [ -f "$pid_file" ]; then
    pid=$(cat "$pid_file")
    if kill -0 "$pid" 2>/dev/null; then
      echo "stopping $pid_file (pid $pid)..."
      kill "$pid" 2>/dev/null || true
    else
      echo "$pid_file process not running"
    fi
    rm -f "$pid_file"
  fi
done

for port in 8081 9090 8080; do
  pid=$(lsof -ti tcp:"$port" 2>/dev/null || true)
  if [ -n "$pid" ]; then
    echo "killing leftover process on port $port (pid $pid)..."
    kill "$pid" 2>/dev/null || true
  fi
done

# Clean up runtime artifacts
rm -f ./dev/ledger.db ./dev/ledger.log ./dev/beacon.log ./dev/edge.log
rm -rf ./dev/output ./dev/cache ./dev/queue

if [ "$CLEAN" = "--clean" ]; then
  echo "removing generated keys, .env, and sample data..."
  rm -f ./dev/device.key ./dev/device_x25519.key ./dev/ledger.key ./dev/beacon.key
  rm -f ./dev/.env ./dev/question_bank.json ./dev/students.csv
fi

echo "=== OETP services stopped ==="
