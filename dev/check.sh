#!/usr/bin/env bash
# OETP quick health check for the dev environment started by start.sh
set -euo pipefail

cd "$(dirname "$0")/.."

ENV_FILE="./dev/.env"
if [ ! -f "$ENV_FILE" ]; then
  echo "ERROR: $ENV_FILE not found. Run ./dev/setup.sh first."
  exit 1
fi

# shellcheck disable=SC1090
source "$ENV_FILE"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

fail=0

check_http() {
  local name="$1" url="$2"
  if curl -sf "$url/health" >/dev/null 2>&1; then
    echo -e "${GREEN}OK${NC} $name ($url)"
  else
    echo -e "${RED}FAIL${NC} $name ($url/health)"
    fail=$((fail + 1))
  fi
}

check_http "ledger" "http://localhost:8081"
check_http "beacon" "http://localhost:9090"
check_http "edge" "http://localhost:8080"

echo ""
if [ "$fail" -eq 0 ]; then
  echo "All services healthy."
else
  echo "$fail service(s) unreachable."
  exit 1
fi
