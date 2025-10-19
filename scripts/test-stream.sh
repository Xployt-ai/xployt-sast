#!/usr/bin/env bash
set -euo pipefail

PORT=${PORT:-8001}
DIR=${1:-$(pwd)}

echo "Starting server..." >&2
node -e "require('./dist/server.js')" &
PID=$!
trap 'kill $PID 2>/dev/null || true' EXIT

sleep 0.5

echo "Requesting streaming scan (NDJSON)..." >&2
curl -N -s -X POST "http://localhost:${PORT}/scan?mode=stream" \
  -H 'accept: application/x-ndjson' \
  -H 'content-type: application/json' \
  -d "{\"path\": \"${DIR}\"}"


