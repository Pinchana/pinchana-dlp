#!/bin/sh
set -eu

test -f .env || { echo "Copy example.env to .env and set every secret/path first." >&2; exit 1; }
docker compose --profile build build worker-image
docker compose up --build -d redis dlp-api vpn orchestrator
