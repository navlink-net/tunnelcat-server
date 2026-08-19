#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$REPO_ROOT"

GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
    go build -o snc-exit/snc-exit ./snc-exit/

echo "built: snc-exit/snc-exit"
