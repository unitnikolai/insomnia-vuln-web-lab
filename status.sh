#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
docker compose ps
echo
echo "Public listeners on this host (should be only 22 and 6901):"
ss -tlnp 2>/dev/null | grep -E ':(22|6901)\b' || sudo ss -tlnp | grep -E ':(22|6901)\b'
