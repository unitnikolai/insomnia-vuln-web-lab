#!/usr/bin/env bash
# Tear the whole fleet down. Pass --wipe to also drop volumes (DVWA/Mutillidae
# DB state) for a clean slate on the next ./up.sh.
set -euo pipefail
cd "$(dirname "$0")"

if [[ "${1:-}" == "--wipe" ]]; then
  docker compose down -v
else
  docker compose down
fi

echo "Fleet is down. Public port 6901 is no longer listening."
