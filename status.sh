#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
docker compose ps

VULHUB_STATE_FILE=.vulhub-active
if [[ -f "$VULHUB_STATE_FILE" ]]; then
  recipe=$(cat "$VULHUB_STATE_FILE")
  echo
  echo "Active Vulhub recipe: $recipe"
  ( cd "vulhub/$recipe" && docker compose -f docker-compose.yml -f docker-compose.vulnbench-override.yml ps )
fi

if [[ -f .vulhub-all-active ]]; then
  echo
  ./vulhub.sh status-all
fi

echo
echo "Public listeners on this host (should be only 22 and 6901):"
ss -tlnp 2>/dev/null | grep -E ':(22|6901)\b' || sudo ss -tlnp | grep -E ':(22|6901)\b'
