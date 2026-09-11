#!/usr/bin/env bash
# Tear the whole fleet down. Pass --wipe to also drop volumes (DVWA/Mutillidae
# DB state) for a clean slate on the next ./up.sh.
set -euo pipefail
cd "$(dirname "$0")"

VULHUB_STATE_FILE=.vulhub-active
VULHUB_ALL_STATE_FILE=.vulhub-all-active

# Both run (if present) before `docker compose down` below, while
# vb-attack-box still exists — tearing down a recipe disconnects it from
# vb-attack-box's networks first, which needs the container to still be there.
if [[ -f "$VULHUB_STATE_FILE" ]]; then
  recipe=$(cat "$VULHUB_STATE_FILE")
  echo "Tearing down active Vulhub recipe: $recipe"
  ./vulhub.sh down "$recipe" || echo "WARNING: failed to tear down $recipe cleanly — check it by hand." >&2
  rm -f "$VULHUB_STATE_FILE"
fi

if [[ -f "$VULHUB_ALL_STATE_FILE" ]]; then
  echo "Tearing down all active batch-mode Vulhub recipes (up-all/up-category)..."
  ./vulhub.sh down-all || echo "WARNING: some Vulhub recipes may not have torn down cleanly — check ./vulhub.sh status-all." >&2
fi

if [[ "${1:-}" == "--wipe" ]]; then
  docker compose down -v
else
  docker compose down
fi

echo "Fleet is down. Public port 6901 is no longer listening."
