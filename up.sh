#!/usr/bin/env bash
# Bring the vuln-lab fleet up: vulnerable targets (internal-network only) +
# one public attack-box (browser-based Kali desktop on :6901).
#
# Usage:
#   ./up.sh                 start and stay up
#   ./up.sh --hours 3       start, and auto tear down after 3 hours
set -euo pipefail
cd "$(dirname "$0")"

ENV_FILE=.env

if [[ ! -f "$ENV_FILE" ]]; then
  echo "No .env found — generating a fresh attack-box password."
  echo "ATTACK_BOX_PASSWORD=$(openssl rand -base64 18 | tr -d '=+/')" > "$ENV_FILE"
  chmod 600 "$ENV_FILE"
fi

docker compose up -d

PASS=$(grep ATTACK_BOX_PASSWORD "$ENV_FILE" | cut -d= -f2)
IP=$(curl -s -4 ifconfig.me || echo "<vps-ip>")

echo
echo "======================================================================"
echo " Fleet is up."
echo
echo " Attack box (public):  https://${IP}:6901"
echo "   password:           ${PASS}"
echo "   (browser will warn about the self-signed cert — that's expected)"
echo
echo " Targets are reachable only from INSIDE the attack box, by name:"
docker compose config --services | grep -v attack-box | sed 's/^/   http:\/\//'
echo "======================================================================"
echo

if [[ "${1:-}" == "--hours" && -n "${2:-}" ]]; then
  if ! command -v at >/dev/null 2>&1; then
    echo "WARNING: 'at' is not installed (sudo apt install at) — auto-teardown not scheduled." >&2
  else
    echo "$(cd "$(pwd)" && pwd)/down.sh" | at now + "$2" hours
    echo "Auto-teardown scheduled in $2 hour(s)."
  fi
fi
