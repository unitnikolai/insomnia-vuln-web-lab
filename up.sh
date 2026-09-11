#!/usr/bin/env bash
# Bring the vuln-lab fleet up: vulnerable targets (internal-network only) +
# one public attack-box (browser-based Kali desktop on :6901).
#
# Usage:
#   ./up.sh                                        start and stay up
#   ./up.sh --hours 3                               start, and auto tear down after 3 hours
#   ./up.sh --vulhub log4j/CVE-2021-44228           also bring up one Vulhub CVE recipe
#   ./up.sh --vulhub-category struts2               bring up every recipe in one Vulhub category (sized batch)
#   ./up.sh --vulhub-all                            bring up EVERY Vulhub recipe at once (heaviest — see vulhub.sh)
#   ./up.sh --vulhub log4j/CVE-2021-44228 --hours 3   any of the above, combined with --hours
#
# --vulhub / --vulhub-category / --vulhub-all delegate to ./vulhub.sh — see
# there for what each does and how they differ (one recipe joined to
# vulnbench, vs. a whole category or the whole collection each on its own
# isolated network). down.sh tears whichever was brought up back down
# automatically. `./vulhub.sh categories` lists categories with recipe
# counts if you're picking one for --vulhub-category.
set -euo pipefail
cd "$(dirname "$0")"

ENV_FILE=.env
HOURS=""
VULHUB_RECIPE=""
VULHUB_CATEGORY=""
VULHUB_ALL=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --hours)
      [[ -n "${2:-}" ]] || { echo "--hours needs a value" >&2; exit 1; }
      HOURS="$2"
      shift 2
      ;;
    --vulhub)
      [[ -n "${2:-}" ]] || { echo "--vulhub needs a recipe, e.g. log4j/CVE-2021-44228" >&2; exit 1; }
      VULHUB_RECIPE="$2"
      shift 2
      ;;
    --vulhub-category)
      [[ -n "${2:-}" ]] || { echo "--vulhub-category needs a category, e.g. struts2" >&2; exit 1; }
      VULHUB_CATEGORY="$2"
      shift 2
      ;;
    --vulhub-all)
      VULHUB_ALL=1
      shift
      ;;
    *)
      echo "Unknown argument: $1" >&2
      echo "Usage: $0 [--vulhub <category/CVE-xxxx-xxxxx> | --vulhub-category <category> | --vulhub-all] [--hours N]" >&2
      exit 1
      ;;
  esac
done

chosen=0
for v in "$VULHUB_RECIPE" "$VULHUB_CATEGORY"; do [[ -n "$v" ]] && chosen=$((chosen + 1)); done
[[ "$VULHUB_ALL" -eq 1 ]] && chosen=$((chosen + 1))
if [[ "$chosen" -gt 1 ]]; then
  echo "--vulhub, --vulhub-category, and --vulhub-all are mutually exclusive." >&2
  exit 1
fi

if [[ ! -f "$ENV_FILE" ]]; then
  echo "No .env found — generating a fresh attack-box password."
  echo "ATTACK_BOX_PASSWORD=$(openssl rand -base64 18 | tr -d '=+/')" > "$ENV_FILE"
  chmod 600 "$ENV_FILE"
fi

# --build: without it, compose reuses whatever image is already cached for
# attack-box and silently ignores any Dockerfile changes since that image
# was last built.
docker compose up -d --build

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
docker compose config --services | grep -vE '^(attack-box|gate)$' | sed 's/^/   http:\/\//'
echo "======================================================================"
echo

if [[ -n "$VULHUB_RECIPE" ]]; then
  # The vulnbench network above already exists by now (docker compose up
  # just created it) — vulhub.sh joins it as external, so this must run
  # after the base fleet is up, not before.
  ./vulhub.sh up "$VULHUB_RECIPE"
elif [[ -n "$VULHUB_CATEGORY" ]]; then
  # Needs vb-attack-box running (checked inside vulhub.sh) to connect each
  # recipe's isolated network to — same ordering requirement as above.
  ./vulhub.sh up-category "$VULHUB_CATEGORY" --yes
elif [[ "$VULHUB_ALL" -eq 1 ]]; then
  ./vulhub.sh up-all --yes
fi

if [[ -n "$HOURS" ]]; then
  if ! command -v at >/dev/null 2>&1; then
    echo "WARNING: 'at' is not installed (sudo apt install at) — auto-teardown not scheduled." >&2
  else
    echo "$(cd "$(pwd)" && pwd)/down.sh" | at now + "$HOURS" hours
    echo "Auto-teardown scheduled in $HOURS hour(s)."
  fi
fi
