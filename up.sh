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

gen_secret() { openssl rand -base64 18 | tr -d '=+/'; }

# Actual (project-prefixed) name of the dashboard-db volume, empty if it
# doesn't exist yet. Matched by suffix so it's robust to the compose project
# name (COMPOSE_PROJECT_NAME / -p / a renamed checkout dir).
db_volume_name() {
  # The trailing `|| true` matters: with `set -o pipefail`, a no-match grep
  # makes this whole pipeline exit non-zero, and under `set -e` that would
  # kill up.sh at the `existing_vol=$(db_volume_name)` assignment below —
  # silently, before any password is minted. Swallow it so "no such volume"
  # reads as empty output + success, not as a fatal error.
  docker volume ls --format '{{.Name}}' 2>/dev/null | grep -E '(^|_)dashboard-db-data$' | head -n1 || true
}

if [[ ! -f "$ENV_FILE" ]]; then
  echo "No .env found — generating fresh secrets."
  {
    echo "ATTACK_BOX_PASSWORD=$(gen_secret)"
  } > "$ENV_FILE"
  chmod 600 "$ENV_FILE"
fi
# DASHBOARD_PASSWORD is intentionally NOT auto-generated: the dashboard is
# already loopback-only + SSH-tunnel'd, so its basic-auth login is optional.
# The dashboard runs with no login unless you add a DASHBOARD_PASSWORD line to
# .env yourself (the app then enforces it; compose no longer requires it).

# DASHBOARD_DB_PASSWORD is special: MySQL bakes it into the dashboard-db
# volume on that volume's FIRST init and ignores the env var forever after.
# So minting a fresh one while the volume already exists guarantees an auth
# mismatch — the dashboard then loops on ER_ACCESS_DENIED_ERROR. Only mint
# one when there's no existing volume to disagree with; otherwise stop and
# tell the user, rather than silently baking in a password nothing can use.
if ! grep -q '^DASHBOARD_DB_PASSWORD=' "$ENV_FILE"; then
  existing_vol=$(db_volume_name)
  if [[ -n "$existing_vol" ]]; then
    cat >&2 <<EOF
ERROR: .env has no DASHBOARD_DB_PASSWORD, but the dashboard-db volume
"$existing_vol" already exists with a password baked in from a previous run.
A new random password would not match it, so the dashboard would fail to log
in (ER_ACCESS_DENIED_ERROR, on a loop).

Do ONE of these, then re-run ./up.sh:
  * Put the original DASHBOARD_DB_PASSWORD line back into .env, or
  * Reset the DB password to a new value, keeping data (see README), or
  * Wipe the volume and reseed — DESTROYS dashboard data incl. scan runs:
      docker compose down && docker volume rm "$existing_vol"
EOF
    exit 1
  fi
  echo "DASHBOARD_DB_PASSWORD=$(gen_secret)" >> "$ENV_FILE"
fi

# --build: without it, compose reuses whatever image is already cached for
# attack-box and silently ignores any Dockerfile changes since that image
# was last built.
docker compose up -d --build

PASS=$(grep ATTACK_BOX_PASSWORD "$ENV_FILE" | cut -d= -f2)
# `|| true`: DASHBOARD_PASSWORD is optional, so a no-match grep must not trip
# `set -o pipefail`/`set -e` and abort the script here.
DASH_PASS=$(grep '^DASHBOARD_PASSWORD=' "$ENV_FILE" | cut -d= -f2- || true)
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
docker compose config --services | grep -vE '^(attack-box|gate|dashboard|dashboard-db)$' | sed 's/^/   http:\/\//'
echo
echo " Benchmark dashboard (NOT reachable from the attack box — SSH tunnel only):"
echo "   ssh -N -L 3010:127.0.0.1:3010 <user>@${IP}"
if [[ -n "$DASH_PASS" ]]; then
  echo "   then open http://127.0.0.1:3010  (user: admin, password: ${DASH_PASS})"
else
  echo "   then open http://127.0.0.1:3010  (no login — add DASHBOARD_PASSWORD to .env to require one)"
fi
echo "======================================================================"
echo

# Static guards above can't catch a DASHBOARD_DB_PASSWORD that's present but
# was *changed* after the volume's first init (the value in .env no longer
# matches what's baked into the volume). Verify against the live DB and warn
# loudly, rather than leave the dashboard silently looping on access-denied.
# (mysqladmin ping reports "alive" even on bad creds, so ping alone can't
# tell — we do a real authenticated query as the dashboard user.)
DB_PASS=$(grep '^DASHBOARD_DB_PASSWORD=' "$ENV_FILE" | cut -d= -f2- || true)
for _ in $(seq 1 30); do
  docker exec vb-dashboard-db mysqladmin --silent ping >/dev/null 2>&1 && break
  sleep 2
done
if docker exec vb-dashboard-db \
     mysql -udashboard -p"$DB_PASS" -e 'SELECT 1' vuln_dashboard >/dev/null 2>&1; then
  : # dashboard user authenticates — nothing to do
else
  cat >&2 <<EOF
WARNING: dashboard-db is running but rejects the DASHBOARD_DB_PASSWORD in
.env (access denied). This usually means .env's value was changed after the
volume was first initialized, so the two no longer agree. The dashboard will
loop on "Waiting for database (N/30): ER_ACCESS_DENIED_ERROR" until fixed.

Do ONE of these:
  * Restore the DASHBOARD_DB_PASSWORD that matches the existing volume, or
  * Reset the DB password to the .env value, keeping data (see README), or
  * Wipe the volume and reseed — DESTROYS dashboard data incl. scan runs:
      docker compose down && docker volume rm "$(db_volume_name)"
EOF
fi

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
