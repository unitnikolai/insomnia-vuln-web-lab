#!/usr/bin/env bash
# Manage Vulhub CVE recipes the safe way: clones/updates
# https://github.com/vulhub/vulhub.git into ./vulhub (already gitignored — a
# stray local clone, not part of this repo), then before bringing a recipe up
# strips any port publish and isolates it onto its own Docker network so it's
# reachable from the attack box by a unique name and never gets a public (or
# even loopback) port of its own — see README section 4.
#
# Usage:
#   ./vulhub.sh list       [filter]                       # browse available recipes
#   ./vulhub.sh categories [filter]                       # browse categories (log4j, struts2, ...) with recipe counts
#   ./vulhub.sh up   <category/CVE-xxxx-xxxxx>             # bring up ONE recipe, joined to vulnbench
#   ./vulhub.sh down <category/CVE-xxxx-xxxxx>
#   ./vulhub.sh up-category   <category> --yes [--include-privileged] [--mem-limit 768m]
#   ./vulhub.sh down-category <category>
#   ./vulhub.sh up-all --yes [--include-privileged] [--mem-limit 768m]   # EVERY recipe at once (heaviest)
#   ./vulhub.sh down-all
#   ./vulhub.sh status-all
#
# --- up / down (single recipe) ---
# Rewrites any bare port publish in that recipe's docker-compose.yml to bind
# 127.0.0.1 only, then generates an override that joins every service to the
# external `vulnbench` network under its own service name. Fine for one (or a
# handful of) recipes at a time — but most recipes reuse common service names
# ("web", "db") and host ports (8080 alone appears in ~half of all recipes),
# so sharing one network across many recipes this way causes name collisions.
#
# --- up-category / down-category, up-all / down-all (batch modes) ---
# A different, heavier isolation model, built for running many recipes
# (a category — e.g. struts2's 20 CVEs — or the whole 300+-recipe collection)
# concurrently without the collisions above:
#   1. Ports are stripped entirely from each recipe (no host binding at all —
#      reachability is only ever via the attack box over Docker's internal
#      network, never the host).
#   2. Each recipe gets its OWN private network (vulhub-<slug>), not the
#      shared vulnbench, so its services keep their original names for
#      intra-recipe traffic (e.g. a "web" container still reaches "db")
#      without colliding with every other recipe's "web"/"db".
#   3. Each service also gets a globally-unique alias, <slug>-<service>
#      (e.g. log4j-cve-2021-44228-solr), and vb-attack-box is connected to
#      every one of these per-recipe networks. From inside the attack box,
#      ALWAYS use the unique alias (http://log4j-cve-2021-44228-solr), never
#      the bare service name — attack-box sits on every recipe's network at
#      once, so the bare name is ambiguous across recipes and which one you
#      get back is undefined.
#   4. Recipes using `privileged: true` (full container escape risk, not just
#      an in-app vuln) are skipped by default — pass --include-privileged to
#      force them in anyway. Currently 2 of 330 upstream recipes are affected.
#   5. Every service gets a `mem_limit` (default 768m, override with
#      --mem-limit, or "none" to disable) — a lot of these images are old
#      JVM apps that size their default heap off whatever memory Docker
#      *reports* as visible, not what the recipe actually needs; uncapped,
#      a handful of containers can eat most of the host. Raise the limit
#      for a specific category (e.g. elasticsearch, hadoop) if containers
#      OOM-loop instead of settling — check with `docker compose logs`
#      inside that recipe's directory.
#
# up-all needs real resources: 300+ image pulls (tens of GB of disk) and
# 500+ running containers even with mem_limit capping the worst case — this
# is why up-category exists, to bring up one category (a handful to ~20
# recipes) at a time on a normal-sized box instead.
set -euo pipefail
cd "$(dirname "$0")"

REPO_DIR="vulhub"
REPO_URL="https://github.com/vulhub/vulhub.git"
OVERRIDE_FILE="docker-compose.vulnbench-override.yml"
STATE_FILE=".vulhub-active"
ALL_STATE_FILE=".vulhub-all-active"
ALL_FAILURES_FILE=".vulhub-all-failures"
ATTACK_BOX="vb-attack-box"
DEFAULT_MEM_LIMIT="768m"

usage() {
  echo "Usage: $0 {list [filter]|categories [filter]|up <recipe>|down <recipe>|" >&2
  echo "           up-category <category> --yes [--include-privileged] [--mem-limit M]|down-category <category>|" >&2
  echo "           up-all --yes [--include-privileged] [--mem-limit M]|down-all|status-all}" >&2
  exit 1
}

clone_or_update() {
  if [[ ! -d "$REPO_DIR" ]]; then
    echo "Cloning vulhub (this is a large repo, may take a minute)..."
    git clone --depth 1 "$REPO_URL" "$REPO_DIR"
  fi
}

all_recipes() {
  cd "$REPO_DIR" && find . -mindepth 2 -maxdepth 3 -name docker-compose.yml \
    | sed 's#^\./##; s#/docker-compose\.yml$##' | sort
}

recipe_dir() {
  local target="$1"
  local dir="$REPO_DIR/$target"
  if [[ ! -f "$dir/docker-compose.yml" ]]; then
    echo "No recipe at $dir (expected $dir/docker-compose.yml)." >&2
    echo "Try: $0 list ${target%%/*}" >&2
    exit 1
  fi
  echo "$dir"
}

# category/CVE-xxxx-xxxxx -> category-cve-xxxx-xxxxx: a DNS-label-safe slug,
# used as both the per-recipe network name and the prefix of each service's
# unique alias in up-all/down-all.
slugify() {
  echo "$1" | tr '[:upper:]' '[:lower:]' | tr '/' '-' | sed -E 's/[^a-z0-9-]/-/g'
}

# Rewrite bare port publishes ("8080:8080", optionally quoted, with no bind
# IP) to "127.0.0.1:8080:8080", and any non-loopback bind IP that's already
# there (e.g. "0.0.0.0:8080:8080") to 127.0.0.1. Idempotent: a line already
# bound to 127.0.0.1 matches neither pattern, so re-running is a no-op.
force_loopback_ports() {
  local compose_file="$1"
  perl -pi -e '
    s/^([ \t]*-[ \t]*)"?(\d+):(\d+)"?[ \t]*$/$1"127.0.0.1:$2:$3"/;
    s/^([ \t]*-[ \t]*)"?(?!127\.0\.0\.1\b)(\d{1,3}(?:\.\d{1,3}){3}):(\d+):(\d+)"?[ \t]*$/$1"127.0.0.1:$3:$4"/;
  ' "$compose_file"
}

# Delete a `ports:` block entirely (header line + its list items) wherever it
# appears — used only by up-all, where reachability is exclusively via the
# attack box over the recipe's own isolated network, so no host binding
# (loopback or otherwise) is needed at all. Only matches the common block
# form (`ports:` alone on its line, followed by `- ...` items indented
# further); an inline/flow form (`ports: ["8080:80"]`) is left untouched and
# caught by the post-strip check below. Idempotent: once removed there's
# nothing left to match on a re-run.
strip_ports() {
  local compose_file="$1"
  perl -0777 -pi -e 's/^([ \t]*)ports:\n((?:\1[ \t]+-[^\n]*\n)*)//mg' "$compose_file"
}

# True if the recipe declares privileged: true anywhere in its raw compose
# file — full container-escape risk, not just an in-app vuln. Deliberately a
# blunt text check run before any parsing, so it can't be missed even if the
# rest of the file is unusual.
is_privileged() {
  grep -qiE '^\s*privileged:\s*true\s*$' "$1"
}

write_network_override() {
  local dir="$1"
  local services
  services=$(cd "$dir" && docker compose config --services)
  {
    echo "# Generated by vulhub.sh — joins vulnbench (defined in the lab's"
    echo "# top-level docker-compose.yml) so this recipe is reachable from the"
    echo "# attack box. Regenerated on every 'vulhub.sh up', safe to delete."
    echo "networks:"
    echo "  vulnbench:"
    echo "    external: true"
    echo "services:"
    while IFS= read -r svc; do
      [[ -n "$svc" ]] || continue
      echo "  ${svc}:"
      echo "    networks: [vulnbench]"
    done <<< "$services"
  } > "$dir/$OVERRIDE_FILE"
}

# category/CVE-xxxx-xxxxx -> category
category_of() {
  echo "${1%%/*}"
}

# Isolated-network override for batch modes (up-category/up-all): unlike
# write_network_override above, this gives the recipe its OWN network (not
# the shared vulnbench) and adds a globally-unique alias per service, on top
# of — not instead of — the service's own name, which still resolves
# normally for intra-recipe traffic since no other recipe's containers share
# this network. Also caps each service's memory (see header comment for why)
# unless mem_limit is "none".
write_isolated_override() {
  local dir="$1" slug="$2" mem_limit="$3" net="vulhub-${2}"
  local services
  services=$(cd "$dir" && docker compose config --services)
  {
    echo "# Generated by vulhub.sh — isolates this recipe onto its own"
    echo "# private network ($net) instead of sharing vulnbench, and gives"
    echo "# each service a globally-unique alias so vb-attack-box can address"
    echo "# it without colliding with same-named services in other recipes."
    echo "# Regenerated on every up-category/up-all run, safe to delete."
    echo "networks:"
    echo "  ${net}:"
    echo "    name: ${net}"
    echo "services:"
    while IFS= read -r svc; do
      [[ -n "$svc" ]] || continue
      echo "  ${svc}:"
      echo "    networks:"
      echo "      ${net}:"
      echo "        aliases: [\"${slug}-${svc}\"]"
      if [[ "$mem_limit" != "none" ]]; then
        echo "    mem_limit: \"${mem_limit}\""
      fi
    done <<< "$services"
  } > "$dir/$OVERRIDE_FILE"
}

require_attack_box() {
  if ! docker ps --format '{{.Names}}' | grep -qx "$ATTACK_BOX"; then
    echo "ERROR: $ATTACK_BOX isn't running — run ./up.sh first so there's" >&2
    echo "something to join these recipes' networks to." >&2
    exit 1
  fi
}

# Brings up one recipe under the batch isolation model. Deliberately does
# NOT rely on the script's own 'set -e': called as the condition of an
# if/while so a failure here (bad recipe, image pull failure, whatever)
# reports and moves on instead of aborting the entire batch. Echoes nothing
# on success beyond what compose itself prints, to keep batch output
# scannable across many recipes.
bring_up_isolated() {
  local target="$1" dir="$2" mem_limit="$3" slug net
  slug="$(slugify "$target")"
  net="vulhub-${slug}"
  strip_ports "$dir/docker-compose.yml" || return 1
  write_isolated_override "$dir" "$slug" "$mem_limit" || return 1
  ( cd "$dir" && docker compose -f docker-compose.yml -f "$OVERRIDE_FILE" up -d ) || return 1
  docker network connect "$net" "$ATTACK_BOX" 2>/dev/null || true
  return 0
}

# Runs bring_up_isolated over a newline-delimited list of targets read from
# stdin, appending survivors to ALL_STATE_FILE (de-duplicated, so re-running
# a category that's already partially up doesn't create repeat entries) and
# failures to ALL_FAILURES_FILE (truncated at the start of each batch — it
# reflects only the most recent run). Sets BATCH_STARTED/BATCH_FAILED/
# BATCH_SKIPPED globals for the caller to report instead of returning via
# stdout, since UP/FAIL/SKIP progress lines already go there.
run_batch() {
  local mem_limit="$1" include_privileged="$2" target dir
  BATCH_STARTED=0 BATCH_FAILED=0 BATCH_SKIPPED=0
  : > "$ALL_FAILURES_FILE"
  while IFS= read -r target; do
    [[ -n "$target" ]] || continue
    dir="$REPO_DIR/$target"
    if [[ "$include_privileged" -ne 1 ]] && is_privileged "$dir/docker-compose.yml"; then
      echo "SKIP  (privileged) $target"
      BATCH_SKIPPED=$((BATCH_SKIPPED + 1))
      continue
    fi
    if bring_up_isolated "$target" "$dir" "$mem_limit"; then
      grep -qxF "$target" "$ALL_STATE_FILE" 2>/dev/null || echo "$target" >> "$ALL_STATE_FILE"
      BATCH_STARTED=$((BATCH_STARTED + 1))
      echo "UP    $target"
    else
      echo "$target" >> "$ALL_FAILURES_FILE"
      BATCH_FAILED=$((BATCH_FAILED + 1))
      echo "FAIL  $target"
    fi
  done
}

# Parses the shared --yes/--include-privileged/--mem-limit flags used by
# up-all and up-category. Sets CONFIRMED/INCLUDE_PRIVILEGED/MEM_LIMIT globals.
parse_batch_flags() {
  CONFIRMED=0
  INCLUDE_PRIVILEGED=0
  MEM_LIMIT="$DEFAULT_MEM_LIMIT"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --yes) CONFIRMED=1; shift ;;
      --include-privileged) INCLUDE_PRIVILEGED=1; shift ;;
      --mem-limit)
        [[ -n "${2:-}" ]] || { echo "--mem-limit needs a value (e.g. 768m, or 'none')" >&2; usage; }
        MEM_LIMIT="$2"; shift 2 ;;
      *) echo "Unknown argument: $1" >&2; usage ;;
    esac
  done
}

tear_down_isolated() {
  local target="$1" dir="$REPO_DIR/$target" slug net
  slug="$(slugify "$target")"
  net="vulhub-${slug}"
  docker network disconnect "$net" "$ATTACK_BOX" 2>/dev/null || true
  if [[ -f "$dir/$OVERRIDE_FILE" ]]; then
    ( cd "$dir" && docker compose -f docker-compose.yml -f "$OVERRIDE_FILE" down ) || true
  fi
}

[[ $# -ge 1 ]] || usage
cmd="$1"; shift || true

case "$cmd" in
  list)
    clone_or_update
    filter="${1:-}"
    recipes=$(all_recipes)
    if [[ -n "$filter" ]]; then
      echo "$recipes" | grep -i "$filter" || { echo "No recipes matching '$filter'."; exit 1; }
    else
      echo "$recipes"
    fi
    ;;

  up)
    [[ $# -ge 1 ]] || usage
    target="$1"
    clone_or_update
    dir="$(recipe_dir "$target")"
    echo "Forcing any published ports in $dir/docker-compose.yml to 127.0.0.1-only..."
    force_loopback_ports "$dir/docker-compose.yml"
    echo "Joining vulnbench network..."
    write_network_override "$dir"
    ( cd "$dir" && docker compose -f docker-compose.yml -f "$OVERRIDE_FILE" up -d )
    echo "$target" > "$STATE_FILE"
    echo
    echo "======================================================================"
    echo " $target is up."
    echo " Reachable from INSIDE the attack box only, by service name, e.g.:"
    ( cd "$dir" && docker compose config --services | sed 's/^/   http:\/\//' )
    echo
    echo " Run ./status.sh to confirm no new public port appeared, and diff"
    echo " $dir/docker-compose.yml against 'git -C $REPO_DIR diff' if this"
    echo " recipe used an unusual port syntax the auto-rewrite might've missed."
    echo " ./down.sh will tear this down too (tracked in $STATE_FILE); to swap"
    echo " to a different recipe without tearing down the rest of the fleet,"
    echo " use '$0 down $target' first."
    echo "======================================================================"
    ;;

  down)
    [[ $# -ge 1 ]] || usage
    target="$1"
    dir="$(recipe_dir "$target")"
    if [[ -f "$dir/$OVERRIDE_FILE" ]]; then
      ( cd "$dir" && docker compose -f docker-compose.yml -f "$OVERRIDE_FILE" down )
    else
      ( cd "$dir" && docker compose down )
    fi
    if [[ -f "$STATE_FILE" && "$(cat "$STATE_FILE")" == "$target" ]]; then
      rm -f "$STATE_FILE"
    fi
    ;;

  categories)
    clone_or_update
    filter="${1:-}"
    cats=$(all_recipes | sed -E 's#/.*$##' | sort | uniq -c | sort -rn | awk '{printf "%-4s %s\n", $1, $2}')
    if [[ -n "$filter" ]]; then
      echo "$cats" | grep -i "$filter" || { echo "No categories matching '$filter'."; exit 1; }
    else
      echo "$cats"
    fi
    ;;

  up-all)
    parse_batch_flags "$@"
    if [[ "$CONFIRMED" -ne 1 ]]; then
      echo "up-all brings up EVERY Vulhub recipe at once: 300+ image pulls," >&2
      echo "tens of GB of disk, 500+ containers even with mem_limit capping" >&2
      echo "the worst case. Consider up-category for a smaller, sized batch." >&2
      echo "Re-run with --yes to confirm this VPS is sized for it: $0 up-all --yes" >&2
      exit 1
    fi
    clone_or_update
    require_attack_box

    run_batch "$MEM_LIMIT" "$INCLUDE_PRIVILEGED" < <(all_recipes)

    echo
    echo "======================================================================"
    echo " up-all finished: $BATCH_STARTED up, $BATCH_FAILED failed, $BATCH_SKIPPED skipped (privileged)."
    echo
    echo " Every recipe is reachable from INSIDE the attack box only, by its"
    echo " unique alias — NEVER the bare service name (ambiguous across"
    echo " recipes since attack-box sits on all of them at once):"
    echo "   http://<category>-<cve>-<service>   e.g. http://log4j-cve-2021-44228-solr"
    echo
    echo " Each service is capped at mem_limit=$MEM_LIMIT. ./status.sh /"
    echo " ./vulhub.sh status-all show what's running."
    if [[ "$BATCH_FAILED" -gt 0 ]]; then
      echo " Failed recipes are listed in $ALL_FAILURES_FILE — check each by hand"
      echo " (missing image, arch mismatch, recipe needing extra setup, etc)."
    fi
    if [[ "$BATCH_SKIPPED" -gt 0 ]]; then
      echo " Skipped privileged recipes: re-run with --include-privileged to"
      echo " force them in (they can escape their container, not just their app)."
    fi
    echo "======================================================================"
    ;;

  down-all)
    if [[ ! -f "$ALL_STATE_FILE" ]]; then
      echo "No active batch recipes tracked in $ALL_STATE_FILE — nothing to do."
      exit 0
    fi
    while IFS= read -r target; do
      [[ -n "$target" ]] || continue
      echo "DOWN  $target"
      tear_down_isolated "$target"
    done < "$ALL_STATE_FILE"
    rm -f "$ALL_STATE_FILE" "$ALL_FAILURES_FILE"
    echo "All batch recipes torn down."
    ;;

  up-category)
    [[ $# -ge 1 ]] || usage
    category="$1"; shift
    parse_batch_flags "$@"
    if [[ "$CONFIRMED" -ne 1 ]]; then
      echo "up-category brings up every recipe under vulhub/$category/ at once." >&2
      echo "Re-run with --yes: $0 up-category $category --yes" >&2
      exit 1
    fi
    clone_or_update
    require_attack_box

    targets=$(all_recipes | grep -E "^${category}/" || true)
    if [[ -z "$targets" ]]; then
      echo "No recipes found under category '$category'. Try: $0 categories $category" >&2
      exit 1
    fi

    run_batch "$MEM_LIMIT" "$INCLUDE_PRIVILEGED" <<< "$targets"

    echo
    echo "======================================================================"
    echo " up-category '$category' finished: $BATCH_STARTED up, $BATCH_FAILED failed, $BATCH_SKIPPED skipped (privileged)."
    echo " Reachable from INSIDE the attack box only, by unique alias, e.g.:"
    echo "$targets" | head -1 | while IFS= read -r t; do
      echo "   http://$(slugify "$t")-<service>"
    done
    echo " Each service is capped at mem_limit=$MEM_LIMIT."
    echo " ./vulhub.sh down-category $category tears down just this category;"
    echo " other active categories/recipes are left running."
    echo "======================================================================"
    ;;

  down-category)
    [[ $# -ge 1 ]] || usage
    category="$1"
    if [[ ! -f "$ALL_STATE_FILE" ]]; then
      echo "No active batch recipes tracked in $ALL_STATE_FILE — nothing to do."
      exit 0
    fi
    matched=0
    while IFS= read -r target; do
      [[ -n "$target" ]] || continue
      if [[ "$(category_of "$target")" == "$category" ]]; then
        echo "DOWN  $target"
        tear_down_isolated "$target"
        matched=$((matched + 1))
      fi
    done < "$ALL_STATE_FILE"
    if [[ "$matched" -eq 0 ]]; then
      echo "No active recipes under category '$category'."
      exit 0
    fi
    tmp="$(mktemp)"
    awk -v cat="$category" -F/ '$1 != cat' "$ALL_STATE_FILE" > "$tmp" && mv "$tmp" "$ALL_STATE_FILE"
    [[ -s "$ALL_STATE_FILE" ]] || rm -f "$ALL_STATE_FILE"
    echo "Category '$category' torn down ($matched recipe(s))."
    ;;

  status-all)
    if [[ -f "$ALL_STATE_FILE" ]]; then
      echo "Tracked active recipes: $(wc -l < "$ALL_STATE_FILE" | tr -d ' ')"
      echo "By category:"
      awk -F/ '{print $1}' "$ALL_STATE_FILE" | sort | uniq -c | sort -rn | awk '{printf "  %-4s %s\n", $1, $2}'
    else
      echo "Tracked active recipes: 0 (no $ALL_STATE_FILE)"
    fi
    echo "Isolated vulhub networks currently on the host:"
    docker network ls --filter "name=^vulhub-" --format '  {{.Name}}' | sort
    if [[ -f "$ALL_FAILURES_FILE" && -s "$ALL_FAILURES_FILE" ]]; then
      echo
      echo "Recipes that failed to start on the last up-all/up-category run:"
      sed 's/^/  /' "$ALL_FAILURES_FILE"
    fi
    ;;

  *)
    usage
    ;;
esac
