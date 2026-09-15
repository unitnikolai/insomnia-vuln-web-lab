# Benchmark dashboard

Node.js (Express + EJS) app backed by MySQL, tracking:

- **Ground truth** — the vulnerabilities/CVEs each lab or Vulhub recipe is
  supposed to yield on a scan (`labs` + `vulnerabilities` tables).
- **Scans** — uploaded JSON scan exports (`scans`, stored verbatim in
  `raw_json` regardless of whether they parse) and a best-effort normalized
  parse of their findings (`scan_findings`), matched against ground truth by
  CVE ID first, then a loose title match.

It is wired into the top-level `docker-compose.yml` as `dashboard` +
`dashboard-db`, so `./up.sh` / `./down.sh` / `./status.sh` from the repo root
manage it along with the rest of the fleet — there's no separate lifecycle to
remember.

## Why it's not on the `vulnbench` network

This dashboard shows the answer key. If it were reachable from inside
`attack-box`, an attendee running a benchmark scan could just browse to it
and read off exactly what they're supposed to find. So it lives on its own
`benchdash` network, has no path to or from `vulnbench`, is bound to
`127.0.0.1:3010` on the host only, and requires basic auth. Reach it via SSH
tunnel, same as the loopback-bound lab targets:

```bash
ssh -N -L 3010:127.0.0.1:3010 user@vps-ip
# open http://127.0.0.1:3010
```

Credentials (`DASHBOARD_USER`/`DASHBOARD_PASSWORD`) are generated into the
repo-root `.env` by `up.sh`, same as `ATTACK_BOX_PASSWORD`. `./up.sh` prints
them each run.

## Seeding

- **Built-in apps** (DVWA, Juice Shop, Mutillidae, VAmPI, DVGA, WebGoat,
  WebWolf) seed automatically the first time `dashboard-db`'s data volume is
  created, from `db/init/001_schema.sql` and `db/init/002_seed_builtin.sql`
  (standard `docker-entrypoint-initdb.d` behavior — only runs against an
  empty data directory). This is a curated starting set of vulnerability
  *classes*, not a claim of exhaustiveness — expand the seed SQL as you tune
  what the benchmark expects.

- **Vulhub recipes** are seeded separately with `seed/seed-vulhub.js`, since
  there are 300+ of them and they live in the gitignored `./vulhub` clone
  (`./vulhub.sh list` from the repo root clones it). Run from the VPS host:

  ```bash
  cd dashboard/seed
  npm install
  DB_HOST=127.0.0.1 DB_PORT=<published-port-or-tunnel> \
    DB_USER=dashboard DB_PASSWORD=<DASHBOARD_DB_PASSWORD from .env> \
    node seed-vulhub.js [path-to-vulhub-clone]
  ```

  Since `dashboard-db` isn't published to the host either (only reachable
  from `dashboard` over `benchdash`), run this via `docker compose exec`
  instead if you'd rather not open another tunnel:

  ```bash
  docker compose cp dashboard/seed vb-dashboard:/tmp/seed
  docker compose exec dashboard sh -c \
    "cd /tmp/seed && npm install && DB_HOST=dashboard-db DB_PASSWORD=$DASHBOARD_DB_PASSWORD node seed-vulhub.js /vulhub-readonly"
  ```

  (that last form needs the repo-root `./vulhub` clone bind-mounted into the
  `dashboard` container — not done by default since it's a large one-off; add
  a volume line for it if you'll be re-seeding often, or just run the script
  from any machine that can reach `dashboard-db` directly, e.g. over the SSH
  tunnel above with `DB_PORT` matching whatever you forward.)

  Safe to re-run — recipes are upserted by slug, not duplicated.

## Upload format (upload feature — structure still TBD)

`POST /upload` (multipart form: `scanFile`, optional `lab_id`, `tool_name`,
`uploaded_by`, `notes`) accepts **any JSON file**. `src/lib/parseScan.js`
currently recognizes:

- a bare top-level array of findings,
- a wrapper object with a `findings` / `vulnerabilities` / `results` /
  `issues` / `alerts` / `items` array,
- OWASP ZAP's report shape (`{ site: [ { alerts: [...] } ] }`).

For each recognized finding it looks for a CVE ID (`cve`/`cve_id`/`CVE`/
`cveId`, or a `CVE-YYYY-NNNNN` pattern in the title/description) and a
title/severity under a few common key names. Anything it can't parse is
still stored in full (`scans.raw_json`) — it just won't show parsed findings
or contribute to the coverage score.

**This is deliberately generic** because the real export format the
benchmark harness will produce hasn't been specified yet. Once it is, either
extend `parseScan.js` with a shape specific to that format, or replace it
entirely — the schema (`scan_findings`: `cve_id`, `title`, `severity`,
`matched_vulnerability_id`, `raw_snippet`) is intentionally tool-agnostic and
shouldn't need to change.

## Local dev

```bash
cd dashboard/server
npm install
DB_HOST=127.0.0.1 DB_PORT=3306 DB_USER=dashboard DB_PASSWORD=devpass DB_NAME=vuln_dashboard \
DASHBOARD_PASSWORD=devpass \
  npm start
```

(point `DB_HOST`/`DB_PORT` at any MySQL 8 instance with the schema from
`db/init/001_schema.sql` applied — e.g. `docker run -p 3306:3306 -e
MYSQL_ROOT_PASSWORD=devpass mysql:8.0` and apply the SQL files by hand for a
quick local loop without the rest of the fleet).
