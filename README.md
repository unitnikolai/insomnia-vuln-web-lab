# vuln-lab — pentest benchmark targets (VPS deployment)

**Architecture:** one public entry point (`gate` — a single-slot access queue
on :6901) in front of `attack-box` (a browser-based Kali desktop), everything
else internal-only, including `attack-box` itself, which has no host port at
all and is reached only by `gate` over the internal `vulnbench` network.
`attack-box` is one shared X session, not one container per attendee, so
`gate` lets in one visitor at a time and holds everyone else in a waiting
room — two people driving the same desktop at once just fight over the mouse
and can crash it under concurrent load. Whoever's admitted logs into the
attack box in their browser and runs their tools *from inside it*, reaching
targets by Docker DNS name on the internal network. The vulnerable targets
themselves never get a public port either — they can't be scanned or hit
directly from the internet, only from inside the attack box.

Treat this VPS as hostile while the fleet runs: several targets (WebGoat,
Vulhub CVEs) contain real, working RCE. Keeping them off the public internet
entirely — rather than trusting them to survive being internet-facing — is
what makes this safe to run as a public demo.

## 0. Provision and lock down the VPS

```bash
# on the VPS, as a non-root sudo user
sudo apt update && sudo apt install -y docker.io docker-compose-plugin at

# firewall: deny everything inbound except SSH and the attack-box port
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow OpenSSH
sudo ufw allow 6901/tcp
sudo ufw enable
```

Also set this at the **cloud provider's** firewall/security-group panel (not
just ufw): allow only 22 and 6901 inbound. Two layers matter — ufw alone
doesn't help if the provider's security group allows all.

Copy this folder to the VPS: `scp -r vuln-lab user@vps-ip:~/`. SSH in,
`cd vuln-lab`, `chmod +x *.sh`, continue below.

## 1. Bring the fleet up

```bash
./up.sh                                            # stays up until you tear it down
./up.sh --hours 3                                  # or: auto tear-down after 3 hours (needs `at`, installed above)
./up.sh --vulhub log4j/CVE-2021-44228              # also bring up one Vulhub CVE recipe (see section 4)
./up.sh --vulhub-category struts2                  # or: a whole Vulhub category at once (see section 4b)
./up.sh --vulhub-all                               # or: EVERY Vulhub recipe at once (heaviest — see section 4c)
./up.sh --vulhub log4j/CVE-2021-44228 --hours 3    # any of the above, combined with --hours
```

First run generates a random attack-box password into `.env` (mode 600) and
prints the login URL. Re-running `up.sh` reuses the same password until you
delete `.env` or rotate it (`rm .env && ./up.sh` for a fresh one — do this
before every public demo rather than reusing a password that's ever been
shown on a screen).

```bash
./status.sh    # what's running, and confirms only 22/6901 are listening
./down.sh       # tear down (keeps DB volumes) — also tears down any active Vulhub recipe
./down.sh --wipe  # tear down and reset all target DB state
```

## 1b. Running your own binary on the attack box

Drop it into `vuln-lab/tools/` on the VPS host:

```bash
scp ./my-tool user@vps-ip:~/vuln-lab/tools/
ssh user@vps-ip 'chmod +x ~/vuln-lab/tools/my-tool'
```

It appears at `/opt/tools/my-tool` inside the desktop immediately — the
directory is bind-mounted, so no rebuild or container restart is needed, even
if you overwrite the binary later (e.g. iterating on a build). Run it from the
in-desktop terminal:

```bash
/opt/tools/my-tool
```

The container itself runs as root and shares the `vulnbench` network, so the
binary can reach targets by name (`http://dvwa`, `http://juice-shop:3000`,
etc.) same as anything else launched from the desktop. Note: the *interactive
terminal session* inside the desktop actually runs as Kasm's own non-root
`kasm_user` regardless of the container's root setting (see 1c below) — if
your binary needs raw sockets, apply the same `setcap` treatment to it. If
it's a Linux binary built elsewhere, match the container's architecture
(`uname -m` inside the desktop first — it's likely `x86_64` unless your VPS is
ARM) and statically link it (or ship its shared-library deps alongside it)
since the image won't have your build environment's libc/libraries.

## 1c. Full raw-socket capability (SYN scans, packet crafting, etc.)

Kasm's desktop images run the actual desktop/terminal session as an internal
`kasm_user`, not root — so Docker's default capabilities on the container
alone aren't enough, and `nmap -sS`, ARP tooling, and anything else needing
`CAP_NET_RAW` fails from the in-browser terminal. (Don't add `user: root` to
work around this — it does grant the container capabilities, but it also
makes the desktop launch GUI apps like Firefox as root, which Firefox
refuses to do.)

**Already baked in for a fresh deploy:** `attack-box.Dockerfile` runs `setcap`
on `nmap`, `tcpdump`, `hping3`, `arping`, and `masscan` at build time, so they
work at full capability from any user inside the container. `up.sh` builds
this automatically (`docker compose` picks up the `build:` section).

**For a binary you drop into `tools/`,** or if a container is already running
and you don't want to rebuild, do it live from the VPS host — this bypasses
Kasm's user-switching entirely by exec'ing in as root directly:

```bash
docker exec -u root vb-attack-box setcap cap_net_raw,cap_net_admin+eip /opt/tools/my-tool
```

This only persists for the life of the current container (it's a change to
the writable layer) — a `down.sh`/`up.sh` cycle rebuilds from the Dockerfile
and loses it again for anything not listed there. Add your own binary's name
to the `for bin in ...` loop in `attack-box.Dockerfile` if you want it to
survive teardown/rebuild automatically.

**For anything else needing root** (apt install, a tool that doesn't work
via setcap alone), `kasm-user` has passwordless `sudo` — `attack-box.Dockerfile`
drops a NOPASSWD sudoers entry for it, since the account otherwise has no
password configured at all and `sudo` would sit at an unsatisfiable prompt.

## 2. What attendees do

1. Browser → `https://<vps-ip>:6901`, click through the self-signed-cert
   warning (expected — it's Kasm's own cert, not a real CA).
2. If someone else is already in, they land on a waiting-room page showing
   their queue position — it polls automatically and forwards them the
   moment they're admitted, no action needed.
3. Once admitted: log in with the password `up.sh` printed.
4. Inside the desktop: Firefox for the web-UI targets, a terminal with
   nmap/sqlmap/nikto/gobuster/curl/etc. for everything else.
5. Closing the tab (or a 45-minute hard cap, or ~30s of never actually
   connecting after being admitted) frees the slot for the next person in
   line automatically.
6. Targets are reachable by container name from inside the desktop:

| App        | URL (from inside the attack box) | Covers                                                 |
|------------|-----------------------------------|---------------------------------------------------------|
| Juice Shop | http://juice-shop:3000            | XSS, SQLi/NoSQLi, IDOR, JWT, SSRF, XXE, business logic   |
| DVWA       | http://dvwa                       | Classic OWASP Top 10, adjustable difficulty              |
| Mutillidae | http://mutillidae                 | Broad OWASP 2007-2021 coverage, LDAP injection, etc.     |
| VAmPI      | http://vampi:5000                 | API Top 10: BOLA, mass assignment, JWT                   |
| DVGA       | http://dvga:5013                  | GraphQL-specific: introspection, batching, injection     |
| WebGoat    | http://webgoat:8080/WebGoat       | Java deserialization, XXE, SSRF, path traversal          |
| WebWolf    | http://webgoat:9090/WebWolf       | SSRF/phishing simulation companion to WebGoat            |

DVWA: click "Create / Reset Database" on first load. Default creds `admin`/`password`.

## 3. crAPI (modern API vulns: BOLA, mass assignment, SSRF, JWT alg confusion)

crAPI ships its own multi-service compose file — don't hand-roll it, use the
upstream one, but join it to the same `vulnbench` network so it's reachable
from the attack box and stays off the public internet:

```bash
git clone https://github.com/OWASP/crAPI.git
cd crAPI/deploy/docker
```

Edit crAPI's `docker-compose.yml`: for every service that publishes a port,
either delete the `ports:` entry (internal-only, reachable by service name
from the attack box) or prefix it `127.0.0.1:` if you want host-local admin
access too — never leave a bare `"8888:8888"`. Add `vulnbench` under each
service's `networks:` and declare it as `external: true` at the bottom of the
file so it joins the existing network from `up.sh` instead of creating its own.
Then:

```bash
docker compose --compatibility up -d
```

## 4. Vulhub — real, historical CVEs (this is where the *rare* stuff lives)

The apps above are synthetic training targets. For actual named vulnerabilities
(deserialization gadget chains, Log4Shell-class RCEs, framework-specific XXE,
Struts/Spring RCEs, etc.), use Vulhub — hundreds of docker-compose recipes, one
per CVE, reproducing the exact vulnerable software version. **Never publish
these to a public port** — they're real exploits for real CVEs.

**Browse recipes** with `./vulhub.sh` directly (this doesn't start anything):

```bash
./vulhub.sh list         # browse all available recipes
./vulhub.sh list log4j   # filter by name
```

**Bring one up** as part of the fleet with `./up.sh --vulhub`, the same way
you'd start any other target:

```bash
./up.sh --vulhub log4j/CVE-2021-44228    # example: Log4Shell
```

This clones/updates `vulhub` (gitignored, not part of this repo) if needed,
rewrites any bare port publish in that recipe's `docker-compose.yml` to bind
`127.0.0.1` only, generates a `docker-compose.vulnbench-override.yml` in the
recipe's directory that joins every service to the `vulnbench` network — same
rule as every other target in this lab — then brings it up, *after* the base
fleet so `vulnbench` already exists. The active recipe name is tracked in the
gitignored `.vulhub-active`, so `./down.sh` tears it down automatically along
with everything else — no separate step to remember.

The port rewrite handles the common `"HOST:CONTAINER"` and `IP:HOST:CONTAINER`
forms; anything unusual (protocol suffixes, port ranges) is left alone and
printed so you can check it by hand before treating the recipe as safe.

Only one recipe at a time this way: many share default ports and a bare
`web`/`db` service name, so they collide with each other when joined to the
same `vulnbench` network. To swap to a different CVE without tearing down the
whole fleet, use `vulhub.sh` directly — it keeps `.vulhub-active` (and
therefore what `./down.sh` will clean up) in sync:

```bash
./vulhub.sh down log4j/CVE-2021-44228
./vulhub.sh up   struts2/CVE-2017-5638
```

### 4b. Bringing up many Vulhub recipes at once (batch mode)

For more than a handful of CVEs concurrently, `vulhub.sh` switches to a
different isolation model than 4 above, since sharing one network doesn't
scale — most recipes reuse the same service names and ports (154 of the 330
recipes bind host port `8080` alone; 170 name a service `web`). Per recipe,
batch mode: strips its `ports:` entirely (no host binding at all, loopback
included — reachable only via the attack box), puts it on its own private
network (`vulhub-<category>-<cve>`) instead of `vulnbench` so its services
keep talking to each other by their original names (a `web` container still
reaches its own `db`) without colliding with every other recipe's `web`/`db`,
and gives each service a globally-unique alias, `<category>-<cve>-<service>`,
with the attack box connected to every one of these per-recipe networks.
**From inside the attack box, always use the unique alias** — e.g.
`http://log4j-cve-2021-44228-solr` — never the bare service name
(`http://solr`): the attack box sits on every active recipe's network at
once, so a bare name is ambiguous and which container answers is undefined.

Every service also gets a `mem_limit` (default `768m`) — a lot of these
images are old JVM apps (Tomcat, Solr, WebLogic, ActiveMQ, Elasticsearch...)
that size their default heap off however much memory Docker *reports* as
visible to the container, not what the app actually needs; uncapped, a
handful of these can eat most of a host's RAM. Override with `--mem-limit`
if a category needs more headroom (or `--mem-limit none` to disable) —
check `docker compose logs` inside a recipe's directory if containers OOM
loop instead of settling.

Two recipes (of 330) declare `privileged: true` — a full container-escape
risk, not just an in-app vulnerability — and are skipped by default in both
modes below. Pass `--include-privileged` to `vulhub.sh` directly if you want
them anyway (neither `up.sh` flag exposes this — run `vulhub.sh up-all` /
`up-category` yourself with it if you need it).

**Recommended: one category at a time.** `./vulhub.sh categories` lists
every category (150 of them) with its recipe count — things like `struts2`
(20 recipes), `spring` (10), `weblogic` (7), `php` (9). Bringing up one
category is a properly *sized* batch instead of an all-or-nothing choice:

```bash
./vulhub.sh categories struts     # how many recipes, before committing
./up.sh --vulhub-category struts2 # bring that category up, joined to the fleet
./vulhub.sh down-category struts2 # tear down just this category — others stay up
```

Rough RAM per category, with the default 768m cap (real usage is normally
well under the cap since idle recipes rarely peak; treat this as a ceiling,
not a measurement — I have not run these live to confirm):

| Category  | Recipes | Ceiling (cap × recipes) |
|-----------|---------|--------------------------|
| struts2   | 20      | ~15GB                    |
| spring    | 10      | ~7.5GB                   |
| weblogic  | 7       | ~5.5GB                   |
| php       | 9       | ~7GB                     |

You can bring up several categories over time — each `up-category` call adds
to what's already running rather than replacing it; `down-category` removes
just that one.

### 4c. Bringing up *every* Vulhub recipe at once

For a full-collection benchmark rig rather than a category at a time,
`./up.sh --vulhub-all` brings up the whole collection concurrently — as of
this writing, 330 recipes / ~446 containers, using the same batch isolation
model as 4b:

```bash
./up.sh --vulhub-all
```

**Size the VPS for this before running it.** Roughly one third of Vulhub's
containers are JVM-based (WebLogic, Solr, Elasticsearch, Confluence,
ActiveMQ, Tomcat/struts2, Jenkins, JBoss, Hadoop, Nexus...) — historically
the category most likely to reserve far more memory than it uses if
uncapped. With every container capped at the default `mem_limit=768m`, the
absolute ceiling for all 330 recipes is in the neighborhood of **300-350GB**;
realistic usage, since most recipes sit idle well under their cap, is likely
much lower, plausibly in the **60-120GB range**, but I have not run the full
collection live to confirm either number — budget toward the ceiling, not
the estimate, and treat `--mem-limit` as a dial: lower it fleet-wide if the
box is smaller than that, or raise it for a specific category if containers
OOM-loop at the default. On top of RAM: expect 300+ image pulls (tens of GB
of disk) and 500+ running containers — a different order of resource use
than the base fleet, a single recipe, or one category. Don't run this on the
same modest box hosting a live demo unless you've confirmed the headroom;
`--vulhub-category` (4b) is almost always the better fit for a real demo.

A handful of recipes will likely fail to start regardless (a 404'd image, an
arch mismatch, a recipe needing manual setup this script doesn't automate)
— both `up-all` and `up-category` report a per-recipe UP/FAIL/SKIP line as
they go and write failures to the gitignored `.vulhub-all-failures` for
follow-up, rather than aborting the whole run over one bad recipe.

```bash
./vulhub.sh status-all   # active recipe count (by category), isolated networks, last run's failures
./down.sh                # tears every batch-mode recipe down too (same as any other target)
```

## 5. Admin-only fallback access: SSH tunnel

For your own poking-around outside of demos, you don't need the attack box —
tunnel straight to a target's loopback binding (still present in
`docker-compose.yml` for this reason):

```bash
ssh -N -L 3000:127.0.0.1:3000 -L 3001:127.0.0.1:3001 user@vps-ip
```

or a SOCKS proxy for ad-hoc access to whatever's currently up:

```bash
ssh -N -D 1080 user@vps-ip
```

## Isolation checklist

- Only `gate` publishes a host port (`6901`) at all now; `attack-box` has no
  `ports:` entry and is reached only over the internal `vulnbench` network by
  `gate`. Every *other* target's `ports:` entry (if any) must stay prefixed
  `127.0.0.1:` — this includes crAPI and any single Vulhub CVE you bring up
  with `./up.sh --vulhub`. (`--vulhub-category`/`--vulhub-all` recipes have
  no `ports:` entry at all — see 4b/4c.)
- `./status.sh` after every `up.sh` — confirms only 22/6901 are listening.
- Rotate the attack-box password before each public demo (`rm .env`).
- Keep SSH hardened: key-based auth only (`PasswordAuthentication no`), and
  consider `fail2ban` for the inevitable credential-stuffing noise on port 22.
- Snapshot the VPS once the base fleet is working, so a target you've broken
  (RCE'd, corrupted DB) is a snapshot-restore away instead of a rebuild.
- Use `./up.sh --hours N` for actual public demos so the window closes itself
  even if you forget to run `down.sh`.

## Optional: automated scoring

- Juice Shop exposes challenge state at `/api/Challenges` (also `--ctf-key`
  mode for scoreboard/CTF integrations) — useful if a benchmark harness wants
  pass/fail signal per challenge rather than a human checklist.
- OWASP ZAP or Nuclei can be run from inside the attack box against these
  containers for baseline scanner comparison runs before/after your own tooling.
