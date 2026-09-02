# vuln-lab — pentest benchmark targets (VPS deployment)

**Architecture:** one public entry point (`attack-box` — a browser-based Kali
desktop on :6901), everything else internal-only. Demo attendees log into the
attack box in their browser and run their tools *from inside it*, reaching
targets by Docker DNS name on the internal `vulnbench` network. The vulnerable
targets themselves never get a public port — they can't be scanned or hit
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
./up.sh              # stays up until you tear it down
./up.sh --hours 3     # or: auto tear-down after 3 hours (needs `at`, installed above)
```

First run generates a random attack-box password into `.env` (mode 600) and
prints the login URL. Re-running `up.sh` reuses the same password until you
delete `.env` or rotate it (`rm .env && ./up.sh` for a fresh one — do this
before every public demo rather than reusing a password that's ever been
shown on a screen).

```bash
./status.sh    # what's running, and confirms only 22/6901 are listening
./down.sh       # tear down (keeps DB volumes)
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

The container runs as root and shares the `vulnbench` network, so the binary
can reach targets by name (`http://dvwa`, `http://juice-shop:3000`, etc.) same
as anything else launched from the desktop. If it's a Linux binary built
elsewhere, match the container's architecture (`uname -m` inside the desktop
first — it's likely `x86_64` unless your VPS is ARM) and statically link it
(or ship its shared-library deps alongside it) since the image won't have your
build environment's libc/libraries.

## 2. What attendees do

1. Browser → `https://<vps-ip>:6901`, click through the self-signed-cert
   warning (expected — it's Kasm's own cert, not a real CA).
2. Log in with the password `up.sh` printed.
3. Inside the desktop: Firefox for the web-UI targets, a terminal with
   nmap/sqlmap/nikto/gobuster/curl/etc. for everything else.
4. Targets are reachable by container name from inside the desktop:

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
these to a public port** — they're real exploits for real CVEs:

```bash
git clone https://github.com/vulhub/vulhub.git
cd vulhub/log4j/CVE-2021-44228        # example: Log4Shell
```

Before `docker compose up -d`, same rule as crAPI: strip any bare port
publish, join `vulnbench` as an external network. Test from inside the attack
box, then `docker compose down` before moving to the next CVE — many share
default ports, so run one (or a few) at a time rather than the whole
collection simultaneously.

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

- Only `attack-box` publishes a non-loopback port (`6901`). Every target's
  `ports:` entry (if any) must stay prefixed `127.0.0.1:` or be absent
  entirely — this includes crAPI and any Vulhub CVE you bring up.
- `./status.sh` after every `up.sh` — confirms only 22/6901 are listening.
- Rotate the attack-box password before each public demo (`rm .env`).
- Keep SSH hardened: key-based auth only (`PasswordAuthentication no`), and
  consider `fail2ban` for the inevitable credential-stuffing noise on port 22.
- Snapshot the VPS once the base fleet is working, so a target you've broken
  (RCE'd, corrupted DB) is a snapshot-restore away instead of a rebuild.
- Use `./up.sh --hours N` for actual public demos so the window closes itself
  even if you forget to run `down.sh`.
- **`attack-box` runs `privileged: true`** — full host capabilities and device
  access, on the one container that's internet-facing. A compromise of it is
  now realistically a full VPS compromise, not a contained one. Given that:
  treat the VPS itself as disposable (snapshot before demos, rebuild after
  anything that looked like a real compromise rather than trusting it's still
  clean), and don't reuse this VPS for anything unrelated.

## Optional: automated scoring

- Juice Shop exposes challenge state at `/api/Challenges` (also `--ctf-key`
  mode for scoreboard/CTF integrations) — useful if a benchmark harness wants
  pass/fail signal per challenge rather than a human checklist.
- OWASP ZAP or Nuclei can be run from inside the attack box against these
  containers for baseline scanner comparison runs before/after your own tooling.
