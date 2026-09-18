'use strict';

// Thin wrapper around the Docker Engine API via the Unix socket.
// No npm dependency needed — just http over the socket.

const http = require('http');

const SOCKET = process.env.DOCKER_SOCKET || '/var/run/docker.sock';

function dockerRequest(method, path, body) {
  return new Promise((resolve, reject) => {
    const opts = {
      socketPath: SOCKET,
      path,
      method,
      headers: { 'Content-Type': 'application/json' },
    };
    const req = http.request(opts, (res) => {
      const chunks = [];
      res.on('data', (d) => chunks.push(d));
      res.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf8');
        let data;
        try { data = JSON.parse(raw); } catch { data = raw; }
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve(data);
        } else {
          const err = new Error(`Docker API ${method} ${path}: ${res.statusCode} — ${typeof data === 'string' ? data : JSON.stringify(data)}`);
          err.statusCode = res.statusCode;
          err.body = data;
          reject(err);
        }
      });
    });
    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

// Container name prefix used by this project's compose file
const PREFIX = 'vb-';

// Map lab slugs to their container names
const SLUG_TO_CONTAINER = {
  'juice-shop':  'vb-juice-shop',
  'dvwa':        'vb-dvwa',
  'mutillidae':  'vb-mutillidae',
  'vampi':       'vb-vampi',
  'dvga':        'vb-dvga',
  'webgoat':     'vb-webgoat',
  // infra containers (not labs, but useful to show)
  '_attack-box':   'vb-attack-box',
  '_gate':         'vb-gate',
  '_dashboard':    'vb-dashboard',
  '_dashboard-db': 'vb-dashboard-db',
};

// Reverse lookup
const CONTAINER_TO_SLUG = {};
for (const [slug, name] of Object.entries(SLUG_TO_CONTAINER)) {
  CONTAINER_TO_SLUG[name] = slug;
}

// Docker reports one entry per published host binding plus one for the bare
// exposed port, so a single "8080:8080" shows up two or three times (IPv4 +
// IPv6 + the exposed port). Collapse to one row per container port, keeping
// the published binding when there is one.
function dedupePorts(ports) {
  const byPort = new Map();
  for (const p of ports) {
    const key = `${p.PrivatePort}/${p.Type}`;
    const entry = {
      private: p.PrivatePort,
      public: p.PublicPort || null,
      type: p.Type,
      ip: p.IP || null,
    };
    const prev = byPort.get(key);
    // Prefer a published binding over the bare exposed port, and an IPv4
    // bind host over the "::" one Docker lists alongside it.
    if (!prev || (!prev.public && entry.public) ||
        (entry.public && prev.ip === '::' && entry.ip !== '::')) {
      byPort.set(key, entry);
    }
  }
  return [...byPort.values()].sort((a, b) => a.private - b.private);
}

// By default only this project's own fleet (vb-*) is returned, which is what
// the lab pages care about. Pass { includeAll: true } to also get containers
// compose spawned for a Vulhub recipe — those are named after the recipe
// directory (s2-045-struts2-1, ...), never vb-, so the prefix filter would
// otherwise hide every recipe the dashboard itself deployed.
async function listContainers(opts = {}) {
  const includeAll = opts.includeAll === true;
  // List ALL containers, including stopped ones
  const containers = await dockerRequest('GET', '/containers/json?all=true');
  const results = [];
  for (const c of containers) {
    // c.Names is like ["/vb-juice-shop"]
    const name = (c.Names || [])[0]?.replace(/^\//, '') || '';
    if (!name) continue;
    if (!includeAll && !name.startsWith(PREFIX)) continue;

    // Every network the container is attached to, with or without an address.
    // A stopped container usually reports no IPAddress (though not always —
    // a retained IPAM reservation can still show one), so `ip` is the wrong
    // thing to key on: keep the attachment itself, since which network a
    // container is on is what identifies the Vulhub recipe that owns it, and
    // that has to work while it's stopped too. Callers that want to *display*
    // an address filter on `ip` themselves.
    const netObj = (c.NetworkSettings && c.NetworkSettings.Networks) || {};
    const networks = Object.entries(netObj).map(([network, cfg]) => ({
      network,
      ip: (cfg && cfg.IPAddress) || null,
      // Aliases are the names the container answers to on that network — for a
      // batch-deployed recipe that's the globally-unique <slug>-<service>
      // alias vulhub.sh writes, which is the only safe way to address it from
      // the attack box. Docker echoes the short container id back as an alias
      // too; drop it, it's not a hostname anyone would type.
      aliases: ((cfg && cfg.Aliases) || []).filter((a) => a && !c.Id.startsWith(a)),
    }));
    // Prefer the `vulnbench` IP as the primary, since that's the address the
    // attack-box uses to reach a target; fall back to whatever network it's on.
    const addressed = networks.filter((n) => n.ip);
    const primaryNet = addressed.find((n) => n.network === 'vulnbench') || addressed[0] || null;

    const labels = c.Labels || {};

    results.push({
      name,
      slug: CONTAINER_TO_SLUG[name] || name.replace(PREFIX, ''),
      id: c.Id,
      state: c.State,     // running, exited, created, paused, etc.
      status: c.Status,   // "Up 2 hours", "Exited (0) 3 days ago", etc.
      image: c.Image,
      ip: primaryNet ? primaryNet.ip : null,
      networks,           // [{ network, ip, aliases }, ...] — ip is null when not running
      ports: dedupePorts(c.Ports || []),
      labels,
      // Set on anything `docker compose` started, which is how every Vulhub
      // recipe comes up — workingDir is the recipe's own directory, the one
      // reliable way back from a container to the recipe that owns it.
      compose: {
        project: labels['com.docker.compose.project'] || null,
        service: labels['com.docker.compose.service'] || null,
        workingDir: labels['com.docker.compose.project.working_dir'] || null,
      },
      created: c.Created,
    });
  }
  results.sort((a, b) => a.name.localeCompare(b.name));
  return results;
}

async function getContainer(nameOrId) {
  return dockerRequest('GET', `/containers/${encodeURIComponent(nameOrId)}/json`);
}

async function startContainer(nameOrId) {
  return dockerRequest('POST', `/containers/${encodeURIComponent(nameOrId)}/start`);
}

async function stopContainer(nameOrId, timeoutSec = 10) {
  return dockerRequest('POST', `/containers/${encodeURIComponent(nameOrId)}/stop?t=${timeoutSec}`);
}

async function restartContainer(nameOrId, timeoutSec = 10) {
  return dockerRequest('POST', `/containers/${encodeURIComponent(nameOrId)}/restart?t=${timeoutSec}`);
}

async function containerLogs(nameOrId, tail = 100) {
  return dockerRequest('GET', `/containers/${encodeURIComponent(nameOrId)}/logs?stdout=true&stderr=true&tail=${tail}`);
}

async function isDockerAvailable() {
  try {
    await dockerRequest('GET', '/version');
    return true;
  } catch {
    return false;
  }
}

module.exports = {
  listContainers,
  getContainer,
  startContainer,
  stopContainer,
  restartContainer,
  containerLogs,
  isDockerAvailable,
  SLUG_TO_CONTAINER,
  CONTAINER_TO_SLUG,
};
