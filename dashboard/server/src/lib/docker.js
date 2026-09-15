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
  '_attack-box': 'vb-attack-box',
  '_gate':       'vb-gate',
};

// Reverse lookup
const CONTAINER_TO_SLUG = {};
for (const [slug, name] of Object.entries(SLUG_TO_CONTAINER)) {
  CONTAINER_TO_SLUG[name] = slug;
}

async function listContainers() {
  // List ALL containers (including stopped) whose name starts with vb-
  const containers = await dockerRequest('GET', '/containers/json?all=true');
  const results = [];
  for (const c of containers) {
    // c.Names is like ["/vb-juice-shop"]
    const name = (c.Names || [])[0]?.replace(/^\//, '') || '';
    if (!name.startsWith(PREFIX)) continue;

    results.push({
      name,
      slug: CONTAINER_TO_SLUG[name] || name.replace(PREFIX, ''),
      id: c.Id,
      state: c.State,     // running, exited, created, paused, etc.
      status: c.Status,   // "Up 2 hours", "Exited (0) 3 days ago", etc.
      image: c.Image,
      ports: (c.Ports || []).map((p) => ({
        private: p.PrivatePort,
        public: p.PublicPort || null,
        type: p.Type,
        ip: p.IP || null,
      })),
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
