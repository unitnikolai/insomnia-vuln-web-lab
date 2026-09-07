// Single-slot access gatekeeper for the shared attack-box (Kasm) desktop.
//
// Only one visitor gets proxied through to the real desktop at a time;
// everyone else sees a waiting-room page with their queue position. This
// exists because the attack box is one shared X session, not one container
// per user — two people driving it at once just fight over the same mouse
// and can crash it under load, so admission is serialized instead.
//
// Disconnect detection: a socket 'close' on the proxied noVNC WebSocket
// frees the slot immediately. A grant that's never followed by a WebSocket
// connection (grant abandoned) and a hard per-turn cap are backstops.

const express = require('express');
const httpProxy = require('http-proxy');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const https = require('https');
const fs = require('fs');

const TARGET = process.env.KASM_TARGET || 'https://attack-box:6901';
const PORT = process.env.PORT || 6901;
const TLS_CERT = process.env.TLS_CERT || '/app/certs/cert.pem';
const TLS_KEY = process.env.TLS_KEY || '/app/certs/key.pem';
const GRANT_GRACE_MS = 30_000;      // must open the ws within this long after being granted
const MAX_SESSION_MS = 45 * 60_000; // hard cap per turn, even if still connected
const SWEEP_INTERVAL_MS = 5_000;

const app = express();
app.use(cookieParser());

const proxy = httpProxy.createProxyServer({
  target: TARGET,
  secure: false, // attack-box serves Kasm's self-signed cert
  changeOrigin: true,
  ws: true,
});
proxy.on('error', (err, req, res) => {
  console.error('Proxy error:', err.message);
  if (res && res.writeHead && !res.headersSent) {
    res.writeHead(502);
    res.end('attack-box unavailable');
  }
});

let active = null; // { id, grantedAt, wsConnected }
const queue = [];  // [{ id, joinedAt }]

function ensureSessionId(req, res) {
  let id = req.cookies.qid;
  if (!id) {
    id = crypto.randomUUID();
    res.cookie('qid', id, { httpOnly: true, sameSite: 'lax' });
  }
  return id;
}

function isActive(id) {
  return !!active && active.id === id;
}

function promoteNext() {
  active = null;
  if (queue.length > 0) {
    const next = queue.shift();
    active = { id: next.id, grantedAt: Date.now(), wsConnected: false };
  }
}

setInterval(() => {
  if (active) {
    const elapsed = Date.now() - active.grantedAt;
    const abandoned = !active.wsConnected && elapsed > GRANT_GRACE_MS;
    const expired = elapsed > MAX_SESSION_MS;
    if (abandoned || expired) promoteNext();
  } else if (queue.length > 0) {
    promoteNext();
  }
}, SWEEP_INTERVAL_MS);

app.get('/queue/status', (req, res) => {
  const id = ensureSessionId(req, res);
  if (isActive(id)) return res.json({ granted: true });

  let pos = queue.findIndex((q) => q.id === id);
  if (pos === -1) {
    queue.push({ id, joinedAt: Date.now() });
    if (!active) promoteNext();
    if (isActive(id)) return res.json({ granted: true });
    pos = queue.findIndex((q) => q.id === id);
  }
  res.json({ granted: false, position: pos + 1, total: queue.length });
});

app.post('/queue/leave', (req, res) => {
  const id = req.cookies.qid;
  if (isActive(id)) {
    promoteNext();
  } else {
    const idx = queue.findIndex((q) => q.id === id);
    if (idx !== -1) queue.splice(idx, 1);
  }
  res.json({ ok: true });
});

app.get('/queue/waiting-room', (req, res) => {
  res.type('html').send(WAITING_ROOM_HTML);
});

// Gate every other request behind the queue.
app.use((req, res, next) => {
  const id = ensureSessionId(req, res);
  if (isActive(id)) return proxy.web(req, res);
  if (req.path.startsWith('/queue/')) return next();
  res.redirect('/queue/waiting-room');
});

// Terminates HTTPS itself (self-signed, same as Kasm's own cert did before
// gate sat in front of it) — browsers still get an https:// page, just with
// the same click-through warning as always.
const server = https.createServer(
  { cert: fs.readFileSync(TLS_CERT), key: fs.readFileSync(TLS_KEY) },
  app
);

server.on('upgrade', (req, socket, head) => {
  const cookies = Object.fromEntries(
    (req.headers.cookie || '')
      .split(';')
      .map((c) => c.trim().split('='))
      .filter((p) => p[0])
  );
  const id = cookies.qid;
  if (!isActive(id)) {
    socket.destroy();
    return;
  }
  active.wsConnected = true;
  socket.on('close', () => {
    if (isActive(id)) promoteNext();
  });
  proxy.ws(req, socket, head);
});

server.listen(PORT, () =>
  console.log(`Gate listening on :${PORT}, proxying to ${TARGET}`)
);

const WAITING_ROOM_HTML = `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Waiting for a slot</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body { font-family: system-ui, sans-serif; background: #0f1115; color: #eaeaea;
         display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
  .card { text-align: center; max-width: 420px; padding: 2rem; }
  h1 { font-size: 1.3rem; margin-bottom: 0.5rem; }
  .pos { font-size: 3rem; font-weight: 700; margin: 1rem 0; }
  .sub { color: #9aa0a6; font-size: 0.95rem; }
  .spinner { margin: 1.5rem auto; width: 28px; height: 28px; border: 3px solid #333;
             border-top-color: #6cf; border-radius: 50%; animation: spin 1s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
</head>
<body>
  <div class="card">
    <h1>Only one person can use the lab at a time</h1>
    <div class="pos" id="pos">&hellip;</div>
    <div class="sub" id="sub">Checking queue&hellip;</div>
    <div class="spinner"></div>
  </div>
<script>
async function poll() {
  try {
    const r = await fetch('/queue/status', { cache: 'no-store' });
    const data = await r.json();
    if (data.granted) {
      document.getElementById('pos').textContent = "You're up!";
      document.getElementById('sub').textContent = 'Connecting to the lab...';
      setTimeout(() => { window.location.href = '/'; }, 800);
      return;
    }
    document.getElementById('pos').textContent = '#' + data.position;
    document.getElementById('sub').textContent =
      data.total === 1 ? 'You are next in line.' : (data.total) + ' people waiting.';
  } catch (e) {
    document.getElementById('sub').textContent = 'Connection error, retrying...';
  }
  setTimeout(poll, 3000);
}
poll();
</script>
</body>
</html>`;
