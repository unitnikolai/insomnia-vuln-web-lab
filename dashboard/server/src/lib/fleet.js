'use strict';

// Wraps vulhub.sh to manage Vulhub recipe containers from the dashboard.
// Also manages the builtin fleet containers via docker compose.

const { execFile } = require('child_process');
const path = require('path');
const fs = require('fs');

const PROJECT_ROOT = process.env.PROJECT_ROOT || '/project';
const VULHUB_SH = path.join(PROJECT_ROOT, 'vulhub.sh');
const COMPOSE_FILE = path.join(PROJECT_ROOT, 'docker-compose.yml');
const VULHUB_DIR = path.join(PROJECT_ROOT, 'vulhub');
// vulhub.sh tracks single-recipe `up` in .vulhub-active (one line, the most
// recent recipe) and batch up-category/up-all in .vulhub-all-active (one line
// per recipe). Both have to be read, or a recipe deployed with the per-recipe
// Deploy button looks inactive on the page that deployed it.
const STATE_FILE = path.join(PROJECT_ROOT, '.vulhub-all-active');
const SINGLE_STATE_FILE = path.join(PROJECT_ROOT, '.vulhub-active');

// Expose for seeder
function getVulhubDir() { return VULHUB_DIR; }

function exec(cmd, args, opts = {}) {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, {
      cwd: PROJECT_ROOT,
      timeout: opts.timeout || 120000,
      maxBuffer: 10 * 1024 * 1024,
      env: { ...process.env, PATH: process.env.PATH + ':/usr/local/bin:/usr/bin:/bin' },
      ...opts,
    }, (err, stdout, stderr) => {
      if (err && !opts.ignoreError) {
        err.stdout = stdout;
        err.stderr = stderr;
        return reject(err);
      }
      resolve({ stdout: stdout || '', stderr: stderr || '', code: err ? err.code : 0 });
    });
  });
}

// Check if vulhub is cloned
function isVulhubCloned() {
  return fs.existsSync(VULHUB_DIR) && fs.existsSync(path.join(VULHUB_DIR, '.git'));
}

// Clone vulhub repo
async function cloneVulhub() {
  await exec('git', ['clone', '--depth', '1', 'https://github.com/vulhub/vulhub.git', VULHUB_DIR], {
    timeout: 300000,
  });
}

// List all available vulhub categories with recipe counts
async function listCategories() {
  if (!isVulhubCloned()) return [];

  const categories = {};
  const entries = fs.readdirSync(VULHUB_DIR, { withFileTypes: true });
  for (const entry of entries) {
    if (!entry.isDirectory() || entry.name.startsWith('.')) continue;
    const catDir = path.join(VULHUB_DIR, entry.name);
    const recipes = fs.readdirSync(catDir, { withFileTypes: true })
      .filter((r) => r.isDirectory() && fs.existsSync(path.join(catDir, r.name, 'docker-compose.yml')));
    if (recipes.length > 0) {
      categories[entry.name] = {
        name: entry.name,
        count: recipes.length,
        recipes: recipes.map((r) => `${entry.name}/${r.name}`).sort(),
      };
    }
  }
  return Object.values(categories).sort((a, b) => b.count - a.count);
}

// List all vulhub recipes
async function listRecipes(categoryFilter) {
  if (!isVulhubCloned()) return [];

  const recipes = [];
  const entries = fs.readdirSync(VULHUB_DIR, { withFileTypes: true });
  for (const entry of entries) {
    if (!entry.isDirectory() || entry.name.startsWith('.')) continue;
    if (categoryFilter && entry.name !== categoryFilter) continue;
    const catDir = path.join(VULHUB_DIR, entry.name);
    const subs = fs.readdirSync(catDir, { withFileTypes: true });
    for (const sub of subs) {
      if (!sub.isDirectory()) continue;
      if (fs.existsSync(path.join(catDir, sub.name, 'docker-compose.yml'))) {
        recipes.push({
          target: `${entry.name}/${sub.name}`,
          category: entry.name,
          name: sub.name,
          cve: extractCve(sub.name),
        });
      }
    }
  }
  return recipes.sort((a, b) => a.target.localeCompare(b.target));
}

function extractCve(name) {
  const m = name.match(/CVE-\d{4}-\d{4,7}/i);
  return m ? m[0].toUpperCase() : null;
}

// Get currently active vulhub recipes from both state files
function getActiveRecipes() {
  const targets = new Set();
  for (const file of [STATE_FILE, SINGLE_STATE_FILE]) {
    if (!fs.existsSync(file)) continue;
    for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
      const target = line.trim();
      if (target) targets.add(target);
    }
  }
  return [...targets].sort();
}

// Mirrors vulhub.sh's slugify(): category/CVE-xxxx-xxxxx -> category-cve-xxxx-xxxxx.
// That slug is the recipe's private network name (vulhub-<slug>) and the prefix
// of each service's unique alias, so it's how a batch-deployed container is
// traced back to its recipe when the compose labels aren't enough.
function slugify(target) {
  return target.toLowerCase().replace(/\//g, '-').replace(/[^a-z0-9-]/g, '-');
}

// A compose container carries the directory its compose file was run from.
// If that directory is <vulhub>/<category>/<recipe>, this is one of ours.
function recipeFromWorkingDir(workingDir) {
  if (!workingDir) return null;
  const rel = path.relative(VULHUB_DIR, workingDir);
  if (!rel || rel.startsWith('..') || path.isAbsolute(rel)) return null;
  const parts = rel.split(path.sep);
  if (parts.length !== 2) return null;
  return parts.join('/');
}

// Group live containers under the Vulhub recipe that owns them. Takes the
// container list from docker.listContainers({ includeAll: true }) so the
// caller only pays for one Docker round-trip per page render.
async function getRecipeFleet(containers) {
  // Reverse slug map, for containers whose working_dir label is missing or
  // points at a path that doesn't line up (e.g. the recipe was brought up from
  // the host shell rather than from this container). Built on first use only —
  // it's a walk of all ~330 recipe directories, and the label resolves every
  // container the dashboard itself deployed.
  let targetBySlug = null;
  const resolveSlug = async (slug) => {
    if (!targetBySlug) {
      targetBySlug = new Map();
      for (const r of await listRecipes()) targetBySlug.set(slugify(r.target), r.target);
    }
    return targetBySlug.get(slug) || null;
  };

  const recipes = new Map();
  for (const c of containers) {
    let target = recipeFromWorkingDir(c.compose && c.compose.workingDir);
    if (!target) {
      const own = (c.networks || []).find((n) => n.network.startsWith('vulhub-'));
      if (own) target = await resolveSlug(own.network.slice('vulhub-'.length));
    }
    if (!target) continue;

    if (!recipes.has(target)) {
      const [category, name] = target.split('/');
      recipes.set(target, {
        target, category, name,
        slug: slugify(target),
        cve: extractCve(name),
        containers: [],
        running: 0,
      });
    }
    const recipe = recipes.get(target);
    recipe.containers.push({ ...c, service: (c.compose && c.compose.service) || c.name });
    if (c.state === 'running') recipe.running += 1;
  }

  const list = [...recipes.values()];
  for (const r of list) {
    r.containers.sort((a, b) => a.name.localeCompare(b.name));
    r.total = r.containers.length;
    r.state = r.running === 0 ? 'exited' : (r.running === r.total ? 'running' : 'partial');

    // Which isolation model brought this recipe up decides how you address it,
    // and that's a property of the recipe, not of one container — so decide it
    // once from the whole group. Otherwise a stopped service (whose network
    // attachment may already be gone) would advertise its bare compose name
    // while its running siblings advertise the unique alias.
    const ownNet = `vulhub-${r.slug}`;
    r.isolated = r.containers.some((c) => (c.networks || []).some((n) => n.network === ownNet));

    for (const c of r.containers) {
      // Batch mode strips host ports and puts the recipe on its own network, so
      // the only route in is the globally-unique alias, used from the attack
      // box. Single-recipe mode joins the shared vulnbench and rebinds the
      // published ports to 127.0.0.1, so the plain service name works there and
      // the host side is reachable too.
      const net = (c.networks || []).find((n) => n.network === ownNet);
      c.host = r.isolated
        ? ((net && net.aliases.find((a) => a.startsWith(`${r.slug}-`))) || `${r.slug}-${c.service}`)
        : c.service;
      c.network = net ? net.network : ((c.networks[0] && c.networks[0].network) || null);
      c.endpoints = buildEndpoints(c.host, c);
    }
  }
  return list.sort((a, b) => a.target.localeCompare(b.target));
}

// "<host>:<port>" for every TCP port the container exposes, plus the loopback
// binding when a host port was published. `host` is whatever name actually
// resolves to it on a user-defined network — a recipe's unique alias, or just
// the container name for anything else.
function buildEndpoints(host, c) {
  const endpoints = [];
  for (const p of c.ports || []) {
    if (p.type && p.type !== 'tcp') continue;
    endpoints.push({ addr: `${host}:${p.private}`, published: null });
    if (p.public) {
      const bindIp = p.ip && p.ip !== '0.0.0.0' && p.ip !== '::' ? p.ip : '127.0.0.1';
      endpoints[endpoints.length - 1].published = `${bindIp}:${p.public}`;
    }
  }
  return endpoints;
}

// Bring up a single vulhub recipe
async function upRecipe(target) {
  const result = await exec('bash', [VULHUB_SH, 'up', target], {
    timeout: 180000,
    ignoreError: true,
  });
  return result;
}

// Bring up a category
async function upCategory(category) {
  const result = await exec('bash', [VULHUB_SH, 'up-category', category, '--yes'], {
    timeout: 600000,
    ignoreError: true,
  });
  return result;
}

// Tear down a single recipe
async function downRecipe(target) {
  const result = await exec('bash', [VULHUB_SH, 'down', target], {
    timeout: 60000,
    ignoreError: true,
  });
  return result;
}

// Tear down a category
async function downCategory(category) {
  const result = await exec('bash', [VULHUB_SH, 'down-category', category], {
    timeout: 120000,
    ignoreError: true,
  });
  return result;
}

// Tear down all vulhub recipes
async function downAll() {
  const result = await exec('bash', [VULHUB_SH, 'down-all'], {
    timeout: 300000,
    ignoreError: true,
  });
  return result;
}

// Builtin services from docker-compose.yml
const BUILTIN_SERVICES = [
  { slug: 'juice-shop',  name: 'OWASP Juice Shop',        container: 'vb-juice-shop', service: 'juice-shop' },
  { slug: 'dvwa',        name: 'Damn Vulnerable Web App',  container: 'vb-dvwa',       service: 'dvwa' },
  { slug: 'mutillidae',  name: 'OWASP Mutillidae II',      container: 'vb-mutillidae', service: 'mutillidae' },
  { slug: 'vampi',       name: 'VAmPI',                    container: 'vb-vampi',      service: 'vampi' },
  { slug: 'dvga',        name: 'Damn Vuln GraphQL App',    container: 'vb-dvga',       service: 'dvga' },
  { slug: 'webgoat',     name: 'WebGoat + WebWolf',        container: 'vb-webgoat',    service: 'webgoat' },
];

const INFRA_SERVICES = [
  { slug: '_attack-box',   name: 'Attack Box (Kali)',    container: 'vb-attack-box',   service: 'attack-box' },
  { slug: '_gate',         name: 'Access Gate',          container: 'vb-gate',         service: 'gate' },
  { slug: '_dashboard',    name: 'Benchmark Dashboard',  container: 'vb-dashboard',    service: 'dashboard' },
  { slug: '_dashboard-db', name: 'Dashboard DB',         container: 'vb-dashboard-db', service: 'dashboard-db' },
];

// Start a builtin service via docker compose
async function startBuiltin(service) {
  return exec('docker', ['compose', '-f', COMPOSE_FILE, 'up', '-d', '--no-deps', service], {
    timeout: 120000,
    ignoreError: true,
  });
}

// Stop a builtin service
async function stopBuiltin(service) {
  return exec('docker', ['compose', '-f', COMPOSE_FILE, 'stop', service], {
    timeout: 30000,
    ignoreError: true,
  });
}

module.exports = {
  isVulhubCloned,
  getRecipeFleet,
  buildEndpoints,
  slugify,
  cloneVulhub,
  listCategories,
  listRecipes,
  getActiveRecipes,
  upRecipe,
  upCategory,
  downRecipe,
  downCategory,
  downAll,
  startBuiltin,
  stopBuiltin,
  getVulhubDir,
  BUILTIN_SERVICES,
  INFRA_SERVICES,
  PROJECT_ROOT,
};
