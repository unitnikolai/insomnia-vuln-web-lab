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
const STATE_FILE = path.join(PROJECT_ROOT, '.vulhub-all-active');

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

// Get currently active vulhub recipes from state file
function getActiveRecipes() {
  if (!fs.existsSync(STATE_FILE)) return [];
  return fs.readFileSync(STATE_FILE, 'utf8').split('\n').filter(Boolean);
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
  { slug: '_attack-box', name: 'Attack Box (Kali)',  container: 'vb-attack-box', service: 'attack-box' },
  { slug: '_gate',       name: 'Access Gate',        container: 'vb-gate',       service: 'gate' },
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
