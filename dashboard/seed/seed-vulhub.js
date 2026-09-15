#!/usr/bin/env node
// Seeds one `labs` row (kind='vulhub') + one `vulnerabilities` row per
// Vulhub recipe, so the dashboard's answer key covers every CVE the fleet
// can bring up via ./up.sh --vulhub / --vulhub-category / --vulhub-all —
// not just a hand-curated subset.
//
// Run from the VPS host, after `./vulhub.sh list` has cloned ./vulhub at
// least once (this script does not clone it itself — it only reads the
// existing checkout):
//
//   cd dashboard/seed
//   npm install
//   DB_HOST=127.0.0.1 DB_PORT=3010... (see README) node seed-vulhub.js [path-to-vulhub-clone]
//
// Safe to re-run: recipes are matched by slug and upserted, not duplicated.
'use strict';

const fs = require('fs');
const path = require('path');
const mysql = require('mysql2/promise');

const VULHUB_DIR = process.argv[2] || path.resolve(__dirname, '../../vulhub');

function slugify(target) {
  return target.toLowerCase().replace(/\//g, '-').replace(/[^a-z0-9-]/g, '-');
}

// category/CVE-xxxx-xxxxx -> CVE-xxxx-xxxxx (or null if the recipe folder
// doesn't follow the CVE-* naming convention — a handful of Vulhub recipes
// are named after the vuln instead, e.g. "docker/unauthorized-rce").
function extractCve(target) {
  const m = target.match(/CVE-\d{4}-\d{4,7}/i);
  return m ? m[0].toUpperCase() : null;
}

function findRecipes(dir) {
  const recipes = [];
  for (const category of fs.readdirSync(dir, { withFileTypes: true })) {
    if (!category.isDirectory() || category.name.startsWith('.')) continue;
    const categoryDir = path.join(dir, category.name);
    for (const recipe of fs.readdirSync(categoryDir, { withFileTypes: true })) {
      if (!recipe.isDirectory()) continue;
      const composePath = path.join(categoryDir, recipe.name, 'docker-compose.yml');
      if (fs.existsSync(composePath)) {
        recipes.push(`${category.name}/${recipe.name}`);
      }
    }
  }
  return recipes.sort();
}

// Pull the first non-empty paragraph out of the recipe's README as a rough
// exploit summary — best-effort only, Vulhub READMEs aren't structured data.
function readmeSummary(dir, target) {
  const readmePath = path.join(dir, target, 'README.md');
  if (!fs.existsSync(readmePath)) return null;
  const text = fs.readFileSync(readmePath, 'utf8');
  const paragraph = text
    .split(/\r?\n\r?\n/)
    .map((p) => p.trim())
    .find((p) => p && !p.startsWith('#') && !p.startsWith('!['));
  if (!paragraph) return null;
  return paragraph.replace(/\s+/g, ' ').slice(0, 2000);
}

async function main() {
  if (!fs.existsSync(VULHUB_DIR)) {
    console.error(`No Vulhub checkout at ${VULHUB_DIR}.`);
    console.error(`Run './vulhub.sh list' from the repo root first to clone it, or pass the path explicitly.`);
    process.exit(1);
  }

  const pool = await mysql.createPool({
    host: process.env.DB_HOST || '127.0.0.1',
    port: Number(process.env.DB_PORT || 3306),
    user: process.env.DB_USER || 'dashboard',
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME || 'vuln_dashboard',
  });

  const recipes = findRecipes(VULHUB_DIR);
  console.log(`Found ${recipes.length} Vulhub recipes under ${VULHUB_DIR}.`);

  let created = 0;
  let updated = 0;

  for (const target of recipes) {
    const slug = `vulhub-${slugify(target)}`;
    const category = target.split('/')[0];
    const cve = extractCve(target);
    const summary = readmeSummary(VULHUB_DIR, target);
    const referenceUrl = `https://github.com/vulhub/vulhub/tree/master/${target}`;
    const name = `Vulhub: ${target}`;

    const [existing] = await pool.query('SELECT id FROM labs WHERE slug = ?', [slug]);
    let labId;
    if (existing.length) {
      labId = existing[0].id;
      await pool.query(
        'UPDATE labs SET name=?, category=?, description=? WHERE id=?',
        [name, category, summary, labId]
      );
      updated++;
    } else {
      const [result] = await pool.query(
        'INSERT INTO labs (slug, name, kind, category, url_hint, description) VALUES (?, ?, "vulhub", ?, ?, ?)',
        [slug, name, category, `http://${slugify(target)}-<service> (batch mode) or by service name (single-recipe mode)`, summary]
      );
      labId = result.insertId;
      created++;
    }

    const [existingVuln] = await pool.query(
      'SELECT id FROM vulnerabilities WHERE lab_id = ? AND title = ?',
      [labId, name]
    );
    if (existingVuln.length) {
      await pool.query(
        'UPDATE vulnerabilities SET cve_id=?, category=?, exploit_notes=?, reference_url=? WHERE id=?',
        [cve, category, summary, referenceUrl, existingVuln[0].id]
      );
    } else {
      await pool.query(
        `INSERT INTO vulnerabilities
           (lab_id, cve_id, title, category, severity, description, exploit_notes, reference_url)
         VALUES (?, ?, ?, ?, 'high', ?, ?, ?)`,
        [labId, cve, name, category, summary, summary, referenceUrl]
      );
    }
  }

  console.log(`Done. ${created} new lab(s), ${updated} updated. ${recipes.length} vulnerability rows upserted.`);
  await pool.end();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
