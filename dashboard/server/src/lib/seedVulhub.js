'use strict';

// Reads every Vulhub recipe from the cloned repo, parses the README for
// CVE details, and upserts labs + vulnerabilities rows in the dashboard DB.
// Designed to be called from the dashboard's web UI, not just CLI.

const fs = require('fs');
const path = require('path');
const { pool } = require('../db');

const CVE_RE = /CVE-\d{4}-\d{4,7}/i;

// Known vuln-class keywords → severity mapping (heuristic)
const SEVERITY_KEYWORDS = {
  critical: ['remote code execution', 'rce', 'command injection', 'deserialization',
             'arbitrary file write', 'sql injection', 'code injection', 'unauthenticated'],
  high:     ['file inclusion', 'file read', 'ssrf', 'authentication bypass',
             'unauthorized access', 'privilege escalation', 'path traversal',
             'directory traversal', 'arbitrary file', 'xxe', 'xss'],
  medium:   ['information disclosure', 'information leak', 'csrf', 'open redirect',
             'denial of service', 'dos'],
  low:      ['clickjacking', 'verbose error'],
};

function guessSeverity(title, description) {
  const text = ((title || '') + ' ' + (description || '')).toLowerCase();
  for (const [sev, keywords] of Object.entries(SEVERITY_KEYWORDS)) {
    for (const kw of keywords) {
      if (text.includes(kw)) return sev;
    }
  }
  return 'high'; // default — most vulhub recipes are high+
}

function extractCve(name) {
  const m = name.match(CVE_RE);
  return m ? m[0].toUpperCase() : null;
}

function slugify(target) {
  return target.toLowerCase().replace(/\//g, '-').replace(/[^a-z0-9-]/g, '-');
}

function parseReadme(readmePath) {
  if (!fs.existsSync(readmePath)) return { title: null, description: null, references: [] };

  const text = fs.readFileSync(readmePath, 'utf8');
  const lines = text.split(/\r?\n/);

  // Title from first # heading
  const titleLine = lines.find((l) => l.startsWith('# '));
  const title = titleLine ? titleLine.replace(/^#+\s*/, '').trim() : null;

  // First non-empty, non-heading paragraph as description
  const paragraphs = text.split(/\r?\n\r?\n/)
    .map((p) => p.trim())
    .filter((p) => p && !p.startsWith('#') && !p.startsWith('![') && !p.startsWith('[中文'));

  const description = paragraphs.length
    ? paragraphs[0].replace(/\s+/g, ' ').slice(0, 2000)
    : null;

  // Extract reference URLs
  const references = [];
  const urlRe = /https?:\/\/[^\s)>\]"]+/g;
  let m;
  while ((m = urlRe.exec(text)) !== null) {
    const url = m[0].replace(/[.,;]+$/, '');
    if (!references.includes(url) && references.length < 10) {
      references.push(url);
    }
  }

  return { title, description, references };
}

function findRecipes(vulhubDir) {
  const recipes = [];
  for (const category of fs.readdirSync(vulhubDir, { withFileTypes: true })) {
    if (!category.isDirectory() || category.name.startsWith('.')) continue;
    const catDir = path.join(vulhubDir, category.name);
    for (const recipe of fs.readdirSync(catDir, { withFileTypes: true })) {
      if (!recipe.isDirectory()) continue;
      const composePath = path.join(catDir, recipe.name, 'docker-compose.yml');
      if (fs.existsSync(composePath)) {
        recipes.push({
          target: `${category.name}/${recipe.name}`,
          category: category.name,
          recipeName: recipe.name,
        });
      }
    }
  }
  return recipes.sort((a, b) => a.target.localeCompare(b.target));
}

async function seedVulhub(vulhubDir) {
  const recipes = findRecipes(vulhubDir);
  const stats = { total: recipes.length, created: 0, updated: 0, errors: 0 };

  for (const recipe of recipes) {
    try {
      const slug = `vulhub-${slugify(recipe.target)}`;
      const cve = extractCve(recipe.recipeName) || extractCve(recipe.target);
      const readmePath = path.join(vulhubDir, recipe.target, 'README.md');
      const { title: readmeTitle, description, references } = parseReadme(readmePath);

      // Use README title if available, else construct from target
      const displayTitle = readmeTitle || `Vulhub: ${recipe.target}`;
      const labName = `Vulhub: ${recipe.target}`;
      const referenceUrl = `https://github.com/vulhub/vulhub/tree/master/${recipe.target}`;
      const severity = guessSeverity(displayTitle, description);

      // Upsert lab
      const [existing] = await pool.query('SELECT id FROM labs WHERE slug = ?', [slug]);
      let labId;
      if (existing.length) {
        labId = existing[0].id;
        await pool.query(
          'UPDATE labs SET name=?, category=?, description=?, url_hint=? WHERE id=?',
          [labName, recipe.category, description, referenceUrl, labId]
        );
        stats.updated++;
      } else {
        const [result] = await pool.query(
          'INSERT INTO labs (slug, name, kind, category, url_hint, description) VALUES (?, ?, "vulhub", ?, ?, ?)',
          [slug, labName, recipe.category, referenceUrl, description]
        );
        labId = result.insertId;
        stats.created++;
      }

      // Upsert vulnerability (ground-truth: what a scanner should find)
      const vulnTitle = displayTitle || labName;
      const [existingVuln] = await pool.query(
        'SELECT id FROM vulnerabilities WHERE lab_id = ? AND title = ?',
        [labId, vulnTitle]
      );

      const refText = references.length
        ? references.map((r) => `- ${r}`).join('\n')
        : null;

      if (existingVuln.length) {
        await pool.query(
          `UPDATE vulnerabilities SET cve_id=?, category=?, severity=?,
           description=?, exploit_notes=?, reference_url=? WHERE id=?`,
          [cve, recipe.category, severity, description, refText, referenceUrl, existingVuln[0].id]
        );
      } else {
        await pool.query(
          `INSERT INTO vulnerabilities
             (lab_id, cve_id, title, category, severity, description, exploit_notes, reference_url)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
          [labId, cve, vulnTitle, recipe.category, severity, description, refText, referenceUrl]
        );
      }
    } catch (err) {
      console.error(`Error seeding ${recipe.target}:`, err.message);
      stats.errors++;
    }
  }

  return stats;
}

module.exports = { seedVulhub, findRecipes, parseReadme };
