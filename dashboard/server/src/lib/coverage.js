'use strict';

// CVE coverage: for every Vulhub recipe, the CVE it's *supposed* to yield
// (the answer key seeded from its README) versus whether an uploaded scan
// has actually turned that CVE up yet.
//
// Evidence comes in two independent dimensions, both carried through rather
// than flattened into one checkmark.
//
// HOW the finding relates to this recipe's answer-key row (`via`):
//
//   'matched' — the finding was linked to this exact ground-truth row by
//               lib/matchFindings (CVE id, or a loose title match).
//   'cve'     — the finding carries this recipe's CVE but was linked to some
//               other row. That happens when recipes share a CVE: struts2's
//               s2-045 and s2-046 are both CVE-2017-5638, and the matcher
//               links a finding to only one of them.
//
// WHETHER the scan was actually aimed at this recipe (`attributed`): true
// when an uploaded scan carrying the evidence had this lab selected. Note
// that routes/upload.js matches against *every* ground-truth row when no lab
// is picked, so `via: 'matched'` alone says nothing about aim — which is why
// attribution is tracked separately instead of being inferred from it.
//
// The UI ticks a recipe green only when the evidence came from a scan aimed
// at it, and amber when the CVE turned up but not from a scan of this
// recipe — still worth knowing, just a weaker claim about this deployment.

const { pool } = require('../db');

// Mirrors seedVulhub.js's slugify, which decides the lab slug a recipe is
// stored under. Recipe target -> lab slug is one-way (case and separators are
// flattened), so callers holding targets build a slug->target map with this
// rather than trying to invert it.
function labSlugFor(target) {
  return 'vulhub-' + target.toLowerCase().replace(/\//g, '-').replace(/[^a-z0-9-]/g, '-');
}

async function getCveCoverage() {
  // The answer key: one row per Vulhub recipe's ground-truth vulnerability.
  const [truth] = await pool.query(
    `SELECT l.id   AS lab_id,
            l.slug AS lab_slug,
            l.name AS lab_name,
            l.category,
            v.id   AS vuln_id,
            v.cve_id,
            v.cve_source,
            v.title,
            v.severity
       FROM labs l
       JOIN vulnerabilities v ON v.lab_id = l.id
      WHERE l.kind = 'vulhub'
      ORDER BY l.category, l.name`
  );

  // Every finding that could possibly satisfy one of those, in one pass —
  // cheaper than a correlated subquery per recipe once there are a few
  // hundred recipes on the page.
  const [hits] = await pool.query(
    `SELECT sf.matched_vulnerability_id AS vuln_id,
            sf.cve_id,
            sf.scan_id,
            sf.severity,
            s.tool_name,
            s.uploaded_at,
            s.lab_id AS scan_lab_id
       FROM scan_findings sf
       JOIN scans s ON s.id = sf.scan_id
      WHERE sf.matched_vulnerability_id IS NOT NULL
         OR sf.cve_id IS NOT NULL
      ORDER BY s.uploaded_at ASC`
  );

  const byVulnId = new Map();   // ground-truth row id -> hits attributed to it
  const byCve = new Map();      // CVE id -> hits carrying it
  for (const h of hits) {
    if (h.vuln_id) {
      if (!byVulnId.has(h.vuln_id)) byVulnId.set(h.vuln_id, []);
      byVulnId.get(h.vuln_id).push(h);
    }
    if (h.cve_id) {
      const key = h.cve_id.toUpperCase();
      if (!byCve.has(key)) byCve.set(key, []);
      byCve.get(key).push(h);
    }
  }

  const recipes = truth.map((t) => {
    const cve = t.cve_id ? t.cve_id.toUpperCase() : null;
    const matchedHits = byVulnId.get(t.vuln_id) || [];
    const cveHits = cve ? (byCve.get(cve) || []) : [];

    // Prefer the attributed hits when describing how it was found.
    const evidence = matchedHits.length ? matchedHits : cveHits;
    const via = matchedHits.length ? 'matched' : (cveHits.length ? 'cve' : null);

    const scans = [];
    const seenScan = new Set();
    let attributed = false;
    for (const h of evidence) {
      // Was this particular scan run against this lab?
      const aimedHere = h.scan_lab_id === t.lab_id;
      if (aimedHere) attributed = true;
      if (seenScan.has(h.scan_id)) continue;
      seenScan.add(h.scan_id);
      scans.push({ id: h.scan_id, tool: h.tool_name, uploaded_at: h.uploaded_at, attributed: aimedHere });
    }

    return {
      labId: t.lab_id,
      slug: t.lab_slug,
      name: t.lab_name,
      category: t.category || 'uncategorized',
      vulnId: t.vuln_id,
      title: t.title,
      severity: t.severity,
      cve,
      // 'dirname' | 'readme-title' | 'readme-body' | null — see seedVulhub.js.
      // Anything but 'dirname'/'readme-title' is an inference worth flagging.
      cveSource: t.cve_source || null,
      inferred: t.cve_source === 'readme-body',
      // A recipe with no CVE at all can never be checked off by CVE matching;
      // it's excluded from the percentages rather than counted as a failure.
      expected: !!cve,
      found: evidence.length > 0,
      via,
      // Confirmed by a scan actually aimed at this recipe — the strong claim.
      attributed,
      hitCount: evidence.length,
      scans,
      lastSeen: scans.length ? scans[scans.length - 1].uploaded_at : null,
    };
  });

  return { recipes, ...summarize(recipes) };
}

// Percentages are over recipes that actually have a CVE to find. Counting the
// 68 recipes whose README names no CVE as permanent misses would peg the bar
// below 80% forever and make it useless as a progress signal, so they're
// reported separately as "untrackable" instead.
function summarize(recipes) {
  const bySlug = new Map(recipes.map((r) => [r.slug, r]));

  const catMap = new Map();
  for (const r of recipes) {
    if (!catMap.has(r.category)) {
      catMap.set(r.category, {
        category: r.category, total: 0, withCve: 0, validated: 0, attributed: 0, unattributed: 0, untrackable: 0,
      });
    }
    const c = catMap.get(r.category);
    c.total += 1;
    if (!r.expected) { c.untrackable += 1; continue; }
    c.withCve += 1;
    if (r.found) {
      c.validated += 1;
      if (r.attributed) c.attributed += 1; else c.unattributed += 1;
    }
  }
  const categories = [...catMap.values()].map((c) => ({ ...c, pct: pct(c.validated, c.withCve) }));
  categories.sort((a, b) => b.total - a.total || a.category.localeCompare(b.category));

  const totals = categories.reduce((acc, c) => ({
    total: acc.total + c.total,
    withCve: acc.withCve + c.withCve,
    validated: acc.validated + c.validated,
    attributed: acc.attributed + c.attributed,
    unattributed: acc.unattributed + c.unattributed,
    untrackable: acc.untrackable + c.untrackable,
  }), { total: 0, withCve: 0, validated: 0, attributed: 0, unattributed: 0, untrackable: 0 });
  totals.pct = pct(totals.validated, totals.withCve);

  return {
    bySlug,
    byCategory: new Map(categories.map((c) => [c.category, c])),
    categories,
    totals,
  };
}

function pct(n, d) {
  if (!d) return 0;
  return Math.round((100 * n) / d);
}

module.exports = { getCveCoverage, labSlugFor };
