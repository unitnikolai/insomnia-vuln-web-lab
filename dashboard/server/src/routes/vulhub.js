'use strict';

const express = require('express');
const { pool } = require('../db');

const router = express.Router();

// ---------- Vulhub metrics dashboard ----------
router.get('/vulhub', async (req, res, next) => {
  try {
    // -- Vulhub ground-truth labs (if seeded) --
    const [vulhubLabs] = await pool.query(
      `SELECT l.*, COUNT(v.id) AS vuln_count
       FROM labs l
       LEFT JOIN vulnerabilities v ON v.lab_id = l.id
       WHERE l.kind = 'vulhub'
       GROUP BY l.id
       ORDER BY l.category, l.name`
    );

    // -- All scans with findings --
    const [scans] = await pool.query(
      `SELECT s.id, s.filename, s.tool_name, s.uploaded_at, s.lab_id,
              l.name AS lab_name, l.kind AS lab_kind
       FROM scans s
       LEFT JOIN labs l ON l.id = s.lab_id
       ORDER BY s.uploaded_at DESC`
    );

    // -- Pull every finding with a CVE from all scans --
    const [allCveFindings] = await pool.query(
      `SELECT sf.scan_id, sf.cve_id, sf.severity, sf.cvss, sf.confidence,
              sf.cwe, sf.cwe_name, sf.owasp, sf.owasp_name, sf.module,
              sf.target_url, sf.matched_vulnerability_id,
              s.tool_name, s.filename
       FROM scan_findings sf
       JOIN scans s ON s.id = sf.scan_id
       WHERE sf.cve_id IS NOT NULL
       ORDER BY sf.cve_id`
    );

    // -- Vulhub ground-truth vulnerabilities (if any) --
    const [vulhubVulns] = await pool.query(
      `SELECT v.*, l.slug AS lab_slug, l.name AS lab_name, l.category AS lab_category
       FROM vulnerabilities v
       JOIN labs l ON l.id = v.lab_id AND l.kind = 'vulhub'
       ORDER BY l.category, v.cve_id`
    );

    // -- Build per-CVE aggregate stats --
    const cveMap = {};
    for (const f of allCveFindings) {
      if (!cveMap[f.cve_id]) {
        cveMap[f.cve_id] = {
          cve_id: f.cve_id,
          severity: f.severity,
          cvss: f.cvss,
          cwe: f.cwe,
          cwe_name: f.cwe_name,
          owasp: f.owasp,
          owasp_name: f.owasp_name,
          scanners: new Set(),
          scan_ids: new Set(),
          targets: new Set(),
          avg_confidence: [],
          matched: false,
        };
      }
      const entry = cveMap[f.cve_id];
      if (f.tool_name) entry.scanners.add(f.tool_name);
      entry.scan_ids.add(f.scan_id);
      if (f.target_url) entry.targets.add(f.target_url);
      if (f.confidence !== null) entry.avg_confidence.push(parseFloat(f.confidence));
      if (f.matched_vulnerability_id) entry.matched = true;
      // Keep highest severity
      if (sevWeight(f.severity) > sevWeight(entry.severity)) {
        entry.severity = f.severity;
      }
      if (f.cvss !== null && (entry.cvss === null || parseFloat(f.cvss) > parseFloat(entry.cvss))) {
        entry.cvss = f.cvss;
      }
    }

    const cveList = Object.values(cveMap).map((c) => ({
      ...c,
      scanners: [...c.scanners],
      scan_count: c.scan_ids.size,
      target_count: c.targets.size,
      targets: [...c.targets],
      avg_confidence: c.avg_confidence.length
        ? c.avg_confidence.reduce((a, b) => a + b, 0) / c.avg_confidence.length
        : null,
    }));
    cveList.sort((a, b) => sevWeight(b.severity) - sevWeight(a.severity) || (b.cvss || 0) - (a.cvss || 0));

    // -- Per-scan CVE detection summary --
    const scanCveMap = {};
    for (const f of allCveFindings) {
      if (!scanCveMap[f.scan_id]) scanCveMap[f.scan_id] = new Set();
      scanCveMap[f.scan_id].add(f.cve_id);
    }
    const scanSummaries = scans.map((s) => ({
      ...s,
      unique_cves: scanCveMap[s.id] ? scanCveMap[s.id].size : 0,
      cves: scanCveMap[s.id] ? [...scanCveMap[s.id]] : [],
    }));

    // -- Severity distribution across all CVEs --
    const sevDist = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    cveList.forEach((c) => {
      const k = (c.severity || '').toUpperCase();
      if (sevDist[k] !== undefined) sevDist[k]++;
    });

    // -- CWE frequency --
    const cweFreq = {};
    cveList.forEach((c) => {
      if (c.cwe) {
        const key = c.cwe_name ? `${c.cwe}: ${c.cwe_name}` : c.cwe;
        cweFreq[key] = (cweFreq[key] || 0) + 1;
      }
    });
    const cweRanked = Object.entries(cweFreq).sort((a, b) => b[1] - a[1]);

    // -- OWASP frequency --
    const owaspFreq = {};
    cveList.forEach((c) => {
      if (c.owasp) {
        const key = c.owasp_name ? `${c.owasp}: ${c.owasp_name}` : c.owasp;
        owaspFreq[key] = (owaspFreq[key] || 0) + 1;
      }
    });
    const owaspRanked = Object.entries(owaspFreq).sort((a, b) => b[1] - a[1]);

    // -- Vulhub ground-truth coverage (if seeded) --
    let vulhubCoverage = null;
    if (vulhubVulns.length) {
      const coveredCves = new Set(vulhubVulns.filter((v) => v.cve_id && cveMap[v.cve_id]).map((v) => v.cve_id));
      const totalWithCve = vulhubVulns.filter((v) => v.cve_id).length;

      // Per-category breakdown
      const catMap = {};
      for (const v of vulhubVulns) {
        const cat = v.lab_category || 'uncategorized';
        if (!catMap[cat]) catMap[cat] = { total: 0, covered: 0 };
        catMap[cat].total++;
        if (v.cve_id && coveredCves.has(v.cve_id)) catMap[cat].covered++;
      }

      vulhubCoverage = {
        totalRecipes: vulhubLabs.length,
        totalVulns: vulhubVulns.length,
        totalWithCve,
        coveredCves: coveredCves.size,
        categories: Object.entries(catMap)
          .map(([cat, data]) => ({ category: cat, ...data, pct: Math.round(100 * data.covered / Math.max(data.total, 1)) }))
          .sort((a, b) => b.total - a.total),
        uncoveredCves: vulhubVulns
          .filter((v) => v.cve_id && !coveredCves.has(v.cve_id))
          .map((v) => ({ cve_id: v.cve_id, lab_name: v.lab_name, lab_category: v.lab_category })),
      };
    }

    // -- Scanner cross-reference: which scanner found which CVE --
    const allScanners = [...new Set(allCveFindings.filter((f) => f.tool_name).map((f) => f.tool_name))];
    const scannerCveMatrix = {};
    for (const scanner of allScanners) {
      scannerCveMatrix[scanner] = new Set(
        allCveFindings.filter((f) => f.tool_name === scanner).map((f) => f.cve_id)
      );
    }

    res.render('vulhub', {
      vulhubLabs,
      vulhubVulns,
      vulhubCoverage,
      cveList,
      scanSummaries,
      sevDist,
      cweRanked,
      owaspRanked,
      allScanners,
      scannerCveMatrix,
      scans,
    });
  } catch (err) {
    next(err);
  }
});

function sevWeight(sev) {
  const s = (sev || '').toUpperCase();
  if (s === 'CRITICAL') return 5;
  if (s === 'HIGH') return 4;
  if (s === 'MEDIUM') return 3;
  if (s === 'LOW') return 2;
  if (s === 'INFO') return 1;
  return 0;
}

module.exports = router;
