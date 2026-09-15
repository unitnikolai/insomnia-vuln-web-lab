'use strict';

const express = require('express');
const { pool } = require('../db');

const router = express.Router();

// ---------- Scan picker page ----------
router.get('/compare', async (req, res, next) => {
  try {
    const [scans] = await pool.query(
      `SELECT s.id, s.filename, s.tool_name, s.uploaded_at, l.name AS lab_name,
              COUNT(sf.id) AS finding_count
       FROM scans s
       LEFT JOIN labs l ON l.id = s.lab_id
       LEFT JOIN scan_findings sf ON sf.scan_id = s.id
       GROUP BY s.id
       ORDER BY s.uploaded_at DESC`
    );

    const scanA = req.query.a ? Number(req.query.a) : null;
    const scanB = req.query.b ? Number(req.query.b) : null;

    if (!scanA || !scanB) {
      return res.render('compare_pick', { scans, a: scanA, b: scanB });
    }

    // ---------- Run comparison ----------
    const [[metaA]] = await pool.query(
      `SELECT s.*, l.name AS lab_name FROM scans s LEFT JOIN labs l ON l.id = s.lab_id WHERE s.id = ?`, [scanA]
    );
    const [[metaB]] = await pool.query(
      `SELECT s.*, l.name AS lab_name FROM scans s LEFT JOIN labs l ON l.id = s.lab_id WHERE s.id = ?`, [scanB]
    );

    if (!metaA || !metaB) {
      return res.status(404).render('error', { message: 'One of the selected scans does not exist.' });
    }

    const [findingsA] = await pool.query('SELECT * FROM scan_findings WHERE scan_id = ?', [scanA]);
    const [findingsB] = await pool.query('SELECT * FROM scan_findings WHERE scan_id = ?', [scanB]);

    const comparison = buildComparison(findingsA, findingsB);

    res.render('compare', {
      metaA, metaB,
      findingsA, findingsB,
      comparison,
    });
  } catch (err) {
    next(err);
  }
});

// ---------- Comparison logic ----------

function severityWeight(sev) {
  const s = (sev || '').toUpperCase();
  if (s === 'CRITICAL') return 5;
  if (s === 'HIGH') return 4;
  if (s === 'MEDIUM') return 3;
  if (s === 'LOW') return 2;
  if (s === 'INFO') return 1;
  return 0;
}

function buildComparison(fA, fB) {
  // -- Severity distribution --
  const sevBuckets = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  const sevA = {}, sevB = {};
  sevBuckets.forEach((b) => { sevA[b] = 0; sevB[b] = 0; });
  fA.forEach((f) => { const k = (f.severity || '').toUpperCase(); if (sevA[k] !== undefined) sevA[k]++; });
  fB.forEach((f) => { const k = (f.severity || '').toUpperCase(); if (sevB[k] !== undefined) sevB[k]++; });

  // -- OWASP category distribution --
  const owaspA = {}, owaspB = {};
  fA.forEach((f) => { if (f.owasp) owaspA[f.owasp] = (owaspA[f.owasp] || 0) + 1; });
  fB.forEach((f) => { if (f.owasp) owaspB[f.owasp] = (owaspB[f.owasp] || 0) + 1; });
  const owaspKeys = [...new Set([...Object.keys(owaspA), ...Object.keys(owaspB)])].sort();

  // -- CWE distribution --
  const cweA = {}, cweB = {};
  fA.forEach((f) => { if (f.cwe) cweA[f.cwe] = (cweA[f.cwe] || 0) + 1; });
  fB.forEach((f) => { if (f.cwe) cweB[f.cwe] = (cweB[f.cwe] || 0) + 1; });
  const cweKeys = [...new Set([...Object.keys(cweA), ...Object.keys(cweB)])].sort();

  // -- CVE overlap (Jaccard) --
  const cvesA = new Set(fA.filter((f) => f.cve_id).map((f) => f.cve_id));
  const cvesB = new Set(fB.filter((f) => f.cve_id).map((f) => f.cve_id));
  const cveIntersection = [...cvesA].filter((c) => cvesB.has(c));
  const cveUnion = new Set([...cvesA, ...cvesB]);
  const cveOnlyA = [...cvesA].filter((c) => !cvesB.has(c));
  const cveOnlyB = [...cvesB].filter((c) => !cvesA.has(c));

  // -- Average CVSS --
  const avgCvss = (findings) => {
    const vals = findings.filter((f) => f.cvss !== null && f.cvss !== undefined).map((f) => parseFloat(f.cvss));
    return vals.length ? (vals.reduce((a, b) => a + b, 0) / vals.length) : null;
  };

  // -- Average confidence --
  const avgConf = (findings) => {
    const vals = findings.filter((f) => f.confidence !== null && f.confidence !== undefined).map((f) => parseFloat(f.confidence));
    return vals.length ? (vals.reduce((a, b) => a + b, 0) / vals.length) : null;
  };

  // -- Weighted severity score --
  const weightedScore = (findings) => {
    return findings.reduce((sum, f) => sum + severityWeight(f.severity), 0);
  };

  // -- Unique targets --
  const targetsA = new Set(fA.filter((f) => f.target_url).map((f) => f.target_url));
  const targetsB = new Set(fB.filter((f) => f.target_url).map((f) => f.target_url));

  // -- Matched ground-truth counts --
  const matchedA = new Set(fA.filter((f) => f.matched_vulnerability_id).map((f) => f.matched_vulnerability_id)).size;
  const matchedB = new Set(fB.filter((f) => f.matched_vulnerability_id).map((f) => f.matched_vulnerability_id)).size;

  return {
    sevBuckets,
    sevA, sevB,
    owaspKeys, owaspA, owaspB,
    cweKeys, cweA, cweB,
    cveIntersection, cveOnlyA, cveOnlyB,
    cveJaccard: cveUnion.size ? (cveIntersection.length / cveUnion.size) : null,
    avgCvssA: avgCvss(fA),
    avgCvssB: avgCvss(fB),
    avgConfA: avgConf(fA),
    avgConfB: avgConf(fB),
    weightedA: weightedScore(fA),
    weightedB: weightedScore(fB),
    targetsA: targetsA.size,
    targetsB: targetsB.size,
    matchedA, matchedB,
  };
}

module.exports = router;
