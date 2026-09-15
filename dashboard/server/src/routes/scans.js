'use strict';

const express = require('express');
const { pool } = require('../db');

const router = express.Router();

router.get('/scans', async (req, res, next) => {
  try {
    const [scans] = await pool.query(
      `SELECT s.*, l.name AS lab_name, l.slug AS lab_slug,
              COUNT(sf.id) AS finding_count,
              SUM(CASE WHEN sf.matched_vulnerability_id IS NOT NULL THEN 1 ELSE 0 END) AS matched_count
       FROM scans s
       LEFT JOIN labs l ON l.id = s.lab_id
       LEFT JOIN scan_findings sf ON sf.scan_id = s.id
       GROUP BY s.id
       ORDER BY s.uploaded_at DESC`
    );
    res.render('scans', { scans });
  } catch (err) {
    next(err);
  }
});

router.get('/scans/:id', async (req, res, next) => {
  try {
    const [[scan]] = await pool.query(
      `SELECT s.*, l.name AS lab_name, l.slug AS lab_slug, l.id AS lab_id
       FROM scans s LEFT JOIN labs l ON l.id = s.lab_id
       WHERE s.id = ?`,
      [req.params.id]
    );
    if (!scan) return res.status(404).render('error', { message: 'No such scan.' });

    const [findings] = await pool.query(
      `SELECT sf.*, v.title AS matched_title, v.cve_id AS matched_cve
       FROM scan_findings sf
       LEFT JOIN vulnerabilities v ON v.id = sf.matched_vulnerability_id
       WHERE sf.scan_id = ?
       ORDER BY (sf.matched_vulnerability_id IS NULL), sf.severity`,
      [scan.id]
    );

    let coverage = null;
    if (scan.lab_id) {
      const [[{ total }]] = await pool.query(
        'SELECT COUNT(*) AS total FROM vulnerabilities WHERE lab_id = ?',
        [scan.lab_id]
      );
      const matchedIds = new Set(findings.filter((f) => f.matched_vulnerability_id).map((f) => f.matched_vulnerability_id));
      coverage = { total, matched: matchedIds.size };
    }

    res.render('scan_detail', { scan, findings, coverage });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
