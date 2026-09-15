'use strict';

const express = require('express');
const { pool } = require('../db');
const docker = require('../lib/docker');

const router = express.Router();

router.get('/', async (req, res, next) => {
  try {
    const [labs] = await pool.query(
      `SELECT l.*,
              COUNT(v.id) AS vuln_count,
              SUM(CASE WHEN v.severity = 'critical' THEN 1 ELSE 0 END) AS critical_count,
              SUM(CASE WHEN v.severity = 'high' THEN 1 ELSE 0 END) AS high_count
       FROM labs l
       LEFT JOIN vulnerabilities v ON v.lab_id = l.id
       WHERE l.kind = 'builtin'
       GROUP BY l.id
       ORDER BY l.category, l.name`
    );
    const [[{ scanCount }]] = await pool.query('SELECT COUNT(*) AS scanCount FROM scans');

    // Try to get container status for each lab
    let containerStatus = {};
    try {
      const containers = await docker.listContainers();
      for (const c of containers) {
        containerStatus[c.slug] = c;
      }
    } catch {
      // Docker socket not available — just skip status
    }

    res.render('index', { labs, scanCount, containerStatus });
  } catch (err) {
    next(err);
  }
});

router.get('/labs/:slug', async (req, res, next) => {
  try {
    const [[lab]] = await pool.query('SELECT * FROM labs WHERE slug = ?', [req.params.slug]);
    if (!lab) return res.status(404).render('error', { message: 'No such lab.' });

    const [vulns] = await pool.query(
      'SELECT * FROM vulnerabilities WHERE lab_id = ? ORDER BY FIELD(severity,"critical","high","medium","low","info"), title',
      [lab.id]
    );

    const [matched] = await pool.query(
      `SELECT DISTINCT matched_vulnerability_id
       FROM scan_findings sf
       JOIN scans s ON s.id = sf.scan_id
       WHERE s.lab_id = ? AND matched_vulnerability_id IS NOT NULL`,
      [lab.id]
    );
    const matchedIds = new Set(matched.map((r) => r.matched_vulnerability_id));

    const [scans] = await pool.query(
      'SELECT id, filename, tool_name, uploaded_at FROM scans WHERE lab_id = ? ORDER BY uploaded_at DESC',
      [lab.id]
    );

    // Container status for this lab
    let container = null;
    try {
      const containerName = docker.SLUG_TO_CONTAINER[lab.slug];
      if (containerName) {
        container = await docker.getContainer(containerName);
      }
    } catch {
      // not found or docker unavailable
    }

    res.render('lab', { lab, vulns, matchedIds, scans, container });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
