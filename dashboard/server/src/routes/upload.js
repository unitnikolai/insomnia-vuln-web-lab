'use strict';

const express = require('express');
const multer = require('multer');
const { pool } = require('../db');
const { parseScan } = require('../lib/parseScan');
const { matchFinding } = require('../lib/matchFindings');

const router = express.Router();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 25 * 1024 * 1024 }, // 25MB — generous for a JSON scan export
});

router.get('/upload', async (req, res, next) => {
  try {
    const [labs] = await pool.query('SELECT id, slug, name, kind FROM labs ORDER BY kind, name');
    res.render('upload', { labs, error: null });
  } catch (err) {
    next(err);
  }
});

router.post('/upload', upload.single('scanFile'), async (req, res, next) => {
  try {
    const [labs] = await pool.query('SELECT id, slug, name, kind FROM labs ORDER BY kind, name');

    if (!req.file) {
      return res.status(400).render('upload', { labs, error: 'Choose a JSON file to upload.' });
    }

    let json;
    try {
      json = JSON.parse(req.file.buffer.toString('utf8'));
    } catch (err) {
      return res.status(400).render('upload', { labs, error: `Not valid JSON: ${err.message}` });
    }

    const labId = req.body.lab_id ? Number(req.body.lab_id) : null;
    const toolName = (req.body.tool_name || '').trim() || null;
    const notes = (req.body.notes || '').trim() || null;

    const [result] = await pool.query(
      `INSERT INTO scans (lab_id, filename, tool_name, uploaded_by, notes, raw_json)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [labId, req.file.originalname, toolName, req.body.uploaded_by || null, notes, JSON.stringify(json)]
    );
    const scanId = result.insertId;

    const findings = parseScan(json);

    let candidateVulns = [];
    if (labId) {
      const [rows] = await pool.query('SELECT * FROM vulnerabilities WHERE lab_id = ?', [labId]);
      candidateVulns = rows;
    } else {
      const [rows] = await pool.query('SELECT * FROM vulnerabilities');
      candidateVulns = rows;
    }

    for (const finding of findings) {
      const match = matchFinding(finding, candidateVulns);
      await pool.query(
        `INSERT INTO scan_findings
           (scan_id, cve_id, title, severity, cvss, confidence, cwe, cwe_name,
            owasp, owasp_name, module, target_url, method, status, finding_id,
            matched_vulnerability_id, raw_snippet)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          scanId,
          finding.cve_id,
          finding.title,
          finding.severity,
          finding.cvss,
          finding.confidence,
          finding.cwe,
          finding.cwe_name,
          finding.owasp,
          finding.owasp_name,
          finding.module,
          finding.target_url,
          finding.method,
          finding.status,
          finding.finding_id,
          match ? match.id : null,
          JSON.stringify(finding.raw),
        ]
      );
    }

    res.redirect(`/scans/${scanId}`);
  } catch (err) {
    next(err);
  }
});

module.exports = router;
