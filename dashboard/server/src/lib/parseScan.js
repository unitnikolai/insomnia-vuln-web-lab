'use strict';

// Best-effort, tool-agnostic parse of an uploaded scan export into a flat
// list of normalized findings. Recognizes the Insomnia/Qustodian export
// shape (the primary format) plus a handful of common DAST tool shapes
// (bare array, wrapper keys, OWASP ZAP site/alerts nesting).

const CVE_RE = /CVE-\d{4}-\d{4,7}/i;
const ARRAY_KEYS = ['findings', 'vulnerabilities', 'results', 'issues', 'alerts', 'items', 'Vulnerabilities'];

function extractCveFromText(text) {
  if (!text) return null;
  const m = String(text).match(CVE_RE);
  return m ? m[0].toUpperCase() : null;
}

function firstDefined(...vals) {
  for (const v of vals) {
    if (v !== undefined && v !== null && v !== '') return v;
  }
  return undefined;
}

function normalizeSeverity(raw) {
  if (!raw) return 'unknown';
  const s = String(raw).toUpperCase().trim();
  if (s === 'CRITICAL') return 'CRITICAL';
  if (s === 'HIGH') return 'HIGH';
  if (s === 'MEDIUM') return 'MEDIUM';
  if (s === 'LOW') return 'LOW';
  if (s === 'INFO' || s === 'INFORMATIONAL') return 'INFO';
  return String(raw).slice(0, 64);
}

function normalizeFinding(item) {
  if (!item || typeof item !== 'object') return null;

  const title = firstDefined(item.title, item.name, item.alert, item.pluginName, item.rule, item.check, 'Untitled finding');
  const cveRaw = firstDefined(item.cve, item.cve_id, item.CVE, item.cveId, item.cveID);
  const cve = (cveRaw ? String(cveRaw).match(CVE_RE) : null)
    ? String(cveRaw).match(CVE_RE)[0].toUpperCase()
    : extractCveFromText(title) || extractCveFromText(item.description);

  const severity = normalizeSeverity(firstDefined(item.severity, item.risk, item.riskdesc, item.level, item.riskDesc));

  // Numeric fields — coerce but don't crash
  const cvssRaw = firstDefined(item.cvss, item.cvss_score, item.score);
  const cvss = cvssRaw !== undefined ? parseFloat(cvssRaw) : null;

  const confRaw = firstDefined(item.confidence);
  const confidence = confRaw !== undefined ? parseFloat(confRaw) : null;

  return {
    cve_id:     cve || null,
    title:      String(title).slice(0, 500),
    severity,
    cvss:       (cvss !== null && !isNaN(cvss)) ? cvss : null,
    confidence: (confidence !== null && !isNaN(confidence)) ? confidence : null,
    cwe:        firstDefined(item.cwe) || null,
    cwe_name:   firstDefined(item.cwe_name) || null,
    owasp:      firstDefined(item.owasp) || null,
    owasp_name: firstDefined(item.owasp_name) || null,
    module:     firstDefined(item.module) || null,
    target_url: firstDefined(item.url, item.target) || null,
    method:     firstDefined(item.method) || null,
    status:     firstDefined(item.status) || null,
    finding_id: firstDefined(item.finding_id) || null,
    raw: item,
  };
}

function findFindingsArray(json) {
  if (Array.isArray(json)) return json;
  if (!json || typeof json !== 'object') return [];

  for (const key of ARRAY_KEYS) {
    if (Array.isArray(json[key]) && json[key].length) return json[key];
  }

  // OWASP ZAP report shape: { site: [ { alerts: [...] }, ... ] }
  if (Array.isArray(json.site)) {
    const alerts = [];
    for (const site of json.site) {
      if (Array.isArray(site.alerts)) alerts.push(...site.alerts);
    }
    if (alerts.length) return alerts;
  }

  for (const key of ARRAY_KEYS) {
    if (Array.isArray(json[key])) return json[key];
  }
  return [];
}

function parseScan(json) {
  const arr = findFindingsArray(json);
  return arr.map(normalizeFinding).filter(Boolean);
}

module.exports = { parseScan, extractCveFromText };
