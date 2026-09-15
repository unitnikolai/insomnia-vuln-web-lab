-- Enrich scan_findings with fields from DAST export JSON so comparison
-- metrics can be computed without re-parsing raw_snippet every time.

ALTER TABLE scan_findings
  ADD COLUMN cvss          DECIMAL(3,1)   NULL AFTER severity,
  ADD COLUMN confidence    DECIMAL(3,2)   NULL AFTER cvss,
  ADD COLUMN cwe           VARCHAR(32)    NULL AFTER confidence,
  ADD COLUMN cwe_name      VARCHAR(255)   NULL AFTER cwe,
  ADD COLUMN owasp         VARCHAR(128)   NULL AFTER cwe_name,
  ADD COLUMN owasp_name    VARCHAR(255)   NULL AFTER owasp,
  ADD COLUMN module        VARCHAR(500)   NULL AFTER owasp_name,
  ADD COLUMN target_url    VARCHAR(500)   NULL AFTER module,
  ADD COLUMN method        VARCHAR(16)    NULL AFTER target_url,
  ADD COLUMN status        VARCHAR(32)    NULL AFTER method,
  ADD COLUMN finding_id    VARCHAR(32)    NULL AFTER status;

ALTER TABLE scan_findings
  ADD INDEX idx_finding_severity (severity),
  ADD INDEX idx_finding_owasp    (owasp),
  ADD INDEX idx_finding_cwe      (cwe);
