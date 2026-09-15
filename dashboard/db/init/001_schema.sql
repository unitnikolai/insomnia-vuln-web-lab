-- Schema for the benchmark dashboard.
--
-- `labs` is every scannable target in the fleet: the built-in apps in the
-- top-level docker-compose.yml (kind='builtin') plus one row per Vulhub
-- recipe (kind='vulhub'), seeded separately by seed/seed-vulhub.js since the
-- Vulhub collection is 300+ recipes and changes as upstream adds more.
--
-- `vulnerabilities` is the ground truth / answer key: what a scan run
-- against a given lab is *supposed* to find. For built-in apps this is a
-- curated list of vuln classes (they're training apps, not real CVEs). For
-- Vulhub recipes it's one row per recipe with its CVE ID.
--
-- `scans` holds every uploaded scan export verbatim (raw_json) regardless of
-- which tool produced it or whether it parsed cleanly, so nothing is ever
-- lost to a parser that doesn't understand a given tool's format yet.
--
-- `scan_findings` is the best-effort normalized parse of each scan's
-- findings (see server/src/lib/parseScan.js), each optionally linked to the
-- ground-truth vulnerability it matched — that link is what the coverage
-- view (found vs. missed) is computed from.

CREATE TABLE IF NOT EXISTS labs (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  slug          VARCHAR(191) NOT NULL UNIQUE,
  name          VARCHAR(255) NOT NULL,
  kind          ENUM('builtin', 'vulhub') NOT NULL,
  category      VARCHAR(128),
  url_hint      VARCHAR(255),
  description   TEXT,
  created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS vulnerabilities (
  id             INT AUTO_INCREMENT PRIMARY KEY,
  lab_id         INT NOT NULL,
  cve_id         VARCHAR(32),
  title          VARCHAR(500) NOT NULL,
  category       VARCHAR(128),
  severity       ENUM('critical', 'high', 'medium', 'low', 'info') NOT NULL DEFAULT 'medium',
  description    TEXT,
  exploit_notes  TEXT,
  reference_url  VARCHAR(500),
  created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (lab_id) REFERENCES labs(id) ON DELETE CASCADE,
  INDEX idx_vuln_cve (cve_id),
  INDEX idx_vuln_lab (lab_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS scans (
  id           INT AUTO_INCREMENT PRIMARY KEY,
  lab_id       INT,
  filename     VARCHAR(255) NOT NULL,
  tool_name    VARCHAR(128),
  uploaded_by  VARCHAR(255),
  notes        TEXT,
  raw_json     LONGTEXT NOT NULL,
  uploaded_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (lab_id) REFERENCES labs(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS scan_findings (
  id                        INT AUTO_INCREMENT PRIMARY KEY,
  scan_id                   INT NOT NULL,
  cve_id                    VARCHAR(32),
  title                     VARCHAR(500),
  severity                  VARCHAR(64),
  matched_vulnerability_id  INT,
  raw_snippet               JSON,
  FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
  FOREIGN KEY (matched_vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE SET NULL,
  INDEX idx_finding_cve (cve_id),
  INDEX idx_finding_scan (scan_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
