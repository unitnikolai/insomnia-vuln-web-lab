-- CVE tracking: where a Vulhub recipe's expected CVE came from.
--
-- Only 249 of the ~330 upstream recipes carry a CVE in their directory name
-- (struts2/s2-045 and friends don't). The rest state it in the README title,
-- and a handful only in the README body. Recording which of those a given
-- cve_id came from keeps the coverage tracker honest: a CVE lifted out of
-- prose is a weaker claim than one in the directory name, and the UI marks
-- it as inferred rather than presenting both as equally certain.
--
-- NOTE: this directory is mysql's docker-entrypoint-initdb.d, which runs
-- ONLY against an empty data dir. Existing deployments get the same change
-- applied idempotently at app startup — see server/src/lib/migrate.js.

ALTER TABLE vulnerabilities
  ADD COLUMN cve_source VARCHAR(32) NULL AFTER cve_id;
