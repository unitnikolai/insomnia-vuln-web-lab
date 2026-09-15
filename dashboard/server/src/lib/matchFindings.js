'use strict';

// Matches a parsed finding against the ground-truth vulnerability list for
// a lab. CVE ID match wins outright (it's unambiguous); otherwise falls
// back to a loose title-substring match, which is intentionally generous —
// this feeds a coverage estimate for a human to review, not an auto-grader.
function matchFinding(finding, candidateVulns) {
  if (finding.cve_id) {
    const byCve = candidateVulns.find((v) => v.cve_id && v.cve_id.toUpperCase() === finding.cve_id.toUpperCase());
    if (byCve) return byCve;
  }

  const findingTitle = (finding.title || '').toLowerCase();
  if (findingTitle) {
    const byTitle = candidateVulns.find((v) => {
      const vulnTitle = (v.title || '').toLowerCase();
      return vulnTitle && (findingTitle.includes(vulnTitle) || vulnTitle.includes(findingTitle));
    });
    if (byTitle) return byTitle;
  }

  return null;
}

module.exports = { matchFinding };
