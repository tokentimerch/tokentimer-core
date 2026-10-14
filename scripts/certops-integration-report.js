"use strict";
/**
 * Validates supporting integration reports against exact committed test groups and source identity.
 * Invoked after the integration runner; rejects missing or skipped cases and does not promote
 * API/PostgreSQL fixture assertions into native certificate-host evidence.
 */
function verify(report, required, candidateSha, scope = "adcs-database-integration") {
  if (report.scope !== scope || (candidateSha && report.candidateSha !== candidateSha)) throw new Error("Database integration report candidate identity mismatch");
  if (!required.length || !Array.isArray(report.tests) || !report.tests.length || report.tests.some((test) => test.status !== "pass")) throw new Error("AD CS database integration did not qualify without skips");
  for (const expected of required) {
    if (report.tests.filter((test) => test.file === expected.file && test.name === expected.name && test.status === "pass").length !== 1) throw new Error(`Required named database case missing: ${expected.name}`);
  }
  return report.tests.length;
}
module.exports = { verify };
