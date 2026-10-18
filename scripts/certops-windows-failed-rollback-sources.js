"use strict";
/** Explicit installed failed-rollback dependencies, including shared owned-PG
 * readers and the parent cleanup guards. Hashes are drift guards, not proof
 * that unrelated parent variants or the stopped/offline journey executed. */
module.exports = Object.freeze([
  ...require("./certops-windows-installed-sources"),
  "scripts/certops_windows_failed_rollback_proof.py",
  ".github/workflows/certops-windows-failed-rollback.yml",
  "scripts/certops-windows-failed-rollback-sources.js",
  "scripts/certops-windows-failed-rollback.js",
  "tests/e2e/helpers/certops-windows-installed-failed-rollback.js",
  "tests/e2e/helpers/certops-windows-predecessor-holder.js",
  "tests/e2e/helpers/certops-windows-predecessor-holder.ps1",
]);
