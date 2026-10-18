"use strict";
/** Reviewed causal inventory for the separate manual alive/default-grace lane.
 * Existing stopped/offline native modules remain loaded by the shared owned PG
 * prerequisite; this manifest never imports or qualifies that other report. */
module.exports = Object.freeze([
  ...require("./certops-windows-installed-sources"),
  "scripts/certops_windows_alive_grace_proof.py",
  ".github/workflows/certops-windows-alive-grace.yml",
  "scripts/certops-windows-alive-grace-sources.js",
  "scripts/certops-windows-alive-grace.js",
  "scripts/certops_windows_stop_offline_proof.py",
  "tests/e2e/helpers/certops-acme-result-outage.js",
  "tests/e2e/helpers/certops-windows-alive-grace-command.js",
  "tests/e2e/helpers/certops-windows-alive-grace-proof.js",
  "tests/e2e/helpers/certops-windows-alive-grace-reaper.js",
  "tests/e2e/helpers/certops-windows-alive-grace.js",
  "tests/e2e/helpers/certops-windows-stop-offline-proof.js",
  "tests/e2e/helpers/certops-windows-stop-offline-reaper.js",
]);
