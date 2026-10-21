"use strict";
/** Explicit causal source inventory for the separate manual stopped/offline lane.
 * Hashes guard source drift; they do not establish native execution. */
module.exports = Object.freeze([
  ...require("./certops-windows-installed-sources"),
  "tests/e2e/helpers/certops-windows-interruption-native.js",
  "scripts/certops_windows_interruption_native_proof.py",
  ".github/workflows/certops-windows-stop-offline.yml",
  "scripts/certops-windows-stop-offline-sources.js",
  "scripts/certops-windows-stop-offline.js",
  "scripts/certops_windows_stop_offline_proof.py",
  "tests/e2e/helpers/certops-windows-stop-offline-proof.js",
  "tests/e2e/helpers/certops-windows-stop-offline-reaper.js",
]);
