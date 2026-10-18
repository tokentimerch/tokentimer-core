"use strict";
/** Manual Azure-free stopped/offline producer. The installed native journey writes
 * facts only after its owned native/API/database cleanup succeeds. This producer
 * cannot turn an interrupted run or a partial sidecar into a passing report. */
const { createProducer } = require("./certops-windows-installed-producer");
module.exports = createProducer({
  proof: require("../tests/e2e/helpers/certops-windows-stop-offline-proof"),
  SOURCES: require("./certops-windows-stop-offline-sources"),
  SOURCE: "scripts/certops-windows-stop-offline.js",
  SUITE: "windows-installed-stop-offline-renewal",
  requiredFlag: "CERTOPS_WINDOWS_STOP_OFFLINE_REQUIRED",
  candidateMessage: "Stop/offline scope requires only current candidate",
  factsName: "windows-stop-offline-native-facts.json",
  reportName: "windows-installed-stop-offline.json",
  timeout: 2520000,
  scope: "real-agent-windows-stop-offline/rsa-2048",
  failureMessage: "Installed stopped/offline journey failed",
  reportField: "nativeWindowsStoppedOffline",
  readOwned: require("../tests/e2e/helpers/certops-windows-stop-offline")
    .readPrivate,
  afterReportName: "windows-installed-interruption-native.json",
});
if (require.main === module)
  module.exports.main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
