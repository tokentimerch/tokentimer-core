"use strict";
/** Manual Azure-free alive/default-grace producer. The installed native journey writes
 * facts only after its owned native/API/database cleanup succeeds. This producer
 * cannot turn an interrupted run or a partial sidecar into a passing report. */
const { createProducer } = require("./certops-windows-installed-producer");
module.exports = createProducer({
  proof: require("../tests/e2e/helpers/certops-windows-alive-grace-proof"),
  SOURCES: require("./certops-windows-alive-grace-sources"),
  SOURCE: "scripts/certops-windows-alive-grace.js",
  SUITE: "windows-installed-alive-grace-renewal",
  requiredFlag: "CERTOPS_WINDOWS_ALIVE_GRACE_REQUIRED",
  candidateMessage: "Alive/default-grace scope requires only current candidate",
  factsName: "windows-alive-grace-native-facts.json",
  reportName: "windows-installed-alive-grace.json",
  timeout: 6120000,
  scope: "real-agent-windows-alive-grace/rsa-2048",
  failureMessage: "Installed alive/default-grace journey failed",
  reportField: "nativeWindowsAliveGrace",
  readOwned:
    require("../tests/e2e/helpers/certops-windows-installed-verify-rollback")
      .readOwned,
});
if (require.main === module)
  module.exports.main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
