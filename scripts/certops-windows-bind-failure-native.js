"use strict";
/** Manual Azure-free installed bind-failure rollback producer. The installed native journey writes
 * facts only after its owned native/API/database cleanup succeeds. This producer
 * cannot turn an interrupted run or a partial sidecar into a passing report. */
const { createProducer } = require("./certops-windows-installed-producer");
module.exports = createProducer({
  proof: require("../tests/e2e/helpers/certops-windows-installed-bind-failure-native"),
  SOURCES: require("./certops-windows-bind-failure-native-sources"),
  SOURCE: "scripts/certops-windows-bind-failure-native.js",
  SUITE: "windows-installed-bind-failure-rollback",
  requiredFlag: "CERTOPS_WINDOWS_BIND_FAILURE_REQUIRED",
  candidateMessage: "Bind-failure scope requires only current candidate",
  factsName: "windows-bind-failure-native-facts.json",
  reportName: "windows-installed-bind-failure-native.json",
  timeout: 1320000,
  scope: "real-agent-windows-bind-failure/rsa-2048",
  failureMessage: "Installed bind-failure rollback journey failed",
  reportField: "nativeInstalledBindFailure",
  readOwned:
    require("../tests/e2e/helpers/certops-windows-installed-verify-rollback")
      .readOwned,
});
if (require.main === module)
  module.exports.main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
