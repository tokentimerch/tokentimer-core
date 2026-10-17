"use strict";

const path = require("node:path");
const contract = require("../tests/e2e/helpers/certops-trust-concurrency");

function main() {
  try {
    const report = contract.run({ env: process.env });
    process.stdout.write(`${JSON.stringify({
      status: report.status,
      qualified: report.qualified,
      publicSignedTrustSeparate: report.publicSignedTrustSeparate,
      publicSignedTrustQualified: report.publicSignedTrustQualified,
      hostCapabilityAbsentIsPass: report.hostCapabilityAbsentIsPass,
    })}\n`);
  } catch (error) {
    const report = contract.closedReport(error.message);
    contract.writeReport(
      process.env[contract.REPORT_ENV] || path.join("qualification-results", contract.REPORT_FILE),
      report,
    );
    process.stdout.write(`${JSON.stringify({ status: "failed", qualified: false })}\n`);
  }
  process.exitCode = 1;
}

if (require.main === module) main();

module.exports = { main };
