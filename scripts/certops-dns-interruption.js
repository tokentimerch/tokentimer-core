"use strict";

const path = require("node:path");
const contract = require("../tests/e2e/helpers/certops-dns-interruption");

function main() {
  try {
    const report = contract.run({ env: process.env });
    process.stdout.write(`${JSON.stringify({
      status: report.status,
      qualified: report.qualified,
      liveDnsQualified: report.liveDnsQualified,
      propagationClaimed: report.propagationClaimed,
      evidenceLevel: report.evidenceLevel,
      hostCapabilityAbsentIsPass: report.hostCapabilityAbsentIsPass,
    })}\n`);
  } catch (error) {
    const report = contract.closedReport(error.message);
    contract.writeReport(
      process.env[contract.REPORT_ENV] || path.join("qualification-results", contract.REPORT_FILE),
      report,
    );
    process.stdout.write(`${JSON.stringify({ status: "failed", qualified: false, liveDnsQualified: false })}\n`);
  }
  process.exitCode = 1;
}

if (require.main === module) main();

module.exports = { main };
