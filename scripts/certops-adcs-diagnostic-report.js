"use strict";

// Check a complete diagnostic run without admitting it as release evidence.
const fs = require("node:fs");
const { verifyReport } = require("./certops-qualification-report");

function verifyDiagnosticReport(report, options) {
  if (!report || report.suite !== "enterprise-adcs-real" || report.debugDetail !== true)
    return ["Expected an AD CS debug report"];
  if (report.guardedFailures !== undefined || report.failureBudgetExhausted !== undefined)
    return ["Diagnostic run recorded guarded failures or exhausted its failure budget"];
  const { debugDetail, ...qualificationShape } = report;
  return verifyReport(qualificationShape, undefined, options);
}

if (require.main === module) {
  try {
    if (process.argv.length !== 3) throw new Error("Expected one diagnostic report");
    const errors = verifyDiagnosticReport(JSON.parse(fs.readFileSync(process.argv[2], "utf8")));
    if (errors.length) { console.error(errors.join("; ")); process.exitCode = 1; }
    else console.log("Diagnostic scenarios passed; this report is not release evidence");
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
module.exports = { verifyDiagnosticReport };
