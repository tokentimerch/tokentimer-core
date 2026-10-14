"use strict";
/**
 * Mocha reporter recording bounded integration outcomes, measured runtime and committed source hashes.
 * Selected by the integration qualification runner; emits supporting API/PostgreSQL evidence
 * without raw assertion values, credentials or a claim of native certificate execution.
 */
const fs = require("node:fs");
const path = require("node:path");
const crypto=require("node:crypto");
module.exports = class QualificationReporter {
  constructor(runner) {
    const group=process.env.CERTOPS_INTEGRATION_GROUP || "adcs";
    const definition=require("../tests/integration/certops-qualification-groups.json")[group];
    if(!definition)throw new Error("Unknown integration evidence source group");
    const fixtureSources=definition.files.map(file=>({file:`tests/integration/${file}`,sha256:crypto.createHash("sha256").update(fs.readFileSync(path.resolve(__dirname,"../tests/integration",file))).digest("hex")}));
    const qualificationEnvironment=require("./certops-stack-reporter").measuredEnvironment();
    const tests = [];
    for (const status of ["pass", "fail", "pending"]) runner.on(status, (test) => tests.push({ file: path.basename(test.file || ""), name: test.title, status }));
    runner.on("end", () => {
      fs.writeFileSync(process.env.CERTOPS_MOCHA_REPORT, JSON.stringify({ scope: process.env.CERTOPS_MOCHA_SCOPE || "adcs-database-integration", evidenceLevel:"integration",candidateSha: process.env.GITHUB_SHA || null, artifactQualification:process.env.GITHUB_ACTIONS === "true" ? "workflow-checkout-source" : "local-worktree-source-baseline-sha-only",fixtureSources,qualificationEnvironment,tests }));
    });
  }
};
