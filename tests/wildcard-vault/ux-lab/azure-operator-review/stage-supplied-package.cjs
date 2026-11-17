"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { CAPABILITIES, inspect, verifyIdentity } = require("../../../../scripts/certops-azure-keyvault-package.cjs");

const ARCHIVE = "tokentimer-agent-0.20.0.tgz";
const MEMBERS = ["artifact.json", ARCHIVE, ARCHIVE + ".sha256"];

function stage({ directory, archiveSha256, candidateSha, destination, producerRunId, artifactId }) {
  assert.ok(path.isAbsolute(directory) && path.isAbsolute(destination), "absolute artifact and staging paths required");
  const packageArtifact = verifyIdentity({
    artifactId, runId: producerRunId, candidateSha, packageSha256: archiveSha256, packageVersion: "0.20.0", capabilities: CAPABILITIES,
  });
  inspect(directory, candidateSha, archiveSha256);
  fs.mkdirSync(destination);
  try {
    const artifacts = path.join(destination, "artifacts");
    fs.mkdirSync(artifacts);
    for (const member of MEMBERS) {
      fs.copyFileSync(path.join(directory, member), path.join(artifacts, member), fs.constants.COPYFILE_EXCL);
    }
    inspect(artifacts, candidateSha, archiveSha256);
    fs.renameSync(path.join(artifacts, "artifact.json"), path.join(destination, "artifact.json"));
    // The trusted workflow authenticates the GitHub artifact before extraction.
    // This record binds the local copy to that input, under the caller's authority.
    const input = { packageArtifact, provenance: "caller-authentication-required" };
    fs.writeFileSync(path.join(destination, "harness-input.json"), JSON.stringify(input) + "\n", { flag: "wx" });
    return input;
  } catch (error) {
    fs.rmSync(destination, { recursive: true, force: true });
    throw error;
  }
}

if (require.main === module) {
  try {
    const [directory, archiveSha256, candidateSha, destination, producerRunId, artifactId] = process.argv.slice(2);
    console.log(JSON.stringify(stage({ directory, archiveSha256, candidateSha, destination, producerRunId, artifactId })));
  } catch {
    console.error("Supplied package staging refused");
    process.exitCode = 1;
  }
}
module.exports = { stage };
