"use strict";
// Pure preflight over actual docker image inspection. Labels are cross-checks,
// not authenticated build attestations; producer provenance remains required.
const assert = require("node:assert/strict");
const {execFileSync} = require("node:child_process");
function inspectCandidateImages({candidateSha,apiImage,workerImage,inspect}) {
  assert.match(candidateSha || "", /^[a-f0-9]{40}$/);
  const result={candidateSha,images:{},provenance:"image-label-cross-check-only"};
  for (const [role,reference] of Object.entries({api:apiImage,worker:workerImage})) {
    assert.match(reference || "", /^sha256:[a-f0-9]{64}$/, `${role} immutable image ID required`);
    const rows=inspect(reference);
    assert.ok(Array.isArray(rows) && rows.length===1, `${role} image missing`);
    const image=rows[0];
    assert.equal(image.Id,reference,`${role} image ID mismatch`);
    assert.equal(image.Config?.Labels?.["io.tokentimer.certops.source-sha"],candidateSha,`${role} candidate mismatch`);
    result.images[role]={id:image.Id,sourceSha:candidateSha};
  }
  assert.notEqual(result.images.api.id,result.images.worker.id,"API and worker must be distinct images");
  return result;
}
function inspectDocker(reference) {
  return JSON.parse(execFileSync("docker",["image","inspect",reference],{encoding:"utf8",timeout:30000,maxBuffer:1048576}));
}
module.exports={inspectCandidateImages,inspectDocker};
if(require.main===module) {
  try { const [candidateSha,apiImage,workerImage]=process.argv.slice(2);
    process.stdout.write(JSON.stringify(inspectCandidateImages({candidateSha,apiImage,workerImage,inspect:inspectDocker}))+"\n");
  } catch { process.stderr.write("Candidate image preflight failed.\n"); process.exitCode=1; }
}
