"use strict";
// Source-bound artifact adversaries only; no SCM/service execution.
const test=require("node:test"),assert=require("node:assert/strict"),{artifact,candidateSha}=require("./test-support/arm64-scm-artifact.cjs"),{verifyMatrix}=require("./certops-release-qualification"),h=require("./certops-arm64-scm-proof");
const slot=require("../docs/certops/release-qualification-matrix.json").slots.find(row=>row.suite===h.suite),options={candidateSha,specification:{schemaVersion:1,slots:[slot]}};
test("separate ARM64 packaged SCM slot requires every measured fact, scenario and current source",()=>{
 assert.ok(slot);assert.equal(slot.requiredSources.length,16);assert.deepEqual(verifyMatrix([artifact()],options),[]);
 for(const key of Object.keys(artifact().report.nativeArm64Scm)){const missing=artifact();delete missing.report.nativeArm64Scm[key];assert.ok(verifyMatrix([missing],options).length,key);const wrong=artifact();wrong.report.nativeArm64Scm[key]=typeof wrong.report.nativeArm64Scm[key]==="boolean"?!wrong.report.nativeArm64Scm[key]:"wrong";assert.ok(verifyMatrix([wrong],options).length,key);}
 for(const file of slot.requiredSources){const wrong=artifact();wrong.report.fixtureSources.find(row=>row.file===file).sha256="f".repeat(64);assert.ok(verifyMatrix([wrong],options).length,file);}
 for(const id of h.REQUIRED_SCENARIOS){const wrong=artifact();wrong.report.scenarios=wrong.report.scenarios.filter(row=>row.id!==id);assert.ok(verifyMatrix([wrong],options).length,id);}
 for(const change of [r=>delete r.nativeArm64Scm,r=>r.nativeArm64Scm.retirementObservationMs=4999,r=>r.nativeArm64Scm.retirementObservationMs=true,r=>r.nativeArm64Scm.generations[1]=r.nativeArm64Scm.generations[0],r=>r.nativeArm64Scm.generations[0].childPid=0x100000000,r=>r.nativeArm64Scm.generations[0].hostCreated="2026-99-14T10:00:00.0000000Z",r=>r.nativeArm64Scm.rawPath="private",r=>r.architecture="x64",r=>r.qualificationEnvironment.productType=3,r=>r.cleanup.status="not-run"]){const wrong=artifact();change(wrong.report);assert.ok(verifyMatrix([wrong],options).length);}
});
