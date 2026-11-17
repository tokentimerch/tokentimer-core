"use strict";
const {test}=require("node:test"),assert=require("node:assert/strict");
const {inspectCandidateImages}=require("./candidate-images.cjs");
test("requires exact candidate-labelled immutable API and worker images",()=>{
 const candidateSha="a".repeat(40), apiImage="sha256:"+"b".repeat(64),workerImage="sha256:"+"c".repeat(64);
 const inspect=id=>[{Id:id,Config:{Labels:{"io.tokentimer.certops.source-sha":candidateSha}}}];
 const input={candidateSha,apiImage,workerImage,inspect};
 assert.equal(inspectCandidateImages(input).images.api.id,apiImage);
 assert.throws(()=>inspectCandidateImages({...input,apiImage:"tt-core-api:36ff"}),/immutable/);
 assert.throws(()=>inspectCandidateImages({...input,inspect:id=>[{Id:id,Config:{Labels:{"io.tokentimer.certops.source-sha":"d".repeat(40)}}}]}),/candidate mismatch/);
 assert.throws(()=>inspectCandidateImages({...input,workerImage:apiImage}),/distinct/);
});
