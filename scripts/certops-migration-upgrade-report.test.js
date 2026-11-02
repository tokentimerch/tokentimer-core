/**
 * Regression coverage: measured old/new source and additive actual schema evidence required.
 * Local fixtures verify this contract; measured native/environment execution
 * is tracked separately in the qualification suites and their reports.
 */
"use strict";
const {test}=require("node:test"),assert=require("node:assert/strict");
const {verifyEvidence}=require("./certops-migration-upgrade-report"),{BASELINE}=require("./certops-migration-upgrade");
const fixture=()=>({suite:"core-api-migration-upgrade",status:"passed",artifactQualification:"workflow-checkout-source",sourceProvenance:"historical-source-build-to-candidate-source",sourceIdentity:{baseline:{sha:BASELINE,version:"0.17.3",lockfileSha256:"a".repeat(64)},candidate:{sha:"b".repeat(40),version:"0.18.0",lockfileSha256:"c".repeat(64)}},databaseRuntime:{imageId:"sha256:"+"d".repeat(64),serverVersion:"16.6"},baselineSchema:{migrations:[{version:1,name:"baseline"}],tables:2,columns:10},candidateSchema:{migrations:[{version:1,name:"baseline"},{version:2,name:"candidate"}],tables:3,columns:12},actualTlsObservedPromotion:true,repeatMigrationSchemaUnchanged:true});
test("measured old/new source and additive actual schema evidence required",()=>{assert.equal(verifyEvidence(fixture()),true);for(const edit of [{status:"failed"},{actualTlsObservedPromotion:false},{repeatMigrationSchemaUnchanged:false},{databaseRuntime:{serverVersion:"16.6",imageId:"postgres:16.6"}},{artifactQualification:"published-release"}])assert.throws(()=>verifyEvidence({...fixture(),...edit}));});
test("historical migrations cannot disappear change names or shrink schema",()=>{for(const schema of [{migrations:[{version:1,name:"changed"}],tables:3,columns:12},{migrations:[],tables:3,columns:12},{migrations:[{version:1,name:"baseline"}],tables:1,columns:12},{migrations:[{version:1,name:"baseline"}],tables:3,columns:9}])assert.throws(()=>verifyEvidence({...fixture(),candidateSchema:schema}));});
test("same-source upgrade and unverified old pin cannot qualify",()=>{const report=fixture();assert.throws(()=>verifyEvidence({...report,sourceIdentity:{...report.sourceIdentity,baseline:{...report.sourceIdentity.baseline,sha:"a".repeat(40)}}}));assert.throws(()=>verifyEvidence({...report,sourceIdentity:{...report.sourceIdentity,candidate:{...report.sourceIdentity.candidate,sha:BASELINE}}}));});
