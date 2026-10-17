"use strict";
/** Tests native report derivation with synthetic receipts; no host is qualified. */
const {test}=require("node:test"),assert=require("node:assert/strict");
const helper=require("../tests/e2e/helpers/certops-adcs-browser-enrollment");
const fixture=require("./fixtures/certops-native-browser-enrollment.cjs");
const matrix=require("../docs/certops/release-qualification-matrix.json");
const {verifyMatrix}=require("./certops-release-qualification");
function errors(report){const slot=matrix.slots.find(row=>row.suite===helper.SUITE);return verifyMatrix([{kind:"host",suite:report.suite,environment:slot.environment,report}],{candidateSha:report.candidateSha,specification:{schemaVersion:1,slots:[slot]}});}
test("completed native browser stages derive an exact source-bound report without first-issue claims",()=>{
  const parent=fixture.parentReport();parent.privateState="must-not-survive";
  const report=helper.createNativeReport(parent,{candidateSha:parent.candidateSha});
  assert.deepEqual(report.requiredScenarios,helper.nativeRequiredScenarios());
  assert.equal(report.scenarios.length,9);assert.deepEqual(errors(report),[]);
  assert.equal(JSON.stringify(report).includes("must-not-survive"),false);
  assert.equal(report.nativeAdcsBrowserEnrollment.nativeBrowserJourney.lifecycle,"renew-existing-inventory-not-first-issue-or-manual-job");
  assert.throws(()=>helper.verifyProof(report.nativeAdcsBrowserEnrollment));
});
test("parent failure, cleanup, absent stages, missing confirmation and stale provenance fail closed",()=>{
  for(const mutate of [
    p=>{p.status="failed";},p=>{p.cleanup.status="failed";},p=>{p.scenarios.pop();},p=>{p.experimental=true;},p=>{p.candidateSha="b".repeat(40);},
    p=>{p.suite="enterprise-adcs-hierarchy-real";},p=>{p.nativeBrowserAdcs.noEnrollmentBeforeConfirmation=false;},
    p=>{p.fixtureSources[0].sha256="0".repeat(64);},p=>{p.fixtureSources.pop();},
    p=>{const rows=p.scenarios.filter(row=>row.id.startsWith("adcs-real-browser-"));rows[1].startedAt=rows[0].startedAt;},
  ]){const parent=fixture.parentReport();mutate(parent);assert.throws(()=>helper.createNativeReport(parent,{candidateSha:"a".repeat(40)}));}
});
test("local ordering proofs, scope labels and incomplete native observations cannot qualify",()=>{
  const report=fixture.nativeReport();
  for(const mutate of [
    r=>{r.nativeAdcsBrowserEnrollment=helper.acceptJourney(helper.JOURNEY.map(step=>({step})));},
    r=>{r.nativeAdcsBrowserEnrollment.nativeExecutionQualified=false;},r=>{r.nativeAdcsBrowserEnrollment.confirmationBeforeSubmit=false;},
    r=>{r.nativeAdcsBrowserEnrollment.nativeBrowserJourney.nativeCaRequestMatched=false;},r=>{r.cleanup.status="failed";},
    r=>{r.scenarios.pop();},r=>{r.platform="linux";},r=>{r.fixtureSources[0].sha256="0".repeat(64);},
  ]){const invalid=structuredClone(report);mutate(invalid);assert.ok(errors(invalid).length);}
});
