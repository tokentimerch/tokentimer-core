"use strict";
/** Offline native-evidence/source adversaries only; never cluster execution. */
const {test}=require("node:test"),assert=require("node:assert/strict");
const {verifyMatrix}=require("./certops-release-qualification");
const h=require("./certops-kubernetes-rbac"),fixture=require("./test-support/kubernetes-rbac-artifact.cjs");
const slot=require("./certops-qualification-manifest").slots.find(row=>row.suite===fixture.SUITE);
const errors=value=>verifyMatrix([value],{candidateSha:fixture.CANDIDATE,specification:{schemaVersion:1,slots:[slot]}});
test("Kubernetes release requires mandatory startup denial, native recovery facts and causal source identity",()=>{
  assert.deepEqual(errors(fixture.artifact()),[]);
  assert.ok(require("./certops-qualification-manifest").suites[fixture.SUITE].includes(h.SCENARIO));
  for(const file of h.REQUIRED_SOURCES)assert.ok(slot.requiredSources.includes(file));
  for(const flag of h.FLAGS)for(const wrong of [false,1,"true",null]){const value=fixture.artifact();value.report.nativeKubernetesRbacStartupRecovery[flag]=wrong;assert.ok(errors(value).length);}
  for(const mutate of [value=>delete value.report.nativeKubernetesRbacStartupRecovery,value=>{value.report.scenarios.find(row=>row.id===h.SCENARIO).status="skipped";},value=>{value.report.nativeKubernetesRbacStartupRecovery.privateKey="withheld";},value=>{value.report.nativeKubernetesRbacStartupRecovery.watchedResourceVersion="100";}]){const value=fixture.artifact();mutate(value);assert.ok(errors(value).length);}
  for(const file of slot.requiredSources){const value=fixture.artifact();value.report.fixtureSources.find(row=>row.file===file).sha256="b".repeat(64);assert.ok(errors(value).length);}
});
