"use strict";
/** Derives only the measured service-stop/DNS recovery slice from its completed
 * native parent. Original-attempt continuation and other operation stages remain
 * unqualified. Loading this module does not execute or qualify a Windows host. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const parentProof = require("./certops-windows-stop-offline-proof");
const SUITE = "windows-installed-interruption-recovery";
const SOURCE = "tests/e2e/helpers/certops-windows-interruption-native.js";
const SCOPE = "service-stop-during-dns-after-native-cng-journal";
const sources = () => [...new Set([SOURCE,...require("../../../scripts/certops-windows-stop-offline-sources")])];
function verifyProof(p) {
  assert.deepEqual(Object.keys(p).sort(),["scope","interruptionMode","observedStage","nativeExecutionQualified","realRebootQualified","powerLossDurabilityQualified","originalOperationAutomaticallyRecovered","parentSuite","nativeStoppedOffline"].sort());
  assert.equal(p.scope,SCOPE);
  assert.equal(p.interruptionMode,"service-stop");
  assert.equal(p.observedStage,"dns-post-after-native-cng-journal");
  assert.equal(p.parentSuite,"windows-installed-stop-offline-renewal");
  assert.equal(p.nativeExecutionQualified,true);
  for(const field of ["realRebootQualified","powerLossDurabilityQualified","originalOperationAutomaticallyRecovered"])assert.equal(p[field],false);
  parentProof.verifyProof(p.nativeStoppedOffline);
  return true;
}
function createReport(parent,{candidateSha=process.env.GITHUB_SHA,root=path.resolve(__dirname,"../../..")}={}) {
  assert.match(candidateSha||"",/^[a-f0-9]{40}$/);
  assert.equal(parent.suite,"windows-installed-stop-offline-renewal");
  assert.equal(parent.experimental===true||parent.qualificationStatus==="not-qualified",false);
  assert.equal(parent.artifactQualification,"workflow-checkout-source");
  assert.equal(parent.platform,"win32");assert.equal(parent.architecture,"x64");
  assert.equal(parent.cleanup?.status,"passed");
  const env=parent.qualificationEnvironment;
  for(const [key,value] of Object.entries({osFamily:"windows",identity:"LocalSystem",nativeLanguage:"en-US",measurement:"native",architecture:"x64"}))assert.equal(env?.[key],value);
  assert.ok(["2022","2025"].includes(env.osVersion));assert.ok([2,3].includes(env.productType));
  assert.deepEqual(require("../../../scripts/certops-qualification-report").verifyReport(parent,undefined,{expectedSha:candidateSha}),[]);
  parentProof.verifyProof(parent.nativeWindowsStoppedOffline);
  const fingerprint=file=>({file,sha256:crypto.createHash("sha256").update(fs.readFileSync(path.join(root,file))).digest("hex")});
  assert.deepEqual(parent.fixtureSource,fingerprint("scripts/certops-windows-stop-offline.js"));
  const fixtureSources=sources().map(file=>{
    const matches=parent.fixtureSources.filter(entry=>entry.file===file);
    assert.equal(matches.length,1,"Native interruption source must be observed exactly once");
    assert.deepEqual(matches[0],fingerprint(file));return matches[0];
  });
  const scenarios=parent.scenarios.filter(entry=>entry.id===parentProof.SCENARIO);
  assert.equal(scenarios.length,1);assert.equal(scenarios[0].status,"passed");assert.equal(scenarios[0].evidenceLevel,"real-host");
  const proof={scope:SCOPE,interruptionMode:"service-stop",observedStage:"dns-post-after-native-cng-journal",nativeExecutionQualified:true,realRebootQualified:false,powerLossDurabilityQualified:false,originalOperationAutomaticallyRecovered:false,parentSuite:parent.suite,nativeStoppedOffline:structuredClone(parent.nativeWindowsStoppedOffline)};
  verifyProof(proof);
  const fields=["schemaVersion","strict","status","candidateSha","startedAt","finishedAt","platform","architecture","cleanup","qualificationEnvironment","artifactQualification","evidenceLevel","requiredCapabilities","capabilities","missingScenarios","missingCapabilities"];
  const result={...Object.fromEntries(fields.map(key=>[key,parent[key]])),suite:SUITE,fixtureSource:fingerprint(SOURCE),fixtureSources,requiredScenarios:[parentProof.SCENARIO],scenarios,nativeInstalledInterruption:proof};
  assert.deepEqual(require("../../../scripts/certops-qualification-report").verifyReport(result,undefined,{expectedSha:candidateSha}),[]);
  return result;
}
module.exports={SUITE,SOURCE,SCOPE,sources,verifyProof,createReport};
