"use strict";
/** Offline release and source adversaries; no native trust refresh runs. */
const { test } = require("node:test"),
  assert = require("node:assert/strict");
const { verifyMatrix } = require("./certops-release-qualification");
const fixture = require("./test-support/linux-trust-independent-artifact.cjs");
const h = require("./certops-linux-trust-independent-roots");
const errors = (artifact, version = "24.04") =>
  verifyMatrix([artifact], {
    candidateSha: fixture.CANDIDATE,
    specification: { schemaVersion: 1, slots: [fixture.slot(version)] },
  });
test("three native trust slots require genuine selective root preservation proof and exact sources", () => {
  for (const version of ["22.04", "24.04", "9.6"])
    assert.deepEqual(errors(fixture.artifact(version), version), []);
  for (const flag of h.FLAGS) {
    const value = fixture.artifact();
    delete value.report.nativeIndependentTrustRoots[flag];
    assert.ok(errors(value).length);
  }
  for (const file of h.REQUIRED_SOURCES) {
    const value = fixture.artifact();
    value.report.fixtureSources.find((row) => row.file === file).sha256 =
      "e".repeat(64);
    assert.ok(errors(value).length);
  }
});
test("trust release rejects wrong native family, unclosed proof, skipped cases and failed cleanup", () => {
  for (const mutate of [
    (v) => delete v.report.nativeIndependentTrustRoots,
    (v) => {
      v.report.nativeIndependentTrustRoots.family = "rhel";
    },
    (v) => {
      v.report.platform = "win32";
    },
    (v) => {
      v.report.nativeIndependentTrustRoots.rawKey = "secret";
    },
    (v) => {
      v.report.scenarios[0].status = "skipped";
    },
    (v) => {
      v.report.cleanup.status = "failed";
    },
  ]) {
    const value = fixture.artifact();
    mutate(value);
    assert.ok(errors(value).length);
  }
});

test("native receipt conflict recovery cannot imply serialized writers or partial-write recovery",()=>{
  const helper=require("./certops-linux-trust-receipt-conflict");
  for(const version of ["22.04","24.04","9.6"]){assert.deepEqual(errors(fixture.artifact(version),version),[]);for(const file of helper.REQUIRED_SOURCES)assert.ok(fixture.slot(version).requiredSources.includes(file));}
  assert.ok(fixture.IDS.includes(helper.SCENARIO));
  for(const flag of helper.FLAGS){for(const wrong of [false,1,"true",null]){const value=fixture.artifact();value.report.nativeTrustReceiptConflict[flag]=wrong;assert.ok(errors(value).length);}const missing=fixture.artifact();delete missing.report.nativeTrustReceiptConflict[flag];assert.ok(errors(missing).length);}
  for(const change of [{serializationQualified:true},{partialWriteRecoveryQualified:true},{family:"rhel"},{writerCount:1},{losingFailureCategory:null},{rawKey:"withheld"}]){const value=fixture.artifact();Object.assign(value.report.nativeTrustReceiptConflict,change);assert.ok(errors(value).length);}
  const absent=fixture.artifact();delete absent.report.nativeTrustReceiptConflict;assert.ok(errors(absent).length);
  for(const file of helper.REQUIRED_SOURCES){const value=fixture.artifact();value.report.fixtureSources.find(row=>row.file===file).sha256="e".repeat(64);assert.ok(errors(value).length);}
});
