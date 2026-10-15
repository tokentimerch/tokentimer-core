"use strict";
/* Supporting contract/source controls only. The protected disposable AD CS lab
 * must execute the helper to qualify actual machine permissions and issuance.
 */
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const subject = require("../tests/e2e/helpers/certops-adcs-live-enroll-acl");
const fixture = require("./fixtures/certops-adcs-live-enroll-acl.cjs").proof;

test("immediate issuance keeps independent native RequestId mandatory without inventing persisted IDs", () => {
  assert.equal(subject.verifyNativeRequestId(42, null, undefined), 42);
  assert.equal(subject.verifyNativeRequestId(42, "42", 42), 42);
  for (const actual of [undefined, 0, 4294967296, 1.5])
    assert.throws(() => subject.verifyNativeRequestId(actual));
  for (const reported of [41, "043", "42x", true])
    assert.throws(() => subject.verifyNativeRequestId(42, reported));
});
test("live machine Enroll proof permits genuine denied CA allocation zero or one", () => {
  for (const delta of [0, 1])
    assert.equal(
      subject.verifyProof(fixture(delta)).deniedCaRequestDelta,
      delta,
    );
});
test("live machine Enroll proof rejects missing native facts and inflated scope", () => {
  for (const flag of subject.FLAGS) {
    const absent = fixture();
    delete absent[flag];
    assert.throws(() => subject.verifyProof(absent));
    const falseFlag = fixture();
    falseFlag[flag] = false;
    assert.throws(() => subject.verifyProof(falseFlag));
  }
  const changes = [
    (proof) => {
      delete proof.actualMachineSidDenied;
    },
    (proof) => {
      proof.exactDaclRestored = false;
    },
    (proof) => {
      proof.restoredDaclSha256 = "e".repeat(64);
    },
    (proof) => {
      proof.appliedDaclSha256 = proof.originalDaclSha256;
    },
    (proof) => {
      proof.deniedCaRequestDelta = 2;
      proof.caRequestCounts = [10, 12, 13];
    },
    (proof) => {
      proof.caRequestCounts[2]++;
    },
    (proof) => {
      proof.enrollmentIds[1] = proof.enrollmentIds[0];
    },
    (proof) => {
      proof.fingerprints[1] = proof.fingerprints[0];
    },
    (proof) => {
      proof.caHresult = "0x80070005";
    },
    (proof) => {
      proof.preflightRefusalQualified = true;
    },
    (proof) => {
      proof.signedCmcRenewalQualified = true;
    },
    (proof) => {
      proof.rawDacl = "private";
    },
  ];
  for (const change of changes) {
    const proof = fixture();
    change(proof);
    assert.throws(() => subject.verifyProof(proof));
  }
});
test("template DACL mutation uses fixed template ownership and receipt before LDAP write", () => {
  const source = fs.readFileSync(
    path.resolve(__dirname, "../infra/certops-adcs/template-enroll-acl.ps1"),
    "utf8",
  );
  assert.match(
    source,
    /Global\\TokenTimerQualification-TemplateEnrollAcl-\$\(\$identity\.guid\)/,
  );
  assert.match(source, /SecurityMasks\]::Dacl/);
  assert.match(source, /0e10c968-78fb-11d2-90d4-00c04f79dc55/);
  assert.ok(
    source.indexOf("$file.Flush($true)") <
      source.indexOf("$entry.CommitChanges()"),
  );
  assert.match(
    source,
    /\$currentSddl -cne \$appliedSddl -and \$currentSddl -cne \$originalSddl/,
  );
  assert.match(source, /Get-ADComputer -Identity 'tt-agent'/);
  assert.match(source, /AssertRegularDirectory \$env:ProgramData/);
  assert.match(source, /AssertRegularDirectory \$parent/);
  assert.match(source, /AssertPrivateDirectory \$directory/);
  assert.match(source, /!\$acl\.AreAccessRulesProtected/);
  assert.match(source, /\$rule\.IsInherited/);
  assert.match(source, /IdentityReference\.Value -cnotin \$allowed/);
  assert.match(source, /Restart-Service CertSvc/);
  assert.match(source, /certutil\.exe -config .* -ping/);
  assert.doesNotMatch(
    source,
    /Set-CATemplate|Add-CATemplate|Remove-CATemplate/,
  );
});
test("unresolved live ACL receipt blocks native store cleanup before record reads", () => {
  const cleanup = require("../tests/e2e/helpers/certops-adcs-webhosting-renewal");
  let reads = 0;
  assert.throws(
    () =>
      cleanup.backgroundCleanupPlan(
        { machineAclPendingVerification: true },
        [],
        () => {
          reads++;
        },
        "My",
        /^owned$/,
      ),
    /live Enroll ACL/,
  );
  assert.equal(reads, 0);
});
test("restored issuance requires successful current claim and exact native leaf evidence", () => {
  const job = {
    status: "succeeded",
    claim_id: "55555555-5555-4555-8555-555555555555",
  };
  const leaf = {
    fingerprint256: "a".repeat(64),
    validTo: "2026-10-25T00:00:00.000Z",
  };
  const evidence = [
    {
      claim_id: job.claim_id,
      metadata: {
        step: "verify",
        fingerprintSha256: leaf.fingerprint256,
        validTo: leaf.validTo,
      },
    },
  ];
  subject.verifyInstalledEvidence(job, evidence, leaf);
  for (const change of [
    (value) => {
      value.job.status = "failed";
    },
    (value) => {
      value.job.claim_id = null;
    },
    (value) => {
      value.evidence[0].claim_id = "66666666-6666-4666-8666-666666666666";
    },
    (value) => {
      value.evidence[0].metadata.step = "install";
    },
    (value) => {
      value.evidence[0].metadata.fingerprintSha256 = "b".repeat(64);
    },
    (value) => {
      value.evidence[0].metadata.validTo = "2026-10-24T00:00:00.000Z";
    },
  ]) {
    const value = structuredClone({ job, evidence });
    change(value);
    assert.throws(() =>
      subject.verifyInstalledEvidence(value.job, value.evidence, leaf),
    );
  }
});
