"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const subject = require("../tests/e2e/helpers/certops-adcs-ocsp");
const { proof } = require("./fixtures/certops-adcs-ocsp.cjs");
test("native OCSP proof requires every actual identity, request, cleanup and narrow-scope fact", () => {
  assert.deepEqual(subject.verifyProof(proof()), proof());
  for (const flag of subject.FLAGS) {
    const missing = proof();
    delete missing[flag];
    assert.throws(() => subject.verifyProof(missing));
    const falseFact = proof();
    falseFact[flag] = false;
    assert.throws(() => subject.verifyProof(falseFact));
  }
  for (const flag of subject.FALSE_FLAGS) {
    const promoted = proof();
    promoted[flag] = true;
    assert.throws(() => subject.verifyProof(promoted));
  }
  for (const mutate of [
    (p) => {
      p.requestIds[0] = p.signerRequestId;
    },
    (p) => {
      p.caRequestCounts[2]++;
    },
    (p) => {
      p.nativeVerdicts[1] = "valid";
    },
    (p) => {
      p.leafFingerprints[1] = p.leafFingerprints[0];
    },
    (p) => {
      p.responseSha256.pop();
    },
    (p) => {
      p.privateCredential = "forbidden";
    },
    (p) => {
      p.deferredRecovery.requestId = p.requestIds[1];
    },
    (p) => {
      p.deferredRecovery.continuationJobId = p.jobIds[1];
    },
    (p) => {
      p.deferredRecovery.originalJobId = p.jobIds[0];
    },
    (p) => {
      p.deferredRecovery.originalClaimId =
        p.deferredRecovery.continuationClaimId;
    },
  ]) {
    const value = proof();
    mutate(value);
    assert.throws(() => subject.verifyProof(value));
  }
});
test("remote broker admits only fixed actions/candidate tools and gates before remote mutation", () => {
  const source = fs.readFileSync(
    path.join(__dirname, "../infra/certops-adcs/ocsp-member-operation.ps1"),
    "utf8",
  );
  assert.ok(
    source.indexOf("Owned OCSP launch challenge mismatch") <
      source.indexOf("New-PSSession"),
  );
  assert.match(source, /Invoke-OwnedOcspPinnedOperation \$owner/);
  assert.match(source, /Remove-PSSession -Session \$session/);
  assert.doesNotMatch(source, /Invoke-Expression|taskkill|Stop-Process/);
  assert.match(source, /\$request\.helperPath -cnotin \$helperPaths/);
  assert.match(source, /\$request\.action -cnotin \$actions/);
});
test("operation drain uses actual shared nativeHandlesClosed contract and refuses invented or incomplete proof", () => {
  const closed = {
    rootExitCode: 0,
    activeNativeProcesses: 0,
    nativeHandlesClosed: true,
  };
  assert.equal(subject.verifyOperationDrain(closed), closed);
  assert.throws(() =>
    subject.verifyOperationDrain({
      rootExitCode: 0,
      activeNativeProcesses: 0,
      retainedHandlesClosed: true,
    }),
  );
  assert.throws(() =>
    subject.verifyOperationDrain({ ...closed, rootExitCode: 1 }),
  );
  assert.throws(() =>
    subject.verifyOperationDrain({ ...closed, activeNativeProcesses: 1 }),
  );
});
