"use strict";
/** Offline observation-contract controls. These values are not native evidence. */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const helper = require("../tests/e2e/helpers/certops-acme-native-adoption");
function fixture() {
  const previous = require("./test-support/acme-bulk-proof.cjs").proof({
    fingerprints: ["a", "b", "c"].map((c) => c.repeat(64)),
    spkiFingerprint: "d".repeat(64),
    sourceProfileId: crypto.randomUUID(),
  });
  return {
    previous,
    proof: {
      scope: helper.SCOPE,
      certificateId: previous.certificateIds[0],
      profileId: crypto.randomUUID(),
      jobIds: [crypto.randomUUID(), crypto.randomUUID()],
      claimIds: [crypto.randomUUID(), crypto.randomUUID()],
      fingerprints: [previous.fingerprints[2], "9".repeat(64)],
      spkiFingerprints: [previous.spkiFingerprints[2], "a".repeat(64)],
      ...Object.fromEntries(helper.FLAGS.map((flag) => [flag, true])),
    },
  };
}
test("native setup consumes the actual public jobDetail claim projection", () => {
  const { jobDetail } = require("../apps/api/routes/certops")._test;
  const row = {
    id: crypto.randomUUID(),
    status: "succeeded",
    mode: "real",
    subject_id: crypto.randomUUID(),
    claim_id: crypto.randomUUID(),
  };
  const agent = crypto.randomUUID();
  const body = {
    job: jobDetail({
      id: row.id,
      status: row.status,
      mode: row.mode,
      operation: "renew",
      subjectType: "managed_certificate",
      subjectId: row.subject_id,
      claimId: row.claim_id,
      claimedByAgentId: agent,
      attemptCount: 1,
      resultMetadata: { keyRotated: true },
    }),
  };
  helper.verifyPublicResult(body, row, agent);
  const wrong = structuredClone(body);
  wrong.job.claimingAgentId = wrong.job.claimedByAgentId;
  delete wrong.job.claimedByAgentId;
  assert.throws(() => helper.verifyPublicResult(wrong, row, agent));
});
test("native re-setup contract binds the genuine earlier owned bulk generation", () => {
  const { proof, previous } = fixture();
  helper.verifyAgainstBulk(proof, previous);
});
test("native re-setup refuses absent native facts, broader claims and private extras", () => {
  const { proof } = fixture();
  for (const key of Object.keys(proof)) {
    const missing = { ...proof };
    delete missing[key];
    assert.throws(() => helper.verifyProof(missing));
  }
  for (const flag of helper.FLAGS)
    assert.throws(() => helper.verifyProof({ ...proof, [flag]: false }));
  for (const extra of [
    { unknownKeyAdopted: true },
    { unattendedWorkerQualified: true },
    { parkedRetryQualified: true },
    { privateKey: "never-persist" },
  ])
    assert.throws(() => helper.verifyProof({ ...proof, ...extra }));
});
test("native re-setup cannot splice identities, replay earlier jobs or reuse key/leaf", () => {
  const { proof, previous } = fixture();
  for (const patch of [
    { certificateId: previous.certificateIds[1] },
    { fingerprints: [previous.fingerprints[0], proof.fingerprints[1]] },
    {
      spkiFingerprints: [
        previous.spkiFingerprints[0],
        proof.spkiFingerprints[1],
      ],
    },
    { jobIds: [previous.issueJobIds[0], proof.jobIds[1]] },
    { claimIds: [previous.claimIds[0], proof.claimIds[1]] },
    { fingerprints: [proof.fingerprints[0], previous.fingerprints[3]] },
    {
      spkiFingerprints: [
        proof.spkiFingerprints[0],
        previous.spkiFingerprints[3],
      ],
    },
  ])
    assert.throws(() =>
      helper.verifyAgainstBulk({ ...proof, ...patch }, previous),
    );
  for (const key of ["jobIds", "claimIds", "fingerprints", "spkiFingerprints"])
    assert.throws(() =>
      helper.verifyProof({
        ...proof,
        [key]: [proof[key][0], proof[key][0].toUpperCase()],
      }),
    );
  const damaged = structuredClone(previous);
  damaged.actualPublicOwnedIssuances = false;
  assert.throws(() => helper.verifyAgainstBulk(proof, damaged));
});

test("actual parent setup context supplies the independent serving TLS observer", () => {
  const source = require("node:fs").readFileSync(
    require("node:path").resolve(
      __dirname,
      "../tests/e2e/acme-real-journey.js",
    ),
    "utf8",
  );
  const expression = source.match(
    /adoption\.qualifyNativeAdoption\((\{[^;]+?\})\)/,
  )?.[1];
  assert.ok(expression);
  const names = [
    ...new Set(expression.match(/\b[A-Za-z][A-Za-z0-9]*\b/g)),
  ].filter((name) => name !== "primaryTlsOptions");
  const observer = () => Promise.resolve("actual-owned-TLS-observer");
  const context = new Function(...names, `return (${expression});`)(
    ...names.map((name) =>
      name === "servedFingerprint" || name === "lifecycleTlsOptions"
        ? observer
        : {},
    ),
  );
  assert.equal(context.servedFingerprint, observer);
  assert.equal(context.primaryTlsOptions, observer);
});

test("actual TLS options callback resolves explicit owned CA instead of implicit default trust",()=>{const ca=Buffer.from('owned-public-CA-control');assert.equal(helper.resolveTlsOptions(()=>({ca})).ca,ca);for(const provider of [undefined,{ca},()=>({}),()=>null])assert.throws(()=>helper.resolveTlsOptions(provider));});
