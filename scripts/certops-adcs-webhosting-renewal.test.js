"use strict";
/** Public projection adversaries only. Native WebHosting enrollment is never
 * executed by these checks and remains pending its protected disposable lane. */
const test = require("node:test"),
  assert = require("node:assert/strict");
const helper = require("../tests/e2e/helpers/certops-adcs-webhosting-renewal");
function proof() {
  return {
    scope: "real-adcs-webhosting-issue-and-fresh-key-manual-renewal",
    store: "WebHosting",
    expiryCleanupQualified: false,
    requestIds: ["1", "2"],
    fingerprints: ["a".repeat(64), "b".repeat(64)],
    ...Object.fromEntries(helper.FLAGS.map((field) => [field, true])),
  };
}
test("WebHosting proof binds two real generations and refuses broader cleanup qualification", () => {
  assert.equal(helper.verifyProof(proof()), true);
  for (const change of [
    (p) => (p.scope = "generic"),
    (p) => (p.store = "My"),
    (p) => (p.expiryCleanupQualified = true),
    (p) => (p.requestIds[1] = p.requestIds[0]),
    (p) => (p.requestIds[1] = "4294967296"),
    (p) => (p.fingerprints[1] = p.fingerprints[0]),
    (p) => (p.rawJournal = "private"),
  ]) {
    const value = proof();
    change(value);
    assert.throws(() => helper.verifyProof(value));
  }
});
test("every independently observed WebHosting fact is mandatory", () => {
  for (const field of helper.FLAGS) {
    for (const value of [false, undefined]) {
      const candidate = proof();
      if (value === undefined) delete candidate[field];
      else candidate[field] = value;
      assert.throws(() => helper.verifyProof(candidate), field);
    }
  }
});
test("native source inventory binds actual admission, discovery, custody and retention paths", () => {
  const fs = require("node:fs"),
    path = require("node:path");
  assert.equal(
    new Set(helper.REQUIRED_SOURCES).size,
    helper.REQUIRED_SOURCES.length,
  );
  for (const file of helper.REQUIRED_SOURCES)
    assert.ok(fs.statSync(path.resolve(__dirname, "..", file)).isFile());
  assert.equal(helper.REQUIRED_SCENARIOS.length, 2);
});

test("store cleanup requires exact durable ownership before any public removal", () => {
  const enrollmentId = "11111111-1111-1111-1111-111111111111",
    certificateId = "22222222-2222-2222-2222-222222222222",
    containerName = "tokentimer-enr-" + enrollmentId,
    thumbprint = "A".repeat(40);
  const receipt = {
    store: "WebHosting",
    domain: "certops-adcs-0123456789-webhosting.example.test",
    certificateId,
    enrollmentIds: [enrollmentId],
    thumbprints: [thumbprint],
  };
  const record = {
    status: "enrolled_by_agent",
    containerName,
    certificateId,
    acceptedStore: "WebHosting",
    acceptedThumbprint: thumbprint,
  };
  assert.equal(
    helper.cleanupPlan(receipt, [{ thumbprint, containerName }], () => record)
      .length,
    1,
  );
  assert.throws(() => helper.cleanupPlan({ ...receipt, guiCancelPendingVerification: true }, [{ thumbprint, containerName }], () => { throw new Error("Must not inspect or delete protected key"); }), /GUI Cancel remains unresolved/);
  assert.throws(() => helper.cleanupPlan({ ...receipt, pendingCaRenewalUnresolved: true }, [{ thumbprint, containerName }], () => { throw new Error("Must preserve accepted pending-CA custody"); }), /pending CA renewal remains unresolved/);
  const pendingReceipt={...receipt,pendingCaRenewalUnresolved:true,cleanupCompleted:true,keyCleanupCompleted:true,removedEnrollmentIds:[...receipt.enrollmentIds]};
  helper.confirmRegisteredKeyCleanup([pendingReceipt]);assert.equal(pendingReceipt.keyCleanupCompleted,false);
  assert.throws(()=>helper.assertRegisteredCleanupComplete([{...pendingReceipt,keyCleanupCompleted:true}]),/Preserve durable/);
  assert.equal(record.status, "enrolled_by_agent"); assert.equal(receipt.cleanupCompleted, undefined);
  for (const change of [
    (r) => (r.acceptedStore = "My"),
    (r) => (r.acceptedThumbprint = "B".repeat(40)),
    (r) => (r.certificateId = "33333333-3333-3333-3333-333333333333"),
    (r) => (r.containerName = "foreign"),
    (r) => (r.status = "issued"),
  ]) {
    const bad = structuredClone(record);
    change(bad);
    assert.throws(() =>
      helper.cleanupPlan(receipt, [{ thumbprint, containerName }], () => bad),
    );
  }
  assert.throws(() =>
    helper.cleanupPlan(receipt, [{ thumbprint, containerName }], () => null),
  );
  assert.throws(() =>
    helper.cleanupPlan(
      receipt,
      [
        {
          thumbprint,
          containerName: "tokentimer-enr-33333333-3333-3333-3333-333333333333",
        },
      ],
      () => record,
    ),
  );
  assert.throws(() =>
    helper.cleanupPlan(
      receipt,
      [
        { thumbprint, containerName },
        { thumbprint, containerName },
      ],
      () => record,
    ),
  );
  assert.throws(() =>
    helper.cleanupPlan(
      { ...receipt, domain: "foreign' ; bad" },
      [],
      () => record,
    ),
  );
});
test("service root exit never substitutes for child drainage", () => {
  const drain = {
    processes: [
      { pid: 10, parent: 1, created: "2026-10-14T00:00:00Z" },
      { pid: 11, parent: 10, created: "2026-10-14T00:00:01Z" },
    ],
  };
  assert.equal(
    helper.assertDrainAbsent(drain, [
      { pid: 20, parent: 1, created: "2026-10-14T00:00:03Z" },
    ]),
    true,
  );
  assert.throws(() => helper.assertDrainAbsent(drain, [drain.processes[1]]));
  assert.throws(() =>
    helper.assertDrainAbsent(drain, [
      { pid: 12, parent: 11, created: "2026-10-14T00:00:04Z" },
    ]),
  );
  assert.throws(() => helper.assertDrainAbsent(undefined, []));
});
test("parent hooks WebHosting before CA rollover and gates exact keys and state on cleanup", () => {
  const fs = require("node:fs"),
    path = require("node:path"),
    source = fs.readFileSync(
      path.resolve(__dirname, "../tests/e2e/certops-adcs-real-e2e.test.js"),
      "utf8",
    );
  assert.ok(
    source.indexOf("qualifyPositiveRenewals(") <
      source.indexOf("qualifyWebHostingRenewal("),
  );
  assert.ok(
    source.indexOf("qualifyWebHostingRenewal(") <
      source.indexOf('gate.scenario("adcs-real-ca-same-key-renewal'),
  );
  assert.match(source, /stores:\["My", "WebHosting"\]/);
  assert.ok(
    source.indexOf("cleanupWebHosting(") <
      source.indexOf("for(const id of ownedEnrollmentIds)"),
  );
  assert.ok(
    source.includes(
      "receipt.enrollmentIds.includes(id)&&!receipt.cleanupCompleted",
    ),
  );
  assert.ok(source.includes("assertRegisteredCleanupComplete(["));
});

test("public cleanup success followed by key refusal preserves durable state", () => {
  const receipt = {
    enrollmentIds: ["11111111-1111-1111-1111-111111111111"],
    cleanupCompleted: true,
  };
  helper.confirmRegisteredKeyCleanup([receipt]);
  assert.equal(receipt.keyCleanupCompleted, false);
  assert.throws(() => helper.assertRegisteredCleanupComplete([receipt]));
  receipt.removedEnrollmentIds = [receipt.enrollmentIds[0]];
  helper.confirmRegisteredKeyCleanup([receipt]);
  assert.equal(helper.assertRegisteredCleanupComplete([receipt]), true);
  receipt.cleanupCompleted = false;
  helper.confirmRegisteredKeyCleanup([receipt]);
  assert.throws(() => helper.assertRegisteredCleanupComplete([receipt]));
});
test("capacity cleanup admits only exact six My identities with separate store ownership", () => {
  const registry = [];
  const receipt = helper.registerCapacityStoreCertificate(registry, {
    domain: "certops-adcs-0123456789-capacity0.example.test",
    certificateId: "22222222-2222-2222-2222-222222222222",
  });
  assert.equal(receipt.store, "My");
  assert.equal(registry[0], receipt);
  assert.throws(() => helper.cleanupPlan(receipt, [], () => null));
  assert.throws(() =>
    helper.registerCapacityStoreCertificate(registry, {
      domain: receipt.domain,
      certificateId: receipt.certificateId,
    }),
  );
  for (const domain of [
    "certops-adcs-0123456789-capacity6.example.test",
    "certops-adcs-0123456789-webhosting.example.test",
    "foreign.example.test",
  ]) {
    assert.throws(() =>
      helper.registerCapacityStoreCertificate([], {
        domain,
        certificateId: receipt.certificateId,
      }),
    );
  }
});
