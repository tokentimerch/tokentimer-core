"use strict";
/** Synthetic proof and real owned-file guards only. No native certificate,
 * service, endpoint, client, API or CA operation executes in these checks. */
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  os = require("node:os");
const h = require("../tests/e2e/helpers/certops-windows-installed-verify-rollback");
const certificateId = "11111111-1111-4111-8111-111111111111",
  jobId = "22222222-2222-4222-8222-222222222222",
  claimId = "33333333-3333-4333-8333-333333333333";
const {
  fixture,
} = require("./fixtures/certops-windows-installed-verify-rollback.cjs");

test("owned sibling removal embeds fresh exact tuple validation before its destructive command", () => {
  const expected = {
    site: "OwnedSite",
    id: 42,
    path: "C:\\owned [path]",
    coordinates: "*:443:owned.example.test",
    flags: 1,
    store: "My",
    thumb: "A".repeat(40),
  };
  const script = h.removeOwnedSiteScript(
    "OwnedSite",
    "owned.example.test",
    443,
    expected,
  );
  assert.ok(
    script.indexOf("Changed owned sibling site preserved") <
      script.indexOf("Remove-Website"),
  );
  assert.ok(
    script.includes(Buffer.from(JSON.stringify(expected)).toString("base64")),
  );
  assert.throws(() =>
    h.removeOwnedSiteScript(
      "foreign';Remove-Item",
      "owned.example.test",
      443,
      expected,
    ),
  );
});

test("installed verification rollback proof requires every measured fact and distinguishes unsupported outcomes", () => {
  h.verifyProof(fixture());
  for (const key of Object.keys(fixture())) {
    const bad = fixture();
    delete bad[key];
    assert.throws(() => h.verifyProof(bad), key);
  }
  for (const flag of h.FLAGS)
    assert.throws(() => h.verifyProof({ ...fixture(), [flag]: false }), flag);
  for (const patch of [
    { failureCode: "BIND_FAILED" },
    { rolledBack: false },
    { retryJobStatus: "failed" },
    { bindFailureQualified: true },
    { rollbackFailureQualified: true },
    { expiryCleanupQualified: true },
    { transientNewBindingObservationQualified: true },
    { appIdPreservationQualified: true },
    { privateKey: "secret" },
    { jobIds: [jobId, jobId] },
    { claimIds: [claimId, claimId] },
    { fingerprints: Array(3).fill("a".repeat(64)) },
  ])
    assert.throws(() => h.verifyProof({ ...fixture(), ...patch }));
  for (const file of h.REQUIRED_SOURCES)
    assert.ok(fs.statSync(path.resolve(__dirname, "..", file)).isFile(), file);
});
test("current claim and accepted receipt use actual production generated ownership shape", () => {
  const row = {
    id: jobId,
    status: "failed",
    operation: "renew",
    mode: "real",
    source: "api",
    subject_id: certificateId,
    agent_id: "owned-installed-agent",
    attempt_count: 1,
    claim_id: claimId,
    payload: { certificateId },
  };
  h.validateClaim(row, { certificateId, agentId: row.agent_id });
  for (const patch of [
    { source: "automation" },
    { attempt_count: "1" },
    { agent_id: "foreign-agent" },
    { mode: "dry_run" },
    { claim_id: null },
    { payload: { certificateId: jobId } },
  ])
    assert.throws(() =>
      h.validateClaim(
        { ...row, ...patch },
        { certificateId, agentId: row.agent_id },
      ),
    );
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "certops-verify-record-"));
  try {
    const store = require("../packages/agent/src/windows-cert-store"),
      containerName = store.buildContainerName(certificateId),
      thumb = "A".repeat(40);
    store.recordIssuedContainer({
      stateDir: root,
      containerName,
      jobId,
      certificateId,
    });
    store.markIssuedContainerAccepted({
      stateDir: root,
      containerName,
      acceptedThumbprint: thumb,
      store: "My",
    });
    const record = store.readIssuedContainerRecord({
      stateDir: root,
      containerName,
    });
    h.validateIssued(record, jobId, certificateId, thumb);
    for (const patch of [
      { status: "generated" },
      { jobId: claimId },
      { certificateId: jobId },
      { acceptedStore: "WebHosting" },
      { acceptedThumbprint: "B".repeat(40) },
      { containerName: store.buildContainerName(jobId) },
    ])
      assert.throws(() =>
        h.validateIssued({ ...record, ...patch }, jobId, certificateId, thumb),
      );
  } finally {
    fs.rmSync(root, { recursive: true });
  }
});
test("native endpoint admission and exact restoration refuse wildcard siblings and foreign replacements", () => {
  const host = {
    keyedBy: "hostnameport",
    ipPort: "owned.example.test:443",
    thumbprint: "A".repeat(40),
    storeName: "My",
    appId: "{11111111-1111-4111-8111-111111111111}",
    settings: { DefaultFlags: 0 },
  };
  h.assertNoShadow([host], 443, "owned.example.test");
  for (const foreign of [
    { ...host, keyedBy: "ipport", ipPort: "127.0.0.1:443" },
    { ...host, keyedBy: "ipport", ipPort: "0.0.0.0:443" },
    { ...host, keyedBy: "ipport", ipPort: "[::]:443" },
    { ...host, ipPort: "foreign.example.test:443" },
  ])
    assert.throws(() =>
      h.assertNoShadow([host, foreign], 443, "owned.example.test"),
    );
  h.assertOwnedEndpoint(structuredClone(host), host);
  h.assertPrimaryRestored(
    { ...host, appId: "{22222222-2222-4222-8222-222222222222}" },
    host,
  );
  assert.throws(() =>
    h.assertPrimaryRestored({ ...host, appId: "not-a-guid" }, host),
  );
  assert.throws(() =>
    h.assertPrimaryRestored({ ...host, settings: { DefaultFlags: 1 } }, host),
  );
  for (const patch of [
    { thumbprint: "B".repeat(40) },
    { storeName: "WebHosting" },
    { appId: "{foreign}" },
    { settings: { DefaultFlags: 1 } },
  ])
    assert.throws(() => h.assertOwnedEndpoint({ ...host, ...patch }, host));
});
test("lost or same-byte replaced verification guard cannot authorize borrowed native cleanup", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "certops-verify-guard-")),
    registry = [];
  const guard = path.join(root, h.GUARD),
    saved = path.join(root, "saved.guard");
  try {
    const owner = h.beginGuard(root, registry),
      original = fs.readFileSync(guard);
    assert.throws(() => h.assertCleanupSafe(root));
    fs.renameSync(guard, saved);
    assert.throws(() => h.assertCleanupSafe(root));
    assert.throws(() => owner.release());
    assert.equal(registry[0].cleanupCompleted, false);
    fs.writeFileSync(guard, original, { flag: "wx" });
    assert.throws(() => owner.release());
    assert.ok(fs.readFileSync(guard).equals(original));
    fs.unlinkSync(guard);
    fs.renameSync(saved, guard);
    owner.release();
    h.assertCleanupSafe(root);
    assert.equal(registry[0].cleanupCompleted, true);
  } finally {
    fs.rmSync(root, { recursive: true });
  }
});
