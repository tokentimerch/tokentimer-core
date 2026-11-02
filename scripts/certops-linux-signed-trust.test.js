"use strict";
/** Offline signed-trust producer checks. Manual workflow_dispatch only. Not native qualification. */
const test = require("node:test"),
  assert = require("node:assert/strict"),
  h = require("./certops-linux-signed-trust-proof"),
  { nativeProof } = require("./test-support/linux-signed-trust-artifact.cjs"),
  { assertJob, identity } = require("./certops-linux-signed-trust");

test("actual idle-stop wiring binds original child with zero-argument close callback", async () => {
  const { stopOwnedAgent } = require("./certops-linux-signed-trust"),
    child = {},
    closed = new WeakSet(),
    resources = [];
  let observed,
    drained = 0;
  const retained = {
    stopAndDrain() {
      drained++;
      return Promise.resolve();
    },
  };
  assert.equal(
    await stopOwnedAgent(
      {
        child,
        entry: "owned-entry",
        configDir: "owned-config",
        resources,
        closed,
        startTicks: "123",
        waitUntil: () => {},
      },
      (options) => {
        observed = options;
        assert.equal(options.isAgentClosed(), false);
        closed.add(child);
        assert.equal(options.isAgentClosed(), true);
        return Promise.resolve(retained);
      },
    ),
    retained,
  );
  assert.equal(observed.agent, child);
  assert.equal(observed.expectedStartTicks, "123");
  assert.equal(drained, 1);
});
test("signed trust proof requires every native observation and distinct actual claims", () => {
  const p = nativeProof();
  h.verifyProof(p);
  for (const field of Object.keys(p)) {
    const q = structuredClone(p);
    delete q[field];
    assert.throws(() => h.verifyProof(q));
  }
  for (const flag of h.FLAGS)
    assert.throws(() => h.verifyProof({ ...p, [flag]: false }));
  for (const q of [
    { ...p, backgroundReconciliationQualified: true },
    { ...p, jobIds: [p.jobIds[0], p.jobIds[0], ...p.jobIds.slice(2)] },
    { ...p, privateKey: "must-not-enter-proof" },
  ])
    assert.throws(() => h.verifyProof(q));
});
test("actual native runner job oracle binds signed subject/agent/payload/current claim", () => {
  const p = nativeProof(),
    expected = {
      operation: "distribute-trust",
      anchorId: p.anchorIds[0],
      agentId: p.agentId,
      fingerprint: p.fingerprints[0],
      anchorType: "root",
    },
    row = {
      status: "succeeded",
      operation: expected.operation,
      subject_type: "trust_anchor",
      subject_id: expected.anchorId,
      assigned_agent_id: p.agentId,
      claimed_by_agent_id: p.agentId,
      attempt_count: 1,
      claim_id: p.claimIds[0],
      payload: {
        trustAnchorId: expected.anchorId,
        fingerprintSha256: expected.fingerprint,
        anchorType: "root",
      },
    };
  assertJob(row, expected);
  for (const patch of [
    { claimed_by_agent_id: p.workspaceId },
    { assigned_agent_id: p.workspaceId },
    { attempt_count: 2 },
    { status: "failed" },
    { payload: { ...row.payload, anchorType: "intermediate" } },
    { subject_id: p.anchorIds[1] },
  ])
    assert.throws(() => assertJob({ ...row, ...patch }, expected));
});
test("original directory identity distinguishes same-path foreign replacements with benign public files", () => {
  const fs = require("node:fs"),
    path = require("node:path"),
    os = require("node:os"),
    root = fs.mkdtempSync(path.join(os.tmpdir(), "signed-trust-identity-")),
    item = path.join(root, "owned"),
    moved = path.join(root, "old");
  try {
    fs.mkdirSync(item);
    const original = identity(item);
    fs.renameSync(item, moved);
    fs.mkdirSync(item);
    fs.writeFileSync(path.join(item, "foreign"), "public");
    assert.notDeepEqual(identity(item), original);
    assert.equal(fs.readFileSync(path.join(item, "foreign"), "utf8"), "public");
  } finally {
    fs.rmSync(root, { recursive: true });
  }
});
