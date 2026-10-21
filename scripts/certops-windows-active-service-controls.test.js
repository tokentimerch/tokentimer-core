"use strict";
/** Pure contract and guarded-public-tempfile tests only; no SCM/CNG/TLS calls. */
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  os = require("node:os"),
  path = require("node:path");
const h = require("../tests/e2e/helpers/certops-windows-active-service-controls");
function proof() {
  return {
    scope: h.SCOPE,
    controlCount: 3,
    certificateOperationInterruptionQualified: false,
    defaultLeaseGraceQualified: false,
    ...Object.fromEntries(h.FLAGS.map((k) => [k, true])),
  };
}
test("active SCM proof is distinct from idle controls and cannot claim interruption or default grace", () => {
  h.verifyProof(proof());
  for (const key of Object.keys(proof())) {
    const p = proof();
    delete p[key];
    assert.throws(() => h.verifyProof(p));
  }
  for (const key of h.FLAGS) {
    const p = proof();
    p[key] = false;
    assert.throws(() => h.verifyProof(p));
  }
  for (const patch of [
    {
      scope: require("../tests/e2e/helpers/certops-windows-service-controls")
        .SCOPE,
    },
    { certificateOperationInterruptionQualified: true },
    { defaultLeaseGraceQualified: true },
    { controlCount: 2 },
    { privateContainer: "secret" },
  ])
    assert.throws(() => h.verifyProof({ ...proof(), ...patch }));
});
test("actual active signed renewal claim is mandatory without coerced attempts or terminal states", () => {
  const row = {
    status: "running",
    operation: "renew",
    mode: "real",
    source: "automation",
    agent_id: "actual-agent",
    attempt_count: 1,
    claim_id: "11111111-1111-4111-8111-111111111111",
  };
  h.validateRunningClaim(row, "actual-agent");
  for (const patch of [
    { status: "succeeded" },
    { operation: "noop" },
    { mode: "dry_run" },
    { source: "manual" },
    { agent_id: "foreign" },
    { attempt_count: "1" },
    { attempt_count: 0 },
    { claim_id: null },
  ])
    assert.throws(() =>
      h.validateRunningClaim({ ...row, ...patch }, "actual-agent"),
    );
  assert.throws(() => h.pendingKeyScript("tokentimer-owned';Remove-Item"));
  assert.ok(
    h
      .pendingKeyScript(
        "tokentimer-11111111-1111-4111-8111-111111111111-abcdef12",
      )
      .includes("CngKey]::Open"),
  );
});
test("durable active-phase receipt independently blocks parent cleanup", () => {
  const root = fs.mkdtempSync(
    path.join(os.tmpdir(), "certops-active-scm-proof-"),
  );
  try {
    h.assertCleanupSafe(root);
    fs.writeFileSync(path.join(root, h.GUARD), "public-ownership-only");
    assert.throws(() => h.assertCleanupSafe(root));
    fs.unlinkSync(path.join(root, h.GUARD));
    h.assertCleanupSafe(root);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
test("pending key uses production managed-certificate namespace while journal binds a distinct job", () => {
  const store = require("../packages/agent/src/windows-cert-store");
  const certificateId = "11111111-1111-4111-8111-111111111111";
  const jobId = "22222222-2222-4222-8222-222222222222";
  const row = { subject_id: certificateId, payload: { certificateId } };
  const container = store.buildContainerName(certificateId);
  h.validatePendingContainer(container, row);
  assert.throws(() =>
    h.validatePendingContainer(store.buildContainerName(jobId), row),
  );
  assert.throws(() =>
    h.validatePendingContainer(container, {
      ...row,
      payload: { certificateId: jobId },
    }),
  );
  assert.throws(() => h.validatePendingContainer(container + "foreign", row));
  assert.throws(() =>
    h.validatePendingContainer(container, { ...row, subject_id: null }),
  );
});

test("active SCM TLS success and failure both await the retained socket close", async () => {
  const { EventEmitter } = require("node:events");
  for (const failure of [false, true]) {
    let secure,
      settled = false;
    const socket = new EventEmitter();
    socket.authorized = true;
    socket.getPeerCertificate = () => ({ fingerprint: "AA:BB" });
    socket.setTimeout = () => socket;
    socket.end = () => {};
    const promise = h.trustedBoundLeaf(
      {
        domain: "owned.example.test",
        port: 443,
        roots: [{ pem: "-----BEGIN CERTIFICATE----- public fixture" }],
        thumbprint: "AABB",
      },
      (_options, callback) => {
        secure = callback;
        return socket;
      },
    );
    const observed = promise.then(
      () => {
        settled = true;
        return "passed";
      },
      () => {
        settled = true;
        return "failed";
      },
    );
    secure();
    if (failure) socket.emit("error", new Error("controlled error"));
    await Promise.resolve();
    assert.equal(settled, false);
    socket.emit("close", failure);
    assert.equal(await observed, failure ? "failed" : "passed");
  }
});

test("actual reporter reads bounded active-control sidecars for every Windows profile", () => {
  const reporter = require("./certops-stack-reporter"),
    root = fs.mkdtempSync(
      path.join(os.tmpdir(), "certops-active-scm-reporter-"),
    ),
    dir = path.join(root, "qualification-results");
  fs.mkdirSync(dir);
  const name =
    "real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence";
  try {
    for (const profile of [
      "rsa-2048",
      "rsa-3072",
      "rsa-4096",
      "ec-p256",
      "ec-p384",
    ]) {
      const scope = "real-agent-windows-acme-iis/" + profile,
        file = path.join(
          dir,
          `windows-active-service-controls-${profile}.json`,
        );
      assert.throws(() =>
        reporter.activeServiceControlsProof(scope, name, root),
      );
      fs.writeFileSync(file, JSON.stringify(proof()));
      assert.deepEqual(
        reporter.activeServiceControlsProof(scope, name, root),
        proof(),
      );
      fs.writeFileSync(
        file,
        JSON.stringify({ ...proof(), actualDnsPostBarrier: false }),
      );
      assert.throws(() =>
        reporter.activeServiceControlsProof(scope, name, root),
      );
      fs.writeFileSync(file, " ".repeat(16385));
      assert.throws(() =>
        reporter.activeServiceControlsProof(scope, name, root),
      );
    }
    assert.equal(
      reporter.activeServiceControlsProof(
        "real-agent-acme-filesystem",
        name,
        root,
      ),
      undefined,
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
