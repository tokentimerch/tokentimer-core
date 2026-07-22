"use strict";

// Phase 4 agent runtime trust layer, end-to-end against the fake control
// plane (tests/integration/fake-agent.js in signed-dispatch mode). No DB.
//
// Exercises the agent-side verification chain DIRECTLY
// (signing.verifyJobSignature -> replay cache -> signing.checkJobTimeWindow)
// rather than via packages/agent/src/index.js. The full dispatch wiring in
// src/index.js is exercised end to end by agent-renewal.test.js; this suite
// keeps direct coverage of the chain order the wiring must preserve:
// integrity first (never trust an unverified
// payload's fields), then replay, then time window, and consume() only
// after every gate passes.
//
// Also asserts the custody invariant: no private-key-shaped content ever
// appears in any protocol message the harness records (field-name ban
// approach reused from tests/unit/certops-agent-protocol-contracts.test.js).

const os = require("node:os");
const path = require("node:path");
const fs = require("node:fs");
const crypto = require("node:crypto");

const { expect } = require("./setup");
const {
  buildFakeAgentControlPlaneApp,
  createFakeAgent,
} = require("./fake-agent");
const {
  verifyJobSignature,
  checkJobTimeWindow,
} = require("../../packages/agent/src/signing");
const {
  createReplayCache,
} = require("../../packages/agent/src/replay");

// Same custody vocabulary as certops-agent-protocol-contracts.test.js.
const FORBIDDEN_FIELD_FRAGMENTS = [
  "privatekey",
  "privatekeypem",
  "encryptedprivatekey",
  "keymaterial",
  "pfxblob",
  "jksblob",
  "tlskey",
  "caprivatekey",
  "keystorepassword",
  "privatekeypassword",
  "keypassword",
  "password",
  "secret",
  "rawsecret",
  "rawprivatekey",
  "keypem",
];

// Non-secret reference names legitimately present in the protocol.
const ALLOWED_CREDENTIAL_ADJACENT_NAMES = new Set(["bootstrapTokenId"]);

function normalizeFieldName(name) {
  return name.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function collectFieldNames(value, names = []) {
  if (Array.isArray(value)) {
    for (const item of value) collectFieldNames(item, names);
    return names;
  }
  if (value === null || typeof value !== "object") return names;
  for (const [key, child] of Object.entries(value)) {
    names.push(key);
    collectFieldNames(child, names);
  }
  return names;
}

function assertNoCustodyShapedContent(payload, label) {
  for (const fieldName of collectFieldNames(payload)) {
    if (ALLOWED_CREDENTIAL_ADJACENT_NAMES.has(fieldName)) continue;
    const normalized = normalizeFieldName(fieldName);
    const hit = FORBIDDEN_FIELD_FRAGMENTS.find((fragment) =>
      normalized.includes(fragment),
    );
    expect(hit, `${label} carries custody-shaped field "${fieldName}"`).to.equal(
      undefined,
    );
  }
  // Belt and braces beyond field names: no PEM private-key block anywhere
  // in the serialized payload either.
  expect(JSON.stringify(payload)).to.not.match(/-----BEGIN [A-Z ]*PRIVATE KEY-----/);
}

const tempDirs = [];

function makeReplayStorePath() {
  const dir = fs.mkdtempSync(
    path.join(os.tmpdir(), "tokentimer-agent-protocol-test-"),
  );
  tempDirs.push(dir);
  return path.join(dir, "replay-store.json");
}

// The full agent-side verification chain in dispatch-wiring order.
function runVerificationChain({ job, publicKeyPem, pinnedSigningKeyId, replayCache }) {
  const integrity = verifyJobSignature({ job, publicKeyPem, pinnedSigningKeyId });
  if (!integrity.allowed) return integrity;

  const replay = replayCache.check({
    nonce: job.nonce,
    jobId: job.jobId,
    expiresAt: job.expiresAt,
  });
  if (!replay.allowed) return replay;

  const window = checkJobTimeWindow({ job, nowMs: Date.now() });
  if (!window.allowed) return window;

  return replayCache.consume({
    nonce: job.nonce,
    jobId: job.jobId,
    expiresAt: job.expiresAt,
  });
}

describe("agent protocol trust layer (signed dispatch, Phase 4)", function () {
  this.timeout(30000);

  after(() => {
    while (tempDirs.length > 0) {
      const dir = tempDirs.pop();
      try {
        fs.rmSync(dir, { recursive: true, force: true });
      } catch (_err) {
        // best-effort cleanup
      }
    }
  });

  async function setupSignedWorld() {
    const app = buildFakeAgentControlPlaneApp({ signedJobDispatch: true });
    const agent = createFakeAgent({ app });

    const registerResponse = await agent.register({ agentVersion: "1.0.0" });
    expect(registerResponse.status).to.equal(201);
    // The register response advertises the pinning info in signed mode.
    expect(registerResponse.body.signingKeyId).to.be.a("string");
    expect(registerResponse.body.signingPublicKeyPem).to.match(
      /-----BEGIN PUBLIC KEY-----/,
    );
    expect(registerResponse.body.signingKeyId).to.equal(
      app.getSigningKeyInfo().signingKeyId,
    );

    const replayCache = createReplayCache({ storePath: makeReplayStorePath() });

    return {
      app,
      agent,
      replayCache,
      publicKeyPem: registerResponse.body.signingPublicKeyPem,
      pinnedSigningKeyId: registerResponse.body.signingKeyId,
    };
  }

  async function claimOneJob(agent) {
    const response = await agent.claim({ maxJobs: 1 });
    expect(response.status).to.equal(200);
    expect(response.body.jobs).to.have.length(1);
    return response.body.jobs[0];
  }

  it("happy path: a valid signed job passes integrity, replay, and time-window checks", async () => {
    const world = await setupSignedWorld();
    world.app.dispatchSignedJob();

    const job = await claimOneJob(world.agent);
    expect(job.signature).to.be.a("string");
    expect(job.signingKeyId).to.equal(world.pinnedSigningKeyId);
    expect(job.nonce).to.be.a("string");

    const result = runVerificationChain({
      job,
      publicKeyPem: world.publicKeyPem,
      pinnedSigningKeyId: world.pinnedSigningKeyId,
      replayCache: world.replayCache,
    });
    expect(result).to.deep.equal({ allowed: true });
  });

  it("tampered payload => job_integrity_failed", async () => {
    const world = await setupSignedWorld();
    world.app.dispatchTamperedJob({ tamperField: "action", tamperValue: "revoke" });

    const job = await claimOneJob(world.agent);
    const result = runVerificationChain({
      job,
      publicKeyPem: world.publicKeyPem,
      pinnedSigningKeyId: world.pinnedSigningKeyId,
      replayCache: world.replayCache,
    });
    expect(result.allowed).to.equal(false);
    expect(result.rejectionReason).to.equal("job_integrity_failed");
    expect(result.detail).to.be.a("string").that.is.not.empty;
  });

  it("replayed nonce+jobId => second delivery rejected with job_replay_rejected", async () => {
    const world = await setupSignedWorld();
    world.app.dispatchReplayedJob();

    const firstDelivery = await claimOneJob(world.agent);
    const firstResult = runVerificationChain({
      job: firstDelivery,
      publicKeyPem: world.publicKeyPem,
      pinnedSigningKeyId: world.pinnedSigningKeyId,
      replayCache: world.replayCache,
    });
    expect(firstResult).to.deep.equal({ allowed: true });

    const secondDelivery = await claimOneJob(world.agent);
    expect(secondDelivery.nonce).to.equal(firstDelivery.nonce);
    expect(secondDelivery.jobId).to.equal(firstDelivery.jobId);

    const secondResult = runVerificationChain({
      job: secondDelivery,
      publicKeyPem: world.publicKeyPem,
      pinnedSigningKeyId: world.pinnedSigningKeyId,
      replayCache: world.replayCache,
    });
    expect(secondResult.allowed).to.equal(false);
    expect(secondResult.rejectionReason).to.equal("job_replay_rejected");
  });

  it("expired window => clock_drift_suspected (documented semantics: window failures read as drift)", async () => {
    const world = await setupSignedWorld();
    world.app.dispatchExpiredJob();

    const job = await claimOneJob(world.agent);
    const result = runVerificationChain({
      job,
      publicKeyPem: world.publicKeyPem,
      pinnedSigningKeyId: world.pinnedSigningKeyId,
      replayCache: world.replayCache,
    });
    expect(result.allowed).to.equal(false);
    // Per the signing module's documented semantics, an expired-but-well-
    // formed window rejects as clock_drift_suspected (a genuinely stale
    // replay is independently caught by the replay cache).
    expect(result.rejectionReason).to.equal("clock_drift_suspected");
    // An expired rejection must NOT consume the nonce (the chain stops
    // before consume), so state stays clean.
    expect(world.replayCache.size()).to.equal(0);
  });

  it("wrong key, variant wrong-signature (rogue key claims pinned key id) => job_integrity_failed", async () => {
    const world = await setupSignedWorld();
    world.app.dispatchWrongKeyJob({ variant: "wrong-signature" });

    const job = await claimOneJob(world.agent);
    expect(job.signingKeyId).to.equal(world.pinnedSigningKeyId);

    const result = runVerificationChain({
      job,
      publicKeyPem: world.publicKeyPem,
      pinnedSigningKeyId: world.pinnedSigningKeyId,
      replayCache: world.replayCache,
    });
    expect(result.allowed).to.equal(false);
    expect(result.rejectionReason).to.equal("job_integrity_failed");
  });

  it("wrong key, variant wrong-key-id (unpinned key id) => job_integrity_failed mentioning the mismatch", async () => {
    const world = await setupSignedWorld();
    world.app.dispatchWrongKeyJob({ variant: "wrong-key-id" });

    const job = await claimOneJob(world.agent);
    expect(job.signingKeyId).to.not.equal(world.pinnedSigningKeyId);

    const result = runVerificationChain({
      job,
      publicKeyPem: world.publicKeyPem,
      pinnedSigningKeyId: world.pinnedSigningKeyId,
      replayCache: world.replayCache,
    });
    expect(result.allowed).to.equal(false);
    expect(result.rejectionReason).to.equal("job_integrity_failed");
    expect(result.detail).to.match(/key id mismatch/i);
  });

  it("rejections report uniformly through the result path with the policy-compatible shape", async () => {
    const world = await setupSignedWorld();
    world.app.dispatchTamperedJob();
    const job = await claimOneJob(world.agent);

    const rejection = runVerificationChain({
      job,
      publicKeyPem: world.publicKeyPem,
      pinnedSigningKeyId: world.pinnedSigningKeyId,
      replayCache: world.replayCache,
    });
    // Shape parity with the policy module's rejection results, so the
    // downstream evidence/result reporting handles both uniformly.
    expect(Object.keys(rejection).sort()).to.deep.equal([
      "allowed",
      "detail",
      "rejectionReason",
    ]);

    const resultResponse = await world.agent.reportResult({
      jobId: job.jobId,
      attemptId: `attempt-${crypto.randomUUID()}`,
      status: "rejected",
      rejectionReason: rejection.rejectionReason,
    });
    expect(resultResponse.status).to.equal(202);
    expect(world.app.state.results).to.have.length(1);
    expect(world.app.state.results[0].body.rejectionReason).to.equal(
      "job_integrity_failed",
    );
  });

  it("no private-key-shaped content appears in any recorded protocol message or dispatched job", async () => {
    const world = await setupSignedWorld();

    world.app.dispatchSignedJob();
    world.app.dispatchTamperedJob();
    world.app.dispatchExpiredJob();
    world.app.dispatchWrongKeyJob({ variant: "wrong-signature" });
    world.app.dispatchWrongKeyJob({ variant: "wrong-key-id" });

    await world.agent.heartbeat({
      agentVersion: "1.0.0",
      pinnedSigningKeyId: world.pinnedSigningKeyId,
    });
    const claimResponse = await world.agent.claim({ maxJobs: 16 });
    expect(claimResponse.body.jobs.length).to.be.greaterThan(0);
    await world.agent.reportResult({
      jobId: claimResponse.body.jobs[0].jobId,
      attemptId: `attempt-${crypto.randomUUID()}`,
      status: "rejected",
      rejectionReason: "job_integrity_failed",
    });

    const { state } = world.app;
    for (const [label, payloads] of Object.entries({
      heartbeats: state.heartbeats,
      claims: state.claims,
      results: state.results,
      evidence: state.evidence,
      dispatchedJobs: claimResponse.body.jobs,
    })) {
      for (const payload of payloads) {
        assertNoCustodyShapedContent(payload, `state.${label}`);
      }
    }

    // The register response itself carries the PUBLIC pinning material only.
    assertNoCustodyShapedContent(
      { signingKeyId: world.pinnedSigningKeyId },
      "register pinning info",
    );
    expect(world.publicKeyPem).to.match(/-----BEGIN PUBLIC KEY-----/);
    expect(world.publicKeyPem).to.not.match(/PRIVATE KEY/);
  });

  it("keeps unsigned mode untouched: default app still returns empty job lists", async () => {
    const app = buildFakeAgentControlPlaneApp();
    expect(app.dispatchSignedJob).to.equal(undefined);
    expect(app.getSigningKeyInfo).to.equal(undefined);

    const agent = createFakeAgent({ app });
    await agent.register({ agentVersion: "1.0.0" });
    const response = await agent.claim({ maxJobs: 5 });
    expect(response.body.jobs).to.deep.equal([]);
  });
});
