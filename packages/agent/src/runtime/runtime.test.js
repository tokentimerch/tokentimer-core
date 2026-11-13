"use strict";

/**
 * Runtime tests for fail-closed lease renew, side-effect journal, and
 * transactional multi-target deploy. Lives under src/runtime/ so the package
 * test glob (src nested *.test.js without globstar) picks it up.
 */

const { describe, it, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  handleClaimedJob,
  buildExecutionContext,
  executeDeployJob,
  renewJobLeaseOrAbort,
  createLeaseState,
} = require("../index.js");
const {
  markSideEffectReached,
  scanUnresolvedJournalEntries,
  hasUnresolvedJournalForJob,
  clearJournalOnTerminal,
} = require("../job-journal");
const { loadPolicyConfig, createPolicyEngine } = require("../policy");
const { generateSigningKeyPair, signJobPayload } = require("../signing");
const {
  AGENT_PROTOCOL_ERROR_CODES,
  AgentProtocolError,
  createProtocolClient,
} = require("../protocol");

function makeTempConfigDir() {
  // See index.test.js's makeTempConfigDir for why .native is required.
  return fs.realpathSync.native(
    fs.mkdtempSync(path.join(os.tmpdir(), "ttagent-runtime-test-")),
  );
}

function createRecordingClient() {
  const calls = { register: [], reportResult: [], reportEvidence: [], renewLease: [] };
  return {
    calls,
    register: (params) => {
      calls.register.push(params);
      return Promise.resolve({
        agentId: "agent-assigned-1",
        credential: "ttagent_agent-assigned-1_0123456789abcdef",
        protocolVersion: "1.0.0",
      });
    },
    reportResult: (params) => {
      calls.reportResult.push(params);
      return Promise.resolve({});
    },
    reportEvidence: (params) => {
      calls.reportEvidence.push(params);
      return Promise.resolve({});
    },
    renewLease: (params) => {
      calls.renewLease.push(params);
      return Promise.resolve({
        ok: true,
        jobId: params.jobId,
        status: "running",
        claimId: params.claimId,
        leaseExpiresAt: new Date(Date.now() + 15 * 60 * 1000).toISOString(),
      });
    },
  };
}

function engineWith(policy = {}, options = {}) {
  return createPolicyEngine(loadPolicyConfig(policy), options);
}

const silentLog = () => {};

/**
 * Fixed, non-empty stand-in for a real agent's registered identity (see the
 * matching constant/comment in ../index.test.js). checkAgentIdBinding
 * requires a non-empty boundAgentId unconditionally; these tests do not
 * themselves exercise ADR-0012 decision 3's agentId binding.
 */
const TEST_BOUND_AGENT_ID = "agent-test-bound-1";

describe("agent runtime: lease, journal, multi-target transaction", () => {
  let workDir;
  let signingKey;

  beforeEach(() => {
    workDir = makeTempConfigDir();
    signingKey = generateSigningKeyPair();
  });

  afterEach(() => {
    fs.rmSync(workDir, { recursive: true, force: true });
  });

  function makeExecutionContext({ dryRun = false } = {}) {
    const keysDir = path.join(workDir, "keys");
    const config = {
      execution: {
        enabled: true,
        dryRun,
        keysDir,
        replayStorePath: path.join(workDir, "replay-store.json"),
        outboxDir: path.join(workDir, "outbox"),
        clockDriftToleranceMs: 30_000,
      },
      pinnedSigningKey: {
        signingKeyId: signingKey.signingKeyId,
        publicKeyPem: signingKey.publicKeyPem,
      },
    };
    return buildExecutionContext({ config });
  }

  function makeSignedJob(overrides = {}) {
    const nowMs = Date.now();
    const job = {
      schemaVersion: 1,
      jobId: "job-lease-journal",
      attemptId: "attempt-1",
      workspaceId: "11111111-1111-4111-8111-111111111111",
      agentId: TEST_BOUND_AGENT_ID,
      certificateId: "certificate-1",
      action: "noop",
      target: { type: "domain", reference: "example.com" },
      keyMode: "agent-local",
      requestedAt: new Date(nowMs).toISOString(),
      issuedAt: new Date(nowMs).toISOString(),
      expiresAt: new Date(nowMs + 5 * 60 * 1000).toISOString(),
      nonce: `nonce-${Math.random().toString(16).slice(2)}-0123456789abcdef`,
      claimId: "claim-1",
      mode: "real",
      signingKeyId: signingKey.signingKeyId,
      ...overrides,
    };
    job.signature = signJobPayload({
      job,
      privateKeyPem: signingKey.privateKeyPem,
    });
    return job;
  }

  function permissiveEngine(selectors = ["example.com", "valid.example.com"]) {
    return engineWith(
      { allowedPaths: [workDir] },
      { declaredTargetSelectors: selectors },
    );
  }

  function readFixture(name) {
    return fs.readFileSync(
      path.join(__dirname, "..", "verify", "fixtures", name),
      "utf8",
    );
  }

  function assertNoPrivateKeyMaterial(value) {
    const text = typeof value === "string" ? value : JSON.stringify(value);
    assert.doesNotMatch(text, /BEGIN [A-Z0-9 ]*PRIVATE KEY/);
  }

  it("blocks execution when the mandatory first lease renew fails with a network error", async () => {
    const client = createRecordingClient();
    client.renewLease = async (params) => {
      client.calls.renewLease.push(params);
      throw new AgentProtocolError(
        "network request to control plane failed",
        AGENT_PROTOCOL_ERROR_CODES.NETWORK_ERROR,
      );
    };
    const outcome = await handleClaimedJob({
      job: makeSignedJob({ action: "noop", claimId: "claim-lease-soft" }),
      policyEngine: permissiveEngine(),
      client,
      executionContext: makeExecutionContext(),
      boundAgentId: TEST_BOUND_AGENT_ID,
      log: silentLog,
    });
    assert.equal(outcome.status, "blocked");
    assert.equal(client.calls.renewLease.length, 1);
    assert.match(client.calls.reportResult[0].errorMessage, /mandatory confirmation failed/);
  });

  it("aborts immediately on first-lease HTTP 409 without executing", async () => {
    const client = createRecordingClient();
    client.renewLease = async (params) => {
      client.calls.renewLease.push(params);
      return { ok: false, status: 409, code: "CERTOPS_AGENT_CLAIM_OWNERSHIP_MISMATCH" };
    };
    const outcome = await handleClaimedJob({
      job: makeSignedJob({ action: "noop", claimId: "claim-409" }),
      policyEngine: permissiveEngine(),
      client,
      executionContext: makeExecutionContext(),
      boundAgentId: TEST_BOUND_AGENT_ID,
      log: silentLog,
    });
    assert.equal(outcome.status, "blocked");
    assert.equal(client.calls.renewLease.length, 1);
    assert.match(client.calls.reportResult[0].errorMessage, /HTTP 409/);
  });

  it("retries a rate-limited mandatory material lease only before confirmed expiry", async () => {
    const leaseState = createLeaseState();
    let nowMs = 1_000, attempts = 0;
    leaseState.lastConfirmedExpiresAtMs = 10_000;
    const gate = await renewJobLeaseOrAbort({
      leaseClient: { renewLease: async () => {
        if (++attempts === 1) throw Object.assign(new AgentProtocolError("limited", AGENT_PROTOCOL_ERROR_CODES.HTTP_ERROR, { status: 429 }), { retryAfterMs: 2_000 });
        return { ok: true, leaseExpiresAt: new Date(20_000).toISOString() };
      } },
      jobId: "job-rate", claimId: "claim-rate", leaseState, required: true,
      now: () => nowMs, sleep: async (ms) => { nowMs += ms; }, log: silentLog,
    });
    assert.equal(gate.ok, true);
    assert.equal(attempts, 2);
    assert.equal(nowMs, 3_000);
  });

  it("does not wait or execute after a rate limit exceeds the confirmed lease", async () => {
    const leaseState = createLeaseState();
    leaseState.lastConfirmedExpiresAtMs = 2_000;
    let attempts = 0, slept = false;
    const gate = await renewJobLeaseOrAbort({
      leaseClient: { renewLease: async () => { attempts++; throw Object.assign(new AgentProtocolError("limited", AGENT_PROTOCOL_ERROR_CODES.HTTP_ERROR, { status: 429 }), { retryAfterMs: 2_000 }); } },
      jobId: "job-rate-expiry", claimId: "claim-rate-expiry", leaseState, required: true,
      now: () => 1_000, sleep: async () => { slept = true; }, log: silentLog,
    });
    assert.equal(gate.ok, false);
    assert.equal(attempts, 1);
    assert.equal(slept, false);
  });

  it("still rejects ownership loss after waiting for a rate limit", async () => {
    const leaseState = createLeaseState();
    leaseState.lastConfirmedExpiresAtMs = 10_000;
    let nowMs = 1_000, attempts = 0;
    const gate = await renewJobLeaseOrAbort({
      leaseClient: { renewLease: async () => {
        if (++attempts === 1) throw Object.assign(new AgentProtocolError("limited", AGENT_PROTOCOL_ERROR_CODES.HTTP_ERROR, { status: 429 }), { retryAfterMs: 1_000 });
        return { ok: false, status: 409, code: "CERTOPS_AGENT_CLAIM_OWNERSHIP_MISMATCH" };
      } },
      jobId: "job-rate-conflict", claimId: "claim-rate-conflict", leaseState, required: true,
      now: () => nowMs, sleep: async (ms) => { nowMs += ms; }, log: silentLog,
    });
    assert.equal(gate.ok, false);
    assert.equal(attempts, 2);
    assert.match(gate.abort.errorMessage, /HTTP 409/);
  });

  it("does not retry a first mandatory lease without confirmed expiry", async () => {
    let attempts = 0;
    const gate = await renewJobLeaseOrAbort({
      leaseClient: { renewLease: async () => { attempts++; throw Object.assign(new AgentProtocolError("limited", AGENT_PROTOCOL_ERROR_CODES.HTTP_ERROR, { status: 429 }), { retryAfterMs: 1_000 }); } },
      jobId: "job-rate-first", claimId: "claim-rate-first", leaseState: createLeaseState(), required: true,
      sleep: async () => { throw new Error("must not sleep"); }, log: silentLog,
    });
    assert.equal(gate.ok, false);
    assert.equal(attempts, 1);
  });

  it("aborts if the confirmed lease expires while waiting for rate limiting", async () => {
    const leaseState = createLeaseState();
    leaseState.lastConfirmedExpiresAtMs = 3_000;
    let nowMs = 1_000, attempts = 0;
    const gate = await renewJobLeaseOrAbort({
      leaseClient: { renewLease: async () => { attempts++; throw Object.assign(new AgentProtocolError("limited", AGENT_PROTOCOL_ERROR_CODES.HTTP_ERROR, { status: 429 }), { retryAfterMs: 1_000 }); } },
      jobId: "job-rate-oversleep", claimId: "claim-rate-oversleep", leaseState, required: true,
      now: () => nowMs, sleep: async () => { nowMs = 3_001; }, log: silentLog,
    });
    assert.equal(gate.ok, false);
    assert.equal(attempts, 1);
  });

  it("bounds repeated rate-limit retries even with a frozen clock", async () => {
    const leaseState = createLeaseState();
    leaseState.lastConfirmedExpiresAtMs = 100_000;
    let attempts = 0;
    const gate = await renewJobLeaseOrAbort({
      leaseClient: { renewLease: async () => { attempts++; throw Object.assign(new AgentProtocolError("limited", AGENT_PROTOCOL_ERROR_CODES.HTTP_ERROR, { status: 429 }), { retryAfterMs: 1_000 }); } },
      jobId: "job-rate-loop", claimId: "claim-rate-loop", leaseState, required: true,
      now: () => 1_000, sleep: async () => {}, log: silentLog,
    });
    assert.equal(gate.ok, false);
    assert.equal(attempts, 4);
  });

  it("retries a real protocol 429 with a new sequence before allowing a material boundary", async () => {
    const leaseState = createLeaseState();
    leaseState.lastConfirmedExpiresAtMs = 10_000;
    let nowMs = 1_000;
    const bodies = [];
    const client = createProtocolClient({
      serverUrl: "https://example.test", agentId: "agent-1", protocolVersion: "1.0.0",
      getCredential: () => "ttagent_agent-1_0123456789abcdef",
      fetchImpl: async (_url, options) => {
        bodies.push(JSON.parse(options.body));
        const status = bodies.length === 1 ? 429 : 200;
        return { status, ok: status === 200, headers: { get: (name) => name === "retry-after" ? "2" : null }, json: async () => ({ ok: true, leaseExpiresAt: new Date(20_000).toISOString() }) };
      },
    });
    const gate = await renewJobLeaseOrAbort({
      leaseClient: client, jobId: "job-rate-wire", claimId: "claim-rate-wire", leaseState, required: true,
      now: () => nowMs, sleep: async (ms) => { nowMs += ms; }, log: silentLog,
    });
    assert.equal(gate.ok, true);
    assert.deepEqual(bodies.map((body) => body.sequence), [1, 2]);
    assert.equal(nowMs, 3_000);
  });

  it("does not retry if a concurrent lease monitor aborts while waiting", async () => {
    const leaseState = createLeaseState();
    leaseState.lastConfirmedExpiresAtMs = 10_000;
    let nowMs = 1_000, attempts = 0;
    const gate = await renewJobLeaseOrAbort({
      leaseClient: { renewLease: async () => { attempts++; throw Object.assign(new AgentProtocolError("limited", AGENT_PROTOCOL_ERROR_CODES.HTTP_ERROR, { status: 429 }), { retryAfterMs: 1_000 }); } },
      jobId: "job-rate-abort", claimId: "claim-rate-abort", leaseState, required: true,
      now: () => nowMs, sleep: async (ms) => { nowMs += ms; leaseState.abort = { status: "blocked", errorMessage: "ownership lost" }; }, log: silentLog,
    });
    assert.equal(gate.ok, false);
    assert.equal(gate.abort.errorMessage, "ownership lost");
    assert.equal(attempts, 1);
  });

  it("aborts mid-job when ownership is lost on a subsequent renew", async () => {
    const leaseState = createLeaseState();
    leaseState.lastConfirmedExpiresAtMs = Date.now() + 60_000;
    const leaseClient = {
      renewLease: async () => ({
        ok: false,
        status: 409,
        code: "CERTOPS_AGENT_CLAIM_OWNERSHIP_MISMATCH",
      }),
    };
    const gate = await renewJobLeaseOrAbort({
      leaseClient,
      jobId: "job-mid",
      claimId: "claim-mid",
      leaseState,
      required: false,
      log: silentLog,
    });
    assert.equal(gate.ok, false);
    assert.match(gate.abort.errorMessage, /HTTP 409/);
  });

  it("aborts before lease expiry when transient renews exhaust the grace window", async () => {
    const leaseState = createLeaseState();
    let nowMs = Date.now();
    leaseState.lastConfirmedExpiresAtMs = nowMs + 50_000;
    const leaseClient = {
      renewLease: async () => {
        throw new AgentProtocolError(
          "network down",
          AGENT_PROTOCOL_ERROR_CODES.NETWORK_ERROR,
        );
      },
    };
    nowMs = leaseState.lastConfirmedExpiresAtMs - 10;
    const gate = await renewJobLeaseOrAbort({
      leaseClient,
      jobId: "job-grace",
      claimId: "claim-grace",
      leaseState,
      required: false,
      now: () => nowMs,
      log: silentLog,
    });
    assert.equal(gate.ok, false);
    assert.match(gate.abort.errorMessage, /expiry|transient|retry would exceed/i);
  });

  it("writes a side-effect journal marker and refuses silent re-execution after crash", async () => {
    const executionContext = makeExecutionContext();
    const jobId = "job-journal-crash";
    markSideEffectReached({
      stateDir: workDir,
      jobId,
      attemptId: "attempt-crash-1",
      claimId: "claim-j",
      stage: "keygen",
    });
    assert.equal(hasUnresolvedJournalForJob(workDir, jobId), true);
    assert.equal(scanUnresolvedJournalEntries(workDir).length, 1);

    const client = createRecordingClient();
    const outcome = await handleClaimedJob({
      job: makeSignedJob({
        jobId,
        attemptId: "attempt-crash-2",
        action: "noop",
        claimId: "claim-new",
      }),
      policyEngine: permissiveEngine(),
      client,
      executionContext,
      boundAgentId: TEST_BOUND_AGENT_ID,
      log: silentLog,
    });
    assert.equal(outcome.status, "orphaned_unknown_effect");
    assert.match(
      client.calls.reportResult[0].errorMessage,
      /unresolved local side-effect journal/i,
    );
    assertNoPrivateKeyMaterial(client.calls.reportResult);
  });

  it("clears the journal once a terminal outcome is reported", () => {
    const jobId = "job-journal-clear";
    const attemptId = "attempt-clear";
    markSideEffectReached({
      stateDir: workDir,
      jobId,
      attemptId,
      claimId: "c",
      stage: "deploy",
    });
    assert.equal(
      clearJournalOnTerminal({
        stateDir: workDir,
        jobId,
        attemptId,
        status: "succeeded",
      }).cleared,
      true,
    );
    assert.equal(hasUnresolvedJournalForJob(workDir, jobId), false);
  });

  it("rolls back the first target when the second write fails (transactional)", async () => {
    const client = createRecordingClient();
    const leafPem = readFixture("leaf.crt.pem");
    const previous = readFixture("wrong-san.crt.pem");
    const a = path.join(workDir, "tls", "t1.pem");
    fs.mkdirSync(path.dirname(a), { recursive: true });
    fs.writeFileSync(a, previous, { mode: 0o600 });
    const b = path.join(workDir, "missing-parent", "t2.pem");

    const outcome = await executeDeployJob({
      job: {
        certificateId: "cert-1",
        certificatePem: leafPem,
        target: { type: "domain", reference: "valid.example.com" },
        deploymentTargets: [
          { type: "endpoint", reference: "a", certPath: a },
          { type: "endpoint", reference: "b", certPath: b },
        ],
      },
      jobId: "job-tx-rollback",
      policyEngine: permissiveEngine(["valid.example.com"]),
      client,
      executionContext: makeExecutionContext(),
      log: silentLog,
    });

    assert.equal(outcome.status, "failed");
    assert.equal(fs.readFileSync(a, "utf8"), previous);
    assertNoPrivateKeyMaterial(JSON.stringify(client.calls));
  });

  it("removes first-deploy files when rolling back a multi-target op", async () => {
    const client = createRecordingClient();
    const leafPem = readFixture("leaf.crt.pem");
    const a = path.join(workDir, "tls", "first.pem");
    fs.mkdirSync(path.dirname(a), { recursive: true });
    const b = path.join(workDir, "nope", "second.pem");

    const outcome = await executeDeployJob({
      job: {
        certificateId: "cert-1",
        certificatePem: leafPem,
        target: { type: "domain", reference: "valid.example.com" },
        deploymentTargets: [
          { type: "endpoint", reference: "a", certPath: a },
          { type: "endpoint", reference: "b", certPath: b },
        ],
      },
      jobId: "job-tx-first-deploy",
      policyEngine: permissiveEngine(["valid.example.com"]),
      client,
      executionContext: makeExecutionContext(),
      log: silentLog,
    });

    assert.equal(outcome.status, "failed");
    assert.equal(fs.existsSync(a), false);
  });

  it("rejects standalone deploy when keyPath is required but no local key exists", async () => {
    const client = createRecordingClient();
    const leafPem = readFixture("leaf.crt.pem");
    const certPath = path.join(workDir, "tls", "needs-key.pem");
    const keyDest = path.join(workDir, "tls", "needs-key.key");
    fs.mkdirSync(path.dirname(certPath), { recursive: true });

    const outcome = await executeDeployJob({
      job: {
        certificateId: "cert-missing-key",
        certificatePem: leafPem,
        target: { type: "domain", reference: "valid.example.com" },
        deploymentTargets: [
          {
            type: "endpoint",
            reference: "nginx",
            certPath,
            keyPath: keyDest,
          },
        ],
      },
      jobId: "job-need-key",
      policyEngine: permissiveEngine(["valid.example.com"]),
      client,
      executionContext: makeExecutionContext(),
      log: silentLog,
    });
    assert.equal(outcome.status, "failed");
    assert.match(outcome.errorMessage, /no permitted local key reference/i);
  });

  it("installs key to every target keyPath (not only the first)", async () => {
    const client = createRecordingClient();
    const executionContext = makeExecutionContext();
    const leafPem = readFixture("leaf.crt.pem");
    const keyPem = readFixture("leaf.key.pem");
    fs.mkdirSync(executionContext.execution.keysDir, { recursive: true });
    fs.writeFileSync(
      path.join(executionContext.execution.keysDir, "cert-1.key.pem"),
      keyPem,
      { mode: 0o600 },
    );
    const certA = path.join(workDir, "tls", "a.pem");
    const keyA = path.join(workDir, "tls", "a.key");
    const certB = path.join(workDir, "tls", "b.pem");
    const keyB = path.join(workDir, "tls", "b.key");
    fs.mkdirSync(path.dirname(certA), { recursive: true });

    const outcome = await executeDeployJob({
      job: {
        certificateId: "cert-1",
        certificatePem: leafPem,
        target: { type: "domain", reference: "valid.example.com" },
        deploymentTargets: [
          { type: "endpoint", reference: "a", certPath: certA, keyPath: keyA },
          { type: "endpoint", reference: "b", certPath: certB, keyPath: keyB },
        ],
      },
      jobId: "job-multi-key",
      policyEngine: permissiveEngine(["valid.example.com"]),
      client,
      executionContext,
      log: silentLog,
    });

    assert.equal(outcome.status, "succeeded");
    assert.equal(fs.readFileSync(keyA, "utf8"), keyPem);
    assert.equal(fs.readFileSync(keyB, "utf8"), keyPem);
    assertNoPrivateKeyMaterial(JSON.stringify(client.calls.reportEvidence));
    assertNoPrivateKeyMaterial(JSON.stringify(client.calls.reportResult));
  });

  it("rejects path-policy violations on keyPath during preflight", async () => {
    const client = createRecordingClient();
    const executionContext = makeExecutionContext();
    const leafPem = readFixture("leaf.crt.pem");
    const keyPem = readFixture("leaf.key.pem");
    fs.mkdirSync(executionContext.execution.keysDir, { recursive: true });
    fs.writeFileSync(
      path.join(executionContext.execution.keysDir, "cert-1.key.pem"),
      keyPem,
      { mode: 0o600 },
    );
    const certPath = path.join(workDir, "tls", "ok.pem");
    fs.mkdirSync(path.dirname(certPath), { recursive: true });

    const outcome = await executeDeployJob({
      job: {
        certificateId: "cert-1",
        certificatePem: leafPem,
        target: { type: "domain", reference: "valid.example.com" },
        deploymentTargets: [
          {
            type: "endpoint",
            reference: "a",
            certPath,
            keyPath: "/etc/shadow-not-allowed.key",
          },
        ],
      },
      jobId: "job-path-reject",
      policyEngine: permissiveEngine(["valid.example.com"]),
      client,
      executionContext,
      log: silentLog,
    });
    assert.ok(outcome.status === "rejected" || outcome.status === "failed");
    assert.match(outcome.errorMessage || "", /keyPath|policy|allowlist/i);
  });
});
