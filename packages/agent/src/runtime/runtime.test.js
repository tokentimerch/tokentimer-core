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
} = require("../protocol");

function makeTempConfigDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "ttagent-runtime-test-"));
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
      log: silentLog,
    });
    assert.equal(outcome.status, "blocked");
    assert.equal(client.calls.renewLease.length, 1);
    assert.match(client.calls.reportResult[0].errorMessage, /HTTP 409/);
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
