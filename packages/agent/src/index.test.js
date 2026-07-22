"use strict";

/**
 * Tests for the bootstrap entrypoint wiring (src/index.js): job
 * descriptor mapping, per-job handling (policy rejection -> evidence +
 * rejected result; policy pass -> blocked result until the signed-dispatch runtime
 * lands), and first-run registration.
 */

const { describe, it, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  handleClaimedJob,
  buildExecutionContext,
  buildJobPolicyDescriptor,
  resolveJobCertPath,
  runDiscoveryScan,
  registerIfNeeded,
  createCandidateAgentId,
  AGENT_VERSION,
} = require("./index.js");
const { loadPolicyConfig, createPolicyEngine, REJECTION_REASONS } = require("./policy");
const { ensureConfigDir, writeCredential, readCredential, loadAgentConfig } = require("./config");
const { generateSigningKeyPair, signJobPayload } = require("./signing");

function makeTempConfigDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "ttagent-index-test-"));
}

function createRecordingClient() {
  const calls = { register: [], reportResult: [], reportEvidence: [] };
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
  };
}

function engineWith(policy = {}, options = {}) {
  return createPolicyEngine(loadPolicyConfig(policy), options);
}

const silentLog = () => {};

function claimedJob(overrides = {}) {
  return {
    schemaVersion: 1,
    jobId: "job-1",
    workspaceId: "11111111-1111-4111-8111-111111111111",
    certificateId: "certificate-1",
    action: "noop",
    target: { type: "domain", reference: "example.com" },
    keyMode: "agent-local",
    requestedAt: "2026-07-23T12:00:00.000Z",
    ...overrides,
  };
}

describe("buildJobPolicyDescriptor", () => {
  it("maps validated metadata policy dimensions and target reference", () => {
    const descriptor = buildJobPolicyDescriptor(claimedJob({
      action: "renew",
      metadata: [
        { name: "caEndpoint", value: "https://acme.example/dir" },
        { name: "dnsZone", value: "example.com" },
        { name: "dnsProvider", value: "route53" },
      ],
    }));
    assert.deepEqual(descriptor, {
      targetSelector: "example.com",
      caEndpoint: "https://acme.example/dir",
      dnsZone: "example.com",
      dnsProvider: "route53",
    });
  });

  it("rejects missing policy dimensions and unknown properties before policy evaluation", () => {
    assert.throws(() => buildJobPolicyDescriptor(claimedJob({ action: "reload" })), /missing required policy dimension/);
    assert.throws(() => buildJobPolicyDescriptor(claimedJob({ exportPrivateKey: true })), /unknown field/);
  });
});

describe("handleClaimedJob", () => {
  it("reports rejected + evidence when agent-local policy rejects the job", async () => {
    const client = createRecordingClient();
    const policyEngine = engineWith({}, { declaredTargetSelectors: [] });

    const outcome = await handleClaimedJob({
      job: claimedJob({ target: { type: "domain", reference: "not-in-scope.example.com" } }),
      policyEngine,
      client,
      log: silentLog,
    });

    assert.equal(outcome.status, "rejected");
    assert.equal(outcome.rejectionReason, REJECTION_REASONS.TARGET_OUT_OF_SCOPE);

    assert.equal(client.calls.reportEvidence.length, 1);
    const evidence = client.calls.reportEvidence[0];
    assert.equal(evidence.jobId, "job-1");
    assert.equal(evidence.evidenceItems[0].eventType, "policy.checked");
    assert.deepEqual(evidence.evidenceItems[0].metadata, [
      { name: "rejectionReason", value: REJECTION_REASONS.TARGET_OUT_OF_SCOPE },
    ]);

    assert.equal(client.calls.reportResult.length, 1);
    const result = client.calls.reportResult[0];
    assert.equal(result.jobId, "job-1");
    assert.equal(result.status, "rejected");
    assert.equal(result.rejectionReason, REJECTION_REASONS.TARGET_OUT_OF_SCOPE);
    assert.match(result.attemptId, /^local-job-1-/);
  });

  it("reports job_integrity_failed for unknown custody-shaped claimed-job fields", async () => {
    const client = createRecordingClient();
    const policyEngine = engineWith(
      { allowedPaths: ["/"] },
      { declaredTargetSelectors: ["example.com"] },
    );

    const outcome = await handleClaimedJob({
      job: claimedJob({ jobId: "job-2", exportPrivateKey: true }),
      policyEngine,
      client,
      log: silentLog,
    });

    assert.equal(outcome.status, "rejected");
    assert.equal(outcome.rejectionReason, "job_integrity_failed");
  });

  it("reports blocked (not executed) when policy allows the job but execution is not enabled", async () => {
    const client = createRecordingClient();
    const policyEngine = engineWith({}, { declaredTargetSelectors: ["example.com"] });

    const outcome = await handleClaimedJob({
      job: claimedJob({ jobId: "job-3" }),
      policyEngine,
      client,
      log: silentLog,
    });

    assert.equal(outcome.status, "blocked");
    assert.equal(client.calls.reportEvidence.length, 0);
    assert.equal(client.calls.reportResult.length, 1);
    const result = client.calls.reportResult[0];
    assert.equal(result.status, "blocked");
    assert.match(result.attemptId, /^local-job-3-/);
    assert.match(result.errorMessage, /execution is not enabled/);
  });

  it("skips jobs without a jobId without reporting anything", async () => {
    const client = createRecordingClient();
    const policyEngine = engineWith();

    const outcome = await handleClaimedJob({
      job: { ...claimedJob(), jobId: undefined },
      policyEngine,
      client,
      log: silentLog,
    });

    assert.equal(outcome.status, "skipped");
    assert.equal(client.calls.reportResult.length, 0);
    assert.equal(client.calls.reportEvidence.length, 0);
  });
});

// A throwaway self-signed certificate (CN=index-test.local) used as a
// fixture for runDiscoveryScan; contains no private key material.
const TEST_CERT_PEM = `-----BEGIN CERTIFICATE-----
MIIDGTCCAgGgAwIBAgIUHuNlDhj7S3QpdjVS5hSep1JzMA8wDQYJKoZIhvcNAQEL
BQAwGzEZMBcGA1UEAwwQaW5kZXgtdGVzdC5sb2NhbDAgFw0yNjA3MjAxNzA4MDla
GA8yMTI2MDYyNjE3MDgwOVowGzEZMBcGA1UEAwwQaW5kZXgtdGVzdC5sb2NhbDCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL5e2nCEDudrko0oa3HzsWYi
k+GOqeokhFswyyn38S4TSvCp92+vV0IsLg9lSH4NMLAE+++JOy0Y7Hgoi4NE6hcg
BzD7iaSRYFZ7c7Y4UVaCAWms0TK4LM5QWmllCzLzXreHPSbMmrSqDji6w+6HB/jo
Sbs8CUp82fZKuzNYPnd/5T6jfq5dIS6P7COeepfr6ye9rEEcLToQnVeq2c9Mmmdh
5SGg0NWlE6WIFKTeTC8mgOk8Ee2PgUlBPLUD5LyszrJ1J+FR7fdCc6SS9XEykjNo
YpcUTSy+jkbhoQcMRB5Unwqdl+Hr4Xrd4uiv2ThGGdUZq98JSCkr1CDIunzgjmcC
AwEAAaNTMFEwHQYDVR0OBBYEFOI8MA5FYk/GlOArVmQBUuYSkpDwMB8GA1UdIwQY
MBaAFOI8MA5FYk/GlOArVmQBUuYSkpDwMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZI
hvcNAQELBQADggEBAEaqNrZR+j5BmFgpy6cC8SYii2nc5BB/1WMcDZ85g77DnqsG
zcKvJrdvfZzsPv+CuxPSsTgVHV3frcxzvdWN4yjb55qHy3chaz4roc3Nm3PXIeFL
UMTnvR8W8jdPFx9Mht5zOtAaGktGhML0EWwBb+kx+DouI7Cxpvrjt90b5ZWu1LIv
E6y2335e3zCej7k3PgmX1FVl8nPEJ46IoEG45HkSpkZyxLKIZyO2l5uMeqYLBpR6
D1tt3S4JVM/+zWGZePU7rInGYl/9N38I5ltc37DHAkuXv2R6su5/8Av8s7sj+u/0
6h12INIho8kWWGuiuDi2YbQj97brgWQBJWcUs3A=
-----END CERTIFICATE-----
`;

describe("runDiscoveryScan", () => {
  let dir;

  beforeEach(() => {
    dir = makeTempConfigDir();
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("reports parsed certificates as certificate.observed evidence with public fields only", async () => {
    fs.writeFileSync(path.join(dir, "server.crt"), TEST_CERT_PEM, "utf8");
    const client = createRecordingClient();

    const outcome = await runDiscoveryScan({
      directories: [dir],
      client,
      log: silentLog,
    });

    assert.equal(outcome.observed, 1);
    assert.equal(client.calls.reportEvidence.length, 1);
    const body = client.calls.reportEvidence[0];
    assert.equal(body.jobId, null);
    assert.equal(body.evidenceItems.length, 1);
    const item = body.evidenceItems[0];
    assert.equal(item.eventType, "certificate.observed");
    assert.match(item.fingerprintSha256, /^[a-f0-9]{64}$/);
    assert.match(item.summary, /index-test\.local/);
    const metadataNames = item.metadata.map((entry) => entry.name);
    assert.deepEqual(metadataNames, ["validTo", "coLocatedKeyDetected"]);
  });

  it("skips unparseable files and sends no evidence when nothing parsed", async () => {
    fs.writeFileSync(path.join(dir, "garbage.crt"), "not a certificate\n", "utf8");
    const client = createRecordingClient();

    const outcome = await runDiscoveryScan({
      directories: [dir],
      client,
      log: silentLog,
    });

    assert.equal(outcome.observed, 0);
    assert.equal(client.calls.reportEvidence.length, 0);
  });

  it("chunks evidence bodies to the schema's 16-item maximum", async () => {
    for (let i = 0; i < 17; i += 1) {
      fs.writeFileSync(path.join(dir, `cert-${String(i).padStart(2, "0")}.crt`), TEST_CERT_PEM, "utf8");
    }
    const client = createRecordingClient();

    const outcome = await runDiscoveryScan({
      directories: [dir],
      client,
      log: silentLog,
    });

    assert.equal(outcome.observed, 17);
    assert.equal(client.calls.reportEvidence.length, 2);
    assert.equal(client.calls.reportEvidence[0].evidenceItems.length, 16);
    assert.equal(client.calls.reportEvidence[1].evidenceItems.length, 1);
  });
});

describe("registerIfNeeded", () => {
  let dir;

  beforeEach(() => {
    dir = makeTempConfigDir();
    ensureConfigDir(dir);
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  function loadConfigFrom(configDir) {
    return loadAgentConfig({ configDir });
  }

  it("returns the stored agentId without calling register when a credential exists", async () => {
    fs.writeFileSync(
      path.join(dir, "config.json"),
      JSON.stringify({ serverUrl: "https://cp.example.com", agentId: "agent-existing" }),
      "utf8",
    );
    writeCredential(dir, "ttagent_agent-existing_0123456789abcdef");

    const client = createRecordingClient();
    const agentId = await registerIfNeeded({
      client,
      config: loadConfigFrom(dir),
      configDir: dir,
      env: {},
    });

    assert.equal(agentId, "agent-existing");
    assert.equal(client.calls.register.length, 0);
  });

  it("fails loudly when a credential exists but agentId is missing (inconsistent dir)", async () => {
    fs.writeFileSync(
      path.join(dir, "config.json"),
      JSON.stringify({ serverUrl: "https://cp.example.com" }),
      "utf8",
    );
    writeCredential(dir, "ttagent_agent-orphan_0123456789abcdef");

    await assert.rejects(
      registerIfNeeded({
        client: createRecordingClient(),
        config: loadConfigFrom(dir),
        configDir: dir,
        env: {},
      }),
      /inconsistent/,
    );
  });

  it("fails loudly when unregistered and no bootstrap token is provided", async () => {
    fs.writeFileSync(
      path.join(dir, "config.json"),
      JSON.stringify({ serverUrl: "https://cp.example.com" }),
      "utf8",
    );

    await assert.rejects(
      registerIfNeeded({
        client: createRecordingClient(),
        config: loadConfigFrom(dir),
        configDir: dir,
        env: {},
      }),
      /TOKENTIMER_AGENT_BOOTSTRAP_TOKEN/,
    );
  });

  it("registers with the bootstrap token and persists the assigned agentId", async () => {
    fs.writeFileSync(
      path.join(dir, "config.json"),
      JSON.stringify({
        serverUrl: "https://cp.example.com",
        declaredTargetSelectors: ["example.com"],
        declaredCommandProfileNames: ["nginx-reload"],
      }),
      "utf8",
    );

    const client = createRecordingClient();
    const agentId = await registerIfNeeded({
      client,
      config: loadConfigFrom(dir),
      configDir: dir,
      env: {
        TOKENTIMER_AGENT_BOOTSTRAP_TOKEN: "bootstrap-raw-token",
        TOKENTIMER_AGENT_BOOTSTRAP_TOKEN_ID: "bst_1",
      },
    });

    assert.equal(agentId, "agent-assigned-1");
    assert.equal(client.calls.register.length, 1);
    const registerCall = client.calls.register[0];
    assert.equal(registerCall.bootstrapToken, "bootstrap-raw-token");
    assert.equal(registerCall.bootstrapTokenId, "bst_1");
    assert.equal(registerCall.agentVersion, AGENT_VERSION);
    assert.deepEqual(registerCall.declaredTargetSelectors, ["example.com"]);
    assert.deepEqual(registerCall.declaredCommandProfileNames, ["nginx-reload"]);

    // The validated registration record is persisted as one recoverable
    // identity + credential transaction by registerIfNeeded itself.
    const persisted = JSON.parse(fs.readFileSync(path.join(dir, "config.json"), "utf8"));
    assert.equal(persisted.agentId, "agent-assigned-1");
    assert.equal(readCredential(dir), "ttagent_agent-assigned-1_0123456789abcdef");
  });

  it("does not persist any state when registration returns malformed identity data", async () => {
    fs.writeFileSync(
      path.join(dir, "config.json"),
      JSON.stringify({ serverUrl: "https://cp.example.com" }),
      "utf8",
    );
    const malformedClient = {
      register: () => Promise.resolve({
        agentId: "bad agent id",
        credential: "ttagent_bad_0123456789abcdef",
        protocolVersion: "1.0.0",
      }),
    };

    await assert.rejects(
      registerIfNeeded({
        client: malformedClient,
        config: loadConfigFrom(dir),
        configDir: dir,
        env: { TOKENTIMER_AGENT_BOOTSTRAP_TOKEN: "bootstrap-token" },
      }),
      /invalid agentId/,
    );
    assert.equal(loadConfigFrom(dir).agentId, null);
    assert.equal(readCredential(dir), null);
  });
});

describe("createCandidateAgentId", () => {
  it("normalizes hostile hostnames into a bounded protocol-valid candidate id", () => {
    const candidate = createCandidateAgentId("host name/with/unsafe😀characters".repeat(8), 1234);
    assert.match(candidate, /^[A-Za-z0-9_.:-]{1,128}$/);
    assert.ok(candidate.length <= 128);
    assert.match(candidate, /^candidate-/);
  });
});

describe("signed-job dispatch chain (handleClaimedJob with executionContext)", () => {
  let workDir;
  let signingKey;

  beforeEach(() => {
    workDir = makeTempConfigDir();
    signingKey = generateSigningKeyPair();
  });

  afterEach(() => {
    fs.rmSync(workDir, { recursive: true, force: true });
  });

  function makeExecutionContext({ dryRun = true, pinned = true } = {}) {
    const keysDir = path.join(workDir, "keys");
    const config = {
      execution: {
        enabled: true,
        dryRun,
        keysDir,
        replayStorePath: path.join(workDir, "replay-store.json"),
        clockDriftToleranceMs: 30000,
      },
      pinnedSigningKey: pinned
        ? {
            signingKeyId: signingKey.signingKeyId,
            publicKeyPem: signingKey.publicKeyPem,
          }
        : null,
    };
    return buildExecutionContext({ config });
  }

  function makeSignedJob(overrides = {}) {
    const nowMs = Date.now();
    const job = {
      schemaVersion: 1,
      jobId: overrides.jobId || "job-m5-1",
      workspaceId: "11111111-2222-3333-4444-555555555555",
      certificateId: "cert-1",
      action: "noop",
      target: { type: "domain", reference: "example.com" },
      keyMode: "agent-local",
      requestedAt: new Date(nowMs).toISOString(),
      issuedAt: new Date(nowMs - 1000).toISOString(),
      expiresAt: new Date(nowMs + 5 * 60 * 1000).toISOString(),
      nonce: `nonce-${Math.random().toString(36).slice(2)}-0123456789abcdef`,
      signingKeyId: signingKey.signingKeyId,
      ...overrides,
    };
    job.signature = signJobPayload({ job, privateKeyPem: signingKey.privateKeyPem });
    return job;
  }

  function permissiveEngine() {
    return engineWith(
      { allowedPaths: [workDir] },
      { declaredTargetSelectors: ["example.com"] },
    );
  }

  it("rejects an unsigned (M2) job with job_integrity_failed while execution is enabled", async () => {
    const client = createRecordingClient();
    const job = makeSignedJob();
    delete job.signature;
    delete job.nonce;

    const outcome = await handleClaimedJob({
      job,
      policyEngine: permissiveEngine(),
      client,
      executionContext: makeExecutionContext(),
      log: silentLog,
    });

    assert.equal(outcome.status, "rejected");
    assert.equal(outcome.rejectionReason, "job_integrity_failed");
    assert.equal(client.calls.reportResult[0].status, "rejected");
    assert.equal(client.calls.reportEvidence.length, 1);
  });

  it("rejects a tampered job with job_integrity_failed", async () => {
    const client = createRecordingClient();
    const job = makeSignedJob();
    job.action = "renew"; // mutate after signing

    const outcome = await handleClaimedJob({
      job,
      policyEngine: permissiveEngine(),
      client,
      executionContext: makeExecutionContext(),
      log: silentLog,
    });

    assert.equal(outcome.status, "rejected");
    assert.equal(outcome.rejectionReason, "job_integrity_failed");
  });

  it("rejects a replayed job with job_replay_rejected on the second dispatch", async () => {
    const client = createRecordingClient();
    const executionContext = makeExecutionContext();
    const policyEngine = permissiveEngine();
    const job = makeSignedJob();

    const first = await handleClaimedJob({
      job,
      policyEngine,
      client,
      executionContext,
      log: silentLog,
    });
    assert.equal(first.status, "succeeded");

    const second = await handleClaimedJob({
      job,
      policyEngine,
      client,
      executionContext,
      log: silentLog,
    });
    assert.equal(second.status, "rejected");
    assert.equal(second.rejectionReason, "job_replay_rejected");
  });

  it("rejects a stale job with clock_drift_suspected", async () => {
    const client = createRecordingClient();
    const nowMs = Date.now();
    const job = makeSignedJob({
      issuedAt: new Date(nowMs - 10 * 60 * 1000).toISOString(),
      expiresAt: new Date(nowMs - 5 * 60 * 1000).toISOString(),
    });

    const outcome = await handleClaimedJob({
      job,
      policyEngine: permissiveEngine(),
      client,
      executionContext: makeExecutionContext(),
      log: silentLog,
    });

    assert.equal(outcome.status, "rejected");
    assert.equal(outcome.rejectionReason, "clock_drift_suspected");
  });

  it("reports blocked (never executes) when execution is enabled but no key is pinned", async () => {
    const client = createRecordingClient();
    const job = makeSignedJob();

    const outcome = await handleClaimedJob({
      job,
      policyEngine: permissiveEngine(),
      client,
      executionContext: makeExecutionContext({ pinned: false }),
      log: silentLog,
    });

    assert.equal(outcome.status, "blocked");
    assert.equal(client.calls.reportResult.length, 1);
    assert.match(client.calls.reportResult[0].errorMessage, /no control-plane signing key is pinned/);
    assert.equal(client.calls.reportEvidence.length, 0);
  });

  it("executes a verified noop job with validation.passed evidence", async () => {
    const client = createRecordingClient();
    const job = makeSignedJob();

    const outcome = await handleClaimedJob({
      job,
      policyEngine: permissiveEngine(),
      client,
      executionContext: makeExecutionContext(),
      log: silentLog,
    });

    assert.equal(outcome.status, "succeeded");
    assert.equal(client.calls.reportResult[0].status, "succeeded");
    assert.equal(client.calls.reportEvidence.length, 1);
    assert.equal(
      client.calls.reportEvidence[0].evidenceItems[0].eventType,
      "validation.passed",
    );
  });

  it("dry-run renew succeeds with a plan and performs zero filesystem side effects", async () => {
    const client = createRecordingClient();
    const executionContext = makeExecutionContext({ dryRun: true });
    const job = makeSignedJob({
      action: "renew",
      commandRef: "certbot-renew",
      caEndpoint: "https://acme.example/dir",
      certPath: path.join(workDir, "deployed", "cert.pem"),
    });
    const policyEngine = engineWith(
      {
        allowedPaths: [workDir],
        allowedCommands: { "certbot-renew": { argv: ["certbot"] } },
        allowedCaEndpoints: ["https://acme.example/dir"],
      },
      { declaredTargetSelectors: ["example.com"] },
    );

    const outcome = await handleClaimedJob({
      job,
      policyEngine,
      client,
      executionContext,
      log: silentLog,
    });

    assert.equal(outcome.status, "succeeded");
    const result = client.calls.reportResult[0];
    assert.equal(result.status, "succeeded");
    assert.equal(result.keyRotated, null);
    assert.equal(result.errorMessage, null);

    // Plan evidence: policy.checked items flagged dryRun.
    assert.equal(client.calls.reportEvidence.length, 1);
    const items = client.calls.reportEvidence[0].evidenceItems;
    assert.ok(items.length >= 4);
    for (const item of items) {
      assert.equal(item.eventType, "policy.checked");
      assert.ok(item.metadata.some((m) => m.name === "dryRun" && m.value === true));
      assert.match(item.summary, /No side effects were performed/);
    }

    // Zero side effects: keysDir was never created, no cert deployed.
    assert.equal(fs.existsSync(executionContext.execution.keysDir), false);
    assert.equal(fs.existsSync(path.join(workDir, "deployed")), false);
  });

  it("blocks revoke jobs and deploy jobs without certificatePem", async () => {
    const client = createRecordingClient();
    const executionContext = makeExecutionContext({ dryRun: false });
    const policyEngine = permissiveEngine();

    const revokeOutcome = await handleClaimedJob({
      job: makeSignedJob({ jobId: "job-revoke", action: "revoke" }),
      policyEngine,
      client,
      executionContext,
      log: silentLog,
    });
    assert.equal(revokeOutcome.status, "blocked");

    const deployOutcome = await handleClaimedJob({
      job: makeSignedJob({ jobId: "job-deploy", action: "deploy" }),
      policyEngine,
      client,
      executionContext,
      log: silentLog,
    });
    assert.equal(deployOutcome.status, "blocked");
    const deployResult = client.calls.reportResult.find((r) => r.jobId === "job-deploy");
    assert.match(deployResult.errorMessage, /certificatePem/);
  });

  it("strictly rejects a signed-dispatch job when executionContext is null", async () => {
    const client = createRecordingClient();
    const job = makeSignedJob(); // signed-dispatch fields are not valid bootstrap input

    const outcome = await handleClaimedJob({
      job,
      policyEngine: permissiveEngine(),
      client,
      executionContext: null,
      log: silentLog,
    });

    // Without execution enabled the strict bootstrap validator rejects the
    // unknown signed-dispatch fields outright; the job is never executed.
    assert.equal(outcome.status, "rejected");
    assert.equal(outcome.rejectionReason, "job_integrity_failed");
    assert.equal(client.calls.reportResult[0].status, "rejected");
  });

  it("buildExecutionContext returns null when execution is absent or disabled and throws on a corrupted replay store", () => {
    assert.equal(buildExecutionContext({ config: {} }), null);
    assert.equal(
      buildExecutionContext({
        config: { execution: { enabled: false } },
      }),
      null,
    );

    const storePath = path.join(workDir, "replay-store.json");
    fs.writeFileSync(storePath, "{corrupted", "utf8");
    assert.throws(
      () =>
        buildExecutionContext({
          config: {
            execution: {
              enabled: true,
              dryRun: true,
              keysDir: path.join(workDir, "keys"),
              replayStorePath: storePath,
              clockDriftToleranceMs: 30000,
            },
            pinnedSigningKey: null,
          },
        }),
      /replay store/,
    );
  });

  it("resolveJobCertPath prefers job.certPath, falls back to absolute target.reference, else null", () => {
    const abs = process.platform === "win32" ? "C:\\certs\\a.pem" : "/certs/a.pem";
    const abs2 = process.platform === "win32" ? "C:\\certs\\b.pem" : "/certs/b.pem";
    assert.equal(resolveJobCertPath({ certPath: abs, target: { reference: abs2 } }), abs);
    assert.equal(resolveJobCertPath({ target: { reference: abs2 } }), abs2);
    assert.equal(resolveJobCertPath({ target: { reference: "example.com" } }), null);
  });
});
