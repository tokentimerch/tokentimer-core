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
  resolveJobMode,
  runDiscoveryScan,
  registerIfNeeded,
  createCandidateAgentId,
  resolveClaimSupportedActions,
  shouldPollForJobs,
  adoptSigningKeyRotation,
  executeJob,
  executeDeployJob,
  AGENT_VERSION,
  EXECUTABLE_JOB_ACTIONS,
  OBSERVE_ONLY_CLAIM_ACTIONS,
  resolveJobSans,
  mapJobKeyAlgorithm,
  resolveJobDeployTargets,
} = require("./index.js");
const { listOutboxEntries, drainOutbox } = require("./outbox");
const { loadPolicyConfig, createPolicyEngine, REJECTION_REASONS } = require("./policy");
const {
  ensureConfigDir,
  writeCredential,
  readCredential,
  loadAgentConfig,
  readRegistrationId,
  ensureRegistrationId,
  writeSigningKeyPin,
  readSigningKeyPin,
  listConfiguredDnsProviderIds,
} = require("./config");
const { generateSigningKeyPair, signJobPayload, verifyJobSignature } = require("./signing");
const {
  AGENT_PROTOCOL_ERROR_CODES,
  AgentProtocolError,
} = require("./protocol");

function makeTempConfigDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "ttagent-index-test-"));
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
      });
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

  it("rejects a bootstrap-mode job carrying signed-dispatch fields with job_integrity_failed", async () => {
    const client = createRecordingClient();
    const policyEngine = engineWith({}, { declaredTargetSelectors: ["example.com"] });

    // claimId/nonce are signed-dispatch fields; bootstrap mode (no
    // executionContext) must strictly reject them instead of echoing them.
    const outcome = await handleClaimedJob({
      job: {
        jobId: "job-m4",
        claimId: "claim-m4-1",
        nonce: "nonce-m4-0123456789abcdef",
        target: { type: "domain", reference: "example.com" },
      },
      policyEngine,
      client,
      log: silentLog,
    });

    assert.equal(outcome.status, "rejected");
    assert.equal(outcome.rejectionReason, "job_integrity_failed");
    const result = client.calls.reportResult[0];
    assert.equal(result.status, "rejected");
    assert.equal(result.rejectionReason, "job_integrity_failed");
    assert.match(result.attemptId, /^local-job-m4-/);
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
    // Use a SAN-bearing fixture so subjectAltNames is present in metadata.
    const leafPem = fs.readFileSync(
      path.join(__dirname, "verify", "fixtures", "leaf.crt.pem"),
      "utf8",
    );
    const certFile = path.join(dir, "server.crt");
    fs.writeFileSync(certFile, leafPem, "utf8");
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
    assert.match(item.summary, /valid\.example\.com/);
    const byName = Object.fromEntries(item.metadata.map((entry) => [entry.name, entry.value]));
    assert.equal(byName.filePath, certFile);
    assert.equal(byName.targetHost, os.hostname());
    assert.equal(byName.subject, "CN=valid.example.com");
    assert.ok(typeof byName.issuer === "string" && byName.issuer.length > 0);
    assert.ok(typeof byName.serialNumber === "string" && byName.serialNumber.length > 0);
    assert.match(byName.subjectAltNames, /DNS:valid\.example\.com/);
    assert.ok(typeof byName.validFrom === "string" && byName.validFrom.length > 0);
    assert.ok(typeof byName.validTo === "string" && byName.validTo.length > 0);
    assert.equal(byName.coLocatedKeyDetected, false);
    assert.deepEqual(
      item.metadata.map((entry) => entry.name),
      [
        "filePath",
        "targetHost",
        "subject",
        "issuer",
        "serialNumber",
        "subjectAltNames",
        "validFrom",
        "validTo",
        "coLocatedKeyDetected",
      ],
    );
  });

  it("omits subjectAltNames metadata when the certificate has no SAN extension", async () => {
    fs.writeFileSync(path.join(dir, "server.crt"), TEST_CERT_PEM, "utf8");
    const client = createRecordingClient();

    const outcome = await runDiscoveryScan({
      directories: [dir],
      client,
      log: silentLog,
    });

    assert.equal(outcome.observed, 1);
    const item = client.calls.reportEvidence[0].evidenceItems[0];
    const metadataNames = item.metadata.map((entry) => entry.name);
    assert.ok(metadataNames.includes("filePath"));
    assert.ok(metadataNames.includes("targetHost"));
    assert.ok(!metadataNames.includes("subjectAltNames"));
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
    assert.deepEqual(registerCall.supportedDnsProviders, []);
    // H1: registrationId must be sent and must match the pre-persisted key.
    assert.match(registerCall.registrationId, /^[0-9a-f-]{36}$/i);
    assert.equal(readRegistrationId(dir), null); // cleared after successful persist

    // The validated registration record is persisted as one recoverable
    // identity + credential transaction by registerIfNeeded itself.
    const persisted = JSON.parse(fs.readFileSync(path.join(dir, "config.json"), "utf8"));
    assert.equal(persisted.agentId, "agent-assigned-1");
    assert.equal(readCredential(dir), "ttagent_agent-assigned-1_0123456789abcdef");
  });

  it("advertises configured DNS provider ids on register", async () => {
    const credFile = path.join(dir, "cf-creds.json");
    fs.writeFileSync(credFile, "{}\n", "utf8");
    fs.writeFileSync(
      path.join(dir, "config.json"),
      JSON.stringify({
        serverUrl: "https://cp.example.com",
        dnsProviders: {
          cloudflare: { credentialsFile: credFile },
          route53: { credentialsFile: credFile },
          zoneProviderMap: { "example.com": "cloudflare" },
        },
      }),
      "utf8",
    );

    const client = createRecordingClient();
    await registerIfNeeded({
      client,
      config: loadConfigFrom(dir),
      configDir: dir,
      env: {
        TOKENTIMER_AGENT_BOOTSTRAP_TOKEN: "bootstrap-raw-token",
        TOKENTIMER_AGENT_BOOTSTRAP_TOKEN_ID: "bst_dns",
      },
    });

    assert.deepEqual(client.calls.register[0].supportedDnsProviders, [
      "cloudflare",
      "route53",
    ]);
  });

  it("persists registrationId before register and reuses it on retry after a crash (H1)", async () => {
    fs.writeFileSync(
      path.join(dir, "config.json"),
      JSON.stringify({ serverUrl: "https://cp.example.com" }),
      "utf8",
    );

    const prePersistedId = ensureRegistrationId(dir);
    assert.equal(readRegistrationId(dir), prePersistedId);

    const client = createRecordingClient();
    await registerIfNeeded({
      client,
      config: loadConfigFrom(dir),
      configDir: dir,
      env: { TOKENTIMER_AGENT_BOOTSTRAP_TOKEN: "bootstrap-token" },
    });

    assert.equal(client.calls.register.length, 1);
    assert.equal(client.calls.register[0].registrationId, prePersistedId);
    assert.equal(readRegistrationId(dir), null);
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
    // H1: registrationId remains so a retry can reuse the same idempotency key.
    assert.match(readRegistrationId(dir), /^[0-9a-f-]{36}$/i);
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

describe("observe-only claim policy (B3)", () => {
  it("advertises zero supported actions when execution is disabled", () => {
    assert.deepEqual(OBSERVE_ONLY_CLAIM_ACTIONS, []);
    assert.deepEqual(resolveClaimSupportedActions(null), []);
    assert.deepEqual(resolveClaimSupportedActions(undefined), []);
    assert.deepEqual(resolveClaimSupportedActions({ enabled: false }), []);
  });

  it("advertises executable actions only when execution is enabled", () => {
    assert.deepEqual(
      resolveClaimSupportedActions({ enabled: true }),
      EXECUTABLE_JOB_ACTIONS,
    );
    assert.ok(EXECUTABLE_JOB_ACTIONS.includes("renew"));
    assert.ok(EXECUTABLE_JOB_ACTIONS.includes("deploy"));
  });

  it("never polls the claim endpoint when observe-only", () => {
    assert.equal(shouldPollForJobs(null), false);
    assert.equal(shouldPollForJobs(undefined), false);
    assert.equal(shouldPollForJobs({ enabled: false }), false);
    assert.equal(shouldPollForJobs({ enabled: true }), true);
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
        outboxDir: path.join(workDir, "outbox"),
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

  function permissiveEngine(selectors = ["example.com", "valid.example.com", "expired.example.com", "other.example.com"]) {
    return engineWith(
      { allowedPaths: [workDir] },
      { declaredTargetSelectors: selectors },
    );
  }

  it("rejects an unsigned job with job_integrity_failed while execution is enabled", async () => {
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

  it("passes job.claimId/job.nonce and a claim-derived attemptId through on a success report", async () => {
    const client = createRecordingClient();
    const job = makeSignedJob({ claimId: "claim-m5-1" });

    const outcome = await handleClaimedJob({
      job,
      policyEngine: permissiveEngine(),
      client,
      executionContext: makeExecutionContext(),
      log: silentLog,
    });

    assert.equal(outcome.status, "succeeded");
    const result = client.calls.reportResult[0];
    assert.equal(result.status, "succeeded");
    assert.equal(result.claimId, "claim-m5-1");
    assert.equal(result.nonce, job.nonce);
    assert.equal(result.attemptId, "claim-m5-1");
  });

  it("prefers a server-assigned attemptId over claimId, and falls back to a local id", async () => {
    // attemptId preference chain: job.attemptId > job.claimId > local id.
    const cases = [
      {
        overrides: { jobId: "job-a", attemptId: "attempt-cp-1", claimId: "claim-1" },
        expected: (id) => id === "attempt-cp-1",
      },
      {
        overrides: { jobId: "job-c" },
        expected: (id) => /^local-job-c-/.test(id),
      },
    ];

    for (const { overrides, expected } of cases) {
      const client = createRecordingClient();
      await handleClaimedJob({
        job: makeSignedJob(overrides),
        policyEngine: permissiveEngine(),
        client,
        executionContext: makeExecutionContext(),
        log: silentLog,
      });
      assert.equal(client.calls.reportResult.length, 1, overrides.jobId);
      assert.ok(expected(client.calls.reportResult[0].attemptId), overrides.jobId);
    }
  });

  it("passes job.claimId/job.nonce through on a failure report", async () => {
    const client = createRecordingClient();
    // renew without commandRef fails inside executeJob (dryRun off).
    const job = makeSignedJob({
      action: "renew",
      claimId: "claim-m5-fail",
      certPath: path.join(workDir, "deployed", "cert.pem"),
    });

    const outcome = await handleClaimedJob({
      job,
      policyEngine: permissiveEngine(),
      client,
      executionContext: makeExecutionContext({ dryRun: false }),
      log: silentLog,
    });

    assert.equal(outcome.status, "failed");
    const result = client.calls.reportResult[0];
    assert.equal(result.status, "failed");
    assert.equal(result.claimId, "claim-m5-fail");
    assert.equal(result.nonce, job.nonce);
  });

  it("passes job.claimId/job.nonce through on a rejection report", async () => {
    const client = createRecordingClient();
    const job = makeSignedJob({ claimId: "claim-m5-rej" });
    job.action = "renew"; // mutate after signing -> job_integrity_failed

    const outcome = await handleClaimedJob({
      job,
      policyEngine: permissiveEngine(),
      client,
      executionContext: makeExecutionContext(),
      log: silentLog,
    });

    assert.equal(outcome.status, "rejected");
    const result = client.calls.reportResult[0];
    assert.equal(result.status, "rejected");
    assert.equal(result.rejectionReason, "job_integrity_failed");
    assert.equal(result.claimId, "claim-m5-rej");
    assert.equal(result.nonce, job.nonce);
  });

  it("dry-run mode renew reports dry_run_complete with a plan and zero filesystem side effects", async () => {
    const client = createRecordingClient();
    // Local dryRun is irrelevant when the signed job mode is dry_run.
    const executionContext = makeExecutionContext({ dryRun: false });
    const job = makeSignedJob({
      action: "renew",
      mode: "dry_run",
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

    assert.equal(outcome.status, "dry_run_complete");
    const result = client.calls.reportResult[0];
    assert.equal(result.status, "dry_run_complete");
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

  it("local execution.dryRun refuses a mode:real job instead of silently succeeding", async () => {
    const client = createRecordingClient();
    const executionContext = makeExecutionContext({ dryRun: true });
    const job = makeSignedJob({
      action: "renew",
      mode: "real",
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

    assert.equal(outcome.status, "blocked");
    assert.equal(client.calls.reportResult[0].status, "blocked");
    assert.match(client.calls.reportResult[0].errorMessage, /execution\.dryRun is true/);
    assert.equal(fs.existsSync(executionContext.execution.keysDir), false);
  });

  it("resolveJobMode defaults omitted mode to real and prefers top-level over payload", () => {
    assert.equal(resolveJobMode({}), "real");
    assert.equal(resolveJobMode({ mode: "dry_run" }), "dry_run");
    assert.equal(resolveJobMode({ payload: { mode: "dry_run" } }), "dry_run");
    assert.equal(resolveJobMode({ mode: "real", payload: { mode: "dry_run" } }), "real");
  });

  it("renews the lease after accept and reports blocked when ownership is lost", async () => {
    const client = createRecordingClient();
    client.renewLease = async (params) => {
      client.calls.renewLease.push(params);
      return {
        ok: false,
        status: 409,
        code: "CERTOPS_AGENT_CLAIM_OWNERSHIP_MISMATCH",
      };
    };
    const job = makeSignedJob({
      action: "noop",
      claimId: "claim-lease-lost",
      mode: "real",
    });

    const outcome = await handleClaimedJob({
      job,
      policyEngine: permissiveEngine(),
      client,
      executionContext: makeExecutionContext({ dryRun: false }),
      log: silentLog,
    });

    assert.equal(outcome.status, "blocked");
    assert.equal(client.calls.renewLease.length, 1);
    assert.equal(client.calls.renewLease[0].claimId, "claim-lease-lost");
    assert.equal(client.calls.reportResult.length, 1);
    assert.equal(client.calls.reportResult[0].status, "blocked");
    assert.match(client.calls.reportResult[0].errorMessage, /HTTP 409/);
  });

  it("continues the job when lease renew fails with a soft network error", async () => {
    const client = createRecordingClient();
    let renewAttempts = 0;
    client.renewLease = async (params) => {
      renewAttempts += 1;
      client.calls.renewLease.push(params);
      throw new AgentProtocolError(
        "network request to control plane failed",
        AGENT_PROTOCOL_ERROR_CODES.NETWORK_ERROR,
      );
    };
    const job = makeSignedJob({
      action: "noop",
      claimId: "claim-lease-soft",
      mode: "real",
    });

    const outcome = await handleClaimedJob({
      job,
      policyEngine: permissiveEngine(),
      client,
      executionContext: makeExecutionContext({ dryRun: false }),
      log: silentLog,
    });

    assert.equal(outcome.status, "succeeded");
    assert.equal(renewAttempts, 1);
    assert.equal(client.calls.reportResult[0].status, "succeeded");
  });

  it("renews the lease before each side-effecting renew step", async () => {
    const client = createRecordingClient();
    const executionContext = makeExecutionContext({ dryRun: false });
    const leaseCalls = [];
    const leaseClient = {
      renewLease: async (params) => {
        leaseCalls.push({ ...params });
        return { ok: true, status: "running", claimId: params.claimId };
      },
    };
    const policyEngine = engineWith(
      {
        allowedPaths: [workDir],
        allowedCommands: { "certbot-renew": { argv: ["certbot"] } },
        allowedCaEndpoints: ["https://acme.example/dir"],
      },
      { declaredTargetSelectors: ["example.com"] },
    );
    const job = makeSignedJob({
      action: "renew",
      mode: "real",
      claimId: "claim-lease-order",
      jobId: "job-lease-order",
      commandRef: "certbot-renew",
      caEndpoint: "https://acme.example/dir",
      certPath: path.join(workDir, "deployed", "cert.pem"),
    });

    // ACME/deploy may fail later (stub PEM / no real child); lease renewals
    // before keys and before the ACME attempt must still have fired.
    await executeJob({
      job,
      jobId: job.jobId,
      claimId: job.claimId,
      policyEngine,
      client,
      leaseClient,
      executionContext,
      log: silentLog,
    }).catch(() => {});

    assert.ok(
      leaseCalls.length >= 2,
      `expected >=2 lease renewals (keys + acme), got ${leaseCalls.length}`,
    );
    assert.ok(leaseCalls.every((c) => c.claimId === "claim-lease-order"));
    assert.ok(leaseCalls.every((c) => c.jobId === "job-lease-order"));
  });

  it("renews the lease before a deploy file write", async () => {
    const client = createRecordingClient();
    const executionContext = makeExecutionContext({ dryRun: false });
    const leaseCalls = [];
    const leaseClient = {
      renewLease: async (params) => {
        leaseCalls.push({ ...params });
        return { ok: true, status: "running", claimId: params.claimId };
      },
    };
    const leafPem = fs.readFileSync(
      path.join(__dirname, "verify", "fixtures", "leaf.crt.pem"),
      "utf8",
    );
    const certPath = path.join(workDir, "tls", "lease-deploy.pem");
    fs.mkdirSync(path.dirname(certPath), { recursive: true });
    const job = makeSignedJob({
      jobId: "job-lease-deploy",
      action: "deploy",
      mode: "real",
      claimId: "claim-lease-deploy",
      certificatePem: leafPem,
      certPath,
      target: { type: "domain", reference: "valid.example.com" },
    });

    await executeJob({
      job,
      jobId: job.jobId,
      claimId: job.claimId,
      policyEngine: permissiveEngine(),
      client,
      leaseClient,
      executionContext,
      log: silentLog,
    });

    assert.ok(leaseCalls.length >= 1, "expected a lease renew before deploy write");
    assert.equal(leaseCalls[0].claimId, "claim-lease-deploy");
  });

  it("adopts a heartbeat signingKeyRotation notice and uses the new pin immediately", () => {
    const configDir = workDir;
    ensureConfigDir(configDir);
    writeSigningKeyPin(configDir, {
      signingKeyId: signingKey.signingKeyId,
      signingPublicKeyPem: signingKey.publicKeyPem,
    });
    const executionContext = makeExecutionContext({ dryRun: false });
    assert.equal(
      executionContext.pinnedSigningKey.signingKeyId,
      signingKey.signingKeyId,
    );

    const nextKey = generateSigningKeyPair();
    const adopted = adoptSigningKeyRotation({
      rotation: {
        pendingSigningKeyId: nextKey.signingKeyId,
        pendingPublicKeyPem: nextKey.publicKeyPem,
        supersedesSigningKeyId: signingKey.signingKeyId,
        status: "pending_ack",
      },
      configDir,
      executionContext,
      log: silentLog,
    });
    assert.equal(adopted.adopted, true);
    assert.equal(executionContext.pinnedSigningKey.signingKeyId, nextKey.signingKeyId);
    assert.deepEqual(readSigningKeyPin(configDir), {
      signingKeyId: nextKey.signingKeyId,
      publicKeyPem: nextKey.publicKeyPem,
    });

    // A job signed with the new key verifies against the updated pin.
    const nowMs = Date.now();
    const job = {
      schemaVersion: 1,
      jobId: "job-rot-1",
      workspaceId: "11111111-2222-3333-4444-555555555555",
      certificateId: "cert-1",
      action: "noop",
      target: { type: "domain", reference: "example.com" },
      keyMode: "agent-local",
      requestedAt: new Date(nowMs).toISOString(),
      issuedAt: new Date(nowMs - 1000).toISOString(),
      expiresAt: new Date(nowMs + 5 * 60 * 1000).toISOString(),
      nonce: "nonce-rotation-ack-0123456789abcdef",
      signingKeyId: nextKey.signingKeyId,
    };
    job.signature = signJobPayload({ job, privateKeyPem: nextKey.privateKeyPem });
    const verdict = verifyJobSignature({
      job,
      publicKeyPem: executionContext.pinnedSigningKey.publicKeyPem,
      pinnedSigningKeyId: executionContext.pinnedSigningKey.signingKeyId,
    });
    assert.equal(verdict.allowed, true);

    // Null / absent rotation leaves the pin untouched.
    const pinBefore = { ...executionContext.pinnedSigningKey };
    assert.equal(
      adoptSigningKeyRotation({
        rotation: null,
        configDir,
        executionContext,
        log: silentLog,
      }).adopted,
      false,
    );
    assert.deepEqual(executionContext.pinnedSigningKey, pinBefore);

    // Malformed PEM is refused.
    const refused = adoptSigningKeyRotation({
      rotation: {
        pendingSigningKeyId: "ttsk_evil",
        pendingPublicKeyPem: "not-a-pem",
        supersedesSigningKeyId: nextKey.signingKeyId,
        status: "pending_ack",
      },
      configDir,
      executionContext,
      log: silentLog,
    });
    assert.equal(refused.adopted, false);
    assert.equal(refused.reason, "invalid_pem");
    assert.equal(executionContext.pinnedSigningKey.signingKeyId, nextKey.signingKeyId);
  });

  it("listConfiguredDnsProviderIds derives supportedDnsProviders from config", () => {
    assert.deepEqual(listConfiguredDnsProviderIds(null), []);
    assert.deepEqual(
      listConfiguredDnsProviderIds({
        cloudflare: { credentialsFile: "/a" },
        route53: { credentialsFile: "/b" },
        zoneProviderMap: { "example.com": "cloudflare" },
      }),
      ["cloudflare", "route53"],
    );
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

  it("rejects an unauthorized verify destination after deploy and rolls back to the previous certificate", async () => {
    const client = createRecordingClient();
    const executionContext = makeExecutionContext({ dryRun: false });
    const fixturesDir = path.join(__dirname, "verify", "fixtures");
    const previousPem = fs.readFileSync(path.join(fixturesDir, "leaf.crt.pem"), "utf8");
    const newPem = fs.readFileSync(path.join(fixturesDir, "selfsigned.crt.pem"), "utf8");
    const certPath = path.join(workDir, "tls", "cert.pem");
    fs.mkdirSync(path.dirname(certPath), { recursive: true });
    fs.writeFileSync(certPath, previousPem);

    const job = makeSignedJob({
      jobId: "job-verify-gate",
      action: "deploy",
      certificatePem: newPem,
      certPath,
      target: { type: "domain", reference: "valid.example.com" },
      // Metadata-endpoint class destination: hard-denied by policy no
      // matter what the allowlist says.
      verifyHost: "169.254.169.254",
    });

    const outcome = await handleClaimedJob({
      job,
      policyEngine: permissiveEngine(),
      client,
      executionContext,
      log: silentLog,
    });

    assert.equal(outcome.status, "rejected");
    assert.equal(outcome.rejectionReason, REJECTION_REASONS.TARGET_OUT_OF_SCOPE);

    // The deploy happened first, then the verify gate rejected and the
    // previous certificate was restored on disk.
    assert.equal(fs.readFileSync(certPath, "utf8"), previousPem);

    const result = client.calls.reportResult.find((r) => r.jobId === "job-verify-gate");
    assert.match(result.errorMessage, /rolled back to the previous certificate/);

    const allItems = client.calls.reportEvidence.flatMap((c) => c.evidenceItems);
    assert.ok(
      allItems.some(
        (item) =>
          item.eventType === "validation.failed" &&
          item.metadata.some((m) => m.name === "step" && m.value === "verify"),
      ),
      "expected a validation.failed verify-step evidence item",
    );
    assert.ok(
      allItems.some(
        (item) =>
          item.eventType === "deployment.updated" &&
          item.metadata.some((m) => m.name === "step" && m.value === "rollback") &&
          item.metadata.some((m) => m.name === "restored" && m.value === true),
      ),
      "expected a rollback evidence item with restored=true",
    );
  });

  describe("executeDeployJob pre-deploy validation and orphaned first-deploy", () => {
    const fixturesDir = path.join(__dirname, "verify", "fixtures");
    function readFixture(name) {
      return fs.readFileSync(path.join(fixturesDir, name), "utf8");
    }

    it("rejects a malformed certificate before any file write", async () => {
      const client = createRecordingClient();
      const executionContext = makeExecutionContext({ dryRun: false });
      const certPath = path.join(workDir, "tls", "malformed.pem");
      fs.mkdirSync(path.dirname(certPath), { recursive: true });

      const outcome = await executeDeployJob({
        job: {
          certificateId: "cert-1",
          certificatePem:
            "-----BEGIN CERTIFICATE-----\nMIIBfake-cert-body-for-tests\n-----END CERTIFICATE-----\n",
          certPath,
          target: { type: "domain", reference: "valid.example.com" },
        },
        jobId: "job-deploy-malformed",
        policyEngine: permissiveEngine(),
        client,
        executionContext,
        log: silentLog,
      });

      assert.equal(outcome.status, "failed");
      assert.match(outcome.errorMessage, /CERTIFICATE_PARSE_FAILED|pre-deploy validation failed/);
      assert.equal(fs.existsSync(certPath), false);
    });

    it("rejects an expired certificate before any file write", async () => {
      const client = createRecordingClient();
      const executionContext = makeExecutionContext({ dryRun: false });
      const certPath = path.join(workDir, "tls", "expired.pem");
      fs.mkdirSync(path.dirname(certPath), { recursive: true });

      const outcome = await executeDeployJob({
        job: {
          certificateId: "cert-1",
          certificatePem: readFixture("expired.crt.pem"),
          certPath,
          target: { type: "domain", reference: "expired.example.com" },
        },
        jobId: "job-deploy-expired",
        policyEngine: permissiveEngine(),
        client,
        executionContext,
        log: silentLog,
      });

      assert.equal(outcome.status, "failed");
      assert.match(outcome.errorMessage, /EXPIRED/);
      assert.equal(fs.existsSync(certPath), false);
    });

    it("rejects a certificate whose SANs do not match target.reference", async () => {
      const client = createRecordingClient();
      const executionContext = makeExecutionContext({ dryRun: false });
      const certPath = path.join(workDir, "tls", "wrong-san.pem");
      fs.mkdirSync(path.dirname(certPath), { recursive: true });

      const outcome = await executeDeployJob({
        job: {
          certificateId: "cert-1",
          certificatePem: readFixture("wrong-san.crt.pem"),
          certPath,
          target: { type: "domain", reference: "valid.example.com" },
        },
        jobId: "job-deploy-wrong-san",
        policyEngine: permissiveEngine(),
        client,
        executionContext,
        log: silentLog,
      });

      assert.equal(outcome.status, "failed");
      assert.match(outcome.errorMessage, /SAN_MISMATCH/);
      assert.equal(fs.existsSync(certPath), false);
    });

    it("deploys a valid certificate with no local key (key-match skipped)", async () => {
      const client = createRecordingClient();
      const executionContext = makeExecutionContext({ dryRun: false });
      const certPath = path.join(workDir, "tls", "deploy-ok.pem");
      fs.mkdirSync(path.dirname(certPath), { recursive: true });
      const leafPem = readFixture("leaf.crt.pem");

      const outcome = await executeDeployJob({
        job: {
          certificateId: "cert-1",
          certificatePem: leafPem,
          certPath,
          target: { type: "domain", reference: "valid.example.com" },
        },
        jobId: "job-deploy-ok",
        policyEngine: permissiveEngine(),
        client,
        executionContext,
        log: silentLog,
      });

      assert.equal(outcome.status, "succeeded");
      assert.equal(fs.readFileSync(certPath, "utf8"), leafPem);
    });

    it("rejects when a local key exists but does not match the certificate", async () => {
      const client = createRecordingClient();
      const executionContext = makeExecutionContext({ dryRun: false });
      const certPath = path.join(workDir, "tls", "key-mismatch.pem");
      fs.mkdirSync(path.dirname(certPath), { recursive: true });
      fs.mkdirSync(executionContext.execution.keysDir, { recursive: true });
      fs.writeFileSync(
        path.join(executionContext.execution.keysDir, "cert-1.key.pem"),
        readFixture("mismatch.key.pem"),
        { mode: 0o600 },
      );

      const outcome = await executeDeployJob({
        job: {
          certificateId: "cert-1",
          certificatePem: readFixture("leaf.crt.pem"),
          certPath,
          target: { type: "domain", reference: "valid.example.com" },
        },
        jobId: "job-deploy-key-mismatch",
        policyEngine: permissiveEngine(),
        client,
        executionContext,
        log: silentLog,
      });

      assert.equal(outcome.status, "failed");
      assert.match(outcome.errorMessage, /PRIVATE_KEY_MISMATCH/);
      assert.equal(fs.existsSync(certPath), false);
    });

    it("reports orphaned_unknown_effect when a first-ever deploy is followed by reload failure", async () => {
      const client = createRecordingClient();
      const executionContext = makeExecutionContext({ dryRun: false });
      const certPath = path.join(workDir, "tls", "orphan-reload.pem");
      fs.mkdirSync(path.dirname(certPath), { recursive: true });
      const leafPem = readFixture("leaf.crt.pem");

      const outcome = await executeDeployJob({
        job: {
          certificateId: "cert-1",
          certificatePem: leafPem,
          certPath,
          target: { type: "domain", reference: "valid.example.com" },
          reloadService: "nginx",
          // Missing reloadCommandRefs forces reload failure after deploy.
        },
        jobId: "job-orphan-reload",
        policyEngine: permissiveEngine(),
        client,
        executionContext,
        log: silentLog,
      });

      assert.equal(outcome.status, "orphaned_unknown_effect");
      assert.match(outcome.errorMessage, /first-ever deployment/i);
      assert.match(outcome.errorMessage, /operator reconciliation/i);
      assert.equal(fs.readFileSync(certPath, "utf8"), leafPem);

      const allItems = client.calls.reportEvidence.flatMap((c) => c.evidenceItems);
      assert.ok(
        allItems.some(
          (item) =>
            item.eventType === "deployment.updated" &&
            item.metadata.some((m) => m.name === "orphanedFirstDeploy" && m.value === true),
        ),
        "expected orphaned first-deploy evidence",
      );
    });

    it("reports orphaned_unknown_effect when a first-ever deploy is followed by verify failure", async () => {
      const client = createRecordingClient();
      const executionContext = makeExecutionContext({ dryRun: false });
      const certPath = path.join(workDir, "tls", "orphan-verify.pem");
      fs.mkdirSync(path.dirname(certPath), { recursive: true });
      const leafPem = readFixture("leaf.crt.pem");

      const outcome = await executeDeployJob({
        job: {
          certificateId: "cert-1",
          certificatePem: leafPem,
          certPath,
          target: { type: "domain", reference: "valid.example.com" },
          verifyHost: "169.254.169.254",
        },
        jobId: "job-orphan-verify",
        policyEngine: permissiveEngine(),
        client,
        executionContext,
        log: silentLog,
      });

      assert.equal(outcome.status, "orphaned_unknown_effect");
      assert.match(outcome.errorMessage, /first-ever deployment/i);
      assert.equal(fs.readFileSync(certPath, "utf8"), leafPem);
    });

    it("still rolls back and reports failed when a subsequent deploy has a backup", async () => {
      const client = createRecordingClient();
      const executionContext = makeExecutionContext({ dryRun: false });
      const certPath = path.join(workDir, "tls", "subsequent.pem");
      fs.mkdirSync(path.dirname(certPath), { recursive: true });
      const previousPem = readFixture("leaf.crt.pem");
      const newPem = readFixture("selfsigned.crt.pem");
      fs.writeFileSync(certPath, previousPem);

      const outcome = await executeDeployJob({
        job: {
          certificateId: "cert-1",
          certificatePem: newPem,
          certPath,
          target: { type: "domain", reference: "valid.example.com" },
          reloadService: "nginx",
        },
        jobId: "job-subsequent-reload",
        policyEngine: permissiveEngine(),
        client,
        executionContext,
        log: silentLog,
      });

      assert.equal(outcome.status, "failed");
      assert.notEqual(outcome.status, "orphaned_unknown_effect");
      assert.match(outcome.errorMessage, /rolled back to the previous certificate/);
      assert.equal(fs.readFileSync(certPath, "utf8"), previousPem);
    });
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
              outboxDir: path.join(workDir, "outbox"),
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

  it("preserves a succeeded execution outcome in the outbox when reportResult fails (B8)", async () => {
    let reportAttempts = 0;
    const client = createRecordingClient();
    client.reportResult = (params) => {
      reportAttempts += 1;
      client.calls.reportResult.push(params);
      return Promise.reject(new Error("control plane unreachable"));
    };

    const outcome = await handleClaimedJob({
      job: makeSignedJob({ jobId: "job-b8-tx-fail" }),
      policyEngine: permissiveEngine(),
      client,
      executionContext: makeExecutionContext(),
      log: silentLog,
    });

    // Execution succeeded; transmission failure must not rewrite the outcome.
    assert.equal(outcome.status, "succeeded");
    assert.equal(reportAttempts, 1);

    const outboxDir = path.join(workDir, "outbox");
    const pending = listOutboxEntries(outboxDir);
    assert.equal(pending.length, 1);
    assert.equal(pending[0].result.status, "succeeded");
    assert.equal(pending[0].result.jobId, "job-b8-tx-fail");

    // Retry from the durable outbox without re-executing.
    const retryClient = createRecordingClient();
    const drained = await drainOutbox(outboxDir, retryClient);
    assert.equal(drained.transmitted, 1);
    assert.equal(drained.remaining, 0);
    assert.equal(retryClient.calls.reportResult.length, 1);
    assert.equal(retryClient.calls.reportResult[0].status, "succeeded");
    assert.equal(listOutboxEntries(outboxDir).length, 0);
  });

  it("fails renew early when eabRef is set but not configured locally", async () => {
    const client = createRecordingClient();
    const executionContext = makeExecutionContext({ dryRun: false });
    const certPath = path.join(workDir, "tls", "eab.pem");
    fs.mkdirSync(path.dirname(certPath), { recursive: true });
    const policyEngine = engineWith(
      {
        allowedPaths: [workDir],
        allowedCommands: { "certbot-renew": { argv: ["certbot"] } },
        allowedCaEndpoints: ["https://acme.example/dir"],
      },
      { declaredTargetSelectors: ["example.com"] },
    );

    const outcome = await executeJob({
      job: makeSignedJob({
        action: "renew",
        mode: "real",
        claimId: "claim-eab-missing",
        jobId: "job-eab-missing",
        commandRef: "certbot-renew",
        caEndpoint: "https://acme.example/dir",
        certPath,
        eabRef: "missing-eab",
        target: { type: "domain", reference: "example.com" },
      }),
      jobId: "job-eab-missing",
      claimId: "claim-eab-missing",
      policyEngine,
      client,
      executionContext,
      log: silentLog,
    });

    assert.equal(outcome.status, "failed");
    assert.match(outcome.errorMessage, /not available locally|not configured locally/i);
  });
});

describe("renewal profile fidelity helpers", () => {
  it("resolveJobSans prefers flattened sans and rejects empty/malformed", () => {
    assert.deepEqual(resolveJobSans({ sans: ["a.example", "b.example"] }), {
      sans: ["a.example", "b.example"],
    });
    assert.deepEqual(
      resolveJobSans({
        renewalProfile: { sanPolicy: { sans: ["from.profile"] } },
      }),
      { sans: ["from.profile"] },
    );
    assert.equal(resolveJobSans({}), null);
    assert.match(resolveJobSans({ sans: [] }).error, /empty/);
    assert.match(resolveJobSans({ sans: [""] }).error, /non-empty string/);
  });

  it("mapJobKeyAlgorithm maps profile pairs and rejects unknowns", () => {
    assert.equal(mapJobKeyAlgorithm({}), null);
    assert.deepEqual(mapJobKeyAlgorithm({ keyAlgorithm: "ecdsa", keySize: 256 }), {
      algorithm: "ec-p256",
    });
    assert.deepEqual(mapJobKeyAlgorithm({ keyAlgorithm: "ecdsa", keySize: 384 }), {
      algorithm: "ec-p384",
    });
    assert.deepEqual(mapJobKeyAlgorithm({ keyAlgorithm: "rsa", keySize: 4096 }), {
      algorithm: "rsa-4096",
    });
    assert.match(
      mapJobKeyAlgorithm({ keyAlgorithm: "rsa", keySize: 1024 }).error,
      /unsupported/,
    );
    assert.match(
      mapJobKeyAlgorithm({ keyAlgorithm: "rsa" }).error,
      /both are required/,
    );
  });

  it("resolveJobDeployTargets expands deploymentTargets and falls back to certPath", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tt-targets-"));
    const a = path.join(dir, "a.pem");
    const b = path.join(dir, "b.pem");
    const resolved = resolveJobDeployTargets({
      deploymentTargets: [
        { type: "endpoint", reference: "a", certPath: a },
        { type: "endpoint", reference: "b", certPath: b, reloadService: "nginx" },
      ],
    });
    assert.equal(resolved.targets.length, 2);
    assert.equal(resolved.targets[0].certPath, a);
    assert.equal(resolved.targets[1].reloadService, "nginx");

    const single = resolveJobDeployTargets({
      certPath: a,
      target: { type: "domain", reference: "example.com" },
    });
    assert.equal(single.targets.length, 1);
    assert.equal(single.targets[0].certPath, a);
    fs.rmSync(dir, { recursive: true, force: true });
  });
});

describe("executeDeployJob multi-target fidelity", () => {
  let workDir;

  beforeEach(() => {
    workDir = makeTempConfigDir();
    fs.mkdirSync(path.join(workDir, "tls"), { recursive: true });
  });

  afterEach(() => {
    fs.rmSync(workDir, { recursive: true, force: true });
  });

  function permissiveEngine() {
    return engineWith(
      { allowedPaths: [workDir] },
      { declaredTargetSelectors: ["valid.example.com", "a", "b"] },
    );
  }

  function makeExecutionContext() {
    return buildExecutionContext({
      config: {
        execution: {
          enabled: true,
          dryRun: false,
          keysDir: path.join(workDir, "keys"),
          replayStorePath: path.join(workDir, "replay.json"),
          outboxDir: path.join(workDir, "outbox"),
          clockDriftToleranceMs: 300000,
        },
        pinnedSigningKey: null,
        acmeAccounts: null,
      },
    });
  }

  function readFixture(name) {
    return fs.readFileSync(path.join(__dirname, "verify", "fixtures", name), "utf8");
  }

  it("deploys to every deploymentTargets destination", async () => {
    const client = createRecordingClient();
    const leafPem = readFixture("leaf.crt.pem");
    const a = path.join(workDir, "tls", "a.pem");
    const b = path.join(workDir, "tls", "b.pem");

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
      jobId: "job-multi-ok",
      policyEngine: permissiveEngine(),
      client,
      executionContext: makeExecutionContext(),
      log: silentLog,
    });

    assert.equal(outcome.status, "succeeded");
    assert.equal(fs.readFileSync(a, "utf8"), leafPem);
    assert.equal(fs.readFileSync(b, "utf8"), leafPem);
    assert.equal(outcome.targetOutcomes.length, 2);
  });

  it("fails the job when any deployment target fails", async () => {
    const client = createRecordingClient();
    const leafPem = readFixture("leaf.crt.pem");
    const a = path.join(workDir, "tls", "ok.pem");
    const missingParent = path.join(workDir, "missing-dir", "fail.pem");

    const outcome = await executeDeployJob({
      job: {
        certificateId: "cert-1",
        certificatePem: leafPem,
        target: { type: "domain", reference: "valid.example.com" },
        deploymentTargets: [
          { type: "endpoint", reference: "a", certPath: a },
          { type: "endpoint", reference: "b", certPath: missingParent },
        ],
      },
      jobId: "job-multi-fail",
      policyEngine: permissiveEngine(),
      client,
      executionContext: makeExecutionContext(),
      log: silentLog,
    });

    assert.equal(outcome.status, "failed");
    assert.equal(fs.readFileSync(a, "utf8"), leafPem);
    assert.match(outcome.errorMessage, /target 2\/2/);
    assert.ok(outcome.targetOutcomes.some((t) => t.status === "failed"));
  });
});
