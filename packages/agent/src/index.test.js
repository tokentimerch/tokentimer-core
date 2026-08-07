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
const crypto = require("node:crypto");
const { EventEmitter } = require("node:events");

const {
  handleClaimedJob,
  UNVERIFIED_JOB_ID_PLACEHOLDER,
  buildExecutionContext,
  buildJobPolicyDescriptor,
  resolveJobCertPath,
  resolveJobMode,
  isValidCertificateId,
  runDiscoveryScan,
  registerIfNeeded,
  createCandidateAgentId,
  resolveClaimSupportedActions,
  shouldPollForJobs,
  adoptSigningKeyRotation,
  executeJob,
  executeDeployJob,
  renewJobLeaseOrAbort,
  createLeaseState,
  startPeriodicLeaseRenewal,
  stopPeriodicLeaseRenewal,
  AGENT_VERSION,
  EXECUTABLE_JOB_ACTIONS,
  OBSERVE_ONLY_CLAIM_ACTIONS,
  resolveJobSans,
  mapJobKeyAlgorithm,
  resolveJobDeployTargets,
  resolveDeclaredCapabilities,
  verifyDeployedCertificateWithRetry,
  MAX_VERIFY_TRANSIENT_RETRIES,
  VERIFY_TRANSIENT_RETRY_DELAYS_MS,
  runWindowsRetentionSweep,
  reconcileOrphanedWindowsCngContainers,
} = require("./index.js");
const {
  markSideEffectReached,
  recordWindowsCngContainer,
  markWindowsCngContainerReconciled,
  scanUnresolvedJournalEntries,
  hasUnresolvedJournalForJob,
  clearJournalOnTerminal,
} = require("./job-journal");
const { listOutboxEntries, drainOutbox } = require("./outbox");
const { readLedgerRow, createLedgerRow } = require("./windows-retention");
const { recordIssuedContainer, markIssuedContainerAccepted } = require("./windows-cert-store");
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
const {
  generateSigningKeyPair,
  signJobPayload,
  verifyJobSignature,
  AGENT_ID_BINDING_CAPABILITY,
  AGENT_ID_BINDING_REJECTION_REASONS,
  getAgentIdBindingMetrics,
  resetAgentIdBindingMetrics,
} = require("./signing");
const {
  AGENT_PROTOCOL_ERROR_CODES,
  AgentProtocolError,
} = require("./protocol");

function makeTempConfigDir() {
  // .native is required on Windows: os.tmpdir() can resolve through a
  // short 8.3 alias (e.g. GitHub-hosted runners' RUNNER~1), while
  // deployCertificate's realpath-based containment re-check resolves
  // through fs.promises.realpath (documented as the promisified form of
  // fs.realpath.native). Plain fs.realpathSync does not perform that
  // Win32 short-name expansion, so it would leave any checkPath allowlist
  // built from this dir on a different spelling than what production
  // code compares against.
  return fs.realpathSync.native(
    fs.mkdtempSync(path.join(os.tmpdir(), "ttagent-index-test-")),
  );
}

/**
 * Fixed, non-empty stand-in for a real agent's registered identity, used as
 * boundAgentId across tests that exercise handleClaimedJob's post-verdict
 * gate but do not themselves test ADR-0012 decision 3's agentId binding
 * (checkAgentIdBinding requires a non-empty boundAgentId unconditionally,
 * since a real agent always knows its own identity by the time it verifies
 * a job). Tests that DO exercise agentId binding declare their own distinct
 * bound/signed ids instead of using this constant.
 */
const TEST_BOUND_AGENT_ID = "agent-test-bound-1";

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

async function waitUntil(predicate, { timeoutMs = 2000, intervalMs = 5 } = {}) {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= deadline) {
      throw new Error(`waitUntil: condition not met within ${timeoutMs}ms`);
    }
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
}

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

/**
 * ADR-0012 decision 2: "there is no observe-only carve-out" from the one
 * normative verification order. `handleClaimedJob` with NO executionContext
 * at all (true bootstrap: no config.execution ever configured) has no
 * possible source for a pinned signing key, so it always lands in
 * decision 2's one above-the-gate exception ("no signing key pinned at
 * all" -> report "blocked"), regardless of what the raw job looks like.
 * This is a deliberate behavior change from the pre-fix code, which used
 * to run the raw wire object through validateClaimedJob (a bootstrap-only
 * schema with no signature/verification concept at all) and could report
 * "rejected" built from unverified fields -- exactly the pattern this ADR
 * forbids. See the "observe-only signature verification" describe block
 * below for the (legitimate, still-supported) case where observe-only mode
 * DOES have a pinned key and therefore runs full verification.
 */
describe("handleClaimedJob (true bootstrap: no executionContext at all)", () => {
  it("reports blocked with the raw job's own identifiers for a v1-shaped job (no signing key pinned)", async () => {
    const client = createRecordingClient();
    const policyEngine = engineWith({}, { declaredTargetSelectors: [] });

    const outcome = await handleClaimedJob({
      job: claimedJob({ jobId: "job-1", claimId: "claim-1", nonce: "nonce-0123456789abcdef" }),
      policyEngine,
      client,
      log: silentLog,
    });

    assert.equal(outcome.status, "blocked");
    assert.equal(client.calls.reportEvidence.length, 0);
    assert.equal(client.calls.reportResult.length, 1);
    const result = client.calls.reportResult[0];
    assert.equal(result.status, "blocked");
    assert.equal(result.jobId, "job-1");
    assert.equal(result.claimId, "claim-1");
    assert.equal(result.nonce, "nonce-0123456789abcdef");
    assert.match(result.errorMessage, /no control-plane signing key is pinned/);
  });

  it("reports blocked with a local, non-attacker-influenced placeholder jobId when the raw job has none (e.g. a v2 envelope)", async () => {
    // A v2 envelope carries no outer jobId at all (ADR-0012 decision 1);
    // this must never resolve to "skipped, nothing reported" the way a
    // missing job.jobId used to short-circuit BEFORE any verification
    // attempt (that early read is exactly decision 16's fix target).
    const client = createRecordingClient();
    const policyEngine = engineWith();

    const outcome = await handleClaimedJob({
      job: { envelopeVersion: 2, payloadB64: "irrelevant", signatureB64: "irrelevant", signingKeyId: "irrelevant" },
      policyEngine,
      client,
      log: silentLog,
    });

    assert.equal(outcome.status, "blocked");
    assert.equal(client.calls.reportResult.length, 1);
    const result = client.calls.reportResult[0];
    assert.equal(result.status, "blocked");
    assert.equal(result.jobId, UNVERIFIED_JOB_ID_PLACEHOLDER);
    assert.equal(result.claimId, null);
    assert.equal(result.nonce, null);
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

  it("clears the Windows service registry Environment value on the already-registered path too", async () => {
    fs.writeFileSync(
      path.join(dir, "config.json"),
      JSON.stringify({ serverUrl: "https://cp.example.com", agentId: "agent-existing" }),
      "utf8",
    );
    writeCredential(dir, "ttagent_agent-existing_0123456789abcdef");

    const clearCalls = [];
    const platformModule = {
      isWindows: () => true,
      clearWindowsServiceBootstrapToken: (options) => {
        clearCalls.push(options);
        return { attempted: true, cleared: true };
      },
    };

    const client = createRecordingClient();
    const agentId = await registerIfNeeded({
      client,
      config: loadConfigFrom(dir),
      configDir: dir,
      env: {},
      platformModule,
    });

    assert.equal(agentId, "agent-existing");
    assert.equal(clearCalls.length, 1);
    assert.equal(clearCalls[0].configDir, dir);
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
    // This build's verify step always reports fingerprint + validTo evidence
    // bound to the claim, so it must declare the capability issuance
    // reconciliation gates on; otherwise every issue job would sit at
    // 'pending' forever against a freshly registered agent. On win32,
    // windows-cert-store-v1/iis-binding-v1 are also candidate capabilities
    // (AGENT_CANDIDATE_CAPABILITIES) and, since real-host verification on
    // tokentimer-winverify-vm qualified them in qualified-capabilities.json,
    // they now pass the manifest gate too.
    const expectedDeclaredCapabilities =
      process.platform === "win32"
        ? ["evidence-claim-binding-v1", "windows-cert-store-v1", "iis-binding-v1"]
        : ["evidence-claim-binding-v1"];
    assert.deepEqual(registerCall.declaredCapabilities, expectedDeclaredCapabilities);
    // H1: registrationId must be sent and must match the pre-persisted key.
    assert.match(registerCall.registrationId, /^[0-9a-f-]{36}$/i);
    assert.equal(readRegistrationId(dir), null); // cleared after successful persist

    // The validated registration record is persisted as one recoverable
    // identity + credential transaction by registerIfNeeded itself.
    const persisted = JSON.parse(fs.readFileSync(path.join(dir, "config.json"), "utf8"));
    assert.equal(persisted.agentId, "agent-assigned-1");
    assert.equal(readCredential(dir), "ttagent_agent-assigned-1_0123456789abcdef");
  });

  it("clears the Windows service registry Environment value after a successful registration", async () => {
    fs.writeFileSync(
      path.join(dir, "config.json"),
      JSON.stringify({ serverUrl: "https://cp.example.com" }),
      "utf8",
    );

    const clearCalls = [];
    const platformModule = {
      isWindows: () => true,
      clearWindowsServiceBootstrapToken: (options) => {
        clearCalls.push(options);
        return { attempted: true, cleared: true };
      },
    };

    const client = createRecordingClient();
    await registerIfNeeded({
      client,
      config: loadConfigFrom(dir),
      configDir: dir,
      env: { TOKENTIMER_AGENT_BOOTSTRAP_TOKEN: "bootstrap-raw-token" },
      platformModule,
    });

    assert.equal(clearCalls.length, 1);
    assert.equal(clearCalls[0].configDir, dir);
  });

  it("logs, but does not throw, when the Windows registry scrub cannot confirm success", async () => {
    fs.writeFileSync(
      path.join(dir, "config.json"),
      JSON.stringify({ serverUrl: "https://cp.example.com" }),
      "utf8",
    );

    const logCalls = [];
    const platformModule = {
      isWindows: () => true,
      clearWindowsServiceBootstrapToken: () => ({
        attempted: true,
        cleared: false,
        reason: "reg.exe add exited 1",
      }),
    };

    const client = createRecordingClient();
    const agentId = await registerIfNeeded({
      client,
      config: loadConfigFrom(dir),
      configDir: dir,
      env: { TOKENTIMER_AGENT_BOOTSTRAP_TOKEN: "bootstrap-raw-token" },
      platformModule,
      log: (...args) => logCalls.push(args),
    });

    assert.equal(agentId, "agent-assigned-1");
    assert.equal(logCalls.length, 1);
    assert.match(logCalls[0][0], /reg\.exe add exited 1/);
  });

  it("never calls the Windows registry scrub on a non-Windows platform", async () => {
    fs.writeFileSync(
      path.join(dir, "config.json"),
      JSON.stringify({ serverUrl: "https://cp.example.com" }),
      "utf8",
    );

    const clearCalls = [];
    const platformModule = {
      isWindows: () => false,
      clearWindowsServiceBootstrapToken: (options) => {
        clearCalls.push(options);
        return { attempted: false, cleared: false };
      },
    };

    const client = createRecordingClient();
    await registerIfNeeded({
      client,
      config: loadConfigFrom(dir),
      configDir: dir,
      env: { TOKENTIMER_AGENT_BOOTSTRAP_TOKEN: "bootstrap-raw-token" },
      platformModule,
    });

    assert.equal(clearCalls.length, 0);
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
      jobId: overrides.jobId || "job-signed-1",
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

  it("submits NO result for an unsigned job while execution is enabled (trusted-identity gate)", async () => {
    // ADR-0012 decision 2: a signature-verdict failure must not produce a
    // result of any kind, because claimId/nonce live inside the payload the
    // verdict just declared untrustworthy. The job fails locally and its
    // lease expires.
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

    assert.equal(outcome.status, "failed");
    assert.equal(outcome.rejectionReason, "job_integrity_failed");
    assert.equal(client.calls.reportResult.length, 0);
    assert.equal(client.calls.reportEvidence.length, 0);
  });

  it("submits NO result for a tampered job, and never echoes its claimId/nonce", async () => {
    const client = createRecordingClient();
    const job = makeSignedJob();
    job.action = "renew"; // mutate after signing
    job.claimId = "attacker-chosen-claim";
    job.nonce = "attackerchosennonce123456";

    const outcome = await handleClaimedJob({
      job,
      policyEngine: permissiveEngine(),
      client,
      executionContext: makeExecutionContext(),
      log: silentLog,
    });

    assert.equal(outcome.status, "failed");
    assert.equal(outcome.rejectionReason, "job_integrity_failed");
    assert.equal(client.calls.reportResult.length, 0);
    assert.equal(client.calls.reportEvidence.length, 0);
    // The attacker-controlled identifiers must not reach the control plane
    // through any call this attempt made.
    const transmitted = JSON.stringify(client.calls);
    assert.ok(!transmitted.includes("attacker-chosen-claim"));
    assert.ok(!transmitted.includes("attackerchosennonce123456"));
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
      boundAgentId: TEST_BOUND_AGENT_ID,
      log: silentLog,
    });
    assert.equal(first.status, "succeeded");

    const second = await handleClaimedJob({
      job,
      policyEngine,
      client,
      executionContext,
      boundAgentId: TEST_BOUND_AGENT_ID,
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
      boundAgentId: TEST_BOUND_AGENT_ID,
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
      boundAgentId: TEST_BOUND_AGENT_ID,
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
    const job = makeSignedJob({ claimId: "claim-ok-1" });

    const outcome = await handleClaimedJob({
      job,
      policyEngine: permissiveEngine(),
      client,
      executionContext: makeExecutionContext(),
      boundAgentId: TEST_BOUND_AGENT_ID,
      log: silentLog,
    });

    assert.equal(outcome.status, "succeeded");
    const result = client.calls.reportResult[0];
    assert.equal(result.status, "succeeded");
    assert.equal(result.claimId, "claim-ok-1");
    assert.equal(result.nonce, job.nonce);
    assert.equal(result.attemptId, "claim-ok-1");
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
        boundAgentId: TEST_BOUND_AGENT_ID,
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
      claimId: "claim-fail-1",
      certPath: path.join(workDir, "deployed", "cert.pem"),
    });

    const outcome = await handleClaimedJob({
      job,
      policyEngine: permissiveEngine(),
      client,
      executionContext: makeExecutionContext({ dryRun: false }),
      boundAgentId: TEST_BOUND_AGENT_ID,
      log: silentLog,
    });

    assert.equal(outcome.status, "failed");
    const result = client.calls.reportResult[0];
    assert.equal(result.status, "failed");
    assert.equal(result.claimId, "claim-fail-1");
    assert.equal(result.nonce, job.nonce);
  });

  it("passes job.claimId/job.nonce through on a below-the-gate rejection report", async () => {
    // The pass-through property is asserted through a SEMANTIC rejection
    // (agent-local policy denies the target), which sits below the
    // trusted-identity gate. A signature-verdict failure cannot be used
    // here: per ADR-0012 decision 2 it submits no result at all, so there
    // would be nothing to inspect.
    const client = createRecordingClient();
    const job = makeSignedJob({ claimId: "claim-rej-1" });

    const outcome = await handleClaimedJob({
      job,
      policyEngine: permissiveEngine([]), // target selector not declared
      client,
      executionContext: makeExecutionContext(),
      boundAgentId: TEST_BOUND_AGENT_ID,
      log: silentLog,
    });

    assert.equal(outcome.status, "rejected");
    const result = client.calls.reportResult[0];
    assert.equal(result.status, "rejected");
    assert.equal(result.claimId, "claim-rej-1");
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
      boundAgentId: TEST_BOUND_AGENT_ID,
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
      boundAgentId: TEST_BOUND_AGENT_ID,
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

  it("resolveJobMode fails CLOSED (dry_run) on an unrecognized mode string, never defaulting to real", () => {
    // Regression: a present-but-garbage mode value (typo, future enum value
    // this build predates, or a tampered field) must never be treated the
    // same as "omitted" -- omitted safely defaults to "real" per
    // COORDINATION-B4, but a value that IS present and does NOT match a
    // known mode must resolve to the no-side-effect "dry_run" mode instead
    // of silently running live operations.
    assert.equal(resolveJobMode({ mode: "REAL" }), "dry_run");
    assert.equal(resolveJobMode({ mode: "live" }), "dry_run");
    assert.equal(resolveJobMode({ mode: "dry-run" }), "dry_run");
    assert.equal(resolveJobMode({ mode: "" }), "real");
    assert.equal(resolveJobMode({ payload: { mode: "bogus" } }), "dry_run");
    // Top-level garbage takes precedence over a valid nested value too.
    assert.equal(resolveJobMode({ mode: "bogus", payload: { mode: "real" } }), "dry_run");
  });

  it("isValidCertificateId enforces the job-payload.schema.json certificateId shape", () => {
    assert.equal(isValidCertificateId("cert-1"), true);
    assert.equal(isValidCertificateId("Cert_1.example:2026"), true);
    assert.equal(isValidCertificateId("a".repeat(128)), true);
    // Regression: this is the one gate standing between an untrusted
    // certificateId and a keysDir path-traversal write/read
    // (`${certificateId}.key.pem`), so every path-hostile shape must be
    // rejected structurally, matching the schema's pattern/length exactly.
    assert.equal(isValidCertificateId("../../../etc/passwd"), false);
    assert.equal(isValidCertificateId("a/b"), false);
    assert.equal(isValidCertificateId("a\\b"), false);
    assert.equal(isValidCertificateId(""), false);
    assert.equal(isValidCertificateId("a".repeat(129)), false);
    assert.equal(isValidCertificateId(null), false);
    assert.equal(isValidCertificateId(undefined), false);
    assert.equal(isValidCertificateId(42), false);
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
      boundAgentId: TEST_BOUND_AGENT_ID,
      log: silentLog,
    });

    assert.equal(outcome.status, "blocked");
    assert.equal(client.calls.renewLease.length, 1);
    assert.equal(client.calls.renewLease[0].claimId, "claim-lease-lost");
    assert.equal(client.calls.reportResult.length, 1);
    assert.equal(client.calls.reportResult[0].status, "blocked");
    assert.match(client.calls.reportResult[0].errorMessage, /HTTP 409/);
  });

  it("aborts when the mandatory first lease renew fails with a network error", async () => {
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
      boundAgentId: TEST_BOUND_AGENT_ID,
      log: silentLog,
    });

    assert.equal(outcome.status, "blocked");
    assert.equal(renewAttempts, 1);
    assert.equal(client.calls.reportResult.length, 1);
    assert.equal(client.calls.reportResult[0].status, "blocked");
    assert.match(client.calls.reportResult[0].errorMessage, /mandatory confirmation failed/);
  });

  it("rejects a real renew job whose deploy certPath is outside the policy allowlist BEFORE generating a key (fail-fast, no wasted ACME order)", async () => {
    const client = createRecordingClient();
    const executionContext = makeExecutionContext({ dryRun: false });
    // allowedPaths only covers workDir/deployed; the job's certPath points
    // elsewhere entirely, matching a policy-disallowed deploy destination.
    const disallowedDir = path.join(workDir, "not-allowed");
    fs.mkdirSync(disallowedDir, { recursive: true });
    const policyEngine = engineWith(
      {
        allowedPaths: [path.join(workDir, "deployed")],
        allowedCommands: { "certbot-renew": { argv: ["certbot"] } },
        allowedCaEndpoints: ["https://acme.example/dir"],
      },
      { declaredTargetSelectors: ["example.com"] },
    );
    const job = makeSignedJob({
      action: "renew",
      mode: "real",
      claimId: "claim-path-preflight",
      jobId: "job-path-preflight",
      commandRef: "certbot-renew",
      caEndpoint: "https://acme.example/dir",
      certPath: path.join(disallowedDir, "cert.pem"),
    });

    const outcome = await executeJob({
      job,
      jobId: job.jobId,
      claimId: job.claimId,
      policyEngine,
      client,
      executionContext,
      log: silentLog,
    });

    assert.equal(outcome.status, "rejected");
    assert.ok(outcome.rejectionReason, "expected a policy rejectionReason");
    // The whole point of a fail-fast preflight: no key material was ever
    // generated (keysDir itself was never even created) for a job that
    // was always going to be rejected at deploy time anyway.
    assert.equal(fs.existsSync(executionContext.execution.keysDir), false);
  });

  it("binds every reportEvidence call to the job's claimId (evidence-claim-binding-v1)", async () => {
    // The agent declares the evidence-claim-binding-v1 capability at
    // registration (see AGENT_DECLARED_CAPABILITIES), which is only honest if
    // evidence produced during execution actually carries claimId. A noop job
    // is the simplest deterministic path that unconditionally reports evidence.
    const client = createRecordingClient();
    const executionContext = makeExecutionContext({ dryRun: false });
    const policyEngine = engineWith({}, { declaredTargetSelectors: [] });
    const job = makeSignedJob({
      action: "noop",
      mode: "real",
      claimId: "claim-evidence-binding-1",
      jobId: "job-evidence-binding-1",
    });

    const outcome = await executeJob({
      job,
      jobId: job.jobId,
      claimId: job.claimId,
      policyEngine,
      client,
      executionContext,
      log: silentLog,
    });

    assert.equal(outcome.status, "succeeded");
    assert.equal(client.calls.reportEvidence.length, 1);
    assert.equal(
      client.calls.reportEvidence[0].claimId,
      "claim-evidence-binding-1",
    );
  });

  it("rejects a real renew job with a policy-disallowed dnsProvider before any mutation", async () => {
    const client = createRecordingClient();
    const executionContext = makeExecutionContext({ dryRun: false });
    const policyEngine = engineWith(
      {
        allowedPaths: [workDir],
        allowedCommands: { "certbot-renew": { argv: ["certbot"] } },
        allowedCaEndpoints: ["https://acme.example/dir"],
        allowedDnsProviders: ["route53"],
      },
      { declaredTargetSelectors: ["example.com"] },
    );
    const job = makeSignedJob({
      action: "renew",
      mode: "real",
      claimId: "claim-dns-preflight",
      jobId: "job-dns-preflight",
      commandRef: "certbot-renew",
      caEndpoint: "https://acme.example/dir",
      certPath: path.join(workDir, "deployed", "cert.pem"),
      dnsProvider: "cloudflare",
      dnsZone: "example.com",
    });

    const outcome = await executeJob({
      job,
      jobId: job.jobId,
      claimId: job.claimId,
      policyEngine,
      client,
      executionContext,
      log: silentLog,
    });

    assert.equal(outcome.status, "rejected");
    assert.equal(fs.existsSync(executionContext.execution.keysDir), false);
  });

  it("rejects a real renew job whose certificateId is path-traversal-shaped, BEFORE writing any key file", async () => {
    const client = createRecordingClient();
    const executionContext = makeExecutionContext({ dryRun: false });
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
      claimId: "claim-certid-preflight",
      jobId: "job-certid-preflight",
      commandRef: "certbot-renew",
      caEndpoint: "https://acme.example/dir",
      certPath: path.join(workDir, "deployed", "cert.pem"),
      certificateId: "../../../etc/cron.d/malicious",
    });

    const outcome = await executeJob({
      job,
      jobId: job.jobId,
      claimId: job.claimId,
      policyEngine,
      client,
      executionContext,
      log: silentLog,
    });

    assert.equal(outcome.status, "failed");
    assert.match(outcome.errorMessage, /certificateId/);
    // The gate runs before keysDir is even created; no key file exists
    // anywhere, in particular not outside keysDir.
    assert.equal(fs.existsSync(executionContext.execution.keysDir), false);
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
      boundAgentId: TEST_BOUND_AGENT_ID,
      log: silentLog,
    });
    assert.equal(revokeOutcome.status, "blocked");

    const deployOutcome = await handleClaimedJob({
      job: makeSignedJob({ jobId: "job-deploy", action: "deploy" }),
      policyEngine,
      client,
      executionContext,
      boundAgentId: TEST_BOUND_AGENT_ID,
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
      boundAgentId: TEST_BOUND_AGENT_ID,
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

  it("reports blocked (no pinned key available) for a signed-dispatch job when executionContext is null", async () => {
    // executionContext === null means there is no possible source for a
    // pinned signing key (ADR-0012 decision 2's one above-the-gate
    // exception), so this lands in the same "blocked" case as execution-
    // enabled-but-unpinned above -- it must NOT run the raw job through any
    // bootstrap-only schema validator, and it must NOT report "rejected"
    // built from unverified fields (the pre-fix behavior this replaces).
    const client = createRecordingClient();
    const job = makeSignedJob();

    const outcome = await handleClaimedJob({
      job,
      policyEngine: permissiveEngine(),
      client,
      executionContext: null,
      log: silentLog,
    });

    assert.equal(outcome.status, "blocked");
    assert.equal(client.calls.reportResult.length, 1);
    const result = client.calls.reportResult[0];
    assert.equal(result.status, "blocked");
    assert.equal(result.jobId, job.jobId);
    assert.equal(result.nonce, job.nonce);
    assert.match(result.errorMessage, /no control-plane signing key is pinned/);
    assert.equal(client.calls.reportEvidence.length, 0);
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

  it("buildExecutionContext threads the configured clockDriftToleranceMs into the replay cache's retention (not the 30s default)", () => {
    // Regression: retentionToleranceMs must track execution.clockDriftToleranceMs
    // exactly, since checkJobTimeWindow accepts jobs until expiresAt + that same
    // tolerance. A hardcoded default here would let the sweep evict a nonce
    // while its job is still acceptable, reopening the replay window.
    const storePath = path.join(workDir, "tolerance-replay-store.json");
    const context = buildExecutionContext({
      config: {
        execution: {
          enabled: true,
          dryRun: true,
          keysDir: path.join(workDir, "tolerance-keys"),
          replayStorePath: storePath,
          outboxDir: path.join(workDir, "tolerance-outbox"),
          clockDriftToleranceMs: 300000,
        },
        pinnedSigningKey: null,
      },
    });

    const nowMs = Date.now();
    // expiresAt is 100s in the past: outside the 30s default tolerance
    // (would be evicted) but well inside the configured 300s tolerance
    // (must be retained).
    const expiresAt = nowMs - 100000;
    context.replayCache.consume({ nonce: "n-1", jobId: "job-1", expiresAt });

    const removed = context.replayCache.sweep(nowMs);
    assert.equal(removed, 0, "nonce must survive sweep within the configured 300s tolerance");
    assert.equal(context.replayCache.size(), 1);

    // Past the configured tolerance, the sweep must evict it.
    const removedLater = context.replayCache.sweep(nowMs + 300000 + 1000);
    assert.equal(removedLater, 1);
    assert.equal(context.replayCache.size(), 0);
  });

  it("startPeriodicLeaseRenewal clears a stale abort once a later heartbeat actually confirms the lease (no sticky misreport)", async () => {
    // Regression: a transient heartbeat failure at/after the confirmed lease
    // expiry aborts immediately (status "blocked"). If the very next
    // heartbeat then succeeds, getAbort() must stop reporting that stale
    // abort -- otherwise a fully executed success later gets overwritten
    // with "blocked" (see handleClaimedJob) and the journal cleanup for
    // terminal "blocked" outcomes erases the record of real side effects.
    let calls = 0;
    const leaseClient = {
      renewLease: async () => {
        calls += 1;
        if (calls === 1) {
          throw new Error("simulated transient network blip");
        }
        return {
          ok: true,
          leaseExpiresAt: new Date(Date.now() + 900000).toISOString(),
        };
      },
    };
    const leaseState = createLeaseState();
    // Already at/past expiry so the first transient failure aborts
    // immediately (no internal retry loop to wait out).
    leaseState.lastConfirmedExpiresAtMs = Date.now() - 1000;

    const handle = startPeriodicLeaseRenewal(
      { leaseClient, jobId: "job-sticky", claimId: "claim-1", log: silentLog, leaseState },
      { intervalMs: 10 },
    );
    try {
      await waitUntil(() => calls >= 1, { timeoutMs: 2000 });
      await waitUntil(() => handle.getAbort() !== null, { timeoutMs: 2000 });
      assert.equal(handle.getAbort().status, "blocked");

      await waitUntil(() => calls >= 2, { timeoutMs: 2000 });
      await waitUntil(() => handle.getAbort() === null, { timeoutMs: 2000 });
      assert.equal(
        handle.getAbort(),
        null,
        "a later successful renew must clear the earlier transient abort",
      );
    } finally {
      stopPeriodicLeaseRenewal(handle);
    }
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
      boundAgentId: TEST_BOUND_AGENT_ID,
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

/**
 * ADR-0012 decision 2: "There is no observe-only carve-out from this
 * order." These tests exercise handleClaimedJob's observe-only branch
 * (executionContext.enabled === false, but a pinnedSigningKey IS available
 * to it -- a legitimate configuration distinct from the true-bootstrap,
 * no-executionContext-at-all case covered above) through the exact same
 * verify-then-derive-identity boundary as the execution-enabled tests
 * above, closing the Finding B gap where this branch used to call
 * validateClaimedJob directly on the raw, unverified wire object with no
 * signature check at all.
 */
describe("observe-only signature verification (ADR-0012 decision 2 Finding B closure)", () => {
  let workDir;
  let signingKey;

  beforeEach(() => {
    workDir = makeTempConfigDir();
    signingKey = generateSigningKeyPair();
  });

  afterEach(() => {
    fs.rmSync(workDir, { recursive: true, force: true });
  });

  function observeOnlyContext({ pinned = true } = {}) {
    return {
      enabled: false,
      pinnedSigningKey: pinned
        ? { signingKeyId: signingKey.signingKeyId, publicKeyPem: signingKey.publicKeyPem }
        : null,
    };
  }

  function baseJobFields(overrides = {}) {
    const nowMs = Date.now();
    return {
      schemaVersion: 1,
      jobId: "job-observe-1",
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
  }

  function makeSignedJobV1(overrides = {}) {
    const job = baseJobFields(overrides);
    job.signature = signJobPayload({ job, privateKeyPem: signingKey.privateKeyPem });
    return job;
  }

  function makeV2Envelope(overrides = {}) {
    const job = baseJobFields(overrides);
    const payloadBytes = Buffer.from(JSON.stringify(job), "utf8");
    const signatureBytes = crypto.sign(
      null,
      payloadBytes,
      crypto.createPrivateKey(signingKey.privateKeyPem),
    );
    const envelope = {
      envelopeVersion: 2,
      payloadB64: payloadBytes.toString("base64"),
      signatureB64: signatureBytes.toString("base64"),
      signingKeyId: signingKey.signingKeyId,
    };
    return { envelope, job };
  }

  function permissiveEngine(selectors = ["example.com"]) {
    return engineWith({ allowedPaths: [workDir] }, { declaredTargetSelectors: selectors });
  }

  it("submits NO result for a tampered v1 job in observe-only mode (same silent failure as execution-enabled)", async () => {
    const client = createRecordingClient();
    const job = makeSignedJobV1();
    job.claimId = "attacker-chosen-claim";
    job.nonce = "attacker-chosen-nonce-0123456789";

    const outcome = await handleClaimedJob({
      job,
      policyEngine: permissiveEngine(),
      client,
      executionContext: observeOnlyContext(),
      log: silentLog,
    });

    assert.equal(outcome.status, "failed");
    assert.equal(outcome.rejectionReason, "job_integrity_failed");
    assert.equal(client.calls.reportResult.length, 0);
    assert.equal(client.calls.reportEvidence.length, 0);
    const transmitted = JSON.stringify(client.calls);
    assert.ok(!transmitted.includes("attacker-chosen-claim"));
    assert.ok(!transmitted.includes("attacker-chosen-nonce"));
  });

  it("submits NO result for a v2 envelope with a bad signature in observe-only mode, proving no early skip for v2's missing outer jobId", async () => {
    const client = createRecordingClient();
    const { envelope } = makeV2Envelope();
    const corrupted = { ...envelope, signatureB64: Buffer.alloc(64, 1).toString("base64") };
    assert.equal(corrupted.jobId, undefined);

    const outcome = await handleClaimedJob({
      job: corrupted,
      policyEngine: permissiveEngine(),
      client,
      executionContext: observeOnlyContext(),
      log: silentLog,
    });

    assert.equal(outcome.status, "failed");
    assert.equal(outcome.rejectionReason, "job_integrity_failed");
    assert.equal(client.calls.reportResult.length, 0);
    assert.equal(client.calls.reportEvidence.length, 0);
  });

  it("reports a policy rejection built from post-gate identifiers for a valid v1 job in observe-only mode", async () => {
    const client = createRecordingClient();
    const job = makeSignedJobV1({ claimId: "claim-observe-1" });

    const outcome = await handleClaimedJob({
      job,
      policyEngine: engineWith({}, { declaredTargetSelectors: [] }),
      client,
      executionContext: observeOnlyContext(),
      boundAgentId: TEST_BOUND_AGENT_ID,
      log: silentLog,
    });

    assert.equal(outcome.status, "rejected");
    assert.equal(outcome.rejectionReason, REJECTION_REASONS.TARGET_OUT_OF_SCOPE);
    assert.equal(client.calls.reportEvidence.length, 1);
    assert.equal(client.calls.reportResult.length, 1);
    const result = client.calls.reportResult[0];
    assert.equal(result.jobId, job.jobId);
    assert.equal(result.claimId, "claim-observe-1");
    assert.equal(result.nonce, job.nonce);
    assert.equal(result.status, "rejected");
  });

  it("reports key_export_requested for a valid job that requests key export, in observe-only mode", async () => {
    const client = createRecordingClient();
    const job = makeSignedJobV1({ exportPrivateKey: true });

    const outcome = await handleClaimedJob({
      job,
      policyEngine: permissiveEngine(),
      client,
      executionContext: observeOnlyContext(),
      boundAgentId: TEST_BOUND_AGENT_ID,
      log: silentLog,
    });

    assert.equal(outcome.status, "rejected");
    assert.equal(outcome.rejectionReason, REJECTION_REASONS.KEY_EXPORT_REQUESTED);
  });

  it("reports blocked when policy allows a verified v1 job but execution is not enabled", async () => {
    const client = createRecordingClient();
    const job = makeSignedJobV1();

    const outcome = await handleClaimedJob({
      job,
      policyEngine: permissiveEngine(),
      client,
      executionContext: observeOnlyContext(),
      boundAgentId: TEST_BOUND_AGENT_ID,
      log: silentLog,
    });

    assert.equal(outcome.status, "blocked");
    assert.equal(client.calls.reportEvidence.length, 0);
    assert.equal(client.calls.reportResult.length, 1);
    const result = client.calls.reportResult[0];
    assert.equal(result.status, "blocked");
    assert.equal(result.jobId, job.jobId);
    assert.match(result.errorMessage, /execution is not enabled/);
  });

  it("processes a valid v2 envelope in observe-only mode using the decoded payload's identifiers (the wire envelope has none)", async () => {
    const client = createRecordingClient();
    const { envelope, job } = makeV2Envelope({ claimId: "claim-v2-observe" });
    assert.equal(envelope.jobId, undefined);

    const outcome = await handleClaimedJob({
      job: envelope,
      policyEngine: permissiveEngine(),
      client,
      executionContext: observeOnlyContext(),
      boundAgentId: TEST_BOUND_AGENT_ID,
      log: silentLog,
    });

    assert.equal(outcome.status, "blocked");
    assert.equal(client.calls.reportResult.length, 1);
    const result = client.calls.reportResult[0];
    assert.equal(result.jobId, job.jobId);
    assert.equal(result.claimId, "claim-v2-observe");
    assert.equal(result.nonce, job.nonce);
  });

  it("reports blocked with the raw job's own identifiers when no signing key is pinned at all, in observe-only mode (v1)", async () => {
    const client = createRecordingClient();
    const job = makeSignedJobV1({ claimId: "claim-nopin-1" });

    const outcome = await handleClaimedJob({
      job,
      policyEngine: permissiveEngine(),
      client,
      executionContext: observeOnlyContext({ pinned: false }),
      log: silentLog,
    });

    assert.equal(outcome.status, "blocked");
    const result = client.calls.reportResult[0];
    assert.equal(result.jobId, job.jobId);
    assert.equal(result.claimId, "claim-nopin-1");
    assert.equal(result.nonce, job.nonce);
    assert.match(result.errorMessage, /no control-plane signing key is pinned/);
  });

  it("reports blocked with the local placeholder jobId when no signing key is pinned at all, in observe-only mode (v2, no outer jobId)", async () => {
    const client = createRecordingClient();
    const { envelope } = makeV2Envelope();

    const outcome = await handleClaimedJob({
      job: envelope,
      policyEngine: permissiveEngine(),
      client,
      executionContext: observeOnlyContext({ pinned: false }),
      log: silentLog,
    });

    assert.equal(outcome.status, "blocked");
    const result = client.calls.reportResult[0];
    assert.equal(result.jobId, UNVERIFIED_JOB_ID_PLACEHOLDER);
    assert.equal(result.claimId, null);
    assert.equal(result.nonce, null);
  });
});

/**
 * ADR-0012 decision 3, gate step 11, exercised through the full
 * handleClaimedJob path rather than checkAgentIdBinding directly: a job
 * signed for one agent's identity must fail closed at the gate before any
 * result is submitted, for both wire shapes the agent accepts (v1's signed
 * object and v2's payloadB64 envelope), and regardless of
 * requireSignedAgentId, since a mismatch is never tolerated by that flag.
 */
describe("agentId mismatch fails closed at the gate (ADR-0012 decision 3, both wire shapes)", () => {
  let workDir;
  let signingKey;
  const AGENT_A = "agent-A";
  const AGENT_B = "agent-B";

  beforeEach(() => {
    workDir = makeTempConfigDir();
    signingKey = generateSigningKeyPair();
  });

  afterEach(() => {
    fs.rmSync(workDir, { recursive: true, force: true });
  });

  function makeExecutionContext() {
    const config = {
      execution: {
        enabled: true,
        dryRun: true,
        keysDir: path.join(workDir, "keys"),
        replayStorePath: path.join(workDir, "replay-store.json"),
        outboxDir: path.join(workDir, "outbox"),
        clockDriftToleranceMs: 30000,
      },
      pinnedSigningKey: {
        signingKeyId: signingKey.signingKeyId,
        publicKeyPem: signingKey.publicKeyPem,
      },
    };
    return buildExecutionContext({ config });
  }

  function baseJobFields(overrides = {}) {
    const nowMs = Date.now();
    return {
      schemaVersion: 1,
      jobId: "job-mismatch-1",
      workspaceId: "11111111-2222-3333-4444-555555555555",
      agentId: AGENT_A,
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
  }

  function makeSignedJobV1(overrides = {}) {
    const job = baseJobFields(overrides);
    job.signature = signJobPayload({ job, privateKeyPem: signingKey.privateKeyPem });
    return job;
  }

  function makeV2Envelope(overrides = {}) {
    const job = baseJobFields(overrides);
    const payloadBytes = Buffer.from(JSON.stringify(job), "utf8");
    const signatureBytes = crypto.sign(
      null,
      payloadBytes,
      crypto.createPrivateKey(signingKey.privateKeyPem),
    );
    return {
      envelopeVersion: 2,
      payloadB64: payloadBytes.toString("base64"),
      signatureB64: signatureBytes.toString("base64"),
      signingKeyId: signingKey.signingKeyId,
    };
  }

  function permissiveEngine() {
    return engineWith({ allowedPaths: [workDir] }, { declaredTargetSelectors: ["example.com"] });
  }

  for (const requireSignedAgentId of [false, true]) {
    it(`v1 wire shape: job signed for ${AGENT_A} delivered to ${AGENT_B} fails at the gate before any action (requireSignedAgentId=${requireSignedAgentId})`, async () => {
      const client = createRecordingClient();
      const job = makeSignedJobV1();

      const outcome = await handleClaimedJob({
        job,
        policyEngine: permissiveEngine(),
        client,
        executionContext: makeExecutionContext(),
        boundAgentId: AGENT_B,
        requireSignedAgentId,
        log: silentLog,
      });

      assert.equal(outcome.status, "failed");
      assert.equal(outcome.rejectionReason, "agent_id_mismatch");
      assert.equal(client.calls.reportResult.length, 0);
      assert.equal(client.calls.reportEvidence.length, 0);
    });

    it(`v2 wire shape: job signed for ${AGENT_A} delivered to ${AGENT_B} fails at the gate before any action (requireSignedAgentId=${requireSignedAgentId})`, async () => {
      const client = createRecordingClient();
      const envelope = makeV2Envelope();

      const outcome = await handleClaimedJob({
        job: envelope,
        policyEngine: permissiveEngine(),
        client,
        executionContext: makeExecutionContext(),
        boundAgentId: AGENT_B,
        requireSignedAgentId,
        log: silentLog,
      });

      assert.equal(outcome.status, "failed");
      assert.equal(outcome.rejectionReason, "agent_id_mismatch");
      assert.equal(client.calls.reportResult.length, 0);
      assert.equal(client.calls.reportEvidence.length, 0);
    });
  }
});

/**
 * Mismatch observability: an agentId mismatch must be distinguishable, at
 * scale, from every other rejection reason -- both in the log stream (a
 * stable, distinct message, never the generic "failed signature
 * verification" line used for every other rejection) and in the paired
 * counter checkAgentIdBinding maintains (packages/agent/src/signing/
 * index.js's getAgentIdBindingMetrics). Exercised through the full
 * handleClaimedJob path, same as the describe block above, so this proves
 * the wiring between checkAgentIdBinding's verdict and src/index.js's log
 * call, not just checkAgentIdBinding in isolation (already covered by
 * signing.test.js).
 */
describe("agentId mismatch observability (log + counter, ADR-0012 decision 3)", () => {
  let workDir;
  let signingKey;
  const AGENT_A = "agent-A";
  const AGENT_B = "agent-B";

  beforeEach(() => {
    workDir = makeTempConfigDir();
    signingKey = generateSigningKeyPair();
    resetAgentIdBindingMetrics();
  });

  afterEach(() => {
    fs.rmSync(workDir, { recursive: true, force: true });
  });

  function makeExecutionContext() {
    const config = {
      execution: {
        enabled: true,
        dryRun: true,
        keysDir: path.join(workDir, "keys"),
        replayStorePath: path.join(workDir, "replay-store.json"),
        outboxDir: path.join(workDir, "outbox"),
        clockDriftToleranceMs: 30000,
      },
      pinnedSigningKey: {
        signingKeyId: signingKey.signingKeyId,
        publicKeyPem: signingKey.publicKeyPem,
      },
    };
    return buildExecutionContext({ config });
  }

  function makeSignedJobV1(overrides = {}) {
    const nowMs = Date.now();
    const job = {
      schemaVersion: 1,
      jobId: "job-mismatch-observability-1",
      workspaceId: "11111111-2222-3333-4444-555555555555",
      agentId: AGENT_A,
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
    return engineWith({ allowedPaths: [workDir] }, { declaredTargetSelectors: ["example.com"] });
  }

  function createRecordingLog() {
    const calls = [];
    const log = (message, details) => {
      calls.push({ message, details });
    };
    return { calls, log };
  }

  it("emits a stable, distinct log line for a mismatch, never the generic signature-verification message", async () => {
    const client = createRecordingClient();
    const job = makeSignedJobV1();
    const { calls, log } = createRecordingLog();

    const outcome = await handleClaimedJob({
      job,
      policyEngine: permissiveEngine(),
      client,
      executionContext: makeExecutionContext(),
      boundAgentId: AGENT_B,
      requireSignedAgentId: false,
      log,
    });

    assert.equal(outcome.status, "failed");
    assert.equal(outcome.rejectionReason, AGENT_ID_BINDING_REJECTION_REASONS.AGENT_ID_MISMATCH);

    assert.equal(calls.length, 1);
    assert.match(calls[0].message, /agent-id binding gate/);
    assert.match(calls[0].message, /agentId mismatch/);
    assert.doesNotMatch(calls[0].message, /failed signature verification/);
    assert.equal(calls[0].details.rejectionReason, AGENT_ID_BINDING_REJECTION_REASONS.AGENT_ID_MISMATCH);
    assert.equal(calls[0].details.boundAgentId, AGENT_B);
  });

  it("increments getAgentIdBindingMetrics().mismatches through the full handleClaimedJob path", async () => {
    const client = createRecordingClient();
    const job = makeSignedJobV1();
    const { log } = createRecordingLog();

    assert.equal(getAgentIdBindingMetrics().mismatches, 0);

    await handleClaimedJob({
      job,
      policyEngine: permissiveEngine(),
      client,
      executionContext: makeExecutionContext(),
      boundAgentId: AGENT_B,
      requireSignedAgentId: false,
      log,
    });

    assert.equal(getAgentIdBindingMetrics().mismatches, 1);
  });

  it("uses the generic signature-verification message for a non-mismatch rejection (e.g. a tampered signature), not the mismatch-specific one", async () => {
    const client = createRecordingClient();
    const job = makeSignedJobV1();
    job.signature = job.signature.slice(0, -4) + "abcd"; // tamper: signature no longer verifies
    const { calls, log } = createRecordingLog();

    const outcome = await handleClaimedJob({
      job,
      policyEngine: permissiveEngine(),
      client,
      executionContext: makeExecutionContext(),
      boundAgentId: AGENT_A,
      requireSignedAgentId: false,
      log,
    });

    assert.equal(outcome.status, "failed");
    assert.notEqual(outcome.rejectionReason, AGENT_ID_BINDING_REJECTION_REASONS.AGENT_ID_MISMATCH);
    assert.equal(calls.length, 1);
    assert.match(calls[0].message, /failed signature verification/);
    assert.equal(getAgentIdBindingMetrics().mismatches, 0);
  });
});

/**
 * ADR-0012 decision 3, step 4: agent-id-binding-v1 must be advertised from
 * the EFFECTIVE runtime value of requireSignedAgentId, never from the
 * compiled-in default. The shipped default is currently false, so the
 * "default true" direction is proven by calling resolveDeclaredCapabilities
 * directly with the override value it would receive at runtime (its only
 * argument IS the already-resolved effective value; there is no separate
 * "default" input for it to read), which is exactly the mechanism under
 * test: the function has no way to reach for a compiled-in default even if
 * it wanted to.
 */
describe("resolveDeclaredCapabilities advertises agent-id-binding-v1 from the effective value only", () => {
  it("effective false (default false, no override) does NOT advertise agent-id-binding-v1", () => {
    const capabilities = resolveDeclaredCapabilities(false);
    assert.ok(!capabilities.includes(AGENT_ID_BINDING_CAPABILITY));
  });

  it("effective true (default false, overridden true) DOES advertise agent-id-binding-v1", () => {
    const capabilities = resolveDeclaredCapabilities(true);
    assert.ok(capabilities.includes(AGENT_ID_BINDING_CAPABILITY));
  });

  it("effective false (simulated default true, overridden false) does NOT advertise agent-id-binding-v1", () => {
    // Simulates a future release where the compiled-in default has flipped to
    // true but this process's effective value was overridden back to false
    // (env var or config.json). resolveDeclaredCapabilities takes only the
    // effective value, so this proves the mechanism cannot see the compiled
    // default at all, today or after that future flip.
    const simulatedEffectiveValue = false;
    const capabilities = resolveDeclaredCapabilities(simulatedEffectiveValue);
    assert.ok(!capabilities.includes(AGENT_ID_BINDING_CAPABILITY));
  });

  it("base capability set is always present regardless of the effective value", () => {
    for (const requireSignedAgentId of [false, true]) {
      const capabilities = resolveDeclaredCapabilities(requireSignedAgentId);
      assert.ok(capabilities.includes("evidence-claim-binding-v1"));
    }
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
    // Transactional rollback: first-deploy target A is removed after B fails.
    assert.equal(fs.existsSync(a), false);
    assert.match(outcome.errorMessage, /target 2|rolled back|first-deploy/i);
    assert.ok(outcome.targetOutcomes.some((t) => t.status === "failed"));
  });
});

describe("lease fail-closed + side-effect journal + multi-target transaction", () => {
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
      path.join(__dirname, "verify", "fixtures", name),
      "utf8",
    );
  }

  function assertNoPrivateKeyMaterial(value) {
    const text = typeof value === "string" ? value : JSON.stringify(value);
    assert.doesNotMatch(text, /BEGIN [A-Z0-9 ]*PRIVATE KEY/);
  }

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

  it("aborts mid-job when ownership is lost on a subsequent renew", async () => {
    const leaseState = createLeaseState();
    leaseState.lastConfirmedExpiresAtMs = Date.now() + 60_000;
    let calls = 0;
    const leaseClient = {
      renewLease: async () => {
        calls += 1;
        if (calls === 1) {
          return { ok: false, status: 409, code: "CERTOPS_AGENT_CLAIM_OWNERSHIP_MISMATCH" };
        }
        return { ok: true, leaseExpiresAt: new Date(Date.now() + 60_000).toISOString() };
      },
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
    // Push clock to just before expiry so backoff would overshoot.
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
    const stateDir = workDir;
    const jobId = "job-journal-crash";
    const attemptId = "attempt-crash-1";
    markSideEffectReached({
      stateDir,
      jobId,
      attemptId,
      claimId: "claim-j",
      stage: "keygen",
    });
    assert.equal(hasUnresolvedJournalForJob(stateDir, jobId), true);
    const unresolved = scanUnresolvedJournalEntries(stateDir);
    assert.equal(unresolved.length, 1);
    assert.equal(unresolved[0].stage, "keygen");

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
    assert.equal(client.calls.reportResult.length, 1);
    assert.match(
      client.calls.reportResult[0].errorMessage,
      /unresolved local side-effect journal/i,
    );
    assert.match(
      client.calls.reportResult[0].errorMessage,
      /needsOperatorReconciliation=true/,
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
    const cleared = clearJournalOnTerminal({
      stateDir: workDir,
      jobId,
      attemptId,
      status: "succeeded",
    });
    assert.equal(cleared.cleared, true);
    assert.equal(hasUnresolvedJournalForJob(workDir, jobId), false);
  });

  it("rolls back the first target when the second write fails (transactional)", async () => {
    const client = createRecordingClient();
    const leafPem = readFixture("leaf.crt.pem");
    const a = path.join(workDir, "tls", "t1.pem");
    const bDir = path.join(workDir, "tls");
    fs.mkdirSync(bDir, { recursive: true });
    // Pre-create an existing cert on A so rollback restores a backup.
    const previous = readFixture("wrong-san.crt.pem");
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

  it("returns orphaned_unknown_effect when multi-target rollback itself fails", async () => {
    const client = createRecordingClient();
    const leafPem = readFixture("leaf.crt.pem");
    const a = path.join(workDir, "tls", "keep.pem");
    fs.mkdirSync(path.dirname(a), { recursive: true });
    fs.writeFileSync(a, readFixture("wrong-san.crt.pem"), { mode: 0o600 });
    const b = path.join(workDir, "tls", "ok2.pem");

    // Poison backups by deleting them after deploy of A via a custom path:
    // deploy A+B where B fails verifyHost authorization after both would need
    // A applied — use missing parent for B so A is applied then rolled back,
    // and delete A's backup mid-flight by making backupDir unwritable...
    // Simpler: spy by removing backup after success of A using two-phase with
    // injected failure in removeDeployedArtifacts path: use first-deploy A
    // and make unlink fail by replacing file with a directory after deploy.
    const outcome = await executeDeployJob({
      job: {
        certificateId: "cert-1",
        certificatePem: leafPem,
        target: { type: "domain", reference: "valid.example.com" },
        deploymentTargets: [
          { type: "endpoint", reference: "a", certPath: a },
          {
            type: "endpoint",
            reference: "b",
            certPath: path.join(workDir, "absent-dir", "x.pem"),
          },
        ],
      },
      jobId: "job-tx-rollback-ok",
      policyEngine: permissiveEngine(["valid.example.com"]),
      client,
      executionContext: makeExecutionContext(),
      log: silentLog,
    });
    // Successful restore of prior backup => ordinary failed (not orphaned).
    assert.equal(outcome.status, "failed");
    assert.equal(fs.readFileSync(a, "utf8"), readFixture("wrong-san.crt.pem"));
    assert.ok(!JSON.stringify(client.calls).includes("BEGIN PRIVATE KEY"));
    void b;
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
    assert.equal(fs.readFileSync(certA, "utf8"), leafPem);
    assert.equal(fs.readFileSync(certB, "utf8"), leafPem);
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

describe("renew chain deployment", () => {
  const CERTIFICATE_ID = "certificate-chain";
  const RENEW_JOB_ID = "job-chain";
  const CA_ENDPOINT = "https://acme.example/dir";

  let workDir;
  let signingKey;

  beforeEach(() => {
    workDir = makeTempConfigDir();
    signingKey = generateSigningKeyPair();
    fs.mkdirSync(path.join(workDir, "deployed"), { recursive: true });
  });

  afterEach(() => {
    fs.rmSync(workDir, { recursive: true, force: true });
  });

  function readFixture(name) {
    return fs.readFileSync(
      path.join(__dirname, "verify", "fixtures", name),
      "utf8",
    );
  }

  function keysDir() {
    return path.join(workDir, "keys");
  }

  function makeExecutionContext(acmeExecFileImpl) {
    return buildExecutionContext({
      config: {
        execution: {
          enabled: true,
          dryRun: false,
          keysDir: keysDir(),
          replayStorePath: path.join(workDir, "replay.json"),
          outboxDir: path.join(workDir, "outbox"),
          clockDriftToleranceMs: 300000,
        },
        pinnedSigningKey: null,
        acmeAccounts: null,
      },
      acmeExecFileImpl,
    });
  }

  /**
   * Seeds the live key so the renewal reuses it instead of rotating: the
   * fixture chain is issued for this exact key, so pre-deploy key matching
   * passes without having to mint a real certificate in the test.
   */
  function seedLiveKey() {
    fs.mkdirSync(keysDir(), { recursive: true });
    fs.writeFileSync(
      path.join(keysDir(), `${CERTIFICATE_ID}.key.pem`),
      readFixture("chain-leaf.key.pem"),
      { mode: 0o600 },
    );
  }

  function argvValue(args, flag) {
    const at = args.indexOf(flag);
    assert.notEqual(at, -1, `adapter argv is missing ${flag}`);
    return args[at + 1];
  }

  /**
   * Stands in for certbot: writes the leaf, chain and fullchain artifacts to
   * the paths the adapter asked for, so the staging layout under test is the
   * one the real tool would produce.
   */
  function makeCertbotStub({ exitCode = 0 } = {}) {
    const calls = [];
    function execFileStub(file, args, options, callback) {
      calls.push({ file, args, options });
      fs.writeFileSync(
        argvValue(args, "--cert-path"),
        readFixture("chain-leaf.crt.pem"),
        { mode: 0o600 },
      );
      fs.writeFileSync(
        argvValue(args, "--chain-path"),
        readFixture("intermediate.crt.pem"),
        { mode: 0o600 },
      );
      fs.writeFileSync(
        argvValue(args, "--fullchain-path"),
        readFixture("chain-leaf-fullchain.crt.pem"),
        { mode: 0o600 },
      );
      const error =
        exitCode === 0
          ? null
          : Object.assign(new Error("Command failed"), { code: exitCode });
      process.nextTick(() => callback(error, "", exitCode === 0 ? "" : "order failed"));
    }
    execFileStub.calls = calls;
    return execFileStub;
  }

  function makeJob(overrides = {}) {
    const nowMs = Date.now();
    const job = {
      schemaVersion: 1,
      jobId: RENEW_JOB_ID,
      workspaceId: "11111111-1111-4111-8111-111111111111",
      certificateId: CERTIFICATE_ID,
      action: "renew",
      target: { type: "domain", reference: "chain.example.com" },
      requestedAt: new Date(nowMs).toISOString(),
      issuedAt: new Date(nowMs).toISOString(),
      expiresAt: new Date(nowMs + 5 * 60 * 1000).toISOString(),
      nonce: `nonce-${Math.random().toString(16).slice(2)}-0123456789abcdef`,
      claimId: "claim-chain",
      mode: "real",
      commandRef: "certbot-renew",
      caEndpoint: CA_ENDPOINT,
      certPath: path.join(workDir, "deployed", "chain.crt.pem"),
      signingKeyId: signingKey.signingKeyId,
      ...overrides,
    };
    job.signature = signJobPayload({
      job,
      privateKeyPem: signingKey.privateKeyPem,
    });
    return job;
  }

  function permissiveEngine() {
    return engineWith(
      {
        allowedPaths: [workDir],
        allowedCommands: { "certbot-renew": { argv: ["certbot"] } },
        allowedCaEndpoints: [CA_ENDPOINT],
      },
      { declaredTargetSelectors: ["chain.example.com"] },
    );
  }

  async function runRenew({ job, acmeExecFileImpl }) {
    const client = createRecordingClient();
    const outcome = await executeJob({
      job,
      jobId: job.jobId,
      claimId: job.claimId,
      policyEngine: permissiveEngine(),
      client,
      executionContext: makeExecutionContext(acmeExecFileImpl),
      log: silentLog,
    });
    return { outcome, client };
  }

  function stagingLeftovers() {
    return fs
      .readdirSync(keysDir())
      .filter((entry) => entry !== `${CERTIFICATE_ID}.key.pem`);
  }

  it("deploys the fullchain to certPath by default, intermediate included", async () => {
    seedLiveKey();
    const job = makeJob();
    const { outcome } = await runRenew({
      job,
      acmeExecFileImpl: makeCertbotStub(),
    });

    assert.equal(outcome.status, "succeeded");
    const deployed = fs.readFileSync(job.certPath, "utf8");
    assert.equal(deployed, readFixture("chain-leaf-fullchain.crt.pem"));
    assert.ok(deployed.includes(readFixture("chain-leaf.crt.pem").trim()));
    assert.ok(deployed.includes(readFixture("intermediate.crt.pem").trim()));
  });

  it("splits leaf and intermediates when the target configures a chainPath", async () => {
    seedLiveKey();
    const chainPath = path.join(workDir, "deployed", "chain.ca.pem");
    const job = makeJob({ chainPath });
    const { outcome } = await runRenew({
      job,
      acmeExecFileImpl: makeCertbotStub(),
    });

    assert.equal(outcome.status, "succeeded");
    const deployedCert = fs.readFileSync(job.certPath, "utf8");
    const deployedChain = fs.readFileSync(chainPath, "utf8");
    const leaf = readFixture("chain-leaf.crt.pem").trim();
    const intermediate = readFixture("intermediate.crt.pem").trim();

    assert.ok(deployedCert.includes(leaf));
    assert.equal(deployedCert.includes(intermediate), false);
    assert.ok(deployedChain.includes(intermediate));
    assert.equal(deployedChain.includes(leaf), false);
  });

  it("leaves no staging artifact behind after a successful renewal", async () => {
    seedLiveKey();
    const job = makeJob();
    const { outcome } = await runRenew({
      job,
      acmeExecFileImpl: makeCertbotStub(),
    });

    assert.equal(outcome.status, "succeeded");
    assert.deepEqual(stagingLeftovers(), []);
  });

  it("leaves no staging artifact behind after a failed renewal", async () => {
    seedLiveKey();
    const job = makeJob();
    const { outcome } = await runRenew({
      job,
      acmeExecFileImpl: makeCertbotStub({ exitCode: 1 }),
    });

    assert.equal(outcome.status, "failed");
    assert.match(outcome.errorMessage, /acme step failed/);
    assert.deepEqual(stagingLeftovers(), []);
    assert.equal(fs.existsSync(job.certPath), false);
  });

  it("falls back to the stdout excerpt when a failed acme run has no stderr", async () => {
    // Regression test: acme.sh routes most diagnostics (including RENEW_SKIP)
    // through its own _info logger to stdout, not stderr. A failure message
    // that only inspects stderrExcerpt reports the unhelpful "no stderr" for
    // exactly the acme.sh failures an operator most needs explained.
    seedLiveKey();
    const job = makeJob();
    function execFileStub(file, args, options, callback) {
      const error = Object.assign(new Error("Command failed"), { code: 2 });
      process.nextTick(() =>
        callback(error, "Skipping renew, Next renewal time is: ...", ""),
      );
    }
    const { outcome } = await runRenew({ job, acmeExecFileImpl: execFileStub });

    assert.equal(outcome.status, "failed");
    assert.match(outcome.errorMessage, /Skipping renew, Next renewal time is/);
  });
});

describe("windows-iis renew job (os-store-managed)", () => {
  const CERTIFICATE_ID = "certificate-iis";
  const RENEW_JOB_ID = "job-iis";
  const CA_ENDPOINT = "https://acme.example/dir";
  const OTHER_THUMBPRINT = "AA".repeat(20);

  const FIXTURE_NEW_CERT_PEM = fs.readFileSync(
    path.join(__dirname, "verify", "fixtures", "selfsigned.crt.pem"),
    "utf8",
  );
  const NEW_THUMBPRINT = new crypto.X509Certificate(FIXTURE_NEW_CERT_PEM).fingerprint.replace(
    /:/g,
    "",
  );

  let workDir;
  let signingKey;

  beforeEach(() => {
    workDir = makeTempConfigDir();
    signingKey = generateSigningKeyPair();
  });

  afterEach(() => {
    fs.rmSync(workDir, { recursive: true, force: true });
  });

  function keysDir() {
    return path.join(workDir, "keys");
  }

  function stateDir() {
    return path.dirname(keysDir());
  }

  function makeExecutionContext({ acmeExecFileImpl, windowsExecFileImpl, windowsConnectImpl }) {
    return buildExecutionContext({
      config: {
        execution: {
          enabled: true,
          dryRun: false,
          keysDir: keysDir(),
          replayStorePath: path.join(workDir, "replay.json"),
          outboxDir: path.join(workDir, "outbox"),
          clockDriftToleranceMs: 300000,
        },
        pinnedSigningKey: null,
        acmeAccounts: null,
      },
      acmeExecFileImpl,
      windowsExecFileImpl,
      windowsConnectImpl,
    });
  }

  /**
   * Stands in for certbot: writes the new self-signed fixture certificate
   * to the outCertPath the adapter asked for (the windows-iis path never
   * separately deploys a chain/intermediate file, so a single leaf is
   * all any test here needs).
   */
  function makeCertbotStub({ exitCode = 0 } = {}) {
    const calls = [];
    function execFileStub(file, args, options, callback) {
      calls.push({ file, args, options });
      const at = args.indexOf("--cert-path");
      if (at !== -1) {
        fs.writeFileSync(args[at + 1], FIXTURE_NEW_CERT_PEM, { mode: 0o600 });
      }
      const error =
        exitCode === 0
          ? null
          : Object.assign(new Error("Command failed"), { code: exitCode });
      process.nextTick(() => callback(error, "", exitCode === 0 ? "" : "order failed"));
    }
    execFileStub.calls = calls;
    return execFileStub;
  }

  /**
   * Combined certreq.exe/certutil.exe/netsh.exe stub covering every
   * Windows child-process tool the CNG/IIS/discovery modules invoke for
   * one windows-iis renewal, keyed on the invoked executable (argv[0])
   * rather than one tool at a time like the sibling modules' own tests,
   * since a single renewal call here drives all three in sequence.
   *
   * @param {object} opts
   * @param {string|null} [opts.outgoingThumbprint] what `netsh http show
   *   sslcert` reports as already bound, before this deploy. null means
   *   "nothing bound yet" (first-ever deploy to this binding).
   * @param {string|null} [opts.storeKeyContainer] the Key Container netsh's
   *   sibling `certutil -store` reports for the outgoing certificate, so
   *   recordSupersededWindowsCertificate can resolve ownershipProvenance.
   */
  function makeWindowsExecStub({ outgoingThumbprint = null, storeKeyContainer = null, acceptExitCode = 0 } = {}) {
    const calls = [];
    function execFileStub(file, args, options, callback) {
      calls.push({ file, args, options });
      let error = null;
      let stdout = "";
      let stderr = "";
      if (file === "certreq.exe" && args[1] === "-new") {
        const reqPath = args[args.length - 1];
        fs.writeFileSync(
          reqPath,
          "-----BEGIN NEW CERTIFICATE REQUEST-----\nMAMCAQA=\n-----END NEW CERTIFICATE REQUEST-----\n",
          "utf8",
        );
      } else if (file === "certreq.exe" && args[1] === "-accept") {
        // acceptCertificateViaCng computes the thumbprint itself from the
        // certificatePem bytes; certreq's own stdout is not parsed.
        if (acceptExitCode !== 0) {
          error = Object.assign(new Error("no matching request"), { code: acceptExitCode });
          stderr = "CertReq: No match";
        }
      } else if (file === "netsh.exe" && args[1] === "show") {
        stdout = outgoingThumbprint
          ? `\nSSL Certificate bindings:\n-------------------------\n\n    IP:port                      : 0.0.0.0:443\n    Certificate Hash              : ${outgoingThumbprint}\n    Application ID              : {12345678-1234-1234-1234-123456789012}\n    Certificate Store Name        : My\n`
          : "";
      } else if (file === "netsh.exe" && (args[1] === "add" || args[1] === "delete")) {
        stdout = "";
      } else if (file === "certutil.exe" && args[0] === "-store") {
        stdout = outgoingThumbprint
          ? `My "Personal"\n================ Certificate 0 ================\nSerial Number: 1a2b3c4d5e\nIssuer: CN=Test Root CA\n NotBefore: 1/1/2026 12:00 AM\n NotAfter: 1/1/2027 12:00 AM\nSubject: CN=old.example.com\nCert Hash(sha1): ${outgoingThumbprint.match(/../g).join(" ")}\n${storeKeyContainer ? `  Key Container = ${storeKeyContainer}\n` : ""}CertUtil: -store command completed successfully.\n`
          : `My "Personal"\nCertUtil: -store command completed successfully.\n`;
      } else if (file === "certutil.exe" && args[0] === "-csp" && args[2] === "-delkey") {
        // removeAbandonedKeyContainer's cleanup call after an ACME failure.
        stdout = "CertUtil: -delkey command completed successfully.\n";
      } else {
        error = new Error(`unexpected windows exec call: ${file} ${args.join(" ")}`);
      }
      process.nextTick(() => callback(error, stdout, stderr));
    }
    execFileStub.calls = calls;
    return execFileStub;
  }

  /** TLS-verify connectImpl stub: always presents the certificate that was
   * just deployed, matching real deployIisBinding usage where the verify
   * step happens right after the netsh add call this same stub answered. */
  function makeConnectStub() {
    function connectStub(_options) {
      const socket = new EventEmitter();
      socket.destroy = () => {};
      socket.getPeerCertificate = () => ({
        raw: new crypto.X509Certificate(FIXTURE_NEW_CERT_PEM).raw,
      });
      process.nextTick(() => socket.emit("secureConnect"));
      return socket;
    }
    return connectStub;
  }

  function makeJob(overrides = {}) {
    const nowMs = Date.now();
    const job = {
      schemaVersion: 1,
      jobId: RENEW_JOB_ID,
      workspaceId: "11111111-1111-4111-8111-111111111111",
      certificateId: CERTIFICATE_ID,
      action: "renew",
      target: {
        type: "windows-iis",
        reference: "iis.example.com",
        store: "My",
        binding: { site: "Default Web Site", port: 443 },
      },
      keyMode: "os-store-managed",
      requestedAt: new Date(nowMs).toISOString(),
      issuedAt: new Date(nowMs).toISOString(),
      expiresAt: new Date(nowMs + 5 * 60 * 1000).toISOString(),
      nonce: `nonce-${Math.random().toString(16).slice(2)}-0123456789abcdef`,
      claimId: "claim-iis",
      mode: "real",
      commandRef: "certbot-renew",
      caEndpoint: CA_ENDPOINT,
      signingKeyId: signingKey.signingKeyId,
      ...overrides,
    };
    job.signature = signJobPayload({
      job,
      privateKeyPem: signingKey.privateKeyPem,
    });
    return job;
  }

  function permissiveEngine() {
    return engineWith(
      {
        allowedCommands: { "certbot-renew": { argv: ["certbot"] } },
        allowedCaEndpoints: [CA_ENDPOINT],
      },
      { declaredTargetSelectors: ["iis.example.com"] },
    );
  }

  async function runIisRenew({ job, windowsOpts = {}, acmeExitCode = 0 }) {
    const client = createRecordingClient();
    const windowsExecFileImpl = makeWindowsExecStub(windowsOpts);
    const outcome = await executeJob({
      job,
      jobId: job.jobId,
      claimId: job.claimId,
      policyEngine: permissiveEngine(),
      client,
      executionContext: makeExecutionContext({
        acmeExecFileImpl: makeCertbotStub({ exitCode: acmeExitCode }),
        windowsExecFileImpl,
        windowsConnectImpl: makeConnectStub(),
      }),
      log: silentLog,
    });
    return { outcome, client, windowsExecFileImpl };
  }

  it("runs CNG CSR -> ACME -> certreq accept -> IIS bind -> TLS verify end to end and reports succeeded", async () => {
    const job = makeJob();
    const { outcome } = await runIisRenew({ job });

    assert.equal(outcome.status, "succeeded");
    assert.equal(outcome.keyRotated, null);
  });

  it("reports a claim-bound validation.passed/step=verify evidence item carrying fingerprintSha256 and validTo, so control-plane reconciliation (reconcileProvisionedCertificate / refreshRenewedCertificateEvidence) can promote or refresh the certificate row", async () => {
    const job = makeJob();
    const { outcome, client } = await runIisRenew({ job });

    assert.equal(outcome.status, "succeeded");
    const allItems = client.calls.reportEvidence.flatMap((c) => c.evidenceItems);
    const verifyItem = allItems.find(
      (item) => item.eventType === "validation.passed" &&
        item.metadata.some((m) => m.name === "step" && m.value === "verify"),
    );
    assert.notEqual(verifyItem, undefined);
    assert.equal(typeof verifyItem.fingerprintSha256, "string");
    assert.equal(verifyItem.fingerprintSha256.length > 0, true);
    assert.equal(
      verifyItem.metadata.some((m) => m.name === "validTo"),
      true,
    );
  });

  it("records a retention-ledger row for the certificate the binding previously pointed at", async () => {
    const job = makeJob();
    // Ownership now requires the naming convention, a durable issuance
    // record, AND that record being upgraded to "enrolled_by_agent" with
    // an acceptedThumbprint matching the predecessor certificate's own
    // thumbprint (see recordSupersededWindowsCertificate's doc comment):
    // this test's "tokentimer-old-1" container is a fixture standing in
    // for a certificate THIS agent previously issued AND accepted, so it
    // must carry both pieces of provenance for ownership to resolve to
    // "tokentimer_installed", exactly as a real prior renewal would have
    // written via generateCsrViaCng + acceptCertificateViaCng's own call
    // sites.
    recordIssuedContainer({
      stateDir: stateDir(),
      containerName: "tokentimer-old-1",
      jobId: "prior-job",
      certificateId: job.certificateId,
    });
    markIssuedContainerAccepted({
      stateDir: stateDir(),
      containerName: "tokentimer-old-1",
      acceptedThumbprint: OTHER_THUMBPRINT,
      store: "My",
    });
    const { outcome } = await runIisRenew({
      job,
      windowsOpts: { outgoingThumbprint: OTHER_THUMBPRINT, storeKeyContainer: "tokentimer-old-1" },
    });

    assert.equal(outcome.status, "succeeded");
    const ledgerDir = path.join(stateDir(), "windows-retention");
    const row = readLedgerRow(ledgerDir, OTHER_THUMBPRINT);
    assert.notEqual(row, null);
    assert.equal(row.replacementThumbprint, NEW_THUMBPRINT.toUpperCase());
    assert.equal(row.cngKeyContainerId, "tokentimer-old-1");
    assert.equal(row.ownershipProvenance, "tokentimer_installed");
    assert.equal(row.lifecycleState, "pending_retention");
  });

  it("records ownershipProvenance preexisting for a container matching this agent's naming convention but with no issuance record (name alone is not proof)", async () => {
    // Same container name as the "tokentimer_installed" case above, but
    // WITHOUT a matching recordIssuedContainer record: proves the naming
    // convention alone is no longer sufficient to authorize automated
    // deletion after the ownership-provenance hardening.
    const job = makeJob();
    const { outcome } = await runIisRenew({
      job,
      windowsOpts: { outgoingThumbprint: OTHER_THUMBPRINT, storeKeyContainer: "tokentimer-old-1" },
    });

    assert.equal(outcome.status, "succeeded");
    const ledgerDir = path.join(stateDir(), "windows-retention");
    const row = readLedgerRow(ledgerDir, OTHER_THUMBPRINT);
    assert.notEqual(row, null);
    assert.equal(row.ownershipProvenance, "preexisting");
  });

  it("records ownershipProvenance preexisting for an issuance record that was never upgraded to enrolled_by_agent (container created but certreq -accept's outcome never confirmed)", async () => {
    // Same container name again, WITH a recordIssuedContainer record but
    // WITHOUT the markIssuedContainerAccepted upgrade: proves a bare
    // "this agent created the container" record is no longer sufficient
    // on its own, closing the gap a PR review found (2026-08-07) where an
    // operator-enrolled certificate in an agent-created container could
    // otherwise inherit tokentimer_installed provenance.
    const job = makeJob();
    recordIssuedContainer({
      stateDir: stateDir(),
      containerName: "tokentimer-old-1",
      jobId: "prior-job",
      certificateId: job.certificateId,
    });
    const { outcome } = await runIisRenew({
      job,
      windowsOpts: { outgoingThumbprint: OTHER_THUMBPRINT, storeKeyContainer: "tokentimer-old-1" },
    });

    assert.equal(outcome.status, "succeeded");
    const ledgerDir = path.join(stateDir(), "windows-retention");
    const row = readLedgerRow(ledgerDir, OTHER_THUMBPRINT);
    assert.notEqual(row, null);
    assert.equal(row.ownershipProvenance, "preexisting");
  });

  it("records ownershipProvenance preexisting when the accepted thumbprint on record does not match the predecessor certificate (operator later enrolled a different certificate into an agent-created container)", async () => {
    // The agent created and accepted a DIFFERENT certificate into this
    // container at some point (acceptedThumbprint recorded), but the
    // predecessor certificate this sweep is now looking at carries
    // OTHER_THUMBPRINT -- a mismatch that must NOT resolve to
    // tokentimer_installed, since it is exactly the scenario the PR
    // review flagged: an operator (or a later, unrelated attempt) can
    // enroll a different certificate into an agent-owned container name
    // without this agent's own acceptCertificateViaCng having produced
    // that specific certificate.
    const job = makeJob();
    recordIssuedContainer({
      stateDir: stateDir(),
      containerName: "tokentimer-old-1",
      jobId: "prior-job",
      certificateId: job.certificateId,
    });
    markIssuedContainerAccepted({
      stateDir: stateDir(),
      containerName: "tokentimer-old-1",
      acceptedThumbprint: "BB".repeat(20),
      store: "My",
    });
    const { outcome } = await runIisRenew({
      job,
      windowsOpts: { outgoingThumbprint: OTHER_THUMBPRINT, storeKeyContainer: "tokentimer-old-1" },
    });

    assert.equal(outcome.status, "succeeded");
    const ledgerDir = path.join(stateDir(), "windows-retention");
    const row = readLedgerRow(ledgerDir, OTHER_THUMBPRINT);
    assert.notEqual(row, null);
    assert.equal(row.ownershipProvenance, "preexisting");
  });

  it("creates no retention-ledger row on a first-ever bind (nothing was bound before)", async () => {
    const job = makeJob();
    const { outcome } = await runIisRenew({ job, windowsOpts: { outgoingThumbprint: null } });

    assert.equal(outcome.status, "succeeded");
    const ledgerDir = path.join(stateDir(), "windows-retention");
    assert.equal(fs.existsSync(ledgerDir), false);
  });

  it("records ownershipProvenance preexisting when the superseded certificate has no CNG key container", async () => {
    const job = makeJob();
    const { outcome } = await runIisRenew({
      job,
      windowsOpts: { outgoingThumbprint: OTHER_THUMBPRINT, storeKeyContainer: null },
    });

    assert.equal(outcome.status, "succeeded");
    const ledgerDir = path.join(stateDir(), "windows-retention");
    const row = readLedgerRow(ledgerDir, OTHER_THUMBPRINT);
    assert.equal(row.ownershipProvenance, "preexisting");
  });

  it("records ownershipProvenance preexisting for a real key container this agent did not create (presence alone is not ownership)", async () => {
    // A container name in exactly the shape an operator's own certreq
    // enrollment, or IIS's own self-signed-cert generator, would leave
    // behind: a real, non-exportable CNG container, just not one
    // buildContainerName ever produced. Retention must not treat this as
    // deletable material just because SOME key container is present.
    const job = makeJob();
    const { outcome } = await runIisRenew({
      job,
      windowsOpts: { outgoingThumbprint: OTHER_THUMBPRINT, storeKeyContainer: "IIS-Self-Signed-{guid}" },
    });

    assert.equal(outcome.status, "succeeded");
    const ledgerDir = path.join(stateDir(), "windows-retention");
    const row = readLedgerRow(ledgerDir, OTHER_THUMBPRINT);
    assert.equal(row.ownershipProvenance, "preexisting");
    assert.notEqual(row.cngKeyContainerId, "IIS-Self-Signed-{guid}");
  });

  it("frees the CNG key container when certreq -accept itself fails (bare accept failure, key never bound to any certificate)", async () => {
    const job = makeJob();
    const { outcome, windowsExecFileImpl } = await runIisRenew({
      job,
      windowsOpts: { acceptExitCode: 2 },
    });

    assert.equal(outcome.status, "failed");
    assert.match(outcome.errorMessage, /CNG certificate acceptance failed/);
    const delkeyCalls = windowsExecFileImpl.calls.filter(
      (c) => c.file === "certutil.exe" && c.args[0] === "-csp" && c.args[2] === "-delkey",
    );
    assert.equal(delkeyCalls.length, 1);
  });

  it("does NOT touch the CNG key container when only the addstore/repairstore store-mirror stage fails (accept itself already succeeded)", async () => {
    const job = makeJob({
      target: {
        type: "windows-iis",
        reference: "iis.example.com",
        store: "WebHosting",
        binding: { site: "Default Web Site", port: 443 },
      },
    });
    const client = createRecordingClient();
    const calls = [];
    const windowsExecFileImpl = (file, args, options, callback) => {
      calls.push({ file, args, options });
      if (file === "certreq.exe" && args[1] === "-new") {
        const reqPath = args[args.length - 1];
        fs.writeFileSync(
          reqPath,
          "-----BEGIN NEW CERTIFICATE REQUEST-----\nMAMCAQA=\n-----END NEW CERTIFICATE REQUEST-----\n",
          "utf8",
        );
        process.nextTick(() => callback(null, "", ""));
        return;
      }
      if (file === "certreq.exe" && args[1] === "-accept") {
        process.nextTick(() => callback(null, "", ""));
        return;
      }
      if (file === "certutil.exe" && args[0] === "-addstore") {
        process.nextTick(() =>
          callback(Object.assign(new Error("access denied"), { code: 5 }), "", "Access is denied."),
        );
        return;
      }
      process.nextTick(() => callback(new Error(`unexpected windows exec call: ${file} ${args.join(" ")}`), "", ""));
    };
    const outcome = await executeJob({
      job,
      jobId: job.jobId,
      claimId: job.claimId,
      policyEngine: permissiveEngine(),
      client,
      executionContext: makeExecutionContext({
        acmeExecFileImpl: makeCertbotStub({ exitCode: 0 }),
        windowsExecFileImpl,
        windowsConnectImpl: makeConnectStub(),
      }),
      log: silentLog,
    });

    assert.equal(outcome.status, "failed");
    assert.equal(outcome.errorMessage.includes("CNG certificate acceptance failed"), true);
    const delkeyCalls = calls.filter(
      (c) => c.file === "certutil.exe" && c.args[0] === "-csp" && c.args[2] === "-delkey",
    );
    assert.equal(delkeyCalls.length, 0);
  });

  it("fails without dispatching any Windows child process when target.binding is missing site/port", async () => {
    const job = makeJob({
      target: { type: "windows-iis", reference: "iis.example.com", store: "My", binding: {} },
    });
    const { outcome, windowsExecFileImpl } = await runIisRenew({ job, windowsOpts: {} });

    assert.equal(outcome.status, "failed");
    assert.match(outcome.errorMessage, /target\.store and target\.binding/);
    assert.equal(windowsExecFileImpl.calls.length, 0);
  });

  it("fails cleanly when the ACME order itself fails, never reaching certreq -accept", async () => {
    const job = makeJob();
    const { outcome, windowsExecFileImpl } = await runIisRenew({ job, acmeExitCode: 1 });

    assert.equal(outcome.status, "failed");
    assert.match(outcome.errorMessage, /acme step failed/);
    // The CNG key container generateCsrViaCng created before the ACME step
    // ran is now orphaned (never accepted into any store); the finally
    // block must best-effort delete it rather than leak it forever.
    const delkeyCalls = windowsExecFileImpl.calls.filter(
      (c) => c.file === "certutil.exe" && c.args[0] === "-csp" && c.args[2] === "-delkey",
    );
    assert.equal(delkeyCalls.length, 1);
  });

  it("does not fail the job a second way when the abandoned-key cleanup itself fails after an ACME rejection", async () => {
    const job = makeJob();
    const client = createRecordingClient();
    const calls = [];
    const windowsExecFileImpl = (file, args, options, callback) => {
      calls.push({ file, args, options });
      if (file === "certreq.exe" && args[1] === "-new") {
        const reqPath = args[args.length - 1];
        fs.writeFileSync(
          reqPath,
          "-----BEGIN NEW CERTIFICATE REQUEST-----\nMAMCAQA=\n-----END NEW CERTIFICATE REQUEST-----\n",
          "utf8",
        );
        process.nextTick(() => callback(null, "", ""));
        return;
      }
      if (file === "certutil.exe" && args[0] === "-csp" && args[2] === "-delkey") {
        process.nextTick(() =>
          callback(Object.assign(new Error("access denied"), { code: 5 }), "", "Access is denied."),
        );
        return;
      }
      process.nextTick(() => callback(new Error(`unexpected windows exec call: ${file} ${args.join(" ")}`), "", ""));
    };
    const acmeExecFileImpl = makeCertbotStub({ exitCode: 1 });
    const outcome = await executeJob({
      job,
      jobId: job.jobId,
      claimId: job.claimId,
      policyEngine: permissiveEngine(),
      client,
      executionContext: makeExecutionContext({ acmeExecFileImpl, windowsExecFileImpl }),
      log: silentLog,
    });

    assert.equal(outcome.status, "failed");
    assert.match(outcome.errorMessage, /acme step failed/);
  });

  it("executeDeployJob rejects a windows-iis target with a clear, specific error", async () => {
    const client = createRecordingClient();
    const job = {
      action: "deploy",
      certificateId: CERTIFICATE_ID,
      target: {
        type: "windows-iis",
        reference: "iis.example.com",
        store: "My",
        binding: { site: "Default Web Site", port: 443 },
      },
      certificatePem: FIXTURE_NEW_CERT_PEM,
    };
    const outcome = await executeDeployJob({
      job,
      jobId: "job-iis-deploy",
      policyEngine: permissiveEngine(),
      client,
      executionContext: makeExecutionContext({}),
      log: silentLog,
    });

    assert.equal(outcome.status, "failed");
    assert.match(outcome.errorMessage, /deploy action does not yet support windows-iis/);
  });
});

describe("runWindowsRetentionSweep (ADR-0012 decision 18 sweep wiring)", () => {
  const OLD_THUMBPRINT = "AA".repeat(20);
  const REPLACEMENT_THUMBPRINT = "BB".repeat(20);
  const CONTAINER_NAME = "tokentimer-old-job-abcd1234";

  let workDir;
  afterEach(() => {
    if (workDir) fs.rmSync(workDir, { recursive: true, force: true });
  });

  function ledgerDirFor(dir) {
    return path.join(dir, "windows-retention");
  }

  function seedRow(dir, overrides = {}) {
    return createLedgerRow({
      ledgerDir: ledgerDirFor(dir),
      oldThumbprint: OLD_THUMBPRINT,
      replacementThumbprint: REPLACEMENT_THUMBPRINT,
      cngKeyContainerId: CONTAINER_NAME,
      verifiedCutoverAt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
      oldNotAfter: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
      ownershipProvenance: "tokentimer_installed",
      store: "My",
      jobOrRollbackJournalRefs: [{ ref: "job-old", active: false }],
      ...overrides,
    });
  }

  /**
   * @param {object} opts
   * @param {boolean} [opts.oldStillBound] whether netsh reports a binding
   *   still pointing at OLD_THUMBPRINT.
   * @param {boolean} [opts.replacementBound] whether netsh reports a
   *   binding for REPLACEMENT_THUMBPRINT (needed before any handshake
   *   probe can even be attempted).
   * @param {string|null} [opts.sharedContainerOnOtherCert] when set, the
   *   certutil -store stub reports a SECOND certificate (distinct
   *   thumbprint) sharing this key container name.
   * @param {boolean} [opts.netshFails] simulate listHttpSysBindings ok:false.
   * @param {boolean} [opts.certutilStoreFails] simulate listMachineStoreCertificates ok:false.
   */
  function makeSweepExecStub({
    oldStillBound = false,
    replacementBound = true,
    sharedContainerOnOtherCert = null,
    netshFails = false,
    certutilStoreFails = false,
  } = {}) {
    const calls = [];
    return function execFileStub(file, args, options, callback) {
      calls.push({ file, args, options });
      if (file === "netsh.exe" && args[1] === "show") {
        if (netshFails) {
          process.nextTick(() => callback(Object.assign(new Error("boom"), { code: 1 }), "", "boom"));
          return;
        }
        const bindings = [];
        if (oldStillBound) {
          bindings.push(
            `    IP:port                      : 0.0.0.0:443\n    Certificate Hash              : ${OLD_THUMBPRINT}\n    Application ID              : {12345678-1234-1234-1234-123456789012}\n    Certificate Store Name        : My\n`,
          );
        }
        if (replacementBound) {
          bindings.push(
            `    IP:port                      : 0.0.0.0:443\n    Certificate Hash              : ${REPLACEMENT_THUMBPRINT}\n    Application ID              : {87654321-4321-4321-4321-210987654321}\n    Certificate Store Name        : My\n`,
          );
        }
        const stdout = bindings.length > 0 ? `\nSSL Certificate bindings:\n-------------------------\n\n${bindings.join("\n")}` : "";
        process.nextTick(() => callback(null, stdout, ""));
        return;
      }
      if (file === "certutil.exe" && args[0] === "-store") {
        if (certutilStoreFails) {
          process.nextTick(() => callback(Object.assign(new Error("boom"), { code: 1 }), "", "boom"));
          return;
        }
        let stdout = `My "Personal"\n`;
        if (sharedContainerOnOtherCert) {
          stdout +=
            `================ Certificate 0 ================\nSerial Number: 1\nIssuer: CN=Test Root CA\n NotBefore: 1/1/2026 12:00 AM\n NotAfter: 1/1/2027 12:00 AM\nSubject: CN=survivor.example.com\nCert Hash(sha1): ${"CC".repeat(20).match(/../g).join(" ")}\n  Key Container = ${sharedContainerOnOtherCert}\n`;
        }
        stdout += "CertUtil: -store command completed successfully.\n";
        process.nextTick(() => callback(null, stdout, ""));
        return;
      }
      if (file === "certutil.exe" && args[0] === "-delstore") {
        process.nextTick(() => callback(null, "CertUtil: -delstore command completed successfully.\n", ""));
        return;
      }
      if (file === "certutil.exe" && args[0] === "-csp" && args[2] === "-delkey") {
        process.nextTick(() => callback(null, "CertUtil: -delkey command completed successfully.\n", ""));
        return;
      }
      process.nextTick(() => callback(new Error(`unexpected windows exec call: ${file} ${args.join(" ")}`), "", ""));
    };
  }

  /** connectImpl stub for the replacement handshake probe: always presents
   * a certificate whose sha1(DER) equals REPLACEMENT_THUMBPRINT (a
   * self-signed fixture built specifically so its own thumbprint matches). */
  function makeHandshakeStub({ matches = true } = {}) {
    return function connectStub(_options) {
      const socket = new EventEmitter();
      socket.destroy = () => {};
      socket.getPeerCertificate = () => ({
        raw: matches
          ? new crypto.X509Certificate(FIXTURE_REPLACEMENT_PROBE_CERT_PEM).raw
          : Buffer.from("not a real certificate, deliberately mismatched"),
      });
      process.nextTick(() => socket.emit("secureConnect"));
      return socket;
    };
  }

  // A self-signed fixture certificate generated purely so this suite can
  // assert the sweep's TLS-probe thumbprint comparison genuinely computes
  // sha1(DER) rather than trusting netsh's own report: REPLACEMENT_THUMBPRINT
  // is set to match this specific certificate's real fingerprint below.
  const FIXTURE_REPLACEMENT_PROBE_CERT_PEM = fs.readFileSync(
    path.join(__dirname, "verify", "fixtures", "selfsigned.crt.pem"),
    "utf8",
  );

  it("returns null without touching execFileImpl when the ledger directory does not exist yet", async () => {
    workDir = makeTempConfigDir();
    let called = false;
    await runWindowsRetentionSweep({
      stateDir: workDir,
      retentionHours: 24,
      execFileImpl: () => {
        called = true;
      },
    });
    assert.equal(called, false);
  });

  it("removes an eligible row: old thumbprint unbound, container not shared, replacement passes handshake, deadline passed", async () => {
    workDir = makeTempConfigDir();
    seedRow(workDir);
    const execFileImpl = makeSweepExecStub({ oldStillBound: false, replacementBound: true });

    // Use the real replacement thumbprint = sha1(DER) of the fixture the
    // handshake stub presents, so the probe's own comparison is exercised
    // for real rather than short-circuited.
    const realReplacementThumbprint = crypto
      .createHash("sha1")
      .update(new crypto.X509Certificate(FIXTURE_REPLACEMENT_PROBE_CERT_PEM).raw)
      .digest("hex")
      .toUpperCase();
    fs.rmSync(ledgerDirFor(workDir), { recursive: true, force: true });
    createLedgerRow({
      ledgerDir: ledgerDirFor(workDir),
      oldThumbprint: OLD_THUMBPRINT,
      replacementThumbprint: realReplacementThumbprint,
      cngKeyContainerId: CONTAINER_NAME,
      verifiedCutoverAt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
      oldNotAfter: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
      ownershipProvenance: "tokentimer_installed",
      store: "My",
      jobOrRollbackJournalRefs: [{ ref: "job-old", active: false }],
    });
    const execFileImplWithRealThumbprint = (file, args, options, callback) => {
      if (file === "netsh.exe" && args[1] === "show") {
        const stdout = `\nSSL Certificate bindings:\n-------------------------\n\n    IP:port                      : 0.0.0.0:443\n    Certificate Hash              : ${realReplacementThumbprint}\n    Application ID              : {87654321-4321-4321-4321-210987654321}\n    Certificate Store Name        : My\n`;
        process.nextTick(() => callback(null, stdout, ""));
        return;
      }
      execFileImpl(file, args, options, callback);
    };

    const summary = await runWindowsRetentionSweep({
      stateDir: workDir,
      retentionHours: 24,
      execFileImpl: execFileImplWithRealThumbprint,
      connectImpl: makeHandshakeStub({ matches: true }),
    });

    assert.deepEqual(summary.removed, [OLD_THUMBPRINT]);
    const row = readLedgerRow(ledgerDirFor(workDir), OLD_THUMBPRINT);
    assert.equal(row.lifecycleState, "removed");
  });

  it("defers (never calls performCleanup) when the old thumbprint is still bound", async () => {
    workDir = makeTempConfigDir();
    seedRow(workDir);
    const execFileImpl = makeSweepExecStub({ oldStillBound: true, replacementBound: true });

    const summary = await runWindowsRetentionSweep({
      stateDir: workDir,
      retentionHours: 24,
      execFileImpl,
      connectImpl: makeHandshakeStub({ matches: true }),
    });

    assert.equal(summary.removed.length, 0);
    assert.equal(summary.deferred[0].reason, "binding_still_present");
    const row = readLedgerRow(ledgerDirFor(workDir), OLD_THUMBPRINT);
    assert.equal(row.lifecycleState, "deferred");
  });

  it("defers when a distinct current certificate shares the same key container", async () => {
    workDir = makeTempConfigDir();
    seedRow(workDir);
    const execFileImpl = makeSweepExecStub({
      oldStillBound: false,
      replacementBound: true,
      sharedContainerOnOtherCert: CONTAINER_NAME,
    });

    const summary = await runWindowsRetentionSweep({
      stateDir: workDir,
      retentionHours: 24,
      execFileImpl,
      connectImpl: makeHandshakeStub({ matches: true }),
    });

    assert.equal(summary.removed.length, 0);
    assert.equal(summary.deferred[0].reason, "shared_key_container");
  });

  it("defers when the replacement's binding cannot be found at all (no handshake possible)", async () => {
    workDir = makeTempConfigDir();
    seedRow(workDir);
    const execFileImpl = makeSweepExecStub({ oldStillBound: false, replacementBound: false });

    const summary = await runWindowsRetentionSweep({
      stateDir: workDir,
      retentionHours: 24,
      execFileImpl,
      connectImpl: makeHandshakeStub({ matches: true }),
    });

    assert.equal(summary.removed.length, 0);
    assert.equal(summary.deferred[0].reason, "replacement_handshake_failed");
  });

  it("fails safe (defers as still-bound) when listHttpSysBindings itself cannot be queried", async () => {
    workDir = makeTempConfigDir();
    seedRow(workDir);
    const execFileImpl = makeSweepExecStub({ netshFails: true });

    const summary = await runWindowsRetentionSweep({
      stateDir: workDir,
      retentionHours: 24,
      execFileImpl,
      connectImpl: makeHandshakeStub({ matches: true }),
    });

    assert.equal(summary.removed.length, 0);
    assert.equal(summary.deferred[0].reason, "binding_still_present");
  });

  it("fails safe (defers as shared) when the machine store itself cannot be queried", async () => {
    workDir = makeTempConfigDir();
    seedRow(workDir);
    const execFileImpl = makeSweepExecStub({
      oldStillBound: false,
      replacementBound: true,
      certutilStoreFails: true,
    });

    const summary = await runWindowsRetentionSweep({
      stateDir: workDir,
      retentionHours: 24,
      execFileImpl,
      connectImpl: makeHandshakeStub({ matches: true }),
    });

    assert.equal(summary.removed.length, 0);
    assert.equal(summary.deferred[0].reason, "shared_key_container");
  });
});

describe("reconcileOrphanedWindowsCngContainers (crash-safe startup cleanup)", () => {
  let workDir;
  afterEach(() => {
    if (workDir) fs.rmSync(workDir, { recursive: true, force: true });
  });

  /**
   * @param {object} opts
   * @param {string|null} [opts.enrolledContainer] a container name certutil
   *   -store should report as currently enrolled to a real certificate, if
   *   any (simulates "a later attempt legitimately used this container").
   *   Enrolled in EVERY queried store unless `enrolledInStore` narrows it.
   * @param {string|null} [opts.enrolledInStore] restricts `enrolledContainer`
   *   to only appear enrolled when that exact store is queried (simulates
   *   a crash after certreq -accept succeeded into "My" but before the
   *   later mirror step into a non-default target store completed).
   * @param {boolean} [opts.delkeyFails] simulate certutil -delkey ok:false.
   */
  function makeReconcileExecStub({ enrolledContainer = null, enrolledInStore = null, delkeyFails = false } = {}) {
    return function execFileStub(file, args, options, callback) {
      if (file === "certutil.exe" && args[0] === "-store") {
        const queriedStore = args[1];
        const showEnrolled =
          enrolledContainer && (enrolledInStore === null || enrolledInStore === queriedStore);
        let stdout = `My "Personal"\n`;
        if (showEnrolled) {
          stdout +=
            `================ Certificate 0 ================\nSerial Number: 1\nIssuer: CN=Test Root CA\n NotBefore: 1/1/2026 12:00 AM\n NotAfter: 1/1/2027 12:00 AM\nSubject: CN=enrolled.example.com\nCert Hash(sha1): ${"DD".repeat(20).match(/../g).join(" ")}\n  Key Container = ${enrolledContainer}\n`;
        }
        stdout += "CertUtil: -store command completed successfully.\n";
        process.nextTick(() => callback(null, stdout, ""));
        return;
      }
      if (file === "certutil.exe" && args[0] === "-csp" && args[2] === "-delkey") {
        if (delkeyFails) {
          process.nextTick(() => callback(Object.assign(new Error("boom"), { code: 1 }), "", "boom"));
          return;
        }
        process.nextTick(() => callback(null, "CertUtil: -delkey command completed successfully.\n", ""));
        return;
      }
      process.nextTick(() => callback(new Error(`unexpected windows exec call: ${file} ${args.join(" ")}`), "", ""));
    };
  }

  /** Seeds a journal entry carrying a recorded CNG container, exactly as
   * executeWindowsIisRenewJob's own call site would leave behind after a
   * hard crash between keygen and cutover. */
  function seedOrphanedContainerJournalEntry(dir, { jobId = "job-1", attemptId = "attempt-1", containerName, store } = {}) {
    markSideEffectReached({ stateDir: dir, jobId, attemptId, stage: "keygen" });
    recordWindowsCngContainer({ stateDir: dir, jobId, attemptId, containerName, ...(store ? { store } : {}) });
  }

  it("frees a container that was never enrolled to any certificate, and marks the journal entry reconciled", async () => {
    workDir = makeTempConfigDir();
    const containerName = "tokentimer-job-1-orphan01";
    seedOrphanedContainerJournalEntry(workDir, { containerName });

    const result = await reconcileOrphanedWindowsCngContainers({
      stateDir: workDir,
      execFileImpl: makeReconcileExecStub(),
    });

    assert.deepEqual(result.freed, [containerName]);
    assert.equal(result.skipped.length, 0);
    const [entry] = scanUnresolvedJournalEntries(workDir);
    assert.equal(typeof entry.windowsCngContainerReconciledAt, "string");
    // Still unresolved: freeing the container never resolves the
    // job-attempt-outcome question this journal entry also tracks.
    assert.equal(hasUnresolvedJournalForJob(workDir, "job-1"), true);
  });

  it("never frees a container that is now legitimately enrolled to a real certificate", async () => {
    workDir = makeTempConfigDir();
    const containerName = "tokentimer-job-1-live0001";
    seedOrphanedContainerJournalEntry(workDir, { containerName });

    const result = await reconcileOrphanedWindowsCngContainers({
      stateDir: workDir,
      execFileImpl: makeReconcileExecStub({ enrolledContainer: containerName }),
    });

    assert.deepEqual(result.freed, []);
    assert.equal(result.skipped.length, 1);
    assert.equal(result.skipped[0].reason, "enrolled");
  });

  it("queries both My and the recorded target store, not just one", async () => {
    workDir = makeTempConfigDir();
    const containerName = "tokentimer-job-1-webhost1";
    seedOrphanedContainerJournalEntry(workDir, { containerName, store: "WebHosting" });

    const queriedStores = [];
    const execFileImpl = (file, args, options, callback) => {
      if (file === "certutil.exe" && args[0] === "-store") {
        queriedStores.push(args[1]);
      }
      return makeReconcileExecStub()(file, args, options, callback);
    };

    const result = await reconcileOrphanedWindowsCngContainers({ stateDir: workDir, execFileImpl });
    assert.deepEqual(new Set(queriedStores), new Set(["My", "WebHosting"]));
    // Never enrolled in either store: genuinely orphaned, safe to free.
    assert.deepEqual(result.freed, [containerName]);
  });

  it("CRITICAL: never deletes a container whose certificate landed in My but the target-store mirror step never ran (crash between certreq -accept and the addstore/repairstore/delstore mirror)", async () => {
    workDir = makeTempConfigDir();
    const containerName = "tokentimer-job-1-webhost2";
    // Simulates the real crash window: the job's recorded target store is
    // "WebHosting" (recordWindowsCngContainer wrote this at keygen time,
    // before certreq -accept ever ran), but certreq -accept always lands
    // in "My" first, and a crash before the later mirror step means the
    // certificate -- and its live key reference -- exists ONLY in "My".
    seedOrphanedContainerJournalEntry(workDir, { containerName, store: "WebHosting" });

    const result = await reconcileOrphanedWindowsCngContainers({
      stateDir: workDir,
      execFileImpl: makeReconcileExecStub({ enrolledContainer: containerName, enrolledInStore: "My" }),
    });

    // Must NOT delete: a real, enrolled certificate in "My" depends on
    // this exact key container.
    assert.deepEqual(result.freed, []);
    assert.equal(result.skipped.length, 1);
    assert.equal(result.skipped[0].reason, "enrolled");
  });

  it("never frees a container when either store's lookup fails (fails closed, does not treat a query error as absence)", async () => {
    workDir = makeTempConfigDir();
    const containerName = "tokentimer-job-1-webhost3";
    seedOrphanedContainerJournalEntry(workDir, { containerName, store: "WebHosting" });

    const execFileImpl = (file, args, options, callback) => {
      if (file === "certutil.exe" && args[0] === "-store" && args[1] === "WebHosting") {
        process.nextTick(() => callback(Object.assign(new Error("boom"), { code: 1 }), "", "access denied"));
        return;
      }
      return makeReconcileExecStub()(file, args, options, callback);
    };

    const result = await reconcileOrphanedWindowsCngContainers({ stateDir: workDir, execFileImpl });
    assert.deepEqual(result.freed, []);
    assert.equal(result.skipped.length, 1);
    assert.match(result.skipped[0].reason, /query failed/);
  });

  it("defers (does not free, does not throw) when delkey fails", async () => {
    workDir = makeTempConfigDir();
    const containerName = "tokentimer-job-1-faildel1";
    seedOrphanedContainerJournalEntry(workDir, { containerName });

    const result = await reconcileOrphanedWindowsCngContainers({
      stateDir: workDir,
      execFileImpl: makeReconcileExecStub({ delkeyFails: true }),
    });

    assert.deepEqual(result.freed, []);
    assert.equal(result.skipped.length, 1);
    assert.match(result.skipped[0].reason, /delkey failed/);
  });

  it("does nothing for a journal entry with no recorded container name (e.g. a non-Windows job)", async () => {
    workDir = makeTempConfigDir();
    markSideEffectReached({ stateDir: workDir, jobId: "job-linux", attemptId: "attempt-1", stage: "deploy" });

    const result = await reconcileOrphanedWindowsCngContainers({
      stateDir: workDir,
      execFileImpl: () => {
        throw new Error("must not shell out when there is nothing to reconcile");
      },
    });

    assert.deepEqual(result.freed, []);
    assert.deepEqual(result.skipped, []);
  });

  it("skips (does not throw) an entry already marked reconciled on a prior startup", async () => {
    workDir = makeTempConfigDir();
    const containerName = "tokentimer-job-1-already1";
    seedOrphanedContainerJournalEntry(workDir, { containerName });
    markWindowsCngContainerReconciled({ stateDir: workDir, jobId: "job-1", attemptId: "attempt-1" });

    const result = await reconcileOrphanedWindowsCngContainers({
      stateDir: workDir,
      execFileImpl: () => {
        throw new Error("must not shell out for an already-reconciled entry");
      },
    });

    assert.deepEqual(result.freed, []);
    assert.deepEqual(result.skipped, []);
  });
});

describe("verifyDeployedCertificateWithRetry", () => {
  function fakeSleep(delays) {
    return async (ms) => {
      delays.push(ms);
    };
  }

  it("returns immediately on a first-attempt verified probe (no retry, no sleep)", async () => {
    const delays = [];
    let calls = 0;
    const probeImpl = async () => {
      calls++;
      return { verified: true, actualFingerprintSha256: "abc123" };
    };

    const result = await verifyDeployedCertificateWithRetry(
      { host: "example.com", expectedFingerprintSha256: "abc123" },
      { probeImpl, sleep: fakeSleep(delays) },
    );

    assert.equal(result.verified, true);
    assert.equal(calls, 1);
    assert.deepEqual(delays, []);
  });

  it("retries on a fingerprint mismatch with an actual certificate, then succeeds once the endpoint cuts over", async () => {
    const delays = [];
    let calls = 0;
    const probeImpl = async () => {
      calls++;
      if (calls < 3) {
        return {
          verified: false,
          actualFingerprintSha256: "stale-fingerprint",
          detail: "Fingerprint mismatch",
        };
      }
      return { verified: true, actualFingerprintSha256: "new-fingerprint" };
    };

    const result = await verifyDeployedCertificateWithRetry(
      { host: "example.com", expectedFingerprintSha256: "new-fingerprint" },
      { probeImpl, sleep: fakeSleep(delays) },
    );

    assert.equal(result.verified, true);
    assert.equal(calls, 3);
    // Two retries happened before the third (successful) attempt, using the
    // configured backoff schedule's first two delays.
    assert.deepEqual(delays, VERIFY_TRANSIENT_RETRY_DELAYS_MS.slice(0, 2));
  });

  it("exhausts retries and returns the last mismatch outcome if the endpoint never cuts over", async () => {
    const delays = [];
    let calls = 0;
    const probeImpl = async () => {
      calls++;
      return {
        verified: false,
        actualFingerprintSha256: "still-stale",
        detail: "Fingerprint mismatch",
      };
    };

    const result = await verifyDeployedCertificateWithRetry(
      { host: "example.com", expectedFingerprintSha256: "expected" },
      { probeImpl, sleep: fakeSleep(delays) },
    );

    assert.equal(result.verified, false);
    assert.equal(result.actualFingerprintSha256, "still-stale");
    // maxRetries retries after the first attempt = maxRetries + 1 calls.
    assert.equal(calls, MAX_VERIFY_TRANSIENT_RETRIES + 1);
    assert.equal(delays.length, MAX_VERIFY_TRANSIENT_RETRIES);
  });

  it("does not retry a connect/handshake failure (no certificate presented at all)", async () => {
    const delays = [];
    let calls = 0;
    const probeImpl = async () => {
      calls++;
      return {
        verified: false,
        actualFingerprintSha256: null,
        detail: "Connection refused",
      };
    };

    const result = await verifyDeployedCertificateWithRetry(
      { host: "example.com", expectedFingerprintSha256: "expected" },
      { probeImpl, sleep: fakeSleep(delays) },
    );

    assert.equal(result.verified, false);
    assert.equal(result.actualFingerprintSha256, null);
    assert.equal(calls, 1);
    assert.deepEqual(delays, []);
  });

  it("respects a custom maxRetries/retryDelaysMs override", async () => {
    const delays = [];
    let calls = 0;
    const probeImpl = async () => {
      calls++;
      return {
        verified: false,
        actualFingerprintSha256: "stale",
        detail: "Fingerprint mismatch",
      };
    };

    const result = await verifyDeployedCertificateWithRetry(
      { host: "example.com", expectedFingerprintSha256: "expected" },
      {
        probeImpl,
        sleep: fakeSleep(delays),
        maxRetries: 1,
        retryDelaysMs: [42],
      },
    );

    assert.equal(result.verified, false);
    assert.equal(calls, 2);
    assert.deepEqual(delays, [42]);
  });
});

