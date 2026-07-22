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
  buildJobPolicyDescriptor,
  runDiscoveryScan,
  registerIfNeeded,
  AGENT_VERSION,
} = require("./index.js");
const { loadPolicyConfig, createPolicyEngine, REJECTION_REASONS } = require("./policy");
const { ensureConfigDir, writeCredential, readCredential, loadAgentConfig } = require("./config");

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
        credential: "ttagent_a_b",
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

describe("buildJobPolicyDescriptor", () => {
  it("maps target.reference to targetSelector and passes through policy dimensions", () => {
    const descriptor = buildJobPolicyDescriptor({
      jobId: "job-1",
      target: { type: "domain", reference: "example.com" },
      commandRef: "nginx-reload",
      path: "/etc/nginx/tls/cert.pem",
      caEndpoint: "https://acme.example/dir",
      dnsZone: "example.com",
      dnsProvider: "route53",
    });
    assert.deepEqual(descriptor, {
      targetSelector: "example.com",
      commandRef: "nginx-reload",
      path: "/etc/nginx/tls/cert.pem",
      caEndpoint: "https://acme.example/dir",
      dnsZone: "example.com",
      dnsProvider: "route53",
    });
  });

  it("omits absent dimensions entirely", () => {
    assert.deepEqual(buildJobPolicyDescriptor({ jobId: "job-1" }), {});
  });

  it("maps any custody-shaped intent flag onto requestsKeyExport", () => {
    for (const field of ["requestsKeyExport", "exportPrivateKey", "keyExport"]) {
      const descriptor = buildJobPolicyDescriptor({ jobId: "j", [field]: true });
      assert.equal(descriptor.requestsKeyExport, true, field);
    }
    // Falsy values must not set the flag at all.
    assert.deepEqual(buildJobPolicyDescriptor({ jobId: "j", keyExport: false }), {});
  });
});

describe("handleClaimedJob", () => {
  it("reports rejected + evidence when agent-local policy rejects the job", async () => {
    const client = createRecordingClient();
    const policyEngine = engineWith({}, { declaredTargetSelectors: [] });

    const outcome = await handleClaimedJob({
      job: {
        jobId: "job-1",
        target: { type: "domain", reference: "not-in-scope.example.com" },
      },
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

  it("unconditionally rejects key-export intent even with permissive policy", async () => {
    const client = createRecordingClient();
    const policyEngine = engineWith(
      { allowedPaths: ["/"] },
      { declaredTargetSelectors: ["example.com"] },
    );

    const outcome = await handleClaimedJob({
      job: {
        jobId: "job-2",
        target: { type: "domain", reference: "example.com" },
        exportPrivateKey: true,
      },
      policyEngine,
      client,
      log: silentLog,
    });

    assert.equal(outcome.status, "rejected");
    assert.equal(outcome.rejectionReason, REJECTION_REASONS.KEY_EXPORT_REQUESTED);
  });

  it("reports blocked (not executed) when policy allows the job, until the signed-dispatch runtime lands", async () => {
    const client = createRecordingClient();
    const policyEngine = engineWith({}, { declaredTargetSelectors: ["example.com"] });

    const outcome = await handleClaimedJob({
      job: {
        jobId: "job-3",
        attemptId: "attempt-cp-1",
        target: { type: "domain", reference: "example.com" },
      },
      policyEngine,
      client,
      log: silentLog,
    });

    assert.equal(outcome.status, "blocked");
    assert.equal(client.calls.reportEvidence.length, 0);
    assert.equal(client.calls.reportResult.length, 1);
    const result = client.calls.reportResult[0];
    assert.equal(result.status, "blocked");
    assert.equal(result.attemptId, "attempt-cp-1");
    assert.match(result.errorMessage, /signed-dispatch runtime/);
  });

  it("skips jobs without a jobId without reporting anything", async () => {
    const client = createRecordingClient();
    const policyEngine = engineWith();

    const outcome = await handleClaimedJob({
      job: { target: { type: "domain", reference: "example.com" } },
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
    writeCredential(dir, "ttagent_existing_secret");

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
    writeCredential(dir, "ttagent_orphan_secret");

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

    // The assigned agentId is persisted to config.json (the credential is
    // persisted by the protocol client's onCredentialIssued hook, which is
    // not part of this recording client).
    const persisted = JSON.parse(fs.readFileSync(path.join(dir, "config.json"), "utf8"));
    assert.equal(persisted.agentId, "agent-assigned-1");
    assert.equal(readCredential(dir), null);
  });
});
