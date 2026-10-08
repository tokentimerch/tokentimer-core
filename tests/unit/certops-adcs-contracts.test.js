"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const Ajv = require("ajv");
const addFormats = require("ajv-formats");

const jobPayloadSchema = require("../../packages/contracts/certops/job-payload.schema.json");
const enrollmentSnapshotSchema = require("../../packages/contracts/certops/enrollment-snapshot.schema.json");
const enrollmentResultSchema = require("../../packages/contracts/certops/enrollment-result-contract.schema.json");
const adcsPreflightResultSchema = require("../../packages/contracts/certops/adcs-preflight-result-contract.schema.json");
const agentProtocolSchema = require("../../packages/contracts/certops/agent-protocol.schema.json");
const {
  ADCS_PREFLIGHT_ACTION,
  CERTIFICATE_ACTIONS,
  TRUST_ANCHOR_ACTIONS,
  selectSchemaForAction,
  validateSignedJob,
} = require("../../packages/contracts/certops/validate-signed-job.cjs");
const {
  V2_MAX_DECODED_PAYLOAD_BYTES,
} = require("../../packages/agent/src/signing/index.js");

const WORKSPACE_ID = "11111111-1111-4111-8111-111111111111";
const AGENT_ID = "22222222-2222-4222-8222-222222222222";
const ENROLLMENT_ID = "5f0c2a8e-3b1d-4c6e-9a7f-1e2d3c4b5a69";
const CA_CONFIG = "ca01.corp.example.com\\Corp Issuing CA 01";
const HEX64 = "a".repeat(64);

function createAjv() {
  const ajv = new Ajv({ allErrors: true, strict: false });
  addFormats(ajv);
  ajv.addSchema(enrollmentSnapshotSchema);
  ajv.addSchema(enrollmentResultSchema);
  ajv.addSchema(adcsPreflightResultSchema);
  ajv.addSchema(agentProtocolSchema);
  return ajv;
}

const ajv = createAjv();
const validateSnapshot = ajv.getSchema(enrollmentSnapshotSchema.$id);
const validateEnrollmentResult = ajv.getSchema(enrollmentResultSchema.$id);
const validatePreflightResult = ajv.getSchema(adcsPreflightResultSchema.$id);
const validateAgentMessage = ajv.getSchema(agentProtocolSchema.$id);

function errorsOf(validate) {
  return JSON.stringify(validate.errors);
}

function validSnapshot(overrides = {}) {
  return {
    schemaVersion: 1,
    kind: "adcs",
    issuerId: "corp-issuing-ca",
    issuerVersion: 1,
    caConfig: CA_CONFIG,
    caKeySha256: HEX64,
    template: "TokenTimerWebServer",
    transport: "dcom",
    authorizedDnsNames: ["app.corp.example.com", "*.apps.corp.example.com"],
    keyAlgorithm: "rsa",
    keySize: 3072,
    policyVersion: 1,
    pollInterval: 900,
    pendingTimeout: 1209600,
    minimumRemainingValidity: 604800,
    requireLaterNotAfter: true,
    ...overrides,
  };
}

function enrollmentFor(snapshotBytes, overrides = {}) {
  return {
    enrollmentId: ENROLLMENT_ID,
    attempt: 1,
    snapshotB64: snapshotBytes.toString("base64"),
    snapshotSha256: crypto.createHash("sha256").update(snapshotBytes).digest("hex"),
    ...overrides,
  };
}

function iisTarget() {
  return {
    type: "windows-iis",
    reference: "iis-01/default-web-site",
    store: "My",
    binding: { site: "Default Web Site", port: 443, sniHost: "app.corp.example.com" },
  };
}

function acmeJob(overrides = {}) {
  return {
    schemaVersion: 1,
    jobId: "job-acme-1",
    workspaceId: WORKSPACE_ID,
    agentId: AGENT_ID,
    certificateId: "cert-1",
    action: "renew",
    target: { type: "domain", reference: "example.com" },
    keyMode: "agent-local",
    requestedAt: "2026-01-01T00:00:00.000Z",
    ...overrides,
  };
}

function adcsJob(overrides = {}) {
  return {
    schemaVersion: 1,
    jobId: "job-adcs-1",
    workspaceId: WORKSPACE_ID,
    agentId: AGENT_ID,
    certificateId: "cert-1",
    action: "renew",
    mode: "real",
    target: iisTarget(),
    keyMode: "os-store-managed",
    requestedAt: "2026-01-01T00:00:00.000Z",
    issuer: { kind: "adcs" },
    enrollment: enrollmentFor(Buffer.from(JSON.stringify(validSnapshot()), "utf8")),
    ...overrides,
  };
}

function preflightJob(overrides = {}) {
  return {
    schemaVersion: 1,
    jobId: "job-preflight-1",
    workspaceId: WORKSPACE_ID,
    agentId: AGENT_ID,
    action: "adcs-preflight",
    mode: "real",
    requestedAt: "2026-01-01T00:00:00.000Z",
    issuer: {
      kind: "adcs",
      issuerId: "corp-issuing-ca",
      caConfig: CA_CONFIG,
      template: "TokenTimerWebServer",
      transport: "dcom",
    },
    ...overrides,
  };
}

function assertValid(job, label = "job") {
  const result = validateSignedJob(job);
  assert.equal(result.valid, true, `${label}: ${JSON.stringify(result.errors)}`);
  return result;
}

function assertInvalid(job, label) {
  const result = validateSignedJob(job);
  assert.equal(result.valid, false, `${label} must be rejected`);
  return result;
}

describe("AD CS issuer job payload", () => {
  it("accepts the first enrollment step and its continuations", () => {
    assertValid(adcsJob(), "first-step renew");
    assertValid(adcsJob({ action: "continue-enrollment" }), "continuation");
    assertValid(
      adcsJob({ action: "continue-enrollment", enrollment: { ...adcsJob().enrollment, attempt: 7 } }),
      "later continuation",
    );
  });

  it("keeps jobs without an issuer, or with issuer kind acme, valid unchanged", () => {
    assertValid(acmeJob(), "issuer-less ACME job");
    assertValid(acmeJob({ issuer: { kind: "acme" } }), "explicit acme issuer");
    assertValid(
      acmeJob({
        issuer: { kind: "acme" },
        commandRef: "certbot-renew",
        caEndpoint: "https://acme.example.com/directory",
        acmeKind: "certbot",
        dnsZone: "example.com",
        dnsProvider: "cloudflare",
      }),
      "explicit acme issuer with ACME execution fields",
    );
  });

  it("rejects unknown issuer kinds and issuer fields outside the snapshot", () => {
    assertInvalid(acmeJob({ issuer: { kind: "venafi" } }), "unknown issuer kind");
    assertInvalid(acmeJob({ issuer: {} }), "issuer without kind");
    assertInvalid(
      adcsJob({ issuer: { kind: "adcs", caConfig: CA_CONFIG } }),
      "caConfig beside the snapshot",
    );
  });

  it("binds continue-enrollment and every enrollment to an adcs issuer", () => {
    const { issuer, enrollment, ...withoutBoth } = adcsJob({ action: "continue-enrollment" });
    assertInvalid({ ...withoutBoth, issuer }, "continue-enrollment without enrollment");
    assertInvalid({ ...withoutBoth, enrollment }, "continue-enrollment without issuer");
    assertInvalid(
      { ...withoutBoth, issuer: { kind: "acme" }, enrollment },
      "continue-enrollment for an acme issuer",
    );
    assertInvalid(acmeJob({ enrollment }), "enrollment on an issuer-less job");
    assertInvalid(adcsJob({ enrollment: undefined }), "adcs renew without enrollment");
  });

  it("runs adcs only as renew or continue-enrollment on a windows-iis CNG target", () => {
    for (const action of ["deploy", "reload", "revoke", "noop"]) {
      assertInvalid(adcsJob({ action }), `adcs ${action}`);
    }
    assertInvalid(adcsJob({ keyMode: "agent-local" }), "adcs with agent-local key");
    assertInvalid(
      adcsJob({ target: { type: "endpoint", reference: "web-01" } }),
      "adcs on a non-IIS target",
    );
  });

  it("refuses every field the snapshot supersedes, each of which is valid on an ACME job", () => {
    const superseded = {
      commandRef: "certbot-renew",
      caEndpoint: "https://acme.example.com/directory",
      acmeKind: "certbot",
      eabRef: "corp-eab",
      accountRef: "corp-account",
      preferredChain: "ISRG Root X1",
      dnsZone: "example.com",
      dnsProvider: "cloudflare",
      keyRotation: true,
      keyAlgorithm: "rsa",
      keySize: 2048,
      sans: ["app.corp.example.com"],
      certificatePem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
      certificatePemSha256: HEX64,
      renewalProfile: {},
      deploymentTargets: [{ type: "endpoint", reference: "web-01" }],
    };
    for (const [field, value] of Object.entries(superseded)) {
      assertValid(acmeJob({ [field]: value }), `${field} on an ACME job`);
      assertInvalid(adcsJob({ [field]: value }), `${field} on an adcs job`);
    }
  });

  it("validates the enrollment binding strictly", () => {
    const base = adcsJob().enrollment;
    const cases = {
      "uppercase enrollmentId": { ...base, enrollmentId: ENROLLMENT_ID.toUpperCase() },
      "braced enrollmentId": { ...base, enrollmentId: `{${ENROLLMENT_ID}}` },
      "attempt 0": { ...base, attempt: 0 },
      "non-integer attempt": { ...base, attempt: 1.5 },
      "base64url snapshot": { ...base, snapshotB64: "ab-_" },
      "unpadded snapshot": { ...base, snapshotB64: "e30" },
      "uppercase snapshot hash": { ...base, snapshotSha256: base.snapshotSha256.toUpperCase() },
      "extra field": { ...base, caConfig: CA_CONFIG },
    };
    for (const [label, enrollment] of Object.entries(cases)) {
      assertInvalid(adcsJob({ enrollment }), label);
    }
    const withoutHash = { ...base };
    delete withoutHash.snapshotSha256;
    assertInvalid(adcsJob({ enrollment: withoutHash }), "enrollment without its hash");
  });

  it("caps the snapshot above the largest valid snapshot and below the signed envelope's limit", () => {
    const label = (n) => `${n}${"a".repeat(62)}`.slice(0, 63);
    const longestName = (i) =>
      `${String(i).padStart(3, "0")}${"b".repeat(60)}.${label("c")}.${label("d")}.${"e".repeat(61)}`;
    const worst = validSnapshot({
      issuerId: "i".repeat(128),
      caConfig: `${label("h")}.${label("o")}.${label("s")}.${"t".repeat(61)}\\${"N".repeat(64)}`,
      template: "T".repeat(64),
      authorizedDnsNames: Array.from({ length: 100 }, (_, i) => longestName(i)),
    });
    assert.equal(worst.authorizedDnsNames[0].length, 253);
    assert.equal(validateSnapshot(worst), true, errorsOf(validateSnapshot));
    const worstBytes = Buffer.from(JSON.stringify(worst), "utf8");
    assertValid(adcsJob({ enrollment: enrollmentFor(worstBytes) }), "largest valid snapshot");

    const largest = Buffer.alloc(28 * 1024, 0x61);
    const job = adcsJob({ enrollment: enrollmentFor(largest) });
    assertValid(job, "28 KiB snapshot");
    const jobBytes = Buffer.byteLength(JSON.stringify(job), "utf8");
    assert.ok(
      jobBytes + 8 * 1024 <= V2_MAX_DECODED_PAYLOAD_BYTES,
      `a maximum snapshot job is ${jobBytes} bytes, leaving under 8 KiB of the ${V2_MAX_DECODED_PAYLOAD_BYTES}-byte limit`,
    );

    const oversized = enrollmentFor(Buffer.alloc(28 * 1024 + 3, 0x61));
    assertInvalid(adcsJob({ enrollment: oversized }), "snapshot over 28 KiB");
  });

  it("uses one enrollmentId shape across the job payload and the enrollment result", () => {
    assert.equal(
      jobPayloadSchema.definitions.enrollmentId.pattern,
      enrollmentResultSchema.properties.enrollmentId.pattern,
    );
  });
});

describe("AD CS enrollment snapshot", () => {
  it("accepts a complete snapshot", () => {
    assert.equal(validateSnapshot(validSnapshot()), true, errorsOf(validateSnapshot));
  });

  it("pairs key sizes with their algorithm", () => {
    for (const keySize of [2048, 3072, 4096]) {
      assert.equal(validateSnapshot(validSnapshot({ keySize })), true, errorsOf(validateSnapshot));
    }
    for (const keySize of [256, 384]) {
      assert.equal(
        validateSnapshot(validSnapshot({ keyAlgorithm: "ecdsa", keySize })),
        true,
        errorsOf(validateSnapshot),
      );
    }
    assert.equal(validateSnapshot(validSnapshot({ keySize: 1024 })), false);
    assert.equal(validateSnapshot(validSnapshot({ keySize: 256 })), false);
    assert.equal(validateSnapshot(validSnapshot({ keyAlgorithm: "ecdsa", keySize: 2048 })), false);
    assert.equal(validateSnapshot(validSnapshot({ keyAlgorithm: "dsa" })), false);
  });

  it("only accepts a host\\CA Name config that is safe as a single argv element", () => {
    assert.equal(validateSnapshot(validSnapshot({ caConfig: "ca01\\Corp CA (G2)" })), true);
    for (const caConfig of [
      "Corp Issuing CA 01",
      "ca01.corp.example.com\\",
      "-ca01.corp.example.com\\Corp CA",
      "ca01.corp.example.com\\Corp \"CA\"",
      "ca01.corp.example.com\\Corp;CA",
      "ca01.corp.example.com\\Corp&CA",
      "ca01.corp.example.com\\Corp\\CA",
      `ca01.corp.example.com\\${"C".repeat(65)}`,
    ]) {
      assert.equal(validateSnapshot(validSnapshot({ caConfig })), false, caConfig);
    }
  });

  it("names templates by common name and pins the transport and CA key", () => {
    assert.equal(validateSnapshot(validSnapshot({ template: "Web Server" })), false);
    assert.equal(validateSnapshot(validSnapshot({ transport: "rpc" })), false);
    assert.equal(validateSnapshot(validSnapshot({ caKeySha256: "A".repeat(64) })), false);
    const unpinned = validSnapshot();
    delete unpinned.caKeySha256;
    assert.equal(validateSnapshot(unpinned), false);
  });

  it("bounds the authorized names and timing fields", () => {
    assert.equal(validateSnapshot(validSnapshot({ authorizedDnsNames: [] })), false);
    assert.equal(
      validateSnapshot(validSnapshot({ authorizedDnsNames: ["*.*.corp.example.com"] })),
      false,
    );
    assert.equal(
      validateSnapshot(validSnapshot({ authorizedDnsNames: ["a.example.com", "a.example.com"] })),
      false,
    );
    assert.equal(validateSnapshot(validSnapshot({ pollInterval: 59 })), false);
    assert.equal(validateSnapshot(validSnapshot({ pendingTimeout: 3599 })), false);
    assert.equal(validateSnapshot(validSnapshot({ minimumRemainingValidity: -1 })), false);
  });

  it("rejects fields outside the frozen configuration", () => {
    assert.equal(validateSnapshot(validSnapshot({ caEndpoint: "https://ca.example.com" })), false);
    assert.equal(validateSnapshot(validSnapshot({ schemaVersion: 2 })), false);
    assert.equal(validateSnapshot(validSnapshot({ kind: "acme" })), false);
  });
});

describe("AD CS enrollment result contract", () => {
  function result(overrides = {}) {
    return { enrollmentId: ENROLLMENT_ID, attempt: 1, state: "prepared", ...overrides };
  }

  function check(value) {
    return validateEnrollmentResult(value);
  }

  it("accepts each reportable state with its required evidence", () => {
    const accepted = [
      result(),
      result({ state: "pending_issuance", requestId: 4242 }),
      result({ state: "denied", requestId: 4242, caHresult: "0x80094012" }),
      result({ state: "submitting", errorCode: "ADCS_CA_UNREACHABLE" }),
      result({ state: "submission_uncertain", errorCode: "ADCS_DISPOSITION_UNKNOWN" }),
      result({ state: "refused", errorCode: "ADCS_TEMPLATE_UNSAFE" }),
      result({ state: "refused", errorCode: "ADCS_CA_CONFIG_UNSAFE" }),
      result({ state: "refused", errorCode: "ADCS_CA_KEY_UNPINNED" }),
      result({ state: "refused", errorCode: null }),
      result({ state: "rejected_invalid", errorCode: "ADCS_CERTIFICATE_INVALID" }),
      result({ state: "rejected_invalid", errorCode: "ADCS_CA_KEY_CHANGED" }),
      result({ state: "installed", requestId: 4242, errorCode: null, caHresult: null }),
    ];
    for (const value of accepted) {
      assert.equal(check(value), true, `${value.state}: ${errorsOf(validateEnrollmentResult)}`);
    }
  });

  it("requires a RequestId once pending and a raw HRESULT on denial", () => {
    assert.equal(check(result({ state: "pending_issuance" })), false);
    assert.equal(check(result({ state: "pending_issuance", requestId: null })), false);
    assert.equal(check(result({ state: "denied" })), false);
    assert.equal(check(result({ state: "denied", caHresult: "0x800b0109" })), false);
    assert.equal(check(result({ requestId: 0 })), false);
    assert.equal(check(result({ requestId: 2 ** 32 })), false);
  });

  it("ties each error code to the one state it can explain", () => {
    assert.equal(check(result({ state: "rejected_invalid" })), false);
    assert.equal(check(result({ state: "rejected_invalid", errorCode: "ADCS_TEMPLATE_UNSAFE" })), false);
    assert.equal(check(result({ state: "submitting", errorCode: "ADCS_TEMPLATE_UNSAFE" })), false);
    assert.equal(check(result({ state: "refused", errorCode: "ADCS_CERTIFICATE_INVALID" })), false);
    assert.equal(check(result({ state: "prepared", errorCode: "ADCS_CA_UNREACHABLE" })), false);
    assert.equal(check(result({ state: "pending_issuance", requestId: 1, errorCode: "ADCS_DISPOSITION_UNKNOWN" })), false);
    assert.equal(check(result({ errorCode: "ADCS_SOMETHING_ELSE" })), false);
  });

  it("never lets the agent report the control-plane-only requested state", () => {
    assert.equal(check(result({ state: "requested" })), false);
    assert.equal(check(result({ state: "running" })), false);
    assert.equal(check(result({ certificatePem: "-----BEGIN CERTIFICATE-----" })), false);
  });
});

describe("AD CS preflight payload", () => {
  it("routes adcs-preflight to its own schema, outside the certificate and trust families", () => {
    const selection = selectSchemaForAction(ADCS_PREFLIGHT_ACTION);
    assert.ok(selection);
    assert.match(selection.schemaId, /adcs-preflight-payload\.schema\.json$/);
    assert.equal(CERTIFICATE_ACTIONS.includes(ADCS_PREFLIGHT_ACTION), false);
    assert.equal(TRUST_ANCHOR_ACTIONS.includes(ADCS_PREFLIGHT_ACTION), false);
    assert.deepEqual([...CERTIFICATE_ACTIONS], jobPayloadSchema.properties.action.enum);
  });

  it("accepts a preflight naming one CA and template", () => {
    const result = assertValid(preflightJob(), "preflight");
    assert.match(result.schemaId, /adcs-preflight-payload\.schema\.json$/);
    const withoutIssuerId = { ...preflightJob().issuer };
    delete withoutIssuerId.issuerId;
    assertValid(preflightJob({ issuer: withoutIssuerId }), "preflight before the issuer exists");
  });

  it("carries nothing certificate-shaped and never runs as a dry run", () => {
    const base = preflightJob();
    assertInvalid({ ...base, certificateId: "cert-1" }, "preflight with certificateId");
    assertInvalid({ ...base, target: iisTarget() }, "preflight with target");
    assertInvalid({ ...base, keyMode: "os-store-managed" }, "preflight with keyMode");
    assertInvalid({ ...base, enrollment: adcsJob().enrollment }, "preflight with enrollment");
    assertInvalid({ ...base, mode: "dry_run" }, "dry-run preflight");
    assertInvalid({ ...base, issuer: { ...base.issuer, kind: "acme" } }, "acme preflight");
    assertInvalid({ ...base, issuer: { ...base.issuer, template: undefined } }, "preflight without template");
    assertInvalid(
      { ...base, issuer: { ...base.issuer, caConfig: "ca01\\Corp;CA" } },
      "preflight with an unsafe caConfig",
    );
    assertInvalid(
      { ...base, issuer: { ...base.issuer, caKeySha256: HEX64 } },
      "preflight carrying a pin it is meant to discover",
    );
  });
});

describe("AD CS preflight result contract", () => {
  function caCertificate(overrides = {}) {
    return {
      certificateB64: "MIIB",
      keySha256: HEX64,
      thumbprintSha1: "AABBCCDDEEFF00112233445566778899AABBCCDD",
      notBefore: "2026-01-01T00:00:00Z",
      notAfter: "2031-01-01T00:00:00Z",
      ...overrides,
    };
  }

  function preflightResult(overrides = {}) {
    return {
      caConfig: CA_CONFIG,
      template: "TokenTimerWebServer",
      templateCheck: {
        verdict: "safe",
        reasons: [],
        schemaVersion: 2,
        templateOid: "1.3.6.1.4.1.311.21.8.1.2.3.4.5.6",
        minimalKeySize: 2048,
        asymmetricAlgorithm: null,
        enrolleeSuppliesSubject: true,
      },
      caCheck: { verdict: "safe", reasons: [], operatorAttested: false },
      caCertificates: [caCertificate()],
      ...overrides,
    };
  }

  it("accepts parsed verdicts and the CA certificates to pin", () => {
    assert.equal(validatePreflightResult(preflightResult()), true, errorsOf(validatePreflightResult));
    assert.equal(
      validatePreflightResult(
        preflightResult({
          templateCheck: { verdict: "unsafe", reasons: ["eku_not_server_auth_only", "schema_version_1"] },
          caCheck: { verdict: "unreadable", reasons: ["flags_unreadable"], operatorAttested: true },
        }),
      ),
      true,
      errorsOf(validatePreflightResult),
    );
  });

  it("keeps verdicts and reasons consistent", () => {
    const withTemplate = (templateCheck) => preflightResult({ templateCheck });
    assert.equal(validatePreflightResult(withTemplate({ verdict: "safe", reasons: ["schema_version_1"] })), false);
    assert.equal(validatePreflightResult(withTemplate({ verdict: "unsafe", reasons: [] })), false);
    assert.equal(validatePreflightResult(withTemplate({ verdict: "unsafe", reasons: ["any_purpose"] })), false);
    assert.equal(
      validatePreflightResult(preflightResult({ caCheck: { verdict: "unreadable", reasons: [], operatorAttested: false } })),
      false,
    );
  });

  it("is size-capped and never carries raw command output", () => {
    assert.equal(
      validatePreflightResult(preflightResult({ caCertificates: Array.from({ length: 9 }, () => caCertificate()) })),
      false,
    );
    assert.equal(
      validatePreflightResult(preflightResult({ caCertificates: [caCertificate({ certificateB64: "A".repeat(8196) })] })),
      false,
    );
    assert.equal(validatePreflightResult(preflightResult({ rawOutput: "certutil -v" })), false);
    assert.equal(
      validatePreflightResult(
        preflightResult({ templateCheck: { verdict: "safe", reasons: [], displayName: "Web Server" } }),
      ),
      false,
    );
  });
});

describe("Agent protocol for AD CS jobs", () => {
  function resultMessage(body) {
    return {
      schemaVersion: 1,
      protocolVersion: "1.0.0",
      messageType: "result",
      agentId: "agent-1",
      workspaceId: WORKSPACE_ID,
      sentAt: "2026-07-20T12:00:00.000Z",
      clockOffsetMs: null,
      body: {
        jobId: "job-adcs-1",
        attemptId: "attempt-1",
        rejectionReason: null,
        keyRotated: null,
        errorMessage: null,
        ...body,
      },
    };
  }

  it("requires an enrollment result whenever a job is awaiting its issuer", () => {
    const enrollmentResult = { enrollmentId: ENROLLMENT_ID, attempt: 1, state: "pending_issuance", requestId: 4242 };
    assert.equal(
      validateAgentMessage(resultMessage({ status: "awaiting_issuer", enrollmentResult })),
      true,
      errorsOf(validateAgentMessage),
    );
    assert.equal(validateAgentMessage(resultMessage({ status: "awaiting_issuer" })), false);
    assert.equal(
      validateAgentMessage(resultMessage({ status: "awaiting_issuer", enrollmentResult: null })),
      false,
    );
  });

  it("names the two refusals an agent makes before any CA contact", () => {
    for (const rejectionReason of ["issuer_not_allowlisted", "enrollment_snapshot_mismatch"]) {
      assert.equal(
        validateAgentMessage(resultMessage({ status: "rejected", rejectionReason })),
        true,
        `${rejectionReason}: ${errorsOf(validateAgentMessage)}`,
      );
    }
  });
});
