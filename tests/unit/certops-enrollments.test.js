"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

const {
  assertForwardTransition,
  assertIssuerKind,
  attachEnrollmentDispatch,
  confirmedKeyAllowed,
  decideContinuation,
  freezeSnapshot,
  storedAdcsPayload,
} = require("../../apps/api/services/certops/enrollmentLifecycle");
const { validateSignedJob } = require("../../packages/contracts/certops/validate-signed-job.cjs");
const { migrations } = require("../../apps/api/migrations/migrate");

const ISSUER = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const ENROLLMENT = "5f0c2a8e-3b1d-4c6e-9a7f-1e2d3c4b5a69";

function snapshotInput() {
  return {
    issuerId: ISSUER,
    issuerVersion: 1,
    caConfig: "ca01.corp.example.com\\Corp Issuing CA 01",
    caKeySha256: "ab".repeat(32),
    template: "TokenTimerWebServer",
    authorizedDnsNames: ["app.example.com"],
    keyAlgorithm: "rsa",
    keySize: 2048,
  };
}

describe("AD CS enrollment lifecycle", () => {
  it("fails closed on an unknown issuer kind", () => {
    assert.equal(assertIssuerKind("acme"), "acme");
    assert.equal(assertIssuerKind("adcs"), "adcs");
    assert.throws(() => assertIssuerKind("venafi"), (error) => error.code === "CERTOPS_ISSUER_KIND_INVALID");
  });

  it("freezes snapshot bytes and refuses a backwards enrollment move", () => {
    const frozen = freezeSnapshot(snapshotInput());
    assert.equal(frozen.sha256, require("node:crypto").createHash("sha256").update(frozen.bytes).digest("hex"));
    assert.doesNotThrow(() => assertForwardTransition("submitting", "submission_uncertain"));
    assert.doesNotThrow(() => assertForwardTransition("installing", "install_failed"));
    assert.throws(
      () => assertForwardTransition("installed", "submitting"),
      (error) => error.code === "CERTOPS_ENROLLMENT_TRANSITION_INVALID",
    );
  });

  it("builds a signed adcs renew payload without storing issuer fields", () => {
    const frozen = freezeSnapshot(snapshotInput());
    const stored = storedAdcsPayload({
      certificateId: "cert-1",
      target: {
        type: "windows-iis",
        reference: "iis-01/default-web-site",
        store: "My",
        binding: { site: "Default Web Site", port: 443, sniHost: "app.example.com" },
      },
    });
    assert.equal(stored.issuerKind, undefined);
    const signed = {
      ...attachEnrollmentDispatch(stored, {
        id: ENROLLMENT,
        attempt: 1,
        snapshotB64: frozen.b64,
        snapshotSha256: frozen.sha256,
        operatorRequestId: 42,
      }),
      schemaVersion: 1,
      jobId: "job-adcs-1",
      workspaceId: "11111111-1111-4111-8111-111111111111",
      agentId: "22222222-2222-4222-8222-222222222222",
      action: "renew",
      mode: "real",
      requestedAt: "2026-01-01T00:00:00.000Z",
    };
    const validated = validateSignedJob(signed);
    assert.equal(validated.valid, true, JSON.stringify(validated.errors));
    assert.equal(signed.metadata[0].name, "adcs.reconcileRequestId");
    assert.equal(signed.metadata[0].value, 42);
  });

  it("polls a pending enrollment and retries an unreachable submit", () => {
    const now = new Date("2026-10-11T12:00:00.000Z");
    const snapshot = { pollInterval: 900, pendingTimeout: 3600 };
    assert.deepEqual(
      decideContinuation(
        {
          state: "pending_issuance",
          pendingSince: new Date("2026-10-11T10:00:00.000Z"),
          nextPollAt: new Date("2026-10-11T11:00:00.000Z"),
          activeJob: false,
        },
        snapshot,
        now,
      ),
      { state: "expired", reason: "pending_timeout" },
    );
    assert.equal(
      decideContinuation(
        {
          state: "submitting",
          lastErrorCode: "ADCS_CA_UNREACHABLE",
          nextPollAt: new Date("2026-10-11T11:00:00.000Z"),
          activeJob: false,
        },
        snapshot,
        now,
      ).reason,
      "ADCS_CA_UNREACHABLE",
    );
    assert.equal(
      decideContinuation(
        { state: "pending_issuance", nextPollAt: now, activeJob: true },
        snapshot,
        now,
      ),
      null,
    );
  });

  it("confirms only a key from a safe preflight", () => {
    const key = "cd".repeat(32);
    assert.equal(
      confirmedKeyAllowed(
        {
          templateCheck: { verdict: "safe", reasons: [] },
          caCertificates: [{ keySha256: key }],
        },
        key,
      ),
      true,
    );
    assert.equal(confirmedKeyAllowed({ templateCheck: { verdict: "unsafe", reasons: ["schema_version_1"] }, caCertificates: [{ keySha256: key }] }, key), false);
  });
});

describe("migration 70 certificate enrollments", () => {
  const migration = migrations.find((entry) => entry.name === "certops_certificate_enrollments");

  it("creates the issuer and enrollment tables and allows adcs-preflight", () => {
    assert.ok(migration);
    assert.equal(migration.version, 70);
    assert.match(migration.sql, /certificate_enrollments/);
    assert.match(migration.sql, /certificate_issuer_versions/);
    assert.match(migration.sql, /'adcs-preflight'/);
    assert.match(migration.sql, /enrollment_id/);
  });
});
