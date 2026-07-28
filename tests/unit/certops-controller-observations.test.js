"use strict";

const assert = require("node:assert/strict");
const { describe, it } = require("node:test");
const {
  CERTOPS_CONTROLLER_CLUSTER_BINDING_REQUIRED,
  CERTOPS_CONTROLLER_OBSERVATION_CLUSTER_MISMATCH,
  CERTOPS_CONTROLLER_OBSERVATION_INVALID,
  CERTOPS_CONTROLLER_OBSERVATION_WORKSPACE_MISMATCH,
  normalizeControllerObservation,
  semanticRequestHash,
  validateAuthenticatedObservationBinding,
  _test,
} = require("../../apps/api/services/certops/controllerObservations");

const workspaceId = "11111111-1111-4111-8111-111111111111";
const certificateUid = "22222222-2222-4222-8222-222222222222";

function observation(overrides = {}) {
  return {
    schemaVersion: 1,
    observationId: "33333333-3333-4333-8333-333333333333",
    idempotencyKey: "a".repeat(64),
    workspaceId,
    clusterId: "controller-a",
    namespace: "certops",
    certificateName: "example-com",
    certificateUid,
    issuerRef: { name: "issuer" },
    secretName: "example-com-tls",
    certificateRequestRef: null,
    dnsNames: ["example.com"],
    conditions: [{ type: "Ready", status: "True" }],
    ready: true,
    publicCertificate: { fingerprintSha256: "b".repeat(64) },
    observationSource: "cert_manager",
    observedAt: "2026-07-21T10:00:00.000Z",
    ...overrides,
  };
}

describe("controller observation normalization", () => {
  it("accepts a bounded public cert-manager observation and redacts only free text", () => {
    const result = normalizeControllerObservation(observation({
      failureMessage: "token=secret-value",
    }));
    assert.equal(result.observation.observationSource, "cert_manager");
    assert.equal(result.observation.failureMessage, "token=[REDACTED]");
    assert.equal(result.redaction.applied, true);
  });

  it("rejects metadata bags and private material", () => {
    assert.throws(
      () => normalizeControllerObservation(observation({ metadata: {} })),
      { code: CERTOPS_CONTROLLER_OBSERVATION_INVALID },
    );
    assert.throws(
      () => normalizeControllerObservation(observation({ failureMessage: "-----BEGIN PRIVATE KEY-----" })),
      { code: "PRIVATE_KEY_MATERIAL_REJECTED" },
    );
  });

  it("excludes retry diagnostics from its semantic request hash", () => {
    const first = normalizeControllerObservation(observation()).observation;
    const replay = normalizeControllerObservation(observation({
      observationId: "44444444-4444-4444-8444-444444444444",
      observedAt: "2026-07-21T10:05:00.000Z",
    })).observation;
    assert.equal(semanticRequestHash(first), semanticRequestHash(replay));
    assert.notEqual(
      semanticRequestHash(first),
      semanticRequestHash({ ...replay, resourceVersion: "next" }),
    );
  });

  it("derives workspace and cluster provenance exclusively from the token binding", () => {
    const normalized = normalizeControllerObservation(observation()).observation;
    assert.doesNotThrow(() => validateAuthenticatedObservationBinding({
      workspaceId,
      controllerClusterId: "controller-a",
    }, normalized));
    assert.throws(
      () => validateAuthenticatedObservationBinding({ workspaceId: certificateUid, controllerClusterId: "controller-a" }, normalized),
      { code: CERTOPS_CONTROLLER_OBSERVATION_WORKSPACE_MISMATCH },
    );
    assert.throws(
      () => validateAuthenticatedObservationBinding({ workspaceId, controllerClusterId: null }, normalized),
      { code: CERTOPS_CONTROLLER_CLUSTER_BINDING_REQUIRED },
    );
    assert.throws(
      () => validateAuthenticatedObservationBinding({ workspaceId, controllerClusterId: "other" }, normalized),
      { code: CERTOPS_CONTROLLER_OBSERVATION_CLUSTER_MISMATCH },
    );
  });

  it("separates Kubernetes labels and resource names from certificate DNS and public SAN identities", () => {
    const normalized = normalizeControllerObservation(observation({
      namespace: "certops",
      certificateName: "certificate.example.com",
      secretName: "secret.example.com",
      certificateRequestRef: { name: "request.example.com" },
      dnsNames: ["*.example.com", "api.example.com"],
      publicCertificate: {
        fingerprintSha256: "b".repeat(64),
        subjectAltNames: [
          "*.example.com",
          "192.0.2.1",
          "2001:db8::1",
          "spiffe://example.test/ns/certops/sa/controller",
          "certops@example.com",
        ],
      },
    })).observation;
    assert.deepEqual(normalized.dnsNames, ["*.example.com", "api.example.com"]);
    assert.deepEqual(normalized.publicCertificate.subjectAltNames, [
      "*.example.com",
      "192.0.2.1",
      "2001:db8::1",
      "spiffe://example.test/ns/certops/sa/controller",
      "certops@example.com",
    ]);
    assert.throws(
      () => normalizeControllerObservation(observation({ dnsNames: ["api.*.example.com"] })),
      { code: CERTOPS_CONTROLLER_OBSERVATION_INVALID },
    );
    assert.throws(
      () => normalizeControllerObservation(observation({ namespace: "team.prod" })),
      { code: CERTOPS_CONTROLLER_OBSERVATION_INVALID },
    );
  });

  it("derives a safe common name from a DN, DNS SAN, or resource-name fallback", () => {
    const certificateFor = _test.certificateFor;
    assert.equal(
      certificateFor(observation({ publicCertificate: { subject: "CN=example.com, O=TokenTimer" } })).commonName,
      "example.com",
    );
    assert.equal(
      certificateFor(observation({ publicCertificate: { subject: "CN=api.example.com\nO=TokenTimer" } })).commonName,
      "api.example.com",
    );
    assert.equal(
      certificateFor(observation({
        dnsNames: ["fallback.example.com"],
        publicCertificate: { subject: "CN=bad\\,example.com, O=TokenTimer" },
      })).commonName,
      "fallback.example.com",
    );
    assert.equal(
      certificateFor(observation({
        dnsNames: ["fallback.example.com"],
        publicCertificate: { subject: "CN=, O=TokenTimer" },
      })).commonName,
      "fallback.example.com",
    );
    assert.equal(
      certificateFor(observation({
        dnsNames: [],
        publicCertificate: { subjectAltNames: ["192.0.2.1", "api.example.com"] },
      })).commonName,
      "api.example.com",
    );
    assert.equal(
      certificateFor(observation({ dnsNames: [], publicCertificate: null })).commonName,
      "example-com",
    );
  });
});

module.exports = { observation };
