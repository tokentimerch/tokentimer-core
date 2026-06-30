"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  PRIVATE_KEY_MATERIAL_REJECTED,
} = require(
  path.resolve(__dirname, "../../apps/api/services/certops/parser.js"),
);
const {
  bridgeEndpointCertificateObservation,
  certificateFromObservation,
} = require(
  path.resolve(__dirname, "../../apps/api/services/certops/monitorBridge.js"),
);

const FAKE_PRIVATE_BODY = "RkFLRS1OT1QtQS1SRUFMLUtFWQ==";
const fakePem = (label) =>
  `-----BEGIN ${label}-----\n${FAKE_PRIVATE_BODY}\n-----END ${label}-----`;

const PRIVATE_KEY_PEM = fakePem("RSA PRIVATE KEY");
const NONCANONICAL_PRIVATE_KEY_PEM = `-----begin rsa private key-----\n${FAKE_PRIVATE_BODY}\n-----end rsa private key-----`;

const WORKSPACE_ID = "550e8400-e29b-41d4-a716-446655440000";
const MONITOR_ID = "660e8400-e29b-41d4-a716-446655440001";

function assertPrivateKeyRejected(fn) {
  assert.throws(fn, (error) => {
    assert.equal(error.code, PRIVATE_KEY_MATERIAL_REJECTED);
    assert.equal(error.status, 422);
    assert.match(error.message, /private key material/i);
    assert.doesNotMatch(error.message, /RSA PRIVATE KEY/i);
    assert.doesNotMatch(error.message, new RegExp(FAKE_PRIVATE_BODY));
    return true;
  });
}

describe("CertOps monitor bridge zero-custody", () => {
  it("rejects private key material in certificate.certificatePem", () => {
    assertPrivateKeyRejected(() =>
      certificateFromObservation({
        certificate: { certificatePem: PRIVATE_KEY_PEM },
      }),
    );
  });

  it("rejects noncanonical private key PEM in observation metadata fields", () => {
    assertPrivateKeyRejected(() =>
      certificateFromObservation({
        certificate: {
          issuer: "Probe CA",
          subject: NONCANONICAL_PRIVATE_KEY_PEM,
        },
      }),
    );
  });

  it("rejects private key material anywhere in bridge options before feature gating", async () => {
    await assert.rejects(
      () =>
        bridgeEndpointCertificateObservation({
          env: { CERTOPS_ENABLED: "false" },
          workspaceId: WORKSPACE_ID,
          domainMonitorId: MONITOR_ID,
          deploymentReference: PRIVATE_KEY_PEM,
          certificate: {
            issuer: "Probe CA",
            subject: "CN=probe.example.com",
            fingerprintSha256: "a".repeat(64),
            notAfter: "2099-01-01",
          },
        }),
      (error) => {
        assert.equal(error.code, PRIVATE_KEY_MATERIAL_REJECTED);
        assert.doesNotMatch(String(error.message), /RSA PRIVATE KEY/i);
        assert.doesNotMatch(String(error.message), new RegExp(FAKE_PRIVATE_BODY));
        return true;
      },
    );
  });

  it("does not emit private-key-looking fields from certificateFromObservation", () => {
    const certificate = certificateFromObservation({
      hostname: "www.example.com",
      certificate: {
        issuer: "Example CA",
        subject: "CN=www.example.com",
        serialNumber: "01",
        fingerprintSha256: "b".repeat(64),
        notAfter: "2099-01-01",
      },
    });

    for (const key of Object.keys(certificate)) {
      assert.doesNotMatch(
        key,
        /private/i,
        `${key} looks like a private-key custody field`,
      );
    }
    assert.equal(certificate.certificatePem, null);
  });
});
