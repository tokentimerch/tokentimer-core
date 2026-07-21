"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

const {
  CERTOPS_CONTROLLER_PROVISIONING_INVALID,
  normalizeDesiredCertificate,
  normalizeHumanProvisionRequest,
  validateAuthenticatedProvisioningBinding,
} = require("../../apps/api/services/certops/controllerProvisioning");

const workspaceId = "00000000-0000-4000-8000-000000000001";
const desired = Object.freeze({
  schemaVersion: 1,
  workspaceId,
  clusterId: "cluster-a",
  jobId: "00000000-0000-4000-8000-000000000002",
  managedCertificateId: "00000000-0000-4000-8000-000000000003",
  namespace: "team-a",
  certificateName: "web-cert",
  secretName: "web-tls",
  issuerRef: { group: "cert-manager.io", kind: "ClusterIssuer", name: "issuer-a" },
  dnsNames: ["www.example.test", "example.test", "example.test"],
});

describe("M3-A7 controller provisioning normalization", () => {
  it("accepts only the bounded public desired Certificate shape", () => {
    const normalized = normalizeDesiredCertificate(desired);
    assert.deepEqual(normalized.dnsNames, ["example.test", "www.example.test"]);
    assert.equal(normalized.issuerRef.kind, "ClusterIssuer");
    assert.equal(normalized.workspaceId, workspaceId);
  });

  it("derives workspace provenance and rejects Kubernetes-manifest or private input", () => {
    const human = normalizeHumanProvisionRequest({
      schemaVersion: 1,
      clusterId: "cluster-a",
      namespace: "team-a",
      certificateName: "web-cert",
      secretName: "web-tls",
      issuerRef: desired.issuerRef,
      dnsNames: ["example.test"],
    }, workspaceId);
    assert.equal(human.workspaceId, workspaceId);
    assert.throws(
      () => normalizeHumanProvisionRequest({ ...human, apiVersion: "v1" }, workspaceId),
      { code: CERTOPS_CONTROLLER_PROVISIONING_INVALID },
    );
    assert.throws(
      () => normalizeHumanProvisionRequest({ ...human, privateKey: "-----BEGIN PRIVATE KEY-----" }, workspaceId),
      { code: "PRIVATE_KEY_MATERIAL_REJECTED" },
    );
  });

  it("enforces authenticated workspace and immutable cluster provenance", () => {
    const normalized = normalizeDesiredCertificate(desired);
    assert.doesNotThrow(() => validateAuthenticatedProvisioningBinding({
      workspaceId,
      controllerClusterId: "cluster-a",
    }, normalized));
    assert.throws(
      () => validateAuthenticatedProvisioningBinding({ workspaceId, controllerClusterId: "cluster-b" }, normalized),
      { code: "CERTOPS_CONTROLLER_PROVISIONING_CLUSTER_MISMATCH" },
    );
  });
});
