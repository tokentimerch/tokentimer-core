"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  certificateFor,
  createCertificateProvisioner,
} = require(path.resolve(__dirname, "../../apps/k8s-controller/src/certificate-provisioner.js"));

const command = Object.freeze({
  schemaVersion: 1,
  workspaceId: "00000000-0000-4000-8000-000000000001",
  clusterId: "cluster-a",
  jobId: "00000000-0000-4000-8000-000000000002",
  managedCertificateId: "00000000-0000-4000-8000-000000000003",
  namespace: "team-a",
  certificateName: "web-cert",
  secretName: "web-tls",
  issuerRef: { group: "cert-manager.io", kind: "ClusterIssuer", name: "issuer-a" },
  dnsNames: ["www.example.test", "example.test"],
});

describe("cert-manager Certificate provisioner", () => {
  it("constructs the only allowed Certificate shape locally", () => {
    assert.deepEqual(certificateFor(command), {
      apiVersion: "cert-manager.io/v1",
      kind: "Certificate",
      metadata: {
        name: "web-cert",
        namespace: "team-a",
        labels: {
          "app.kubernetes.io/managed-by": "tokentimer",
          "certops.tokentimer.io/intent-id": command.jobId,
          "certops.tokentimer.io/workspace-id": command.workspaceId,
          "certops.tokentimer.io/cluster-id": "cluster-a",
          "certops.tokentimer.io/managed-certificate-id": command.managedCertificateId,
        },
      },
      spec: {
        secretName: "web-tls",
        dnsNames: ["www.example.test", "example.test"],
        issuerRef: command.issuerRef,
      },
    });
  });

  it("creates absent resources, reconciles matching ownership, and never adopts a foreign Certificate", async () => {
    const calls = [];
    const client = {
      async getCertificate() {
        const error = new Error("missing");
        error.statusCode = 404;
        throw error;
      },
      async createCertificate(value) { calls.push(["create", value]); return { body: { metadata: { uid: "public-uid" } } }; },
      async patchCertificate(value) { calls.push(["patch", value]); return { body: value.certificate }; },
    };
    const provisioner = createCertificateProvisioner({ client, clusterId: "cluster-a", watchNamespaces: ["team-a"] });
    const created = await provisioner.reconcile(command);
    assert.equal(created.operation, "created");
    assert.equal(calls.length, 1);
    assert.equal(calls[0][0], "create");

    const owned = certificateFor(command);
    client.getCertificate = async () => ({ body: owned });
    const unchanged = await provisioner.reconcile(command);
    assert.equal(unchanged.operation, "unchanged");
    assert.equal(calls.length, 1);

    client.getCertificate = async () => ({ body: { metadata: { labels: {} }, spec: {} } });
    await assert.rejects(() => provisioner.reconcile(command), {
      code: "CERTOPS_K8S_UNMANAGED_RESOURCE_CONFLICT",
    });
    assert.equal(calls.length, 1);
  });

  it("rejects a local namespace policy mismatch before any Kubernetes call", async () => {
    const client = { getCertificate: async () => { throw new Error("must not call"); } };
    const provisioner = createCertificateProvisioner({ client, clusterId: "cluster-a", watchNamespaces: ["team-b"] });
    await assert.rejects(() => provisioner.reconcile(command), {
      code: "CERTOPS_PROVISIONING_NAMESPACE_FORBIDDEN",
    });
  });
});
