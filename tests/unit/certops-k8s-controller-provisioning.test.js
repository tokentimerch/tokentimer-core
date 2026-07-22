"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  certificateFor,
  createCertificateProvisioner,
  isOwnedByCommand,
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
          "certops.tokentimer.io/last-intent-id": command.jobId,
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
    const provisioner = createCertificateProvisioner({
      client,
      clusterId: "cluster-a",
      watchNamespaces: ["team-a"],
      workspaceId: command.workspaceId,
    });
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

  it("rejects workspace, cluster, and namespace mismatches before any Kubernetes call", async () => {
    const calls = [];
    const client = {
      async getCertificate(value) { calls.push(["get", value]); },
      async createCertificate(value) { calls.push(["create", value]); },
      async patchCertificate(value) { calls.push(["patch", value]); },
    };
    const provisioner = createCertificateProvisioner({
      client,
      clusterId: "cluster-a",
      watchNamespaces: ["team-a"],
      workspaceId: command.workspaceId,
    });
    const cases = [
      [{ ...command, workspaceId: "00000000-0000-4000-8000-000000000099" }, "CERTOPS_PROVISIONING_WORKSPACE_MISMATCH"],
      [{ ...command, clusterId: "cluster-b" }, "CERTOPS_PROVISIONING_CLUSTER_MISMATCH"],
      [{ ...command, namespace: "team-b" }, "CERTOPS_PROVISIONING_NAMESPACE_FORBIDDEN"],
    ];
    for (const [mismatched, code] of cases) {
      await assert.rejects(() => provisioner.reconcile(mismatched), { code });
      assert.deepEqual(calls, []);
    }
  });

  it("uses stable ownership across later jobs while rejecting changed ownership", async () => {
    const later = {
      ...command,
      jobId: "00000000-0000-4000-8000-000000000004",
      secretName: "web-tls-v2",
      dnsNames: ["api.example.test"],
      issuerRef: { ...command.issuerRef, name: "issuer-b" },
    };
    const existing = certificateFor(command);
    assert.equal(isOwnedByCommand(existing, later), true);
    const calls = [];
    const client = {
      getCertificate: async () => ({ body: existing }),
      patchCertificate: async (value) => { calls.push(value); return { body: value.certificate }; },
    };
    const provisioner = createCertificateProvisioner({
      client,
      clusterId: "cluster-a",
      watchNamespaces: ["team-a"],
      workspaceId: command.workspaceId,
    });
    const result = await provisioner.reconcile(later);
    assert.equal(result.operation, "reconciled");
    assert.equal(calls[0].certificate.metadata.labels["certops.tokentimer.io/last-intent-id"], later.jobId);
    for (const field of ["workspaceId", "clusterId", "managedCertificateId"]) {
      const mismatched = { ...later, [field]: field === "clusterId" ? "cluster-b" : "00000000-0000-4000-8000-000000000099" };
      assert.equal(isOwnedByCommand(existing, mismatched), false);
    }
    assert.equal(isOwnedByCommand({ metadata: { labels: {} } }, later), false);
  });

  it("handles create races only after re-reading stable ownership", async () => {
    const owned = certificateFor(command);
    const calls = [];
    const conflict = Object.assign(new Error("exists"), { statusCode: 409 });
    const missing = Object.assign(new Error("missing"), { statusCode: 404 });
    let reads = 0;
    const client = {
      async getCertificate() {
        reads += 1;
        if (reads === 1) throw missing;
        return { body: owned };
      },
      async createCertificate() { throw conflict; },
      async patchCertificate(value) { calls.push(value); return { body: value.certificate }; },
    };
    const provisioner = createCertificateProvisioner({
      client,
      clusterId: "cluster-a",
      watchNamespaces: ["team-a"],
      workspaceId: command.workspaceId,
    });
    assert.equal((await provisioner.reconcile(command)).operation, "unchanged");

    reads = 0;
    const changed = { ...command, dnsNames: ["changed.example.test"] };
    const reconciled = await provisioner.reconcile(changed);
    assert.equal(reconciled.operation, "reconciled");
    assert.equal(calls.length, 1);

    reads = 0;
    client.getCertificate = async () => {
      reads += 1;
      if (reads === 1) throw missing;
      return { body: { metadata: { labels: {} }, spec: {} } };
    };
    await assert.rejects(() => provisioner.reconcile(command), {
      code: "CERTOPS_K8S_UNMANAGED_RESOURCE_CONFLICT",
    });
  });
});
