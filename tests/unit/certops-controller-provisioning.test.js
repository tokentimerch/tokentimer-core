"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

const {
  CERTOPS_CONTROLLER_PROVISIONING_INVALID,
  DELIVERY_RETRY_INTERVAL_SECONDS,
  admitControllerProvisioningDelivery,
  canonicalizeControllerProvisioningTerminalOccurredAt,
  normalizeDesiredCertificate,
  normalizeHumanProvisionRequest,
  takeNextControllerProvisioningCommand,
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

describe("controller provisioning normalization", () => {
  for (const status of ["pending", "claimed", "running"]) {
    it(`preserves ${status} command admission semantics after its management period closes`, async () => {
      let delivered = false;
      const client = { release() {}, async query(sql) {
        if (["BEGIN", "COMMIT", "ROLLBACK"].includes(sql)) return { rows: [] };
        if (sql.includes("FROM system_settings")) return { rows: [{ certops_settings: { enabled: true } }] };
        if (sql.includes("FROM workspaces")) return { rows: [{ id: workspaceId, certops_paused: false }] };
        if (sql.includes("FROM certificate_jobs j")) return { rows: [{ id: desired.jobId, status,
          subject_type: "managed_certificate", subject_id: desired.managedCertificateId,
          operation: "deploy", management_period_id: "00000000-0000-4000-8000-000000000004",
          payload: { desiredCertificate: desired }, claimed_by_controller_cluster_id: "cluster-a" }] };
        if (sql.includes("FROM managed_certificates mc")) return { rows: [{ id: desired.managedCertificateId }] };
        if (sql.includes("FROM certops_management_periods")) return { rows: [] }; // Closed period.
        if (sql.includes("INSERT INTO certificate_controller_provision_deliveries")) {
          delivered = true;
          return { rows: [{ job_id: desired.jobId }] };
        }
        if (sql.includes("UPDATE certificate_jobs")) return { rows: [{ status }] };
        throw new Error(`unexpected query: ${sql}`);
      } };
      const result = await takeNextControllerProvisioningCommand({
        dbPool: { connect: async () => client }, env: { CERTOPS_ENABLED: "true" },
        apiToken: { workspaceId, controllerClusterId: "cluster-a" },
      });
      assert.equal(delivered, status !== "pending");
      if (status === "pending") assert.equal(result, null);
      else assert.equal(result.command.jobId, desired.jobId);
    });
  }

  it("uses the delivery row as an atomic admission gate before a controller claim", async () => {
    const calls = [];
    const admitted = await admitControllerProvisioningDelivery({
      client: {
        query: async (sql, values) => {
          calls.push({ sql, values });
          return { rows: [] };
        },
      },
      row: {
        id: desired.jobId,
        claimed_by_controller_cluster_id: null,
        lease_expires_at: null,
      },
      apiToken: {
        workspaceId,
        controllerClusterId: "cluster-a",
      },
    });

    assert.equal(admitted, false);
    assert.equal(calls.length, 1);
    assert.match(calls[0].sql, /INSERT INTO certificate_controller_provision_deliveries/);
    assert.match(calls[0].sql, /ON CONFLICT \(job_id\) DO UPDATE/);
    assert.match(calls[0].sql, /WHERE certificate_controller_provision_deliveries\.delivered_at <=/);
    assert.match(calls[0].sql, /RETURNING job_id/);
    assert.deepEqual(calls[0].values, [
      desired.jobId,
      workspaceId,
      "cluster-a",
      String(DELIVERY_RETRY_INTERVAL_SECONDS),
      false,
    ]);
  });

  it("admits an expired lease only for the same controller cluster", async () => {
    const calls = [];
    const admitted = await admitControllerProvisioningDelivery({
      client: {
        query: async (sql, values) => {
          calls.push({ sql, values });
          return { rows: [{ job_id: desired.jobId }] };
        },
      },
      row: {
        id: desired.jobId,
        claimed_by_controller_cluster_id: "cluster-a",
        lease_expires_at: new Date(Date.now() - 1_000),
      },
      apiToken: {
        workspaceId,
        controllerClusterId: "cluster-a",
      },
    });
    assert.equal(admitted, true);
    assert.equal(calls[0].values[4], true);

    await admitControllerProvisioningDelivery({
      client: {
        query: async (sql, values) => {
          calls.push({ sql, values });
          return { rows: [] };
        },
      },
      row: {
        id: desired.jobId,
        claimed_by_controller_cluster_id: "cluster-b",
        lease_expires_at: new Date(Date.now() - 1_000),
      },
      apiToken: {
        workspaceId,
        controllerClusterId: "cluster-a",
      },
    });
    assert.equal(calls[1].values[4], false);
  });

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

  it("canonicalizes only older controller-provisioning terminal timestamps", async () => {
    const startedAt = "2026-07-21T12:00:00.000Z";
    const olderAt = "2026-07-21T11:00:00.000Z";
    const laterAt = "2026-07-21T13:00:00.000Z";
    const controllerClient = {
      query: async () => ({
        rows: [
          {
            source: "controller_provisioning",
            started_at: new Date(startedAt),
          },
        ],
      }),
    };

    for (const eventType of ["job.completed", "job.failed"]) {
      assert.equal(
        await canonicalizeControllerProvisioningTerminalOccurredAt({
          client: controllerClient,
          workspaceId,
          jobId: desired.jobId,
          eventType,
          occurredAt: olderAt,
        }),
        startedAt,
      );
      assert.equal(
        await canonicalizeControllerProvisioningTerminalOccurredAt({
          client: controllerClient,
          workspaceId,
          jobId: desired.jobId,
          eventType,
          occurredAt: laterAt,
        }),
        laterAt,
      );
    }

    let nonTerminalQueries = 0;
    assert.equal(
      await canonicalizeControllerProvisioningTerminalOccurredAt({
        client: {
          query: async () => {
            nonTerminalQueries += 1;
            return { rows: [] };
          },
        },
        workspaceId,
        jobId: desired.jobId,
        eventType: "job.started",
        occurredAt: olderAt,
      }),
      olderAt,
    );
    assert.equal(nonTerminalQueries, 0);

    assert.equal(
      await canonicalizeControllerProvisioningTerminalOccurredAt({
        client: {
          query: async () => ({
            rows: [{ source: "api", started_at: new Date(startedAt) }],
          }),
        },
        workspaceId,
        jobId: desired.jobId,
        eventType: "job.completed",
        occurredAt: olderAt,
      }),
      olderAt,
    );
  });
});
