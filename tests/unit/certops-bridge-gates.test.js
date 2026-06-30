"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  evaluateCertOpsMonitorBridgeGate,
  wouldConsumeNewManagedCertificateObservation,
} = require(
  path.resolve(__dirname, "../../apps/api/services/certops/bridgeGates.js"),
);
const { CERTOPS_MONITOR_BRIDGE_SKIPPED } = require(
  path.resolve(__dirname, "../../apps/api/services/certops/monitorBridge.js"),
);

function mockClient(handlers) {
  return {
    async query(sql, params) {
      for (const handler of handlers) {
        const result = handler(sql, params);
        if (result !== undefined) return result;
      }
      throw new Error(`Unexpected query: ${sql}`);
    },
  };
}

describe("CertOps bridge gates (Core OSS)", () => {
  it("skips when CertOps is disabled", async () => {
    const client = mockClient([
      () => ({ rows: [] }),
    ]);

    const gate = await evaluateCertOpsMonitorBridgeGate({
      client,
      workspaceId: "ws-1",
      domainMonitorId: "mon-1",
      env: { CERTOPS_ENABLED: "false" },
    });

    assert.equal(gate.allowed, false);
    assert.equal(gate.skipped, true);
    assert.equal(gate.code, CERTOPS_MONITOR_BRIDGE_SKIPPED);
    assert.equal(gate.reason, "certops_disabled");
  });

  it("skips when workspace does not exist", async () => {
    const client = mockClient([
      () => ({ rows: [] }),
      (sql) => {
        if (sql.includes("FROM workspaces")) return { rows: [] };
      },
    ]);

    const gate = await evaluateCertOpsMonitorBridgeGate({
      client,
      workspaceId: "missing-ws",
      domainMonitorId: "mon-1",
      env: { CERTOPS_ENABLED: "true" },
    });

    assert.equal(gate.allowed, false);
    assert.equal(gate.skipped, true);
    assert.equal(gate.reason, "workspace_not_found");
  });

  it("allows when CertOps is enabled and workspace exists", async () => {
    const client = mockClient([
      (sql) => {
        if (sql.includes("FROM workspaces")) {
          return { rows: [{ id: "ws-1" }] };
        }
      },
    ]);

    const gate = await evaluateCertOpsMonitorBridgeGate({
      client,
      workspaceId: "ws-1",
      domainMonitorId: "mon-1",
      fingerprintSha256: "aa:bb",
      env: { CERTOPS_ENABLED: "true" },
    });

    assert.equal(gate.allowed, true);
    assert.equal(gate.skipped, false);
  });

  it("requires client, workspaceId, and domainMonitorId", async () => {
    await assert.rejects(
      () => evaluateCertOpsMonitorBridgeGate({ workspaceId: "ws-1" }),
      /client, workspaceId, and domainMonitorId are required/,
    );
  });
});

describe("wouldConsumeNewManagedCertificateObservation", () => {
  const VALID_FINGERPRINT =
    "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99";

  it("returns false when monitor already has a managed certificate", async () => {
    const client = mockClient([
      (sql) => {
        if (sql.includes("source_ref")) {
          return { rows: [{ id: "mc-1", fingerprint_sha256: "abc" }] };
        }
      },
    ]);

    const consumes = await wouldConsumeNewManagedCertificateObservation(
      client,
      "ws-1",
      "mon-1",
      "deadbeef",
    );
    assert.equal(consumes, false);
  });

  it("returns false when fingerprint already exists in workspace", async () => {
    const client = mockClient([
      (sql) => {
        if (sql.includes("source_ref")) return { rows: [] };
        if (sql.includes("fingerprint_sha256 = $2")) {
          return { rows: [{ id: "mc-existing" }] };
        }
      },
    ]);

    const consumes = await wouldConsumeNewManagedCertificateObservation(
      client,
      "ws-1",
      "mon-1",
      VALID_FINGERPRINT,
    );
    assert.equal(consumes, false);
  });

  it("returns true for a new monitor and fingerprint", async () => {
    const client = mockClient([
      (sql) => {
        if (sql.includes("source_ref")) return { rows: [] };
        if (sql.includes("fingerprint_sha256 = $2")) return { rows: [] };
      },
    ]);

    const consumes = await wouldConsumeNewManagedCertificateObservation(
      client,
      "ws-1",
      "mon-new",
      VALID_FINGERPRINT,
    );
    assert.equal(consumes, true);
  });
});
