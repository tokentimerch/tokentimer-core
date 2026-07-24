"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  CERTOPS_AGENT_OBSERVATION_INVALID,
  normalizeAgentFilesystemObservation,
  persistAgentDiscoveryEvidenceBatch,
} = require(
  path.resolve(
    __dirname,
    "../../apps/api/services/certops/agentObservations.js",
  ),
);

const AGENT = {
  id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  agentId: "agent-host-1",
  workspaceId: "11111111-1111-4111-8111-111111111111",
  hostname: "edge-01.example",
};

describe("normalizeAgentFilesystemObservation", () => {
  it("builds a structured observation and overlays server-owned agentId", () => {
    const observation = normalizeAgentFilesystemObservation({
      agent: AGENT,
      evidenceItem: {
        evidenceId: "ev_discovery_1",
        eventType: "certificate.observed",
        observedAt: "2026-07-24T08:00:00.000Z",
        fingerprintSha256: "a".repeat(64),
        summary: "found cert",
        metadata: [
          { name: "filePath", value: "/etc/ssl/certs/app.pem" },
          { name: "agentId", value: "spoofed-agent" },
          { name: "subject", value: "CN=app.example" },
          { name: "issuer", value: "CN=Test CA" },
          { name: "targetHost", value: "edge-01.example" },
        ],
      },
      serverObservedAt: "2026-07-24T08:00:01.000Z",
    });

    assert.equal(observation.agentId, AGENT.agentId);
    assert.equal(observation.agentRowId, AGENT.id);
    assert.equal(observation.filePath, "/etc/ssl/certs/app.pem");
    assert.equal(observation.fingerprintSha256, "a".repeat(64));
    assert.equal(observation.source, "agent_filesystem");
    assert.equal(observation.observedAtServer, "2026-07-24T08:00:01.000Z");
  });

  it("rejects discovery evidence without fingerprint or filePath", () => {
    assert.throws(
      () =>
        normalizeAgentFilesystemObservation({
          agent: AGENT,
          evidenceItem: {
            evidenceId: "ev_1",
            eventType: "certificate.observed",
            observedAt: "2026-07-24T08:00:00.000Z",
            metadata: [{ name: "filePath", value: "/tmp/a.pem" }],
          },
        }),
      (error) => error.code === CERTOPS_AGENT_OBSERVATION_INVALID,
    );
  });
});

describe("persistAgentDiscoveryEvidenceBatch", () => {
  it("rolls back sequence when inventory upsert fails mid-batch", async () => {
    const queries = [];
    let begun = false;
    let rolledBack = false;
    const client = {
      async query(sql, params) {
        queries.push({ sql, params });
        if (sql === "BEGIN") {
          begun = true;
          return { rows: [] };
        }
        if (sql === "ROLLBACK") {
          rolledBack = true;
          return { rows: [] };
        }
        if (sql.includes("SET last_sequence")) {
          return { rows: [{ id: AGENT.id }] };
        }
        if (sql.includes("FROM certificate_evidence")) {
          return { rows: [] };
        }
        if (sql.includes("INSERT INTO managed_certificates")) {
          throw new Error("inventory boom");
        }
        return { rows: [] };
      },
      release() {},
    };
    const dbPool = {
      async connect() {
        return client;
      },
    };

    await assert.rejects(
      () =>
        persistAgentDiscoveryEvidenceBatch({
          dbPool,
          agent: AGENT,
          envelope: { sequence: 3 },
          evidenceItems: [
            {
              evidenceId: "ev_1",
              eventType: "certificate.observed",
              observedAt: "2026-07-24T08:00:00.000Z",
              fingerprintSha256: "b".repeat(64),
              metadata: [
                { name: "filePath", value: "/etc/ssl/certs/app.pem" },
                { name: "targetHost", value: "edge-01.example" },
              ],
            },
          ],
          deps: {
            enforceAgentSequence: async ({ client: c, envelope }) => {
              await c.query("SET last_sequence = $1", [envelope.sequence]);
            },
          },
        }),
      /inventory boom/,
    );

    assert.equal(begun, true);
    assert.equal(rolledBack, true);
    assert.ok(queries.some((entry) => entry.sql.includes("SET last_sequence")));
  });
});
