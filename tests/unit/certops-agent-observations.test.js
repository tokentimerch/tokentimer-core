"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  CERTOPS_AGENT_OBSERVATION_INVALID,
  normalizeAgentFilesystemObservation,
  persistAgentDiscoveryEvidenceBatch,
  _test,
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

describe("certificateFor", () => {
  it("derives commonName from the certificate's own subject CN, not the discovering host", () => {
    const observation = normalizeAgentFilesystemObservation({
      agent: AGENT,
      evidenceItem: {
        evidenceId: "ev_cn_1",
        eventType: "certificate.observed",
        observedAt: "2026-07-24T08:00:00.000Z",
        fingerprintSha256: "c".repeat(64),
        metadata: [
          { name: "filePath", value: "/etc/ssl/certs/app.pem" },
          { name: "targetHost", value: "edge-01.example" },
          { name: "subject", value: "CN=app.example.com, O=Example Inc" },
        ],
      },
    });

    const certificate = _test.certificateFor(observation);
    assert.equal(certificate.commonName, "app.example.com");
  });

  it("falls back to the discovery host only when the certificate has no SAN or subject CN", () => {
    const observation = normalizeAgentFilesystemObservation({
      agent: AGENT,
      evidenceItem: {
        evidenceId: "ev_cn_2",
        eventType: "certificate.observed",
        observedAt: "2026-07-24T08:00:00.000Z",
        fingerprintSha256: "d".repeat(64),
        metadata: [
          { name: "filePath", value: "/etc/ssl/certs/app.pem" },
          { name: "targetHost", value: "edge-01.example" },
        ],
      },
    });

    const certificate = _test.certificateFor(observation);
    assert.equal(certificate.commonName, "edge-01.example");
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
        if (sql.includes("INSERT INTO tokens")) {
          return { rows: [{ id: 999 }] };
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
                { name: "validFrom", value: "2026-01-01T00:00:00.000Z" },
                { name: "validTo", value: "2027-01-01T00:00:00.000Z" },
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

  it("mints and links an ssl_cert token for a filesystem discovery with no existing token", async () => {
    const queries = [];
    const client = {
      async query(sql, params) {
        queries.push({ sql, params });
        if (sql === "BEGIN" || sql === "COMMIT") return { rows: [] };
        if (sql.includes("SET last_sequence")) {
          return { rows: [{ id: AGENT.id }] };
        }
        if (sql.includes("FROM certificate_evidence")) {
          return { rows: [] };
        }
        // No pre-existing managed_certificate or token: both lookups miss.
        if (sql.includes("FROM managed_certificates") && sql.includes("SELECT")) {
          return { rows: [] };
        }
        if (sql.includes("FROM tokens") && sql.includes("SELECT")) {
          return { rows: [] };
        }
        if (sql.includes("INSERT INTO tokens")) {
          return { rows: [{ id: 4242 }] };
        }
        if (sql.includes("INSERT INTO managed_certificates")) {
          return {
            rows: [
              {
                id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
                token_id: 4242,
                workspace_id: AGENT.workspaceId,
                status: "discovered",
              },
            ],
          };
        }
        if (sql.includes("INSERT INTO certificate_targets")) {
          return { rows: [{ id: "target-1" }] };
        }
        if (sql.includes("INSERT INTO certificate_instances")) {
          return { rows: [{ id: "instance-1" }] };
        }
        if (sql.includes("INSERT INTO certificate_evidence")) {
          return { rows: [{ id: "evidence-1" }] };
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

    const result = await persistAgentDiscoveryEvidenceBatch({
      dbPool,
      agent: AGENT,
      envelope: { sequence: 4 },
      evidenceItems: [
        {
          evidenceId: "ev_token_1",
          eventType: "certificate.observed",
          observedAt: "2026-07-24T08:00:00.000Z",
          fingerprintSha256: "e".repeat(64),
          metadata: [
            { name: "filePath", value: "/etc/ssl/certs/app.pem" },
            { name: "targetHost", value: "edge-01.example" },
            { name: "subject", value: "CN=app.example.com" },
            { name: "validFrom", value: "2026-01-01T00:00:00.000Z" },
            { name: "validTo", value: "2027-01-01T00:00:00.000Z" },
          ],
        },
      ],
      deps: {
        enforceAgentSequence: async ({ client: c, envelope }) => {
          await c.query("SET last_sequence = $1", [envelope.sequence]);
        },
      },
    });

    assert.equal(result.ok, true);
    const tokenInsert = queries.find((entry) =>
      entry.sql.includes("INSERT INTO tokens"),
    );
    assert.ok(tokenInsert, "expected a token to be minted for the discovery");
    assert.ok(
      String(tokenInsert.params.at(-1)).includes("agent filesystem discovery"),
      "token notes should attribute the agent filesystem source, not the generic PEM-import copy",
    );

    const certInsert = queries.find((entry) =>
      entry.sql.includes("INSERT INTO managed_certificates"),
    );
    assert.ok(certInsert, "expected a managed_certificate insert");
    assert.equal(
      certInsert.params[1],
      4242,
      "the minted token id should be passed as the managed_certificate's token_id",
    );
  });
});
