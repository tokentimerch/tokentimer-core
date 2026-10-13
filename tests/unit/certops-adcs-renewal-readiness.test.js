const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

const {
  CERTOPS_ADCS_AGENT_NOT_PREPARED,
  createAutomaticAdcsRenewal,
} = require("../../apps/api/services/certops/renewalScheduler");

const CERTIFICATE = {
  id: "cert-1",
  workspace_id: "ws-1",
  profile_id: "profile-1",
  profile_issuer_id: "issuer-1",
  common_name: "www.example.com",
  not_after: "2026-12-01T00:00:00Z",
  profile_public_metadata: {
    renewalProfile: {
      target: {
        type: "windows-iis",
        reference: "www.example.com",
        store: "My",
        binding: { site: "Default Web Site", port: 443 },
      },
      sanPolicy: { sans: ["www.example.com"] },
      keyAlgorithm: "rsa",
      keySize: 2048,
    },
  },
};

// Plain strings, as the enrollment snapshot contract defines them.
const CA_CONFIG = "ca.example.com\\Issuing CA";
const TEMPLATE = "WebServer";
const CA_KEY = "ab".repeat(32);
const CONFIRMED_AT = new Date("2026-10-01T00:00:00Z");

// Answers each gate query by its SQL shape; anything else fails the test.
function fakePool({
  agentRows = [],
  declaredRows = [],
  openRows = [],
  versionRows = [
    { ca_config: CA_CONFIG, template: TEMPLATE, ca_key_sha256: CA_KEY, confirmed_at: CONFIRMED_AT },
  ],
}) {
  const queries = [];
  return {
    queries,
    async query(sql, params) {
      queries.push({ sql, params });
      if (sql.includes("SELECT kind FROM certificate_issuers")) {
        return { rows: [{ kind: "adcs" }] };
      }
      if (sql.includes("certificate_issuer_versions v")) return { rows: versionRows };
      if (sql.includes("SELECT a.id")) return { rows: agentRows };
      if (sql.includes("SELECT 1")) return { rows: declaredRows };
      if (sql.includes("FROM certificate_enrollments")) return { rows: openRows };
      throw new Error(`unexpected query: ${sql.slice(0, 80)}`);
    },
  };
}

function run(pool) {
  return createAutomaticAdcsRenewal({
    dbPool: pool,
    certificate: CERTIFICATE,
    mode: "real",
    env: {},
    auditWriter: async () => {},
  });
}

describe("AD CS automatic renewal agent readiness", () => {
  it("waits when a declaring agent has not run a safe adcs-preflight for this CA", async () => {
    const pool = fakePool({ declaredRows: [{ "?column?": 1 }] });
    await assert.rejects(run(pool), { code: CERTOPS_ADCS_AGENT_NOT_PREPARED });
    const select = pool.queries.find((q) => q.sql.includes("SELECT a.id"));
    assert.match(select.sql, /'adcs-preflight'/);
    assert.match(select.sql, /preflightVerdict'->>'caCheck' = 'safe'/);
    assert.match(select.sql, /preflightVerdict'->>'templateCheck' = 'safe'/);
    assert.match(select.sql, /preflightVerdict'->>'caConfig' = \$4::text/);
    assert.match(select.sql, /preflightVerdict'->>'template' = \$5::text/);
    assert.match(select.sql, /preflightVerdict'->'caKeySha256s'/);
    assert.match(select.sql, /latest\.created_at >= \$7::timestamptz/);
    assert.deepEqual(select.params, [
      "ws-1",
      "www.example.com",
      "issuer-1",
      CA_CONFIG,
      TEMPLATE,
      CA_KEY,
      CONFIRMED_AT,
    ]);
  });

  it("does not qualify any agent when no version is confirmed", async () => {
    const pool = fakePool({ declaredRows: [{ "?column?": 1 }], versionRows: [] });
    await assert.rejects(run(pool), { code: CERTOPS_ADCS_AGENT_NOT_PREPARED });
    const select = pool.queries.find((q) => q.sql.includes("SELECT a.id"));
    assert.deepEqual(select.params.slice(3), [null, null, null, null]);
  });

  it("keeps the not-deployable reason when no active agent declares the target", async () => {
    const pool = fakePool({ declaredRows: [] });
    await assert.rejects(run(pool), (error) => {
      assert.notEqual(error.code, CERTOPS_ADCS_AGENT_NOT_PREPARED);
      return error.code === "CERTOPS_CERTIFICATE_NOT_AGENT_DEPLOYABLE";
    });
  });

  it("proceeds past the gate once a prepared agent exists", async () => {
    const pool = fakePool({
      agentRows: [{ id: "agent-1" }],
      openRows: [{ id: "enrollment-open" }],
    });
    const result = await run(pool);
    assert.deepEqual(result, { job: { id: null, operation: "renew" }, created: false });
  });
});
