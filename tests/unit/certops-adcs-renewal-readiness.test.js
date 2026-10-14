const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

const {
  CERTOPS_ADCS_AGENT_NOT_PREPARED,
  createAutomaticAdcsRenewal,
} = require("../../apps/api/services/certops/renewalScheduler");
const {
  ADCS_PREFLIGHT_MAX_AGE_MS,
} = require("../../packages/contracts/certops/adcs-preflight-freshness.cjs");

const MINUTE_MS = 60 * 1000;
const HOUR_MS = 60 * MINUTE_MS;

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
const CONFIRMED_AT = new Date(Date.now() - 7 * 24 * HOUR_MS);

function confirmedVersion() {
  return {
    ca_config: CA_CONFIG,
    template: TEMPLATE,
    ca_key_sha256: CA_KEY,
    confirmed_at: CONFIRMED_AT,
  };
}

// The latest adcs-preflight an agent holds, as the gate loads it: a safe
// verdict for the confirmed CA, template, and key, created `createdAgoMs` ago.
function preflightEvidence({ id = "agent-1", createdAgoMs = HOUR_MS, verdict = {} } = {}) {
  return {
    id,
    last_seen_at: new Date(),
    status: "succeeded",
    created_at: new Date(Date.now() - createdAgoMs),
    result_metadata: {
      preflightVerdict: {
        templateCheck: "safe",
        caCheck: "safe",
        caConfig: CA_CONFIG,
        template: TEMPLATE,
        caKeySha256s: [CA_KEY],
        ...verdict,
      },
    },
  };
}

// Answers each gate query by its SQL shape; anything else fails the test.
function fakePool({
  agentRows = [],
  declaredRows = [{ "?column?": 1 }],
  openRows = [],
  versionRows = [confirmedVersion()],
} = {}) {
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
  it("waits when a declaring agent has no qualifying adcs-preflight for this CA", async () => {
    const pool = fakePool({ declaredRows: [{ "?column?": 1 }] });
    await assert.rejects(run(pool), { code: CERTOPS_ADCS_AGENT_NOT_PREPARED });
    const select = pool.queries.find((q) => q.sql.includes("SELECT a.id"));
    assert.match(select.sql, /'adcs-preflight'/);
    assert.match(select.sql, /declared_target_selectors @>/);
    assert.deepEqual(select.params, ["ws-1", "www.example.com", "issuer-1"]);
  });

  it("accepts a safe preflight taken an hour ago, after confirmation", async () => {
    const pool = fakePool({
      agentRows: [preflightEvidence({ createdAgoMs: HOUR_MS })],
      openRows: [{ id: "enrollment-open" }],
    });
    const result = await run(pool);
    assert.deepEqual(result, { job: { id: null, operation: "renew" }, created: false });
  });

  it("waits when the only preflight is older than the 24-hour freshness bound", async () => {
    const pool = fakePool({
      agentRows: [preflightEvidence({ createdAgoMs: 25 * HOUR_MS })],
    });
    await assert.rejects(run(pool), { code: CERTOPS_ADCS_AGENT_NOT_PREPARED });
  });

  it("accepts a 23h-old preflight from the same agent for the same CA/template/pin", async () => {
    const pool = fakePool({
      agentRows: [preflightEvidence({ createdAgoMs: 23 * HOUR_MS })],
      openRows: [{ id: "enrollment-open" }],
    });
    assert.deepEqual(await run(pool), {
      job: { id: null, operation: "renew" },
      created: false,
    });
  });

  it("waits when the only declaring agent has no preflight of its own", async () => {
    // Gate SQL returns one row per declaring agent. Agent B declares the
    // target but holds no preflight; another agent's evidence is not on this row.
    const pool = fakePool({
      agentRows: [
        {
          id: "agent-b",
          last_seen_at: new Date(),
          status: null,
          created_at: null,
          result_metadata: null,
        },
      ],
    });
    await assert.rejects(run(pool), { code: CERTOPS_ADCS_AGENT_NOT_PREPARED });
  });

  it("uses the shared freshness constant as the boundary", async () => {
    assert.equal(ADCS_PREFLIGHT_MAX_AGE_MS, 24 * HOUR_MS);

    const justInside = fakePool({
      agentRows: [preflightEvidence({ createdAgoMs: ADCS_PREFLIGHT_MAX_AGE_MS - MINUTE_MS })],
      openRows: [{ id: "enrollment-open" }],
    });
    assert.deepEqual(await run(justInside), {
      job: { id: null, operation: "renew" },
      created: false,
    });

    const justOutside = fakePool({
      agentRows: [preflightEvidence({ createdAgoMs: ADCS_PREFLIGHT_MAX_AGE_MS + MINUTE_MS })],
    });
    await assert.rejects(run(justOutside), { code: CERTOPS_ADCS_AGENT_NOT_PREPARED });
  });

  it("does not qualify a preflight taken before the CA was re-confirmed", async () => {
    const pool = fakePool({
      agentRows: [preflightEvidence({ createdAgoMs: HOUR_MS })],
      versionRows: [{ ...confirmedVersion(), confirmed_at: new Date(Date.now() - 30 * MINUTE_MS) }],
    });
    await assert.rejects(run(pool), { code: CERTOPS_ADCS_AGENT_NOT_PREPARED });
  });

  it("does not qualify a preflight that checked a different template", async () => {
    const pool = fakePool({
      agentRows: [preflightEvidence({ verdict: { template: "OtherTemplate" } })],
    });
    await assert.rejects(run(pool), { code: CERTOPS_ADCS_AGENT_NOT_PREPARED });
  });

  it("does not qualify any agent when no version is confirmed", async () => {
    const pool = fakePool({
      agentRows: [preflightEvidence()],
      versionRows: [],
    });
    await assert.rejects(run(pool), { code: CERTOPS_ADCS_AGENT_NOT_PREPARED });
  });

  it("keeps the not-deployable reason when no active agent declares the target", async () => {
    const pool = fakePool({ declaredRows: [] });
    await assert.rejects(run(pool), (error) => {
      assert.notEqual(error.code, CERTOPS_ADCS_AGENT_NOT_PREPARED);
      return error.code === "CERTOPS_CERTIFICATE_NOT_AGENT_DEPLOYABLE";
    });
  });
});
