const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const {
  loadAdcsReality,
  loadObservedCertificates,
} = require("../../apps/api/services/onboarding/certopsReality");

describe("loadAdcsReality session facts", () => {
  const SINCE = "2026-10-22T10:00:00.000Z";
  const row = (over) => ({
    id: "i",
    name: "CA",
    confirmed: true,
    current_version: 1,
    last_preflight: null,
    ...over,
  });
  const load = async (rows, opts) => {
    const answers = [
      { rows },
      { rows: [{ n: 0 }] },
      { rows: [{ installed: 0 }] },
      { rows: [] },
    ];
    return loadAdcsReality({ query: async () => answers.shift() }, "w", opts);
  };

  it("marks issuers created before the session so the guide never adopts them", async () => {
    const { issuers } = await load(
      [
        row({ id: "old", created_at: "2026-10-22T09:00:00.000Z" }),
        row({ id: "new", created_at: "2026-10-22T11:00:00.000Z" }),
      ],
      { since: SINCE },
    );
    assert.equal(issuers[0].existedBeforeSession, true);
    assert.equal(issuers[0].createdAt, "2026-10-22T09:00:00.000Z");
    assert.equal(issuers[1].existedBeforeSession, false);
  });

  it("never claims an issuer pre-dates a session it cannot date", async () => {
    const { issuers } = await load([
      row({ created_at: "2026-10-22T09:00:00.000Z" }),
    ]);
    assert.equal(issuers[0].existedBeforeSession, false);
  });

  it("reports profiles, attached certificates and the check taken after the pin", async () => {
    const { issuers } = await load([
      row({
        id: "a",
        profile_count: 2,
        attached_certificates: 1,
        checked_after_pin: true,
        revalidation_required: true,
      }),
      row({ id: "b", checked_after_pin: false }),
      row({ id: "c", confirmed: false, checked_after_pin: true }),
    ]);
    assert.equal(issuers[0].profileCount, 2);
    assert.equal(issuers[0].attachedCertificates, 1);
    assert.equal(issuers[0].checkedAfterPin, true);
    assert.equal(issuers[0].revalidationRequired, true);
    assert.equal(issuers[1].checkedAfterPin, false);
    assert.equal(issuers[2].checkedAfterPin, null);
  });
});

describe("loadObservedCertificates", () => {
  const AGENT = "33333333-3333-3333-3333-333333333333";
  const SINCE = "2026-10-22T10:00:00.000Z";

  it("asks for nothing without a session start, an agent or a cluster", async () => {
    let asked = false;
    const pool = {
      query: async () => {
        asked = true;
        return { rows: [] };
      },
    };
    assert.deepEqual(await loadObservedCertificates(pool, "w", {}), {
      total: 0,
      items: [],
    });
    assert.equal(asked, false);
  });

  it("scopes by workspace, the chosen agent, the cluster and the session start", async () => {
    let seen;
    const pool = {
      query: async (sql, params) => {
        seen = { sql, params };
        return { rows: [] };
      },
    };
    await loadObservedCertificates(pool, "w1", {
      since: SINCE,
      agentId: AGENT,
      clusterId: "prod-eu",
    });
    assert.deepEqual(seen.params, ["w1", AGENT, SINCE, "prod-eu"]);
    assert.match(seen.sql, /mc\.workspace_id = \$1/);
    assert.match(seen.sql, /LIMIT 50/);
  });

  it("drops an agent or cluster id that is not well formed", async () => {
    let seen;
    const pool = {
      query: async (sql, params) => {
        seen = params;
        return { rows: [] };
      },
    };
    await loadObservedCertificates(pool, "w", {
      since: SINCE,
      agentId: "x' OR 1=1",
      clusterId: "Bad/Cluster",
    });
    assert.equal(seen[1], null);
    assert.equal(seen[3], null);
  });

  it("returns the total, tokens and where each certificate came from", async () => {
    const pool = {
      query: async () => ({
        rows: [
          {
            certificate_id: "c1",
            token_id: 7,
            source: "agent_filesystem",
            agent_id: AGENT,
            cluster_id: "agent-1",
            total: 130,
          },
          {
            certificate_id: "c2",
            token_id: null,
            source: "cert_manager",
            agent_id: null,
            cluster_id: "prod-eu",
            total: 130,
          },
        ],
      }),
    };
    assert.deepEqual(
      await loadObservedCertificates(pool, "w", { since: SINCE }),
      {
        total: 130,
        items: [
          {
            certificateId: "c1",
            tokenId: 7,
            source: "agent_filesystem",
            agentId: AGENT,
            clusterId: null,
          },
          {
            certificateId: "c2",
            tokenId: null,
            source: "cert_manager",
            agentId: null,
            clusterId: "prod-eu",
          },
        ],
      },
    );
  });
});
