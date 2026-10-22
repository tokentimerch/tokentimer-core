const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const {
  buildSummary,
  summarizeContactGroups,
  reachableGroupIds,
  tokenGroupMap,
  splitExisting,
} = require("../../apps/api/services/onboarding/summary");

const emailContact = { id: "c1", details: { email: "ops@example.com" } };
const phoneOnly = { id: "c2", details: {} };

describe("onboarding summary helpers", () => {
  it("only counts groups that can reach an email recipient", () => {
    const summary = summarizeContactGroups(
      {
        contact_groups: [
          { id: "g1", name: "Ops", email_contact_ids: ["c1"] },
          { id: "g2", name: "Phones", email_contact_ids: ["c2"] },
          { id: "g3", name: "Hook", webhook_names: ["x"] },
        ],
        default_contact_group_id: "g1",
        email_alerts_enabled: true,
      },
      [emailContact, phoneOnly],
    );
    assert.equal(summary.count, 3);
    assert.equal(summary.withEmailRecipient, 1);
    assert.equal(summary.defaultHasEmailRecipient, true);
  });

  it("does not treat a default group without an email recipient as ready", () => {
    const summary = summarizeContactGroups(
      {
        contact_groups: [{ id: "g2", name: "Phones", email_contact_ids: ["c2"] }],
        default_contact_group_id: "g2",
      },
      [emailContact, phoneOnly],
    );
    assert.equal(summary.defaultHasEmailRecipient, false);
  });

  it("handles a missing default group and missing settings", () => {
    const noDefault = summarizeContactGroups(
      { contact_groups: [{ id: "g1", name: "Ops", email_contact_ids: ["c1"] }] },
      [emailContact],
    );
    assert.equal(noDefault.defaultHasEmailRecipient, false);
    assert.equal(noDefault.withEmailRecipient, 1);

    const empty = summarizeContactGroups(undefined, []);
    assert.equal(empty.count, 0);
    assert.equal(empty.defaultHasEmailRecipient, false);
    assert.equal(empty.emailAlertsEnabled, null);
  });

  it("reports which referenced ids still exist", () => {
    assert.deepEqual(splitExisting([1, 2, 3], [2]), {
      existing: [2],
      missing: [1, 3],
    });
    assert.deepEqual(splitExisting(["a"], ["a"]), {
      existing: ["a"],
      missing: [],
    });
  });

  it("reports asset-step ids separately from all token ids", async () => {
    const seen = [];
    const pool = {
      query: async (sql, params) => {
        if (sql.includes("FROM tokens WHERE workspace_id = $1 AND id = ANY")) {
          seen.push(params[1]);
          return { rows: [{ id: 5 }, { id: 9 }] };
        }
        if (sql.includes("COUNT(*)")) return { rows: [{ n: 2 }] };
        if (sql.includes("COUNT(DISTINCT")) return { rows: [{ n: 0 }] };
        return { rows: [] };
      },
    };
    const summary = await buildSummary(pool, {
      workspaceId: "w1",
      refs: { tokenIds: [5, 9], assetTokenIds: [9, 11] },
    });
    assert.deepEqual(summary.references.tokenIds.existing, [5, 9]);
    assert.deepEqual(summary.references.assetTokenIds, {
      existing: [9],
      missing: [11],
    });
    assert.equal(seen.length, 1);

    const legacy = await buildSummary(pool, {
      workspaceId: "w1",
      refs: { tokenIds: [5] },
    });
    assert.deepEqual(legacy.references.assetTokenIds, {
      existing: [],
      missing: [],
    });
  });
});

describe("groups attached to session items", () => {
  const settings = {
    contact_groups: [
      { id: "g1", name: "Ops", email_contact_ids: ["c1"] },
      { id: "g2", name: "Nobody", email_contact_ids: ["c2"] },
    ],
    default_contact_group_id: "g1",
  };

  it("lists only groups that exist and reach a recipient", () => {
    const reachable = reachableGroupIds(settings, [emailContact, phoneOnly]);
    assert.deepEqual([...reachable], ["g1"]);
  });

  it("maps a token with no group row to an empty list", () => {
    const reachable = reachableGroupIds(settings, [emailContact, phoneOnly]);
    const map = tokenGroupMap(
      [5, 6, 7],
      [
        { token_id: 5, contact_group_id: "g1" },
        { token_id: 5, contact_group_id: "g1" },
        { token_id: 6, contact_group_id: "g2" },
        { token_id: 6, contact_group_id: "gone" },
        { token_id: 99, contact_group_id: "g1" },
      ],
      reachable,
    );
    assert.deepEqual(map, { 5: ["g1"], 6: [], 7: [] });
  });

  it("exposes tokenGroups for session tokens and monitor certificates", async () => {
    const memberQueries = [];
    const pool = {
      query: async (sql, params) => {
        if (sql.includes("token_contact_groups")) {
          memberQueries.push(params[1]);
          return { rows: [{ token_id: 5, contact_group_id: "g1" }] };
        }
        if (sql.includes("FROM workspace_settings")) {
          return { rows: [settings] };
        }
        if (sql.includes("FROM workspace_contacts")) {
          return { rows: [emailContact, phoneOnly] };
        }
        if (sql.includes("FROM domain_monitors") && sql.includes("ORDER BY")) {
          return {
            rows: [
              { id: "11111111-1111-1111-1111-111111111111", token_id: 8 },
            ],
          };
        }
        if (sql.includes("FROM domain_monitors")) {
          return {
            rows: [{ id: "11111111-1111-1111-1111-111111111111" }],
          };
        }
        if (sql.includes("FROM tokens WHERE workspace_id = $1 AND id = ANY")) {
          return { rows: [{ id: 5 }] };
        }
        if (sql.includes("COUNT(*)")) return { rows: [{ n: 1 }] };
        if (sql.includes("COUNT(DISTINCT")) return { rows: [{ n: 0 }] };
        return { rows: [] };
      },
    };
    const summary = await buildSummary(pool, {
      workspaceId: "w1",
      refs: {
        tokenIds: [5],
        monitorIds: ["11111111-1111-1111-1111-111111111111"],
      },
    });
    assert.deepEqual(summary.references.tokenGroups, { 5: ["g1"], 8: [] });
    assert.deepEqual(memberQueries[0].sort(), [5, 8]);
  });

  it("skips the membership query when the session holds no tokens", async () => {
    let asked = false;
    const pool = {
      query: async (sql) => {
        if (sql.includes("token_contact_groups")) asked = true;
        if (sql.includes("COUNT(*)")) return { rows: [{ n: 0 }] };
        if (sql.includes("COUNT(DISTINCT")) return { rows: [{ n: 0 }] };
        return { rows: [] };
      },
    };
    const summary = await buildSummary(pool, { workspaceId: "w1", refs: {} });
    assert.deepEqual(summary.references.tokenGroups, {});
    assert.equal(asked, false);
  });
});