"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { pathToFileURL } = require("node:url");

const api = require(
  path.resolve(__dirname, "../../apps/api/src/shared/contactGroups.js"),
);
const { assertContactGroupIds } = require(
  path.resolve(__dirname, "../../apps/api/src/shared/assertContactGroupIds.js"),
);
const {
  replaceAssetContactGroups,
  loadAssignedGroupIds,
  loadAssignedGroupIdsForAssets,
} = require(
  path.resolve(
    __dirname,
    "../../apps/api/src/shared/replaceAssetContactGroups.js",
  ),
);

const GROUP_A = { id: "a", name: "Alpha", thresholds: [14, 7] };
const GROUP_B = { id: "b", name: "Beta", thresholds: [30] };
const GROUP_DEFAULT = { id: "default", name: "Default", thresholds: [] };
const CONTACT_GROUPS = [GROUP_B, GROUP_DEFAULT, GROUP_A];
const WORKSPACE_THRESHOLDS = [30, 14, 7, 1, 0];

async function loadWorkerContactGroups() {
  return import(
    pathToFileURL(
      path.resolve(__dirname, "../../apps/worker/src/shared/contactGroups.js"),
    ).href
  );
}

function createMockClient(handler) {
  const state = { queries: [] };
  const client = {
    query: async (text, params) => {
      const sql = typeof text === "string" ? text : text?.text || "";
      state.queries.push({ text: sql, params });
      return handler(sql, params, state);
    },
  };
  return { state, client };
}

describe("canonicalLegacyContactGroupId", () => {
  it("returns the lexicographically smallest unique id", () => {
    assert.equal(api.canonicalLegacyContactGroupId(["z", "a", "m"]), "a");
    assert.equal(api.canonicalLegacyContactGroupId(["m", "z", "a"]), "a");
  });

  it("is stable when assigned ids are reordered", () => {
    const forward = api.canonicalLegacyContactGroupId(["ops", "alerts", "sec"]);
    const reverse = api.canonicalLegacyContactGroupId(["sec", "alerts", "ops"]);
    assert.equal(forward, "alerts");
    assert.equal(reverse, forward);
  });

  it("does not change when workspace_settings.contact_groups is reordered", () => {
    const assigned = ["b", "a"];
    const forward = api.resolveContactGroupsForAsset({
      contactGroups: CONTACT_GROUPS,
      assignedIds: assigned,
      defaultContactGroupId: "default",
    });
    const reversed = api.resolveContactGroupsForAsset({
      contactGroups: [...CONTACT_GROUPS].reverse(),
      assignedIds: assigned,
      defaultContactGroupId: "default",
    });
    assert.equal(
      api.canonicalLegacyContactGroupId(forward.map((g) => g.id)),
      "a",
    );
    assert.deepEqual(
      forward.map((g) => g.id),
      reversed.map((g) => g.id),
    );
  });

  it("returns null for an empty assignment", () => {
    assert.equal(api.canonicalLegacyContactGroupId([]), null);
    assert.equal(api.canonicalLegacyContactGroupId(["", "  ", 12]), null);
    assert.equal(api.canonicalLegacyContactGroupId(null), null);
  });
});

describe("normalizeAssignedGroupIds", () => {
  it("unique-sorts in UTF-8 byte order and drops empty or non-string values", () => {
    assert.deepEqual(
      api.normalizeAssignedGroupIds(["b", "a", "b", "", " a ", 3]),
      ["a", "b"],
    );
    assert.deepEqual(api.normalizeAssignedGroupIds(["B", "a"]), ["B", "a"]);
  });
});

describe("resolveContactGroupsForAsset", () => {
  it("empty assigned ids resolve to the workspace default", () => {
    const resolved = api.resolveContactGroupsForAsset({
      contactGroups: CONTACT_GROUPS,
      assignedIds: [],
      defaultContactGroupId: "default",
    });
    assert.deepEqual(
      resolved.map((g) => g.id),
      ["default"],
    );

    const missingAssigned = api.resolveContactGroupsForAsset({
      contactGroups: CONTACT_GROUPS,
      assignedIds: undefined,
      defaultContactGroupId: "default",
    });
    assert.deepEqual(
      missingAssigned.map((g) => g.id),
      ["default"],
    );
  });

  it("empty assigned with no default returns []", () => {
    const resolved = api.resolveContactGroupsForAsset({
      contactGroups: CONTACT_GROUPS,
      assignedIds: [],
      defaultContactGroupId: null,
    });
    assert.deepEqual(resolved, []);
  });

  it("keeps valid groups and drops stale ids without adding the default", () => {
    const resolved = api.resolveContactGroupsForAsset({
      contactGroups: CONTACT_GROUPS,
      assignedIds: ["missing", "b", "a"],
      defaultContactGroupId: "default",
    });
    assert.deepEqual(
      resolved.map((g) => g.id),
      ["a", "b"],
    );
  });

  it("falls back to the default when every assigned id is missing from JSON", () => {
    const resolved = api.resolveContactGroupsForAsset({
      contactGroups: CONTACT_GROUPS,
      assignedIds: ["gone", "also-gone"],
      defaultContactGroupId: "default",
    });
    assert.deepEqual(
      resolved.map((g) => g.id),
      ["default"],
    );
  });

  it("returns [] when every assigned id is stale and the default is also missing", () => {
    const resolved = api.resolveContactGroupsForAsset({
      contactGroups: CONTACT_GROUPS,
      assignedIds: ["gone"],
      defaultContactGroupId: "not-in-json",
    });
    assert.deepEqual(resolved, []);
  });

  it("does not use a singular contact_group_id argument", () => {
    const resolved = api.resolveContactGroupsForAsset({
      contactGroups: CONTACT_GROUPS,
      assignedIds: [],
      defaultContactGroupId: "default",
      contactGroupId: "a",
      contact_group_id: "b",
    });
    assert.deepEqual(
      resolved.map((g) => g.id),
      ["default"],
    );
  });
});

describe("effectiveThresholds and window union", () => {
  it("uses group thresholds when they are in range, else workspace", () => {
    assert.deepEqual(
      api.effectiveThresholds(GROUP_A, WORKSPACE_THRESHOLDS),
      [14, 7],
    );
    assert.deepEqual(
      api.effectiveThresholds(GROUP_DEFAULT, WORKSPACE_THRESHOLDS),
      WORKSPACE_THRESHOLDS,
    );
    assert.deepEqual(
      api.effectiveThresholds({ thresholds: [9999] }, WORKSPACE_THRESHOLDS),
      WORKSPACE_THRESHOLDS,
    );
  });

  it("filters groups that fire for a given window", () => {
    const groups = [GROUP_A, GROUP_B, GROUP_DEFAULT];
    const atSeven = api.unionGroupsForThresholdWindow(
      groups,
      WORKSPACE_THRESHOLDS,
      7,
    );
    assert.deepEqual(
      atSeven.map((g) => g.id),
      ["a", "default"],
    );
    assert.equal(
      api.groupFiresForWindow(GROUP_B, WORKSPACE_THRESHOLDS, 7),
      false,
    );
    assert.equal(
      api.groupFiresForWindow(GROUP_B, WORKSPACE_THRESHOLDS, 30),
      true,
    );
  });
});

describe("dedupeNormalizedDestinations", () => {
  it("lowercases emails and uniques by trimmed value", () => {
    assert.deepEqual(
      api.dedupeNormalizedDestinations(
        [" Alice@Example.com ", "alice@example.com", "", "bob@example.com"],
        "email",
      ),
      ["alice@example.com", "bob@example.com"],
    );
  });

  it("uniques phones and webhook URLs without lowercasing", () => {
    assert.deepEqual(
      api.dedupeNormalizedDestinations([" +15551212 ", "+15551212"], "phone"),
      ["+15551212"],
    );
    assert.deepEqual(
      api.dedupeNormalizedDestinations(
        [" https://hooks.example/A ", "https://hooks.example/A"],
        "webhook",
      ),
      ["https://hooks.example/A"],
    );
  });
});

describe("worker ESM matches API CJS", () => {
  it("resolves the same groups, canonical id, and destinations", async () => {
    const worker = await loadWorkerContactGroups();
    const cases = [
      { assignedIds: [], defaultContactGroupId: "default" },
      { assignedIds: ["b", "missing", "a"], defaultContactGroupId: "default" },
      { assignedIds: ["gone"], defaultContactGroupId: "default" },
      { assignedIds: ["gone"], defaultContactGroupId: null },
    ];
    for (const sample of cases) {
      const apiIds = api
        .resolveContactGroupsForAsset({
          contactGroups: CONTACT_GROUPS,
          ...sample,
        })
        .map((g) => g.id);
      const workerIds = worker
        .resolveContactGroupsForAsset({
          contactGroups: CONTACT_GROUPS,
          ...sample,
        })
        .map((g) => g.id);
      assert.deepEqual(workerIds, apiIds);
    }

    const ids = ["z", "a", "a", "m"];
    assert.equal(
      worker.canonicalLegacyContactGroupId(ids),
      api.canonicalLegacyContactGroupId(ids),
    );
    assert.deepEqual(
      worker.normalizeAssignedGroupIds(ids),
      api.normalizeAssignedGroupIds(ids),
    );
    assert.deepEqual(
      worker.dedupeNormalizedDestinations(["A@X.com", "a@x.com"], "email"),
      api.dedupeNormalizedDestinations(["A@X.com", "a@x.com"], "email"),
    );
    assert.deepEqual(
      worker.unionEffectiveThresholds([GROUP_A, GROUP_B], WORKSPACE_THRESHOLDS),
      api.unionEffectiveThresholds([GROUP_A, GROUP_B], WORKSPACE_THRESHOLDS),
    );
    assert.deepEqual(
      worker.unionContactIds(
        [
          { email_contact_ids: ["u1", "u2"] },
          { email_contact_ids: ["u2", "u3"] },
        ],
        "email_contact_ids",
      ),
      api.unionContactIds(
        [
          { email_contact_ids: ["u1", "u2"] },
          { email_contact_ids: ["u2", "u3"] },
        ],
        "email_contact_ids",
      ),
    );
    assert.deepEqual(
      worker.deliveryChannelsFromEligibleGroups(
        [
          {
            email_contact_ids: ["u1"],
            whatsapp_contact_ids: ["+1"],
          },
        ],
        { alertKey: "expires:1:7" },
      ),
      api.deliveryChannelsFromEligibleGroups(
        [
          {
            email_contact_ids: ["u1"],
            whatsapp_contact_ids: ["+1"],
          },
        ],
        { alertKey: "expires:1:7" },
      ),
    );
  });
});

describe("membershipAfterContactGroupMove", () => {
  it("replaces the moved id and keeps the rest", () => {
    assert.deepEqual(
      api.membershipAfterContactGroupMove(["a", "c"], "a", "b"),
      ["b", "c"],
    );
  });

  it("is a no-op add when the asset was only on the source group", () => {
    assert.deepEqual(api.membershipAfterContactGroupMove(["a"], "a", "b"), [
      "b",
    ]);
  });

  it("treats an empty join (legacy singular-only) as just the destination", () => {
    assert.deepEqual(api.membershipAfterContactGroupMove([], "a", "b"), ["b"]);
  });
});

describe("interpretContactGroupWrite", () => {
  it("lets the plural field win when both are present", () => {
    assert.deepEqual(
      api.interpretContactGroupWrite({
        contactGroupIds: ["b", "a", "b"],
        contactGroupId: "ignored",
        hasPlural: true,
        hasSingular: true,
      }),
      { action: "set", ids: ["a", "b"] },
    );
  });

  it("rejects a present non-array plural field", () => {
    assert.throws(
      () =>
        api.interpretContactGroupWrite({
          contactGroupIds: "ops",
          contactGroupId: "keep-me",
          hasPlural: true,
          hasSingular: true,
        }),
      (err) => {
        assert.equal(err.code, "VALIDATION_ERROR");
        assert.match(
          err.message,
          /contact_group_ids must be an array of strings/,
        );
        return true;
      },
    );
  });

  it("rejects non-string members in the plural field", () => {
    assert.throws(
      () =>
        api.interpretContactGroupWrite({
          contactGroupIds: ["ops", 123],
          hasPlural: true,
          hasSingular: false,
        }),
      (err) => {
        assert.equal(err.code, "VALIDATION_ERROR");
        return true;
      },
    );
  });

  it("treats an empty plural array as a clear", () => {
    assert.deepEqual(
      api.interpretContactGroupWrite({
        contactGroupIds: [],
        contactGroupId: "keep-me",
        hasPlural: true,
        hasSingular: true,
      }),
      { action: "set", ids: [] },
    );
  });

  it("omits membership when both fields are absent", () => {
    assert.deepEqual(
      api.interpretContactGroupWrite({
        contactGroupIds: undefined,
        contactGroupId: undefined,
        hasPlural: false,
        hasSingular: false,
      }),
      { action: "omit" },
    );
  });

  it("clears membership when the singular field is null or empty", () => {
    assert.deepEqual(
      api.interpretContactGroupWrite({
        contactGroupIds: undefined,
        contactGroupId: null,
        hasPlural: false,
        hasSingular: true,
      }),
      { action: "set", ids: [] },
    );
    assert.deepEqual(
      api.interpretContactGroupWrite({
        contactGroupIds: undefined,
        contactGroupId: "  ",
        hasPlural: false,
        hasSingular: true,
      }),
      { action: "set", ids: [] },
    );
  });

  it("sets a single id from the singular field", () => {
    assert.deepEqual(
      api.interpretContactGroupWrite({
        contactGroupIds: undefined,
        contactGroupId: " g1 ",
        hasPlural: false,
        hasSingular: true,
      }),
      { action: "set", ids: ["g1"] },
    );
  });
});

describe("assertContactGroupIds", () => {
  it("treats an empty list as success without querying", async () => {
    const { state, client } = createMockClient(() => {
      throw new Error("should not query");
    });
    await assertContactGroupIds(client, "ws-1", []);
    assert.equal(state.queries.length, 0);
  });

  it("throws VALIDATION_ERROR when a group id is missing from JSON", async () => {
    const { client } = createMockClient(() => ({
      rows: [{ contact_groups: CONTACT_GROUPS }],
    }));
    await assert.rejects(
      () => assertContactGroupIds(client, "ws-1", ["a", "nope"]),
      (err) => {
        assert.equal(err.code, "VALIDATION_ERROR");
        assert.equal(err.message, "Invalid contact_group_id for workspace");
        return true;
      },
    );
  });

  it("accepts ids that exist in the workspace JSON array", async () => {
    const { client } = createMockClient(() => ({
      rows: [{ contact_groups: CONTACT_GROUPS }],
    }));
    await assertContactGroupIds(client, "ws-1", ["b", "a"]);
  });
});

describe("replaceAssetContactGroups", () => {
  it("deletes, inserts remaining ids, and mirrors the lex-smallest singular id", async () => {
    const { state, client } = createMockClient(() => ({ rows: [] }));
    await replaceAssetContactGroups({
      client,
      kind: "token",
      assetId: 42,
      workspaceId: "ws-1",
      ids: ["b", "a", "a"],
    });
    assert.equal(state.queries.length, 3);
    assert.match(state.queries[0].text, /DELETE FROM token_contact_groups/);
    assert.deepEqual(state.queries[0].params, [42, "ws-1"]);
    assert.match(state.queries[1].text, /INSERT INTO token_contact_groups/);
    assert.deepEqual(state.queries[1].params, [42, "ws-1", ["a", "b"]]);
    assert.match(state.queries[2].text, /UPDATE tokens/);
    assert.deepEqual(state.queries[2].params, ["a", 42, "ws-1"]);
  });

  it("skips insert and nulls the singular column when ids are empty", async () => {
    const { state, client } = createMockClient(() => ({ rows: [] }));
    await replaceAssetContactGroups({
      client,
      kind: "agent",
      assetId: "agent-1",
      workspaceId: "ws-1",
      ids: [],
    });
    assert.equal(state.queries.length, 2);
    assert.match(
      state.queries[0].text,
      /DELETE FROM certops_agent_contact_groups/,
    );
    assert.match(state.queries[1].text, /UPDATE certops_agents/);
    assert.deepEqual(state.queries[1].params, [null, "agent-1", "ws-1"]);
  });

  it("loadAssignedGroupIds returns lex-sorted join ids", async () => {
    const { client } = createMockClient(() => ({
      rows: [{ contact_group_id: "b" }, { contact_group_id: "a" }],
    }));
    const ids = await loadAssignedGroupIds({
      client,
      kind: "token",
      assetId: 9,
      workspaceId: "ws-1",
    });
    assert.deepEqual(ids, ["a", "b"]);
  });

  it("mirrors the same canonical singular id when assigned ids are reordered", async () => {
    const first = createMockClient(() => ({ rows: [] }));
    await replaceAssetContactGroups({
      client: first.client,
      kind: "token",
      assetId: 1,
      workspaceId: "ws-1",
      ids: ["ops", "alerts", "sec"],
    });
    const second = createMockClient(() => ({ rows: [] }));
    await replaceAssetContactGroups({
      client: second.client,
      kind: "token",
      assetId: 1,
      workspaceId: "ws-1",
      ids: ["sec", "alerts", "ops"],
    });
    assert.deepEqual(first.state.queries[2].params[0], "alerts");
    assert.deepEqual(second.state.queries[2].params[0], "alerts");
    assert.deepEqual(
      first.state.queries[1].params[2],
      second.state.queries[1].params[2],
    );
  });

  it("loadAssignedGroupIdsForAssets batches one query and fills missing assets with []", async () => {
    const { state, client } = createMockClient(() => ({
      rows: [
        { asset_id: 1, contact_group_id: "b" },
        { asset_id: 1, contact_group_id: "a" },
        { asset_id: 3, contact_group_id: "z" },
      ],
    }));
    const assigned = await loadAssignedGroupIdsForAssets({
      client,
      kind: "token",
      assetIds: [1, 2, 1, 3],
      workspaceId: "ws-1",
    });
    assert.equal(state.queries.length, 1);
    assert.match(state.queries[0].text, /ANY\(\$2::int\[\]\)/);
    assert.deepEqual(assigned.get("1"), ["a", "b"]);
    assert.deepEqual(assigned.get("2"), []);
    assert.deepEqual(assigned.get("3"), ["z"]);
  });
});

describe("queue union vs delivery re-filter", () => {
  const groupA = {
    id: "a",
    name: "Alpha",
    thresholds: [30, 7],
    email_contact_ids: ["alice", "bob"],
  };
  const groupB = {
    id: "b",
    name: "Beta",
    thresholds: [14],
    email_contact_ids: ["alice", "carol"],
  };
  const both = [groupA, groupB];

  it("queues the union of A={30,7} and B={14} and delivery at 14 keeps only B", () => {
    const queued = api.unionEffectiveThresholds(both, WORKSPACE_THRESHOLDS);
    assert.deepEqual(
      [...queued].sort((left, right) => left - right),
      [7, 14, 30],
    );
    assert.deepEqual(
      api
        .unionGroupsForThresholdWindow(both, WORKSPACE_THRESHOLDS, 30)
        .map((g) => g.id),
      ["a"],
    );
    assert.deepEqual(
      api
        .unionGroupsForThresholdWindow(both, WORKSPACE_THRESHOLDS, 14)
        .map((g) => g.id),
      ["b"],
    );
    assert.deepEqual(
      api
        .unionGroupsForThresholdWindow(both, WORKSPACE_THRESHOLDS, 7)
        .map((g) => g.id),
      ["a"],
    );
  });

  it("dedupes overlapping destinations across groups that share a window", () => {
    const bothAtFourteen = [{ ...groupA, thresholds: [14] }, groupB];
    const eligible = api.unionGroupsForThresholdWindow(
      bothAtFourteen,
      WORKSPACE_THRESHOLDS,
      14,
    );
    assert.deepEqual(api.unionContactIds(eligible, "email_contact_ids"), [
      "alice",
      "bob",
      "carol",
    ]);
  });

  it("drops the queued window when assignment no longer includes a firing group", () => {
    const queued = api.resolveContactGroupsForAsset({
      contactGroups: both,
      assignedIds: ["a", "b"],
      defaultContactGroupId: "default",
    });
    assert.deepEqual(
      api
        .unionGroupsForThresholdWindow(queued, WORKSPACE_THRESHOLDS, 14)
        .map((g) => g.id),
      ["b"],
    );

    const afterReassign = api.resolveContactGroupsForAsset({
      contactGroups: both,
      assignedIds: ["a"],
      defaultContactGroupId: "default",
    });
    assert.deepEqual(
      api.unionGroupsForThresholdWindow(
        afterReassign,
        WORKSPACE_THRESHOLDS,
        14,
      ),
      [],
    );
  });
});

describe("deliveryChannelsFromEligibleGroups", () => {
  const emailGroup = {
    id: "email",
    email_contact_ids: ["u1"],
  };
  const whatsappGroup = {
    id: "wa",
    whatsapp_contact_ids: ["+15551212"],
  };

  it("derives WhatsApp after a queued email-only snapshot would have dropped it", () => {
    const queuedChannels = ["email"];
    const live = api.deliveryChannelsFromEligibleGroups([whatsappGroup], {
      alertKey: "expires:42:14",
    });
    assert.deepEqual(live, ["whatsapp"]);
    assert.equal(queuedChannels.filter((ch) => live.includes(ch)).length, 0);
  });

  it("does not add WhatsApp for renewal or agent-health alerts", () => {
    assert.deepEqual(
      api.deliveryChannelsFromEligibleGroups([whatsappGroup], {
        alertKey: "cert_renewal_failed:99",
      }),
      [],
    );
    assert.deepEqual(
      api.deliveryChannelsFromEligibleGroups([whatsappGroup], {
        alertKey: "agent_health:abc",
      }),
      [],
    );
    assert.deepEqual(
      api.deliveryChannelsFromEligibleGroups([emailGroup, whatsappGroup], {
        alertKey: "endpoint_health:7",
      }),
      ["email", "whatsapp"],
    );
  });
});
