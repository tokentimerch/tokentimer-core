"use strict";

process.env.WEEKLY_DIGEST_RECIPIENT_KEY =
  process.env.WEEKLY_DIGEST_RECIPIENT_KEY ||
  "tokentimer-test-digest-recipient-key";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { pathToFileURL } = require("node:url");

const digestHref = pathToFileURL(
  path.resolve(
    __dirname,
    "../../apps/worker/src/shared/weeklyDigestRecipients.js",
  ),
).href;

async function loadDigest() {
  return import(digestHref);
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

const TOKEN_X = { id: "X", name: "Token X" };
const TOKEN_Y = { id: "Y", name: "Token Y" };
const TOKEN_Z = { id: "Z", name: "Token Z" };

describe("weekly digest recipient aggregation", () => {
  it("unions Alice tokens across groups A={X,Y} and B={Z} into one email", async () => {
    const { aggregateDigestRecipients } = await loadDigest();
    const rows = aggregateDigestRecipients({
      groups: [
        {
          id: "A",
          weekly_digest_email: true,
          emails: ["Alice@Example.com"],
        },
        {
          id: "B",
          weekly_digest_email: true,
          emails: ["alice@example.com"],
        },
      ],
      tokensByGroupId: {
        A: [TOKEN_X, TOKEN_Y],
        B: [TOKEN_Z],
      },
    });

    assert.equal(rows.length, 1);
    assert.equal(rows[0].channel, "email");
    assert.equal(rows[0].recipientKey, "alice@example.com");
    assert.deepEqual(
      rows[0].tokens.map((t) => t.id),
      ["X", "Y", "Z"],
    );
    assert.deepEqual(rows[0].contributingGroupIds, ["A", "B"]);
  });

  it("does not contribute tokens from a group whose digest email flag is off", async () => {
    const { invertDigestCandidates } = await loadDigest();
    const rows = invertDigestCandidates({
      groupCandidates: [
        {
          group: { id: "A", weekly_digest_email: true },
          tokens: [TOKEN_X, TOKEN_Y],
          emails: ["alice@example.com"],
        },
        {
          group: { id: "B", weekly_digest_email: false },
          tokens: [TOKEN_Z],
          emails: ["alice@example.com"],
        },
      ],
    });

    assert.equal(rows.length, 1);
    assert.deepEqual(
      rows[0].tokens.map((t) => t.id),
      ["X", "Y"],
    );
    assert.deepEqual(rows[0].contributingGroupIds, ["A"]);
  });

  it("collapses two contacts that share an email into one recipient", async () => {
    const { invertDigestCandidates } = await loadDigest();
    const rows = invertDigestCandidates({
      groupCandidates: [
        {
          group: { id: "ops", weekly_digest_email: true },
          tokens: [TOKEN_X],
          emails: ["alice@example.com", "Alice@example.com"],
        },
      ],
    });

    assert.equal(rows.length, 1);
    assert.equal(rows[0].recipientKey, "alice@example.com");
    assert.deepEqual(
      rows[0].tokens.map((t) => t.id),
      ["X"],
    );
  });
});

describe("claimWeeklyDigestRecipient", () => {
  it("uses an atomic INSERT ON CONFLICT claim and returns the row when RETURNING wins", async () => {
    const { claimWeeklyDigestRecipient, hashDigestRecipientKey } =
      await loadDigest();
    const hashed = hashDigestRecipientKey("alice@example.com");
    const claimed = {
      workspace_id: "ws-1",
      channel: "email",
      recipient_key: hashed,
      status: "pending",
    };
    const { state, client } = createMockClient(() => ({ rows: [claimed] }));
    const row = await claimWeeklyDigestRecipient(client, {
      workspaceId: "ws-1",
      weekStartDate: "2026-09-14",
      channel: "email",
      recipientKey: "alice@example.com",
      tokensCount: 3,
      leaseMs: 60000,
    });

    assert.equal(row, claimed);
    assert.equal(state.queries.length, 1);
    const sql = state.queries[0].text;
    assert.match(sql, /INSERT INTO weekly_digest_recipient_log/);
    assert.match(
      sql,
      /ON CONFLICT \(workspace_id, week_start_date, channel, recipient_key\)/,
    );
    assert.match(sql, /WHERE weekly_digest_recipient_log\.status <> 'sent'/);
    assert.match(
      sql,
      /attempt_count = weekly_digest_recipient_log\.attempt_count \+ 1/,
    );
    assert.match(sql, /lease_expires_at < NOW\(\)/);
    assert.match(sql, /RETURNING \*/);
    assert.equal(hashed.length, 64);
    assert.notEqual(hashed, "alice@example.com");
    assert.deepEqual(state.queries[0].params, [
      "ws-1",
      "2026-09-14",
      "email",
      hashed,
      60000,
      3,
    ]);
  });

  it("returns null when RETURNING is empty so the caller does not send", async () => {
    const { claimWeeklyDigestRecipient } = await loadDigest();
    const { client } = createMockClient(() => ({ rows: [] }));
    const row = await claimWeeklyDigestRecipient(client, {
      workspaceId: "ws-1",
      weekStartDate: "2026-09-14",
      channel: "email",
      recipientKey: "alice@example.com",
      tokensCount: 1,
      leaseMs: 1000,
    });
    assert.equal(row, null);
  });

  it("marks a pending row sent", async () => {
    const { markWeeklyDigestRecipientSent, hashDigestRecipientKey } =
      await loadDigest();
    const { state, client } = createMockClient(() => ({
      rows: [{ status: "sent" }],
    }));
    const row = await markWeeklyDigestRecipientSent(client, {
      workspaceId: "ws-1",
      weekStartDate: "2026-09-14",
      channel: "email",
      recipientKey: "alice@example.com",
    });
    assert.equal(row.status, "sent");
    assert.match(state.queries[0].text, /SET status = 'sent'/);
    assert.match(state.queries[0].text, /status = 'pending'/);
    assert.equal(
      state.queries[0].params[3],
      hashDigestRecipientKey("alice@example.com"),
    );
  });
});

describe("weeklyDigestWhatsAppIdempotencyKey", () => {
  it("keys by workspace, week, and hashed phone with no group id", async () => {
    const { weeklyDigestWhatsAppIdempotencyKey, hashDigestRecipientKey } =
      await loadDigest();
    const hashed = hashDigestRecipientKey("+15551212");
    assert.equal(
      weeklyDigestWhatsAppIdempotencyKey({
        workspaceId: "ws-1",
        weekStartDate: "2026-09-14",
        phone: "+15551212",
      }),
      `weekly-digest:ws-1:2026-09-14:whatsapp:${hashed}`,
    );
    assert.doesNotMatch(
      weeklyDigestWhatsAppIdempotencyKey({
        workspaceId: "ws-1",
        weekStartDate: "2026-09-14",
        phone: "+15551212",
      }),
      /\+15551212/,
    );
  });
});
