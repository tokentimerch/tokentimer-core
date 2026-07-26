"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  OUTBOX_EVENT_TYPES,
  enqueueOutboxEvent,
} = require(
  path.resolve(__dirname, "../../apps/api/services/certops/outbox.js"),
);

const WORKSPACE_A = "11111111-1111-4111-8111-111111111111";

function createClient({ conflict = false } = {}) {
  const state = { queries: [] };
  return {
    state,
    query: async (text, params) => {
      const sql = typeof text === "string" ? text : text?.text || "";
      state.queries.push({ text: sql, params });
      if (conflict) return { rows: [] };
      return { rows: [{ id: "outbox-1" }] };
    },
  };
}

const SYNTHETIC_PRIVATE_KEY_PEM = [
  "-----BEGIN PRIVATE KEY-----",
  "MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEA",
  "-----END PRIVATE KEY-----",
].join("\n");

describe("certops outbox enqueueOutboxEvent", () => {
  it("inserts the intent with ON CONFLICT DO NOTHING for idempotency", async () => {
    const client = createClient();
    const outcome = await enqueueOutboxEvent({
      client,
      workspaceId: WORKSPACE_A,
      eventType: OUTBOX_EVENT_TYPES.RENEWAL_ALERT_REQUESTED,
      dedupeKey: "job-1",
      payload: { jobId: "job-1", operation: "renew" },
    });

    assert.equal(outcome.enqueued, true);
    assert.equal(outcome.id, "outbox-1");
    const insert = client.state.queries[0];
    assert.match(insert.text, /INSERT INTO certops_outbox/);
    assert.match(insert.text, /ON CONFLICT \(workspace_id, event_type, dedupe_key\) DO NOTHING/);
    assert.equal(insert.params[0], WORKSPACE_A);
    assert.equal(insert.params[1], "renewal_alert_requested");
    assert.equal(insert.params[2], "job-1");
  });

  it("reports enqueued=false when the intent already exists, without throwing", async () => {
    const client = createClient({ conflict: true });
    const outcome = await enqueueOutboxEvent({
      client,
      workspaceId: WORKSPACE_A,
      eventType: OUTBOX_EVENT_TYPES.RENEWAL_ALERT_REQUESTED,
      dedupeKey: "job-1",
      payload: { jobId: "job-1" },
    });
    // A retried caller transaction enqueues the same side effect once. That is
    // a success, not an error.
    assert.equal(outcome.enqueued, false);
    assert.equal(outcome.id, null);
  });

  it("requires the caller's transaction client", async () => {
    await assert.rejects(
      enqueueOutboxEvent({
        workspaceId: WORKSPACE_A,
        eventType: OUTBOX_EVENT_TYPES.RENEWAL_ALERT_REQUESTED,
        dedupeKey: "job-1",
      }),
      /CERTOPS_OUTBOX_NO_CLIENT|transaction client/,
    );
  });

  it("rejects an unknown event type", async () => {
    await assert.rejects(
      enqueueOutboxEvent({
        client: createClient(),
        workspaceId: WORKSPACE_A,
        eventType: "arbitrary_event",
        dedupeKey: "job-1",
      }),
      (err) => {
        assert.equal(err.code, "CERTOPS_OUTBOX_UNKNOWN_EVENT_TYPE");
        return true;
      },
    );
  });

  it("rejects a payload field outside the per-event allowlist", async () => {
    await assert.rejects(
      enqueueOutboxEvent({
        client: createClient(),
        workspaceId: WORKSPACE_A,
        eventType: OUTBOX_EVENT_TYPES.RENEWAL_ALERT_REQUESTED,
        dedupeKey: "job-1",
        payload: { jobId: "job-1", certificatePem: "whatever" },
      }),
      /not permitted/,
    );
  });

  it("rejects secret material even in an allowed field", async () => {
    await assert.rejects(
      enqueueOutboxEvent({
        client: createClient(),
        workspaceId: WORKSPACE_A,
        eventType: OUTBOX_EVENT_TYPES.RENEWAL_ALERT_REQUESTED,
        dedupeKey: "job-1",
        payload: { jobId: "job-1", errorCode: SYNTHETIC_PRIVATE_KEY_PEM },
      }),
      (err) => {
        assert.equal(err.code, "CERTOPS_OUTBOX_SECRET_MATERIAL");
        return true;
      },
    );
  });

  it("rejects a missing or unbounded dedupe key", async () => {
    await assert.rejects(
      enqueueOutboxEvent({
        client: createClient(),
        workspaceId: WORKSPACE_A,
        eventType: OUTBOX_EVENT_TYPES.RENEWAL_ALERT_REQUESTED,
        dedupeKey: "   ",
      }),
      /dedupeKey/,
    );
    await assert.rejects(
      enqueueOutboxEvent({
        client: createClient(),
        workspaceId: WORKSPACE_A,
        eventType: OUTBOX_EVENT_TYPES.RENEWAL_ALERT_REQUESTED,
        dedupeKey: "x".repeat(257),
      }),
      /dedupeKey/,
    );
  });

  it("rejects a non-scalar payload value", async () => {
    await assert.rejects(
      enqueueOutboxEvent({
        client: createClient(),
        workspaceId: WORKSPACE_A,
        eventType: OUTBOX_EVENT_TYPES.RENEWAL_ALERT_REQUESTED,
        dedupeKey: "job-1",
        payload: { jobId: { nested: true } },
      }),
      /must be a scalar/,
    );
  });
});
