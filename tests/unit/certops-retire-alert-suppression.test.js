"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const { suppressPendingRetiredCertificateAlerts } = require(
  path.resolve(__dirname, "../../apps/api/services/certops/inventory.js"),
);

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

describe("suppressPendingRetiredCertificateAlerts", () => {
  it("does nothing when there is no token", async () => {
    const { state, client } = createMockClient(() => {
      throw new Error("unexpected query");
    });
    const outcome = await suppressPendingRetiredCertificateAlerts(client, {
      tokenId: null,
    });
    assert.deepEqual(outcome, { deleted: 0, reason: "no_token" });
    assert.equal(state.queries.length, 0);
  });

  it("deletes undelivered expiry and renewal-failure alerts", async () => {
    const { state, client } = createMockClient((sql) => {
      if (sql.includes("DELETE FROM alert_queue")) {
        return { rowCount: 3, rows: [] };
      }
      throw new Error(`unexpected query: ${sql}`);
    });
    const outcome = await suppressPendingRetiredCertificateAlerts(client, {
      tokenId: 42,
    });
    assert.deepEqual(outcome, { deleted: 3 });
    const del = state.queries.find((q) =>
      q.text.includes("DELETE FROM alert_queue"),
    );
    assert.ok(del);
    assert.equal(del.params[0], 42);
    assert.match(del.text, /token_expiry:%/);
    assert.match(del.text, /cert_renewal_failed:%/);
    assert.match(del.text, /status IN \('pending', 'failed', 'partial', 'blocked'\)/);
  });
});
