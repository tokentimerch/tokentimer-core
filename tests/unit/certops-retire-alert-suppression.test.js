"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const { suppressPendingRetiredCertificateAlerts } = require(
  path.resolve(__dirname, "../../apps/api/services/certops/inventory.js"),
);
const { RETIRED_CERT_UNSENT_ALERT_STATUSES } = require(
  path.resolve(
    __dirname,
    "../../apps/api/src/shared/retiredCertificateAlerts.js",
  ),
);

const WORKSPACE_A = "11111111-1111-4111-8111-111111111111";
const CERT_A = "22222222-2222-4222-8222-222222222222";

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

function assertCoversEveryUnsentStatus(sql) {
  for (const status of RETIRED_CERT_UNSENT_ALERT_STATUSES) {
    assert.match(
      sql,
      new RegExp(`'${status}'`),
      `cleanup SQL must include unsent status ${status}`,
    );
  }
  assert.doesNotMatch(sql, /'sent'/);
}

describe("suppressPendingRetiredCertificateAlerts", () => {
  it("does nothing when there is no certificate and expiry is not being suppressed", async () => {
    const { state, client } = createMockClient(() => {
      throw new Error("unexpected query");
    });
    const outcome = await suppressPendingRetiredCertificateAlerts(client, {
      tokenId: 42,
    });
    assert.deepEqual(outcome, { deleted: 0 });
    assert.equal(state.queries.length, 0);
  });

  it("deletes this certificate's renewal-failure alerts while a sibling keeps the token live", async () => {
    const { state, client } = createMockClient((sql) => {
      if (sql.includes("DELETE FROM alert_queue aq")) {
        return { rowCount: 2, rows: [] };
      }
      throw new Error(`unexpected query: ${sql}`);
    });
    const outcome = await suppressPendingRetiredCertificateAlerts(client, {
      tokenId: 42,
      certificateId: CERT_A,
      workspaceId: WORKSPACE_A,
      suppressTokenExpiry: false,
    });
    assert.deepEqual(outcome, { deleted: 2 });
    assert.equal(state.queries.length, 1);
    const del = state.queries[0];
    assert.match(del.text, /USING certificate_jobs cj/);
    assert.match(del.text, /cert_renewal_failed:/);
    assert.match(del.text, /cj\.subject_id = \$1::text/);
    assert.equal(del.params[0], CERT_A);
    assert.equal(del.params[1], WORKSPACE_A);
    assert.doesNotMatch(del.text, /token_expiry:/);
    assertCoversEveryUnsentStatus(del.text);
  });

  it("also deletes token expiry alerts once no live sibling remains", async () => {
    const { state, client } = createMockClient((sql) => {
      if (sql.includes("USING certificate_jobs")) {
        return { rowCount: 1, rows: [] };
      }
      if (sql.includes("DELETE FROM alert_queue") && sql.includes("token_id")) {
        return { rowCount: 4, rows: [] };
      }
      throw new Error(`unexpected query: ${sql}`);
    });
    const outcome = await suppressPendingRetiredCertificateAlerts(client, {
      tokenId: 42,
      certificateId: CERT_A,
      workspaceId: WORKSPACE_A,
      suppressTokenExpiry: true,
    });
    assert.deepEqual(outcome, { deleted: 5 });
    const expiry = state.queries.find((q) =>
      q.text.includes("alert_key LIKE 'token_expiry:%'"),
    );
    assert.ok(expiry);
    assert.equal(expiry.params[0], 42);
    assert.doesNotMatch(expiry.text, /cert_renewal_failed:/);
    assertCoversEveryUnsentStatus(expiry.text);
  });
});
