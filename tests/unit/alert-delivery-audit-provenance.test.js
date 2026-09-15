const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

describe("per-alert delivery audit provenance", () => {
  it("persists exact alert ID/key and historical workspace for every delivery lifecycle action", async () => {
    const { _test } = await import("../../apps/worker/src/delivery-worker.js");
    const workspaceId = "00000000-0000-4000-8000-000000000001";
    const alert = { id: 24, alert_key: "endpoint_health:24:down",
      workspace_id: workspaceId };
    const writes = [];
    const client = { query: async (_sql, params) => {
      writes.push(params);
      return { rowCount: 1 };
    } };
    const actions = [
      "ALERT_DELIVERY_DEFERRED",
      "ALERT_PARTIAL_SUCCESS",
      "ALERT_BLOCKED_MAX_ATTEMPTS",
      "ALERT_BLOCKED_WHATSAPP_ERROR",
      "ALERT_RETRY_SCHEDULED",
      "ALERT_SENT",
      "ALERT_SEND_FAILED",
    ];
    for (const action of actions) {
      await _test.writeAlertAudit(client, alert, {
        subjectUserId: 7, action, targetId: 9,
        workspaceId: "00000000-0000-4000-8000-000000000002",
        metadata: { days: 0 },
      });
    }
    assert.equal(writes.length, actions.length);
    for (const [index, params] of writes.entries()) {
      assert.equal(params[2], actions[index]);
      assert.equal(params[7], workspaceId);
      assert.deepEqual(params[6], {
        days: 0, alert_id: 24, alert_key: alert.alert_key,
      });
    }
  });
});
