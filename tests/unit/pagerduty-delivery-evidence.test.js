"use strict";
const { before, describe, it } = require("node:test");
const assert = require("node:assert/strict");
let evidence, identity;
const workspaceId = "workspace-a";
const pd = {
  name: "pd",
  kind: "pagerduty",
  url: "https://events.pagerduty.com/v2/enqueue",
  routingKey: "A".repeat(32),
};
const second = { ...pd, name: "second", routingKey: "B".repeat(32) };
function success(metadata, workspace = workspaceId) {
  return {
    channel: "webhooks",
    status: "success",
    workspace_id: workspace,
    metadata,
  };
}
before(async () => {
  evidence = await import("../../apps/worker/src/shared/deliveryEvidence.js");
  identity =
    await import("../../apps/worker/src/shared/webhookDestinations.js");
});
describe("versioned PagerDuty delivery evidence", () => {
  it("recognizes a URL-only legacy success without inventing correlation", () => {
    const row = success({
      kind: "pagerduty",
      urlHash: evidence.webhookUrlHash(pd),
    });
    assert.equal(
      evidence.webhookDeliveryEvidence(workspaceId, pd, [pd], [row]),
      "legacy_delivered",
    );
    assert.equal(row.metadata.destination_id, undefined);
    assert.equal(row.metadata.dedup_key, undefined);
  });
  it("does not count aliases as independent integrations", () => {
    const row = success(
      { kind: "pagerduty", urlHash: evidence.webhookUrlHash(pd) },
      null,
    );
    assert.equal(
      evidence.webhookDeliveryEvidence(
        workspaceId,
        pd,
        [pd, { ...pd, name: "alias" }],
        [row],
      ),
      "legacy_delivered",
    );
  });
  it("parks ambiguous URL history for every unproven routing key", () => {
    const row = success({
      kind: "pagerduty",
      urlHash: evidence.webhookUrlHash(pd),
    });
    for (const webhook of [pd, second])
      assert.equal(
        evidence.webhookDeliveryEvidence(
          workspaceId,
          webhook,
          [pd, second],
          [row],
        ),
        "legacy_ambiguous",
      );
  });
  it("mixed scoped success and old URL success cannot be reassigned to a second key", () => {
    const rows = [
      success({ kind: "pagerduty", urlHash: evidence.webhookUrlHash(pd) }),
      success({
        kind: "pagerduty",
        destination_id: identity.webhookDestinationId(workspaceId, pd),
      }),
    ];
    assert.equal(
      evidence.webhookDeliveryEvidence(workspaceId, pd, [pd, second], rows),
      "delivered",
    );
    assert.equal(
      evidence.webhookDeliveryEvidence(workspaceId, second, [pd, second], rows),
      "legacy_ambiguous",
    );
  });
  it("only pending independent endpoints remain retryable after partial delivery", () => {
    const other = {
      ...second,
      url: "https://events.eu.pagerduty.com/v2/enqueue",
    };
    const rows = [
      success({ kind: "pagerduty", urlHash: evidence.webhookUrlHash(pd) }),
    ];
    assert.equal(
      evidence.webhookDeliveryEvidence(workspaceId, pd, [pd, other], rows),
      "legacy_delivered",
    );
    assert.equal(
      evidence.webhookDeliveryEvidence(workspaceId, other, [pd, other], rows),
      "pending",
    );
  });
  it("rejects foreign-tenant history and resolution events as trigger evidence", () => {
    const metadata = {
      kind: "pagerduty",
      destination_id: identity.webhookDestinationId(workspaceId, pd),
      urlHash: evidence.webhookUrlHash(pd),
    };
    assert.equal(
      evidence.webhookDeliveryEvidence(
        workspaceId,
        pd,
        [pd],
        [success(metadata, "workspace-b")],
      ),
      "pending",
    );
    assert.equal(
      evidence.webhookDeliveryEvidence(
        workspaceId,
        pd,
        [pd],
        [success({ ...metadata, event_action: "resolve" })],
      ),
      "pending",
    );
  });
  it("preserves URL evidence for non-PagerDuty webhooks", () => {
    const webhook = { kind: "generic", url: "https://example.test/receiver" };
    const rows = [
      success({ kind: "generic", urlHash: evidence.webhookUrlHash(webhook) }),
    ];
    assert.equal(
      evidence.webhookDeliveryEvidence(workspaceId, webhook, [webhook], rows),
      "delivered",
    );
  });
});
describe("recipient aggregate acceptance", () => {
  it("requires every email recipient, using the delivery worker's normalization", () => {
    const rows = [
      {
        channel: "email",
        status: "success",
        metadata: { recipient: "Alice@Example.test" },
      },
    ];
    assert.equal(
      evidence.recipientDeliveryComplete("email", ["alice@example.test"], rows),
      true,
    );
    assert.equal(
      evidence.recipientDeliveryComplete(
        "email",
        ["alice@example.test", "bob@example.test"],
        rows,
      ),
      false,
    );
    assert.equal(evidence.recipientDeliveryComplete("email", [], rows), false);
  });
  it("does not infer WhatsApp success from email or another phone", () => {
    const rows = [
      {
        channel: "email",
        status: "success",
        metadata: { recipient: "+41790000001" },
      },
      {
        channel: "whatsapp",
        status: "success",
        metadata: { recipient: "+41790000002" },
      },
    ];
    assert.equal(
      evidence.recipientDeliveryComplete("whatsapp", ["+41790000001"], rows),
      false,
    );
  });
});
