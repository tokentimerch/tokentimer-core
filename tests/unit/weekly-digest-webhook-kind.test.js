"use strict";
const { it } = require("node:test");
const assert = require("node:assert/strict");
const { pathToFileURL } = require("node:url");
const path = require("node:path");

it("preserves the configured webhook kind for weekly digests", async () => {
  const { deliverRecipientDigest } = await import(pathToFileURL(path.resolve(__dirname, "../../apps/worker/src/weekly-digest.js")).href);
  const url = "https://example.office.com/webhook";
  for (const kind of ["generic", "teams"]) {
    let sent;
    await deliverRecipientDigest({
      row: { channel: "webhook", recipientKey: url, tokens: [] },
      ws: { workspace_id: "test", workspace_name: "Test" },
      weekStartDate: "2026-01-05", groupNames: [],
      phoneNameByKey: new Map(), webhookByUrl: new Map([[url, { url, kind }]]),
      postWebhook: async (destination, body, selectedKind) => { sent = { destination, body, selectedKind }; return { success: true }; },
    });
    assert.equal(sent.selectedKind, kind);
    assert.equal(sent.destination, url);
    if (kind === "generic") assert.equal(sent.body.type, "weekly_digest");
    else assert.equal(sent.body.attachments[0].content.type, "AdaptiveCard");
  }
});
