"use strict";

const { it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { pathToFileURL } = require("node:url");

it("normalizes explicit webhook kinds and detects generic provider hosts", async () => {
  const { resolveWebhookProviderKind } = await import(
    pathToFileURL(
      path.join(
        __dirname,
        "..",
        "..",
        "apps",
        "worker",
        "src",
        "shared",
        "webhookProviderKind.js",
      ),
    ).href
  );

  assert.equal(
    resolveWebhookProviderKind({
      kind: " Slack ",
      url: "https://hooks.slack.com/services/x",
    }),
    "slack",
  );
  assert.equal(
    resolveWebhookProviderKind({
      kind: "TEAMS",
      url: "https://example.environment.api.powerplatform.com/hook",
    }),
    "teams",
  );
  assert.equal(
    resolveWebhookProviderKind({
      kind: "generic",
      url: "https://discord.com/api/webhooks/x",
    }),
    "discord",
  );
  assert.equal(
    resolveWebhookProviderKind({ url: "https://custom.example.test/hook" }),
    "generic",
  );
});
