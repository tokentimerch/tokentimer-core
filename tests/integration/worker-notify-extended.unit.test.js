const { expect } = require("chai");
const path = require("path");
const { pathToFileURL } = require("url");

async function importFresh(relativePath) {
  const abs = path.join(__dirname, "..", "..", relativePath);
  const href = `${pathToFileURL(abs).href}?t=${Date.now()}-${Math.random()}`;
  return import(href);
}

describe("Worker notify extended unit coverage", () => {
  it("formats webhook payloads for generic/slack/discord/teams/pagerduty", async () => {
    const webhooks = await importFresh("apps/worker/src/notify/webhooks.js");
    const tokenData = {
      token_id: 1,
      name: "Test Token",
      expiration: "2026-12-01",
      daysLeft: 3,
      type: "api",
      renewal_url: "https://renew.local",
    };

    const genericPayload = webhooks.formatPayload(
      "generic",
      "message",
      tokenData,
      {
        severity: "warning",
        title: "Alert",
      },
    );
    const slackPayload = webhooks.formatPayload("slack", "message", tokenData, {
      severity: "critical",
      title: "Alert",
    });
    const discordPayload = webhooks.formatPayload(
      "discord",
      "message",
      tokenData,
      {
        severity: "error",
      },
    );
    const teamsPayload = webhooks.formatPayload("teams", "message", tokenData, {
      severity: "info",
    });
    const pagerdutyPayload = webhooks.formatPayload(
      "pagerduty",
      "message",
      tokenData,
      {
        severity: "critical",
      },
    );

    expect(genericPayload).to.have.property("text");
    expect(genericPayload).to.have.property("content");
    expect(slackPayload).to.have.property("blocks");
    expect(discordPayload).to.have.property("embeds");
    expect(teamsPayload).to.have.property("@type");
    expect(pagerdutyPayload).to.have.property("event_action");
    expect(pagerdutyPayload.payload).to.have.property("severity", "critical");
  });

  it("postJson rejects provider hosts not in allowlist", async () => {
    process.env.NODE_ENV = "test";
    delete process.env.WEBHOOK_ALLOW_ALL_HOSTS;
    delete process.env.WEBHOOK_PROVIDER_HOSTS;
    delete process.env.WEBHOOK_EXTRA_PROVIDER_HOSTS;

    const webhooks = await importFresh("apps/worker/src/notify/webhooks.js");
    const result = await webhooks.postJson(
      "https://example.com/hook",
      { hello: "world" },
      "slack",
    );
    expect(result.success).to.equal(false);
    expect(String(result.error)).to.match(/not allowed/i);
  });

  it("postJson test mode returns deterministic success/failure for provider hosts", async () => {
    process.env.NODE_ENV = "test";
    const webhooks = await importFresh("apps/worker/src/notify/webhooks.js");

    const ok = await webhooks.postJson(
      "https://hooks.slack.com/services/__ok__",
      { msg: "ok" },
      "slack",
    );
    const fail = await webhooks.postJson(
      "https://hooks.slack.com/services/__fail__",
      { msg: "fail" },
      "slack",
    );

    expect(ok.success).to.equal(true);
    expect(fail.success).to.equal(false);
    expect(String(fail.error)).to.match(/TEST_MODE_WEBHOOK_FAILURE/);
  });

  it("sendEmailNotification short-circuits in test mode", async () => {
    process.env.NODE_ENV = "test";
    const email = await importFresh("apps/worker/src/notify/email.js");
    const result = await email.sendEmailNotification({
      to: "dev@example.com",
      subject: "Subject",
      text: "Text",
      html: "<p>HTML</p>",
    });
    expect(result).to.deep.equal({ success: true });
  });

  it("generateEmailTemplate returns both html and text content", async () => {
    const email = await importFresh("apps/worker/src/notify/email.js");
    const out = email.generateEmailTemplate({
      title: "Worker email",
      greeting: "Hi",
      content: "<p>Body</p>",
      buttonText: "Open",
      buttonUrl: "https://example.com",
      footerNote: "Footer",
      plainTextContent: "Body plain",
    });
    expect(out).to.have.property("html");
    expect(out).to.have.property("text");
    expect(String(out.html)).to.include("Worker email");
    expect(String(out.text)).to.include("Body plain");
  });
});
