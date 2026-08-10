"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { pathToFileURL } = require("node:url");

// delivery-worker.js is ESM; dynamic-import it from this CommonJS test file,
// matching the existing certops-worker.test.js convention for the sibling
// worker module.
const deliveryWorkerUrl = pathToFileURL(
  path.join(__dirname, "..", "..", "apps", "worker", "src", "delivery-worker.js"),
).href;

describe("agent_health alert content: impacted-certificate rendering", () => {
  it("renders each impacted certificate with its human-readable renewal-path state label, not the raw wire value", async () => {
    const { _test } = await import(deliveryWorkerUrl);
    const lines = _test.formatImpactedCertificateLines({
      impactedCertificates: [
        { id: "c1", commonName: "api.example.com", renewalPathState: "unavailable" },
        { id: "c2", commonName: "internal.example.com", renewalPathState: "degraded" },
        { id: "c3", commonName: "vpn.example.com", renewalPathState: "unavailable" },
      ],
      extraImpactedCount: 0,
    });
    assert.deepEqual(lines, [
      "- api.example.com \u2014 Renewal path unavailable",
      "- internal.example.com \u2014 Degraded",
      "- vpn.example.com \u2014 Renewal path unavailable",
    ]);
  });

  it("falls back to the raw state string for an unrecognized future state rather than dropping it", async () => {
    const { _test } = await import(deliveryWorkerUrl);
    const lines = _test.formatImpactedCertificateLines({
      impactedCertificates: [
        { id: "c1", commonName: "future.example.com", renewalPathState: "some_future_state" },
      ],
      extraImpactedCount: 0,
    });
    assert.deepEqual(lines, ["- future.example.com \u2014 some_future_state"]);
  });

  it("omits the state suffix entirely when renewalPathState is null (never renders a stray dash)", async () => {
    const { _test } = await import(deliveryWorkerUrl);
    const lines = _test.formatImpactedCertificateLines({
      impactedCertificates: [{ id: "c1", commonName: "no-state.example.com", renewalPathState: null }],
      extraImpactedCount: 0,
    });
    assert.deepEqual(lines, ["- no-state.example.com"]);
  });

  it("appends a capped '+N more' line without an alert storm per certificate", async () => {
    const { _test } = await import(deliveryWorkerUrl);
    const lines = _test.formatImpactedCertificateLines({
      impactedCertificates: [
        { id: "c1", commonName: "api.example.com", renewalPathState: "unavailable" },
      ],
      extraImpactedCount: 3,
    });
    assert.deepEqual(lines, ["- api.example.com \u2014 Renewal path unavailable", "+3 more"]);
  });

  it("returns no lines and no '+N more' when there are no impacted certificates at all", async () => {
    const { _test } = await import(deliveryWorkerUrl);
    const lines = _test.formatImpactedCertificateLines({
      impactedCertificates: [],
      extraImpactedCount: 0,
    });
    assert.deepEqual(lines, []);
  });

  it("getAgentHealthContext derives extraImpactedCount from the total vs. the capped list, matching the queued metadata shape", async () => {
    const { _test } = await import(deliveryWorkerUrl);
    const context = _test.getAgentHealthContext({
      alert_key: "agent_health:agent-row-1:down",
      metadata: {
        agentName: "prod-iis-01",
        lastSeenAt: new Date(Date.now() - 15 * 60 * 1000).toISOString(),
        offlineAfterMs: 600000,
        impactedCertificates: [
          { id: "c1", commonName: "api.example.com", renewalPathState: "unavailable" },
        ],
        impactedCertificateTotalCount: 4,
      },
    });
    assert.equal(context.isDown, true);
    assert.equal(context.impactedTotalCount, 4);
    assert.equal(context.extraImpactedCount, 3);
    assert.equal(context.title, "Agent Down: prod-iis-01");
  });

  it("escapes hostile metadata in HTML email while preserving readable plain text", async () => {
    const { _test } = await import(deliveryWorkerUrl);
    const alert = {
      alert_key: "agent_health:agent-row-1:down",
      metadata: {
        agentName: '<img src=x onerror="boom">',
        hostname: "</td></tr><tr><td>spoof<script>alert(1)</script>",
        platform: "win32 & prod",
        impactedCertificates: [
          {
            id: "c1",
            commonName: '<a href="https://example.invalid">fake login</a>',
            renewalPathState: "unavailable",
          },
        ],
        impactedCertificateTotalCount: 1,
      },
    };
    const message = _test.buildAgentHealthEmailContent(alert);
    assert.ok(!message.html.includes("<img src=x"));
    assert.ok(!message.html.includes("<script>alert(1)</script>"));
    assert.ok(!message.html.includes('<a href="https://example.invalid">'));
    assert.ok(!message.html.includes("</td></tr><tr><td>spoof"));
    assert.match(message.html, /&lt;img src=x onerror=&quot;boom&quot;&gt;/);
    assert.match(
      message.html,
      /&lt;a href=&quot;https:\/\/example\.invalid&quot;&gt;fake login&lt;\/a&gt;/,
    );
    assert.match(
      message.text,
      /<a href="https:\/\/example\.invalid">fake login<\/a>/,
    );
  });

  it("neutralizes mentions and markup for Slack, Discord, and Teams payloads", async () => {
    const { _test } = await import(deliveryWorkerUrl);
    const alert = {
      alert_key: "agent_health:agent-row-1:down",
      metadata: {
        agentName: "@everyone <@U123> *ops*\r\nStatus: RECOVERED",
        hostname: "host_[prod] @channel",
        impactedCertificates: [
          { id: "c1", commonName: "@here <b>svc</b>", renewalPathState: "unavailable" },
        ],
        impactedCertificateTotalCount: 1,
      },
    };
    for (const kind of ["slack", "discord", "teams"]) {
      const payload = _test.buildAgentHealthWebhookPayload(kind, alert);
      const encoded = JSON.stringify(payload);
      assert.doesNotThrow(() => JSON.parse(encoded));
      assert.ok(!encoded.includes("@everyone"), `${kind} broadcast mention`);
      assert.ok(!encoded.includes("@channel"), `${kind} channel mention`);
      assert.ok(!encoded.includes("<@U123>"), `${kind} user mention`);
      assert.ok(!encoded.includes("\\r\\n"), `${kind} line-break injection`);
      if (kind === "slack") {
        const mrkdwnText = [
          payload.text,
          ...payload.blocks
            .filter((block) => block.text?.type === "mrkdwn")
            .map((block) => block.text.text),
        ].join("\n");
        assert.ok(!mrkdwnText.includes("*ops*"), "slack emphasis injection");
      } else {
        assert.ok(!encoded.includes("*ops*"), `${kind} emphasis injection`);
      }
      assert.ok(!encoded.includes("<b>svc</b>"), `${kind} tag/link injection`);
    }
    const discord = _test.buildAgentHealthWebhookPayload("discord", alert);
    assert.deepEqual(discord.allowed_mentions, { parse: [] });
  });
});
