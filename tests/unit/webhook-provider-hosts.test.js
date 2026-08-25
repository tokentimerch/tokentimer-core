"use strict";

const { describe, it, afterEach } = require("node:test");
const assert = require("node:assert");

const {
  DEFAULT_WEBHOOK_PROVIDER_HOSTS,
  getWebhookProviderHosts,
  allowAllWebhookHosts,
  webhookHostAllowed,
} = require("../../packages/webhook-safety");

const ENV_KEYS = [
  "WEBHOOK_EXTRA_PROVIDER_HOSTS",
  "WEBHOOK_PROVIDER_HOSTS",
  "WEBHOOK_ALLOW_ALL_HOSTS",
];

afterEach(() => {
  for (const key of ENV_KEYS) delete process.env[key];
});

describe("DEFAULT_WEBHOOK_PROVIDER_HOSTS", () => {
  it("includes Slack, Discord, Teams, PagerDuty, and Power Automate hosts", () => {
    assert.ok(DEFAULT_WEBHOOK_PROVIDER_HOSTS.includes("hooks.slack.com"));
    assert.ok(DEFAULT_WEBHOOK_PROVIDER_HOSTS.includes("discord.com"));
    assert.ok(DEFAULT_WEBHOOK_PROVIDER_HOSTS.includes("discordapp.com"));

    // Teams: apex + explicit hosts + wildcards
    assert.ok(DEFAULT_WEBHOOK_PROVIDER_HOSTS.includes("outlook.office.com"));
    assert.ok(DEFAULT_WEBHOOK_PROVIDER_HOSTS.includes("webhook.office.com"));
    assert.ok(DEFAULT_WEBHOOK_PROVIDER_HOSTS.includes("office.com"));
    assert.ok(DEFAULT_WEBHOOK_PROVIDER_HOSTS.includes("office365.com"));
    assert.ok(DEFAULT_WEBHOOK_PROVIDER_HOSTS.includes("*.office.com"));
    assert.ok(DEFAULT_WEBHOOK_PROVIDER_HOSTS.includes("*.office365.com"));

    // PagerDuty: US + EU + wildcard
    assert.ok(DEFAULT_WEBHOOK_PROVIDER_HOSTS.includes("events.pagerduty.com"));
    assert.ok(
      DEFAULT_WEBHOOK_PROVIDER_HOSTS.includes("events.eu.pagerduty.com"),
    );
    assert.ok(DEFAULT_WEBHOOK_PROVIDER_HOSTS.includes("*.pagerduty.com"));

    // Power Automate / Logic Apps
    assert.ok(DEFAULT_WEBHOOK_PROVIDER_HOSTS.includes("*.logic.azure.com"));
    assert.ok(
      DEFAULT_WEBHOOK_PROVIDER_HOSTS.includes(
        "*.environment.api.powerplatform.com",
      ),
    );

    assert.strictEqual(DEFAULT_WEBHOOK_PROVIDER_HOSTS.length, 14);
  });
});

describe("getWebhookProviderHosts", () => {
  it("never includes the literal '*' allow-all sentinel, even when set", () => {
    process.env.WEBHOOK_EXTRA_PROVIDER_HOSTS = "*";
    assert.ok(!getWebhookProviderHosts().includes("*"));

    process.env.WEBHOOK_EXTRA_PROVIDER_HOSTS = "";
    process.env.WEBHOOK_PROVIDER_HOSTS = "*";
    assert.ok(!getWebhookProviderHosts().includes("*"));
  });

  it("falls back cleanly to just the defaults when env vars are unset/empty", () => {
    delete process.env.WEBHOOK_EXTRA_PROVIDER_HOSTS;
    delete process.env.WEBHOOK_PROVIDER_HOSTS;
    assert.deepStrictEqual(
      getWebhookProviderHosts(),
      DEFAULT_WEBHOOK_PROVIDER_HOSTS,
    );

    process.env.WEBHOOK_EXTRA_PROVIDER_HOSTS = "";
    process.env.WEBHOOK_PROVIDER_HOSTS = "";
    assert.deepStrictEqual(
      getWebhookProviderHosts(),
      DEFAULT_WEBHOOK_PROVIDER_HOSTS,
    );
  });

  it("WEBHOOK_EXTRA_PROVIDER_HOSTS adds to (does not replace) the defaults", () => {
    process.env.WEBHOOK_EXTRA_PROVIDER_HOSTS = "hooks.internal.example.com";
    const hosts = getWebhookProviderHosts();
    assert.ok(hosts.includes("hooks.slack.com"));
    assert.ok(hosts.includes("hooks.internal.example.com"));
    assert.strictEqual(hosts.length, DEFAULT_WEBHOOK_PROVIDER_HOSTS.length + 1);
  });

  it("WEBHOOK_PROVIDER_HOSTS (legacy alias) is used on its own when WEBHOOK_EXTRA_PROVIDER_HOSTS is unset", () => {
    process.env.WEBHOOK_PROVIDER_HOSTS = "legacy-alias.example.com";
    const hosts = getWebhookProviderHosts();
    assert.ok(hosts.includes("legacy-alias.example.com"));
  });

  it("unions WEBHOOK_PROVIDER_HOSTS and WEBHOOK_EXTRA_PROVIDER_HOSTS when both are set", () => {
    process.env.WEBHOOK_PROVIDER_HOSTS = "legacy-alias.example.com";
    process.env.WEBHOOK_EXTRA_PROVIDER_HOSTS = "modern.example.com";
    const hosts = getWebhookProviderHosts();
    assert.ok(
      hosts.includes("modern.example.com"),
      "WEBHOOK_EXTRA_PROVIDER_HOSTS entries must be present",
    );
    assert.ok(
      hosts.includes("legacy-alias.example.com"),
      "WEBHOOK_PROVIDER_HOSTS entries must also be present (union, not fallback)",
    );
  });

  it("dedupes when the same host appears in both variables", () => {
    process.env.WEBHOOK_PROVIDER_HOSTS = "shared.example.com";
    process.env.WEBHOOK_EXTRA_PROVIDER_HOSTS = "shared.example.com";
    const hosts = getWebhookProviderHosts();
    assert.strictEqual(
      hosts.filter((h) => h === "shared.example.com").length,
      1,
    );
  });

  it("normalizes trailing dot, case, whitespace, drops empties, and dedupes", () => {
    process.env.WEBHOOK_EXTRA_PROVIDER_HOSTS =
      "  Example.COM. ,  , hooks.slack.com, EXAMPLE.com.,example.com";
    const hosts = getWebhookProviderHosts();
    const matches = hosts.filter((h) => h === "example.com");
    assert.strictEqual(matches.length, 1);
    // Duplicate of an existing default should not double up either.
    const slackMatches = hosts.filter((h) => h === "hooks.slack.com");
    assert.strictEqual(slackMatches.length, 1);
  });
});

describe("allowAllWebhookHosts", () => {
  it("is false by default", () => {
    assert.strictEqual(allowAllWebhookHosts(), false);
  });

  it("WEBHOOK_ALLOW_ALL_HOSTS=true bypasses the allowlist entirely", () => {
    process.env.WEBHOOK_ALLOW_ALL_HOSTS = "true";
    assert.strictEqual(allowAllWebhookHosts(), true);
    assert.strictEqual(webhookHostAllowed("totally-random-host.example"), true);
  });

  it("is case-insensitive for WEBHOOK_ALLOW_ALL_HOSTS", () => {
    process.env.WEBHOOK_ALLOW_ALL_HOSTS = "TRUE";
    assert.strictEqual(allowAllWebhookHosts(), true);
  });

  it("a literal '*' in WEBHOOK_EXTRA_PROVIDER_HOSTS also triggers allow-all", () => {
    process.env.WEBHOOK_EXTRA_PROVIDER_HOSTS = "*";
    assert.strictEqual(allowAllWebhookHosts(), true);
    // Must not require a host literally named "*" to match.
    assert.strictEqual(webhookHostAllowed("anything-goes.example"), true);
  });

  it("a literal '*' mixed with other extras still triggers allow-all", () => {
    process.env.WEBHOOK_EXTRA_PROVIDER_HOSTS = "hooks.internal.example.com,*";
    assert.strictEqual(allowAllWebhookHosts(), true);
  });
});

describe("webhookHostAllowed", () => {
  it("allows canonical default hosts", () => {
    assert.strictEqual(webhookHostAllowed("hooks.slack.com"), true);
    assert.strictEqual(webhookHostAllowed("discord.com"), true);
    assert.strictEqual(webhookHostAllowed("events.pagerduty.com"), true);
  });

  it("rejects hosts not on the allowlist", () => {
    assert.strictEqual(webhookHostAllowed("not-allowed.example.com"), false);
  });

  it("matches a random subdomain of an allowed wildcard entry", () => {
    assert.strictEqual(
      webhookHostAllowed(
        `${Math.random().toString(36).slice(2)}.pagerduty.com`,
      ),
      true,
    );
    assert.strictEqual(
      webhookHostAllowed("myflow123.logic.azure.com"),
      true,
    );
    assert.strictEqual(
      webhookHostAllowed(
        "01234567-89ab-cdef-0123-456789abcdef.02.environment.api.powerplatform.com",
      ),
      true,
    );
  });

  it("matches the bare apex of a wildcard-only entry", () => {
    assert.strictEqual(webhookHostAllowed("pagerduty.com"), true);
    assert.strictEqual(webhookHostAllowed("logic.azure.com"), true);
    assert.strictEqual(
      webhookHostAllowed("environment.api.powerplatform.com"),
      true,
    );
  });

  it("a literal '*' entry is excluded from the returned host list and never itself matches literally as a hostname", () => {
    process.env.WEBHOOK_ALLOW_ALL_HOSTS = "false";
    process.env.WEBHOOK_EXTRA_PROVIDER_HOSTS = "hooks.internal.example.com,*";
    assert.ok(
      !getWebhookProviderHosts().includes("*"),
      "* must never appear in the returned host list; it is an allow-all sentinel, not a hostname",
    );
    // allowAllWebhookHosts() consumes "*" separately from the returned host
    // list, so it still takes effect even though getWebhookProviderHosts()
    // strips the sentinel out.
    assert.strictEqual(webhookHostAllowed("random.example"), true);
  });

  it("normalizes the checked hostname (case, trailing dot)", () => {
    assert.strictEqual(webhookHostAllowed("HOOKS.SLACK.COM"), true);
    assert.strictEqual(webhookHostAllowed("hooks.slack.com."), true);
  });

  it("honors extras end-to-end through webhookHostAllowed", () => {
    process.env.WEBHOOK_EXTRA_PROVIDER_HOSTS = "hooks.internal.example.com";
    assert.strictEqual(
      webhookHostAllowed("hooks.internal.example.com"),
      true,
    );
    assert.strictEqual(webhookHostAllowed("other.example.com"), false);
  });
});
