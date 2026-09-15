"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { pathToFileURL } = require("node:url");

const {
  resolveGitHubApiBase,
  scanGitHub,
} = require("../../apps/api/services/githubIntegration");
const {
  isGitLabDotComHost,
  scanGitLab,
} = require("../../apps/api/services/gitlabIntegration");

describe("resolveGitHubApiBase", () => {
  it("maps github.com and www.github.com to api.github.com", () => {
    assert.equal(
      resolveGitHubApiBase("https://github.com"),
      "https://api.github.com",
    );
    assert.equal(
      resolveGitHubApiBase("https://www.github.com"),
      "https://api.github.com",
    );
    assert.equal(
      resolveGitHubApiBase("https://GitHub.COM"),
      "https://api.github.com",
    );
  });

  it("keeps api.github.com unchanged", () => {
    assert.equal(
      resolveGitHubApiBase("https://api.github.com"),
      "https://api.github.com",
    );
  });

  it("does not treat a path, query, or sibling host as GitHub cloud", () => {
    assert.equal(
      resolveGitHubApiBase("https://evil.example/api.github.com"),
      "https://evil.example/api.github.com",
    );
    assert.equal(
      resolveGitHubApiBase("https://github.com.evil.com"),
      "https://github.com.evil.com",
    );
    assert.equal(
      resolveGitHubApiBase("https://api.github.com.evil.com"),
      "https://api.github.com.evil.com",
    );
  });

  it("keeps GitHub Enterprise hosts as-is", () => {
    assert.equal(
      resolveGitHubApiBase("https://ghe.example.com/api/v3"),
      "https://ghe.example.com/api/v3",
    );
  });

  it("rejects an unparseable base URL", () => {
    assert.throws(() => resolveGitHubApiBase("not a url"), {
      message: "Invalid baseUrl format",
    });
  });
});

describe("isGitLabDotComHost", () => {
  it("recognizes gitlab.com and www.gitlab.com", () => {
    assert.equal(isGitLabDotComHost("gitlab.com"), true);
    assert.equal(isGitLabDotComHost("www.gitlab.com"), true);
    assert.equal(isGitLabDotComHost("GitLab.COM"), true);
  });

  it("does not treat a query or sibling host as GitLab cloud", () => {
    assert.equal(
      isGitLabDotComHost(new URL("https://evil.com/?x=gitlab.com").hostname),
      false,
    );
    assert.equal(isGitLabDotComHost("gitlab.example.com"), false);
    assert.equal(isGitLabDotComHost("gitlab.com.evil.com"), false);
  });
});

describe("scan URL validation", () => {
  it("rejects an unparseable GitHub scan baseUrl before contacting GitHub", async () => {
    await assert.rejects(
      () => scanGitHub({ baseUrl: "not a url", token: "token" }),
      { message: "Invalid baseUrl format" },
    );
  });

  it("rejects an unparseable GitLab scan baseUrl before contacting GitLab", async () => {
    await assert.rejects(
      () => scanGitLab({ baseUrl: "not a url", token: "token" }),
      { message: "Invalid baseUrl format" },
    );
  });
});

describe("detectWebhookProviderKind", () => {
  it("classifies Slack, Discord, Teams, and PagerDuty by hostname", async () => {
    const { detectWebhookProviderKind } = await import(
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

    assert.equal(detectWebhookProviderKind("hooks.slack.com"), "slack");
    assert.equal(detectWebhookProviderKind("discord.com"), "discord");
    assert.equal(detectWebhookProviderKind("canary.discord.com"), "discord");
    assert.equal(detectWebhookProviderKind("notdiscord.com"), null);
    assert.equal(detectWebhookProviderKind("webhook.office.com"), "teams");
    assert.equal(detectWebhookProviderKind("office.com"), null);
    assert.equal(detectWebhookProviderKind("events.pagerduty.com"), "pagerduty");
  });
});
