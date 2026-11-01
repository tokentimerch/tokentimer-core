"use strict";

const { before, describe, it } = require("node:test");
const assert = require("node:assert/strict");
let identity, lifecycle;
const workspaceId = "3d1e2319-1723-4c34-af98-abc794652a6c";
const webhook = {
  name: "primary",
  kind: "pagerduty",
  url: "https://events.pagerduty.com/v2/enqueue",
  routingKey: "A".repeat(32),
};

before(async () => {
  identity =
    await import("../../apps/worker/src/shared/webhookDestinations.js");
  lifecycle = await import("../../apps/worker/src/pagerduty-incidents.js");
});

describe("PagerDuty destination and episode identity", () => {
  it("is stable across retries, thresholds and contact-group/configuration renames", () => {
    const destinationId = identity.pagerDutyDestinationId(workspaceId, webhook);
    assert.equal(
      destinationId,
      identity.pagerDutyDestinationId(workspaceId, {
        ...webhook,
        name: "renamed",
      }),
    );
    const input = {
      workspaceId,
      tokenId: 1,
      destinationId,
      episodeId: "episode-a",
    };
    const key = identity.pagerDutyDedupKey(input);
    assert.equal(
      key,
      identity.pagerDutyDedupKey({
        ...input,
        thresholdDays: 7,
        alertQueueId: 98,
      }),
    );
    assert.ok(key.length <= 255);
    assert.doesNotMatch(key, new RegExp(webhook.routingKey));
    assert.match(destinationId, /^[a-f0-9]{64}$/);
  });
  it("isolates assets, workspaces, integrations, endpoints and later risk episodes", () => {
    const destinationId = identity.pagerDutyDestinationId(workspaceId, webhook);
    const input = {
      workspaceId,
      tokenId: 1,
      destinationId,
      episodeId: "episode-a",
    };
    const key = identity.pagerDutyDedupKey(input);
    for (const change of [
      { tokenId: 2 },
      { workspaceId: "another-tenant" },
      {
        destinationId: identity.pagerDutyDestinationId(workspaceId, {
          ...webhook,
          routingKey: "B".repeat(32),
        }),
      },
      { episodeId: "episode-b" },
    ])
      assert.notEqual(key, identity.pagerDutyDedupKey({ ...input, ...change }));
    assert.notEqual(
      destinationId,
      identity.pagerDutyDestinationId("another-tenant", webhook),
    );
    assert.notEqual(
      destinationId,
      identity.pagerDutyDestinationId(workspaceId, {
        ...webhook,
        url: "https://events.eu.pagerduty.com/v2/enqueue",
      }),
    );
  });
  it("deduplicates aliases across groups but keeps routing keys independent at the same URL", () => {
    const second = {
      ...webhook,
      name: "secondary",
      routingKey: "B".repeat(32),
    };
    assert.deepEqual(
      identity.uniqueWebhookDestinations(
        [webhook, { ...webhook, name: "alias" }, second],
        workspaceId,
      ),
      [webhook, second],
    );
  });
  it("preserves URL-based deduplication for other webhook kinds and recognizes implicit PagerDuty providers", () => {
    const generic = { kind: "generic", url: "https://example.test/webhook" };
    assert.deepEqual(
      identity.uniqueWebhookDestinations(
        [generic, { ...generic, name: "alias" }],
        workspaceId,
      ),
      [generic],
    );
    assert.equal(identity.pagerDutyDestinationId(workspaceId, generic), null);
    assert.equal(
      identity.pagerDutyDestinationId(workspaceId, {
        ...webhook,
        kind: "generic",
      }),
      identity.pagerDutyDestinationId(workspaceId, webhook),
    );
  });
});

describe("PagerDuty expiration recovery", () => {
  const now = new Date("2026-10-27T12:00:00Z");
  const incident = {
    original_expiration: "2026-10-28",
    risk_threshold_days: 30,
    expiry_authority: "manual",
  };
  const context = { token_id: 1, expiration: "2027-04-27" };
  it("accepts an authorized manual extension outside the complete destination window", () => {
    assert.equal(
      lifecycle.isPagerDutyRecovery(incident, context, 7, now),
      true,
    );
  });
  for (const [name, expiration] of [
    ["unchanged", "2026-10-28"],
    ["shortened", "2026-10-27"],
    ["still inside the window", "2026-11-01"],
    ["invalid", "invalid"],
    ["missing", null],
  ]) {
    it(`does not recover when expiration is ${name}`, () => {
      assert.equal(
        lifecycle.isPagerDutyRecovery(
          incident,
          { ...context, expiration },
          null,
          now,
        ),
        false,
      );
    });
  }
  it("uses the wider of original and current destination thresholds", () => {
    assert.equal(
      lifecycle.isPagerDutyRecovery(
        incident,
        { ...context, expiration: "2026-11-10" },
        7,
        now,
      ),
      false,
    );
    assert.equal(
      lifecycle.isPagerDutyRecovery(incident, context, 365, now),
      false,
    );
  });
  it("does not equate asset deletion or certificate retirement with renewal", () => {
    assert.equal(
      lifecycle.isPagerDutyRecovery(
        incident,
        { ...context, token_id: null },
        null,
        now,
      ),
      false,
    );
    assert.equal(
      lifecycle.isPagerDutyRecovery(
        incident,
        { ...context, cert_lifecycle_status: "revoked" },
        null,
        now,
      ),
      false,
    );
  });
  it("requires certificate/TLS evidence even after the owner or monitor disappears", () => {
    for (const authority of ["certificate", "monitor"]) {
      const managed = { ...incident, expiry_authority: authority };
      assert.equal(
        lifecycle.isPagerDutyRecovery(managed, context, null, now),
        false,
      );
      const evidence =
        authority === "certificate"
          ? { managed_expiry_verified: true }
          : { monitored_expiry_verified: true };
      assert.equal(
        lifecycle.isPagerDutyRecovery(
          managed,
          { ...context, ...evidence },
          null,
          now,
        ),
        true,
      );
    }
  });
  it("rejects unknown provider expiry evidence and its never-expires fallback", () => {
    const provider = { ...incident, expiry_authority: "provider" };
    assert.equal(
      lifecycle.isPagerDutyRecovery(provider, context, null, now),
      false,
    );
    const observed = {
      ...context,
      source_provider: "gitlab",
      source_observed_at: now,
    };
    assert.equal(
      lifecycle.isPagerDutyRecovery(provider, observed, null, now),
      true,
    );
    assert.equal(
      lifecycle.isPagerDutyRecovery(
        provider,
        { ...observed, expiration: "2099-12-31" },
        null,
        now,
      ),
      false,
    );
    const initialObservation = {
      ...provider,
      original_source_observed_at: "2026-10-26T12:00:00Z",
    };
    assert.equal(
      lifecycle.isPagerDutyRecovery(
        initialObservation,
        { ...observed, source_observed_at: "2026-10-26T12:00:00Z" },
        null,
        now,
      ),
      false,
    );
    assert.equal(
      lifecycle.isPagerDutyRecovery(initialObservation, observed, null, now),
      true,
    );
  });
});

describe("PagerDuty failure handling", () => {
  for (const status of [408, 425, 429, 500, 502, 503])
    it(`retries HTTP ${status} without persisting provider secrets`, () => {
      const result = lifecycle.classifyPagerDutyResult({
        success: false,
        status,
        error: "routing_key=do-not-store",
      });
      assert.equal(result.retryable, true);
      assert.equal(result.error, `pagerduty_http_${status}`);
      assert.doesNotMatch(JSON.stringify(result), /routing_key|do-not-store/);
    });
  for (const status of [200, 400, 401, 403, 404])
    it(`parks non-acceptance HTTP ${status}`, () => {
      assert.equal(
        lifecycle.classifyPagerDutyResult({ success: false, status }).retryable,
        false,
      );
    });
  it("retries transport uncertainty but accepts only explicit provider success", () => {
    assert.equal(
      lifecycle.classifyPagerDutyResult({ error: "timeout" }).retryable,
      true,
    );
    assert.deepEqual(
      lifecycle.classifyPagerDutyResult({ success: true, status: 202 }),
      { success: true, retryable: false, error: null },
    );
  });
  it("backs off exponentially with an hour cap and a finite attempt budget", () => {
    assert.deepEqual(
      [1, 2, 3, 8, 20].map(lifecycle.pagerDutyRetryDelay),
      [60000, 120000, 240000, 3600000, 3600000],
    );
    assert.equal(lifecycle.MAX_PAGERDUTY_ATTEMPTS, 8);
  });
});
