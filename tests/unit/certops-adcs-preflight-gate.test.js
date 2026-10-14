"use strict";

/**
 * Shared AD CS preflight gate. The renewal scheduler and renewal-path health
 * both call qualifiesAdcsPreflight / loadQualifyingAdcsAgents, so these
 * boundaries must stay covered at the predicate itself.
 */

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

const {
  ADCS_PREFLIGHT_MAX_AGE_MS,
  loadQualifyingAdcsAgents,
  qualifiesAdcsPreflight,
} = require("../../apps/api/services/certops/adcsPreflightGate");

const HOUR_MS = 60 * 60 * 1000;
const NOW = Date.parse("2026-10-13T12:00:00.000Z");
const CA = "ca01.corp.example.com\\Corp Issuing CA 01";
const TEMPLATE = "TokenTimerWebServer";
const KEY = "ab".repeat(32);

function version(overrides = {}) {
  return {
    ca_config: CA,
    template: TEMPLATE,
    ca_key_sha256: KEY,
    confirmed_at: new Date(NOW - 7 * 24 * HOUR_MS),
    ...overrides,
  };
}

function evidence({ createdAgoMs = HOUR_MS, status = "succeeded", verdict = {} } = {}) {
  return {
    status,
    created_at: new Date(NOW - createdAgoMs),
    result_metadata: {
      preflightVerdict: {
        templateCheck: "safe",
        caCheck: "safe",
        caConfig: CA,
        template: TEMPLATE,
        caKeySha256s: [KEY],
        ...verdict,
      },
    },
  };
}

describe("qualifiesAdcsPreflight", () => {
  it("accepts a 23h-old safe preflight for the same CA, template, and pin", () => {
    assert.equal(
      qualifiesAdcsPreflight(evidence({ createdAgoMs: 23 * HOUR_MS }), version(), NOW),
      true,
    );
  });

  it("rejects a 25h-old preflight even when CA, template, and pin still match", () => {
    assert.equal(
      qualifiesAdcsPreflight(evidence({ createdAgoMs: 25 * HOUR_MS }), version(), NOW),
      false,
    );
  });

  it("uses the shared 24-hour freshness constant as the boundary", () => {
    assert.equal(ADCS_PREFLIGHT_MAX_AGE_MS, 24 * HOUR_MS);
    assert.equal(
      qualifiesAdcsPreflight(
        evidence({ createdAgoMs: ADCS_PREFLIGHT_MAX_AGE_MS - 60_000 }),
        version(),
        NOW,
      ),
      true,
    );
    assert.equal(
      qualifiesAdcsPreflight(
        evidence({ createdAgoMs: ADCS_PREFLIGHT_MAX_AGE_MS + 60_000 }),
        version(),
        NOW,
      ),
      false,
    );
  });

  it("rejects a preflight taken before the CA was re-confirmed", () => {
    assert.equal(
      qualifiesAdcsPreflight(
        evidence({ createdAgoMs: HOUR_MS }),
        version({ confirmed_at: new Date(NOW - 30 * 60 * 1000) }),
        NOW,
      ),
      false,
    );
  });

  it("rejects mismatched template, CA config, or pinned key", () => {
    assert.equal(
      qualifiesAdcsPreflight(
        evidence({ verdict: { template: "OtherTemplate" } }),
        version(),
        NOW,
      ),
      false,
    );
    assert.equal(
      qualifiesAdcsPreflight(
        evidence({ verdict: { caConfig: "other-ca\\Other CA" } }),
        version(),
        NOW,
      ),
      false,
    );
    assert.equal(
      qualifiesAdcsPreflight(
        evidence({ verdict: { caKeySha256s: ["cd".repeat(32)] } }),
        version(),
        NOW,
      ),
      false,
    );
  });

  it("rejects failed or missing preflight evidence", () => {
    assert.equal(qualifiesAdcsPreflight(null, version(), NOW), false);
    assert.equal(
      qualifiesAdcsPreflight(evidence({ status: "failed" }), version(), NOW),
      false,
    );
    assert.equal(qualifiesAdcsPreflight(evidence(), null, NOW), false);
  });
});

describe("loadQualifyingAdcsAgents", () => {
  it("returns only the agent that holds its own qualifying preflight", async () => {
    const agentA = {
      id: "agent-a",
      last_seen_at: new Date(NOW - 60_000).toISOString(),
      ...evidence({ createdAgoMs: 23 * HOUR_MS }),
    };
    // Same CA/template/pin and still inside the freshness window, but this row
    // belongs to agent B. Agent A's evidence must not qualify B.
    const agentB = {
      id: "agent-b",
      last_seen_at: new Date(NOW - 30_000).toISOString(),
      status: null,
      created_at: null,
      result_metadata: null,
    };
    const db = {
      async query(sql, params) {
        assert.match(sql, /adcs-preflight/);
        assert.deepEqual(params, ["ws-1", "app.example.com", "issuer-1"]);
        return { rows: [agentB, agentA] };
      },
    };

    const agents = await loadQualifyingAdcsAgents({
      db,
      workspaceId: "ws-1",
      issuerId: "issuer-1",
      reference: "app.example.com",
      version: version(),
      nowMs: NOW,
    });

    assert.deepEqual(
      agents.map((row) => row.id),
      ["agent-a"],
    );
  });

  it("does not let agent A's fresh preflight qualify agent B's stale row", async () => {
    const rows = [
      {
        id: "agent-a",
        last_seen_at: new Date(NOW - 60_000).toISOString(),
        ...evidence({ createdAgoMs: HOUR_MS }),
      },
      {
        id: "agent-b",
        last_seen_at: new Date(NOW - 30_000).toISOString(),
        ...evidence({ createdAgoMs: 25 * HOUR_MS }),
      },
    ];
    const db = {
      async query() {
        return { rows };
      },
    };

    const agents = await loadQualifyingAdcsAgents({
      db,
      workspaceId: "ws-1",
      issuerId: "issuer-1",
      reference: "app.example.com",
      version: version(),
      nowMs: NOW,
    });

    assert.deepEqual(
      agents.map((row) => row.id),
      ["agent-a"],
    );
  });
});
