const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const {
  evaluateAlertEligibility,
  findThresholdWindow,
} = require("../../packages/alert-eligibility");
const {
  buildDeliveryState,
  countWorkspaceAlertEligibility,
  enrichTokenWithAlertStateBestEffort,
} = require("../../apps/api/services/alertEligibility");

describe("workspace eligibility summary", () => {
  it("counts the whole workspace via the shared evaluator, not a page", async () => {
    const calls = [];
    const queryable = {
      query: async (sql, params) => {
        calls.push({ sql, params });
        if (sql.startsWith("SELECT id FROM tokens")) {
          return { rows: [{ id: 1 }, { id: 2 }, { id: 3 }] };
        }
        return {
          rows: [
            {
              token_id: 1,
              expiration: "2026-10-20",
              imported_at: "2026-09-01",
              alert_thresholds: [7],
            },
            {
              token_id: 2,
              expiration: "2026-09-20",
              imported_at: "2026-09-01",
              alert_thresholds: [7],
              contact_groups: [{ id: "ops", email_contact_ids: ["c1"] }],
              default_contact_group_id: "ops",
            },
            {
              token_id: 3,
              expiration: "2026-09-20",
              imported_at: "2026-09-14",
              alert_thresholds: [7],
            },
          ],
        };
      },
    };
    const summary = await countWorkspaceAlertEligibility("workspace-1", {
      queryable,
      referenceDate: "2026-09-15T12:00:00Z",
    });
    assert.deepEqual(summary, {
      total: 3,
      counts: { outside_threshold: 1, due: 1, suppressed: 1 },
    });
    assert.equal(calls.length, 2);
    assert.equal(calls[0].params[0], "workspace-1");
    assert.deepEqual(calls[1].params[0], [1, 2, 3]);
    assert.doesNotMatch(calls[1].sql, /alert_delivery_log|audit_events|alert_queue/);
  });
});

const REFERENCE_DATE = "2026-09-13T12:00:00.000Z";

function eligibleAsset(overrides = {}) {
  return {
    expiration: "2026-09-20",
    imported_at: "2026-09-12T10:00:00.000Z",
    alert_thresholds: [7, 0, -2],
    contact_groups: [{ id: "ops", email_contact_ids: ["contact-1"] }],
    default_contact_group_id: "ops",
    ws_email_alerts_enabled: true,
    webhook_urls: [],
    cert_lifecycle_status: null,
    ...overrides,
  };
}

function evaluate(asset) {
  return evaluateAlertEligibility(asset, { referenceDate: REFERENCE_DATE });
}

describe("alert eligibility evaluator", () => {
  it("preserves PostgreSQL DATE calendar values outside UTC", () => {
    const expiration = new Date(2026, 8, 13);
    const result = evaluate(eligibleAsset({ expiration }));

    assert.equal(result.status, "due");
    assert.equal(result.days_until_expiry, 0);
    assert.equal(result.effective_threshold, 0);
  });

  it("reports an import before the threshold as due", () => {
    const result = evaluate(eligibleAsset());
    assert.equal(result.status, "due");
    assert.equal(result.reason, "threshold_reached");
    assert.equal(result.effective_threshold, 7);
    assert.equal(result.days_until_expiry, 7);
    assert.deepEqual(result.eligible_channels, ["email"]);
  });

  it("keeps the threshold-date boundary eligible", () => {
    const result = evaluate(
      eligibleAsset({
        expiration: "2026-09-18",
        imported_at: "2026-09-11T23:59:59.000Z",
      }),
    );
    assert.equal(result.status, "due");
    assert.equal(result.threshold_date, "2026-09-11");
  });

  it("suppresses an import after the active threshold as stale catch-up", () => {
    const result = evaluate(
      eligibleAsset({
        expiration: "2026-09-18",
        imported_at: "2026-09-12T01:00:00.000Z",
      }),
    );
    assert.equal(result.status, "suppressed");
    assert.equal(result.reason, "stale_import_threshold");
    assert.equal(result.effective_threshold, 7);
    assert.equal(result.next_threshold, 0);
    assert.equal(result.next_evaluation_at, "2026-09-18");
  });

  it("reports expiry day zero as due when imported that day", () => {
    const result = evaluate(
      eligibleAsset({
        expiration: "2026-09-13",
        imported_at: "2026-09-13T23:30:00.000Z",
      }),
    );
    assert.equal(result.status, "due");
    assert.equal(result.effective_threshold, 0);
    assert.equal(result.threshold_type, "expiry_day");
  });

  it("does not reach a negative threshold before its post-expiry day", () => {
    assert.equal(findThresholdWindow(-1, [7, 0, -2]), null);
    const result = evaluate(
      eligibleAsset({
        expiration: "2026-09-12",
        imported_at: "2026-09-12",
      }),
    );
    assert.equal(result.status, "outside_threshold");
    assert.equal(result.next_threshold, -2);
    assert.equal(result.next_evaluation_at, "2026-09-14");
  });

  it("reports the exact negative threshold day as due", () => {
    const result = evaluate(
      eligibleAsset({
        expiration: "2026-09-11",
        imported_at: "2026-09-11",
      }),
    );
    assert.equal(result.status, "due");
    assert.equal(result.effective_threshold, -2);
    assert.equal(result.threshold_type, "post_expiry");
  });

  it("explains expired-at-import behavior when no negative threshold exists", () => {
    const result = evaluate(
      eligibleAsset({
        expiration: "2026-09-12",
        imported_at: "2026-09-13",
        alert_thresholds: [7, 0],
      }),
    );
    assert.equal(result.status, "outside_threshold");
    assert.equal(result.reason, "post_expiry_threshold_not_configured");
    assert.equal(result.metadata.expired_at_import, true);
  });

  it("suppresses a stale import after a negative threshold", () => {
    const result = evaluate(
      eligibleAsset({
        expiration: "2026-09-10",
        imported_at: "2026-09-13",
      }),
    );
    assert.equal(result.status, "suppressed");
    assert.equal(result.reason, "stale_import_threshold");
    assert.equal(result.effective_threshold, -2);
  });

  it("suppresses retired certificates before threshold or channel decisions", () => {
    const result = evaluate(
      eligibleAsset({ cert_lifecycle_status: "decommissioned" }),
    );
    assert.equal(result.status, "suppressed");
    assert.equal(result.reason, "retired_certificate");
  });

  it("suppresses a reached threshold without eligible recipients or channels", () => {
    const result = evaluate(
      eligibleAsset({
        contact_groups: [{ id: "ops", email_contact_ids: [] }],
      }),
    );
    assert.equal(result.status, "suppressed");
    assert.equal(result.reason, "no_eligible_channels");
    assert.deepEqual(result.eligible_channels, []);
  });

  it("uses contact-group threshold overrides and named webhook eligibility", () => {
    const result = evaluate(
      eligibleAsset({
        expiration: "2026-09-18",
        contact_groups: [
          {
            id: "ops",
            thresholds: [5, -5],
            webhook_names: ["pager"],
          },
        ],
        webhook_urls: [{ name: "pager", url: "https://example.test/hook" }],
      }),
    );
    assert.equal(result.status, "due");
    assert.equal(result.effective_threshold, 5);
    assert.deepEqual(result.effective_thresholds, [5, -5]);
    assert.deepEqual(result.eligible_channels, ["webhooks"]);
  });
});

describe("delivery state projection", () => {
  it("classifies discarded sent queue rows as discarded, not successful delivery", () => {
    for (const [message, reason] of [
      ["Discarded: certificate revoked or decommissioned", "retired_certificate"],
      ["Discarded: endpoint recovered before threshold", "endpoint_recovered"],
    ]) {
      const state = buildDeliveryState({ alert_id: 12, alert_status: "sent",
        alert_error_message: message });
      assert.equal(state.status, "discarded");
      assert.equal(state.reason, reason);
    }
  });
  it("requires durable success evidence before describing a closed queue as sent", () => {
    const unverified = buildDeliveryState({ alert_id: 15, alert_status: "sent",
      alert_success_evidence: false });
    assert.equal(unverified.status, "sent_unverified");
    assert.equal(unverified.reason, "delivery_unverified");
    assert.equal(buildDeliveryState({ alert_id: 15, alert_status: "sent",
      alert_success_evidence: true }).status, "sent");
  });
  it("redacts queue and attempt errors from viewer-readable alert state", () => {
    const state = buildDeliveryState({
      alert_id: 45,
      alert_status: "failed",
      alert_error_message: "SMTP to ops@example.test at https://hooks.example.test/private?token=secret +49 151 23456789 password=hunter2",
      delivery_attempt_error: "Webhook hooks.example.test/private failed for +1 555 123 4567 bearer_token=topsecret",
      delivery_attempt_status: "failed",
      delivery_attempt_id: 999,
    });
    assert.doesNotMatch(JSON.stringify(state), /ops@example|hooks.example|151 23456789|555 123 4567|hunter2|topsecret/);
  });
  it("keeps delivery windows, plan limits, and retries out of eligibility", () => {
    const deferred = buildDeliveryState({
      alert_id: 42,
      alert_status: "pending",
      alert_error_message: "OUT_OF_WINDOW",
      next_attempt_at: "2026-09-14T08:00:00.000Z",
    });
    assert.equal(deferred.reason, "delivery_window");

    const limited = buildDeliveryState({
      alert_id: 43,
      alert_status: "limit_exceeded",
      alert_error_message: "PLAN_LIMIT",
    });
    assert.equal(limited.reason, "monthly_plan_limit");

    const retrying = buildDeliveryState({
      alert_id: 44,
      alert_status: "failed",
      next_attempt_at: "2026-09-14T08:00:00.000Z",
    });
    assert.equal(retrying.reason, "retry_scheduled");
  });
});

describe("mutation alert-state enrichment", () => {
  it("returns the mutated token when projection fails instead of throwing", async () => {
    const token = { id: 9, name: "asset" };
    const enriched = await enrichTokenWithAlertStateBestEffort(token, {
      queryable: {
        query: async () => {
          throw new Error("projection boom");
        },
      },
    });
    assert.equal(enriched.id, 9);
    assert.equal(enriched.name, "asset");
    assert.equal(enriched.alert_state, null);
  });
});
