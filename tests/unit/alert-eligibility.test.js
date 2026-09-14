const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const {
  evaluateAlertEligibility,
  findThresholdWindow,
} = require("../../packages/alert-eligibility");
const {
  buildDeliveryState,
} = require("../../apps/api/services/alertEligibility");

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
