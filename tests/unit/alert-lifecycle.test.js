"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const {
  buildAlertLifecycleEvents,
  fetchAlertLifecycle,
  safeErrorMessage,
} = require("../../apps/api/services/alertLifecycle");

function queueRow(overrides = {}) {
  return {
    alert_id: 10,
    token_id: 7,
    token_name: "Production certificate",
    workspace_id: "00000000-0000-4000-8000-000000000001",
    expiration: "2026-09-20",
    threshold_days: 7,
    original_channels: ["email"],
    status: "pending",
    error_message: null,
    created_at: "2026-09-13T08:03:00.000Z",
    updated_at: "2026-09-13T08:03:00.000Z",
    ...overrides,
  };
}

function deliveryRow(overrides = {}) {
  return {
    delivery_id: 100,
    alert_id: 10,
    token_id: 7,
    token_name: "Production certificate",
    workspace_id: "00000000-0000-4000-8000-000000000001",
    threshold_days: 7,
    channel: "email",
    delivery_status: "failed",
    sent_at: "2026-09-13T08:04:00.000Z",
    error_message: "SMTP timeout",
    ...overrides,
  };
}

describe("alert lifecycle normalization", () => {
  it("derives threshold and queue events only from queue-backed alerts", () => {
    const events = buildAlertLifecycleEvents({ queueRows: [queueRow()] });
    assert.deepEqual(
      events.map((event) => event.type),
      ["alert_queued", "threshold_reached"],
    );
    const threshold = events.find(
      (event) => event.type === "threshold_reached",
    );
    assert.equal(threshold.occurred_at, "2026-09-13T00:00:00.000Z");
    assert.equal(threshold.threshold_days, 7);
  });

  it("uses the shared threshold semantics for multiple and post-expiry thresholds", () => {
    const events = buildAlertLifecycleEvents({
      queueRows: [
        queueRow(),
        queueRow({
          alert_id: 11,
          threshold_days: 0,
          created_at: "2026-09-20T01:00:00.000Z",
          updated_at: "2026-09-20T01:00:00.000Z",
        }),
        queueRow({
          alert_id: 12,
          threshold_days: -2,
          created_at: "2026-09-22T01:00:00.000Z",
          updated_at: "2026-09-22T01:00:00.000Z",
        }),
      ],
    });
    const thresholds = events
      .filter((event) => event.type === "threshold_reached")
      .map((event) => [event.threshold_days, event.occurred_at]);
    assert.deepEqual(thresholds, [
      [-2, "2026-09-22T00:00:00.000Z"],
      [0, "2026-09-20T00:00:00.000Z"],
      [7, "2026-09-13T00:00:00.000Z"],
    ]);
  });

  it("normalizes delivery outcomes, retries, requeues, partial delivery, blocking, and no-channel evidence", () => {
    const auditRows = [
      ["ALERT_NOT_QUEUED_NO_CHANNEL", 1, { threshold: 7 }],
      ["ALERT_DELIVERY_DEFERRED", 2, { threshold: 7 }],
      [
        "ALERT_RETRY_SCHEDULED",
        3,
        {
          days: 7,
          next_attempt_at: "2026-09-13T09:00:00.000Z",
          channels_to_retry: ["email"],
        },
      ],
      ["ALERT_PARTIAL_SUCCESS", 4, { channel: "webhooks" }],
      ["ALERT_BLOCKED_MAX_ATTEMPTS", 5, { days: 7 }],
      ["ALERT_MANUAL_RETRY", 6, { reason: "user_initiated" }],
      ["ALERTS_BULK_REQUEUED", 7, { updated: 4 }],
    ].map(([action, id, audit_metadata]) => ({
      audit_id: id,
      action,
      audit_metadata,
      occurred_at: `2026-09-13T08:${String(id).padStart(2, "0")}:00.000Z`,
      token_id: action === "ALERTS_BULK_REQUEUED" ? null : 7,
      token_name:
        action === "ALERTS_BULK_REQUEUED" ? null : "Production certificate",
      workspace_id: "00000000-0000-4000-8000-000000000001",
      alert_id: action === "ALERT_MANUAL_RETRY" ? 10 : null,
    }));
    const events = buildAlertLifecycleEvents({
      deliveryRows: [
        deliveryRow(),
        deliveryRow({
          delivery_id: 101,
          delivery_status: "success",
          sent_at: "2026-09-13T08:08:00.000Z",
          error_message: null,
        }),
        deliveryRow({
          delivery_id: 102,
          delivery_status: "blocked",
          channel: "whatsapp",
        }),
      ],
      auditRows,
    });
    const types = new Set(events.map((event) => event.type));
    for (const type of [
      "alert_not_queued",
      "delivery_deferred",
      "delivery_failed",
      "delivery_succeeded",
      "delivery_partial",
      "delivery_blocked",
      "retry_scheduled",
      "alert_requeued",
    ]) {
      assert.ok(types.has(type), `expected ${type}`);
    }
    const bulk = events.find((event) => event.reason === "bulk_requeue");
    assert.equal(bulk.metadata.updated_count, 4);
  });

  it("uses queue state as historical evidence for plan blocking and legacy outcomes", () => {
    const events = buildAlertLifecycleEvents({
      queueRows: [
        queueRow({ status: "limit_exceeded", error_message: "PLAN_LIMIT" }),
        queueRow({
          alert_id: 11,
          status: "sent",
          created_at: "2026-09-14T08:00:00.000Z",
          updated_at: "2026-09-14T08:05:00.000Z",
        }),
      ],
    });
    assert.ok(
      events.some(
        (event) =>
          event.type === "delivery_blocked" && event.reason === "monthly_limit",
      ),
    );
    assert.ok(events.some((event) => event.type === "delivery_succeeded"));
  });

  it("preserves the monthly-limit reason when a blocked delivery log exists", () => {
    const events = buildAlertLifecycleEvents({
      queueRows: [
        queueRow({ status: "limit_exceeded", error_message: "PLAN_LIMIT" }),
      ],
      deliveryRows: [
        deliveryRow({
          delivery_status: "blocked",
          queue_status: "limit_exceeded",
        }),
      ],
    });
    const blocked = events.filter(
      (event) => event.type === "delivery_blocked",
    );
    assert.equal(blocked.length, 1);
    assert.equal(blocked[0].reason, "monthly_limit");
  });

  it("does not duplicate a sent or failed queue outcome when a delivery log proves it", () => {
    const events = buildAlertLifecycleEvents({
      queueRows: [
        queueRow({ status: "sent" }),
        queueRow({
          alert_id: 11,
          status: "failed",
          created_at: "2026-09-14T08:03:00.000Z",
          updated_at: "2026-09-14T08:04:00.000Z",
        }),
      ],
      deliveryRows: [
        deliveryRow({ delivery_status: "success", error_message: null }),
        deliveryRow({
          delivery_id: 101,
          alert_id: 11,
          sent_at: "2026-09-14T08:04:00.000Z",
        }),
      ],
      auditRows: [
        {
          audit_id: 99,
          action: "ALERT_SENT",
          occurred_at: "2026-09-13T08:04:00.000Z",
          token_id: 7,
          audit_metadata: { days: 7 },
        },
        {
          audit_id: 100,
          action: "ALERT_SEND_FAILED",
          occurred_at: "2026-09-14T08:04:00.000Z",
          token_id: 7,
          audit_metadata: { days: 7 },
        },
      ],
    });
    assert.equal(
      events.filter((event) => event.type === "delivery_succeeded").length,
      1,
    );
    assert.equal(
      events.filter((event) => event.type === "delivery_failed").length,
      1,
    );
  });

  it("uses legacy queue and delivery audits only when primary records are absent", () => {
    const auditRows = [
      ["ALERT_QUEUED", 201],
      ["ALERT_SENT", 202],
      ["ALERT_SEND_FAILED", 203],
    ].map(([action, audit_id], index) => ({
      audit_id,
      action,
      audit_metadata: {
        threshold: 7,
        channels: ["email"],
        error: action === "ALERT_SEND_FAILED" ? "SMTP timeout" : undefined,
      },
      occurred_at: `2026-09-13T09:0${index}:00.000Z`,
      token_id: 7,
      token_name: "Production certificate",
      workspace_id: "00000000-0000-4000-8000-000000000001",
    }));
    const events = buildAlertLifecycleEvents({ auditRows });
    assert.deepEqual(
      events.map((event) => event.type),
      ["delivery_failed", "delivery_succeeded", "alert_queued"],
    );
    assert.ok(events.every((event) => event.source === "audit_events"));
    assert.equal(
      events.some((event) => event.type === "threshold_reached"),
      false,
    );
  });

  it("orders equal timestamps deterministically in lifecycle order", () => {
    const occurredAt = "2026-09-13T08:03:00.000Z";
    const events = buildAlertLifecycleEvents({
      queueRows: [queueRow({ created_at: occurredAt })],
      deliveryRows: [
        deliveryRow({ delivery_status: "success", sent_at: occurredAt }),
      ],
    });
    assert.deepEqual(
      events
        .filter((event) => event.occurred_at === occurredAt)
        .map((event) => event.type),
      ["delivery_succeeded", "alert_queued"],
    );
  });

  it("never fabricates current suppression decisions without persisted evidence", () => {
    const events = buildAlertLifecycleEvents({
      currentEligibility: { reason: "stale_import_threshold" },
    });
    assert.deepEqual(events, []);
  });

  it("redacts contact details, URLs, and generic secrets from errors", () => {
    const error = safeErrorMessage(
      "email ops@example.com or +49 151 23456789 failed at https://hooks.example.test/a password=hunter2",
    );
    assert.doesNotMatch(
      error,
      /ops@example\.com|49 151 23456789|hooks\.example|hunter2/,
    );
    assert.match(
      error,
      /EMAIL_REDACTED|PHONE_REDACTED|URL_REDACTED|REDACTED/,
    );
  });
});

describe("alert lifecycle fetching", () => {
  it("uses three bounded queries and paginates the combined read model", async () => {
    const calls = [];
    const query = async (sql, params) => {
      calls.push({ sql, params });
      if (sql.includes("alert-lifecycle:queue")) {
        return {
          rows: [
            queueRow(),
            queueRow({
              alert_id: 11,
              created_at: "2026-09-14T08:03:00.000Z",
              updated_at: "2026-09-14T08:03:00.000Z",
            }),
          ],
        };
      }
      return { rows: [] };
    };
    const page = await fetchAlertLifecycle(
      { workspaceId: "workspace-1", limit: 2, offset: 1 },
      query,
    );
    assert.equal(calls.length, 3);
    assert.ok(calls.every((call) => call.params.at(-1) === 4));
    assert.equal(page.items.length, 2);
    assert.equal(page.pagination.offset, 1);
    assert.equal(page.pagination.hasMore, true);
    assert.match(calls[0].sql, /t\.workspace_id = \$1/);
  });
});
