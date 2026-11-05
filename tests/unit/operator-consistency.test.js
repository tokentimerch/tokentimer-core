"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { renewEffect, hashRenewalIntent, hashPlan } = require("../../apps/api/services/operator/planEffects");
const { requestView, assistantPendingLimit } = require("../../apps/api/services/operator/renewRequests");
const { inspectOutbound } = require("../../packages/mcp/src/outbound");

test("preview keeps the actual renewal-loader name and expiry", () => {
  const effect = renewEffect({ certificate: { common_name: "api.example.com", not_after: "2026-12-01T00:00:00Z" } });
  assert.equal(effect.target.commonName.value, "api.example.com");
  assert.equal(effect.target.notAfter, "2026-12-01T00:00:00.000Z");
});
test("resolved renewal intent binds profile contents but ignores generated publication bookkeeping", () => {
  const payload = { renewalProfile: { sanPolicy: { sans: ["a.example.com"] } }, publication: { groupId: "group", materialVersionId: "one" } };
  assert.equal(hashRenewalIntent(payload), hashRenewalIntent({ ...payload, publication: { ...payload.publication, materialVersionId: "two" } }));
  assert.notEqual(hashRenewalIntent(payload), hashRenewalIntent({ ...payload, renewalProfile: { sanPolicy: { sans: ["b.example.com"] } } }));
});
test("temporary availability warnings do not invalidate preview consent", () => {
  const effect = renewEffect({ certificate: { common_name: "api.example.com" }, requireApprovalAlways: false });
  assert.equal(hashPlan({ effect }), hashPlan({ effect: { ...effect, warnings: ["paused"] } }));
  assert.notEqual(hashPlan({ effect }), hashPlan({ effect: { ...effect, standingRenewal: { ...effect.standingRenewal, futureRenewalsNeedApproval: true } } }));
});
test("unknown execution effect remains explicit and requires reconciliation", () => {
  const view = requestView({ id: "request", request_id: "retry" }, { id: "job", status: "orphaned_unknown_effect", error_code: "LEASE_EXPIRED" });
  assert.equal(view.state, "unknown_effect");
  assert.equal(view.stateReason, "reconciliation_required");
});

test("queued work is distinct from human approval and has no approval deadline", () => {
  const row = { id: "request", request_id: "retry", approval_expires_at: "2026-12-01T00:00:00Z" };
  assert.equal(requestView(row, { id: "job", status: "pending", approved_at: null }).state, "pending");
  assert.equal(requestView(row, { id: "job", status: "pending", approved_at: null }).approvalExpiresAt, null);
  assert.equal(requestView(row, { id: "job", status: "pending", approved_at: "2026-11-01T00:00:00Z" }).state, "approved");
  assert.equal(requestView(row, { id: "job", status: "pending_approval" }).approvalExpiresAt, "2026-12-01T00:00:00.000Z");
  for (const enabled of [false, true]) {
    assert.equal(renewEffect({ certificate: {}, requireApprovalAlways: enabled }).approvalAuthority, enabled ? "other_manager_or_admin" : "none");
  }
});
test("a low CA cap cannot be exhausted by waiting assistant requests", () => {
  assert.equal(assistantPendingLimit(1), 0);
  assert.equal(assistantPendingLimit(2), 1);
  assert.equal(assistantPendingLimit(5), 2);
});
test("enrollment grants are withheld even inside an allowed text field", () => {
  assert.equal(inspectOutbound({ commonName: { value: `ttopg_${"1".repeat(16)}_${"a".repeat(64)}`, untrusted: true, truncated: false } }).clean, false);
});
