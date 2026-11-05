"use strict";
const { test, mock } = require("node:test");
const assert = require("node:assert/strict");
const router = require("../../apps/api/routes/certops-enrollments");
const db = require("../../apps/api/db/database");
const killSwitch = require("../../apps/api/services/certops/workspaceKillSwitch");
const recovery = require("../../apps/api/services/certops/acmeStorePersistence");
const route = router.stack.find(layer => layer.route?.path?.includes("acme-store-enrollments") && layer.route.methods.post).route;
const session = route.stack[2].handle, handler = route.stack.at(-1).handle;
const lookup = router.stack.find(layer => layer.route?.path?.includes("acme-store-enrollments") && layer.route.methods.get).route.stack.at(-1).handle;
const id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
function response() { return { statusCode: 200, status(code) { this.statusCode = code; return this; }, json(body) { this.body = body; return this; } }; }
test("recovery requires a human session and an explicit acknowledgement", async () => {
  for (const req of [{ isWorkerCall: true, user: { id: 1 } }, { user: null }]) {
    const res = response(); session(req, res, () => assert.fail("must not authorize")); assert.equal(res.statusCode, 403);
  }
  for (const body of [{ orphanedJobId: id, reason: "reviewed" }, { orphanedJobId: id, acknowledgeUnknownEffect: true, injected: true }]) {
    const res = response(); await handler({ params: { enrollmentId: id }, body }, res); assert.equal(res.statusCode, 400);
  }
});
test("recovery locks owner before workspace, commits atomically and rolls back errors", async () => {
  const calls = [];
  const client = { query: async sql => { calls.push(String(sql)); }, release: () => calls.push("release") };
  const poolStub = mock.method(db.pool, "connect", async () => client);
  const lockStub = mock.method(killSwitch, "lockWorkspaceForCertOpsSideEffect", async () => calls.push("workspace"));
  const recoverStub = mock.method(recovery, "continueAcmeStoreEnrollmentTx", async args => {
    assert.equal(args.actorUserId, 3); assert.equal(args.acknowledgeUnknownEffect, true);
    calls.push("recovery"); return { created: true, jobId: id };
  });
  try {
    const req = { workspace: { id }, user: { id: 3 }, params: { enrollmentId: id }, body: { orphanedJobId: id, reason: "reviewed", acknowledgeUnknownEffect: true } };
    const res = response(); await handler(req, res);
    assert.equal(res.statusCode, 201); assert.equal(calls[0], "BEGIN"); assert.match(calls[1], /FOR SHARE OF a/);
    assert.deepEqual(calls.slice(2), ["workspace", "recovery", "COMMIT", "release"]);
    calls.length = 0; recoverStub.mock.mockImplementation(async () => { throw new Error("audit failed"); });
    const failed = response(); await handler(req, failed); assert.equal(failed.statusCode, 500); assert.ok(calls.includes("ROLLBACK")); assert.ok(!calls.includes("COMMIT"));
  } finally { poolStub.mock.restore(); lockStub.mock.restore(); recoverStub.mock.restore(); }
});
test("lookup is scoped to workspace and returns only recovery state", async () => {
  const query = mock.method(db.pool, "query", async (sql, params) => {
    assert.match(sql, /e.workspace_id=\$1/); assert.deepEqual(params, [id, id]);
    return { rows: [{ id, current_job_id: id, status: "orphaned_unknown_effect", needs_operator_reconciliation: true, state: "submitting", secret: "not returned" }] };
  });
  try {
    const res = response(); await lookup({ workspace: { id }, params: { jobId: id } }, res);
    assert.deepEqual(res.body, { enrollmentId: id, state: "submitting", outcomeUncertain: true, recoveryAvailable: true });
    query.mock.mockImplementation(async () => ({ rows: [{ id, current_job_id: id, status: "orphaned_unknown_effect", needs_operator_reconciliation: true, state: "installed" }] }));
    const installed = response(); await lookup({ workspace: { id }, params: { jobId: id } }, installed);
    assert.equal(installed.body.recoveryAvailable, true, "lost installation acknowledgement must allow proof replay");
    query.mock.mockImplementation(async () => ({ rows: [] }));
    const missing = response(); await lookup({ workspace: { id }, params: { jobId: id } }, missing); assert.equal(missing.statusCode, 404);
  } finally { query.mock.restore(); }
});
