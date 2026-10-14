"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const { createApiFixture } = require("./helpers/certops-api-fixture");
const { createHostGate } = require("../../packages/agent/scripts/host-gate");
test("manual job approval and pause boundaries through real API", { timeout: 120000 }, async (t) => {
  const baseUrl = process.env.CERTOPS_CSR_API_URL;
  if (!baseUrl && process.env.CERTOPS_E2E_REQUIRED !== "1") {
    // skip-reason: no-host - requires isolated authenticated API and PostgreSQL
    t.skip("Disposable API URL required"); return;
  }
  assert.ok(baseUrl); const fixture = await createApiFixture(baseUrl);
  let approver; let ready = false; let primaryError;
  const gate = createHostGate({ suite: "jobs-api-boundaries", strict: process.env.CERTOPS_E2E_REQUIRED === "1", evidenceLevel: "integration", reportPath: process.env.CERTOPS_JOBS_API_REPORT, requiredCapabilities: ["api", "postgres"], probeCapabilities: async () => ({ api: { available: true }, postgres: { available: true } }) });
  gate.report.fixtureSource = { file: "tests/e2e/certops-jobs-api-e2e.test.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") };
  gate.report.artifactQualification = process.env.GITHUB_ACTIONS === "true" ? "workflow-checkout-source" : "local-worktree-source-baseline-sha-only";
  const prefix = `/api/v1/workspaces/${fixture.workspaceId}/certops`;
  let jobId;
  try {
    assert.equal(await gate.preflight(), true); ready = true;
    approver = await createApiFixture(baseUrl);
    await fixture.pool.query("INSERT INTO workspace_memberships(workspace_id,user_id,role) VALUES ($1,$2,'workspace_manager')", [fixture.workspaceId, approver.userId]);
    await gate.scenario("jobs-api-approval-create-idempotency", async () => {
      assert.equal((await fixture.request(`${prefix}/settings`, "PUT", { certOpsRequireApprovalAlways: true, reason: "Qualification approval policy" })).status, 200);
      const input = { operation: "noop", idempotencyKey: crypto.randomUUID(), source: "executor" };
      const created = await fixture.request(`${prefix}/jobs`, "POST", input); assert.equal(created.status, 201); jobId = created.body.job.id;
      assert.equal(created.body.job.status, "pending_approval"); assert.equal(created.body.job.source, "api");
      assert.equal((await fixture.request(`${prefix}/jobs`, "POST", input)).body.job.id, jobId);
      assert.equal((await fixture.pool.query("SELECT count(*)::int AS count FROM audit_events WHERE workspace_id=$1 AND action='CERTOPS_JOB_CREATED_MANUAL' AND metadata->>'jobId'=$2", [fixture.workspaceId, jobId])).rows[0].count, 1);
    });
    await gate.scenario("jobs-api-self-approval-refusal", async () => {
      const result = await fixture.request(`${prefix}/jobs/${jobId}/approve`, "POST", { reason: "Self approval forbidden" }); assert.equal(result.status, 403); assert.equal(result.body.code, "CERTOPS_APPROVAL_SELF_APPROVAL_FORBIDDEN");
    });
    await gate.scenario("jobs-api-paused-approval-binding", async () => {
      assert.equal((await fixture.request(`${prefix}/settings`, "PUT", { certOpsPaused: true, reason: "Qualification pause" })).status, 200);
      assert.equal((await fixture.request(`${prefix}/jobs`, "POST", { operation: "noop" })).status, 409);
      assert.equal((await fixture.request(`${prefix}/jobs`)).status, 200);
      const approved = await approver.request(`${prefix}/jobs/${jobId}/approve`, "POST", { reason: "Independent approval while claims remain paused" }); assert.equal(approved.status, 200);
      const stored = (await fixture.pool.query("SELECT status,payload,approved_payload_hash,approved_by_user_id FROM certificate_jobs WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, jobId])).rows[0];
      assert.equal(stored.status, "pending"); assert.equal(stored.approved_by_user_id, approver.userId);
      const { canonicalizeJobPayload } = require("../../packages/contracts/certops/canonical-json.cjs");
      assert.equal(stored.approved_payload_hash, crypto.createHash("sha256").update(canonicalizeJobPayload(stored.payload)).digest("hex"));
      assert.equal((await approver.request(`${prefix}/jobs/${jobId}/approve`, "POST", { reason: "Repeated approval" })).status, 409);
      assert.equal((await fixture.request(`${prefix}/settings`, "PUT", { certOpsPaused: false, reason: "Qualification resume" })).status, 200);
    });
    await gate.scenario("jobs-api-private-material-refusal", async () => {
      assert.equal((await fixture.request(`${prefix}/jobs`, "POST", { operation: "noop", payload: { privateKeyPem: "-----BEGIN PRIVATE KEY-----\nfixture\n-----END PRIVATE KEY-----" } })).status, 422);
    });
    await gate.scenario("jobs-api-bulk-shape-atomic-refusal", async () => {
      const before = (await fixture.pool.query("SELECT count(*)::int AS count FROM certificate_jobs WHERE workspace_id=$1", [fixture.workspaceId])).rows[0].count;
      for (const input of [{ certificateIds: [] }, { certificateIds: ["invalid"] }, { certificateIds: [jobId, jobId] }]) assert.equal((await fixture.request(`${prefix}/jobs/bulk-renew`, "POST", input)).status, 400);
      assert.equal((await fixture.pool.query("SELECT count(*)::int AS count FROM certificate_jobs WHERE workspace_id=$1", [fixture.workspaceId])).rows[0].count, before);
    });
  } catch (error) { primaryError = error; throw error; }
  finally {
    const cleanup = async () => { try { await fixture.cleanup(); } finally { if (approver) await approver.cleanup(); } };
    try { if (ready) { await gate.scenario("jobs-api-cleanup", cleanup); await gate.finish({ requiredScenarios: require("../../docs/certops/qualification-suites.json").suites["jobs-api-boundaries"] }); } else await cleanup(); }
    catch (error) { if (primaryError) throw new AggregateError([primaryError, error], "Jobs API journey and finalization failed"); throw error; }
  }
});
