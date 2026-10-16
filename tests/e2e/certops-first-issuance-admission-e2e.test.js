/**
 * Supporting API/PostgreSQL qualification: public first issuance retains period and fresh execution admission fences.
 * Run via scripts/certops-api-qualification.js with an explicitly disposable API stack.
 * The registered fixture sends genuine machine-protocol requests; it does not run
 * an installed native agent. Named strict reports and owned cleanup are mandatory. */
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto"), fs = require("node:fs"), path = require("node:path"), os = require("node:os");
const { createApiFixture } = require("./helpers/certops-api-fixture");
const { createRegisteredAgent } = require("./helpers/certops-registered-agent");
const { createHostGate } = require("../../packages/agent/scripts/host-gate");
const { verifyJobSignature } = require("../../packages/agent/src/signing");
const scenarios = ["first-issue-public-provisioning", "first-issue-binding-capability-refusal", "first-issue-stopped-period-refusal", "first-issue-routing-refusal", "first-issue-signed-admission", "first-issue-cleanup"];
test("public first issuance retains period and fresh execution admission fences", { timeout: 120000 }, async (t) => {
  const baseUrl = process.env.CERTOPS_CSR_API_URL;
  if (!baseUrl && process.env.CERTOPS_E2E_REQUIRED !== "1") {
    // skip-reason: no-host - requires disposable authenticated API PostgreSQL and signing keys
    t.skip("Disposable API and signing configuration required"); return;
  }
  assert.ok(baseUrl); const fixture = await createApiFixture(baseUrl);
  const prefix = `/api/v1/workspaces/${fixture.workspaceId}/certops`, domain = "first-issue.example.test", provider = "pebble-challtestsrv", command = "qualification-admission";
  const gate = createHostGate({ suite: "first-issuance-admission-api", evidenceLevel: "integration", strict: process.env.CERTOPS_E2E_REQUIRED === "1", reportPath: process.env.CERTOPS_FIRST_ISSUANCE_ADMISSION_REPORT, requiredCapabilities: ["api", "postgres"], fixtureSource: { file: "tests/e2e/certops-first-issuance-admission-e2e.test.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") }, probeCapabilities: () => ({ api: { available: true }, postgres: { available: true } }) });
  gate.report.executionScope = "Actual public issuance admission and authenticated signed dispatch; no issuer contact, native key generation or installation";
  let agent, stopped, allowed, heartbeat, ready = false, failure;
  const create = async () => {
    const response = await fixture.request(`${prefix}/jobs`, "POST", { operation: "issue", idempotencyKey: crypto.randomUUID(), payload: { sans: [domain], target: { type: "domain", reference: domain }, certPath: path.join(os.tmpdir(), `certops-first-admission-${crypto.randomUUID()}`, "leaf.pem"), caEndpoint: "https://qualification.invalid/directory", commandRef: command, acmeKind: "certbot", dnsZone: "example.test", dnsProvider: provider } });
    assert.equal(response.status, 201); return response.body.job;
  };
  const claim = async (dnsProvider = provider) => {
    const response = await agent.machine("jobs/claim", "claim", { maxJobs: 10, supportedActions: ["renew"], supportedDnsProviders: [dnsProvider] });
    assert.equal(response.status, 200); return response.body.jobs;
  };
  const advertise = async (targets = [domain], commands = [command]) => {
    const response = await agent.machine("heartbeat", "heartbeat", { agentVersion: "1.0.0", declaredCapabilities: ["evidence-claim-binding-v1"], declaredTargetSelectors: targets, declaredCommandProfileNames: commands, supportedDnsProviders: [provider] });
    assert.equal(response.status, 200); heartbeat = response.body;
  };
  const row = async (id) => (await fixture.pool.query("SELECT status,attempt_count FROM certificate_jobs WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, id])).rows[0];
  try {
    assert.equal(await gate.preflight(), true); ready = true;
    await gate.scenario(scenarios[0], async () => {
      stopped = await create(); assert.equal(stopped.status, "pending");
      const certificate = (await fixture.pool.query("SELECT status FROM managed_certificates WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, stopped.subjectId])).rows[0]; assert.equal(certificate.status, "provisioning");
      const periods = (await fixture.pool.query("SELECT id FROM certops_management_periods WHERE workspace_id=$1 AND managed_certificate_id=$2 AND ended_at IS NULL", [fixture.workspaceId, stopped.subjectId])).rows; assert.equal(periods.length, 1); stopped.periodId = periods[0].id;
      agent = await createRegisteredAgent(fixture, baseUrl, [], { declaredTargetSelectors: [domain], declaredCommandProfileNames: [command], supportedDnsProviders: [provider] });
    });
    await gate.scenario(scenarios[1], async () => {
      assert.deepEqual(await claim(), []); assert.deepEqual(await row(stopped.id), { status: "pending", attempt_count: 0 });
    });
    await gate.scenario(scenarios[2], async () => {
      assert.equal((await fixture.request(`${prefix}/management-periods/${stopped.periodId}/stop`, "POST", {})).status, 200);
      await advertise(); assert.deepEqual(await claim(), []); assert.deepEqual(await row(stopped.id), { status: "cancelled", attempt_count: 0 });
      assert.ok((await fixture.pool.query("SELECT ended_at FROM certops_management_periods WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, stopped.periodId])).rows[0].ended_at);
    });
    await gate.scenario(scenarios[3], async () => {
      allowed = await create();
      assert.deepEqual(await claim("cloudflare"), []);
      await advertise(["outside.example.test"]); assert.deepEqual(await claim(), []);
      await advertise([domain], ["unqualified-command"]); assert.deepEqual(await claim(), []);
      await advertise([domain], []); assert.deepEqual(await claim(), []);
      assert.deepEqual((await fixture.pool.query("SELECT declared_command_profile_names FROM certops_agents WHERE agent_id=$1", [agent.agentId])).rows[0].declared_command_profile_names, []);
      assert.deepEqual(await row(allowed.id), { status: "pending", attempt_count: 0 });
    });
    await gate.scenario(scenarios[4], async () => {
      await advertise(); const jobs = await claim(); assert.equal(jobs.length, 1);
      const job = jobs[0]; assert.equal(job.jobId, allowed.id); assert.equal(job.action, "renew"); assert.equal(job.agentId, agent.agentId); assert.equal(job.certificateId, allowed.subjectId);
      assert.ok(job.claimId); assert.equal(verifyJobSignature({ job, publicKeyPem: heartbeat.signingPublicKeyPem, pinnedSigningKeyId: heartbeat.signingKeyId }).allowed, true);
      assert.deepEqual(await row(allowed.id), { status: "claimed", attempt_count: 1 }); assert.deepEqual(await row(stopped.id), { status: "cancelled", attempt_count: 0 });
      assert.equal((await fixture.pool.query("SELECT count(*)::int AS count FROM certificate_evidence WHERE workspace_id=$1", [fixture.workspaceId])).rows[0].count, 0);
    });
  } catch (error) { failure = error; }
  finally {
    try { if (ready) { await gate.scenario(scenarios.at(-1), fixture.cleanup); await gate.finish({ requiredScenarios: scenarios }); } else await fixture.cleanup(); }
    catch (error) { failure = failure ? new AggregateError([failure, error], "First issuance qualification and cleanup failed") : error; }
  }
  if (failure) throw failure;
});
