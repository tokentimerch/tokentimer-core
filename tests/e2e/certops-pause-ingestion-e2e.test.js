/**
 * Supporting API/PostgreSQL qualification: workspace pause blocks new work while retaining owned result ingestion.
 * Run via scripts/certops-api-qualification.js with an explicitly disposable API stack.
 * The registered fixture sends genuine machine-protocol requests; it does not run
 * an installed native agent. Named strict reports and owned cleanup are mandatory. */
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os"), path = require("node:path"), { spawnSync } = require("node:child_process");
const { runDiscoveryScan } = require("../../packages/agent/src");
const { createApiFixture } = require("./helpers/certops-api-fixture");
const { createRegisteredAgent } = require("./helpers/certops-registered-agent");
const { createHostGate } = require("../../packages/agent/scripts/host-gate");
const scenarios = ["pause-ingestion-owned-claims", "pause-ingestion-audited-pause", "pause-ingestion-blocked-provision", "pause-ingestion-existing-result-evidence", "pause-ingestion-audited-resume", "pause-ingestion-cleanup", "pause-ingestion-native-discovery-observation"];
test("workspace pause blocks new work while retaining owned result ingestion", { timeout: 120000 }, async (t) => {
  const baseUrl = process.env.CERTOPS_CSR_API_URL;
  if (!baseUrl && process.env.CERTOPS_E2E_REQUIRED !== "1") {
    // skip-reason: no-host - requires disposable authenticated API PostgreSQL and signing keys
    t.skip("Disposable API required"); return;
  }
  assert.ok(baseUrl);
  const fixture = await createApiFixture(baseUrl);
  const prefix = `/api/v1/workspaces/${fixture.workspaceId}/certops`;
  const gate = createHostGate({ suite: "pause-ingestion-api", evidenceLevel: "integration", strict: process.env.CERTOPS_E2E_REQUIRED === "1", reportPath: process.env.CERTOPS_PAUSE_INGESTION_REPORT, requiredCapabilities: ["api", "postgres", "openssl"], fixtureSource: { file: "tests/e2e/certops-pause-ingestion-e2e.test.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") }, probeCapabilities: () => ({ api: { available: true }, postgres: { available: true }, openssl: { available: spawnSync("openssl", ["version"], { stdio: "ignore" }).status === 0 } }) });
  gate.report.executionScope = "Authenticated public pause and dispatch boundaries, protocol-reported noop evidence/results and actual native public-file discovery; no native certificate mutation";
  gate.report.fixtureSources = ["tests/e2e/certops-pause-ingestion-e2e.test.js", "tests/e2e/helpers/certops-registered-agent.js", "packages/agent/src/discovery/index.js", "packages/agent/src/index.js"].map(file => ({ file, sha256: crypto.createHash("sha256").update(fs.readFileSync(path.resolve(__dirname, "../..", file))).digest("hex") }));
  let ready = false, failure, agent, owned, waiting, discoveryRoot;
  const claim = () => agent.machine("jobs/claim", "claim", { maxJobs: 1, supportedActions: ["noop"] });
  const row = async (id) => (await fixture.pool.query("SELECT status,attempt_count FROM certificate_jobs WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, id])).rows[0];
  try {
    assert.equal(await gate.preflight(), true); ready = true;
    await gate.scenario(scenarios[0], async () => {
      agent = await createRegisteredAgent(fixture, baseUrl);
      owned = await agent.claimNoop();
      const created = await fixture.request(`${prefix}/jobs`, "POST", { operation: "noop" });
      assert.equal(created.status, 201); waiting = created.body.job.id;
    });
    await gate.scenario(scenarios[1], async () => {
      assert.equal((await fixture.request(`${prefix}/settings`, "PUT", { certOpsPaused: true, reason: "Qualification pause ingestion" })).status, 200);
      assert.equal((await fixture.request(`${prefix}/settings`, "PUT", { certOpsPaused: true, reason: "Qualification duplicate pause" })).status, 200);
      const audits = (await fixture.pool.query("SELECT metadata FROM audit_events WHERE workspace_id=$1 AND action='CERTOPS_WORKSPACE_PAUSED'", [fixture.workspaceId])).rows;
      assert.equal(audits.length, 1); assert.equal(audits[0].metadata.reason, "Qualification pause ingestion");
      const response = await claim(); assert.equal(response.status, 409); assert.equal(response.body.code, "CERTOPS_WORKSPACE_PAUSED");
      assert.deepEqual(await row(waiting), { status: "pending", attempt_count: 0 });
    });
    await gate.scenario(scenarios[2], async () => {
      for (const operation of ["noop", "issue"]) {
        const response = await fixture.request(`${prefix}/jobs`, "POST", { operation }); assert.equal(response.status, 409);
      }
      assert.equal((await fixture.request(`${prefix}/jobs`)).status, 200);
      assert.equal((await fixture.pool.query("SELECT count(*)::int AS count FROM managed_certificates WHERE workspace_id=$1", [fixture.workspaceId])).rows[0].count, 0);
    });
    await gate.scenario(scenarios[3], async () => {
      assert.equal((await agent.machine("heartbeat", "heartbeat", { agentVersion: "1.0.0" })).status, 200);
      const evidenceId = crypto.randomUUID();
      const evidence = await agent.machine("jobs/results", "evidence", { jobId: owned.jobId, claimId: owned.claimId, evidenceItems: [{ evidenceId, eventType: "policy.checked", observedAt: new Date().toISOString(), summary: "Protocol qualification noop policy observation" }] });
      assert.equal(evidence.status, 200); assert.equal(evidence.body.evidenceCount, 1);
      const result = await agent.machine("jobs/results", "result", { jobId: owned.jobId, attemptId: owned.job.attemptId, nonce: owned.job.nonce, status: "succeeded", keyRotated: false });
      assert.equal(result.status, 200); assert.equal((await row(owned.jobId)).status, "succeeded");
      assert.equal((await fixture.pool.query("SELECT count(*)::int AS count FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2", [fixture.workspaceId, owned.jobId])).rows[0].count, 1);
    });
    await gate.scenario("pause-ingestion-native-discovery-observation", async () => {
      // Exercise the real native public-file collector and authenticated machine
      // ingestion while paused. This is observation, not a seeded inventory row
      // or an installed Windows/service execution claim. Key material stays out
      // of the scanned directory and child output is never exposed.
      discoveryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "certops-paused-discovery-"));
      const publicDirectory = path.join(discoveryRoot, "public"); fs.mkdirSync(publicDirectory);
      const certificateFile = path.join(publicDirectory, "leaf.pem");
      const generated = spawnSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", path.join(discoveryRoot, "private.key"), "-out", certificateFile, "-subj", "/CN=paused-discovery.example.test", "-addext", "subjectAltName=DNS:paused-discovery.example.test", "-days", "2"], { timeout: 20000, stdio: "ignore" });
      assert.ifError(generated.error); assert.equal(generated.status, 0, "Owned public certificate generation required");
      const fingerprint = new crypto.X509Certificate(fs.readFileSync(certificateFile)).fingerprint256.replaceAll(":", "").toLowerCase();
      const jobState = async () => (await fixture.pool.query("SELECT id,status,attempt_count,claim_id FROM certificate_jobs WHERE workspace_id=$1 ORDER BY id", [fixture.workspaceId])).rows;
      const before = await jobState(); let reports = 0;
      const scan = await runDiscoveryScan({ directories: [publicDirectory], client: { async reportEvidence(body) {
        const response = await agent.machine("jobs/results", "evidence", { ...body, evidenceItems: body.evidenceItems.map(item => ({ ...item, evidenceId: crypto.randomUUID() })) });
        assert.equal(response.status, 200); reports++;
      } } });
      assert.equal(scan.observed, 1); assert.equal(scan.warnings, 0); assert.equal(reports, 1);
      const inventory = await fixture.request(`${prefix}/certificate-identities`); assert.equal(inventory.status, 200);
      const identity = inventory.body.items.find(item => item.fingerprintSha256 === fingerprint); assert.ok(identity, "Paused discovery must persist independently parsed public identity");
      const detail = await fixture.request(`${prefix}/certificate-identities/${identity.identityId}`); assert.equal(detail.status, 200);
      assert.ok(detail.body.certificate.locations.some(location => location.locationKind === "filesystem" && location.presenceState === "confirmed_present" && location.evidenceKind === "stored_copy"));
      assert.equal((await fixture.pool.query("SELECT count(*)::int AS count FROM certops_slot_observations WHERE workspace_id=$1", [fixture.workspaceId])).rows[0].count, 1);
      assert.deepEqual(await jobState(), before, "Passive discovery must not create a job or consume an execution attempt");
      assert.equal((await fixture.pool.query("SELECT count(*)::int AS count FROM audit_events WHERE workspace_id=$1 AND action='CERTOPS_WORKSPACE_PAUSED'", [fixture.workspaceId])).rows[0].count, 1);
      assert.equal((await claim()).status, 409); assert.deepEqual(await row(waiting), { status: "pending", attempt_count: 0 });
    }, { oracle: "Real filesystem public certificate discovery is accepted by authenticated agent ingestion during pause, persists independent fingerprint and exact stored-copy location, and creates no job/attempt or extra pause audit" });
    await gate.scenario(scenarios[4], async () => {
      assert.equal((await fixture.request(`${prefix}/settings`, "PUT", { certOpsPaused: false, reason: "Qualification resume ingestion" })).status, 200);
      const audits = (await fixture.pool.query("SELECT metadata FROM audit_events WHERE workspace_id=$1 AND action='CERTOPS_WORKSPACE_RESUMED'", [fixture.workspaceId])).rows;
      assert.equal(audits.length, 1); assert.equal(audits[0].metadata.reason, "Qualification resume ingestion");
      const response = await claim(); assert.equal(response.status, 200); assert.equal(response.body.jobs.length, 1); assert.equal(response.body.jobs[0].jobId, waiting);
      assert.deepEqual(await row(waiting), { status: "claimed", attempt_count: 1 });
    });
  } catch (error) { failure = error; }
  finally {
    const cleanup = async () => {
      const errors = []; try { await fixture.cleanup(); } catch (error) { errors.push(error); }
      try { if (discoveryRoot) { assert.equal(path.dirname(path.resolve(discoveryRoot)), path.resolve(os.tmpdir())); assert.ok(path.basename(discoveryRoot).startsWith("certops-paused-discovery-")); fs.rmSync(discoveryRoot, { recursive: true }); assert.equal(fs.existsSync(discoveryRoot), false); } } catch (error) { errors.push(error); }
      if (errors.length) throw new AggregateError(errors, "Paused discovery owned cleanup failed");
    };
    try { if (ready) await gate.scenario(scenarios[5], cleanup); else await cleanup(); } catch (error) { failure = failure ? new AggregateError([failure, error], "Pause qualification cleanup failed") : error; }
    try { if (ready) await gate.finish({ requiredScenarios: scenarios }); } catch (error) { failure = failure ? new AggregateError([failure, error], "Pause qualification incomplete") : error; }
  }
  if (failure) throw failure;
});
