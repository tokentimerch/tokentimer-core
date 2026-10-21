/**
 * Qualification: native Linux certificate dry-run
 *
 * Four certificate operations augment the signed noop dry-run using the actual Linux
 * agent/API/Postgres, genuine CA-signed fixtures, restrictive custody files, a retained
 * TLS listener and independent command/gateway counters. Positive controls must prove
 * the configured path could mutate before refusal is useful. The generic public job
 * route does not expose mode: call production createCertificateJob with mode: "dry_run"
 * while retaining public certificate import, real signing, native claim/lease/result
 * processing and persisted evidence. Never fabricate jobs, dispatches, nonces, success
 * or evidence rows. These are native certificate-operation refusal checks, not public
 * mode-selection coverage.
 */
/**
 * Qualification: foreground native agent faults
 *
 * Run separate trusted-main certops-native-agent-qualification.yml against migrated
 * API/Postgres on disposable Ubuntu 24.04; retain actual 300 seconds test bound rather
 * than central API timeout. Real candidate process/signing/lease/state cover
 * registration/private credentials, signed noop/dry-run, command-policy refusal, restart
 * with pin/credential, tampered payload/signature/unknown key, cross-agent valid-claim
 * misdelivery, initial lease loss, outbox retry, replay refusal, real logs across
 * restart, corrupt pin, observe-only and cleanup. Follow advertised wire capabilities;
 * do not claim v2 from this source. Public admission is normal noop; dry-run uses
 * production creator because public generic jobs lack that mode. Harmless operations do
 * not qualify native cert/service. Loopback HTTP 503, HTTP 429 and connection-reset
 * faults, lost committed-ack, recursive HTTP 413 splitting and one permanently rejected
 * split line must preserve ordered unique real log sequences, one attempt, completed
 * streams and successful jobs. Require cached exact original ack/no duplicate storage;
 * single-line rejection means one agent gap, zero server drops/no double count. Never
 * inject diagnostic lines. One-second polling and three-second heartbeats respect
 * production machine-token budget; observe-only waits for real 200 heartbeat and
 * persisted empty operation declaration. Genuine allowlisted validate/reload children
 * emit generated secret sentinels to both streams; private receipts prove emission while
 * public logs, DB evidence/results and parent console contain neither sentinels nor raw
 * child markers. This tests output withholding, not child-output streaming or
 * certificate execution. Short-expiry control re-signs actual claimed job/agent/attempt
 * with production nonceTtlSeconds: 2, holds response >=5 monotonic seconds, uses fresh
 * actual HTTP Date and temporary1ms local tolerance then exact restoration. No
 * clocks/journal/expiry rows are rewritten. Agent must refuse before first
 * lease/success; real 409 result nonce may leave original job claimed, so require exact
 * rejection in dead-letter outbox, not invented server rejection. Fresh claim must
 * succeed with same pin/credential. This is shortened signing-fixture expiry, not
 * stock-window or Windows SCM proof. Source-bound sanitized report only; drain owned
 * children/temp/workspace and always destroy stack. Local baseline runs/pure checks
 * cannot qualify hosted release cells.
 */
// Shared execution, evidence and cleanup policy: docs/certops/e2e-qualification.md.
/**
 * Run the production Linux agent against the real API/PostgreSQL disposable stack.
 * certops-native-agent-qualification.yml supplies an isolated runtime. Actual child restart, lease
 * loss, credential handling and log transport faults are observed with persisted
 * oracles and owned cleanup; no Windows SCM or native certificate issuance is implied. */
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const http = require("node:http");
const crypto = require("node:crypto");
const { spawn, spawnSync } = require("node:child_process");
const { createApiFixture } = require("./helpers/certops-api-fixture");
const { createRegisteredAgent } = require("./helpers/certops-registered-agent");
const { createHostGate } = require("../../packages/agent/scripts/host-gate");
const { createNativeLogFaults, cases: logFaultCases } = require("./helpers/certops-native-log-faults");
const logFaults = createNativeLogFaults();
const { qualifyNativeLogPrivacy } = require("./helpers/certops-native-log-privacy");
const { qualifyNativeCertificateDryRun, scenarios: certificateDryRunScenarios } = require("./helpers/certops-native-certificate-dry-run");
const { SCENARIO: timingScenario, createNativeDispatchTiming } = require("./helpers/certops-native-dispatch-timing");
const scenarios = ["native-agent-registration", "native-agent-signed-noop", "native-agent-signed-dry-run", "native-agent-restart-state", "native-agent-untrusted-claims", "native-agent-initial-lease-failure", "native-agent-outbox-restart", "native-agent-corrupt-pin", "native-agent-observe-only", "native-agent-local-command-policy", "native-agent-cross-agent-binding", "native-agent-durable-replay", "native-agent-real-log-persistence", ...logFaultCases.map(([id]) => id), "native-agent-child-output-confidentiality", timingScenario, ...certificateDryRunScenarios, "native-agent-cleanup"];
async function wait(check, timeout = 30000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) { if (await check()) return; await new Promise((resolve) => setTimeout(resolve, 100)); }
  throw new Error("Actual native agent fixture exceeded its deadline");
}
test("real native agent signed gates durable outbox restart and observe-only behavior", { timeout: 300000 }, async (t) => {
  const baseUrl = process.env.CERTOPS_CSR_API_URL;
  if (!baseUrl && process.env.CERTOPS_E2E_REQUIRED !== "1") {
    // skip-reason: no-host - requires disposable real API PostgreSQL and Linux agent process
    t.skip("Disposable real API and PostgreSQL required"); return;
  }
  assert.ok(baseUrl); assert.equal(process.platform, "linux"); assert.equal(process.env.CERTOPS_NATIVE_AGENT_DISPOSABLE_STACK, "1");
  const fixture = await createApiFixture(baseUrl);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "certops-native-agent-"));
  const configDir = path.join(root, "state"); fs.mkdirSync(configDir, { mode: 0o700 });
  const agentId = crypto.randomUUID(), prefix = `/api/v1/workspaces/${fixture.workspaceId}/certops`;
  const gate = createHostGate({ suite: "native-agent-api", evidenceLevel: "e2e", strict: true, reportPath: process.env.CERTOPS_NATIVE_AGENT_REPORT || process.env.CERTOPS_QUALIFICATION_REPORT, requiredCapabilities: ["api", "postgres", "native-node-agent", "openssl"], fixtureSource: { file: "tests/e2e/certops-native-agent-e2e.test.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") }, probeCapabilities: async () => ({ api: { available: (await fetch(new URL("/", baseUrl))).status === 200 }, postgres: { available: (await fixture.pool.query("SELECT 1")).rows.length === 1 }, "native-node-agent": { available: process.platform === "linux" && fs.existsSync(path.resolve(__dirname, "../../packages/agent/bin/tokentimer-agent.js")) }, openssl: { available: spawnSync("openssl", ["version"], { stdio: "ignore", timeout: 5000 }).status === 0 } }) });
  gate.report.executionScope = "Unmodified native Node agent with real API signing leases results and persisted state; deliberate loopback transport faults, harmless noop jobs, local certificate dry-run/deploy and explicit command sentinels; no live CA/DNS-provider or Windows qualification";
  gate.report.artifactQualification = process.env.GITHUB_ACTIONS === "true" ? "workflow-checkout-source" : "local-worktree-source-baseline-sha-only";
  let mode = "normal", agent, proxy, ready = false, failure, cleanup = "failed";
  let clockRejections=0;
  let rejected = 0, bindingRejected = 0, misdeliveredJob, capturedOwnJob, replayRejections = 0, heartbeatCount = 0, claimCount = 0, blockedResults = 0, blockedLeases = 0, leak = false;
  const heartbeatFacts = { declaredOperations: -1, lastStatus: 0, acceptedObserveOnly: 0 };
  const prohibited = new Set(), counters = new Map(), children = [];
  const count = (jobId, field) => { const row = counters.get(jobId) || { results: 0, evidence: 0, leases: 0, mutations: 0 }; row[field]++; counters.set(jobId, row); };
  const row = async (id) => (await fixture.pool.query("SELECT status,attempt_count,claim_id,result_metadata FROM certificate_jobs WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, id])).rows[0];
  const agentRow = async () => (await fixture.pool.query("SELECT id,last_seen_at,supported_operations FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2", [fixture.workspaceId, agentId])).rows[0];
  const hashFile = (file) => crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
  const files = () => fs.existsSync(path.join(configDir, "outbox")) ? fs.readdirSync(path.join(configDir, "outbox")).filter((file) => file.endsWith(".json")) : [];
  async function stop(child = agent) {
    if (!child?.pid || child.exitCode !== null || child.signalCode !== null) return;
    child.kill("SIGTERM");
    try { await wait(() => child.exitCode !== null || child.signalCode !== null, 5000); }
    catch { child.kill("SIGKILL"); await wait(() => child.exitCode !== null || child.signalCode !== null, 5000); }
  }
  function configure(enabled = true) {
    // Keep the expanded fault suite within the real 120/minute machine-token
    // budget instead of raising or bypassing the server's production limiter.
    fs.writeFileSync(path.join(configDir, "config.json"), JSON.stringify({ serverUrl: `http://127.0.0.1:${proxy.address().port}`, agentId, allowInsecureLocalHttp: true, pollIntervalMs: 1000, heartbeatIntervalMs: 3000, discovery: null, windowsDiscovery: { enabled: false }, execution: { enabled, dryRun: false }, policy: { allowedPaths: [root], allowedCommands: {} } }), { mode: 0o600 });
  }
  function start(bootstrap) {
    const env = { PATH: process.env.PATH, HOME: process.env.HOME, LANG: "C.UTF-8", TOKENTIMER_AGENT_CONFIG_DIR: configDir, ...(process.env.NODE_PATH ? { NODE_PATH: process.env.NODE_PATH } : {}), ...(bootstrap ? { TOKENTIMER_AGENT_BOOTSTRAP_TOKEN: bootstrap.plaintextToken, TOKENTIMER_AGENT_BOOTSTRAP_TOKEN_ID: String(bootstrap.token.id) } : {}) };
    if (bootstrap) prohibited.add(bootstrap.plaintextToken);
    const child = spawn(process.execPath, [path.resolve(__dirname, "../../packages/agent/bin/tokentimer-agent.js")], { env, stdio: ["ignore", "pipe", "pipe"] }); children.push(child); agent = child;
    let tail = "";
    const inspect = (chunk) => {
      const text = tail + chunk.toString();
      for (const secret of prohibited) if (text.includes(secret)) leak = true;
      if (/-----BEGIN [^-]*PRIVATE KEY-----/.test(text)) leak = true;
      const complete = text.split(/\r?\n/); tail = complete.pop().slice(-1024);
      rejected += complete.filter((line) => line.includes("claimed job failed signature verification")).length;
      clockRejections+=complete.filter(line=>line.includes("rejected: clock_drift_suspected")).length;
      bindingRejected += complete.filter((line) => line.includes("agent-id binding gate rejected a claimed job")).length;
    };
    child.stdout.on("data", inspect); child.stderr.on("data", inspect); child.on("error", () => {}); return child;
  }
  async function create(modeValue = "real") {
    if (modeValue === "dry_run") {
      // The public generic job route intentionally creates real jobs. Exercise
      // the production scheduler/service admission for a signed dry-run noop.
      const { createCertificateJob } = require("../../apps/api/services/certops/jobs");
      const job = await createCertificateJob({ client: fixture.pool, workspaceId: fixture.workspaceId, operation: "noop", source: "api", mode: "dry_run", requestedByUserId: fixture.userId });
      assert.equal(job.mode, "dry_run"); return job.id;
    }
    const response = await fixture.request(`${prefix}/jobs`, "POST", { operation: "noop", mode: modeValue }); assert.equal(response.status, 201); return response.body.job.id;
  }
  const timing=createNativeDispatchTiming({fixture,agentRow,configDir,stop,start,wait,row,create,counters,getClockRejections:()=>clockRejections});
  try {
    await gate.preflight(); ready = true;
    proxy = http.createServer((request, response) => {
      const faultMode = mode; const chunks = []; let size = 0;
      const respond = (status, output = Buffer.alloc(0), headers = {}) => { if (!response.destroyed && !response.writableEnded && !response.headersSent) response.writeHead(status, { "content-type": "application/json", "content-length": output.length, ...headers }).end(output); };
      request.on("data", (chunk) => { size += chunk.length; if (size > 1048576) request.destroy(); else chunks.push(chunk); });
      request.on("end", () => {
        if (request.method !== "POST" || !request.url.startsWith("/api/v1/certops/agent/")) { respond(403); return; }
        const body = Buffer.concat(chunks); let parsed;
        try { parsed = JSON.parse(body.toString()); } catch { respond(400); return; }
        if (logFaults.incoming(request.url, parsed, response, respond)) return;
        const jobId = parsed.body?.jobId || request.url.match(/jobs\/([^/]+)\/lease/)?.[1];
        if (request.url.endsWith("/heartbeat")) { heartbeatCount++; heartbeatFacts.declaredOperations = Array.isArray(parsed.body?.supportedOperations) ? parsed.body.supportedOperations.length : -1; }
        if (request.url.endsWith("/claim")) claimCount++;
        if (jobId && request.url.endsWith("/results")) count(jobId, parsed.messageType === "evidence" ? "evidence" : "results");
        if (jobId && parsed.messageType === "result" && parsed.body.rejectionReason === "job_replay_rejected") replayRejections++;
        if (jobId && request.url.endsWith("/lease")) count(jobId, "leases");
        if ((faultMode === "lease-unavailable" && request.url.endsWith("/lease")) || (faultMode === "results-unavailable" && request.url.endsWith("/results"))) {
          if (faultMode === "lease-unavailable") blockedLeases++; else blockedResults++;
          respond(503, Buffer.from(JSON.stringify({ error: "Qualification transport interruption" }))); return;
        }
        const upstream = http.request(new URL(request.url, baseUrl), { method: "POST", headers: { "content-type": "application/json", authorization: request.headers.authorization, "accept-encoding": "identity" }, timeout: 15000 }, (reply) => {
          const parts = []; let length = 0;
          reply.on("data", (chunk) => { length += chunk.length; if (length > 1048576) reply.destroy(); else parts.push(chunk); });
          reply.on("end", async () => {
            let output = Buffer.concat(parts);
            try {
              timing.observedReply(request.url,parsed,reply.statusCode,output);
              if(await timing.replied(request.url,reply.statusCode,output,respond))return;
              if (request.url.endsWith("/heartbeat")) { heartbeatFacts.lastStatus = reply.statusCode; if (reply.statusCode === 200 && Array.isArray(parsed.body?.supportedOperations) && parsed.body.supportedOperations.length === 0) heartbeatFacts.acceptedObserveOnly++; }
              if (request.url.endsWith("/claim") && faultMode === "normal" && !capturedOwnJob) {
                const envelope = JSON.parse(output.toString());
                if (envelope.jobs?.length) capturedOwnJob = structuredClone(envelope.jobs[0]);
              }
              if (request.url.endsWith("/claim") && ["foreign-agent", "replay-own"].includes(faultMode)) {
                const envelope = JSON.parse(output.toString());
                assert.deepEqual(envelope.jobs, []);
                const captured = faultMode === "foreign-agent" ? misdeliveredJob : capturedOwnJob;
                count(captured.jobId, "mutations"); envelope.jobs = [captured];
                output = Buffer.from(JSON.stringify(envelope));
              }
              if (request.url.endsWith("/claim") && ["payload", "signature", "unknown-key"].includes(faultMode)) {
                const envelope = JSON.parse(output.toString());
                for (const job of envelope.jobs || []) {
                  const v2 = job.envelopeVersion === 2;
                  const payload = v2 ? JSON.parse(Buffer.from(job.payloadB64, "base64").toString()) : job;
                  assert.ok(payload.jobId); count(payload.jobId, "mutations");
                  if (faultMode === "payload") { payload.subjectId = "altered-in-transit"; if (v2) job.payloadB64 = Buffer.from(JSON.stringify(payload)).toString("base64"); }
                  else if (faultMode === "signature") job[v2 ? "signatureB64" : "signature"] = crypto.randomBytes(64).toString("base64");
                  else job.signingKeyId = "qualification-unknown-key";
                }
                output = Buffer.from(JSON.stringify(envelope));
              }
              if (logFaults.replied(request.url, parsed, reply.statusCode, output, response)) return;
              respond(reply.statusCode, output);
            } catch(error) { timing.failed(error);respond(502); }
          }); reply.on("error", () => respond(502));
        });
        request.on("aborted", () => upstream.destroy()); response.on("close", () => { if (!response.writableFinished) upstream.destroy(); });
        upstream.on("timeout", () => upstream.destroy()); upstream.on("error", () => respond(502)); upstream.end(body);
      }); request.on("error", () => {});
    });
    await new Promise((resolve) => proxy.listen(0, "127.0.0.1", resolve)); configure();
    await gate.scenario(scenarios[0], async () => {
      const bootstrap = await fixture.request(`${prefix}/agent-bootstrap-tokens`, "POST", { name: "Native process qualification", expiresAt: new Date(Date.now() + 3600000).toISOString() }); assert.equal(bootstrap.status, 201);
      start(bootstrap.body); await wait(async () => Boolean(await agentRow()) && fs.existsSync(path.join(configDir, "credential")) && fs.existsSync(path.join(configDir, "signing-key-pin.json")));
      prohibited.add(fs.readFileSync(path.join(configDir, "credential"), "utf8").trim()); assert.equal(fs.statSync(path.join(configDir, "credential")).mode & 0o777, 0o600);
    });
    await gate.scenario(scenarios[1], async () => { const id = await create(); await wait(async () => (await row(id)).status === "succeeded"); assert.equal((await row(id)).attempt_count, 1); assert.ok((await fixture.pool.query("SELECT 1 FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2", [fixture.workspaceId, id])).rows.length); });
    await gate.scenario(scenarios[2], async () => { const id = await create("dry_run"); await wait(async () => (await row(id)).status === "dry_run_complete"); assert.equal(fs.existsSync(path.join(configDir, "keys")) ? fs.readdirSync(path.join(configDir, "keys")).length : 0, 0); });
    await gate.scenario("native-agent-real-log-persistence",async()=>{
      const id=await create();await wait(async()=>(await row(id)).status==="succeeded");
      const read=async()=>{const response=await fixture.request(`${prefix}/jobs/${id}/agent-log`);assert.equal(response.status,200);return response.body;};
      let persisted;
      await wait(async()=>{const current=await read();if(!current.logsComplete||!current.items.length)return false;persisted=current;return true;});
      assert.equal(persisted.jobStatus,"succeeded");assert.equal(persisted.linesVisible,true);
      assert.ok(persisted.items.some(line=>line.message.includes("passed signature/replay/clock/policy verification")),"Persisted logs must come from the actual signed execution path");
      const sequences=persisted.items.map(line=>line.seq);assert.deepEqual(sequences,[...new Set(sequences)].sort((a,b)=>a-b));
      const serialized=JSON.stringify(persisted);
      for(const secret of prohibited)assert.equal(serialized.includes(secret),false,"Actual persisted execution logs must exclude local credentials");
      const seen=(await agentRow()).last_seen_at;
      await stop();start();await wait(async()=>Date.parse((await agentRow()).last_seen_at)>Date.parse(seen));
      const after=await read();assert.deepEqual(after.items,persisted.items);assert.equal(after.logsComplete,true);
      assert.equal((await row(id)).attempt_count,1);
    },{oracle:"Actual native process console batches, authenticated API persistence and stream finalization survive real process restart; no diagnostic lines injected"});
    await timing.qualify(gate);
    await logFaults.qualify({ gate, fixture, prefix, create, row, stop, start, wait, prohibited });
    await qualifyNativeLogPrivacy({ gate, fixture, prefix, configDir, root, stop, start, wait, row, prohibited });
    gate.report.fixtureSources.push({ file: "tests/e2e/helpers/certops-native-log-privacy.js", sha256: hashFile(path.join(__dirname, "helpers/certops-native-log-privacy.js")) });
    await qualifyNativeCertificateDryRun({ gate, fixture, prefix, configDir, root, stop, start, wait, row, prohibited });
    await gate.scenario(scenarios[3], async () => {
      const before = ["credential", "signing-key-pin.json"].map((file) => hashFile(path.join(configDir, file))); const seen = (await agentRow()).last_seen_at;
      await stop(); start(); await wait(async () => Date.parse((await agentRow()).last_seen_at) > Date.parse(seen)); assert.deepEqual(["credential", "signing-key-pin.json"].map((file) => hashFile(path.join(configDir, file))), before);
      assert.equal((await fixture.pool.query("SELECT count(*)::int AS count FROM certops_agents WHERE workspace_id=$1", [fixture.workspaceId])).rows[0].count, 1);
    });
    await gate.scenario(scenarios[4], async () => {
      for (const fault of ["payload", "signature", "unknown-key"]) {
        mode = fault; const before = rejected; const id = await create();
        try { await wait(() => (counters.get(id)?.mutations || 0) > 0 && rejected > before); }
        catch { throw new Error(`Native ${fault} fault oracle: mutations=${counters.get(id)?.mutations || 0}, rejections=${rejected - before}, status=${(await row(id)).status}`); }
        const heartbeats = heartbeatCount; await wait(() => heartbeatCount >= heartbeats + 2);
        assert.equal(counters.get(id).results, 0); assert.equal(counters.get(id).evidence, 0); assert.equal(counters.get(id).leases, 0);
        assert.equal((await row(id)).status, "claimed"); assert.equal((await fixture.pool.query("SELECT count(*)::int AS count FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2", [fixture.workspaceId, id])).rows[0].count, 0);
      }
      mode = "normal";
    });
    await gate.scenario(scenarios[5], async () => {
      mode = "lease-unavailable"; const id = await create(); await wait(async () => (await row(id)).status === "blocked"); assert.ok(blockedLeases > 0);
      assert.equal((await fixture.pool.query("SELECT count(*)::int AS count FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2", [fixture.workspaceId, id])).rows[0].count, 0); mode = "normal";
    });
    await gate.scenario(scenarios[6], async () => {
      mode = "results-unavailable"; const id = await create();
      await wait(() => blockedResults > 0 && files().some((file) => { const item = JSON.parse(fs.readFileSync(path.join(configDir, "outbox", file), "utf8")); return item.result?.jobId === id && item.result.status === "succeeded"; }));
      assert.equal((await row(id)).status, "running"); const digest = hashFile(path.join(configDir, "credential")); await stop(); mode = "normal"; start();
      await wait(async () => (await row(id)).status === "succeeded" && files().length === 0, 60000); assert.equal((await row(id)).attempt_count, 1); assert.equal(hashFile(path.join(configDir, "credential")), digest);
    });
    await gate.scenario(scenarios[7], async () => {
      await stop(); const pinPath = path.join(configDir, "signing-key-pin.json"), original = fs.readFileSync(pinPath), seen = (await agentRow()).last_seen_at;
      try { fs.writeFileSync(pinPath, "{corrupt-owned-pin"); const bad = start(); await wait(() => bad.exitCode !== null || bad.signalCode !== null); assert.notEqual(bad.exitCode, 0); }
      finally { await stop(); fs.writeFileSync(pinPath, original, { mode: 0o600 }); }
      start(); await wait(async () => Date.parse((await agentRow()).last_seen_at) > Date.parse(seen));
    });
    await gate.scenario(scenarios[9], async () => {
      const before = ["credential", "signing-key-pin.json"].map((file) => hashFile(path.join(configDir, file)));
      const response = await fixture.request(`${prefix}/jobs`, "POST", { operation: "reload", subjectType: "domain", subjectId: "qualification.example.test", payload: { reloadService: "qualification-unapproved", reloadCommandRefs: { validate: "qualification-unapproved-validate", reload: "qualification-unapproved-reload" } } });
      assert.equal(response.status, 201); const id = response.body.job.id;
      await wait(async () => (await row(id)).status === "rejected");
      assert.equal((await row(id)).result_metadata.rejectionReason, "command_not_allowlisted");
      assert.deepEqual(["credential", "signing-key-pin.json"].map((file) => hashFile(path.join(configDir, file))), before);
      assert.equal(fs.existsSync(path.join(configDir, "keys")) ? fs.readdirSync(path.join(configDir, "keys")).length : 0, 0);
    });
    await gate.scenario(scenarios[11], async () => {
      assert.ok(capturedOwnJob); assert.equal((await row(capturedOwnJob.jobId)).status, "succeeded");
      await stop(); const before = replayRejections, leases = counters.get(capturedOwnJob.jobId).leases;
      const evidence = (await fixture.pool.query("SELECT count(*)::int AS count FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2 AND evidence_type='validation.passed'", [fixture.workspaceId, capturedOwnJob.jobId])).rows[0].count;
      mode = "replay-own"; start(); await wait(() => replayRejections > before);
      assert.equal((await row(capturedOwnJob.jobId)).status, "succeeded"); assert.equal((await row(capturedOwnJob.jobId)).attempt_count, 1);
      assert.equal(counters.get(capturedOwnJob.jobId).leases, leases);
      assert.equal((await fixture.pool.query("SELECT count(*)::int AS count FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2 AND evidence_type='validation.passed'", [fixture.workspaceId, capturedOwnJob.jobId])).rows[0].count, evidence);
      assert.ok((await fixture.pool.query("SELECT count(*)::int AS count FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2 AND evidence_type='policy.checked'", [fixture.workspaceId, capturedOwnJob.jobId])).rows[0].count > 0);
      await stop(); mode = "normal"; start();
    });
    await gate.scenario(scenarios[10], async () => {
      await stop();
      const other = await createRegisteredAgent(fixture, baseUrl);
      const otherId = (await fixture.pool.query("SELECT id FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2", [fixture.workspaceId, other.agentId])).rows[0].id;
      const created = await fixture.request(`${prefix}/jobs`, "POST", { operation: "noop", assignedAgentId: otherId }); assert.equal(created.status, 201);
      const claimed = await other.machine("jobs/claim", "claim", { maxJobs: 1, supportedActions: ["noop"] }); assert.equal(claimed.status, 200);
      misdeliveredJob = claimed.body.jobs.find((job) => job.jobId === created.body.job.id); assert.ok(misdeliveredJob); assert.equal(misdeliveredJob.agentId, other.agentId);
      const before = bindingRejected; mode = "foreign-agent"; start();
      await wait(() => bindingRejected > before && (counters.get(misdeliveredJob.jobId)?.mutations || 0) > 0);
      const beats = heartbeatCount; await wait(() => heartbeatCount >= beats + 2);
      assert.equal((await row(misdeliveredJob.jobId)).status, "claimed");
      for (const field of ["results", "evidence", "leases"]) assert.equal(counters.get(misdeliveredJob.jobId)[field], 0);
      assert.equal((await fixture.pool.query("SELECT count(*)::int AS count FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2", [fixture.workspaceId, misdeliveredJob.jobId])).rows[0].count, 0);
      await stop(); mode = "normal";
    });
    await gate.scenario(scenarios[8], async () => {
      await stop(); configure(false); const before = claimCount, heartbeats = heartbeatCount; const id = await create(); start(); await wait(() => heartbeatCount >= heartbeats + 3);
      gate.report.observeOnlyDiagnostics = { beforeClaims: before, afterClaims: claimCount, beforeHeartbeats: heartbeats, afterHeartbeats: heartbeatCount, jobStatus: (await row(id)).status, advertisedOperations: (await agentRow()).supported_operations.length, leakedCredential: leak, heartbeatFacts };
      // An observed HTTP request is not a committed capability declaration.
      await wait(async () => heartbeatFacts.acceptedObserveOnly > 0 && (await agentRow()).supported_operations.length === 0);
      gate.report.observeOnlyDiagnostics.advertisedOperations = (await agentRow()).supported_operations.length;
      assert.equal(claimCount, before); assert.equal((await row(id)).status, "pending"); assert.equal((await agentRow()).supported_operations.length, 0); assert.equal(leak, false);
    });
  } catch (error) { failure = error; }
  finally {
    const clean = async () => {
      const outcomes = await Promise.allSettled(children.map((child) => stop(child)));
      const childrenDrained = outcomes.every(outcome => outcome.status === "fulfilled");
      outcomes.push(...await Promise.allSettled([
        (async () => {
          if (!proxy?.listening) return;
          const port = proxy.address().port; let closed = false;
          proxy.closeAllConnections(); proxy.close(() => { closed = true; });
          await wait(() => closed, 5000);
          const oracle = http.createServer();
          try { await new Promise((resolve, reject) => { oracle.once("error", reject); oracle.listen(port, "127.0.0.1", resolve); }); }
          finally { if (oracle.listening) await new Promise((resolve) => oracle.close(resolve)); }
        })(),
        (async () => { if (!childrenDrained) throw new Error("Owned fixture root preserved because an agent child could not be drained"); assert.equal(path.dirname(path.resolve(root)), path.resolve(os.tmpdir())); assert.ok(path.basename(root).startsWith("certops-native-agent-")); fs.rmSync(root, { recursive: true, force: true }); })(),
        fixture.cleanup(),
        (async () => { const cached = require.cache[require.resolve("../../apps/api/db/database")]; if (cached) await cached.exports.pool.end(); })(),
      ]));
      const errors = outcomes.filter((outcome) => outcome.status === "rejected").map((outcome) => outcome.reason);
      if (errors.length) throw new AggregateError(errors, "Native agent independent cleanup failed");
      assert.equal(fs.existsSync(root), false); assert.equal(leak, false);
    };
    try { if (ready) await gate.scenario(scenarios.at(-1), clean); else await clean(); cleanup = "passed"; } catch (error) { failure ||= error; }
    try { await gate.finish({ requiredScenarios: scenarios, cleanup: { status: cleanup } }); } catch (error) { failure ||= error; }
  }
  if (failure) throw failure;
});
module.exports = { scenarios };
