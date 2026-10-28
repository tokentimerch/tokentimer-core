"use strict";

// Opt-in real assistant/browser qualification, never a production smoke test.
// Run each phase with the same disposable database and work directory.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const cp = require("node:child_process");
const { pool } = require("../apps/api/db/database");
const { chromium, request } = require("playwright");
const root = path.resolve(__dirname, "..");
const api = process.env.MCP_QUALIFY_API;
const dashboard = process.env.MCP_QUALIFY_DASHBOARD;
const work = path.resolve(process.env.MCP_QUALIFY_WORK || "");
assert.equal(process.env.MCP_CLIENT_QUALIFY, "true", "Explicit disposable qualification opt-in required");
assert.match(process.env.DB_NAME || "", /_mcp_test$/);
for (const url of [api, dashboard]) assert.ok(url && ["127.0.0.1", "localhost"].includes(new URL(url).hostname));
assert.ok(process.env.MCP_QUALIFY_WORK, "Use a dedicated qualification output directory");
fs.mkdirSync(work, { recursive: true });
const fixturePath = path.join(work, "fixture.json");
const fixture = () => JSON.parse(fs.readFileSync(fixturePath, "utf8"));
const save = value => fs.writeFileSync(fixturePath, JSON.stringify(value, null, 2));
const credentialFile = path.join(work, "credential");
const bin = path.join(root, "packages/mcp/bin/tokentimer-mcp.js");

async function signedIn(person) {
  const client = await request.newContext({ baseURL: api });
  const before = await (await client.get("/api/csrf-token")).json();
  const login = await client.post("/auth/login", { headers: { "x-csrf-token": before.csrfToken }, data: { email: person.email, password: person.password } });
  assert.equal(login.status(), 200, "Real session login failed");
  const csrf = await (await client.get("/api/csrf-token")).json();
  return { client, headers: { "x-csrf-token": csrf.csrfToken } };
}
async function prepare() {
  assert.equal(fs.existsSync(fixturePath), false, "Refuse to overwrite qualification fixtures");
  const password = crypto.randomBytes(24).toString("hex");
  const bcrypt = require("../apps/api/node_modules/bcryptjs");
  const people = [];
  for (const label of ["requester", "reviewer", "viewer"]) {
    const email = `mcp-${label}-${crypto.randomUUID()}@example.test`;
    const row = await pool.query("INSERT INTO users (email, display_name, auth_method, password_hash, email_verified) VALUES ($1,$2,'local',$3,TRUE) RETURNING id", [email, `MCP ${label}`, await bcrypt.hash(password, 10)]);
    people.push({ id: row.rows[0].id, email, password });
  }
  const workspaceId = crypto.randomUUID();
  await pool.query("INSERT INTO workspaces (id,name,created_by,operator_writes_enabled) VALUES ($1,'Disposable MCP qualification',$2,TRUE)", [workspaceId, people[0].id]);
  for (let i = 0; i < people.length; i++) await pool.query("INSERT INTO workspace_memberships (workspace_id,user_id,role) VALUES ($1,$2,$3)", [workspaceId, people[i].id, ["admin", "workspace_manager", "viewer"][i]]);
  const renewalProfile = {
    schemaVersion: 1, profileName: "Qualification web TLS", sanPolicy: { mode: "exact", sans: ["mcp.example.test"], allowWildcards: false },
    keyAlgorithm: "rsa", keySize: 2048, keyRotationPolicy: { rotateOnRenew: true }, preferredChain: null,
    ca: { endpoint: "https://ca.example.test/directory", accountRef: null, eabRef: null },
    acme: { kind: "certbot", commandRef: "qualification-only" }, dns: { provider: "cloudflare", zone: "example.test" },
    deploymentTargets: [{ type: "endpoint", reference: "qualification/web", certPath: "/srv/qualification/cert.pem", reloadService: "nginx" }],
    target: { type: "endpoint", reference: "qualification/web", certPath: "/srv/qualification/cert.pem" },
    verification: { host: "mcp.example.test", port: 443, requireMatch: true },
  };
  const profile = (await pool.query("INSERT INTO certificate_profiles (workspace_id,name,status,source,source_ref,renew_before_days,key_mode,public_metadata,created_by) VALUES ($1,'Qualification TLS','active','manual','qualification',30,'agent-local',$2,$3) RETURNING id", [workspaceId, { renewalProfile }, people[0].id])).rows[0].id;
  const fingerprint = crypto.randomBytes(32).toString("hex");
  const certificateId = (await pool.query("INSERT INTO managed_certificates (workspace_id,source,source_ref,fingerprint_sha256,common_name,issuer,not_after,key_mode,subject_alt_names,profile_id) VALUES ($1,'agent_filesystem','qualification-only',$2,'mcp.example.test','Qualification CA',NOW()+INTERVAL '20 days','agent-local',ARRAY['mcp.example.test'],$3) RETURNING id", [workspaceId, fingerprint, profile])).rows[0].id;
  const identityId = (await pool.query("SELECT id FROM certops_certificate_identities WHERE workspace_id=$1 AND fingerprint_sha256=$2", [workspaceId, fingerprint])).rows[0].id;
  const state = { workspaceId, people, certificateId, identityId, requestId: crypto.randomUUID() };
  save(state);
  const { client, headers } = await signedIn(people[0]);
  try {
    const response = await client.post(`/api/v1/workspaces/${workspaceId}/operator/enrollments`, { headers, data: { name: "Codex CLI qualification", scopes: ["mcp:identity:read", "mcp:certs:read", "mcp:jobs:read", "mcp:agents:read", "mcp:requests:read", "mcp:renew:request"], roleCeiling: "workspace_manager", connectionLifetimeDays: 1 } });
    assert.equal(response.status(), 201, `Enrollment creation failed: ${response.status()}`);
    const { grant, enrollment } = await response.json();
    const result = cp.spawnSync(process.execPath, [bin, "enroll", "--api-url", api, "--credential-file", credentialFile], { input: `${grant}\n`, encoding: "utf8", timeout: 30000 });
    assert.equal(result.status, 0, `Enrollment CLI failed: ${result.stderr}`);
    assert.ok(!result.stdout.includes(grant), "Setup code leaked to stdout");
    const row = (await pool.query("SELECT redeemed_connection_id FROM operator_enrollment_grants WHERE id=$1", [enrollment.id])).rows[0];
    state.connectionId = row.redeemed_connection_id; save(state);
    fs.writeFileSync(path.join(work, "enrollment.txt"), "Session + CSRF enrollment and actual CLI credential storage passed. No secret values retained in evidence.\n");
  } finally { await client.dispose(); }
  console.log("Prepared disposable workspace; actual enrollment CLI passed.");
}

async function clientJourney(afterDecision = false) {
  const state = fixture();
  const trace = path.join(work, "trace.cjs");
  // Transparent byte forwarding: record only negotiation and tool names.
  fs.writeFileSync(trace, `const cp=require('node:child_process'),fs=require('node:fs');const child=cp.spawn(process.execPath,[process.argv[2]],{stdio:['pipe','pipe','inherit']});function observe(stream,tag){let pending='';stream.on('data',b=>{pending+=b;let n;while((n=pending.indexOf('\\n'))>=0){const line=pending.slice(0,n);pending=pending.slice(n+1);try{const m=JSON.parse(line);if(m.method==='initialize'||m.result?.protocolVersion||m.method==='tools/call')fs.appendFileSync(process.env.MCP_QUALIFY_TRACE,JSON.stringify({direction:tag,protocolVersion:m.params?.protocolVersion||m.result?.protocolVersion,clientInfo:m.params?.clientInfo,tool:m.params?.name})+'\\n')}catch{}}});}observe(process.stdin,'client');observe(child.stdout,'server');process.stdin.pipe(child.stdin);child.stdout.pipe(process.stdout);child.on('exit',code=>process.exit(code||0));`);
  const overrides = {
    "features.shell_tool": false,
    "mcp_servers.tokentimer.command": process.execPath,
    "mcp_servers.tokentimer.args": [trace, bin],
    "mcp_servers.tokentimer.required": true,
    "mcp_servers.tokentimer.startup_timeout_sec": 30,
    "mcp_servers.tokentimer.default_tools_approval_mode": "auto",
    "mcp_servers.tokentimer.tools.tt_request_renew.approval_mode": "approve",
    "mcp_servers.tokentimer.env": { TOKENTIMER_API_URL: api, TOKENTIMER_MCP_CREDENTIAL_FILE: credentialFile, TOKENTIMER_MCP_ENABLE_WRITES: "true", MCP_QUALIFY_TRACE: path.join(work, "negotiation.jsonl") },
  };
  const phase = afterDecision ? "after-decision" : "request";
  const prompt = afterDecision
    ? `This is a disposable TokenTimer MCP client qualification. Only use tokentimer MCP tools; no shell, files or other tools. Call tt_whoami, tt_list_my_requests, and tt_get_action_request for the request with requestId ${state.requestId}. Report the actual state, distinguish approval from execution, and stop.`
    : `This is a disposable TokenTimer MCP client qualification. Only use tokentimer MCP tools; no shell, files or other tools. Call tt_whoami, tt_list_certificates, tt_get_certificate(identityId=${state.identityId}), tt_preview_renew(identityId=${state.identityId}), then tt_request_renew using exactly its returned planId and planHash and requestId ${state.requestId}. Repeat tt_request_renew once with exactly the same three values to verify replay. Call tt_get_action_request for the returned requestRecordId. Report the actual state and whether replay created a second job. This is only a renewal request requiring a different human to approve. Do not seek or perform approval. Stop after these calls.`;
  const args = ["exec", "--ignore-user-config", "--ephemeral", "--json", "--skip-git-repo-check", "--sandbox", "read-only", "-C", work];
  // Config values use TOML inline tables for env, JSON-compatible scalars elsewhere.
  for (const [key, value] of Object.entries(overrides)) args.push("-c", `${key}=${typeof value === "object" && !Array.isArray(value) ? "{" + Object.entries(value).map(([k,v]) => `${k}=${JSON.stringify(v)}`).join(",") + "}" : JSON.stringify(value)}`);
  args.push(prompt);
  const clientPath = process.env.MCP_QUALIFY_CLIENT || "codex";
  const result = cp.spawnSync(clientPath, args, { encoding: "utf8", timeout: 180000, maxBuffer: 4 * 1024 * 1024, env: { ...process.env, TOKENTIMER_MCP_CREDENTIAL: "" } });
  // MCP responses contain no credentials; still sweep the captured trace.
  assert.ok(!/ttopc_[a-f0-9]{16}_[a-f0-9]{64}|ttopg_[a-f0-9]{16}_[a-f0-9]{64}/.test(result.stdout || ""), "Secret leaked in client transcript");
  fs.writeFileSync(path.join(work, `client-${phase}.jsonl`), result.stdout || "");
  fs.writeFileSync(path.join(work, `client-${phase}.stderr.txt`), result.stderr || "");
  assert.equal(result.status, 0, "Actual assistant client failed; inspect sanitized client evidence");
  const events = (result.stdout || "").trim().split("\n").map(line => JSON.parse(line));
  assert.ok(events.some(e => e.type === "turn.completed"), "Client turn did not complete");
  const row = await pool.query("SELECT id,job_id FROM operator_action_requests WHERE connection_id=$1 AND request_id=$2", [state.connectionId, state.requestId]);
  assert.equal(row.rowCount, 1, "Exactly one accepted request required");
  state.requestRecordId = row.rows[0].id; state.jobId = row.rows[0].job_id; save(state);
  console.log(`Actual client ${phase} journey completed; one durable request.`);
}

async function browserJourney() {
  const state = fixture();
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  try {
    const person = state.people[1];
    const csrf = await (await context.request.get(`${api}/api/csrf-token`)).json();
    const login = await context.request.post(`${api}/auth/login`, { headers: { "x-csrf-token": csrf.csrfToken }, data: { email: person.email, password: person.password } });
    assert.equal(login.status(), 200);
    const page = await context.newPage();
    const posts = [];
    page.on("request", request => { if (request.method() === "POST" && request.url().endsWith(`/jobs/${state.jobId}/approve`)) posts.push(request.postDataJSON()); });
    await page.goto(`${dashboard}/certops/jobs?workspace=${state.workspaceId}`, { waitUntil: "networkidle" });
    await page.getByRole("button", { name: "Approve", exact: true }).click();
    const dialog = page.getByRole("dialog");
    await dialog.getByText("Assistant-originated renewal request").waitFor();
    await page.screenshot({ path: path.join(work, "approval-origin.png"), fullPage: true });
    for (const text of ["MCP requester", "Codex CLI qualification", "/srv/qualification/cert.pem", "https://ca.example.test/directory", "mcp.example.test"]) assert.ok((await dialog.innerText()).includes(text), `Review missing ${text}`);
    const approve = dialog.getByRole("button", { name: "Approve", exact: true });
    assert.equal(await approve.isDisabled(), true);
    await dialog.getByText("I reviewed the requester, connection, destinations and complete renewal effect.").click();
    assert.equal(await dialog.getByRole("checkbox").isChecked(), true);
    assert.equal(await approve.isEnabled(), true);
    await page.screenshot({ path: path.join(work, "approval-review.png"), fullPage: true });
    const response = page.waitForResponse(r => r.request().method() === "POST" && r.url().endsWith(`/jobs/${state.jobId}/approve`));
    await approve.click();
    assert.equal((await response).status(), 200);
    assert.equal(posts.length, 1); assert.match(posts[0].reviewHash, /^[a-f0-9]{64}$/);
    const job = (await pool.query("SELECT status,approved_by_user_id FROM certificate_jobs WHERE id=$1", [state.jobId])).rows[0];
    assert.equal(job.status, "pending"); assert.equal(job.approved_by_user_id, person.id);
    assert.notEqual(person.id, state.people[0].id);
    const noAgent = await pool.query("SELECT id FROM certificate_jobs WHERE id=$1 AND claimed_by_agent_id IS NOT NULL", [state.jobId]);
    assert.equal(noAgent.rowCount, 0, "Approval must not claim execution");
    fs.writeFileSync(path.join(work, "browser-result.json"), JSON.stringify({ independentSession: true, reviewDisplayed: true, acknowledgementRequired: true, exactReviewBinding: true, approvePosts: 1, jobStatus: job.status, executionQualified: false }, null, 2));
    console.log("Real dashboard session approval completed; exact review binding passed.");
  } finally { await context.close(); await browser.close(); }
}

async function cleanup() {
  const state = fixture();
  // Immutable audit rows intentionally prevent hard-deleting attributable
  // fixture users. Contain their connection here; the runner removes the
  // entire disposable database/container after all qualification phases.
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    if (state.connectionId) await require("../apps/api/services/operator/connections").revokeConnection({ client, workspaceId: state.workspaceId, connectionId: state.connectionId, revokedBy: state.people[0].id });
    await client.query("UPDATE workspaces SET operator_writes_enabled=FALSE WHERE id=$1", [state.workspaceId]);
    await client.query("COMMIT");
  } catch (error) { await client.query("ROLLBACK"); throw error; }
  finally { client.release(); }
  fs.rmSync(credentialFile, { force: true }); fs.rmSync(fixturePath, { force: true });
  console.log("Connection revoked, workspace writes disabled and private files removed. Remove the disposable database/container to erase audit fixtures.");
}
async function negativeBrowserJourney() {
  const state = fixture();
  // All fixture work is undispatched. End the first request before preparing
  // a separate deliberate request for rejection and expiry qualification.
  await pool.query("UPDATE certificate_jobs SET status='cancelled' WHERE workspace_id=$1 AND status='pending'", [state.workspaceId]);
  const { credential } = require("../packages/mcp/src/credentialStore").parseCredentialFile(fs.readFileSync(credentialFile, "utf8"));
  const operatorPost = async (route, data) => {
    const response = await fetch(api + route, { method: "POST", headers: { Authorization: `Bearer ${credential}`, "Content-Type": "application/json" }, body: JSON.stringify(data) });
    assert.ok(response.ok, `Fixture operator request failed: ${response.status}`);
    return response.json();
  };
  const plan = await operatorPost("/api/v1/operator/renewals/preview", { identityId: state.identityId });
  const pending = await operatorPost("/api/v1/operator/renewals/requests", { planId: plan.planId, planHash: plan.planHash, requestId: crypto.randomUUID() });
  const browser = await chromium.launch({ headless: true });
  try {
    for (const actorIndex of [0,2,1]) {
      const context = await browser.newContext();
      try {
        const person = state.people[actorIndex];
        const csrf = await (await context.request.get(`${api}/api/csrf-token`)).json();
        assert.equal((await context.request.post(`${api}/auth/login`, { headers: { "x-csrf-token": csrf.csrfToken }, data: { email: person.email, password: person.password } })).status(), 200);
        const page = await context.newPage();
        await page.goto(`${dashboard}/certops/jobs?workspace=${state.workspaceId}`, { waitUntil: "networkidle" });
        const reviewUrl = `${api}/api/v1/workspaces/${state.workspaceId}/certops/jobs/${pending.jobId}/approval-review`;
        if (actorIndex === 2) {
          assert.equal(await page.getByRole("button", { name: "Approve", exact: true }).count(), 0);
          assert.equal((await context.request.get(reviewUrl)).status(), 403);
          continue;
        }
        if (actorIndex === 1) await pool.query("UPDATE operator_action_requests SET approval_expires_at=NOW()-INTERVAL '1 second' WHERE id=$1", [pending.requestRecordId]);
        await page.getByRole("button", { name: "Approve", exact: true }).click();
        const dialog = page.getByRole("dialog");
        await dialog.getByRole("alert").waitFor();
        assert.equal(await dialog.getByRole("button", { name: "Approve", exact: true }).isDisabled(), true);
        const review = (await (await context.request.get(reviewUrl)).json()).review;
        const token = await (await context.request.get(`${api}/api/csrf-token`)).json();
        const attempt = await context.request.post(`${api}/api/v1/workspaces/${state.workspaceId}/certops/jobs/${pending.jobId}/approve`, { headers: { "x-csrf-token": token.csrfToken }, data: { reviewHash: review.reviewHash } });
        assert.equal(attempt.status(), actorIndex === 0 ? 403 : 409);
        if (actorIndex === 1) {
          await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
          await page.getByRole("button", { name: "Reject", exact: true }).click();
          const response = page.waitForResponse(r => r.request().method() === "POST" && r.url().endsWith(`/jobs/${pending.jobId}/reject`));
          await page.getByRole("dialog").getByRole("button", { name: "Reject", exact: true }).click();
          assert.equal((await response).status(), 200);
        }
      } finally { await context.close(); }
    }
    assert.equal((await pool.query("SELECT status FROM certificate_jobs WHERE id=$1", [pending.jobId])).rows[0].status, "rejected");
    fs.writeFileSync(path.join(work, "browser-refusals.json"), JSON.stringify({ requesterApprovalForbidden: true, viewerReviewForbidden: true, expiredApprovalForbidden: true, rejectionStillAvailable: true }, null, 2));
    console.log("Real browser self-approval, viewer, expiry and rejection checks passed.");
  } finally { await browser.close(); }
}
const phases = { prepare, client: () => clientJourney(false), browser: browserJourney, after: () => clientJourney(true), negative: negativeBrowserJourney, cleanup };
assert.ok(phases[process.argv[2]], "Choose prepare, client, browser, after, negative or cleanup");
phases[process.argv[2]]().catch(error => { console.error(error.message); process.exitCode = 1; }).finally(() => pool.end());
