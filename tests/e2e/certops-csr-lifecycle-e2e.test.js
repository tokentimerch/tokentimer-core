/**
 * Supporting API/PostgreSQL qualification: CSR authenticated API lifecycle.
 * Run via scripts/certops-api-qualification.js with an explicitly disposable API stack.
 * Public requests and persisted rows are the oracle; prerequisite state is isolated.
 * Native certificate deployment is qualified separately; strict reports and cleanup apply. */
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { createRequire } = require("node:module");
const apiRequire = createRequire(path.resolve(__dirname, "../../apps/api/package.json"));
const { createHostGate } = require("../../packages/agent/scripts/host-gate");

// Real authenticated API and database, external OpenSSL signer, operator
// attestation. This does not claim endpoint-worker discovery or agent deployment.
test("CSR authenticated API lifecycle", { timeout: 120000 }, async (t) => {
  const baseUrl = process.env.CERTOPS_CSR_API_URL;
  const strict = process.env.CERTOPS_E2E_REQUIRED === "1";
  if (!baseUrl && !strict) {
    // skip-reason: no-host - requires isolated real feature-enabled API stack
    t.skip("CERTOPS_CSR_API_URL is required"); return;
  }
  assert.ok(baseUrl, "Strict CSR qualification requires CERTOPS_CSR_API_URL");
  assert.equal(process.env.CERTOPS_CSR_DISPOSABLE_STACK, "1", "CSR fixture requires explicit disposable stack authorization");
  const gate = createHostGate({ suite: "csr-api-lifecycle", strict, evidenceLevel: "integration", reportPath: process.env.CERTOPS_CSR_REPORT, requiredCapabilities: ["openssl", "api", "postgres"], probeCapabilities: async () => ({ openssl: { available: spawnSync("openssl", ["version"]).status === 0 }, api: { available: (await fetch(baseUrl, { signal: AbortSignal.timeout(10000) })).ok }, postgres: { available: true } }) });
  gate.report.fixtureSource = { file: "tests/e2e/certops-csr-lifecycle-e2e.test.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") };
  gate.report.artifactQualification = process.env.GITHUB_ACTIONS === "true" ? "workflow-checkout-source" : "local-worktree-source-baseline-sha-only";
  const { Pool } = apiRequire("pg");
  const pool = new Pool({ host: process.env.DB_HOST || "localhost", port: Number(process.env.DB_PORT || 5432), user: process.env.DB_USER || "tokentimer", password: process.env.DB_PASSWORD || "password", database: process.env.DB_NAME || "tokentimer", connectionTimeoutMillis: 5000 });
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "csr-api-"));
  const workspaceId = crypto.randomUUID();
  const foreignWorkspaceId = crypto.randomUUID();
  let userId;
  let foreignUserId;
  let ready = false;
  const cookies = new Map();
  let csrfToken;
  async function request(route, method = "GET", body, authenticated = true) {
    const response = await fetch(new URL(route, baseUrl), { method, signal: AbortSignal.timeout(15000), headers: { "content-type": "application/json", ...(authenticated ? { cookie: [...cookies].map(([key, value]) => `${key}=${value}`).join("; "), ...(csrfToken ? { "x-csrf-token": csrfToken } : {}) } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}) });
    for (const cookie of response.headers.getSetCookie()) { const pair = cookie.split(";", 1)[0]; const split = pair.indexOf("="); cookies.set(pair.slice(0, split), pair.slice(split + 1)); }
    return { status: response.status, body: await response.json() };
  }
  const route = `/api/v1/workspaces/${workspaceId}/certops/csrs`;
  function openssl(args) { const result = spawnSync("openssl", args, { cwd: directory, encoding: "utf8", timeout: 20000 }); assert.equal(result.status, 0, "OpenSSL fixture operation failed"); }
  try {
    await pool.query("SELECT 1 FROM certificate_csr_workflows LIMIT 1");
    assert.equal(await gate.preflight(), true); ready = true;
    const password = crypto.randomBytes(24).toString("hex");
    const email = `csr-${crypto.randomUUID()}@example.test`;
    userId = (await pool.query("INSERT INTO users(email, display_name, password_hash, email_verified) VALUES ($1,'CSR qualification',$2,true) RETURNING id", [email, await apiRequire("bcryptjs").hash(password, 10)])).rows[0].id;
    await pool.query("INSERT INTO workspaces(id,name,created_by) VALUES ($1,'CSR qualification',$2)", [workspaceId, userId]);
    await pool.query("INSERT INTO workspace_memberships(workspace_id,user_id,role) VALUES ($1,$2,'admin')", [workspaceId, userId]);
    const foreignPassword = crypto.randomBytes(24).toString("hex");
    const foreignEmail = `foreign-${crypto.randomUUID()}@example.test`;
    foreignUserId = (await pool.query("INSERT INTO users(email,display_name,password_hash,email_verified) VALUES ($1,'Foreign CSR fixture',$2,true) RETURNING id", [foreignEmail, await apiRequire("bcryptjs").hash(foreignPassword, 10)])).rows[0].id;
    await pool.query("INSERT INTO workspaces(id,name,created_by) VALUES ($1,'Foreign CSR fixture',$2)", [foreignWorkspaceId, foreignUserId]);
    await pool.query("INSERT INTO workspace_memberships(workspace_id,user_id,role) VALUES ($1,$2,'admin')", [foreignWorkspaceId, foreignUserId]);
    csrfToken = (await request("/api/csrf-token")).body.csrfToken;
    assert.equal((await request("/auth/login", "POST", { email, password })).status, 200);
    csrfToken = (await request("/api/csrf-token")).body.csrfToken;
    openssl(["req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", "private.key", "-out", "public.csr", "-subj", "/CN=csr.example.test", "-addext", "subjectAltName=DNS:csr.example.test"]);
    openssl(["req", "-verify", "-in", "public.csr", "-noout"]);
    openssl(["x509", "-req", "-in", "public.csr", "-signkey", "private.key", "-copy_extensions", "copy", "-days", "2", "-out", "public.crt"]);
    const csrPem = fs.readFileSync(path.join(directory, "public.csr"), "utf8");
    const certificatePem = fs.readFileSync(path.join(directory, "public.crt"), "utf8");
    let workflowId;
    let managedCertificateId;
    let changedManagedCertificateId;
    await gate.scenario("csr-api-create-idempotency", async () => {
      const input = { csrPem, target: { name: "CSR qualification host", type: "host" } };
      const created = await request(route, "POST", input); assert.equal(created.status, 201); workflowId = created.body.id;
      assert.equal((await request(route, "POST", input)).body.id, workflowId);
    });
    await gate.scenario("csr-api-private-material-refusal", async () => {
      const rejected = await request(route, "POST", { csrPem: fs.readFileSync(path.join(directory, "private.key"), "utf8"), target: { name: "Refused", type: "host" } });
      assert.equal(rejected.status, 422);
    });
    await gate.scenario("csr-api-malformed-input-refusal", async () => {
      const count = async () => (await pool.query("SELECT count(*)::int AS count FROM certificate_csr_workflows WHERE workspace_id=$1", [workspaceId])).rows[0].count;
      const before = await count();
      assert.equal((await request(route, "POST", { csrPem: "invalid CSR", target: { name: "Malformed", type: "host" } })).status, 400);
      assert.equal((await request(route, "POST", { csrPem, target: { name: "Invalid target", type: "unsupported" } })).status, 400);
      assert.equal(await count(), before);
    });
    await gate.scenario("csr-api-public-export", async () => {
      const exported = await request(`${route}/${workflowId}`); assert.equal(exported.status, 200);
      assert.match(exported.body.csrPem, /BEGIN CERTIFICATE REQUEST/);
      assert.doesNotMatch(JSON.stringify(exported.body), /BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY/);
      fs.writeFileSync(path.join(directory, "exported.csr"), exported.body.csrPem);
      openssl(["req", "-verify", "-in", "exported.csr", "-noout"]);
      assert.equal(exported.body.spkiFingerprintSha256.length, 64);
    });
    await gate.scenario("csr-api-concurrent-create", async () => {
      const input = { csrPem, target: { name: "Concurrent CSR fixture", type: "host" } };
      const results = await Promise.all([request(route, "POST", input), request(route, "POST", input)]);
      assert.ok(results.every((result) => result.status === 201));
      assert.equal(results[0].body.id, results[1].body.id);
      const count = await pool.query("SELECT count(*)::int AS count FROM certificate_csr_workflows WHERE workspace_id=$1 AND target_id=$2", [workspaceId, results[0].body.targetId]);
      assert.equal(count.rows[0].count, 1);
    });
    await gate.scenario("csr-api-signed-key-mismatch", async () => {
      openssl(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "mismatch.key", "-out", "mismatch.crt", "-subj", "/CN=csr.example.test", "-days", "2"]);
      const rejected = await request(`${route}/${workflowId}/signed-certificate`, "POST", { certificatePem: fs.readFileSync(path.join(directory, "mismatch.crt"), "utf8") });
      assert.equal(rejected.status, 422); assert.equal(rejected.body.code, "CERTOPS_CSR_PUBLIC_KEY_MISMATCH");
      assert.equal((await request(`${route}/${workflowId}`)).body.signedFingerprintSha256, null);
    });
    await gate.scenario("csr-api-import-attestation", async () => {
      const signed = await request(`${route}/${workflowId}/signed-certificate`, "POST", { certificatePem });
      assert.equal(signed.status, 200); assert.equal(signed.body.status, "signed_pending_install");
      managedCertificateId = signed.body.managedCertificateId;
      const certificate = new crypto.X509Certificate(certificatePem);
      assert.equal(signed.body.signedFingerprintSha256.replace(/:/g, "").toLowerCase(), certificate.fingerprint256.replace(/:/g, "").toLowerCase());
      const confirmed = await request(`${route}/${workflowId}/confirm-installation`, "POST", {});
      assert.equal(confirmed.status, 200); assert.equal(confirmed.body.status, "completed"); assert.equal(confirmed.body.confirmationMethod, "manual");
      assert.equal((await request(`${route}/${workflowId}/cancel`, "POST", {})).status, 409);
    });
    await gate.scenario("csr-api-cancel-restart", async () => {
      const input = { csrPem, target: { name: "Cancelled CSR fixture", type: "host" } };
      const created = await request(route, "POST", input); assert.equal(created.status, 201);
      const id = created.body.id;
      assert.equal((await request(`${route}/${id}/cancel`, "POST", {})).body.status, "cancelled");
      assert.equal((await request(`${route}/${id}/cancel`, "POST", {})).body.status, "cancelled");
      const refused = await request(`${route}/${id}/signed-certificate`, "POST", { certificatePem });
      assert.equal(refused.status, 409); assert.equal(refused.body.code, "CERTOPS_CSR_STATE_CONFLICT");
      const restarted = await request(route, "POST", input);
      assert.equal(restarted.body.id, id); assert.equal(restarted.body.status, "pending_signature");
      assert.equal(restarted.body.signedFingerprintSha256, null); assert.equal(restarted.body.confirmedAt, null);
    });
    await gate.scenario("csr-api-name-review-gate", async () => {
      fs.writeFileSync(path.join(directory, "changed.ext"), "subjectAltName=DNS:changed.example.test\n");
      openssl(["x509", "-req", "-in", "public.csr", "-signkey", "private.key", "-extfile", "changed.ext", "-days", "2", "-out", "changed.crt"]);
      const created = await request(route, "POST", { csrPem, target: { name: "CSR name review fixture", type: "host" } }); assert.equal(created.status, 201);
      const id = created.body.id;
      const signed = await request(`${route}/${id}/signed-certificate`, "POST", { certificatePem: fs.readFileSync(path.join(directory, "changed.crt"), "utf8") });
      assert.equal(signed.status, 200); assert.equal(signed.body.namesChanged, true);
      changedManagedCertificateId = signed.body.managedCertificateId;
      const refused = await request(`${route}/${id}/confirm-installation`, "POST", {});
      assert.equal(refused.status, 409); assert.equal(refused.body.code, "CERTOPS_CSR_NAMES_ACK_REQUIRED");
      const acknowledged = await request(`${route}/${id}/acknowledge-names`, "POST", {});
      assert.equal(acknowledged.status, 200); assert.equal(acknowledged.body.status, "signed_pending_install");
      assert.equal((await request(`${route}/${id}/confirm-installation`, "POST", {})).body.status, "completed");
    });
    await gate.scenario("csr-api-identity-collision", async () => {
      const created = await request(route, "POST", { csrPem, existingCertificateId: changedManagedCertificateId, target: { name: "CSR identity collision fixture", type: "host" } });
      assert.equal(created.status, 201);
      const refused = await request(`${route}/${created.body.id}/signed-certificate`, "POST", { certificatePem });
      assert.equal(refused.status, 409); assert.equal(refused.body.code, "CERTOPS_CSR_IDENTITY_CONFLICT");
      const persisted = await request(`${route}/${created.body.id}`);
      assert.equal(persisted.body.signedFingerprintSha256, null);
      assert.equal(persisted.body.existingCertificateId, changedManagedCertificateId);
    });
    await gate.scenario("csr-api-retired-identity-refusal", async () => {
      const fingerprint = new crypto.X509Certificate(certificatePem).fingerprint256.replace(/:/g, "").toLowerCase();
      const retirement = `/api/v1/workspaces/${workspaceId}/certops/certificates/${managedCertificateId}/retire`;
      assert.equal((await request(retirement, "POST", { status: "revoked" })).status, 428);
      const retired = await request(retirement, "POST", { expectedFingerprintSha256: fingerprint, status: "revoked", reason: "Qualification fixture lifecycle", acknowledgeUncertainty: true });
      assert.equal(retired.status, 200);
      const refused = await request(route, "POST", { csrPem, existingCertificateId: managedCertificateId, target: { name: "Retired CSR refusal", type: "host" } });
      assert.equal(refused.status, 409); assert.equal(refused.body.code, "CERTOPS_CSR_IDENTITY_CONFLICT");
    });
    await gate.scenario("csr-api-anonymous-denial", async () => {
      assert.equal((await request(route, "GET", undefined, false)).status, 401);
    });
    await gate.scenario("csr-api-cross-workspace-denial", async () => {
      const foreignRoute = `/api/v1/workspaces/${foreignWorkspaceId}/certops/csrs`;
      for (const response of [await request(foreignRoute), await request(`${foreignRoute}/${workflowId}`), await request(foreignRoute, "POST", { csrPem, target: { name: "Forbidden fixture", type: "host" } })]) {
        assert.ok([403, 404].includes(response.status), "Nonmembers must receive denial or concealed absence");
        assert.ok(!JSON.stringify(response.body).includes(csrPem));
      }
      assert.equal((await pool.query("SELECT count(*)::int AS count FROM certificate_csr_workflows WHERE workspace_id=$1", [foreignWorkspaceId])).rows[0].count, 0);
    });
    await gate.scenario("csr-api-viewer-denial", async () => {
      // Fixture role setup precedes a real independent login; route guards
      // receive the actual persisted viewer membership, never mocked auth.
      await pool.query("INSERT INTO workspace_memberships(workspace_id,user_id,role) VALUES ($1,$2,'viewer')", [workspaceId, foreignUserId]);
      cookies.clear(); csrfToken = undefined;
      csrfToken = (await request("/api/csrf-token")).body.csrfToken;
      assert.equal((await request("/auth/login", "POST", { email: foreignEmail, password: foreignPassword })).status, 200);
      csrfToken = (await request("/api/csrf-token")).body.csrfToken;
      assert.equal((await request(route)).status, 403);
      assert.equal((await request(route, "POST", { csrPem, target: { name: "Viewer refusal", type: "host" } })).status, 403);
      assert.equal((await request(`${route}/${workflowId}/confirm-installation`, "POST", {})).status, 403);
    });
  } finally {
    try {
      if (ready) {
      await gate.scenario("csr-api-cleanup", async () => {
        const failures = [];
        // Match existing integration fixture cleanup: delete only audit events
        // owned by this disposable fixture, without weakening immutable guards.
        try {
          await pool.query("DELETE FROM audit_events WHERE workspace_id=ANY($1::uuid[]) OR actor_user_id=ANY($2::int[]) OR subject_user_id=ANY($2::int[])", [[workspaceId, foreignWorkspaceId], [userId, foreignUserId].filter(Boolean)]);
        } catch (error) { failures.push(error); }
        for (const id of [workspaceId, foreignWorkspaceId]) {
          try { await pool.query("DELETE FROM workspaces WHERE id=$1", [id]); }
          catch (error) { failures.push(error); }
        }
        for (const id of [userId, foreignUserId].filter(Boolean)) {
          try { await pool.query("DELETE FROM users WHERE id=$1", [id]); }
          catch (error) { failures.push(error); }
        }
        try { fs.rmSync(directory, { recursive: true, force: true }); }
        catch (error) { failures.push(error); }
        if (failures.length) throw new AggregateError(failures, "CSR owned fixture cleanup failed");
      });
      await gate.finish({ requiredScenarios: require("../../docs/certops/qualification-suites.json").suites["csr-api-lifecycle"] });
      }
    } finally { await pool.end(); fs.rmSync(directory, { recursive: true, force: true }); }
  }
});
