"use strict";

/**
 * E2E integration suite for the CertOps agent surface.
 *
 * Boots the real Express API (apps/api/index.js) as a child process (the
 * module listens at import time and exports nothing, so in-process import is
 * not possible without modifying apps/), drives the four
 * /api/v1/certops/agent/* routes with real envelopes, verifies signed
 * dispatch with the real packages/agent signing module, and exercises the
 * lease reaper from apps/worker/src/certops-worker.js directly.
 *
 * Requires the local docker Postgres (tokentimer-pg) with migrations
 * applied. The whole suite self-skips when the DB is unreachable, following
 * the tests/contract/api-endpoints.test.js describe.skip pattern.
 *
 * Run: pnpm test:e2e:agent  (or node --test tests/e2e/certops-agent-e2e.test.js)
 */

const { describe, it, before, after } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const path = require("node:path");
const { spawn } = require("node:child_process");
const { pathToFileURL } = require("node:url");
const net = require("node:net");

const repoRoot = path.resolve(__dirname, "..", "..");
const apiDir = path.join(repoRoot, "apps", "api");

const DB_ENV = {
  DB_HOST: process.env.DB_HOST || "localhost",
  DB_PORT: process.env.DB_PORT || "5432",
  DB_USER: process.env.DB_USER || "tokentimer",
  DB_PASSWORD: process.env.DB_PASSWORD || "password",
  DB_NAME: process.env.DB_NAME || "tokentimer",
};

// The signing key row in certops_signing_keys is encrypted with this env
// key. A fresh random key would make an existing active key undecryptable at
// dispatch time, so the suite retires any active key it cannot own and lets
// registerAgent mint a fresh one (restored in cleanup).
const SIGNING_ENCRYPTION_KEY =
  process.env.CERTOPS_SIGNING_ENCRYPTION_KEY ||
  crypto.randomBytes(32).toString("hex");
const REGISTRATION_ENCRYPTION_KEY =
  process.env.CERTOPS_REGISTRATION_ENCRYPTION_KEY ||
  crypto.randomBytes(32).toString("hex");

const RUN_ID = crypto.randomBytes(6).toString("hex");
const PROTOCOL_VERSION = "1.0.0";

// --- DB availability probe (self-skip support) ---

let pool = null;
let dbAvailable = false;
let skipReason = "";

async function probeDatabase() {
  let pg;
  try {
    pg = require(path.join(apiDir, "node_modules", "pg"));
  } catch (_err) {
    try {
      pg = require("pg");
    } catch (err) {
      skipReason = `pg module not resolvable: ${err.message}`;
      return false;
    }
  }
  const candidate = new pg.Pool({
    host: DB_ENV.DB_HOST,
    port: Number(DB_ENV.DB_PORT),
    user: DB_ENV.DB_USER,
    password: DB_ENV.DB_PASSWORD,
    database: DB_ENV.DB_NAME,
    connectionTimeoutMillis: 3000,
    max: 4,
  });
  try {
    await candidate.query("SELECT 1 FROM certops_agents LIMIT 1");
    pool = candidate;
    return true;
  } catch (err) {
    skipReason = `database unreachable or migrations missing at ${DB_ENV.DB_HOST}:${DB_ENV.DB_PORT}/${DB_ENV.DB_NAME}: ${err.message}`;
    await candidate.end().catch(() => {});
    return false;
  }
}

// --- API server lifecycle (child process fallback; see header) ---

let apiProcess = null;
let baseUrl = null;

function pickFreePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close((err) => (err ? reject(err) : resolve(port)));
    });
    server.on("error", reject);
  });
}

async function waitForHealth(url, timeoutMs = 30000) {
  const deadline = Date.now() + timeoutMs;
  let lastError = null;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${url}/health`);
      if (res.ok) return;
      lastError = new Error(`health returned ${res.status}`);
    } catch (err) {
      lastError = err;
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`API did not become healthy: ${lastError?.message}`);
}

async function startApiServer() {
  const port = await pickFreePort();
  baseUrl = `http://127.0.0.1:${port}`;
  apiProcess = spawn(process.execPath, ["index.js"], {
    cwd: apiDir,
    stdio: ["ignore", "pipe", "pipe"],
    env: {
      ...process.env,
      ...DB_ENV,
      NODE_ENV: "test",
      PORT: String(port),
      HOST: "127.0.0.1",
      SESSION_SECRET: "certops-agent-e2e-session-secret",
      CERTOPS_ENABLED: "true",
      CERTOPS_SIGNING_ENCRYPTION_KEY: SIGNING_ENCRYPTION_KEY,
      CERTOPS_REGISTRATION_ENCRYPTION_KEY: REGISTRATION_ENCRYPTION_KEY,
      DISABLE_ADMIN_BOOTSTRAP: "true",
      ENABLE_METRICS: "false",
    },
  });
  let output = "";
  apiProcess.stdout.on("data", (chunk) => {
    output += chunk.toString();
  });
  apiProcess.stderr.on("data", (chunk) => {
    output += chunk.toString();
  });
  apiProcess.on("exit", (code) => {
    if (code !== null && code !== 0 && baseUrl) {
      // Surface startup crashes in the failure message of waitForHealth.
      output += `\n[api exited with code ${code}]`;
    }
  });
  try {
    await waitForHealth(baseUrl);
  } catch (err) {
    throw new Error(`${err.message}\n--- api output ---\n${output.slice(-4000)}`);
  }
}

function stopApiServer() {
  if (apiProcess && !apiProcess.killed) {
    apiProcess.kill();
  }
  apiProcess = null;
}

// --- Protocol helpers ---

function envelope(messageType, agentId, body, extra = {}) {
  return {
    schemaVersion: 1,
    protocolVersion: PROTOCOL_VERSION,
    messageType,
    agentId,
    sentAt: new Date().toISOString(),
    ...extra,
    body,
  };
}

async function postAgent(route, bearer, payload) {
  const res = await fetch(`${baseUrl}/api/v1/certops/agent/${route}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${bearer}`,
    },
    body: JSON.stringify(payload),
  });
  let body = null;
  try {
    body = await res.json();
  } catch (_err) {
    body = null;
  }
  return { status: res.status, body };
}

// --- Signing-key ownership (see SIGNING_ENCRYPTION_KEY note above) ---

function decryptsWithSuiteKey(ciphertext) {
  const parts = String(ciphertext || "").split(":");
  if (parts.length !== 3) return false;
  try {
    const key = Buffer.from(SIGNING_ENCRYPTION_KEY, "hex");
    const decipher = crypto.createDecipheriv(
      "aes-256-gcm",
      key,
      Buffer.from(parts[0], "hex"),
    );
    decipher.setAuthTag(Buffer.from(parts[1], "hex"));
    decipher.update(parts[2], "hex", "utf8");
    decipher.final("utf8");
    return true;
  } catch (_err) {
    return false;
  }
}

async function ensureOwnableSigningKey() {
  const { rows } = await pool.query(
    `SELECT id, private_key_encrypted FROM certops_signing_keys
      WHERE status = 'active'`,
  );
  for (const row of rows) {
    if (!decryptsWithSuiteKey(row.private_key_encrypted)) {
      // Orphaned key from a previous run with a lost encryption key: the
      // server could never sign with it either, so retiring is safe.
      await pool.query(
        `UPDATE certops_signing_keys SET status = 'retired' WHERE id = $1`,
        [row.id],
      );
    }
  }
}

// --- Seeded state (unique per run so reruns survive failed cleanup) ---

const seeded = {
  userId: null,
  workspaceId: null,
  bootstrapTokenIds: [],
  agentDbIds: [],
  jobIds: [],
};

let services = null;

function loadServices() {
  // Set env BEFORE requiring server modules: db/database builds its Pool and
  // jobSigning reads the encryption key from process.env.
  Object.assign(process.env, DB_ENV, {
    CERTOPS_SIGNING_ENCRYPTION_KEY: SIGNING_ENCRYPTION_KEY,
    CERTOPS_REGISTRATION_ENCRYPTION_KEY: REGISTRATION_ENCRYPTION_KEY,
    CERTOPS_ENABLED: "true",
    SESSION_SECRET: process.env.SESSION_SECRET || "certops-agent-e2e",
  });
  return {
    jobs: require(path.join(apiDir, "services", "certops", "jobs.js")),
    agentCredentials: require(
      path.join(apiDir, "services", "certops", "agentCredentials.js"),
    ),
    signing: require(
      path.join(repoRoot, "packages", "agent", "src", "signing"),
    ),
    apiDb: require(path.join(apiDir, "db", "database.js")),
  };
}

async function seedWorkspace() {
  const email = `certops-e2e-${RUN_ID}@example.test`;
  const userResult = await pool.query(
    `INSERT INTO users (email, display_name, password_hash)
     VALUES ($1, 'E2E', 'x') RETURNING id`,
    [email],
  );
  seeded.userId = userResult.rows[0].id;

  seeded.workspaceId = crypto.randomUUID();
  await pool.query(
    `INSERT INTO workspaces (id, name, plan, created_by)
     VALUES ($1, $2, 'oss', $3)`,
    [seeded.workspaceId, `certops-e2e-${RUN_ID}`, seeded.userId],
  );
}

async function createBootstrap() {
  const { token, plaintextToken } =
    await services.agentCredentials.createBootstrapToken({
      workspaceId: seeded.workspaceId,
      name: `e2e-${RUN_ID}-${crypto.randomBytes(3).toString("hex")}`,
      expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
    });
  seeded.bootstrapTokenIds.push(token.id);
  return { token, plaintextToken };
}

async function registerAgent(agentId) {
  const { token, plaintextToken } = await createBootstrap();
  const response = await postAgent(
    "register",
    plaintextToken,
    envelope("register", agentId, {
      bootstrapTokenId: String(token.id),
      agentVersion: "1.0.0",
      hostname: "e2e-host",
      platform: "linux",
    }),
  );
  assert.equal(response.status, 201, JSON.stringify(response.body));
  const agentRow = await pool.query(
    `SELECT id FROM certops_agents WHERE agent_id = $1`,
    [response.body.agentId],
  );
  seeded.agentDbIds.push(agentRow.rows[0].id);
  return { ...response.body, plaintextBootstrapToken: plaintextToken, bootstrapToken: token };
}

async function createRenewJob() {
  const job = await services.jobs.createCertificateJob({
    workspaceId: seeded.workspaceId,
    operation: "renew",
    source: "api",
    subjectType: null,
    subjectId: null,
    payload: {
      action: "renew",
      domains: [`e2e-${RUN_ID}.example.test`],
      caEndpoint: "https://acme.example.test/directory",
      acmeKind: "certbot",
    },
    requestedByUserId: seeded.userId,
  });
  seeded.jobIds.push(job.id);
  // createCertificateJob already defaults to the claimable 'pending' status;
  // the explicit UPDATE keeps the suite robust if the default ever changes.
  await pool.query(
    `UPDATE certificate_jobs SET status = 'pending' WHERE id = $1`,
    [job.id],
  );
  return job;
}

function claimEnvelope(agentId, maxJobs = 1) {
  return envelope("claim", agentId, {
    maxJobs,
    supportedActions: ["renew"],
  });
}

async function cleanupSeededRows() {
  if (!pool || !seeded.workspaceId) return;
  const ws = seeded.workspaceId;
  await pool.query(
    `DELETE FROM certificate_evidence WHERE workspace_id = $1`,
    [ws],
  ).catch(() => {});
  await pool.query(
    `DELETE FROM certificate_job_log WHERE workspace_id = $1`,
    [ws],
  ).catch(() => {});
  await pool.query(
    `DELETE FROM certops_consumed_nonces WHERE workspace_id = $1`,
    [ws],
  ).catch(() => {});
  await pool.query(
    `DELETE FROM certificate_jobs WHERE workspace_id = $1`,
    [ws],
  ).catch(() => {});
  await pool.query(
    `DELETE FROM certops_agents WHERE workspace_id = $1`,
    [ws],
  ).catch(() => {});
  await pool.query(
    `DELETE FROM certops_agent_bootstrap_tokens WHERE workspace_id = $1`,
    [ws],
  ).catch(() => {});
  await pool.query(`DELETE FROM workspaces WHERE id = $1`, [ws]).catch(
    () => {},
  );
  if (seeded.userId) {
    await pool.query(`DELETE FROM users WHERE id = $1`, [seeded.userId]).catch(
      () => {},
    );
  }
}

// --- Suite ---

describe("CertOps agent surface E2E", () => {
  before(async () => {
    dbAvailable = await probeDatabase();
    if (!dbAvailable) {
      console.log(
        `certops-agent-e2e skipped: ${skipReason} ` +
          "(start the tokentimer-pg docker Postgres and apply migrations)",
      );
      return;
    }
    services = loadServices();
    await ensureOwnableSigningKey();
    await seedWorkspace();
    await startApiServer();
  });

  after(async () => {
    stopApiServer();
    await cleanupSeededRows();
    if (services?.apiDb?.pool) {
      await services.apiDb.pool.end().catch(() => {});
    }
    if (pool) await pool.end().catch(() => {});
  });

  // Shared across the sequential subtests below.
  const state = {};

  it("happy path: register, heartbeat, claim, verify, result, idempotent duplicate ack", async (t) => {
    if (!dbAvailable) return t.skip(skipReason);

    const agentId = `e2e-agent-${RUN_ID}-happy`;
    const reg = await registerAgent(agentId);
    assert.equal(reg.agentId, agentId);
    assert.match(reg.credential, /^ttagent_/);
    assert.match(reg.signingPublicKeyPem, /-----BEGIN PUBLIC KEY-----/);
    assert.ok(reg.signingKeyId);
    state.agent = reg;

    const heartbeat = await postAgent(
      "heartbeat",
      reg.credential,
      envelope("heartbeat", agentId, {
        agentVersion: "1.0.0",
        ntpSynced: true,
        pinnedSigningKeyId: reg.signingKeyId,
      }),
    );
    assert.equal(heartbeat.status, 200, JSON.stringify(heartbeat.body));
    assert.equal(heartbeat.body.status, "active");

    await createRenewJob();
    const claim = await postAgent(
      "jobs/claim",
      reg.credential,
      claimEnvelope(agentId),
    );
    assert.equal(claim.status, 200, JSON.stringify(claim.body));
    assert.equal(claim.body.jobs.length, 1);
    const job = claim.body.jobs[0];
    for (const field of [
      "jobId",
      "workspaceId",
      "action",
      "claimId",
      "attemptId",
      "leaseExpiresAt",
      "attemptCount",
      "nonce",
      "issuedAt",
      "expiresAt",
      "signingKeyId",
      "signature",
    ]) {
      assert.ok(job[field] !== undefined && job[field] !== null, field);
    }
    assert.equal(job.action, "renew");
    // The dispatched payload carries a server-assigned attemptId mirroring
    // the claim id, so a real agent can report results without ever
    // hand-crafting a claimId.
    assert.equal(job.attemptId, job.claimId);
    state.signedJob = job;

    // Agent-side verification with the real signing module.
    const integrity = services.signing.verifyJobSignature({
      job,
      publicKeyPem: reg.signingPublicKeyPem,
      pinnedSigningKeyId: reg.signingKeyId,
    });
    assert.deepEqual(integrity, { allowed: true });
    const window = services.signing.checkJobTimeWindow({
      job,
      nowMs: Date.now(),
    });
    assert.deepEqual(window, { allowed: true });

    // Real-agent shape: no explicit claimId; the server falls back to
    // attemptId (which mirrors the claim id) for ownership re-proof.
    const resultBody = {
      jobId: job.jobId,
      attemptId: job.attemptId,
      status: "succeeded",
      keyRotated: false,
      nonce: job.nonce,
    };
    const result = await postAgent(
      "jobs/results",
      reg.credential,
      envelope("result", agentId, resultBody),
    );
    assert.equal(result.status, 200, JSON.stringify(result.body));
    assert.equal(result.body.status, "succeeded");

    // Duplicate delivery of the same terminal outcome is acknowledged
    // idempotently: the replayed nonce is recognized as belonging to this
    // already-completed job and returns the recorded outcome instead of 409.
    const replay = await postAgent(
      "jobs/results",
      reg.credential,
      envelope("result", agentId, resultBody),
    );
    assert.equal(replay.status, 200, JSON.stringify(replay.body));
    assert.equal(replay.body.status, "succeeded");
    assert.equal(replay.body.duplicate, true);

    // A conflicting outcome for the completed job is still rejected by the
    // replay ledger: idempotent acks only apply to matching terminal states.
    const conflicting = await postAgent(
      "jobs/results",
      reg.credential,
      envelope("result", agentId, {
        ...resultBody,
        status: "failed",
        errorCode: "deploy_failed",
        errorMessage: "conflicting replay",
      }),
    );
    assert.equal(conflicting.status, 409, JSON.stringify(conflicting.body));
    assert.equal(
      conflicting.body.code,
      "CERTOPS_AGENT_RESULT_NONCE_REJECTED",
    );
  });

  it("tamper: mutating a signed field fails agent-side verification", async (t) => {
    if (!dbAvailable) return t.skip(skipReason);
    const tampered = { ...state.signedJob, action: "revoke" };
    const verdict = services.signing.verifyJobSignature({
      job: tampered,
      publicKeyPem: state.agent.signingPublicKeyPem,
      pinnedSigningKeyId: state.agent.signingKeyId,
    });
    assert.equal(verdict.allowed, false);
    assert.equal(verdict.rejectionReason, "job_integrity_failed");
    assert.ok(verdict.detail);
  });

  it("bootstrap token reuse is rejected with 401", async (t) => {
    if (!dbAvailable) return t.skip(skipReason);
    const reuse = await postAgent(
      "register",
      state.agent.plaintextBootstrapToken,
      envelope("register", `e2e-agent-${RUN_ID}-reuse`, {
        bootstrapTokenId: String(state.agent.bootstrapToken.id),
        agentVersion: "1.0.0",
      }),
    );
    assert.equal(reuse.status, 401, JSON.stringify(reuse.body));
  });

  it("bad agent credential is rejected with 401", async (t) => {
    if (!dbAvailable) return t.skip(skipReason);
    const bogus = `ttagent_${crypto.randomBytes(16).toString("hex")}${crypto
      .randomBytes(16)
      .toString("hex")}`;
    const res = await postAgent(
      "heartbeat",
      bogus,
      envelope("heartbeat", `e2e-agent-${RUN_ID}-happy`, {
        agentVersion: "1.0.0",
      }),
    );
    assert.equal(res.status, 401, JSON.stringify(res.body));
  });

  it("retired agent gets 410 on heartbeat, claim, and results", async (t) => {
    if (!dbAvailable) return t.skip(skipReason);
    const agentId = `e2e-agent-${RUN_ID}-retired`;
    const reg = await registerAgent(agentId);
    await pool.query(
      `UPDATE certops_agents
          SET status = 'retired', retired_at = NOW(), retire_reason = 'e2e'
        WHERE agent_id = $1`,
      [agentId],
    );
    const hb = await postAgent(
      "heartbeat",
      reg.credential,
      envelope("heartbeat", agentId, { agentVersion: "1.0.0" }),
    );
    assert.equal(hb.status, 410, JSON.stringify(hb.body));
    const claim = await postAgent(
      "jobs/claim",
      reg.credential,
      claimEnvelope(agentId),
    );
    assert.equal(claim.status, 410, JSON.stringify(claim.body));
    const result = await postAgent(
      "jobs/results",
      reg.credential,
      envelope("result", agentId, {
        jobId: crypto.randomUUID(),
        attemptId: crypto.randomUUID(),
        status: "succeeded",
      }),
    );
    assert.equal(result.status, 410, JSON.stringify(result.body));
  });

  it("workspace kill switch blocks claims with 409", async (t) => {
    if (!dbAvailable) return t.skip(skipReason);
    await pool.query(
      `UPDATE workspaces SET certops_paused = TRUE WHERE id = $1`,
      [seeded.workspaceId],
    );
    try {
      const claim = await postAgent(
        "jobs/claim",
        state.agent.credential,
        claimEnvelope(state.agent.agentId),
      );
      assert.equal(claim.status, 409, JSON.stringify(claim.body));
      assert.equal(claim.body.code, "CERTOPS_WORKSPACE_PAUSED");
    } finally {
      await pool.query(
        `UPDATE workspaces SET certops_paused = FALSE WHERE id = $1`,
        [seeded.workspaceId],
      );
    }
  });

  it("evidence is accepted; private key material is rejected with 422", async (t) => {
    if (!dbAvailable) return t.skip(skipReason);
    const jobId = state.signedJob.jobId;
    const evidence = await postAgent(
      "jobs/results",
      state.agent.credential,
      envelope("evidence", state.agent.agentId, {
        jobId,
        evidenceItems: [
          {
            eventType: "validation.passed",
            observedAt: new Date().toISOString(),
            fingerprintSha256: crypto.randomBytes(32).toString("hex"),
            summary: "e2e validation evidence",
          },
        ],
      }),
    );
    assert.equal(evidence.status, 200, JSON.stringify(evidence.body));
    assert.equal(evidence.body.evidenceCount, 1);

    const leaked = await postAgent(
      "jobs/results",
      state.agent.credential,
      envelope("evidence", state.agent.agentId, {
        jobId,
        evidenceItems: [
          {
            eventType: "validation.passed",
            observedAt: new Date().toISOString(),
            summary:
              "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA==\n-----END PRIVATE KEY-----",
          },
        ],
      }),
    );
    assert.equal(leaked.status, 422, JSON.stringify(leaked.body));
    assert.equal(leaked.body.code, "PRIVATE_KEY_MATERIAL_REJECTED");
  });

  it("second claim returns no jobs while the lease is held", async (t) => {
    if (!dbAvailable) return t.skip(skipReason);
    await createRenewJob();
    const first = await postAgent(
      "jobs/claim",
      state.agent.credential,
      claimEnvelope(state.agent.agentId),
    );
    assert.equal(first.status, 200, JSON.stringify(first.body));
    assert.equal(first.body.jobs.length, 1);
    state.leasedJob = first.body.jobs[0];

    const second = await postAgent(
      "jobs/claim",
      state.agent.credential,
      claimEnvelope(state.agent.agentId),
    );
    assert.equal(second.status, 200, JSON.stringify(second.body));
    assert.equal(second.body.jobs.length, 0);
  });

  it("lease reaper defers, then requeues once the claiming agent goes silent", async (t) => {
    if (!dbAvailable) return t.skip(skipReason);
    const jobId = state.leasedJob.jobId;
    await pool.query(
      `UPDATE certificate_jobs
          SET lease_expires_at = NOW() - INTERVAL '1 minute'
        WHERE id = $1`,
      [jobId],
    );

    const workerUrl = pathToFileURL(
      path.join(repoRoot, "apps", "worker", "src", "certops-worker.js"),
    ).href;
    const worker = await import(workerUrl);

    // Pass 1: the claiming agent is still heartbeating (fresh last_seen_at),
    // so the expired lease is deferred, not requeued.
    let client = await pool.connect();
    let summary;
    try {
      summary = await worker.reapExpiredLeases({ client });
    } finally {
      client.release();
    }
    assert.ok(summary.deferred >= 1, JSON.stringify(summary));
    const deferred = await pool.query(
      `SELECT status FROM certificate_jobs WHERE id = $1`,
      [jobId],
    );
    assert.equal(deferred.rows[0].status, "claimed");

    // Pass 2: silence the agent past the offline threshold; now the job
    // is provably orphaned and gets requeued.
    await pool.query(
      `UPDATE certops_agents SET last_seen_at = NOW() - INTERVAL '1 hour'
        WHERE agent_id = $1`,
      [state.agent.agentId],
    );
    client = await pool.connect();
    try {
      summary = await worker.reapExpiredLeases({ client });
    } finally {
      client.release();
    }
    assert.ok(summary.scanned >= 1, JSON.stringify(summary));
    assert.ok(summary.requeued >= 1, JSON.stringify(summary));

    const { rows } = await pool.query(
      `SELECT status, attempt_count, max_attempts, claim_id, lease_expires_at
         FROM certificate_jobs WHERE id = $1`,
      [jobId],
    );
    assert.equal(rows[0].status, "pending");
    // The claim path counted this dispatch attempt; the reaper does not
    // consume an extra retry on requeue.
    assert.equal(rows[0].attempt_count, 1);
    assert.equal(rows[0].claim_id, null);
    assert.equal(rows[0].lease_expires_at, null);
    state.requeuedJobId = jobId;
  });

  it("lease reaper fails an expired job with exhausted retry budget", async (t) => {
    if (!dbAvailable) return t.skip(skipReason);
    const jobId = state.requeuedJobId;
    // The reaper set next_attempt_at into the future (backoff); clear it so
    // the job is immediately claimable again, then exhaust the budget.
    await pool.query(
      `UPDATE certificate_jobs SET next_attempt_at = NULL WHERE id = $1`,
      [jobId],
    );
    const claim = await postAgent(
      "jobs/claim",
      state.agent.credential,
      claimEnvelope(state.agent.agentId),
    );
    assert.equal(claim.status, 200, JSON.stringify(claim.body));
    assert.equal(claim.body.jobs.length, 1);
    assert.equal(claim.body.jobs[0].jobId, jobId);

    await pool.query(
      `UPDATE certificate_jobs
          SET attempt_count = max_attempts,
              lease_expires_at = NOW() - INTERVAL '1 minute'
        WHERE id = $1`,
      [jobId],
    );
    // Silence the agent so the terminal failure is attributed to
    // agent_offline rather than lease_expired.
    await pool.query(
      `UPDATE certops_agents SET last_seen_at = NOW() - INTERVAL '1 hour'
        WHERE agent_id = $1`,
      [state.agent.agentId],
    );

    const workerUrl = pathToFileURL(
      path.join(repoRoot, "apps", "worker", "src", "certops-worker.js"),
    ).href;
    const worker = await import(workerUrl);
    const client = await pool.connect();
    let summary;
    try {
      summary = await worker.reapExpiredLeases({ client });
    } finally {
      client.release();
    }
    assert.ok(summary.failed >= 1, JSON.stringify(summary));

    const { rows } = await pool.query(
      `SELECT status, error_code FROM certificate_jobs WHERE id = $1`,
      [jobId],
    );
    assert.equal(rows[0].status, "failed");
    assert.equal(rows[0].error_code, "agent_offline");
  });

  it("sequence enforcement: monotonic accepted, regression 409, re-register resets the generation, sequence-less accepted", async (t) => {
    if (!dbAvailable) return t.skip(skipReason);

    const agentId = `e2e-agent-${RUN_ID}-seq`;
    const lastSequenceOf = async () => {
      const { rows } = await pool.query(
        `SELECT last_sequence FROM certops_agents WHERE agent_id = $1`,
        [agentId],
      );
      return Number(rows[0].last_sequence);
    };

    // Register with a sequence: the new generation starts at that value.
    const boot1 = await createBootstrap();
    const reg1 = await postAgent(
      "register",
      boot1.plaintextToken,
      envelope(
        "register",
        agentId,
        { bootstrapTokenId: String(boot1.token.id), agentVersion: "1.0.0" },
        { sequence: 3 },
      ),
    );
    assert.equal(reg1.status, 201, JSON.stringify(reg1.body));
    assert.equal(await lastSequenceOf(), 3);

    const heartbeatWith = (sequence) =>
      postAgent(
        "heartbeat",
        reg1.body.credential,
        envelope(
          "heartbeat",
          agentId,
          { agentVersion: "1.0.0" },
          sequence === undefined ? {} : { sequence },
        ),
      );

    // Normal increasing sequence is accepted.
    const hb4 = await heartbeatWith(4);
    assert.equal(hb4.status, 200, JSON.stringify(hb4.body));
    assert.equal(await lastSequenceOf(), 4);

    // Replayed (equal) and lower sequences are rejected with 409 and do not
    // move the high-water mark.
    for (const stale of [4, 2]) {
      const rejected = await heartbeatWith(stale);
      assert.equal(rejected.status, 409, JSON.stringify(rejected.body));
      assert.equal(rejected.body.code, "CERTOPS_AGENT_SEQUENCE_REGRESSION");
    }
    assert.equal(await lastSequenceOf(), 4);

    // A claim poll also participates in the same per-agent counter.
    const claim = await postAgent(
      "jobs/claim",
      reg1.body.credential,
      envelope(
        "claim",
        agentId,
        { maxJobs: 1, supportedActions: ["renew"] },
        { sequence: 5 },
      ),
    );
    assert.equal(claim.status, 200, JSON.stringify(claim.body));
    assert.equal(await lastSequenceOf(), 5);

    // Backward compatibility: an envelope without a sequence is processed
    // as today and leaves last_sequence untouched.
    const legacy = await heartbeatWith(undefined);
    assert.equal(legacy.status, 200, JSON.stringify(legacy.body));
    assert.equal(await lastSequenceOf(), 5);

    // Re-register (decommission + fresh install with the same agentId):
    // registration begins a new generation, so a low restarted counter is
    // accepted again. All FKs to certops_agents are ON DELETE SET NULL.
    await pool.query(`DELETE FROM certops_agents WHERE agent_id = $1`, [
      agentId,
    ]);
    const boot2 = await createBootstrap();
    const reg2 = await postAgent(
      "register",
      boot2.plaintextToken,
      envelope(
        "register",
        agentId,
        { bootstrapTokenId: String(boot2.token.id), agentVersion: "1.0.0" },
        { sequence: 1 },
      ),
    );
    assert.equal(reg2.status, 201, JSON.stringify(reg2.body));
    assert.equal(await lastSequenceOf(), 1);

    const restarted = await postAgent(
      "heartbeat",
      reg2.body.credential,
      envelope(
        "heartbeat",
        agentId,
        { agentVersion: "1.0.0" },
        { sequence: 2 },
      ),
    );
    assert.equal(restarted.status, 200, JSON.stringify(restarted.body));
    assert.equal(await lastSequenceOf(), 2);
  });
});
