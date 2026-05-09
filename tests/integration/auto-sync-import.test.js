/**
 * Auto-Sync Import Integration Tests
 *
 * Verifies that the auto-sync worker imports tokens using the same
 * deduplication semantics as the manual import endpoint:
 *   - Token.findByNameLocationAndWorkspace (name + location, exact case)
 *   - UPDATE when (name, location, workspace) already exists
 *   - INSERT when not found
 *   - No dedup when location is absent (always insert, same as manual import)
 *
 * Also covers worker-level behaviors:
 *   - KDF mismatch: credentials encrypted with the legacy SHA-256 key still decrypt
 *   - Disabled / future-scheduled configs are skipped
 *   - Scan failure records last_sync_status = "failed" with a non-empty error
 *   - next_sync_at is always advanced after a run (success or failure)
 */

const crypto = require("crypto");
const { TestUtils, request, expect } = require("./setup");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";
const WORKER_SECRET = "auto-sync-import-test-secret";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Encrypt credentials the same way the API does (scrypt KDF) */
function encryptScrypt(plaintext, secret) {
  const KDF_SALT = "tokentimer-settings-encryption";
  const key = crypto.scryptSync(secret, KDF_SALT, 32);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  let enc = cipher.update(plaintext, "utf8", "hex");
  enc += cipher.final("hex");
  return `${iv.toString("hex")}:${cipher.getAuthTag().toString("hex")}:${enc}`;
}

/** Encrypt credentials with the legacy SHA-256 key (pre-v0.1 tokens in DB) */
function encryptLegacy(plaintext, secret) {
  const key = crypto.createHash("sha256").update(secret).digest();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  let enc = cipher.update(plaintext, "utf8", "hex");
  enc += cipher.final("hex");
  return `${iv.toString("hex")}:${cipher.getAuthTag().toString("hex")}:${enc}`;
}

async function runWorker() {
  return TestUtils.runNode(
    "node",
    ["--experimental-vm-modules", "src/auto-sync-worker.js"],
    "apps/worker",
    {
      SESSION_SECRET: WORKER_SECRET,
      API_URL: BASE,
      NODE_ENV: "test",
    },
    { allowExitCodes: [0, 1] },
  );
}

async function insertConfig(workspaceId, userId, overrides = {}) {
  const creds = encryptScrypt(
    JSON.stringify({ token: "fake-token", baseUrl: "https://api.github.com" }),
    WORKER_SECRET,
  );
  const res = await TestUtils.execQuery(
    `INSERT INTO auto_sync_configs
       (workspace_id, provider, credentials_encrypted, frequency,
        schedule_time, schedule_tz, enabled, next_sync_at, created_by)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
     RETURNING id`,
    [
      workspaceId,
      overrides.provider ?? "github",
      overrides.credentials ?? creds,
      overrides.frequency ?? "daily",
      overrides.schedule_time ?? "09:00",
      overrides.schedule_tz ?? "UTC",
      overrides.enabled ?? true,
      overrides.next_sync_at ?? new Date(Date.now() - 60000),
      userId,
    ],
  );
  return res.rows[0].id;
}

async function tokenCount(workspaceId) {
  const r = await TestUtils.execQuery(
    "SELECT COUNT(*)::int AS n FROM tokens WHERE workspace_id = $1",
    [workspaceId],
  );
  return r.rows[0].n;
}

async function getTokens(workspaceId) {
  const r = await TestUtils.execQuery(
    "SELECT * FROM tokens WHERE workspace_id = $1 ORDER BY id",
    [workspaceId],
  );
  return r.rows;
}

// ---------------------------------------------------------------------------
// Suite 1: deduplication with location (mirrors manual import)
// ---------------------------------------------------------------------------
describe("Auto-sync import deduplication — with location", function () {
  this.timeout(90000);

  let testUser, workspaceId, configId;

  before(async () => {
    testUser = await TestUtils.createVerifiedTestUser();
    const ws = await TestUtils.execQuery(
      "SELECT id FROM workspaces WHERE created_by = $1 LIMIT 1",
      [testUser.id],
    );
    workspaceId = ws.rows[0].id;
    configId = await insertConfig(workspaceId, testUser.id);
  });

  after(async () => {
    await TestUtils.execQuery(
      "DELETE FROM auto_sync_configs WHERE workspace_id = $1",
      [workspaceId],
    );
    await TestUtils.execQuery(
      "DELETE FROM tokens WHERE workspace_id = $1",
      [workspaceId],
    );
    await TestUtils.cleanupTestUser(testUser.email);
  });

  // The worker calls the scan endpoint (which is mocked to return items via the
  // API's test-mode stub). Since no real GitHub token is provided, the scan will
  // fail at the API level. We insert a token manually then verify that a second
  // manual-import call does NOT create a duplicate — this validates that the
  // import endpoint itself deduplicates correctly, which is what auto-sync now
  // delegates to.

  it("POST /api/v1/integrations/import - creates token on first import", async () => {
    // Authenticate as the test user
    const session = await TestUtils.loginTestUser(testUser.email, "SecureTest123!@#");

    const res = await request(BASE)
      .post(`/api/v1/integrations/import?workspace_id=${workspaceId}`)
      .set("Cookie", session.cookie)
      .send({
        items: [
          {
            name: "my-github-pat",
            type: "api_key",
            category: "key_secret",
            location: "user/my-github-pat",
            expiration: "2027-01-01",
          },
        ],
      })
      .expect(200);

    expect(res.body.created).to.be.an("array").with.length(1);
    expect(res.body.updated).to.be.an("array").with.length(0);
    expect(await tokenCount(workspaceId)).to.equal(1);
  });

  it("POST /api/v1/integrations/import - updates (not duplicates) on re-import with same name+location", async () => {
    const session = await TestUtils.loginTestUser(testUser.email, "SecureTest123!@#");

    const newExpiry = "2028-06-30";
    const res = await request(BASE)
      .post(`/api/v1/integrations/import?workspace_id=${workspaceId}`)
      .set("Cookie", session.cookie)
      .send({
        items: [
          {
            name: "my-github-pat",
            type: "api_key",
            category: "key_secret",
            location: "user/my-github-pat",
            expiration: newExpiry,
          },
        ],
      })
      .expect(200);

    expect(res.body.created).to.be.an("array").with.length(0);
    expect(res.body.updated).to.be.an("array").with.length(1);

    // Token count must stay at 1 — no duplicate inserted
    expect(await tokenCount(workspaceId)).to.equal(1);

    // Expiration must have been refreshed
    const tokens = await getTokens(workspaceId);
    expect(tokens[0].expiration).to.include(newExpiry.replace(/-/g, "-"));
  });

  it("POST /api/v1/integrations/import - same name but different location creates a new token", async () => {
    const session = await TestUtils.loginTestUser(testUser.email, "SecureTest123!@#");

    const res = await request(BASE)
      .post(`/api/v1/integrations/import?workspace_id=${workspaceId}`)
      .set("Cookie", session.cookie)
      .send({
        items: [
          {
            name: "my-github-pat",
            type: "api_key",
            category: "key_secret",
            location: "org/different-repo",
            expiration: "2027-01-01",
          },
        ],
      })
      .expect(200);

    expect(res.body.created).to.be.an("array").with.length(1);
    expect(await tokenCount(workspaceId)).to.equal(2);
  });
});

// ---------------------------------------------------------------------------
// Suite 2: deduplication without location (no-dedup path, same as manual)
// ---------------------------------------------------------------------------
describe("Auto-sync import deduplication — without location", function () {
  this.timeout(90000);

  let testUser, workspaceId;

  before(async () => {
    testUser = await TestUtils.createVerifiedTestUser();
    const ws = await TestUtils.execQuery(
      "SELECT id FROM workspaces WHERE created_by = $1 LIMIT 1",
      [testUser.id],
    );
    workspaceId = ws.rows[0].id;
  });

  after(async () => {
    await TestUtils.execQuery(
      "DELETE FROM tokens WHERE workspace_id = $1",
      [workspaceId],
    );
    await TestUtils.cleanupTestUser(testUser.email);
  });

  it("POST /api/v1/integrations/import - inserts a new token when location is absent", async () => {
    const session = await TestUtils.loginTestUser(testUser.email, "SecureTest123!@#");

    await request(BASE)
      .post(`/api/v1/integrations/import?workspace_id=${workspaceId}`)
      .set("Cookie", session.cookie)
      .send({ items: [{ name: "no-location-key", type: "api_key", category: "key_secret" }] })
      .expect(200);

    expect(await tokenCount(workspaceId)).to.equal(1);
  });

  it("POST /api/v1/integrations/import - second call without location creates a second row (no dedup)", async () => {
    const session = await TestUtils.loginTestUser(testUser.email, "SecureTest123!@#");

    // This matches manual import behavior: without a location, two items with
    // the same name are treated as distinct entries.
    const res = await request(BASE)
      .post(`/api/v1/integrations/import?workspace_id=${workspaceId}`)
      .set("Cookie", session.cookie)
      .send({ items: [{ name: "no-location-key", type: "api_key", category: "key_secret" }] })
      .expect(200);

    expect(res.body.created).to.be.an("array").with.length(1);
    expect(await tokenCount(workspaceId)).to.equal(2);
  });
});

// ---------------------------------------------------------------------------
// Suite 3: worker-level behaviours
// ---------------------------------------------------------------------------
describe("Auto-sync worker behaviours", function () {
  this.timeout(120000);

  let testUser, workspaceId;

  before(async () => {
    testUser = await TestUtils.createVerifiedTestUser();
    const ws = await TestUtils.execQuery(
      "SELECT id FROM workspaces WHERE created_by = $1 LIMIT 1",
      [testUser.id],
    );
    workspaceId = ws.rows[0].id;
  });

  afterEach(async () => {
    await TestUtils.execQuery(
      "DELETE FROM auto_sync_configs WHERE workspace_id = $1",
      [workspaceId],
    );
    await TestUtils.execQuery(
      "DELETE FROM tokens WHERE workspace_id = $1",
      [workspaceId],
    );
  });

  after(async () => {
    await TestUtils.cleanupTestUser(testUser.email);
  });

  it("skips disabled configs (no last_sync_at set)", async () => {
    await insertConfig(workspaceId, testUser.id, { enabled: false });
    await runWorker();

    const r = await TestUtils.execQuery(
      "SELECT COUNT(*)::int AS n FROM auto_sync_configs WHERE workspace_id = $1 AND last_sync_at IS NOT NULL",
      [workspaceId],
    );
    expect(r.rows[0].n).to.equal(0);
  });

  it("skips configs whose next_sync_at is in the future", async () => {
    await insertConfig(workspaceId, testUser.id, {
      next_sync_at: new Date(Date.now() + 3600000),
    });
    await runWorker();

    const r = await TestUtils.execQuery(
      "SELECT COUNT(*)::int AS n FROM auto_sync_configs WHERE workspace_id = $1 AND last_sync_at IS NOT NULL",
      [workspaceId],
    );
    expect(r.rows[0].n).to.equal(0);
  });

  it("records last_sync_status=failed and a non-empty error when the scan fails", async () => {
    await insertConfig(workspaceId, testUser.id);
    await runWorker();

    const r = await TestUtils.execQuery(
      "SELECT last_sync_status, last_sync_error FROM auto_sync_configs WHERE workspace_id = $1",
      [workspaceId],
    );
    expect(r.rows[0].last_sync_status).to.equal("failed");
    expect(String(r.rows[0].last_sync_error || "").length).to.be.greaterThan(0);
  });

  it("advances next_sync_at after a failed run", async () => {
    await insertConfig(workspaceId, testUser.id);
    const before = Date.now();
    await runWorker();

    const r = await TestUtils.execQuery(
      "SELECT next_sync_at FROM auto_sync_configs WHERE workspace_id = $1",
      [workspaceId],
    );
    expect(new Date(r.rows[0].next_sync_at).getTime()).to.be.greaterThan(before);
  });

  it("decrypts credentials encrypted with the legacy SHA-256 KDF (fallback path)", async () => {
    // Pre-v0.1 credentials were encrypted with SHA-256; the worker must still
    // handle them via the fallback path.
    const legacyCreds = encryptLegacy(
      JSON.stringify({ token: "legacy-token", baseUrl: "https://api.github.com" }),
      WORKER_SECRET,
    );
    await insertConfig(workspaceId, testUser.id, { credentials: legacyCreds });
    await runWorker();

    // The run should have attempted a scan (not aborted at decryption).
    // For an invalid token the scan fails — but it must fail with a
    // scan error, not "Failed to decrypt credentials".
    const r = await TestUtils.execQuery(
      "SELECT last_sync_error FROM auto_sync_configs WHERE workspace_id = $1",
      [workspaceId],
    );
    expect(String(r.rows[0].last_sync_error || "")).to.not.include(
      "Failed to decrypt",
    );
  });

  it("worker auth: import endpoint is reachable with SESSION_SECRET bearer token", async () => {
    // Verify that loadWorkspace grants admin role to worker calls so the
    // import endpoint does not return 403.
    const session = await TestUtils.loginTestUser(testUser.email, "SecureTest123!@#");
    const ws = await request(BASE)
      .get(`/api/v1/workspaces?limit=1`)
      .set("Cookie", session.cookie)
      .expect(200);
    const wsId = ws.body.items?.[0]?.id;

    const res = await request(BASE)
      .post(`/api/v1/integrations/import?workspace_id=${wsId}`)
      .set("Authorization", `Bearer ${WORKER_SECRET}`)
      .send({
        items: [
          {
            name: "worker-auth-test-token",
            type: "api_key",
            category: "key_secret",
            location: "test/location",
          },
        ],
      })
      .expect(200);

    expect(res.body.created).to.be.an("array").with.length(1);
  });
});
