"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const verification = require("../../packages/recipient-verification");
const grace = require("../../packages/recipient-verification/legacy-grace");
const { main: runCommand, buildPool } = require("../../scripts/recipient-legacy-grace.cjs");

const workspaceId = "11111111-1111-4111-8111-111111111111";
const contactId = "22222222-2222-4222-8222-222222222222";
const envKeys = ["TT_DEPLOYMENT", "RECIPIENT_VERIFICATION_MODE", "RECIPIENT_VERIFICATION_CLOUD_SHADOW", "RECIPIENT_VERIFICATION_LEGACY_GRACE", "RECIPIENT_FINGERPRINT_SECRET"];
const previousEnv = Object.fromEntries(envKeys.map(key => [key, process.env[key]]));

test.beforeEach(() => {
  process.env.TT_DEPLOYMENT = "cloud";
  process.env.RECIPIENT_VERIFICATION_MODE = "enforce";
  process.env.RECIPIENT_FINGERPRINT_SECRET = "grace-unit-test-only";
  delete process.env.RECIPIENT_VERIFICATION_CLOUD_SHADOW;
  delete process.env.RECIPIENT_VERIFICATION_LEGACY_GRACE;
});
test.after(() => {
  for (const key of envKeys) {
    if (previousEnv[key] === undefined) delete process.env[key];
    else process.env[key] = previousEnv[key];
  }
});

function database({ status = "pending", suppression, expiresAt, unavailable = false } = {}) {
  const calls = [];
  return {
    calls,
    async query(sql, params) {
      calls.push({ sql, params });
      if (sql.includes("RV_SUPPRESSION_LOOKUP")) return { rows: suppression ? [{ reason: suppression }] : [] };
      if (sql.includes("RV_DELIVERY_LOOKUP")) return { rows: status ? [{ status, consent_at: status === "verified" ? new Date() : null }] : [] };
      if (sql.includes("RV_LEGACY_GRACE_LOOKUP")) {
        if (unavailable) throw Object.assign(new Error("synthetic timeout"), { code: "57014" });
        return { rows: expiresAt ? [{ expires_at: expiresAt }] : [] };
      }
      if (sql.includes("RV_LIST_STATUS") || sql.includes("RV_LIST_CHALLENGES")) return { rows: [] };
      throw new Error("Unexpected query in unit fixture");
    },
  };
}

function recipient(client, channel = "email") {
  return { client, workspaceId, contactId, channel, destination: channel === "email" ? "legacy@example.test" : "+14155550100" };
}

test("grace is opt-in and never weakens the effective enforce mode", async () => {
  const client = database({ expiresAt: new Date(Date.now() + 60000) });
  assert.equal((await verification.canDeliverToRecipient(recipient(client))).allowed, false);
  assert.equal(client.calls.some(call => call.sql.includes("RV_LEGACY_GRACE_LOOKUP")), false);
  process.env.RECIPIENT_VERIFICATION_LEGACY_GRACE = "1";
  assert.equal(verification.resolveEnforcementMode(), "enforce");
  assert.equal(verification.describeEnforcement().legacyGraceEnabled, true);
  assert.equal(verification.legacyGraceEnabled({ TT_DEPLOYMENT: "typo", RECIPIENT_VERIFICATION_LEGACY_GRACE: "1" }), false);
});

test("an active legacy grant allows pending email and WhatsApp while preserving its basis and deadline", async () => {
  process.env.RECIPIENT_VERIFICATION_LEGACY_GRACE = "1";
  const expiresAt = new Date(Date.now() + 60000).toISOString();
  for (const channel of ["email", "whatsapp"]) {
    for (const status of ["pending", null]) {
      const client = database({ status, expiresAt });
      const result = await verification.canDeliverToRecipient(recipient(client, channel));
      assert.deepEqual(result, { allowed: true, mode: "enforce", shadowBlocked: false, code: null,
        delivery_basis: "legacy_grace", grace_expires_at: expiresAt });
      const lookup = client.calls.find(call => call.sql.includes("RV_LEGACY_GRACE_LOOKUP"));
      assert.deepEqual(lookup.params.slice(0, 4), [workspaceId, contactId, channel, recipient(client, channel).destination]);
      assert.equal(lookup.params[4], verification.destinationFingerprint(channel, recipient(client, channel).destination));
    }
  }
});

test("explicit refusals and suppression win before a legacy grant can be considered", async () => {
  process.env.RECIPIENT_VERIFICATION_LEGACY_GRACE = "1";
  for (const input of [
    { status: "revoked", code: "RECIPIENT_REVOKED" },
    { status: "opted_out", code: "RECIPIENT_OPTED_OUT" },
    { suppression: "recipient_declined", code: "RECIPIENT_OPTED_OUT" },
    { suppression: "verification_abuse", code: "RECIPIENT_SUPPRESSED" },
  ]) {
    const client = database({ ...input, expiresAt: new Date(Date.now() + 60000) });
    const result = await verification.canDeliverToRecipient(recipient(client));
    assert.equal(result.allowed, false);
    assert.equal(result.code, input.code);
    assert.equal(result.delivery_basis, undefined);
    assert.equal(client.calls.some(call => call.sql.includes("RV_LEGACY_GRACE_LOOKUP")), false);
  }
});

test("absent and expired grants block delivery; unavailable grace lookup remains retryable", async () => {
  process.env.RECIPIENT_VERIFICATION_LEGACY_GRACE = "1";
  for (const expiresAt of [undefined, new Date(Date.now() - 1), "invalid"]) {
    const result = await verification.canDeliverToRecipient(recipient(database({ expiresAt })));
    assert.equal(result.allowed, false);
    assert.equal(result.code, "RECIPIENT_NOT_VERIFIED");
  }
  const client = database({ unavailable: true });
  const gated = await verification.filterDeliveryRecipients({ client, workspaceId, channel: "email",
    recipients: [{ contactId, destination: "legacy@example.test" }] });
  assert.equal(gated.allowed.length, 0);
  assert.equal(gated.unavailable, true);
  assert.equal(gated.code, "RECIPIENT_VERIFICATION_UNAVAILABLE");
});

test("contact views keep pending status and expose temporary delivery without fabricating consent", async () => {
  process.env.RECIPIENT_VERIFICATION_LEGACY_GRACE = "1";
  const expiresAt = new Date(Date.now() + 60000).toISOString();
  const result = await verification.attachVerification(database({ expiresAt }), workspaceId,
    [{ id: contactId, details: { email: "legacy@example.test" }, phone_e164: "+14155550100" }]);
  for (const channel of ["email", "whatsapp"]) {
    assert.equal(result.items[0].verification[channel].status, "pending");
    assert.equal(result.items[0].verification[channel].delivery_basis, "legacy_grace");
    assert.equal(result.items[0].verification[channel].grace_expires_at, expiresAt);
    assert.ok(!result.items[0].verification[channel].consent_at);
    assert.equal(result.verification_summary[channel].verified, 0);
    assert.equal(result.verification_summary[channel].pending, 1);
  }
});

test("the explicit emergency shadow mode retains its existing semantics", async () => {
  process.env.RECIPIENT_VERIFICATION_MODE = "shadow";
  process.env.RECIPIENT_VERIFICATION_CLOUD_SHADOW = "1";
  const result = await verification.canDeliverToRecipient(recipient(database({ status: "opted_out" })));
  assert.equal(result.allowed, true);
  assert.equal(result.shadowBlocked, true);
  assert.equal(result.code, "RECIPIENT_OPTED_OUT");
  assert.equal(result.delivery_basis, undefined);
});

test("contact grace enrichment bounds concurrent database queries for large contact pages", async () => {
  process.env.RECIPIENT_VERIFICATION_LEGACY_GRACE = "1";
  const base = database();
  let active = 0;
  let maximum = 0;
  const client = { async query(...args) {
    active += 1;
    maximum = Math.max(maximum, active);
    try {
      await new Promise(resolve => setImmediate(resolve));
      return await base.query(...args);
    } finally { active -= 1; }
  } };
  const contacts = Array.from({ length: 40 }, () => ({ id: crypto.randomUUID(), details: { email: "pending@example.test" } }));
  await verification.attachVerification(client, workspaceId, contacts);
  assert.ok(maximum > 1);
  assert.ok(maximum <= 8, `Observed ${maximum} concurrent queries`);
});

function snapshot() {
  const now = Date.now();
  return { version: 1, id: crypto.randomUUID(), cutoff_at: new Date(now - 60000).toISOString(),
    captured_at: new Date(now - 1000).toISOString(), expires_at: new Date(now + 60000).toISOString(),
    recipients: [{ workspace_id: workspaceId, contact_id: contactId, channel: "email", destination: "legacy@example.test", source_version: "123" }] };
}

test("snapshots require a bounded future deadline, a fixed cutoff and unique exact destinations", () => {
  assert.doesNotThrow(() => grace.validateSnapshot(snapshot()));
  for (const transform of [
    value => { delete value.expires_at; },
    value => { value.expires_at = new Date(Date.now() + grace.MAX_GRACE_MS + 60000).toISOString(); },
    value => { value.expires_at = new Date(Date.now() - 100).toISOString(); },
    value => { value.cutoff_at = new Date(Date.now() + 60000).toISOString(); },
    value => { value.cutoff_at = "2026-02-30T00:00:00Z"; },
    value => { value.recipients.push({ ...value.recipients[0] }); },
    value => { value.recipients[0].destination = "Unnormalized@EXAMPLE.TEST"; },
    value => { value.recipients[0].source_version = ""; },
  ]) {
    const value = snapshot();
    transform(value);
    assert.throws(() => grace.validateSnapshot(value), { code: "LEGACY_GRACE_INVALID" });
  }
});

test("activation rejects an altered reviewed snapshot before opening a transaction", async () => {
  const value = snapshot();
  const digest = grace.snapshotDigest(value);
  value.recipients[0].destination = "changed@example.test";
  await assert.rejects(grace.activateLegacyGrace({ pool: { connect: () => assert.fail("must not connect") },
    snapshot: value, expectedSha256: digest, operator: "test-operator" }), { code: "LEGACY_GRACE_INVALID" });
});

test("the operator command preserves API TLS requirements without opening a connection", async () => {
  for (const [mode, environment, verified] of [
    ["verify", "production", true], ["verify", "development", true],
    ["require", "production", true], ["require", "development", false],
    ["require", undefined, false], ["require-no-verify", "production", false],
    ["require-no-verify", "development", false],
  ]) {
    const pool = buildPool({ DB_SSL: mode, NODE_ENV: environment });
    try {
      assert.equal(pool.options.ssl.rejectUnauthorized, verified, `${mode} / ${environment}`);
      assert.equal(pool.options.ssl.minVersion, "TLSv1.3");
      assert.equal(pool.totalCount, 0);
    } finally { await pool.end(); }
  }
  const plain = buildPool({ DB_HOST: "db.example.test", DB_PORT: "55432", DB_NAME: "grace_test",
    DB_USER: "operator", DB_PASSWORD: "test-only", NODE_ENV: "test" });
  try {
    assert.equal(plain.options.ssl, false);
    assert.equal(plain.options.host, "db.example.test");
    assert.equal(plain.options.port, 55432);
    assert.equal(plain.options.database, "grace_test");
    assert.equal(plain.options.user, "operator");
    assert.equal(plain.options.max, 1);
    assert.equal(plain.totalCount, 0);
  } finally { await plain.end(); }
});

test("an explicit database CA always authenticates the server and an unreadable CA fails closed", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "recipient-grace-ca-"));
  const ca = path.join(directory, "root.pem");
  try {
    fs.writeFileSync(ca, "test-only CA content");
    for (const mode of [undefined, "require", "require-no-verify", "verify"]) {
      const pool = buildPool({ DB_SSL: mode, NODE_ENV: "development", PGSSLROOTCERT: ca });
      try {
        assert.equal(pool.options.ssl.ca, "test-only CA content");
        assert.equal(pool.options.ssl.rejectUnauthorized, true);
        assert.equal(pool.options.ssl.minVersion, "TLSv1.3");
        assert.equal(pool.totalCount, 0);
      } finally { await pool.end(); }
    }
    assert.throws(() => buildPool({ PGSSLROOTCERT: path.join(directory, "missing.pem") }), { code: "ENOENT" });
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test("the operator command does not connect or write without explicit --apply", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "recipient-grace-"));
  const file = path.join(directory, "snapshot.json");
  const value = snapshot();
  const previousLog = console.log;
  const messages = [];
  console.log = message => messages.push(message);
  try {
    fs.writeFileSync(file, JSON.stringify(value));
    await runCommand(["activate", "--input", file, "--sha256", grace.snapshotDigest(value), "--operator", "test-operator"]);
    await runCommand(["revoke", "--snapshot-id", value.id]);
    assert.equal(messages.length, 2);
    assert.ok(messages.every(message => message.includes("No changes made")));
  } finally {
    console.log = previousLog;
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
