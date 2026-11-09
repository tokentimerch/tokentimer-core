"use strict";

const assert = require("node:assert/strict");
const { test } = require("node:test");
const { pathToFileURL } = require("node:url");
const path = require("node:path");
const verification = require("../../packages/recipient-verification");
const workspaceId = "11111111-1111-4111-8111-111111111111";
const contactId = "22222222-2222-4222-8222-222222222222";
const email = "member@example.test";
const keys = ["TT_DEPLOYMENT", "RECIPIENT_VERIFICATION_MODE", "RECIPIENT_FINGERPRINT_SECRET",
  "RECIPIENT_VERIFICATION_LEGACY_GRACE"];
const previous = Object.fromEntries(keys.map(key => [key, process.env[key]]));

test.beforeEach(() => {
  process.env.TT_DEPLOYMENT = "self-hosted";
  process.env.RECIPIENT_VERIFICATION_MODE = "enforce";
  process.env.RECIPIENT_FINGERPRINT_SECRET = "member-unit-test-only";
  delete process.env.RECIPIENT_VERIFICATION_LEGACY_GRACE;
});
test.after(() => {
  for (const key of keys) {
    if (previous[key] === undefined) delete process.env[key];
    else process.env[key] = previous[key];
  }
});

function database({ status, suppression, member = true, error } = {}) {
  const calls = [];
  const client = {
    calls,
    async query(sql, params) {
      calls.push({ sql, params });
      if (["BEGIN", "COMMIT", "ROLLBACK"].includes(sql)) return { rows: [] };
      if (sql.includes("RV_CONTACT")) return { rows: [{ id: contactId, details: { email } }] };
      if (sql.includes("RV_SUPPRESSION_LOOKUP")) return { rows: suppression ? [{ reason: suppression }] : [] };
      if (sql.includes("RV_DELIVERY_LOOKUP")) return { rows: status ? [{ status, consent_at: status === "verified" ? new Date() : null }] : [] };
      if (sql.includes("RV_VERIFIED_MEMBER_EMAILS")) {
        if (error) throw Object.assign(new Error("synthetic lookup failure"), { code: error });
        return { rows: member ? [{ contact_id: contactId, destination_normalized: email }] : [] };
      }
      if (/RV_LIST_(?:STATUS|CHALLENGES|MEMBER_REVOCATIONS)/.test(sql)) return { rows: [] };
      throw new Error("Unexpected member fixture query: " + sql);
    },
    release() {},
  };
  return { ...client, connect: async () => client };
}
const recipient = (client, channel = "email") => ({
  client, workspaceId, contactId, channel, destination: channel === "email" ? email : "+14155550100",
});

test("verified members need no second confirmation with absent or pending consent", async () => {
  for (const status of [undefined, "pending"]) {
    const client = database({ status });
    assert.deepEqual(await verification.canDeliverToRecipient(recipient(client)), {
      allowed: true, mode: "enforce", shadowBlocked: false, code: null, delivery_basis: "verified_member",
    });
    assert.equal(client.calls.some(call => /\b(?:INSERT|UPDATE|DELETE)\b/.test(call.sql)), false);
  }
});

test("member proof never overrides refusals or authorizes WhatsApp", async () => {
  for (const options of [
    { status: "revoked" }, { status: "opted_out" },
    { suppression: "member_verification_revoked" }, { suppression: "recipient_declined" },
    { suppression: "verification_abuse" },
  ]) {
    const client = database(options);
    assert.equal((await verification.canDeliverToRecipient(recipient(client))).allowed, false);
    assert.equal(client.calls.some(call => call.sql.includes("RV_VERIFIED_MEMBER_EMAILS")), false);
  }
  assert.equal((await verification.canDeliverToRecipient(recipient(database(), "whatsapp"))).allowed, false);
  assert.equal((await verification.canDeliverToRecipient(recipient(database({ member: false })))).allowed, false);
});

test("member lookup failure is retryable and explicit confirmation remains independent", async () => {
  for (const error of ["57014", "42703"]) {
    assert.equal((await verification.canDeliverToRecipient(recipient(database({ error })))).code,
      "RECIPIENT_VERIFICATION_UNAVAILABLE");
    assert.equal((await verification.canDeliverToRecipient(recipient(database({ error, status: "verified" })))).allowed, true);
  }
});

test("member contacts show verified without a fabricated consent date or challenge", async () => {
  const client = database();
  const result = await verification.attachVerification(client, workspaceId, [{ id: contactId, details: { email } }]);
  assert.deepEqual(result.items[0].verification.email, {
    status: "verified", delivery_basis: "verified_member", consent_at: null, verified_at: null, invitation: null,
  });
  assert.equal(result.verification_summary.email.verified, 1);
  assert.equal(result.verification_summary.email.pending, 0);
  assert.equal(client.calls.filter(call => call.sql.includes("RV_VERIFIED_MEMBER_EMAILS")).length, 1);
});

test("repeated verification requests do not send challenges or spend invitation quota", async () => {
  const pool = database();
  for (let i = 0; i < 2; i++) {
    const result = await verification.createInvitation({ pool, workspaceId, contactId, channel: "email", actorUserId: 1 });
    assert.equal(result.alreadyVerified, true);
    assert.equal(result.token, null);
  }
  assert.equal(pool.calls.some(call => /\b(?:INSERT|UPDATE|DELETE)\b|pg_advisory/.test(call.sql)), false);
});

test("dashboard distinguishes inherited proof from recipient consent", async () => {
  const { channelStatus } = await import(pathToFileURL(path.resolve(__dirname,
    "../../apps/dashboard/src/pages/contactVerificationStatus.js")).href);
  const result = channelStatus({ verification: { email: {
    status: "verified", delivery_basis: "verified_member",
  } } }, "email");
  assert.equal(result.label, "Verified member");
  assert.equal(result.consent_at, null);
});
