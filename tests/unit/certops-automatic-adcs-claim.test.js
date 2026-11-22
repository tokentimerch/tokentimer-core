"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { lockAutomaticAdcsRenewalForClaim } = require("../../apps/api/services/certops/managementClaim");

const target = { type: "windows-iis", reference: "app.example.test", store: "My", binding: { site: "Site", port: 443 } };
const profile = { target, sanPolicy: { sans: ["app.example.test"] }, keyAlgorithm: "rsa", keySize: 2048 };
const snapshot = { authorizedDnsNames: ["app.example.test"], keyAlgorithm: "rsa", keySize: 2048 };
const baseJob = { status: "pending", source: "automation", operation: "renew", attempt_count: 0,
  enrollment_id: "enrollment", subject_type: "managed_certificate", subject_id: "certificate", id: "job", management_period_id: "period", certificate_identity_id:"identity", assigned_agent_id:"agent" };
const baseRow = { automation_enabled: true, renewal_profile_id: "profile", profile_id: "profile", profile_status: "active",
  issuer_id: "issuer", enrolled_issuer_id: "issuer", current_version: 1, issuer_version: 1,
  currently_due:true,current_identity_id:"identity",fingerprint_sha256:"a".repeat(64),identity_fingerprint:"a".repeat(64),enrolled_agent_id:"agent",
  public_metadata: { renewalProfile: profile }, snapshot_bytes: Buffer.from(JSON.stringify(snapshot)), deploy_target: target };

test("automatic AD CS claim revalidates locked policy and frozen intent", async () => {
  const query = async (row) => {
    let sql;
    const allowed = await lockAutomaticAdcsRenewalForClaim({ client: { async query(text) { sql = text; return { rows: row ? [row] : [] }; } }, job: baseJob, workspaceId: "ws" });
    assert.match(sql, /FOR SHARE OF period, mc, cp, issuer SKIP LOCKED/);
    return allowed;
  };
  assert.equal(await query(baseRow), true);
  for (const row of [null, { ...baseRow, automation_enabled: false }, { ...baseRow, currently_due:false }, { ...baseRow, profile_status: "disabled" },
    { ...baseRow, profile_status: "archived" }, { ...baseRow, revalidation_required: true },
    { ...baseRow, snapshot_bytes: Buffer.from("invalid") }]) assert.equal(await query(row), false);
  for (const row of [{ ...baseRow, issuer_id:"other" }, { ...baseRow, issuer_id:"other",revalidation_required:true }, { ...baseRow, current_version:2 },
    { ...baseRow, renewal_profile_id:"other" }, { ...baseRow, fingerprint_sha256:"b".repeat(64) },
    { ...baseRow, deploy_target:{...target,binding:{site:"Site",port:444}} }]) assert.equal(await query(row), "supersede");
  const ipTarget={...target,binding:{site:"Site",port:443,address:"192.0.2.1"}};
  assert.equal(await query({...baseRow,deploy_target:ipTarget,deployed_agent_id:"other"}),"supersede");
  assert.equal(await query({...baseRow,deploy_target:ipTarget,deployed_agent_id:null}),false);
});

test("manual work, continuations and already-started claims keep their existing recovery path", async () => {
  for (const job of [{ ...baseJob, source: "manual" }, { ...baseJob, operation: "continue-enrollment" },
    { ...baseJob, status: "claimed", attempt_count: 1 }, { ...baseJob, attempt_count: 1 },
    { ...baseJob, enrollment_id: null }]) {
    assert.equal(await lockAutomaticAdcsRenewalForClaim({ client: { query() { assert.fail("unexpected query"); } }, job, workspaceId: "ws" }), true);
  }
});
