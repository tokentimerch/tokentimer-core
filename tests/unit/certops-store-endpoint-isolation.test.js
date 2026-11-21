"use strict";

const { it } = require("node:test");
const assert = require("node:assert/strict");
const { linkReconciledCertificateToken } = require("../../apps/api/services/certops/inventory");

it("keeps endpoint expiry and its alert when the machine store receives a replacement", async () => {
  const tokens = new Map([[10, { expiration: "2026-11-10", issuer: "old" }]]);
  const endpoint = { tokenId: 10, fingerprint: "old", expiry: "2026-11-10" };
  const alerts = [{ tokenId: 10, status: "pending" }];
  let managedTokenId = 10;
  let allocations = 0;
  const client = { async query(sql, params) {
    if (sql.includes("pg_advisory_xact_lock")) return { rows: [] };
    if (sql.includes("FOR UPDATE") && sql.includes("FROM tokens")) return { rows: [{ id: params[1] }] };
    if (sql.includes("FROM domain_monitors")) return { rows: params[1] === endpoint.tokenId ? [{ "?column?": 1 }] : [] };
    if (sql.includes("INSERT INTO tokens")) { allocations++; tokens.set(11, { expiration: params[4], issuer: params[5] }); return { rows: [{ id: 11 }] }; }
    if (sql.includes("DELETE FROM token_contact_groups") || sql.includes("SET contact_group_id")) return { rows: [] };
    if (sql.includes("SELECT expiration::text")) return { rows: [{ expiration: tokens.get(params[0]).expiration }] };
    if (sql.includes("UPDATE alert_queue")) { alerts.filter(a => a.tokenId === params[0]).forEach(a => { a.status = "sent"; }); return { rows: [] }; }
    if (sql.includes("UPDATE tokens")) { Object.assign(tokens.get(params[0]), { expiration: params[2], issuer: params[3] }); return { rows: [] }; }
    if (sql.includes("UPDATE managed_certificates")) { managedTokenId = params[2]; return { rows: [] }; }
    throw new Error(`unexpected query ${sql}`);
  } };
  const certificate = { commonName: "web.example.com", subjectAltNames: ["web.example.com"], issuer: "new", notAfter: new Date("2027-11-10T00:00:00Z") };
  const args = { client, workspaceId: "11111111-1111-4111-8111-111111111111", certificateId: "22222222-2222-4222-8222-222222222222", certificate, isolateFromEndpoint: true };
  assert.equal(await linkReconciledCertificateToken({ ...args, existingTokenId: managedTokenId }), 11);
  assert.equal(tokens.get(10).expiration, endpoint.expiry);
  assert.equal(endpoint.fingerprint, "old");
  assert.equal(alerts[0].status, "pending");
  assert.equal(tokens.get(managedTokenId).expiration, "2027-11-10");
  assert.equal(await linkReconciledCertificateToken({ ...args, existingTokenId: managedTokenId }), 11);
  assert.equal(allocations, 1);
});
