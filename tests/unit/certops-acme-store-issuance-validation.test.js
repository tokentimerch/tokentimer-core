"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { createAcmeStoreIssueTx } = require("../../apps/api/services/certops/acmeStoreIssuance");

test("ACME store rejects explicit empty or invalid key options rather than defaulting them", async () => {
  const client = { async query(sql) {
    if (sql.includes("pg_advisory_xact_lock")) return { rows: [] };
    if (sql.includes("SELECT id FROM managed_certificates")) return { rows: [] };
    if (sql.includes("FROM certops_agents")) return { rows: [{ agent_id: "agent-one", status: "active", platform: "win32",
      declared_capabilities: ["windows-store-only-acme-v1", "evidence-claim-binding-v1"], capabilities_updated_at: new Date() }] };
    throw new Error(`unexpected write: ${sql}`);
  } };
  const options = { client, transactionOwned: true, workspaceId: "11111111-1111-4111-8111-111111111111",
    assignedAgentId: "22222222-2222-4222-8222-222222222222", idempotencyKey: "issue-1",
    payload: { target: { type: "windows-cert-store", reference: "host.example.com", store: "My" },
      caEndpoint: "https://ca.example.com/directory", commandRef: "certbot", dnsProvider: "dns", dnsZone: "example.com" } };
  for (const value of [{ keySize: 0 }, { keySize: null }, { keyAlgorithm: "" }, { keyAlgorithm: null }]) {
    await assert.rejects(createAcmeStoreIssueTx({ ...options, payload: { ...options.payload, ...value } }),
      { code: "CERTOPS_ACME_STORE_INVALID" });
  }
});
