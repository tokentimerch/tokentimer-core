/**
 * Authenticate a fixture agent through the genuine registration and signed machine protocol.
 * API qualification suites use this client to test server admission and persistence.
 * This helper constructs protocol requests; it does not launch an installed agent or
 * establish native certificate-store/IIS execution evidence. */
"use strict";
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
async function createRegisteredAgent(fixture, baseUrl, declaredCapabilities = [], registrationOptions = {}) {
  const agentId = crypto.randomUUID();
  const prefix = `/api/v1/workspaces/${fixture.workspaceId}/certops`;
  let credential;
  async function machine(route, messageType, body, token = credential) {
    const response = await fetch(new URL(`/api/v1/certops/agent/${route}`, baseUrl), { method: "POST", signal: AbortSignal.timeout(15000), headers: { "content-type": "application/json", authorization: `Bearer ${token}` }, body: JSON.stringify({ schemaVersion: 1, protocolVersion: "1.0.0", messageType, agentId, sentAt: new Date().toISOString(), body }) });
    return { status: response.status, body: await response.json() };
  }
  const bootstrap = await fixture.request(`${prefix}/agent-bootstrap-tokens`, "POST", { name: "Registered protocol fixture", expiresAt: new Date(Date.now() + 3600000).toISOString() }); assert.equal(bootstrap.status, 201);
  const registration = await machine("register", "register", { bootstrapTokenId: bootstrap.body.token.id, registrationId: crypto.randomUUID(), hostname: "registered-protocol-fixture", platform: registrationOptions.platform || "linux", agentVersion: "1.0.0", declaredCapabilities, ...(registrationOptions.declaredCommandProfileNames ? { declaredCommandProfileNames: registrationOptions.declaredCommandProfileNames } : {}), ...(registrationOptions.supportedDnsProviders ? { supportedDnsProviders: registrationOptions.supportedDnsProviders } : {}), ...(registrationOptions.declaredTargetSelectors ? { declaredTargetSelectors: registrationOptions.declaredTargetSelectors } : {}) }, bootstrap.body.plaintextToken); assert.equal(registration.status, 201); credential = registration.body.credential;
  return { agentId, machine, signingKeyId: registration.body.signingKeyId, signingPublicKeyPem: registration.body.signingPublicKeyPem, async claimNoop() {
    const created = await fixture.request(`${prefix}/jobs`, "POST", { operation: "noop" }); assert.equal(created.status, 201);
    const claimed = await machine("jobs/claim", "claim", { maxJobs: 1, supportedActions: ["noop"] }); assert.equal(claimed.status, 200);
    const job = claimed.body.jobs.find((row) => (row.jobId || row.id) === created.body.job.id); assert.ok(job);
    return { jobId: created.body.job.id, claimId: String(job.claimId), job };
  } };
}
module.exports = { createRegisteredAgent };
