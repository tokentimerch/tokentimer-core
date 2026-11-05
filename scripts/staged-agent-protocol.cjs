"use strict";

// Public-route acceptance for a disposable composed API. This is a protocol
// client, not native certificate, installed-agent or external CA qualification.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { verifyJobSignature, checkJobTimeWindow, checkAgentIdBinding } = require("../packages/agent/src/signing");
const agentVersion = require("../packages/agent/package.json").version;

function validateTarget({ baseUrl, workspaceId, disposable, sessionCookie, csrfToken }) {
  assert.equal(disposable, true, "Explicit disposable-stack authorization required");
  const url = new URL(baseUrl);
  assert.ok(["http:", "https:"].includes(url.protocol), "HTTP API required");
  assert.ok(["127.0.0.1", "localhost", "[::1]"].includes(url.hostname), "Only a loopback disposable API is accepted");
  assert.equal(url.username + url.password + url.search + url.hash, "", "Bare API origin required");
  assert.equal(url.pathname, "/", "Bare API origin required");
  assert.match(workspaceId || "", /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i, "Fixture workspace UUID required");
  assert.ok(typeof sessionCookie === "string" && sessionCookie.length > 0, "Authenticated fixture session required");
  assert.ok(typeof csrfToken === "string" && csrfToken.length > 0, "Fixture CSRF token required");
  return url.origin;
}

function expectStatus(response, expected, step) {
  // Never include response bodies: registration returns plaintext credentials.
  assert.equal(response.status, expected, `${step}: unexpected HTTP status`);
}

async function runStagedAgentProtocol(options) {
  const origin = validateTarget(options);
  const { workspaceId, sessionCookie, csrfToken, edition } = options;
  assert.ok(["core", "cloud", "enterprise"].includes(edition), "Edition required");
  const prefix = `/api/v1/workspaces/${workspaceId}/certops`;
  const agentId = `staged-${crypto.randomUUID()}`;
  let credential, bootstrapTokenId, agentRowId;
  const checks = [];
  const passed = (name) => checks.push(name);

  async function request(route, method, body, machineToken) {
    const response = await fetch(new URL(route, origin), {
      method,
      redirect: "error",
      signal: AbortSignal.timeout(30000),
      headers: {
        "content-type": "application/json",
        ...(machineToken ? { authorization: `Bearer ${machineToken}` } : { cookie: sessionCookie, "x-csrf-token": csrfToken }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    let value;
    try { value = await response.json(); } catch { value = null; }
    return { status: response.status, body: value };
  }
  const session = (route, method = "GET", body) => request(route, method, body);
  const machine = (route, messageType, body, token = credential) => request(`/api/v1/certops/agent/${route}`, "POST", {
    schemaVersion: 1, protocolVersion: "1.0.0", messageType, agentId, sentAt: new Date().toISOString(), body,
  }, token);

  let failure;
  try {
    const bootstrap = await session(`${prefix}/agent-bootstrap-tokens`, "POST", {
      name: "Disposable staged protocol acceptance", expiresAt: new Date(Date.now() + 600000).toISOString(),
    });
    expectStatus(bootstrap, 201, "bootstrap");
    bootstrapTokenId = bootstrap.body?.token?.id;
    assert.ok(bootstrapTokenId, "Bootstrap token identifier absent");
    assert.ok(bootstrap.body?.plaintextToken, "Bootstrap credential absent");
    const registrationBody = {
      bootstrapTokenId, registrationId: crypto.randomUUID(), hostname: "disposable-staged-protocol",
      platform: "linux", agentVersion, declaredCapabilities: ["agent-id-binding-v1"],
    };
    const registration = await machine("register", "register", registrationBody, bootstrap.body.plaintextToken);
    expectStatus(registration, 201, "register");
    credential = registration.body?.credential;
    assert.ok(typeof credential === "string" && credential.startsWith("ttagent_"), "Agent credential absent");
    assert.ok(registration.body?.signingKeyId, "Signing key identifier absent");
    assert.match(registration.body?.signingPublicKeyPem || "", /-----BEGIN PUBLIC KEY-----/);
    passed("public-bootstrap-and-registration");

    const heartbeat = await machine("heartbeat", "heartbeat", {
      agentVersion, ntpSynced: true, pinnedSigningKeyId: registration.body.signingKeyId, supportedOperations: ["noop"],
    });
    expectStatus(heartbeat, 200, "heartbeat");
    assert.equal(heartbeat.body?.status, "active");
    passed("authenticated-heartbeat");

    const agents = await session(`${prefix}/agents`);
    expectStatus(agents, 200, "agent-list");
    const row = agents.body?.items?.find((item) => item.agentId === agentId);
    assert.ok(row?.id, "Registered fixture agent absent from fleet");
    agentRowId = row.id;
    const created = await session(`${prefix}/jobs`, "POST", { operation: "noop", assignedAgentId: agentRowId });
    expectStatus(created, 201, "create-noop");
    assert.ok(created.body?.job?.id, "Public noop creation returned no job");
    passed("public-owned-noop-job");

    const claim = await machine("jobs/claim", "claim", { maxJobs: 1, supportedActions: ["noop"] });
    expectStatus(claim, 200, "claim");
    assert.equal(claim.body?.jobs?.length, 1, "Expected exactly the owned noop job");
    const job = claim.body.jobs[0];
    assert.equal(job.jobId, created.body.job.id);
    assert.equal(job.workspaceId, workspaceId);
    assert.equal(job.action, "noop");
    assert.equal(job.agentId, agentId);
    const verify = (value) => verifyJobSignature({ job: value, publicKeyPem: registration.body.signingPublicKeyPem, pinnedSigningKeyId: registration.body.signingKeyId });
    assert.equal(verify(job).allowed, true, "Actual dispatched job signature rejected");
    assert.equal(checkJobTimeWindow({ job, nowMs: Date.now() }).allowed, true, "Actual dispatched job expired");
    assert.equal(checkAgentIdBinding({ job, boundAgentId: agentId, requireSignedAgentId: true }).allowed, true, "Dispatched agent binding rejected");
    assert.equal(verify({ ...job, action: "revoke" }).allowed, false, "Tampered job unexpectedly verified");
    passed("signed-claim-agent-binding-and-tamper-refusal");

    const badCredential = await machine("heartbeat", "heartbeat", { agentVersion }, "ttagent_invalid_disposable_fixture");
    expectStatus(badCredential, 401, "bad-credential");
    passed("invalid-machine-credential-refused");

    const outcome = { jobId: job.jobId, attemptId: job.attemptId, status: "succeeded", keyRotated: false, nonce: job.nonce };
    const completed = await machine("jobs/results", "result", outcome);
    expectStatus(completed, 200, "result");
    assert.equal(completed.body?.status, "succeeded");
    const duplicate = await machine("jobs/results", "result", outcome);
    expectStatus(duplicate, 200, "duplicate-result");
    assert.equal(duplicate.body?.status, "succeeded");
    assert.equal(duplicate.body?.duplicate, true);
    passed("genuine-result-and-idempotent-duplicate");

    const conflicting = await machine("jobs/results", "result", { ...outcome, status: "failed", errorMessage: "Disposable conflicting outcome" });
    expectStatus(conflicting, 409, "conflicting-result");
    assert.equal(conflicting.body?.code, "CERTOPS_AGENT_RESULT_NONCE_REJECTED");
    passed("conflicting-result-refused");
    const persisted = await session(`${prefix}/jobs/${encodeURIComponent(job.jobId)}`);
    expectStatus(persisted, 200, "persisted-job");
    assert.equal(persisted.body?.job?.status, "succeeded");
    passed("public-terminal-job-oracle");
  } catch (error) { failure = error; }
  const cleanupErrors = [];
  if (agentRowId) {
    try {
      const retired = await session(`${prefix}/agents/${encodeURIComponent(agentRowId)}/retire`, "POST", { force: true, reason: "Disposable staged protocol acceptance cleanup" });
      expectStatus(retired, 200, "retire-owned-agent");
    } catch (error) { cleanupErrors.push(error); }
  }
  if (bootstrapTokenId) {
    try { expectStatus(await session(`${prefix}/agent-bootstrap-tokens/${encodeURIComponent(bootstrapTokenId)}/revoke`, "POST", {}), 200, "revoke-owned-bootstrap"); }
    catch (error) { cleanupErrors.push(error); }
  }
  credential = undefined;
  if (failure || cleanupErrors.length) throw new AggregateError([...(failure ? [failure] : []), ...cleanupErrors], "Staged protocol acceptance failed; inspect assertion steps without logging credentials");
  assert.equal(checks.length, 8, "All staged protocol checks must execute");
  return { edition, origin, checks, passed: checks.length, cleanup: "owned-agent-retired-and-bootstrap-revoked", scope: "public signed machine protocol; no native certificate execution" };
}

module.exports = { runStagedAgentProtocol, validateTarget };

if (require.main === module) {
  runStagedAgentProtocol({
    baseUrl: process.env.TT_STAGED_API_URL,
    workspaceId: process.env.TT_STAGED_WORKSPACE_ID,
    sessionCookie: process.env.TT_STAGED_SESSION_COOKIE,
    csrfToken: process.env.TT_STAGED_CSRF_TOKEN,
    disposable: process.env.TT_STAGED_DISPOSABLE === "1",
    edition: process.env.TT_STAGED_EDITION,
  }).then((result) => console.log(JSON.stringify(result))).catch((error) => {
    console.error(error.message);
    for (const nested of error.errors || []) console.error(nested.message);
    process.exitCode = 1;
  });
}
