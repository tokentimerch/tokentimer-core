"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  ROUTES,
  AgentProtocolError,
  AGENT_PROTOCOL_ERROR_CODES,
  jitteredDelay,
  withRetry,
  startPollLoop,
  createProtocolClient,
} = require("./index.js");

let originalFetch;

test.beforeEach(() => {
  originalFetch = global.fetch;
});

test.afterEach(() => {
  global.fetch = originalFetch;
});

/**
 * Builds a fake fetch that records every call and returns a queued
 * Response-like object ({ ok, status, json: async () => ... }) per call.
 */
function stubFetch(responses) {
  const calls = [];
  let index = 0;
  global.fetch = async (url, init) => {
    const entry = responses[Math.min(index, responses.length - 1)];
    index += 1;
    calls.push({ url, init, parsedBody: init?.body ? JSON.parse(init.body) : null });
    if (entry.throws) {
      throw entry.throws;
    }
    return {
      ok: entry.status >= 200 && entry.status < 300,
      status: entry.status,
      json: async () => entry.json ?? {},
    };
  };
  return calls;
}

test("register: happy path calls onCredentialIssued and returns agentId/credential/protocolVersion", async () => {
  const calls = stubFetch([
    {
      status: 201,
      json: { agentId: "agent-1", credential: "ttagent_agent-1_secret", protocolVersion: "1.0.0" },
    },
  ]);

  let issuedCredential = null;
  const client = createProtocolClient({
    serverUrl: "https://example.test",
    agentId: "candidate-agent-1",
    protocolVersion: "1.0.0",
    getCredential: () => null,
    onCredentialIssued: (raw) => {
      issuedCredential = raw;
    },
  });

  const result = await client.register({
    bootstrapToken: "raw-bootstrap-token",
    bootstrapTokenId: "bst_abc123",
    agentVersion: "0.1.0",
    hostname: "host-1",
    platform: "linux",
    nodeVersion: "v22.0.0",
    declaredTargetSelectors: ["example.com"],
    declaredCommandProfileNames: ["nginx-reload"],
  });

  assert.equal(result.agentId, "agent-1");
  assert.equal(result.credential, "ttagent_agent-1_secret");
  assert.equal(result.protocolVersion, "1.0.0");
  assert.equal(issuedCredential, "ttagent_agent-1_secret");

  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, `https://example.test${ROUTES.REGISTER}`);
  assert.equal(calls[0].init.headers.authorization, "Bearer raw-bootstrap-token");
  assert.equal(calls[0].parsedBody.messageType, "register");
  assert.equal(calls[0].parsedBody.body.bootstrapTokenId, "bst_abc123");
  assert.equal(calls[0].parsedBody.body.agentVersion, "0.1.0");
  assert.equal(calls[0].parsedBody.schemaVersion, 1);
});

test("heartbeat: HTTP 410 resolves to { retired: true } without throwing", async () => {
  stubFetch([{ status: 410, json: {} }]);

  const client = createProtocolClient({
    serverUrl: "https://example.test",
    agentId: "agent-1",
    protocolVersion: "1.0.0",
    getCredential: () => "ttagent_agent-1_secret",
  });

  const result = await client.heartbeat({ agentVersion: "0.1.0" });
  assert.deepEqual(result, { retired: true });
});

test("heartbeat: clockOffsetMs is carried on the envelope when provided", async () => {
  const calls = stubFetch([{ status: 200, json: {} }]);

  const client = createProtocolClient({
    serverUrl: "https://example.test",
    agentId: "agent-1",
    protocolVersion: "1.0.0",
    getCredential: () => "ttagent_agent-1_secret",
  });

  await client.heartbeat({ agentVersion: "0.1.0", clockOffsetMs: -125 });
  assert.equal(calls[0].parsedBody.clockOffsetMs, -125);

  await client.heartbeat({ agentVersion: "0.1.0" });
  assert.equal(calls[1].parsedBody.clockOffsetMs, null);
});

test("heartbeat: other non-2xx throws AgentProtocolError with code http_error", async () => {
  stubFetch([{ status: 500, json: { error: "boom" } }]);

  const client = createProtocolClient({
    serverUrl: "https://example.test",
    agentId: "agent-1",
    protocolVersion: "1.0.0",
    getCredential: () => "ttagent_agent-1_secret",
  });

  await assert.rejects(
    () => client.heartbeat({ agentVersion: "0.1.0" }),
    (err) => {
      assert.ok(err instanceof AgentProtocolError);
      assert.equal(err.code, AGENT_PROTOCOL_ERROR_CODES.HTTP_ERROR);
      assert.equal(err.status, 500);
      return true;
    },
  );
});

test("heartbeat: network failure throws AgentProtocolError with code network_error", async () => {
  stubFetch([{ throws: new Error("ECONNRESET") }]);

  const client = createProtocolClient({
    serverUrl: "https://example.test",
    agentId: "agent-1",
    protocolVersion: "1.0.0",
    getCredential: () => "ttagent_agent-1_secret",
  });

  await assert.rejects(
    () => client.heartbeat({ agentVersion: "0.1.0" }),
    (err) => {
      assert.ok(err instanceof AgentProtocolError);
      assert.equal(err.code, AGENT_PROTOCOL_ERROR_CODES.NETWORK_ERROR);
      return true;
    },
  );
});

test("claim: returns jobs array from response and sends claimBody", async () => {
  const calls = stubFetch([
    { status: 200, json: { jobs: [{ jobId: "job-1" }, { jobId: "job-2" }] } },
  ]);

  const client = createProtocolClient({
    serverUrl: "https://example.test",
    agentId: "agent-1",
    protocolVersion: "1.0.0",
    getCredential: () => "ttagent_agent-1_secret",
  });

  const jobs = await client.claim({ maxJobs: 2, supportedActions: ["renew", "reload"] });
  assert.deepEqual(jobs, [{ jobId: "job-1" }, { jobId: "job-2" }]);

  assert.equal(calls[0].url, `https://example.test${ROUTES.CLAIM}`);
  assert.equal(calls[0].init.headers.authorization, "Bearer ttagent_agent-1_secret");
  assert.equal(calls[0].parsedBody.messageType, "claim");
  assert.equal(calls[0].parsedBody.body.maxJobs, 2);
  assert.deepEqual(calls[0].parsedBody.body.supportedActions, ["renew", "reload"]);
});

test("claim: missing jobs field in response returns empty array", async () => {
  stubFetch([{ status: 200, json: {} }]);

  const client = createProtocolClient({
    serverUrl: "https://example.test",
    agentId: "agent-1",
    protocolVersion: "1.0.0",
    getCredential: () => "ttagent_agent-1_secret",
  });

  const jobs = await client.claim({ maxJobs: 1 });
  assert.deepEqual(jobs, []);
});

test("reportResult: sends correct envelope shape (messageType + resultBody fields)", async () => {
  const calls = stubFetch([{ status: 202, json: { accepted: true } }]);

  const client = createProtocolClient({
    serverUrl: "https://example.test",
    agentId: "agent-1",
    protocolVersion: "1.0.0",
    getCredential: () => "ttagent_agent-1_secret",
  });

  await client.reportResult({
    jobId: "job-1",
    attemptId: "attempt-1",
    status: "succeeded",
    keyRotated: true,
    clockOffsetMs: 42,
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, `https://example.test${ROUTES.RESULTS}`);
  assert.equal(calls[0].parsedBody.messageType, "result");
  assert.equal(calls[0].parsedBody.clockOffsetMs, 42);
  assert.equal(calls[0].parsedBody.body.jobId, "job-1");
  assert.equal(calls[0].parsedBody.body.attemptId, "attempt-1");
  assert.equal(calls[0].parsedBody.body.status, "succeeded");
  assert.equal(calls[0].parsedBody.body.keyRotated, true);
  assert.equal(calls[0].parsedBody.body.rejectionReason, null);
});

test("reportEvidence: sends correct envelope shape (messageType + evidenceBody fields)", async () => {
  const calls = stubFetch([{ status: 202, json: { accepted: true } }]);

  const client = createProtocolClient({
    serverUrl: "https://example.test",
    agentId: "agent-1",
    protocolVersion: "1.0.0",
    getCredential: () => "ttagent_agent-1_secret",
  });

  const evidenceItems = [
    { eventType: "certificate.observed", observedAt: new Date().toISOString() },
  ];

  await client.reportEvidence({ jobId: "job-1", evidenceItems });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].parsedBody.messageType, "evidence");
  assert.equal(calls[0].parsedBody.body.jobId, "job-1");
  assert.deepEqual(calls[0].parsedBody.body.evidenceItems, evidenceItems);
});

test("jitteredDelay: stays within expected bounds across many samples", () => {
  const baseMs = 1000;
  const jitterRatio = 0.2;
  for (let i = 0; i < 500; i += 1) {
    const delay = jitteredDelay(baseMs, jitterRatio);
    assert.ok(delay >= baseMs * (1 - jitterRatio) - 1, `delay ${delay} too low`);
    assert.ok(delay <= baseMs * (1 + jitterRatio) + 1, `delay ${delay} too high`);
  }
});

test("jitteredDelay: floors at 0 for degenerate inputs", () => {
  assert.equal(jitteredDelay(0), 0);
  assert.equal(jitteredDelay(-100), 0);
});

test("withRetry: retries on failure and eventually succeeds", async () => {
  let attempts = 0;
  const result = await withRetry(
    async () => {
      attempts += 1;
      if (attempts < 3) {
        throw new Error(`transient failure ${attempts}`);
      }
      return "ok";
    },
    { maxAttempts: 5, baseDelayMs: 1, maxDelayMs: 5 },
  );

  assert.equal(result, "ok");
  assert.equal(attempts, 3);
});

test("withRetry: gives up after maxAttempts, throwing the last error", async () => {
  let attempts = 0;
  await assert.rejects(
    () =>
      withRetry(
        async () => {
          attempts += 1;
          throw new Error(`failure ${attempts}`);
        },
        { maxAttempts: 3, baseDelayMs: 1, maxDelayMs: 5 },
      ),
    (err) => {
      assert.equal(err.message, "failure 3");
      return true;
    },
  );
  assert.equal(attempts, 3);
});

test("startPollLoop: calls onTick repeatedly until aborted", async () => {
  const controller = new AbortController();
  let tickCount = 0;

  const loopPromise = startPollLoop({
    intervalMs: 10,
    jitterRatio: 0.1,
    signal: controller.signal,
    startImmediately: false,
    onTick: async () => {
      tickCount += 1;
      if (tickCount >= 3) {
        controller.abort();
      }
    },
  });

  await Promise.race([
    loopPromise,
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error("startPollLoop test timed out")), 5000),
    ),
  ]);

  assert.ok(tickCount >= 2, `expected at least 2 ticks, got ${tickCount}`);
});

test("startPollLoop: swallows onTick errors and keeps ticking", async () => {
  const controller = new AbortController();
  let tickCount = 0;
  const loggedErrors = [];

  const loopPromise = startPollLoop({
    intervalMs: 10,
    signal: controller.signal,
    startImmediately: false,
    onError: (err) => loggedErrors.push(err),
    onTick: async () => {
      tickCount += 1;
      if (tickCount >= 3) {
        controller.abort();
        return;
      }
      throw new Error(`tick ${tickCount} failed`);
    },
  });

  await Promise.race([
    loopPromise,
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error("startPollLoop test timed out")), 5000),
    ),
  ]);

  assert.ok(tickCount >= 2, `expected at least 2 ticks, got ${tickCount}`);
  assert.ok(loggedErrors.length >= 1, "expected at least one logged error");
});
