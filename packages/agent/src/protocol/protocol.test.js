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
  parseServerUrl,
  validateEnvelopeShape,
} = require("./index.js");

const CREDENTIAL = "ttagent_agent-1_0123456789abcdef";

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
  global.fetch = (url, init) => {
    const entry = responses[Math.min(index, responses.length - 1)];
    index += 1;
    calls.push({ url, init, parsedBody: init?.body ? JSON.parse(init.body) : null });
    if (entry.throws) {
      throw entry.throws;
    }
    return Promise.resolve({
      ok: entry.status >= 200 && entry.status < 300,
      status: entry.status,
      json: () => Promise.resolve(entry.json ?? {}),
    });
  };
  return calls;
}

test("register: validates and returns the full response before persistence", async () => {
  const calls = stubFetch([
    {
      status: 201,
      json: { agentId: "agent-1", credential: CREDENTIAL, protocolVersion: "1.0.0" },
    },
  ]);

  const client = createProtocolClient({
    serverUrl: "https://example.test",
    agentId: "candidate-agent-1",
    protocolVersion: "1.0.0",
    getCredential: () => null,
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
  assert.equal(result.credential, CREDENTIAL);
  assert.equal(result.protocolVersion, "1.0.0");

  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, `https://example.test${ROUTES.REGISTER}`);
  assert.equal(calls[0].init.headers.authorization, "Bearer raw-bootstrap-token");
  assert.equal(calls[0].parsedBody.messageType, "register");
  assert.equal(calls[0].parsedBody.body.bootstrapTokenId, "bst_abc123");
  assert.equal(calls[0].parsedBody.body.agentVersion, "0.1.0");
  assert.equal(calls[0].parsedBody.schemaVersion, 1);
});

test("register: rejects malformed or unexpected response fields", async () => {
  stubFetch([
    {
      status: 201,
      json: {
        agentId: "agent-1",
        credential: CREDENTIAL,
        protocolVersion: "1.0.0",
        serverControlledSecret: "do-not-persist",
      },
    },
  ]);
  const client = createProtocolClient({
    serverUrl: "https://example.test",
    agentId: "candidate-agent-1",
    protocolVersion: "1.0.0",
  });
  await assert.rejects(
    () => client.register({ bootstrapToken: "bootstrap-token", bootstrapTokenId: "bst_1", agentVersion: "0.1.0" }),
    (err) => {
      assert.equal(err.code, AGENT_PROTOCOL_ERROR_CODES.INVALID_RESPONSE);
      return true;
    },
  );
});

test("heartbeat: HTTP 410 resolves to { retired: true } without throwing", async () => {
  stubFetch([{ status: 410, json: {} }]);

  const client = createProtocolClient({
    serverUrl: "https://example.test",
    agentId: "agent-1",
    protocolVersion: "1.0.0",
    getCredential: () => CREDENTIAL,
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
    getCredential: () => CREDENTIAL,
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
    getCredential: () => CREDENTIAL,
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
    getCredential: () => CREDENTIAL,
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
    getCredential: () => CREDENTIAL,
  });

  const jobs = await client.claim({ maxJobs: 2, supportedActions: ["renew", "reload"] });
  assert.deepEqual(jobs, [{ jobId: "job-1" }, { jobId: "job-2" }]);

  assert.equal(calls[0].url, `https://example.test${ROUTES.CLAIM}`);
  assert.equal(calls[0].init.headers.authorization, `Bearer ${CREDENTIAL}`);
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
    getCredential: () => CREDENTIAL,
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
    getCredential: () => CREDENTIAL,
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
    getCredential: () => CREDENTIAL,
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

test("transport: strictly rejects unsafe server URLs and permits explicit local HTTP only", () => {
  for (const value of [
    "http://control-plane.example.test",
    "https://user:password@example.test",
    "https://example.test/#fragment",
    "https://example.test/?query=1",
    "https://example.test/base-path",
  ]) {
    assert.throws(() => parseServerUrl(value), AgentProtocolError);
  }
  assert.equal(
    parseServerUrl("http://127.0.0.1:4010", { allowInsecureLocalHttp: true }),
    "http://127.0.0.1:4010",
  );
  assert.throws(
    () => parseServerUrl("http://example.test", { allowInsecureLocalHttp: true }),
    AgentProtocolError,
  );
});

test("transport: blocks redirects and applies timeout/cancellation-safe fetch options", async () => {
  const calls = stubFetch([{ status: 302, json: { location: "https://elsewhere.test" } }]);
  const client = createProtocolClient({
    serverUrl: "https://example.test",
    agentId: "agent-1",
    protocolVersion: "1.0.0",
    getCredential: () => CREDENTIAL,
  });
  await assert.rejects(() => client.heartbeat({ agentVersion: "0.1.0" }), (err) => {
    assert.equal(err.code, AGENT_PROTOCOL_ERROR_CODES.HTTP_ERROR);
    return true;
  });
  assert.equal(calls[0].init.redirect, "error");
  assert.ok(calls[0].init.signal instanceof AbortSignal);
});

test("transport: cancels an in-flight request when shutdown aborts", async () => {
  const controller = new AbortController();
  global.fetch = (_url, init) => new Promise((_, reject) => {
    if (init.signal.aborted) {
      reject(new Error("aborted"));
      return;
    }
    init.signal.addEventListener("abort", () => reject(new Error("aborted")), { once: true });
  });
  const client = createProtocolClient({
    serverUrl: "https://example.test",
    agentId: "agent-1",
    protocolVersion: "1.0.0",
    getCredential: () => CREDENTIAL,
    signal: controller.signal,
  });
  const request = client.heartbeat({ agentVersion: "0.1.0" });
  controller.abort();
  await assert.rejects(request, (err) => {
    assert.equal(err.code, AGENT_PROTOCOL_ERROR_CODES.NETWORK_ERROR);
    return true;
  });
});

test("transport: rejects bounded oversized response streams without parsing the body", async () => {
  global.fetch = () => Promise.resolve({
    ok: true,
    status: 200,
    headers: { get: () => null },
    body: {
      getReader() {
        let readCount = 0;
        return {
          read() {
            readCount += 1;
            return Promise.resolve(readCount === 1
              ? { done: false, value: new Uint8Array(70 * 1024) }
              : { done: true });
          },
          async cancel() {},
          releaseLock() {},
        };
      },
    },
  });
  const client = createProtocolClient({
    serverUrl: "https://example.test",
    agentId: "agent-1",
    protocolVersion: "1.0.0",
    getCredential: () => CREDENTIAL,
  });
  await assert.rejects(() => client.heartbeat({ agentVersion: "0.1.0" }), (err) => {
    assert.equal(err.code, AGENT_PROTOCOL_ERROR_CODES.INVALID_RESPONSE);
    return true;
  });
});

test("outbound boundary: rejects unknown/private fields and redacts allowed generic secret text", async () => {
  const calls = stubFetch([{ status: 202, json: { accepted: true } }]);
  const client = createProtocolClient({
    serverUrl: "https://example.test",
    agentId: "agent-1",
    protocolVersion: "1.0.0",
    getCredential: () => CREDENTIAL,
  });
  await client.reportResult({
    jobId: "job-1",
    attemptId: "attempt-1",
    status: "failed",
    errorMessage: "request failed with Authorization: Bearer server-controlled-token",
  });
  assert.match(calls[0].parsedBody.body.errorMessage, /\[REDACTED\]/);
  assert.doesNotMatch(calls[0].parsedBody.body.errorMessage, /server-controlled-token/);

  const malformed = {
    schemaVersion: 1,
    protocolVersion: "1.0.0",
    messageType: "claim",
    agentId: "agent-1",
    sentAt: new Date().toISOString(),
    body: { maxJobs: 1, privateKey: "-----BEGIN PRIVATE KEY-----\nsecret" },
  };
  assert.ok(validateEnvelopeShape(malformed).some((problem) => problem.includes("unknown field")));

  await assert.rejects(
    () => client.reportEvidence({
      evidenceItems: [{
        eventType: "validation.failed",
        observedAt: new Date().toISOString(),
        summary: "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----",
      }],
    }),
    (err) => err.code === "PRIVATE_KEY_MATERIAL_REJECTED",
  );
  await assert.rejects(
    () => client.reportEvidence({
      evidenceItems: [{
        eventType: "validation.failed",
        observedAt: new Date().toISOString(),
        unknownField: "not allowed",
      }],
    }),
    (err) => err.code === AGENT_PROTOCOL_ERROR_CODES.INVALID_MESSAGE,
  );
  assert.equal(calls.length, 1, "unsafe evidence must not reach fetch");
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
    () => {
      attempts += 1;
      if (attempts < 3) {
        return Promise.reject(new Error(`transient failure ${attempts}`));
      }
      return Promise.resolve("ok");
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
        () => {
          attempts += 1;
          return Promise.reject(new Error(`failure ${attempts}`));
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
    onTick: () => {
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
    onTick: () => {
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

test("startPollLoop: startImmediately false waits before the first tick", async () => {
  const controller = new AbortController();
  let tickCount = 0;
  const loopPromise = startPollLoop({
    intervalMs: 100,
    signal: controller.signal,
    startImmediately: false,
    onTick: () => {
      tickCount += 1;
    },
  });
  await new Promise((resolve) => setTimeout(resolve, 15));
  assert.equal(tickCount, 0);
  controller.abort();
  await loopPromise;
});

test("startPollLoop: startImmediately true invokes the first tick without waiting", async () => {
  const controller = new AbortController();
  let tickCount = 0;
  await startPollLoop({
    intervalMs: 1_000,
    signal: controller.signal,
    startImmediately: true,
    onTick: () => {
      tickCount += 1;
      controller.abort();
    },
  });
  assert.equal(tickCount, 1);
});
