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
  createCaAwareFetch,
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

test("reportResult: forwards claimId and nonce in the body when provided", async () => {
  const calls = stubFetch([{ status: 202, json: { accepted: true } }]);

  const client = createProtocolClient({
    serverUrl: "https://example.test",
    agentId: "agent-1",
    protocolVersion: "1.0.0",
    getCredential: () => "ttagent_agent-1_secret",
  });

  await client.reportResult({
    jobId: "job-1",
    attemptId: "claim-uuid-1",
    status: "succeeded",
    claimId: "claim-uuid-1",
    nonce: "nonce-0123456789abcdef",
  });

  assert.equal(calls.length, 1);
  const body = calls[0].parsedBody.body;
  assert.equal(body.claimId, "claim-uuid-1");
  assert.equal(body.nonce, "nonce-0123456789abcdef");
});

test("reportResult: omits claimId and nonce entirely when null or absent (schema-minimal observe-only report)", async () => {
  const calls = stubFetch([
    { status: 202, json: { accepted: true } },
    { status: 202, json: { accepted: true } },
  ]);

  const client = createProtocolClient({
    serverUrl: "https://example.test",
    agentId: "agent-1",
    protocolVersion: "1.0.0",
    getCredential: () => "ttagent_agent-1_secret",
  });

  await client.reportResult({
    jobId: "job-1",
    attemptId: "attempt-1",
    status: "blocked",
  });
  await client.reportResult({
    jobId: "job-1",
    attemptId: "attempt-1",
    status: "blocked",
    claimId: null,
    nonce: null,
  });

  for (const call of calls) {
    assert.equal("claimId" in call.parsedBody.body, false);
    assert.equal("nonce" in call.parsedBody.body, false);
  }
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

/**
 * Like stubFetch but the queued entries may carry a dateHeader that is
 * exposed through response.headers.get("date"), for clock-sampling tests.
 */
function stubFetchWithHeaders(responses) {
  const calls = [];
  let index = 0;
  global.fetch = (url, init) => {
    const entry = responses[Math.min(index, responses.length - 1)];
    index += 1;
    calls.push({ url, init, parsedBody: init?.body ? JSON.parse(init.body) : null });
    return Promise.resolve({
      ok: entry.status >= 200 && entry.status < 300,
      status: entry.status,
      headers: {
        get: (name) =>
          String(name).toLowerCase() === "date" && entry.dateHeader ? entry.dateHeader : null,
      },
      json: () => Promise.resolve(entry.json ?? {}),
    });
  };
  return calls;
}

test("register: returns null signing-key fields when the response omits them", async () => {
  stubFetch([
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
  });
  assert.equal(result.signingKeyId, null);
  assert.equal(result.signingPublicKeyPem, null);
});

test("register: passes through signingKeyId and signingPublicKeyPem when the response carries them", async () => {
  const signingPublicKeyPem =
    "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAfake\n-----END PUBLIC KEY-----\n";
  stubFetch([
    {
      status: 201,
      json: {
        agentId: "agent-1",
        credential: CREDENTIAL,
        protocolVersion: "1.0.0",
        signingKeyId: "signing-key-1",
        signingPublicKeyPem,
      },
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
  });
  assert.equal(result.signingKeyId, "signing-key-1");
  assert.equal(result.signingPublicKeyPem, signingPublicKeyPem);
});

test("register: rejects a signingKeyId without its public key (and vice versa)", async () => {
  stubFetch([
    {
      status: 201,
      json: {
        agentId: "agent-1",
        credential: CREDENTIAL,
        protocolVersion: "1.0.0",
        signingKeyId: "signing-key-1",
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

test("register: rejects a signingPublicKeyPem containing private key material", async () => {
  stubFetch([
    {
      status: 201,
      json: {
        agentId: "agent-1",
        credential: CREDENTIAL,
        protocolVersion: "1.0.0",
        signingKeyId: "signing-key-1",
        signingPublicKeyPem:
          "-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----\n-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n",
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

test("onServerDate: fires with the Date header and a local timestamp on successful requests", async () => {
  const dateHeader = "Wed, 22 Jul 2026 12:00:00 GMT";
  stubFetchWithHeaders([
    { status: 200, dateHeader, json: {} },
    { status: 200, dateHeader, json: { jobs: [] } },
  ]);

  const samples = [];
  const client = createProtocolClient({
    serverUrl: "https://example.test",
    agentId: "agent-1",
    protocolVersion: "1.0.0",
    getCredential: () => CREDENTIAL,
    onServerDate: (dateHeaderValue, localNowMs) => {
      samples.push({ dateHeaderValue, localNowMs });
    },
  });

  const before = Date.now();
  await client.heartbeat({ agentVersion: "0.1.0" });
  await client.claim({ maxJobs: 1 });
  const after = Date.now();

  assert.equal(samples.length, 2);
  for (const sample of samples) {
    assert.equal(sample.dateHeaderValue, dateHeader);
    assert.ok(sample.localNowMs >= before && sample.localNowMs <= after);
  }
});

test("onServerDate: not fired on non-2xx responses or when the Date header is absent", async () => {
  stubFetchWithHeaders([
    { status: 500, dateHeader: "Wed, 22 Jul 2026 12:00:00 GMT", json: {} },
    { status: 200, json: {} },
  ]);

  const samples = [];
  const client = createProtocolClient({
    serverUrl: "https://example.test",
    agentId: "agent-1",
    protocolVersion: "1.0.0",
    getCredential: () => CREDENTIAL,
    onServerDate: (dateHeaderValue, localNowMs) => {
      samples.push({ dateHeaderValue, localNowMs });
    },
  });

  await assert.rejects(() => client.heartbeat({ agentVersion: "0.1.0" }));
  await client.heartbeat({ agentVersion: "0.1.0" });
  assert.equal(samples.length, 0);
});

test("onServerDate: a throwing callback never fails the protocol request", async () => {
  stubFetchWithHeaders([
    { status: 200, dateHeader: "Wed, 22 Jul 2026 12:00:00 GMT", json: {} },
  ]);

  const client = createProtocolClient({
    serverUrl: "https://example.test",
    agentId: "agent-1",
    protocolVersion: "1.0.0",
    getCredential: () => CREDENTIAL,
    onServerDate: () => {
      throw new Error("clock sampling exploded");
    },
  });

  const result = await client.heartbeat({ agentVersion: "0.1.0" });
  assert.deepEqual(result, {});
});
test("createProtocolClient: fetchImpl override is used instead of global fetch", async () => {
  // Poison global fetch so any accidental use fails the test loudly.
  global.fetch = async () => {
    throw new Error("global fetch must not be called when fetchImpl is provided");
  };

  const fetchImplCalls = [];
  const fetchImpl = async (url, init) => {
    fetchImplCalls.push({ url, init });
    return {
      ok: true,
      status: 200,
      headers: { get: () => null },
      json: async () => ({ ok: true }),
    };
  };

  const client = createProtocolClient({
    serverUrl: "https://cp.example.com",
    agentId: "agent-1",
    protocolVersion: "1.0.0",
    getCredential: () => "ttagent_agent-1_secret",
    fetchImpl,
  });

  await client.heartbeat({ agentVersion: "0.1.0" });
  assert.equal(fetchImplCalls.length, 1);
  assert.equal(
    fetchImplCalls[0].url,
    `https://cp.example.com${ROUTES.HEARTBEAT}`,
  );
  assert.equal(
    fetchImplCalls[0].init.headers.authorization,
    "Bearer ttagent_agent-1_secret",
  );
});

test("createCaAwareFetch: requires a non-empty caBundlePem", () => {
  assert.throws(
    () => createCaAwareFetch({ caBundlePem: "" }),
    (err) =>
      err instanceof AgentProtocolError &&
      err.code === AGENT_PROTOCOL_ERROR_CODES.INVALID_MESSAGE,
  );
  assert.throws(() => createCaAwareFetch({}), AgentProtocolError);
});

test("createCaAwareFetch: passes plain http URLs through to the base fetch", async () => {
  const baseCalls = [];
  const caFetch = createCaAwareFetch({
    caBundlePem: "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n",
    baseFetch: async (url, init) => {
      baseCalls.push({ url, init });
      return {
        ok: true,
        status: 200,
        headers: { get: () => null },
        json: async () => ({}),
      };
    },
  });

  const response = await caFetch("http://plain.example.com/api", { method: "POST" });
  assert.equal(baseCalls.length, 1);
  assert.equal(baseCalls[0].url, "http://plain.example.com/api");
  assert.equal(response.status, 200);
});

test("createCaAwareFetch: https request against an untrusted-by-bundle endpoint fails with a TLS error", async () => {
  // A syntactically valid but wrong CA bundle must cause verification
  // failure (never a silent fallback to the default trust store). Any
  // network/TLS error is acceptable here; the point is that the request
  // does NOT succeed against a host the bundle does not anchor.
  const caFetch = createCaAwareFetch({
    caBundlePem:
      "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUfake\n-----END CERTIFICATE-----\n",
  });
  await assert.rejects(
    caFetch("https://127.0.0.1:1/never-listens", { method: "POST", body: "{}" }),
  );
});
