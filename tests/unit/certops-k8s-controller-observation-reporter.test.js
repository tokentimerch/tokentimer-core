"use strict";

const assert = require("node:assert/strict");
const path = require("node:path");
const { describe, it } = require("node:test");
const {
  createObservationEnvelope,
  idempotencyKeyFor,
} = require("../../apps/k8s-controller/src/observation-envelope");
const {
  MAX_RESPONSE_BYTES,
  boundedJson,
  createControllerObservationReporter,
} = require("../../apps/k8s-controller/src/observation-reporter");

const token = `ttx_${"a".repeat(16)}_${"b".repeat(64)}`;
const TEST_TOKEN_FILE = path.resolve("token");

function reporterOptions(overrides = {}) {
  return {
    apiUrl: "https://api.example.test",
    apiTokenFile: TEST_TOKEN_FILE,
    fsOptions: {
      fsImpl: {
        statSync: () => ({ isFile: () => true, mode: 0o600 }),
        readFileSync: () => token,
      },
    },
    random: () => 0,
    sleep: async () => {},
    ...overrides,
  };
}

function successfulResponse(duplicate = false) {
  return {
    status: duplicate ? 200 : 201,
    headers: { get: () => null },
    text: async () => JSON.stringify({
      managedCertificateId: "33333333-3333-4333-8333-333333333333",
      targetId: "44444444-4444-4444-8444-444444444444",
      certificateInstanceId: null,
      duplicate,
    }),
  };
}

function observation(overrides = {}) {
  return {
    workspaceId: "11111111-1111-4111-8111-111111111111",
    clusterId: "controller-a",
    namespace: "certops",
    certificateName: "example-com",
    certificateUid: "22222222-2222-4222-8222-222222222222",
    certificateGeneration: 2,
    resourceVersion: "42",
    issuerRef: { name: "issuer" },
    secretName: "example-com-tls",
    certificateRequestRef: null,
    dnsNames: ["example.com"],
    conditions: [{ type: "Ready", status: "True", reason: "Issued" }],
    ready: true,
    publicCertificate: { fingerprintSha256: "a".repeat(64) },
    observedAt: "2026-07-21T10:00:00.000Z",
    ...overrides,
  };
}

describe("controller observation envelope", () => {
  it("uses a deterministic semantic idempotency key and UUID", () => {
    const first = createObservationEnvelope(observation());
    const replay = createObservationEnvelope(observation({ observedAt: "2026-07-21T10:01:00.000Z" }));
    assert.equal(first.idempotencyKey, replay.idempotencyKey);
    assert.equal(first.observationId, replay.observationId);
    assert.notEqual(first.idempotencyKey, idempotencyKeyFor(observation({ resourceVersion: "43" })));
    assert.notEqual(first.idempotencyKey, idempotencyKeyFor(observation({ certificateGeneration: 3 })));
    assert.notEqual(first.idempotencyKey, idempotencyKeyFor(observation({ publicCertificate: { fingerprintSha256: "b".repeat(64) } })));
  });

  it("blocks private material before serialization", () => {
    assert.throws(
      () => createObservationEnvelope(observation({ failureMessage: "-----BEGIN PRIVATE KEY-----" })),
      { code: "PRIVATE_KEY_MATERIAL_REJECTED" },
    );
  });
});

describe("controller observation reporter", () => {
  it("re-reads a rotated mounted token without retaining it", async () => {
    let currentToken = `ttx_${"a".repeat(16)}_${"b".repeat(64)}`;
    const authorizations = [];
    const reporter = createControllerObservationReporter({
      apiUrl: "https://api.example.test",
      apiTokenFile: TEST_TOKEN_FILE,
      fsOptions: {
        fsImpl: {
          statSync: () => ({ isFile: () => true, mode: 0o600 }),
          readFileSync: () => currentToken,
        },
      },
      fetchImpl: async (_url, options) => {
        authorizations.push(options.headers.Authorization);
        return {
          status: 201,
          headers: { get: () => null },
          text: async () => JSON.stringify({
            managedCertificateId: "33333333-3333-4333-8333-333333333333",
            targetId: null,
            certificateInstanceId: null,
            duplicate: false,
          }),
        };
      },
    });
    await reporter.start();
    await reporter.report(observation());
    currentToken = `ttx_${"c".repeat(16)}_${"d".repeat(64)}`;
    await reporter.report(observation({ resourceVersion: "43" }));
    assert.deepEqual(authorizations, [
      `Bearer ttx_${"a".repeat(16)}_${"b".repeat(64)}`,
      `Bearer ttx_${"c".repeat(16)}_${"d".repeat(64)}`,
    ]);
  });

  it("reuses its exact payload and idempotency key across transient retries", async () => {
    const calls = [];
    let attempts = 0;
    const token = `ttx_${"a".repeat(16)}_${"b".repeat(64)}`;
    const reporter = createControllerObservationReporter({
      apiUrl: "https://api.example.test",
      apiTokenFile: TEST_TOKEN_FILE,
      fsOptions: { fsImpl: { statSync: () => ({ isFile: () => true, mode: 0o600 }), readFileSync: () => token } },
      random: () => 0,
      sleep: async () => {},
      fetchImpl: async (_url, options) => {
        calls.push(options);
        attempts += 1;
        if (attempts === 1) return { status: 503, headers: { get: () => null }, text: async () => "{}" };
        return {
          status: 201,
          headers: { get: () => null },
          text: async () => JSON.stringify({
            managedCertificateId: "33333333-3333-4333-8333-333333333333",
            targetId: "44444444-4444-4444-8444-444444444444",
            certificateInstanceId: null,
            duplicate: false,
          }),
        };
      },
    });
    await reporter.start();
    const result = await reporter.report(observation());
    assert.equal(result.duplicate, false);
    assert.equal(calls.length, 2);
    assert.equal(calls[0].body, calls[1].body);
    assert.equal(calls[0].headers["Idempotency-Key"], calls[1].headers["Idempotency-Key"]);
    assert.equal(calls[0].redirect, "error");
    assert.match(calls[0].headers.Authorization, /^Bearer ttx_/);
    await reporter.stopAcceptingWork();
    await assert.rejects(() => reporter.report(observation()), { code: "CONTROLLER_REPORTER_STOPPING" });
  });

  it("retries a wrapped Node fetch transport failure with the same envelope", async () => {
    const calls = [];
    const reporter = createControllerObservationReporter(reporterOptions({
      fetchImpl: async (_url, options) => {
        calls.push(options);
        if (calls.length === 1) {
          const error = new TypeError("fetch failed");
          error.cause = { code: "ECONNREFUSED" };
          throw error;
        }
        return successfulResponse();
      },
    }));
    await reporter.start();
    await reporter.report(observation());
    assert.equal(calls.length, 2);
    assert.equal(calls[0].body, calls[1].body);
    assert.equal(calls[0].headers["Idempotency-Key"], calls[1].headers["Idempotency-Key"]);
    assert.match(JSON.parse(calls[0].body).observationId, /^[0-9a-f-]{36}$/i);
  });

  it("does not retry unknown wrapped failures or permanent HTTP responses", async () => {
    let unknownAttempts = 0;
    const unknownReporter = createControllerObservationReporter(reporterOptions({
      fetchImpl: async () => {
        unknownAttempts += 1;
        const error = new TypeError("fetch failed");
        error.cause = { code: "UNEXPECTED_FAILURE" };
        throw error;
      },
    }));
    await unknownReporter.start();
    await assert.rejects(() => unknownReporter.report(observation()), TypeError);
    assert.equal(unknownAttempts, 1);

    let permanentAttempts = 0;
    const permanentReporter = createControllerObservationReporter(reporterOptions({
      fetchImpl: async () => {
        permanentAttempts += 1;
        return { status: 422, headers: { get: () => null }, text: async () => "{}" };
      },
    }));
    await permanentReporter.start();
    await assert.rejects(() => permanentReporter.report(observation()), {
      code: "CONTROLLER_REPORTER_HTTP_422",
    });
    assert.equal(permanentAttempts, 1);
  });

  it("retries HTTP 408, 429, and 5xx responses", async () => {
    for (const status of [408, 429, 503]) {
      let attempts = 0;
      const reporter = createControllerObservationReporter(reporterOptions({
        fetchImpl: async () => {
          attempts += 1;
          if (attempts === 1) {
            return {
              status,
              headers: { get: (name) => name === "retry-after" && status === 429 ? "1" : null },
              text: async () => "{}",
            };
          }
          return successfulResponse();
        },
      }));
      await reporter.start();
      await reporter.report(observation({ resourceVersion: String(status) }));
      assert.equal(attempts, 2);
    }
  });

  it("allows an active request to finish successfully after stopping", async () => {
    let attempts = 0;
    let requestStarted;
    const started = new Promise((resolve) => { requestStarted = resolve; });
    let resolveResponse;
    let aborted = false;
    const reporter = createControllerObservationReporter(reporterOptions({
      fetchImpl: async (_url, options) => {
        attempts += 1;
        requestStarted();
        return new Promise((resolve, reject) => {
          resolveResponse = () => resolve(successfulResponse());
          options.signal.addEventListener("abort", () => {
            aborted = true;
            const error = new Error("aborted");
            error.name = "AbortError";
            reject(error);
          }, { once: true });
        });
      },
    }));
    await reporter.start();
    const reporting = reporter.report(observation());
    await started;
    await reporter.stopAcceptingWork();
    assert.equal(aborted, false);
    resolveResponse();
    assert.deepEqual(await reporting, {
      managedCertificateId: "33333333-3333-4333-8333-333333333333",
      targetId: "44444444-4444-4444-8444-444444444444",
      certificateInstanceId: null,
      duplicate: false,
    });
    assert.equal(attempts, 1);
    await assert.rejects(() => reporter.report(observation()), { code: "CONTROLLER_REPORTER_STOPPING" });
  });

  it("does not retry or sleep after an active transient failure during shutdown", async () => {
    let attempts = 0;
    let sleepCalls = 0;
    let requestStarted;
    let resolveResponse;
    const started = new Promise((resolve) => { requestStarted = resolve; });
    const reporter = createControllerObservationReporter(reporterOptions({
      sleep: async () => { sleepCalls += 1; },
      fetchImpl: async () => {
        attempts += 1;
        requestStarted();
        return new Promise((resolve) => { resolveResponse = resolve; });
      },
    }));
    await reporter.start();
    const reporting = reporter.report(observation());
    await started;
    await reporter.stopAcceptingWork();
    resolveResponse({ status: 503, headers: { get: () => null }, text: async () => "{}" });
    await assert.rejects(() => reporting, { code: "CONTROLLER_REPORTER_STOPPING" });
    assert.equal(attempts, 1);
    assert.equal(sleepCalls, 0);
  });

  it("close aborts an active request with the stable stopping code", async () => {
    let attempts = 0;
    let requestStarted;
    const started = new Promise((resolve) => { requestStarted = resolve; });
    const reporter = createControllerObservationReporter(reporterOptions({
      fetchImpl: async (_url, options) => {
        attempts += 1;
        requestStarted();
        return new Promise((_resolve, reject) => {
          options.signal.addEventListener("abort", () => {
            const error = new Error("aborted");
            error.name = "AbortError";
            reject(error);
          }, { once: true });
        });
      },
    }));
    await reporter.start();
    const reporting = reporter.report(observation());
    await started;
    await reporter.close();
    await assert.rejects(() => reporting, { code: "CONTROLLER_REPORTER_STOPPING" });
    assert.equal(attempts, 1);
  });

  it("close interrupts a pending retry delay before another attempt starts", async () => {
    let attempts = 0;
    let sleepStarted;
    const waiting = new Promise((resolve) => { sleepStarted = resolve; });
    const reporter = createControllerObservationReporter(reporterOptions({
      sleep: () => {
        sleepStarted();
        return new Promise(() => {});
      },
      fetchImpl: async () => {
        attempts += 1;
        return { status: 503, headers: { get: () => null }, text: async () => "{}" };
      },
    }));
    await reporter.start();
    const reporting = reporter.report(observation());
    await waiting;
    await reporter.close();
    await assert.rejects(() => reporting, { code: "CONTROLLER_REPORTER_STOPPING" });
    assert.equal(attempts, 1);
  });

  it("bounds streamed response bodies before consuming an unbounded payload", async () => {
    let cancelled = false;
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(new Uint8Array(MAX_RESPONSE_BYTES + 1));
      },
      cancel() {
        cancelled = true;
      },
    });
    await assert.rejects(
      () => boundedJson({ body: stream }),
      { code: "CONTROLLER_REPORTER_INVALID_RESPONSE" },
    );
    assert.equal(cancelled, true);
  });
});
