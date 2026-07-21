"use strict";

const assert = require("node:assert/strict");
const { describe, it } = require("node:test");
const {
  createObservationEnvelope,
  idempotencyKeyFor,
} = require("../../apps/k8s-controller/src/observation-envelope");
const {
  createControllerObservationReporter,
} = require("../../apps/k8s-controller/src/observation-reporter");

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
      apiTokenFile: "C:\\token",
      fsOptions: {
        fsImpl: {
          statSync: () => ({ isFile: () => true, mode: 0o600 }),
          readFileSync: () => currentToken,
        },
        platform: "win32",
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
      apiTokenFile: "C:\\token",
      fsOptions: { fsImpl: { statSync: () => ({ isFile: () => true, mode: 0o600 }), readFileSync: () => token }, platform: "win32" },
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
});
