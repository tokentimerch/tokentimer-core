"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const {
  MAX_RESPONSE_BYTES,
  readBoundedJsonResponse,
} = require("../../apps/k8s-controller/src/observation-reporter");
const {
  createControllerProvisioningCommandClient,
  MAX_PROVISIONING_RESPONSE_BYTES,
  maximumProvisioningResponseEnvelope,
  PROVISIONING_COMMAND_SCHEMA_LIMITS,
  stableId,
  validateCommand,
} = require("../../apps/k8s-controller/src/provisioning-command-client");
const provisioningSchema = require("../../packages/contracts/certops/controller-provisioning.schema.json");

const command = {
  schemaVersion: 1,
  workspaceId: "00000000-0000-4000-8000-000000000001",
  clusterId: "cluster-a",
  jobId: "00000000-0000-4000-8000-000000000002",
  managedCertificateId: "00000000-0000-4000-8000-000000000003",
  namespace: "team-a",
  certificateName: "web-cert",
  secretName: "web-tls",
  issuerRef: { group: "cert-manager.io", kind: "ClusterIssuer", name: "issuer-a" },
  dnsNames: ["example.test"],
};

function validEnvelope() {
  return {
    command: {
      ...command,
      issuerRef: { ...command.issuerRef },
      dnsNames: [...command.dnsNames],
    },
    eventTimestamps: {
      started: "2026-07-21T12:00:00.000Z",
    },
  };
}

function assertInvalidResponse(value, code = "CONTROLLER_PROVISIONING_INVALID_RESPONSE") {
  assert.throws(() => validateCommand(value), { code });
}

function streamFrom(chunks, { error = null, onCancel } = {}) {
  return {
    getReader() {
      let index = 0;
      return {
        async read() {
          if (error) throw error;
          if (index >= chunks.length) return { done: true };
          return { done: false, value: Buffer.from(chunks[index++]) };
        },
        async cancel() { onCancel?.(); },
        releaseLock() {},
      };
    },
  };
}

function response(body, status = 200) {
  return { status, headers: new Headers(), body: streamFrom([body]) };
}

function blockingStream(signal) {
  return {
    getReader() {
      return {
        read: () => new Promise((_, reject) => {
          signal.addEventListener("abort", () => {
            const error = new Error("aborted");
            error.name = "AbortError";
            reject(error);
          }, { once: true });
        }),
        async cancel() {},
        releaseLock() {},
      };
    },
  };
}

function createClient(fetchImpl, options = {}) {
  return createControllerProvisioningCommandClient({
    apiUrl: "https://api.example.test",
    apiTokenFile: "/token",
    fetchImpl,
    fsOptions: {
      fsImpl: {
        statSync: () => ({ isFile: () => true, mode: 0o600 }),
        readFileSync: () => `ttx_${"a".repeat(16)}_${"b".repeat(64)}\n`,
      },
      platform: "linux",
    },
    sleep: async () => {},
    ...options,
  });
}

describe("controller provisioning command response boundary", () => {
  it("uses a provisioning-specific bound calculated from the published command schema", () => {
    assert.equal(provisioningSchema.properties.dnsNames.maxItems, PROVISIONING_COMMAND_SCHEMA_LIMITS.dnsNameCount);
    assert.equal(provisioningSchema.properties.dnsNames.items.maxLength, PROVISIONING_COMMAND_SCHEMA_LIMITS.dnsNameLength);
    assert.equal(provisioningSchema.definitions.label.maxLength, PROVISIONING_COMMAND_SCHEMA_LIMITS.clusterOrNamespaceLength);
    assert.equal(provisioningSchema.definitions.name.maxLength, PROVISIONING_COMMAND_SCHEMA_LIMITS.kubernetesNameLength);
    assert.equal(MAX_PROVISIONING_RESPONSE_BYTES > MAX_RESPONSE_BYTES, true);

    const openapi = fs.readFileSync(path.resolve(
      __dirname,
      "../../packages/contracts/openapi/openapi.yaml",
    ), "utf8");
    const commandSection = openapi.slice(
      openapi.indexOf("    CertOpsControllerProvisioningCommand:\n"),
      openapi.indexOf("    CertOpsProvisioningCommandResponse:\n"),
    );
    assert.match(commandSection, /maxItems: 100/);
    assert.match(commandSection, /maxLength: 253/);
  });

  it("accepts a maximum-valid command at the exact provisioning response byte limit", async () => {
    const envelope = maximumProvisioningResponseEnvelope();
    const exact = JSON.stringify(envelope);
    assert.equal(envelope.command.dnsNames.length, 100);
    assert.equal(envelope.command.dnsNames.every((name) => name.length === 253), true);
    assert.equal(Buffer.byteLength(exact), MAX_PROVISIONING_RESPONSE_BYTES);

    const client = createClient(async () => response(exact));
    await client.start();
    const received = await client.nextCommand();
    assert.deepEqual(received.dnsNames, envelope.command.dnsNames);
    assert.equal(Object.isFrozen(received), true);
    assert.equal(Object.isFrozen(received.dnsNames), true);
    assert.equal(Object.isFrozen(received.issuerRef), true);
    assert.equal(Object.isFrozen(received.eventTimestamps), true);
  });

  it("rejects and cancels provisioning responses at one byte over the exact bound", async () => {
    let cancelled = false;
    const exact = JSON.stringify(maximumProvisioningResponseEnvelope());
    const client = createClient(async () => ({
      status: 200,
      headers: new Headers(),
      body: streamFrom([exact, " "], { onCancel: () => { cancelled = true; } }),
    }));
    await client.start();
    await assert.rejects(() => client.nextCommand(), {
      code: "CONTROLLER_PROVISIONING_INVALID_RESPONSE",
    });
    assert.equal(cancelled, true);
  });

  it("reads normal and exactly bounded streamed JSON without response.text", async () => {
    const normal = await readBoundedJsonResponse(response(JSON.stringify({ command })), {
      errorFactory: (code) => Object.assign(new Error(code), { code }),
      invalidResponseCode: "CONTROLLER_PROVISIONING_INVALID_RESPONSE",
    });
    assert.deepEqual(normal.command, command);
    const exact = `${JSON.stringify({ ok: true })}${" ".repeat(MAX_RESPONSE_BYTES - Buffer.byteLength(JSON.stringify({ ok: true })) )}`;
    const exactResult = await readBoundedJsonResponse(response(exact), {
      errorFactory: (code) => Object.assign(new Error(code), { code }),
      invalidResponseCode: "CONTROLLER_PROVISIONING_INVALID_RESPONSE",
    });
    assert.equal(exactResult.ok, true);
  });

  it("cancels oversized streams before buffering their complete body", async () => {
    let cancelled = false;
    await assert.rejects(
      () => readBoundedJsonResponse({
        body: streamFrom(["{" + "x".repeat(MAX_RESPONSE_BYTES) + "}"], { onCancel: () => { cancelled = true; } }),
      }, {
        errorFactory: (code) => Object.assign(new Error(code), { code }),
        invalidResponseCode: "CONTROLLER_PROVISIONING_INVALID_RESPONSE",
      }),
      { code: "CONTROLLER_PROVISIONING_INVALID_RESPONSE" },
    );
    assert.equal(cancelled, true);
  });

  it("never falls back to unrestricted response.text for command responses", async () => {
    let textCalled = false;
    const client = createClient(async () => ({
      status: 200,
      headers: new Headers(),
      text: async () => { textCalled = true; return JSON.stringify({ command }); },
    }));
    await client.start();
    await assert.rejects(() => client.nextCommand(), {
      code: "CONTROLLER_PROVISIONING_INVALID_RESPONSE",
    });
    assert.equal(textCalled, false);
  });

  it("retries transient stream failures and keeps stable event timestamps and IDs", async () => {
    let calls = 0;
    const client = createClient(async () => {
      calls += 1;
      if (calls === 1) {
        return { status: 200, headers: new Headers(), body: streamFrom([], { error: Object.assign(new Error("reset"), { code: "ECONNRESET" }) }) };
      }
      return response(JSON.stringify({ command }));
    }, { clock: () => new Date("2026-07-21T12:00:00.000Z") });
    await client.start();
    const received = await client.nextCommand();
    assert.equal(calls, 2);
    const sent = [];
    // Report retries use the same already-built event, including occurredAt.
    const reportingClient = createClient(async (_url, options) => {
      sent.push(JSON.parse(options.body));
      return response(JSON.stringify({}));
    }, { clock: () => new Date("2026-07-21T12:00:00.000Z") });
    await reportingClient.start();
    await reportingClient.reportEvent(received, "started", { status: "running", eventType: "job.started" });
    await reportingClient.reportEvent(received, "started", { status: "running", eventType: "job.started" });
    await reportingClient.reportEvent(received, "completed", { status: "succeeded", eventType: "job.completed" });
    assert.equal(sent[0].occurredAt, "2026-07-21T12:00:00.000Z");
    assert.equal(sent[0].occurredAt, sent[1].occurredAt);
    assert.notEqual(sent[0].eventId, sent[2].eventId);
    assert.equal(sent[0].eventId, stableId(command.jobId, "started"));
  });

  it("clamps terminal event timestamps to started when the clock moves backward", async () => {
    const sent = [];
    const clockValues = [
      new Date("2026-07-21T12:00:00.000Z"),
      new Date("2026-07-21T11:59:00.000Z"),
      new Date("2026-07-21T11:58:00.000Z"),
    ];
    const client = createClient(async (_url, options) => {
      sent.push(JSON.parse(options.body));
      return response(JSON.stringify({}));
    }, { clock: () => clockValues.shift() });
    await client.start();
    await client.reportEvent(command, "started", { status: "running", eventType: "job.started" });
    await client.reportEvent(command, "completed", { status: "succeeded", eventType: "job.completed" });
    await client.reportEvent(command, "failed", { status: "failed", eventType: "job.failed" });

    assert.equal(sent[1].occurredAt, sent[0].occurredAt);
    assert.equal(sent[2].occurredAt, sent[0].occurredAt);
    assert.equal(sent[1].eventId, stableId(command.jobId, "completed"));
    assert.equal(sent[2].eventId, stableId(command.jobId, "failed"));
  });

  it("uses a later clock value for a normally ordered terminal event", async () => {
    const sent = [];
    const clockValues = [
      new Date("2026-07-21T12:00:00.000Z"),
      new Date("2026-07-21T12:01:00.000Z"),
    ];
    const client = createClient(async (_url, options) => {
      sent.push(JSON.parse(options.body));
      return response(JSON.stringify({}));
    }, { clock: () => clockValues.shift() });
    await client.start();
    await client.reportEvent(command, "started", { status: "running", eventType: "job.started" });
    await client.reportEvent(command, "completed", { status: "succeeded", eventType: "job.completed" });
    assert.equal(sent[1].occurredAt, "2026-07-21T12:01:00.000Z");
    assert.equal(Date.parse(sent[1].occurredAt) >= Date.parse(sent[0].occurredAt), true);
  });

  it("keeps the terminal timestamp across HTTP retries and command redelivery", async () => {
    const sent = [];
    let reportAttempts = 0;
    const client = createClient(async (url, options) => {
      if (url.endsWith("/provisioning-commands/next")) {
        return response(JSON.stringify({
          command,
          eventTimestamps: { started: "2026-07-21T12:00:00.000Z" },
        }));
      }
      sent.push(JSON.parse(options.body));
      reportAttempts += 1;
      if (reportAttempts === 1) {
        const error = new Error("reset");
        error.code = "ECONNRESET";
        throw error;
      }
      return response(JSON.stringify({}));
    }, {
      clock: () => new Date("2026-07-21T11:59:00.000Z"),
    });
    await client.start();
    const delivery = await client.nextCommand();
    await client.reportEvent(delivery, "completed", { status: "succeeded", eventType: "job.completed" });
    assert.equal(sent.length, 2);
    assert.equal(sent[0].occurredAt, "2026-07-21T12:00:00.000Z");
    assert.equal(sent[1].occurredAt, sent[0].occurredAt);
  });

  it("keeps the timeout active while reading a body and aborts an in-progress read during shutdown", async () => {
    let calls = 0;
    const timed = createClient(async (_url, options) => {
      calls += 1;
      return calls === 1
        ? { status: 200, headers: new Headers(), body: blockingStream(options.signal) }
        : response(JSON.stringify({ command }));
    }, { requestTimeoutMs: 5 });
    await timed.start();
    assert.equal((await timed.nextCommand()).jobId, command.jobId);
    assert.equal(calls, 2);

    const stopping = createClient(async (_url, options) => ({
      status: 200,
      headers: new Headers(),
      body: blockingStream(options.signal),
    }));
    await stopping.start();
    const pending = stopping.nextCommand();
    await new Promise((resolve) => setImmediate(resolve));
    await stopping.close();
    await assert.rejects(() => pending, {
      code: "CONTROLLER_PROVISIONING_STOPPING",
    });
  });
});

describe("controller provisioning command contract validation", () => {
  it("requires plain response, command, issuer, and timestamp objects with no unknown fields", () => {
    const cases = [
      [],
      new Date(),
      { command: validEnvelope().command, unexpected: true },
      { command: [], eventTimestamps: {} },
      { command: { ...validEnvelope().command, unexpected: true } },
      { command: { ...validEnvelope().command, issuerRef: [] } },
      { command: validEnvelope().command, eventTimestamps: [] },
      { command: validEnvelope().command, eventTimestamps: { queued: "2026-07-21T12:00:00Z" } },
    ];
    for (const value of cases) assertInvalidResponse(value);
  });

  it("rejects malformed UUID identities", () => {
    for (const field of ["workspaceId", "jobId", "managedCertificateId"]) {
      const envelope = validEnvelope();
      envelope.command[field] = "not-a-uuid";
      assertInvalidResponse(envelope);
    }
  });

  it("rejects unknown issuer fields and any issuer kind outside the frozen pair", () => {
    const unknown = validEnvelope();
    unknown.command.issuerRef.extra = "unsupported";
    assertInvalidResponse(unknown);

    for (const kind of ["issuer", "CertificateIssuer", "", 1]) {
      const envelope = validEnvelope();
      envelope.command.issuerRef.kind = kind;
      assertInvalidResponse(envelope);
    }
  });

  it("rejects invalid cluster, namespace, Certificate, Secret, and issuer names", () => {
    const cases = [
      ["clusterId", "Cluster-A"],
      ["namespace", "team_a"],
      ["certificateName", "-web-cert"],
      ["secretName", `${"a".repeat(64)}.example`],
    ];
    for (const [field, value] of cases) {
      const envelope = validEnvelope();
      envelope.command[field] = value;
      assertInvalidResponse(envelope);
    }
    for (const [field, value] of [
      ["group", "cert_manager.io"],
      ["name", `${"a".repeat(64)}.example`],
    ]) {
      const envelope = validEnvelope();
      envelope.command.issuerRef[field] = value;
      assertInvalidResponse(envelope);
    }
  });

  it("rejects empty, oversized, duplicate, uppercase, and malformed wildcard DNS identities", () => {
    const invalidDnsNames = [
      [],
      Array.from({ length: 101 }, (_, index) => `name-${index}.example.test`),
      ["example.test", "example.test"],
      ["Example.test"],
      ["**.example.test"],
      ["www.*.example.test"],
      [`${"a".repeat(64)}.example.test`],
    ];
    for (const dnsNames of invalidDnsNames) {
      const envelope = validEnvelope();
      envelope.command.dnsNames = dnsNames;
      assertInvalidResponse(envelope);
    }
  });

  it("validates bounded RFC 3339 event timestamps rather than Date.parse-compatible strings", () => {
    const invalidTimestamps = [
      "2026-07-21 12:00:00Z",
      "2026-7-21T12:00:00Z",
      "2026-02-29T12:00:00Z",
      "1999-12-31T23:59:59Z",
      "2026-07-21T12:00:00+14:01",
      `2026-07-21T12:00:00.${"1".repeat(65)}Z`,
    ];
    for (const timestamp of invalidTimestamps) {
      const envelope = validEnvelope();
      envelope.eventTimestamps.started = timestamp;
      assertInvalidResponse(envelope);
    }

    const valid = validEnvelope();
    valid.eventTimestamps.completed = "2026-07-21T13:30:00+01:30";
    assert.equal(
      validateCommand(valid).eventTimestamps.completed,
      "2026-07-21T12:00:00.000Z",
    );
  });

  it("rejects private material anywhere in the complete response before execution", () => {
    const envelope = validEnvelope();
    envelope.eventTimestamps.started =
      "-----BEGIN PRIVATE KEY-----\nnever-execute\n-----END PRIVATE KEY-----";
    assertInvalidResponse(envelope, "PRIVATE_KEY_MATERIAL_REJECTED");
  });

  it("accepts and freezes a fully valid command with lowercase wildcard DNS identities", () => {
    const envelope = validEnvelope();
    envelope.command.workspaceId = envelope.command.workspaceId.toUpperCase();
    envelope.command.dnsNames = ["*.example.test", "example.test"];
    const validated = validateCommand(envelope);

    assert.equal(validated.command.workspaceId, command.workspaceId);
    assert.deepEqual(validated.command.dnsNames, ["*.example.test", "example.test"]);
    assert.equal(Object.isFrozen(validated), true);
    assert.equal(Object.isFrozen(validated.command), true);
    assert.equal(Object.isFrozen(validated.command.issuerRef), true);
    assert.equal(Object.isFrozen(validated.command.dnsNames), true);
  });
});
