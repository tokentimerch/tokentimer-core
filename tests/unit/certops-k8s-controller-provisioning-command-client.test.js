"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

const {
  MAX_RESPONSE_BYTES,
  readBoundedJsonResponse,
} = require("../../apps/k8s-controller/src/observation-reporter");
const {
  createControllerProvisioningCommandClient,
  stableId,
} = require("../../apps/k8s-controller/src/provisioning-command-client");

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
