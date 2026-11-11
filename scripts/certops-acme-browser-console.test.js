"use strict";
/** Pure proof/ownership adversaries only; no Chromium or native ACME runs. */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const helper = require("../tests/e2e/helpers/certops-acme-browser-console");
function proof() {
  const id = (c) =>
    `${c.repeat(8)}-${c.repeat(4)}-4${c.repeat(3)}-8${c.repeat(3)}-${c.repeat(12)}`;
  return {
    schemaVersion: 1,
    scope: helper.SCOPE,
    client: "certbot",
    jobId: id("a"),
    certificateId: id("b"),
    claimId: id("c"),
    agentId: id("d"),
    fingerprint: "a".repeat(64),
    firstLineSha256: "b".repeat(64),
    completionLineSha256: "c".repeat(64),
    acceptedLines: 42,
    browserCertOpsWrites: 0,
    ...Object.fromEntries(helper.FLAGS.map((flag) => [flag, true])),
  };
}
test("native console proof is closed and every native observation mandatory", () => {
  assert.equal(helper.verifyProof(proof()), true);
  for (const flag of helper.FLAGS) {
    const p = proof();
    p[flag] = false;
    assert.throws(() => helper.verifyProof(p));
  }
  for (const key of Object.keys(proof())) {
    const p = proof();
    delete p[key];
    assert.throws(() => helper.verifyProof(p));
  }
  for (const update of [
    { client: "acme.sh" },
    { browserCertOpsWrites: 1 },
    { acceptedLines: 2001 },
    { acceptedLines: 1 },
    { rawLog: "private" },
    { firstLineSha256: "c".repeat(64) },
    { claimId: "foreign" },
  ])
    assert.throws(() => helper.verifyProof({ ...proof(), ...update }));
});
test("Linux command barrier binds original parent, process group, start identity and actual client", () => {
  const token = "a-token",
    receipt = {
      token,
      pid: 42,
      parentPid: 41,
      processGroup: 40,
      startTicks: "12345",
      binary: "certbot",
    };
  const fields = ["S", "41", "40", ...Array(16).fill("0"), "12345", "0"];
  const stat = `42 (name with ) parenthesis) ${fields.join(" ")}`;
  const native = helper.parseProcStat(stat);
  assert.equal(
    helper.verifyBarrier(receipt, native, { token, agentPid: 41 }),
    true,
  );
  for (const delta of [
    { token: "other" },
    { pid: 0 },
    { parentPid: 99 },
    { startTicks: "12346" },
    { processGroup: 99 },
    { binary: "other" },
  ])
    assert.throws(() =>
      helper.verifyBarrier({ ...receipt, ...delta }, native, {
        token,
        agentPid: 41,
      }),
    );
  assert.throws(() => helper.parseProcStat("missing process identity"));
});
test("browser mutation accounting includes all workspace CertOps write methods", () => {
  const origin = "http://127.0.0.1:15450";
  const request = (method, suffix, host = origin) => ({
    method: () => method,
    url: () => host + suffix,
  });
  for (const method of ["POST", "PATCH", "PUT", "DELETE"]) {
    assert.equal(
      helper.isCertOpsWrite(
        request(method, "/api/v1/workspaces/other/certops/anything"),
        origin,
      ),
      true,
    );
    assert.equal(
      helper.isCertOpsWrite(
        request(method, "/api/v1/workspaces/other/certops"),
        origin,
      ),
      true,
    );
  }
  for (const req of [
    request("GET", "/api/v1/workspaces/x/certops/jobs"),
    request("POST", "/api/v1/auth/login"),
  ])
    assert.equal(helper.isCertOpsWrite(req, origin), false);
  assert.equal(
    helper.isCertOpsWrite(
      request(
        "POST",
        "/api/v1/workspaces/x/certops/jobs",
        "https://foreign.example",
      ),
    ),
    true,
  );
});
test("browser and API origins are independently bound to bare owned loopback endpoints", () => {
  assert.equal(
    helper.ownedOrigin("http://localhost:5173"),
    "http://localhost:5173",
  );
  assert.equal(
    helper.ownedOrigin("http://127.0.0.1:4000/"),
    "http://127.0.0.1:4000",
  );
  for (const value of [
    "http://localhost.attacker.test:5173",
    "http://user:password@localhost:4000",
    "http://localhost:4000/other",
    "http://localhost:4000/?query=1",
    "http://localhost:4000/#fragment",
    "file:///tmp/console",
  ])
    assert.throws(() => helper.ownedOrigin(value));
});
test("actual browser log payload must retain the native claim and complete without gaps", () => {
  const claim = proof().claimId;
  const payload = {
    items: [{ claimId: claim, message: "actual native line" }],
    streams: [
      {
        claimId: claim,
        streamingEnabled: true,
        status: "final",
        agentGapLines: 0,
        serverDroppedLines: 0,
        truncated: false,
      },
    ],
    jobStatus: "succeeded",
    logsComplete: true,
    hasMore: false,
    storageEnabled: true,
  };
  assert.equal(helper.verifyLogPayload(payload, claim, true), true);
  for (const patch of [
    { linesVisible: false },
    { storageEnabled: false },
    { hasMore: true },
    { logsComplete: false },
    { jobStatus: "failed" },
    { items: [{ claimId: proof().jobId, message: "foreign claim" }] },
  ])
    assert.throws(() =>
      helper.verifyLogPayload({ ...payload, ...patch }, claim, true),
    );
  for (const patch of [
    { claimId: proof().jobId },
    { streamingEnabled: false },
    { agentGapLines: 1 },
    { serverDroppedLines: 1 },
    { truncated: true },
    { status: "abandoned" },
  ])
    assert.throws(() =>
      helper.verifyLogPayload(
        { ...payload, streams: [{ ...payload.streams[0], ...patch }] },
        claim,
        true,
      ),
    );
  const live = {
    ...payload,
    jobStatus: "running",
    logsComplete: false,
    streams: [{ ...payload.streams[0], status: "streaming" }],
  };
  assert.equal(helper.verifyLogPayload(live, claim, false), true);
  assert.throws(() => helper.verifyLogPayload(payload, claim, false));
});
test("retained browser resource registers before launch and clears only after actual close", async () => {
  const child = new EventEmitter();
  child.pid = 42;
  let registered,
    closed = 0;
  const resource = helper.createBrowserOwnership((value) => {
    registered = value;
  });
  assert.equal(registered, resource);
  assert.equal(resource.hasOwnershipReceipt(), false);
  resource.begin();
  assert.equal(resource.hasOwnershipReceipt(), true);
  resource.attach({
    process: () => child,
    close: () => {
      closed++;
      child.emit("close", 0, null);
      return Promise.resolve();
    },
  });
  assert.equal(resource.hasLiveChild(), true);
  await resource.close();
  assert.equal(resource.hasLiveChild(), false);
  assert.equal(resource.hasOwnershipReceipt(), false);
  await resource.close();
  assert.equal(closed, 1);
});
test("unknown browser launch and failed server drain retain ownership", async () => {
  const unknown = helper.createBrowserOwnership(() => {});
  unknown.begin();
  await assert.rejects(unknown.close());
  assert.equal(unknown.hasOwnershipReceipt(), true);
  const child = new EventEmitter();
  child.pid = 43;
  const failed = helper.createBrowserOwnership(() => {});
  failed.begin();
  failed.attach({
    process: () => child,
    close: () => Promise.reject(new Error("controlled close failure")),
  });
  await assert.rejects(failed.close());
  assert.equal(failed.hasLiveChild(), true);
  assert.equal(failed.hasOwnershipReceipt(), true);
});
test("parent registry retains native guard after browser closure or throwing actor construction", async () => {
  let nativeGuard = true,
    browserClosed = false;
  const registered = helper.nativeCleanupResource(
    {
      hasLiveChild: () => !browserClosed,
      hasOwnershipReceipt: () => !browserClosed,
      close: () => {
        browserClosed = true;
        return Promise.resolve();
      },
    },
    () => nativeGuard,
  );
  assert.throws(() => registered.completeNativeOperation());
  await registered.close();
  assert.equal(registered.hasLiveChild(), false);
  assert.equal(registered.hasOwnershipReceipt(), true);
  assert.throws(() => registered.assertCleanupSafe());
  assert.throws(() => registered.completeNativeOperation());
  nativeGuard = false;
  assert.equal(
    registered.hasOwnershipReceipt(),
    true,
    "Lost guard cannot resolve unknown native operation",
  );
  assert.throws(() => registered.assertCleanupSafe());
  registered.completeNativeOperation();
  assert.equal(registered.hasOwnershipReceipt(), false);
  registered.assertCleanupSafe();
});
