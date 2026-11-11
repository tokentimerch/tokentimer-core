"use strict";
// Pure protocol/oracle checks only. No DNS server, provider or native hook runs.
const test = require("node:test");
const assert = require("node:assert/strict");
const {
  SCOPE,
  FLAGS,
  verifyProof,
  question,
  verifyDatagrams,
  verifyObservation,
  REQUIRED_SOURCES,
} = require("./certops-dns-resolver-views");
const fs = require("node:fs");
const path = require("node:path");
const { verifyReady, verifyClosed } = require("./certops-dns-owned-server");
test("retained DNS child receipts cannot adopt a foreign owner or omit native drainage", () => {
  const nonce = "a".repeat(32),
    ready = {
      kind: "certops-dns-server-pidfd-ready",
      nonce,
      wrapperPid: 100,
      workerPid: 101,
      parentPid: 100,
      birth: "12345",
      groupId: 90,
      sessionId: 90,
      pidfdPinnedBeforeExec: true,
    };
  const closed = {
    kind: "certops-dns-server-pidfd-closed",
    nonce,
    wrapperPid: 100,
    workerPid: 101,
    rootExitCode: -15,
    pidfdSignalUsed: true,
    pidfdClosed: true,
    workerWaited: true,
  };
  assert.equal(verifyReady(ready, nonce, 100), true);
  assert.equal(verifyClosed(closed, ready), true);
  for (const change of [
    { parentPid: 99 },
    { pidfdPinnedBeforeExec: false },
    { nonce: "b".repeat(32) },
    { extra: true },
  ])
    assert.throws(() => verifyReady({ ...ready, ...change }, nonce, 100));
  for (const change of [
    { workerPid: 102 },
    { pidfdClosed: false },
    { workerWaited: false },
    { wrapperPid: 99 },
    { extra: true },
  ])
    assert.throws(() => verifyClosed({ ...closed, ...change }, ready));
});
function packet(name, response = false) {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(42);
  header.writeUInt16BE(response ? 0x8000 : 0, 2);
  header.writeUInt16BE(1, 4);
  const labels = name
    .split(".")
    .map((label) =>
      Buffer.concat([Buffer.from([label.length]), Buffer.from(label)]),
    );
  return Buffer.concat([header, ...labels, Buffer.from([0, 0, 16, 0, 1])]);
}
function proof() {
  return {
    schemaVersion: 1,
    scope: SCOPE,
    allAttempts: 2,
    recoveryAttempts: 1,
    quorumAttempts: 1,
    allForwarded: [2, 2],
    quorumForwarded: [1, 1],
    ...Object.fromEntries(FLAGS.map((flag) => [flag, true])),
  };
}
test("closed proof requires every observation and both independently queried views", () => {
  assert.equal(verifyProof(proof()), true);
  for (const flag of FLAGS) {
    const p = proof();
    delete p[flag];
    assert.throws(() => verifyProof(p));
  }
  for (const change of [
    { extra: "private" },
    { allForwarded: [2, 0] },
    { quorumForwarded: [1, 0] },
    { allAttempts: 1 },
    { scope: "recursive-public-cache" },
  ])
    assert.throws(() => verifyProof({ ...proof(), ...change }));
});
test("native DNS datagrams retain question, transaction and nontruncated response identity", () => {
  const name = "_acme-challenge.owned.invalid",
    q = packet(name),
    r = packet(name, true);
  assert.equal(question(q), name);
  assert.equal(verifyDatagrams(q, r, name), true);
  const changed = Buffer.from(r);
  changed.writeUInt16BE(43);
  assert.throws(() => verifyDatagrams(q, changed, name));
  const truncated = Buffer.from(r);
  truncated.writeUInt16BE(0x8200, 2);
  assert.throws(() => verifyDatagrams(q, truncated, name));
  assert.throws(() =>
    verifyDatagrams(q, packet("foreign.invalid", true), name),
  );
  const compressed = Buffer.from(q);
  compressed[12] = 0xc0;
  assert.throws(() => question(compressed));
});
test("all refuses reachable disagreement while quorum requires both real observations", () => {
  const endpoints = ["127.0.0.1:20001", "127.0.0.1:20002"];
  for (const [mode, ok, matches] of [
    ["all", false, [true, false]],
    ["all", true, [true, true]],
    ["quorum", true, [true, false]],
  ]) {
    const result = {
      code: ok ? 0 : 1,
      event: {
        ok,
        phase: "propagation",
        verificationMode: mode,
        servers: endpoints,
        attempts: 2,
        serverResults: endpoints.map((server, index) => ({
          server,
          matched: matches[index],
          skipped: false,
        })),
      },
    };
    assert.equal(
      verifyObservation(result, { mode, endpoints, matches, ok }),
      2,
    );
    for (const mutate of [
      (r) => {
        r.event.serverResults[1].skipped = true;
      },
      (r) => {
        r.event.serverResults.pop();
      },
      (r) => {
        r.event.servers.reverse();
      },
      (r) => {
        r.code = ok ? 1 : 0;
      },
    ]) {
      const bad = structuredClone(result);
      mutate(bad);
      assert.throws(() =>
        verifyObservation(bad, { mode, endpoints, matches, ok }),
      );
    }
  }
});
test("every declared causal source is a distinct existing repository file", () => {
  assert.equal(new Set(REQUIRED_SOURCES).size, REQUIRED_SOURCES.length);
  for (const source of REQUIRED_SOURCES)
    assert.equal(
      fs.statSync(path.resolve(__dirname, "..", source)).isFile(),
      true,
      source,
    );
});
