"use strict";
/** Offline actual-report contract/adversaries. These are not browser or CA
 * executions and cannot produce a native qualification report. */
const { test } = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  os = require("node:os"),
  path = require("node:path");
const report = require("./certops-acme-native-console-report"),
  helper = require("../tests/e2e/helpers/certops-acme-browser-console");
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
const candidate = "a".repeat(40);
function events() {
  return [
    ...report.NATIVE_CASES,
    require("./certops-acme-stage-report").JOURNEY,
  ].map((name) => ({
    type: "test:pass",
    name,
    file: "tests/e2e/certops-agent-e2e.test.js",
    scope: "real-agent-acme-filesystem",
    candidateSha: candidate,
  }));
}
test("native console wrapper refuses missing/skipped/foreign actual journey events", () => {
  const text = (rows) => rows.map((row) => JSON.stringify(row)).join("\n");
  assert.equal(
    report.verifyActualJourney(text(events()), proof(), candidate),
    true,
  );
  for (const rows of [
    events().slice(1),
    [...events(), events()[0]],
    events().map((row, index) => (index ? row : { ...row, skip: true })),
    events().map((row) => ({ ...row, candidateSha: "b".repeat(40) })),
    events().map((row) => ({ ...row, scope: "agent-protocol" })),
    events().map((row) => ({ ...row, file: "proof-unit.test.js" })),
  ])
    assert.throws(() =>
      report.verifyActualJourney(text(rows), proof(), candidate),
    );
  assert.throws(() =>
    report.verifyActualJourney(
      text(events()),
      { ...proof(), actualSignedNativeClaim: false },
      candidate,
    ),
  );
});
test("fixed native sidecar is bounded and requires closed real-console facts", () => {
  const tempBase = fs.realpathSync.native(os.tmpdir()),
    root = fs.mkdtempSync(path.join(tempBase, "certops-native-console-proof-"));
  const fixed = path.join(root, report.SIDECAR);
  fs.mkdirSync(path.dirname(fixed));
  try {
    fs.writeFileSync(fixed, JSON.stringify(proof()), { mode: 0o600 });
    assert.deepEqual(report.readProof(root), proof());
    fs.writeFileSync(fixed, " ".repeat(65537));
    assert.throws(() => report.readProof(root));
    fs.writeFileSync(
      fixed,
      JSON.stringify({ ...proof(), rawLog: "private-extra" }),
    );
    assert.throws(() => report.readProof(root));
    fs.unlinkSync(fixed);
    fs.mkdirSync(fixed);
    assert.throws(() => report.readProof(root));
    fs.rmdirSync(fixed);
    assert.throws(() => report.readProof(root));
  } finally {
    const resolved = path.resolve(root);
    assert.ok(resolved.startsWith(tempBase + path.sep));
    assert.equal(fs.lstatSync(resolved).isSymbolicLink(), false);
    fs.rmSync(resolved, { recursive: true });
  }
});
test("dedicated runner restricts trusted manual native Ubuntu certbot account scope", () => {
  const runner = require("./certops-acme-native-console"),
    env = {
      CERTOPS_PROTOCOL_DISPOSABLE_STACK: "1",
      CERTOPS_NATIVE_ACME_CONSOLE: "1",
      CERTOPS_REAL_ACME_CLIENT: "certbot",
      CERTOPS_REAL_ACME_EAB: "none",
      GITHUB_ACTIONS: "true",
      GITHUB_REF: "refs/heads/main",
      GITHUB_EVENT_NAME: "workflow_dispatch",
      GITHUB_SHA: candidate,
    };
  const release = 'ID=ubuntu\nVERSION_ID="24.04"\n';
  assert.equal(runner.checkScope(env, "linux", release, false), true);
  for (const patch of [
    { CERTOPS_NATIVE_ACME_CONSOLE: "0" },
    { CERTOPS_REAL_ACME_CLIENT: "acme.sh" },
    { CERTOPS_REAL_ACME_EAB: "required" },
    { GITHUB_REF: "refs/pull/1/merge" },
    { GITHUB_EVENT_NAME: "pull_request" },
    { GITHUB_ACTIONS: "false" },
  ])
    assert.throws(() =>
      runner.checkScope({ ...env, ...patch }, "linux", release, false),
    );
  assert.throws(() => runner.checkScope(env, "win32", release, false));
  assert.throws(() => runner.checkScope(env, "linux", release, true));
  assert.throws(() =>
    runner.checkScope(env, "linux", 'ID=alpine\nVERSION_ID="3.22"\n', false),
  );
  for (const file of runner.REQUIRED_SOURCES)
    assert.ok(
      fs.existsSync(path.join(__dirname, "..", file)),
      `Missing critical source ${file}`,
    );
});
