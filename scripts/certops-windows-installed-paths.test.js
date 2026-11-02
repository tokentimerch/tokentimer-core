"use strict";
// Supporting oracle tests only: no Windows service, certificate or native child.
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  os = require("node:os"),
  path = require("node:path");
const helper = require("../tests/e2e/helpers/certops-windows-installed-paths");
test("historical supporting cleanup precedes current qualification and failures preserve sequence", async () => {
  for (const failure of [null, "supporting", "current"]) {
    const environment = {
      CERTOPS_WINDOWS_HISTORICAL_PACKAGE: "owned-historical-package",
    };
    const calls = [];
    let supportingDrained = false;
    const execution = helper.runHistoricalThenCurrent(async (supporting) => {
      calls.push(supporting);
      if (supporting) {
        assert.equal(
          environment.CERTOPS_WINDOWS_HISTORICAL_PACKAGE,
          "owned-historical-package",
        );
        if (failure === "supporting")
          throw new Error("supporting cleanup unresolved");
        await Promise.resolve();
        supportingDrained = true;
      } else {
        assert.equal(supportingDrained, true);
        assert.equal(environment.CERTOPS_WINDOWS_HISTORICAL_PACKAGE, undefined);
        if (failure === "current")
          throw new Error("current qualification failed");
        return "actual-current-result";
      }
    }, environment);
    if (failure) await assert.rejects(execution);
    else assert.equal(await execution, "actual-current-result");
    assert.deepEqual(calls, failure === "supporting" ? [true] : [true, false]);
    assert.equal(
      environment.CERTOPS_WINDOWS_HISTORICAL_PACKAGE,
      "owned-historical-package",
    );
  }
});
function fixture() {
  const root = "C:\\runner\\certops Windows-é-[literal]-abc123",
    expected = {
      host: root + "\\app\\bin\\tokentimer-agent-host-amd64.exe",
      node: "C:\\Program Files\\nodejs\\node.exe",
      entry: root + "\\app\\bin\\tokentimer-agent.js",
      config: root + "\\state",
    };
  return {
    expected,
    value: {
      serviceArgs: [expected.host, expected.node, expected.entry],
      hostExe: expected.host,
      hostId: 100,
      hostCreation: "2026-10-14T10:00:00Z",
      hostSid: "S-1-5-18",
      childArgs: [expected.node, expected.entry],
      childExe: expected.node,
      childId: 101,
      childCreation: "2026-10-14T10:00:01Z",
      childSid: "S-1-5-18",
      parentId: 100,
      environment: ["TOKENTIMER_AGENT_CONFIG_DIR=" + expected.config],
    },
  };
}
test("actual parsed paths require exact SCM/native child/config identities", () => {
  const { value, expected } = fixture();
  assert.equal(helper.validateObservation(value, expected), true);
  for (const change of [
    (v) => v.serviceArgs.push("foreign"),
    (v) => (v.serviceArgs[2] += "-foreign"),
    (v) => (v.childArgs[1] = expected.entry.replace("[literal]", "l")),
    (v) => (v.hostExe = expected.node),
    (v) => (v.childExe = expected.host),
    (v) => (v.parentId = 999),
    (v) => (v.childSid = "S-1-5-32-544"),
    (v) => (v.hostId = 0),
    (v) => (v.childId = v.hostId),
    (v) => v.environment.push("TOKENTIMER_AGENT_CONFIG_DIR=" + expected.config),
    (v) => (v.environment[0] += "-foreign"),
    (v) => v.environment.push("TOKENTIMER_AGENT_BOOTSTRAP_TOKEN=secret"),
  ]) {
    const bad = structuredClone(value);
    change(bad);
    assert.throws(() => helper.validateObservation(bad, expected));
  }
});
test("closed public proof refuses every absent/false flag and private extra", () => {
  const value = {
    scope: helper.SCOPE,
    ...Object.fromEntries(helper.FLAGS.map((k) => [k, true])),
  };
  assert.equal(helper.verifyProof(value), true);
  for (const flag of helper.FLAGS) {
    assert.throws(() => helper.verifyProof({ ...value, [flag]: false }));
    const missing = { ...value };
    delete missing[flag];
    assert.throws(() => helper.verifyProof(missing));
  }
  assert.throws(() => helper.verifyProof({ ...value, privatePath: "secret" }));
  assert.throws(() => helper.verifyProof({ ...value, scope: "default-root" }));
});
test("owned Unicode root receipt refuses a replaced directory", () => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "certops-path-proof-"));
  let receipt;
  try {
    receipt = helper.createOwnedRoot(parent);
    assert.ok(receipt.root.includes("é-[literal]"));
    assert.equal(helper.assertOwnedRoot(receipt), true);
    fs.renameSync(receipt.root, receipt.root + "-original");
    fs.mkdirSync(receipt.root);
    assert.throws(() => helper.assertOwnedRoot(receipt));
    fs.rmdirSync(receipt.root);
    fs.rmdirSync(receipt.root + "-original");
  } finally {
    fs.rmdirSync(parent);
  }
});
test("source manifest names actual critical files and native parser is read-only", () => {
  for (const file of helper.REQUIRED_SOURCES)
    assert.ok(fs.statSync(path.resolve(__dirname, "..", file)).isFile(), file);
  const script = helper.observationScript();
  assert.match(script, /CommandLineToArgvW/);
  assert.match(script, /GetOwnerSid/);
  assert.doesNotMatch(script, /Stop-Process|Remove-Item|New-Service/);
});
