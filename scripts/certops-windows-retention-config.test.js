"use strict";
/** Supporting actual production configuration reads only. No SCM, native
 * certificate/key, network, clock override or retention sweep is executed. */
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  os = require("node:os"),
  { spawnSync } = require("node:child_process");
const h = require("../tests/e2e/helpers/certops-windows-retention-config");
test("retention boundary copies change only policy and actual production startup validator refuses each", () => {
  const value = {
      serverUrl: "https://owned.example.test",
      label: "literal-config",
      windows: { supersededRetentionHours: 168, sweepIntervalMs: 21600000 },
    },
    original = Buffer.from(JSON.stringify(value));
  const rows = h.policyCases(original);
  assert.deepEqual(
    rows.map((x) => x.id),
    h.CASES,
  );
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "retention-config-")),
    file = path.join(root, "config.json"),
    entry = path.resolve(__dirname, "../packages/agent/src/config");
  try {
    const run = () =>
      spawnSync(
        process.execPath,
        ["-e", `require(${JSON.stringify(entry)}).loadAgentConfig()`],
        {
          env: { ...process.env, TOKENTIMER_AGENT_CONFIG_DIR: root },
          encoding: "utf8",
          timeout: 10000,
        },
      );
    for (const row of rows) {
      const parsed = JSON.parse(row.content);
      assert.equal(parsed.serverUrl, value.serverUrl);
      assert.equal(parsed.label, value.label);
      fs.writeFileSync(file, row.content);
      const result = run();
      assert.equal(result.status, 1);
      assert.ok(result.stderr.includes(row.expectedError));
      assert.deepEqual(fs.readFileSync(file), row.content);
    }
    fs.writeFileSync(file, original);
    const restored = run();
    assert.equal(restored.status, 0, restored.stderr);
    assert.deepEqual(fs.readFileSync(file), original);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
test("policy startup proof cannot qualify timers or omit measured native facts", () => {
  const p = {
    scope: h.SCOPE,
    policies: [...h.CASES],
    startupFailureCount: 3,
    retentionTimerQualified: false,
    ...Object.fromEntries(h.FLAGS.map((x) => [x, true])),
  };
  h.verifyProof(p);
  for (const key of Object.keys(p)) {
    const q = { ...p };
    delete q[key];
    assert.throws(() => h.verifyProof(q));
  }
  assert.throws(() => h.verifyProof({ ...p, retentionTimerQualified: true }));
  for (const flag of h.FLAGS)
    assert.throws(() => h.verifyProof({ ...p, [flag]: false }));
  assert.throws(() => h.verifyProof({ ...p, rawConfig: "secret" }));
});
test("shared native engine refuses empty or ambiguous process counts and protects either pending policy guard", () => {
  const engine = require("../tests/e2e/helpers/certops-windows-config-encoding");
  assert.equal(engine.verifyProcessCount("0"), true);
  assert.equal(engine.verifyProcessCount("2"), false);
  for (const value of ["", " ", "\n", "00", "-1", "0.0", "NaN", 0])
    assert.throws(() => engine.verifyProcessCount(value));
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "policy-guard-"));
  try {
    fs.writeFileSync(
      path.join(root, ".installed-retention-policy-active.json"),
      "owned-test",
    );
    assert.throws(() => engine.assertCleanupSafe(root));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
  const source = fs.readFileSync(
    path.join(
      __dirname,
      "../tests/e2e/helpers/certops-windows-config-encoding.js",
    ),
    "utf8",
  );
  assert.ok(
    source.includes("(policyMode || credentialMode || fresh.includes(file))"),
    "policy validation error has no config pathname, unlike parse failures",
  );
  assert.ok(source.includes("policy.policyCases(original)"));
});
test("actual policy reporter requires full sidecar for each Windows key profile", () => {
  const reporter = require("./certops-stack-reporter"),
    root = fs.mkdtempSync(path.join(os.tmpdir(), "policy-report-")),
    main =
      "real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence";
  const proof = {
    scope: h.SCOPE,
    policies: [...h.CASES],
    startupFailureCount: 3,
    retentionTimerQualified: false,
    ...Object.fromEntries(h.FLAGS.map((x) => [x, true])),
  };
  try {
    fs.mkdirSync(path.join(root, "qualification-results"));
    for (const profile of [
      "rsa-2048",
      "rsa-3072",
      "rsa-4096",
      "ec-p256",
      "ec-p384",
    ]) {
      const scope = "real-agent-windows-acme-iis/" + profile,
        file = path.join(
          root,
          "qualification-results",
          `windows-retention-config-${profile}.json`,
        );
      assert.throws(() => reporter.retentionConfigProof(scope, main, root));
      fs.writeFileSync(file, JSON.stringify(proof));
      assert.deepEqual(reporter.retentionConfigProof(scope, main, root), proof);
      fs.writeFileSync(
        file,
        JSON.stringify({ ...proof, retentionTimerQualified: true }),
      );
      assert.throws(() => reporter.retentionConfigProof(scope, main, root));
    }
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
