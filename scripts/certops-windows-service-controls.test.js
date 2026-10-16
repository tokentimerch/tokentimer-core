"use strict";
/** Offline contract/adversarial checks; no SCM control, certificate, CNG or TLS
 * action executes here. Native success remains a qualified Windows prerequisite. */
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  os = require("node:os"),
  path = require("node:path");
const h = require("../tests/e2e/helpers/certops-windows-service-controls");
const proof = () => ({
  scope: h.SCOPE,
  controlCount: 3,
  certificateOperationInterruptionQualified: false,
  ...Object.fromEntries(h.FLAGS.map((flag) => [flag, true])),
});
test("SCM proof requires complete native facts and refuses interruption promotion", () => {
  assert.equal(h.verifyProof(proof()), true);
  for (const key of Object.keys(proof())) {
    const value = proof();
    delete value[key];
    assert.throws(() => h.verifyProof(value));
  }
  for (const flag of h.FLAGS)
    assert.throws(() => h.verifyProof({ ...proof(), [flag]: false }));
  for (const patch of [
    { controlCount: 2 },
    { certificateOperationInterruptionQualified: true },
    { rawProcess: "private" },
  ])
    assert.throws(() => h.verifyProof({ ...proof(), ...patch }));
});
test("native controls must actually close with supported and refused results", () => {
  h.classifyControlResult("interrogate", { status: 0, signal: null });
  for (const command of ["pause", "continue"])
    h.classifyControlResult(command, { status: 1052, signal: null });
  for (const command of ["pause", "continue"])
    assert.throws(() =>
      h.classifyControlResult(command, { status: 0, signal: null }),
    );
  for (const status of [5, 1061, 1062])
    assert.throws(() =>
      h.classifyControlResult("pause", { status, signal: null }),
    );
  for (const result of [
    { status: 1, signal: null },
    { status: null, signal: "SIGTERM" },
    { status: 0, signal: null, error: new Error("timeout") },
  ])
    assert.throws(() => h.classifyControlResult("interrogate", result));
  assert.throws(() =>
    h.classifyControlResult("stop", { status: 0, signal: null }),
  );
});
test("unresolved owned control receipt preserves native fixture cleanup", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "certops-scm-controls-"));
  try {
    const file = path.join(root, h.GUARD);
    fs.writeFileSync(file, "owned", { flag: "wx" });
    assert.throws(() => h.assertCleanupSafe(root));
    assert.equal(fs.readFileSync(file, "utf8"), "owned");
    fs.unlinkSync(file);
    h.assertCleanupSafe(root);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
test("native custody script binds exact protected machine key and hostname store", () => {
  const script = h.custodyScript({
    thumbprint: "A".repeat(40),
    domain: "owned.example.test",
    port: 44321,
  });
  assert.match(script, /SslSniBindingInfo/);
  assert.match(script, /SslCertStoreName -ine 'My'/);
  assert.match(script, /IsMachineKey/);
  assert.match(script, /ExportPolicy -ne 0/);
  assert.throws(() =>
    h.custodyScript({
      thumbprint: "A".repeat(40),
      domain: "owned';remove",
      port: 44321,
    }),
  );
  assert.throws(() =>
    h.custodyScript({
      thumbprint: "A".repeat(40),
      domain: "owned.example.test",
      port: 0,
    }),
  );
});

test("claim polling last-seen advancement cannot replace real heartbeat uptime", () => {
  const before = {
    status: "active",
    last_seen_at: "2026-10-15T10:00:00.000Z",
    uptime_seconds: "12",
  };
  assert.equal(
    h.hasFreshHeartbeat(before, {
      ...before,
      last_seen_at: "2026-10-15T10:00:05.000Z",
    }),
    false,
  );
  assert.equal(
    h.hasFreshHeartbeat(before, { ...before, uptime_seconds: "17" }),
    false,
  );
  assert.equal(
    h.hasFreshHeartbeat(before, {
      ...before,
      last_seen_at: "2026-10-15T10:00:05.000Z",
      uptime_seconds: "17",
    }),
    true,
  );
  for (const value of [null, "nan", "1.5", -1])
    assert.throws(() =>
      h.hasFreshHeartbeat(before, {
        ...before,
        last_seen_at: "2026-10-15T10:00:05.000Z",
        uptime_seconds: value,
      }),
    );
});

test("actual reporter validates bounded sidecars for every Windows key profile", () => {
  const reporter = require("./certops-stack-reporter");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "certops-scm-report-"));
  const dir = path.join(root, "qualification-results");
  fs.mkdirSync(dir);
  const main =
    "real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence";
  try {
    for (const profile of [
      "rsa-2048",
      "rsa-3072",
      "rsa-4096",
      "ec-p256",
      "ec-p384",
    ]) {
      const scope = "real-agent-windows-acme-iis/" + profile,
        file = path.join(dir, `windows-service-controls-${profile}.json`);
      assert.throws(() => reporter.serviceControlsProof(scope, main, root));
      fs.writeFileSync(file, JSON.stringify(proof()));
      assert.deepEqual(
        reporter.serviceControlsProof(scope, main, root),
        proof(),
      );
      fs.writeFileSync(
        file,
        JSON.stringify({ ...proof(), pauseAndContinueRefused: false }),
      );
      assert.throws(() => reporter.serviceControlsProof(scope, main, root));
      fs.writeFileSync(file, " ".repeat(16385));
      assert.throws(() => reporter.serviceControlsProof(scope, main, root));
    }
    assert.equal(
      reporter.serviceControlsProof("real-agent-acme-filesystem", main, root),
      undefined,
    );
    assert.equal(
      reporter.serviceControlsProof(
        "real-agent-windows-acme-iis/rsa-2048",
        "unrelated",
        root,
      ),
      undefined,
    );
    assert.throws(() =>
      reporter.serviceControlsProof(
        "real-agent-windows-acme-iis/../../foreign",
        main,
        root,
      ),
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
test("parent guard precedes every cleanup and proof is emitted only after successful cleanup", () => {
  const source = fs.readFileSync(
    path.join(__dirname, "../tests/e2e/windows-real-journey.js"),
    "utf8",
  );
  const guard = source.indexOf("serviceControls.assertCleanupSafe(workDir)");
  assert.ok(
    guard > 0 &&
      guard <
        source.indexOf(
          'require("./helpers/certops-windows-owned-process").assertCleanupSafe(workDir)',
          guard,
        ),
  );
  const { createRequire } = require("node:module");
  const espree = createRequire(require.resolve("../packages/agent/node_modules/eslint/package.json"))("espree");
  const ast = espree.parse(source, { ecmaVersion: "latest", sourceType: "script", range: true });
  const matches = [];
  function visit(node) {
    if (!node || typeof node !== "object") return;
    if (node.type === "IfStatement" && source.slice(...node.consequent.range).includes("serviceControls.verifyProof(serviceControlProof)")) matches.push(node);
    for (const child of Object.values(node)) if (Array.isArray(child)) child.forEach(visit); else if (child && typeof child === "object") visit(child);
  }
  visit(ast);
  assert.equal(matches.length, 1, "Single actual normal-scope proof publication gate required");
  const successful = matches[0].range[0];
  const expression = source.slice(...matches[0].test.range);
  const baseline = { failedRollbackOnly: false, aliveGraceOnly: false, stoppedOfflineOnly: false, historicalSupportingOnly: false, journeyFailure: null, errors: [] };
  const evaluate = (values) => require("node:vm").runInNewContext(expression, values);
  assert.equal(evaluate(baseline), true);
  for (const key of ["failedRollbackOnly", "aliveGraceOnly", "stoppedOfflineOnly", "historicalSupportingOnly"]) assert.equal(evaluate({ ...baseline, [key]: true }), false, key);
  assert.equal(evaluate({ ...baseline, journeyFailure: new Error("controlled journey failure") }), false);
  assert.equal(evaluate({ ...baseline, errors: [new Error("controlled cleanup failure")] }), false);
  assert.ok(successful > guard);
  assert.ok(
    source.indexOf("serviceControls.verifyProof(serviceControlProof)") >
      successful,
  );
});

test("trusted TLS options use the actual Windows parent root-object contract", () => {
  const pem =
    "-----BEGIN CERTIFICATE-----\npublic-fixture\n-----END CERTIFICATE-----";
  const options = h.tlsOptions({
    domain: "owned.example.test",
    port: 44321,
    roots: [{ pem, thumbprint: "public-root" }],
  });
  assert.deepEqual(options.ca, [pem]);
  assert.equal(options.rejectUnauthorized, true);
  assert.equal(options.servername, "owned.example.test");
  assert.throws(() =>
    h.tlsOptions({ domain: "owned.example.test", port: 44321, roots: [pem] }),
  );
  assert.throws(() =>
    h.tlsOptions({ domain: "owned.example.test", port: 44321, roots: [] }),
  );
});

test("sticky SCM guard precedes the first native identity observation", () => {
  const source = fs.readFileSync(
    path.join(
      __dirname,
      "../tests/e2e/helpers/certops-windows-service-controls.js",
    ),
    "utf8",
  );
  const guard = source.indexOf("active.add(receipt.root)");
  const observe = source.indexOf("const original = observe()");
  assert.ok(guard > 0 && observe > guard);
});
