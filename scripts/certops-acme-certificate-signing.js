/**
 * Qualification: native certificate signing-key rotation
 *
 * Use only manual certops-acme-certificate-signing.yml with a separate disposable
 * Ubuntu/certbot/noEAB API/Postgres/Pebble stack; refuse repository .env or shared API
 * DB container. Never rotate a shared database. After real predecessor issuance, hold
 * public renewal only after the agent verified its original v2 signed claim. The
 * observer reads job/key IDs without claiming signature verification; consumed
 * nonce/current claim establish admission. Operator begin, real heartbeat pin ack and
 * completion WITHOUT force must precede command release. Both original and
 * replacement-key-signed renewals need actual CA leaves, matching keys/trusted TLS,
 * current-claim evidence and one attempt; record execution key policy and actual custody
 * change. Keep config/credentials unchanged and require replacement pin adoption.
 * Original command drain/exact receipt identities/sticky guards protect private and DB
 * cleanup. The separate noop pin-adoption suite does not qualify this certificate
 * execution composition; source/proof checks cannot establish native runs.
 */
// Shared execution, evidence and cleanup policy: docs/certops/e2e-qualification.md.
"use strict";
/** Manual Azure-free Ubuntu one-agent rotation producer. A passed artifact is
 * written only after the real native child, strict public projection and owned
 * Pebble teardown complete. Shared fleets, .env overrides and partial native
 * facts are refused. Native execution of the registered cell remains pending. */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
const { createHostGate } = require("../packages/agent/scripts/host-gate");
const proof = require("../tests/e2e/helpers/certops-acme-certificate-signing");
const SOURCE = "scripts/certops-acme-certificate-signing.js";
const SUITE = "native-certificate-signing-rotation";
const FIELD = "nativeCertificateSigningRotation";
const CAPABILITIES = Object.freeze([
  "linux",
  "api",
  "postgres",
  "nativeAcme",
  "native-node-agent",
  "rotation-cli",
]);
const REQUIRED_SOURCES = require("./certops-acme-certificate-signing-sources");
const CELL = Object.freeze({
  id: "linux-native-certificate-signing-rotation",
  kind: "host",
  suite: SUITE,
  source: "tests/e2e/certops-certificate-signing-native.js",
  workflow: ".github/workflows/certops-acme-certificate-signing.yml",
  scenario: proof.SCENARIO,
  environment: Object.freeze({
    osFamily: "linux",
    distributionId: "ubuntu",
    distributionVersion: "24.04",
    distribution: "ubuntu",
    osVersion: "24.04",
    executionSurface: "host",
    measurement: "native",
  }),
  requiredSources: REQUIRED_SOURCES,
});
function projectReport(report) {
  assert.ok(report && typeof report === "object" && !Array.isArray(report));
  assert.equal(report.suite, SUITE);
  assert.equal(report.strict, true);
  assert.equal(report.status, "passed");
  assert.equal(report.schemaVersion, 1);
  assert.equal(report.evidenceLevel, "e2e");
  assert.equal(report.platform, "linux");
  assert.equal(report.architecture, "x64");
  assert.equal(report.cleanup && report.cleanup.status, "passed");
  assert.match(String(report.candidateSha), /^[a-f0-9]{40}$/);
  assert.equal(typeof report.startedAt, "string");
  assert.equal(typeof report.finishedAt, "string");
  assert.ok(Date.parse(report.finishedAt) >= Date.parse(report.startedAt));
  assert.deepEqual(report.requiredScenarios, [proof.SCENARIO]);
  assert.deepEqual(report.missingScenarios, []);
  assert.deepEqual(report.missingCapabilities, []);
  assert.deepEqual(report.requiredCapabilities, [...CAPABILITIES]);
  assert.ok(Array.isArray(report.scenarios) && report.scenarios.length === 1);
  const scenario = report.scenarios[0];
  assert.equal(scenario.id, proof.SCENARIO);
  assert.equal(scenario.status, "passed");
  assert.equal(scenario.evidenceLevel, "e2e");
  assert.equal(typeof scenario.startedAt, "string");
  assert.equal(typeof scenario.finishedAt, "string");
  assert.ok(Date.parse(scenario.finishedAt) >= Date.parse(scenario.startedAt));
  for (const name of CAPABILITIES)
    assert.equal(report.capabilities?.[name]?.available, true, name);
  const environment = report.qualificationEnvironment || {};
  for (const [key, value] of Object.entries(CELL.environment))
    assert.equal(environment[key], value, key);
  assert.equal(report.nativeRuntime?.platform, "linux");
  assert.equal(report.nativeRuntime?.architecture, "x64");
  assert.equal(typeof report.nativeRuntime?.uid, "number");
  assert.ok(report.nativeRuntime.uid > 0);
  assert.ok(Array.isArray(report.fixtureSources));
  assert.deepEqual(
    report.fixtureSources.map((row) => row.file),
    [...REQUIRED_SOURCES],
  );
  for (const row of report.fixtureSources) {
    assert.equal(typeof row.file, "string");
    assert.match(row.sha256, /^[a-f0-9]{64}$/);
  }
  const projected = structuredClone(report[FIELD]);
  proof.verifyProof(projected);
  assert.equal(JSON.stringify(projected).includes("BEGIN "), false);
  return Object.freeze({ [FIELD]: projected });
}
async function main() {
  assert.equal(process.platform, "linux");
  assert.equal(process.arch, "x64");
  assert.ok(process.getuid() > 0, "Dedicated non-root Ubuntu runner required");
  assert.equal(process.env.CERTOPS_CERTIFICATE_SIGNING_DISPOSABLE_STACK, "1");
  assert.equal(process.env.CERTOPS_REAL_ACME_CLIENT, "certbot");
  assert.equal(process.env.CERTOPS_REAL_ACME_EAB, "none");
  const root = path.resolve(__dirname, "..");
  assert.equal(fs.existsSync(path.join(root, ".env")), false);
  const output = path.join(root, "qualification-results");
  fs.mkdirSync(output, { recursive: true });
  const facts = path.join(output, "certificate-signing-facts.json"),
    reportPath = path.join(output, "certificate-signing-rotation.json");
  assert.equal(fs.existsSync(facts), false);
  assert.equal(fs.existsSync(reportPath), false);
  const source = (file) => ({
    file,
    sha256: crypto
      .createHash("sha256")
      .update(fs.readFileSync(path.join(root, file)))
      .digest("hex"),
  });
  const gate = createHostGate({
    suite: SUITE,
    strict: true,
    reportPath,
    evidenceLevel: "e2e",
    requiredCapabilities: ["linux"],
    fixtureSource: source(SOURCE),
    probeCapabilities: () => ({
      linux: { available: process.platform === "linux" },
    }),
  });
  assert.equal(await gate.preflight(), true);
  assert.equal(gate.report.qualificationEnvironment.distributionId, "ubuntu");
  assert.equal(
    gate.report.qualificationEnvironment.distributionVersion,
    "24.04",
  );
  assert.equal(gate.report.qualificationEnvironment.executionSurface, "host");
  gate.report.qualificationEnvironment.osVersion = "24.04";
  gate.report.qualificationEnvironment.distribution = "ubuntu";
  gate.report.requiredCapabilities = [...CAPABILITIES];
  gate.report.fixtureSources = REQUIRED_SOURCES.map(source);
  await gate.scenario(proof.SCENARIO, async () => {
    await require("./certops-real-acme").withPebble(async (fixtureEnv) => {
      const result = spawnSync(
        process.execPath,
        ["tests/e2e/certops-certificate-signing-native.js"],
        {
          cwd: root,
          stdio: "inherit",
          timeout: 1020000,
          env: { ...process.env, ...fixtureEnv },
        },
      );
      assert.ifError(result.error);
      assert.equal(
        result.status,
        0,
        "Actual isolated certificate/rotation child failed",
      );
      await Promise.resolve();
    });
    const p = JSON.parse(
      require("../tests/e2e/helpers/certops-acme-native-adoption").readOwnedBytes(
        facts,
        16384,
      ),
    );
    proof.verifyProof(p);
    gate.report[FIELD] = p;
    gate.report.nativeRuntime = {
      platform: process.platform,
      architecture: process.arch,
      uid: process.getuid(),
    };
    for (const name of CAPABILITIES)
      gate.report.capabilities[name] = { available: true };
  });
  await gate.finish({
    requiredScenarios: [proof.SCENARIO],
    cleanup: {
      status: "passed",
      summary:
        "Actual owned command/agent pidfds, TLS/gateway, API fixture/private root and Pebble cleanup completed before passing facts",
    },
  });
  try {
    projectReport(JSON.parse(fs.readFileSync(reportPath, "utf8")));
  } catch (error) {
    failTeardown(reportPath);
    throw error;
  }
}
function failTeardown(
  reportPath = path.resolve(
    __dirname,
    "../qualification-results/certificate-signing-rotation.json",
  ),
) {
  const original = fs.lstatSync(reportPath, { bigint: true });
  assert.ok(
    original.isFile() &&
      !original.isSymbolicLink() &&
      original.ino > 0n &&
      original.size > 0n &&
      original.size <= 2097152n,
  );
  const fd = fs.openSync(
    reportPath,
    fs.constants.O_RDWR | (fs.constants.O_NOFOLLOW || 0),
  );
  try {
    const before = fs.fstatSync(fd, { bigint: true });
    assert.ok(
      before.dev === original.dev &&
        before.ino === original.ino &&
        before.size === original.size,
    );
    const bytes = Buffer.alloc(Number(before.size) + 1),
      length = fs.readSync(fd, bytes, 0, bytes.length, 0);
    const current = fs.lstatSync(reportPath, { bigint: true }),
      after = fs.fstatSync(fd, { bigint: true });
    assert.ok(
      length === Number(before.size) &&
        ["dev", "ino", "size", "mtimeNs", "ctimeNs"].every(
          (key) => before[key] === after[key],
        ) &&
        !current.isSymbolicLink() &&
        current.dev === before.dev &&
        current.ino === before.ino,
    );
    const report = JSON.parse(bytes.subarray(0, length));
    assert.equal(report.suite, SUITE);
    report.status = "failed";
    report.cleanup = {
      status: "failed",
      summary: "Owned isolated API/PostgreSQL stack teardown failed",
    };
    const output = Buffer.from(JSON.stringify(report));
    fs.ftruncateSync(fd, 0);
    fs.writeSync(fd, output, 0, output.length, 0);
    fs.fsyncSync(fd);
    const final = fs.lstatSync(reportPath, { bigint: true });
    assert.ok(
      !final.isSymbolicLink() &&
        final.dev === before.dev &&
        final.ino === before.ino,
    );
  } finally {
    fs.closeSync(fd);
  }
}
if (require.main === module) {
  if (process.argv[2] === "fail-teardown") {
    try {
      failTeardown();
    } catch {
      process.exitCode = 1;
    }
  } else
    main().catch(() => {
      console.error(
        "Dedicated certificate signing producer failed; inspect bounded report only",
      );
      process.exitCode = 1;
    });
}
module.exports = {
  main,
  SOURCE,
  SUITE,
  FIELD,
  CELL,
  CAPABILITIES,
  REQUIRED_SOURCES,
  projectReport,
  failTeardown,
};
