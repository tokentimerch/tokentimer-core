"use strict";
/** Actual wrapper VM and software contracts; no agent/client/CA/key or native
 * process executes. Temporary public files belong exclusively to each test. */
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  os = require("node:os"),
  vm = require("node:vm"),
  crypto = require("node:crypto");
const h = require("../tests/e2e/helpers/certops-acme-certificate-signing");
const { fixture } = require("./fixtures/certops-acme-certificate-signing.cjs");
test("closed rotation proof requires old/new claims and respects real certificate key policy", () => {
  for (const rotate of [true, false])
    assert.equal(h.verifyProof(fixture(rotate)), true);
  for (const key of Object.keys(fixture())) {
    const p = fixture();
    delete p[key];
    assert.throws(() => h.verifyProof(p), key);
  }
  for (const key of h.FLAGS)
    assert.throws(() => h.verifyProof({ ...fixture(), [key]: false }), key);
  for (const patch of [
    { forcedCompletionQualified: true },
    { sharedFleetQualified: true },
    { atomicTreeContainmentQualified: true },
    { rotatePrivateKey: false },
    { unknown: true },
    { signingKeyIds: ["same", "same"] },
  ])
    assert.throws(() => h.verifyProof({ ...fixture(), ...patch }));
});
test("actual command wrapper leaves arm immutable and delegates only after its exact owned go token", () => {
  const file = path.resolve(
      __dirname,
      "../tests/e2e/helpers/certops-acme-signing-command.js",
    ),
    source = fs.readFileSync(file, "utf8");
  for (const mode of ["held", "wrong-token", "unarmed"]) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "signing-command-")),
      token = crypto.randomUUID();
    try {
      const arm = path.join(root, "armed.json");
      if (mode !== "unarmed")
        fs.writeFileSync(arm, JSON.stringify({ token }), { mode: 0o600 });
      const original = mode === "unarmed" ? null : fs.readFileSync(arm);
      let tick,
        launches = 0;
      const fake = {
        platform: "linux",
        pid: 123,
        ppid: 12,
        argv: ["node", file, root, "certbot", "public-argument"],
        env: {},
      };
      vm.runInNewContext(
        source,
        {
          process: fake,
          Buffer,
          setTimeout() {
            return 1;
          },
          clearTimeout() {},
          setInterval(callback) {
            tick = callback;
            return 2;
          },
          clearInterval() {},
          require(name) {
            if (name === "node:fs")
              return {
                ...fs,
                readFileSync(value, ...args) {
                  if (value === "/proc/self/stat")
                    return (
                      "123 (owned public fixture) " +
                      ["S", "12", "123", ...Array(16).fill("0"), "777"].join(
                        " ",
                      )
                    );
                  return fs.readFileSync(value, ...args);
                },
              };
            if (name === "node:child_process")
              return {
                spawn(binary, args) {
                  launches++;
                  assert.equal(binary, "certbot");
                  assert.deepEqual(Array.from(args), ["public-argument"]);
                  return { once() {} };
                },
              };
            return require(name);
          },
        },
        { filename: file },
      );
      if (mode === "unarmed") {
        assert.equal(launches, 1);
        continue;
      }
      tick();
      assert.equal(launches, 0);
      fs.writeFileSync(
        path.join(root, "go"),
        mode === "held" ? token : crypto.randomUUID(),
        { mode: 0o600 },
      );
      if (mode === "held") {
        tick();
        assert.equal(launches, 1);
      } else assert.throws(tick);
      assert.ok(fs.readFileSync(arm).equals(original));
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  }
});

test("actual native admission refuses any preexisting certificate or signing fleet before CLI/native launch", async () => {
  const { createRequire } = require("node:module");
  const file = path.resolve(
      __dirname,
      "../tests/e2e/helpers/certops-acme-certificate-signing.js",
    ),
    actualRequire = createRequire(file);
  for (const field of ["agents", "keys", "jobs", "certificates", "profiles"]) {
    let cleaned = 0,
      launched = 0;
    const module = { exports: {} };
    vm.runInNewContext(
      fs.readFileSync(file, "utf8"),
      {
        module,
        exports: module.exports,
        __dirname: path.dirname(file),
        Buffer,
        setTimeout,
        process: {
          platform: "linux",
          env: {
            CERTOPS_CERTIFICATE_SIGNING_DISPOSABLE_STACK: "1",
            CERTOPS_REAL_ACME_CLIENT: "certbot",
            CERTOPS_REAL_ACME_EAB: "none",
          },
        },
        require(name) {
          if (name === "./certops-api-fixture")
            return {
              async createApiFixture() {
                await Promise.resolve();
                return {
                  pool: {
                    async query() {
                      await Promise.resolve();
                      return {
                        rows: [
                          {
                            agents: 0,
                            keys: 0,
                            jobs: 0,
                            certificates: 0,
                            profiles: 0,
                            [field]: 1,
                          },
                        ],
                      };
                    },
                  },
                  async cleanup() {
                    await Promise.resolve();
                    cleaned++;
                  },
                };
              },
            };
          if (name === "node:child_process")
            return {
              spawn() {
                launched++;
                throw Error("Unexpected native launch");
              },
              spawnSync() {
                launched++;
                throw Error("Unexpected operator launch");
              },
            };
          if (name === "node:fs")
            return {
              ...fs,
              existsSync() {
                return false;
              },
            };
          return actualRequire(name);
        },
      },
      { filename: file },
    );
    await assert.rejects(
      module.exports.qualify({
        baseUrl: "http://127.0.0.1:1",
        repoRoot: path.resolve(__dirname, ".."),
      }),
    );
    assert.equal(cleaned, 1);
    assert.equal(launched, 0);
  }
});

test("actual producer downgrades a previous passed report when isolated stack teardown fails", () => {
  const producer = require("./certops-acme-certificate-signing");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "signing-report-"));
  try {
    const file = path.join(root, "report.json");
    fs.writeFileSync(
      file,
      JSON.stringify({
        suite: producer.SUITE,
        status: "passed",
        cleanup: { status: "passed" },
      }),
      { mode: 0o600 },
    );
    producer.failTeardown(file);
    const value = JSON.parse(fs.readFileSync(file));
    assert.equal(value.status, "failed");
    assert.equal(value.cleanup.status, "failed");
    fs.writeFileSync(
      file,
      JSON.stringify({ suite: "unrelated", status: "passed" }),
    );
    assert.throws(() => producer.failTeardown(file));
    assert.equal(JSON.parse(fs.readFileSync(file)).suite, "unrelated");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

function passedReport(mutate) {
  const producer = require("./certops-acme-certificate-signing");
  const report = {
    schemaVersion: 1,
    suite: producer.SUITE,
    strict: true,
    status: "passed",
    evidenceLevel: "e2e",
    platform: "linux",
    architecture: "x64",
    candidateSha: "a".repeat(40),
    startedAt: "2026-10-17T00:00:00.000Z",
    finishedAt: "2026-10-17T00:10:00.000Z",
    requiredScenarios: [h.SCENARIO],
    missingScenarios: [],
    missingCapabilities: [],
    requiredCapabilities: [...producer.CAPABILITIES],
    scenarios: [
      {
        id: h.SCENARIO,
        status: "passed",
        evidenceLevel: "e2e",
        startedAt: "2026-10-17T00:00:01.000Z",
        finishedAt: "2026-10-17T00:09:00.000Z",
      },
    ],
    capabilities: Object.fromEntries(
      producer.CAPABILITIES.map((name) => [name, { available: true }]),
    ),
    qualificationEnvironment: { ...producer.CELL.environment },
    nativeRuntime: { platform: "linux", architecture: "x64", uid: 1000 },
    fixtureSources: producer.REQUIRED_SOURCES.map((file) => ({
      file,
      sha256: "ab".repeat(32),
    })),
    cleanup: { status: "passed", summary: "owned cleanup" },
    [producer.FIELD]: fixture(),
  };
  if (mutate) mutate(report);
  return report;
}

test("strict projection keeps only the closed public old and new certificate proof", () => {
  const producer = require("./certops-acme-certificate-signing");
  for (const rotate of [true, false]) {
    const report = passedReport(
      (value) => {
        value[producer.FIELD] = fixture(rotate);
        value.unprojectedSecret = "must-not-project";
      },
    );
    const projected = producer.projectReport(report);
    assert.deepEqual(Object.keys(projected), [producer.FIELD]);
    assert.equal(h.verifyProof(projected[producer.FIELD]), true);
    assert.equal(JSON.stringify(projected).includes("must-not-project"), false);
  }
  for (const mutate of [
    (report) => {
      report.status = "failed";
    },
    (report) => {
      report.cleanup = { status: "failed" };
    },
    (report) => {
      report.strict = false;
    },
    (report) => {
      report.platform = "win32";
    },
    (report) => {
      report.nativeRuntime.uid = 0;
    },
    (report) => {
      report.qualificationEnvironment.executionSurface = "container";
    },
    (report) => {
      report.scenarios = [];
    },
    (report) => {
      report.requiredCapabilities = ["linux"];
    },
    (report) => {
      report.fixtureSources = report.fixtureSources.slice(1);
    },
    (report) => {
      report.candidateSha = "abc";
    },
    (report) => {
      delete report[producer.FIELD];
    },
    (report) => {
      report[producer.FIELD] = { ...fixture(), sharedFleetQualified: true };
    },
    (report) => {
      report[producer.FIELD] = { ...fixture(), forcedCompletionQualified: true };
    },
  ])
    assert.throws(() => producer.projectReport(passedReport(mutate)));
});

test("mandatory cell names the separate manual certificate rotation slot", () => {
  const producer = require("./certops-acme-certificate-signing");
  assert.deepEqual(
    Object.keys(producer.CELL).sort(),
    [
      "environment",
      "id",
      "kind",
      "requiredSources",
      "scenario",
      "source",
      "suite",
      "workflow",
    ].sort(),
  );
  assert.equal(producer.CELL.id, "linux-native-certificate-signing-rotation");
  assert.equal(producer.CELL.kind, "host");
  assert.equal(producer.CELL.suite, producer.SUITE);
  assert.equal(producer.CELL.scenario, h.SCENARIO);
  assert.equal(
    producer.CELL.source,
    "tests/e2e/certops-certificate-signing-native.js",
  );
  assert.equal(
    producer.CELL.workflow,
    ".github/workflows/certops-acme-certificate-signing.yml",
  );
  assert.deepEqual(producer.CELL.environment, {
    osFamily: "linux",
    distributionId: "ubuntu",
    distributionVersion: "24.04",
    distribution: "ubuntu",
    osVersion: "24.04",
    executionSurface: "host",
    measurement: "native",
  });
  assert.equal(producer.CELL.requiredSources, producer.REQUIRED_SOURCES);
  const workflow = fs.readFileSync(
    path.resolve(__dirname, "../.github/workflows/certops-acme-certificate-signing.yml"),
    "utf8",
  );
  assert.match(
    workflow,
    /\non:\n {2}workflow_dispatch:\npermissions:\n {2}contents: read\n/,
  );
  for (const banned of [
    "push:",
    "pull_request:",
    "schedule:",
    "workflow_call:",
    "workflow_run:",
  ])
    assert.equal(workflow.includes(banned), false, banned);
  assert.match(workflow, /node scripts\/certops-acme-certificate-signing\.js\n/);
  assert.match(workflow, /projectReport/);
  assert.match(
    workflow,
    /actions\/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd/,
  );
  assert.match(
    workflow,
    /actions\/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02/,
  );
});
