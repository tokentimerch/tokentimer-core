"use strict";
/** Real production config-reader controls on owned temporary public files only.
 * No SCM, certificate, key, network or CA operation executes in these tests. */
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  os = require("node:os"),
  { spawnSync } = require("node:child_process");
const h = require("../tests/e2e/helpers/certops-windows-config-encoding");
test("encoding variants preserve the same actual JSON while production UTF-8 reader refuses them", () => {
  const original = Buffer.from(
    JSON.stringify({
      serverUrl: "https://owned.example.test",
      label: "é-[literal]",
    }),
  );
  const rows = h.encodingCases(original);
  assert.deepEqual(
    rows.map((row) => row.id),
    h.CASES,
  );
  assert.equal(new Set(rows.map((row) => row.sha256)).size, 3);
  assert.deepEqual(rows[0].content.subarray(3), original);
  assert.equal(
    rows[1].content.subarray(2).toString("utf16le"),
    original.toString("utf8"),
  );
  const be = Buffer.from(rows[2].content.subarray(2));
  be.swap16();
  assert.equal(be.toString("utf16le"), original.toString("utf8"));
  const directory = fs.mkdtempSync(
      path.join(os.tmpdir(), "certops-config-encoding-"),
    ),
    file = path.join(directory, "config.json"),
    marker = path.join(directory, "credential");
  try {
    fs.writeFileSync(marker, "public-unregistered-state-marker");
    const entry = path.resolve(__dirname, "../packages/agent/src/config");
    const env = { ...process.env, TOKENTIMER_AGENT_CONFIG_DIR: directory };
    const run = () =>
      spawnSync(
        process.execPath,
        ["-e", `require(${JSON.stringify(entry)}).loadAgentConfig()`],
        { env, encoding: "utf8", timeout: 10000 },
      );
    for (const row of rows) {
      fs.writeFileSync(file, row.content);
      const result = run();
      assert.equal(result.status, 1);
      assert.match(result.stderr, /failed to parse/);
      assert.equal(
        fs.readFileSync(marker, "utf8"),
        "public-unregistered-state-marker",
      );
      assert.deepEqual(fs.readFileSync(file), row.content);
    }
    // Remove only our deliberately invalid public marker so positive config load
    // does not confuse credential-shape validation with encoding validation.
    fs.unlinkSync(marker);
    fs.writeFileSync(file, original);
    const repaired = run();
    assert.equal(repaired.status, 0, repaired.stderr);
    assert.deepEqual(fs.readFileSync(file), original);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
test("encoding generator refuses invalid original bytes and public proof cannot omit measured native facts", () => {
  for (const value of [
    Buffer.from([0xff]),
    Buffer.from("[]"),
    Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from("{}")]),
  ])
    assert.throws(() => h.encodingCases(value));
  const proof = {
    scope: h.SCOPE,
    encodings: [...h.CASES],
    startupFailureCount: 3,
    ...Object.fromEntries(h.FLAGS.map((flag) => [flag, true])),
  };
  assert.equal(h.verifyProof(proof), true);
  for (const key of Object.keys(proof)) {
    const bad = { ...proof };
    delete bad[key];
    assert.throws(() => h.verifyProof(bad));
  }
  for (const flag of h.FLAGS)
    assert.throws(() => h.verifyProof({ ...proof, [flag]: false }));
  assert.throws(() => h.verifyProof({ ...proof, rawConfiguration: "private" }));
});

test("stopped native fixture requires exact quoted service paths and refuses foreign ownership", () => {
  const expected = [
    "C:\\owned root\\host.exe",
    "C:\\Program Files\\node.exe",
    "C:\\owned root\\agent.js",
  ];
  const value = {
    state: "Stopped",
    pid: 0,
    identity: "LocalSystem",
    path: expected.map((x) => `"${x}"`).join(" "),
  };
  h.validateStoppedService(value, expected);
  for (const patch of [
    { state: "Running" },
    { pid: 1 },
    { identity: "LocalService" },
    { path: value.path + " --foreign" },
    { path: value.path.replace("host.exe", "host.exe-foreign") },
  ])
    assert.throws(() =>
      h.validateStoppedService({ ...value, ...patch }, expected),
    );
});

test("retained configuration writer refuses identical-byte foreign replacement before mutation", () => {
  const directory = fs.mkdtempSync(
    path.join(os.tmpdir(), "certops-config-object-"),
  );
  const file = path.join(directory, "config.json"),
    retained = path.join(directory, "original-owned.json");
  const original = Buffer.from('{"serverUrl":"https://owned.example.test"}');
  fs.writeFileSync(file, original);
  const st = fs.lstatSync(file, { bigint: true }),
    identity = `${st.dev}:${st.ino}`,
    fd = fs.openSync(file, fs.constants.O_RDWR);
  try {
    const changed = Buffer.from("{invalid");
    h.writeOwnedConfig(fd, file, identity, original, changed);
    assert.deepEqual(fs.readFileSync(file), changed);
    h.writeOwnedConfig(fd, file, identity, changed, original);
    fs.renameSync(file, retained);
    fs.writeFileSync(file, original, { flag: "wx" });
    assert.throws(() =>
      h.writeOwnedConfig(fd, file, identity, original, changed),
    );
    assert.deepEqual(fs.readFileSync(file), original);
    assert.deepEqual(fs.readFileSync(retained), original);
  } finally {
    fs.closeSync(fd);
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("actual reporter accepts only bounded complete native encoding sidecars in all five profiles", () => {
  const reporter = require("./certops-stack-reporter"),
    directory = fs.mkdtempSync(
      path.join(os.tmpdir(), "certops-encoding-report-"),
    );
  fs.mkdirSync(path.join(directory, "qualification-results"));
  const proof = {
    scope: h.SCOPE,
    encodings: [...h.CASES],
    startupFailureCount: 3,
    ...Object.fromEntries(h.FLAGS.map((flag) => [flag, true])),
  };
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
        file = path.join(
          directory,
          "qualification-results",
          `windows-config-encoding-${profile}.json`,
        );
      assert.throws(() => reporter.configEncodingProof(scope, main, directory));
      fs.writeFileSync(file, JSON.stringify(proof));
      assert.deepEqual(
        reporter.configEncodingProof(scope, main, directory),
        proof,
      );
      fs.writeFileSync(
        file,
        JSON.stringify({ ...proof, encodings: ["utf8-bom"] }),
      );
      assert.throws(() => reporter.configEncodingProof(scope, main, directory));
    }
    assert.equal(
      reporter.configEncodingProof(
        "real-agent-acme-filesystem",
        main,
        directory,
      ),
      undefined,
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
