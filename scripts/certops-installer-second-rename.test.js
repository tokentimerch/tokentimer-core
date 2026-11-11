"use strict";
/** Portable report contract negatives for second-rename qualification. The real
 * filesystem/notification regression is invoked explicitly by Windows PowerShell;
 * these tests establish neither installed service nor native certificate proof. */
const { test } = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  os = require("node:os"),
  { spawn } = require("node:child_process");
const {
  verifyProof,
  publishActivationSignal,
} = require("../tests/e2e/helpers/certops-windows-second-rename");
// Independent committed expectation: removing an oracle from the producer's
// own field list must not also remove its regression coverage.
const expectedProof = () => ({
  childIdentityVerifiedBeforeActivation: true,
  actualProductionFunctions: true,
  nativeOrderedRestoreEvents: true,
  originalDirectoryIdentityRestored: true,
  heldStagingIdentityUnchanged: true,
  explicitStagingCleanupFailure: true,
  candidateNeverActivated: true,
  predecessorFilesUnchanged: true,
  sameRunningServicePid: true,
  configurationAndCredentialUnchanged: true,
  cngCustodyUnchanged: true,
  bindingAndTrustedTlsUnchanged: true,
  freshAuthenticatedHeartbeat: true,
  nativeHandleReleased: true,
  ownedStagingRemoved: true,
  ownedChildDrained: true,
});
test("activation proof requires every restoration custody heartbeat and cleanup oracle", () => {
  const facts = {
    ...expectedProof(),
    scope: "production-activation-functions-not-installer-cli",
  };
  assert.equal(verifyProof(facts), true);
  for (const field of Object.keys(expectedProof())) {
    assert.throws(
      () => verifyProof({ ...facts, [field]: false }),
      undefined,
      field,
    );
    const missing = { ...facts };
    delete missing[field];
    assert.throws(() => verifyProof(missing), undefined, field);
  }
});
test("activation-function proof cannot claim full installer CLI execution", () => {
  const facts = expectedProof();
  for (const scope of [
    undefined,
    "full-installer-cli",
    "first-rename-preservation",
  ])
    assert.throws(() => verifyProof({ ...facts, scope }));
});

test(
  "actual activation signal publishers hide incomplete bytes from the waiting child",
  { timeout: 30000 },
  async () => {
    for (const signal of ["go", "release"]) {
      const root = fs.mkdtempSync(
        path.join(os.tmpdir(), "certops-activation-signal-"),
      );
      const marker = path.join(root, "writer-open"),
        resume = path.join(root, "resume"),
        target = path.join(root, signal);
      const code = `
const fs = require('node:fs'), path = require('node:path');
const [source, root, signal] = process.argv.slice(1);
const publish = require(source).publishActivationSignal;
const write = fs.writeFileSync;
fs.writeFileSync = function(file, bytes, options) {
  if (typeof file === 'number') {
    write(path.join(root, 'writer-open'), 'public-ready');
    const deadline = Date.now() + 8000;
    while (!fs.existsSync(path.join(root, 'resume'))) {
      if (Date.now() >= deadline) throw new Error('Controlled signal release missing');
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 10);
    }
  }
  return write.apply(fs, arguments);
};
publish(root, signal, 'a'.repeat(32));
`;
      const child = spawn(
        process.execPath,
        [
          "-e",
          code,
          require.resolve("../tests/e2e/helpers/certops-windows-second-rename"),
          root,
          signal,
        ],
        { windowsHide: true, timeout: 12000, stdio: "ignore" },
      );
      const closed = new Promise((resolve) => {
        child.once("error", (error) => resolve({ error }));
        child.once("close", (code) => resolve({ code }));
      });
      try {
        const deadline = Date.now() + 10000;
        while (
          !fs.existsSync(marker) &&
          child.exitCode === null &&
          Date.now() < deadline
        )
          await new Promise((resolve) => setTimeout(resolve, 10));
        assert.equal(
          fs.existsSync(marker),
          true,
          "Actual signal writer reached the controlled pause",
        );
        const premature = fs.existsSync(target);
        fs.writeFileSync(resume, "public-resume");
        const result = await closed;
        assert.equal(result.error, undefined);
        assert.equal(result.code, 0);
        assert.equal(
          premature,
          false,
          "The reader must not see an empty or partial signal",
        );
        assert.equal(fs.readFileSync(target, "utf8"), "a".repeat(32));
        assert.equal(
          fs.readdirSync(root).some((name) => name.startsWith(".signal-")),
          false,
        );
      } finally {
        if (!fs.existsSync(resume)) fs.writeFileSync(resume, "public-resume");
        await closed;
        assert.equal(
          path.dirname(path.resolve(root)),
          path.resolve(os.tmpdir()),
        );
        for (const name of fs.readdirSync(root)) {
          const file = path.join(root, name);
          assert.equal(fs.lstatSync(file).isFile(), true);
          fs.unlinkSync(file);
        }
        fs.rmdirSync(root);
      }
    }
  },
);

test("activation signals refuse an existing target without replacing its bytes", () => {
  const root = fs.mkdtempSync(
    path.join(os.tmpdir(), "certops-activation-signal-collision-"),
  );
  try {
    for (const name of ["go", "release"]) {
      const target = path.join(root, name);
      fs.writeFileSync(target, "foreign-public-sentinel");
      assert.throws(() => publishActivationSignal(root, name, "a".repeat(32)), {
        code: "EEXIST",
      });
      assert.equal(fs.readFileSync(target, "utf8"), "foreign-public-sentinel");
    }
    assert.throws(() => publishActivationSignal(root, "../go", "a".repeat(32)));
    assert.throws(() => publishActivationSignal(root, "go", "invalid-token"));
  } finally {
    assert.equal(path.dirname(path.resolve(root)), path.resolve(os.tmpdir()));
    for (const name of fs.readdirSync(root)) {
      const file = path.join(root, name);
      assert.equal(fs.lstatSync(file).isFile(), true);
      fs.unlinkSync(file);
    }
    fs.rmdirSync(root);
  }
});

test("supporting activation failures expose bounded phases without private messages or paths", () => {
  const {
    failureSummary,
  } = require("./certops-installer-second-rename-support");
  const error = Object.assign(
    new Error("private token and process arguments"),
    {
      code: "ENOENT",
      activationPhase: "closed-receipt",
      nativeRootExitCode: 1,
      nativeStartupPhase: "suspended-observation",
      privatePath: "private-path",
    },
  );
  const aggregate = new AggregateError([error], "private aggregate message");
  assert.deepEqual(failureSummary(aggregate), {
    name: "AggregateError",
    causes: [
      {
        name: "Error",
        code: "ENOENT",
        phase: "closed-receipt",
        nativeRootExitCode: 1,
        nativeStartupPhase: "suspended-observation",
      },
    ],
  });
  assert.deepEqual(
    failureSummary({
      name: "private-name",
      code: "private-code",
      activationPhase: "private-phase",
      nativeRootExitCode: -1,
    }),
    { name: "UnknownError" },
  );
  aggregate.errors.push(aggregate);
  assert.ok(JSON.stringify(failureSummary(aggregate)).length < 2000);
});

test("startup diagnostics retain only known native stages and numeric error codes", () => {
  const {
    failureSummary,
  } = require("./certops-installer-second-rename-support");
  assert.deepEqual(
    failureSummary(
      new Error(
        "Contained native failure at native-create: System.ComponentModel.Win32Exception (-2147467259, native 5)",
      ),
    ),
    {
      name: "Error",
      nativeFailure: {
        stage: "native-create",
        hresult: -2147467259,
        nativeErrorCode: 5,
      },
    },
  );
  assert.deepEqual(
    failureSummary(
      new Error("Contained native phase exceeded bounded deadline"),
    ),
    { name: "Error", reason: "native-startup-deadline" },
  );
  for (const message of [
    "Contained native failure at private-stage: System.Private (-1, native 5)",
    "Contained native failure at native-create: System.Private (-999999999999, native 5)",
    "Contained native failure at native-create: System.Private (-1, native 5) private suffix",
  ])
    assert.deepEqual(failureSummary(new Error(message)), { name: "Error" });
});
