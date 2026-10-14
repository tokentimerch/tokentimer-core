"use strict";
/** Portable protocol/quoting adversaries. These tests never launch a process,
 * service, certificate operation or native Job Object. */
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path");
const helper = require("../tests/e2e/helpers/certops-windows-contained-process");
test("native Windows PowerShell never inherits PowerShell Core module paths", () => {
  const original = {
    PATH: "native-path",
    PSModulePath: "foreign-modules",
    psmodulepath: "foreign-lowercase",
    OWNED_PRIVATE_ENV: "private-inherited",
  };
  assert.deepEqual(helper.nativeEnvironment(original), {
    PATH: "native-path",
    OWNED_PRIVATE_ENV: "private-inherited",
  });
  assert.equal(original.PSModulePath, "foreign-modules");
});
test("supplied child environment is complete and cannot inherit unrelated secrets", () => {
  const inherited = {
    PATH: "native-path",
    UNRELATED_SECRET_SENTINEL: "must-not-enter-child",
    PSModulePath: "foreign",
  };
  assert.deepEqual(
    helper.childEnvironment(
      { PATH: "owned-native-path", OWNED_TOKEN: "private-explicit" },
      inherited,
    ),
    { PATH: "owned-native-path", OWNED_TOKEN: "private-explicit" },
  );
  assert.deepEqual(helper.childEnvironment(undefined, inherited), {
    PATH: "native-path",
    UNRELATED_SECRET_SENTINEL: "must-not-enter-child",
  });
  assert.deepEqual(helper.childEnvironment({}, inherited), {});
});
test("Windows argv encoder preserves spaces Unicode literal brackets quotes and terminal slashes", () => {
  assert.equal(
    helper.commandLine("C:\\Windows\\powershell.exe", [
      "C:\\Windows é [literal]\\driver.ps1",
      'a"b',
      "C:\\trailing\\",
      "",
    ]),
    '"C:\\Windows\\powershell.exe" "C:\\Windows é [literal]\\driver.ps1" "a\\\"b" "C:\\trailing\\\\" ""',
  );
  for (const bad of ["a\nforged", "a\0b", false, null])
    assert.throws(() => helper.quoteArgument(bad));
  assert.throws(() => helper.commandLine("node", new Array(65).fill("x")));
});
test("suspended root receipt cannot qualify uncontained or foreign native identity", () => {
  const expected = {
      token: "a".repeat(32),
      wrapperPid: 10,
      ownerPid: 9,
      sid: "S-1-5-18",
      executable: "C:\\owned\\powershell.exe",
      commandLine: '"C:\\owned\\powershell.exe" "owned.ps1"',
    },
    value = {
      ...expected,
      pid: 11,
      parentPid: 10,
      creationTime: "2026-10-14T12:00:00.1234567Z",
      executablePath: expected.executable,
      commandLineOrigin: "sealed-createprocess-input",
      nativeSuspended: true,
      jobAssignedBeforeResume: true,
    };
  delete value.executable;
  assert.equal(helper.verifyStarted(value, expected), true);
  for (const change of [
    { token: "b".repeat(32) },
    { wrapperPid: 12 },
    { ownerPid: 12 },
    { pid: 0 },
    { parentPid: 9 },
    { sid: "S-1-5-32-544" },
    { executablePath: "C:\\foreign.exe" },
    { commandLine: "foreign" },
    { commandLineOrigin: "observed-before-native-resume" },
    { nativeSuspended: false },
    { jobAssignedBeforeResume: false },
    { privateEnvironment: { secret: "must-not-qualify" } },
  ])
    assert.throws(() =>
      helper.verifyStarted({ ...value, ...change }, expected),
    );
});
test("native drain requires exact owner root Active0 real exit and all handles closed", () => {
  const expected = {
      token: "a".repeat(32),
      wrapperPid: 10,
      ownerPid: 9,
      rootPid: 11,
    },
    value = {
      token: expected.token,
      wrapperPid: 10,
      ownerPid: 9,
      nativeRootPid: 11,
      rootExitCode: 0,
      launchOccurred: true,
      activeNativeProcesses: 0,
      retainedJobDrained: true,
      nativeRootExited: true,
      nativeHandlesClosed: true,
    };
  assert.equal(helper.verifyClosed(value, expected), true);
  for (const key of Object.keys(value)) {
    const missing = { ...value };
    delete missing[key];
    assert.throws(() => helper.verifyClosed(missing, expected));
  }
  for (const change of [
    { nativeRootPid: 12 },
    { rootExitCode: -1 },
    { rootExitCode: 0x100000000 },
    { activeNativeProcesses: 1 },
    { activeNativeProcesses: false },
    { retainedJobDrained: false },
    { nativeRootExited: false },
    { nativeHandlesClosed: false },
    { launchOccurred: false },
    { rawEnvironment: "private" },
  ])
    assert.throws(() => helper.verifyClosed({ ...value, ...change }, expected));
  const empty = {
    ...value,
    launchOccurred: false,
    nativeRootPid: null,
    rootExitCode: null,
  };
  assert.equal(
    helper.verifyClosed(empty, { ...expected, rootPid: null }),
    true,
  );
  assert.throws(() => helper.verifyClosed(empty, expected));
});
test("contained adapter has no PID-kill fallback and retains native close boundaries", () => {
  const source = fs.readFileSync(
    path.resolve(
      __dirname,
      "../tests/e2e/helpers/certops-windows-contained-process.js",
    ),
    "utf8",
  );
  assert.doesNotMatch(
    source,
    /taskkill|Stop-Process|process\.kill|child\.kill/,
  );
  assert.match(source, /onCreated\(resource\)/);
  assert.match(source, /child\.once\("close"/);
  assert.match(source, /verifyClosed\(result/);
  assert.match(source, /nativeObservation\(started.pid\)/);
});
