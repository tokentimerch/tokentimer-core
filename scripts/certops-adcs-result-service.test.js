"use strict";

// Managed PowerShell pipeline controls only: Get-CimInstance is replaced by an
// in-process public object fixture. No service or native process is observed.
const test = require("node:test");
const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const subject = require("../tests/e2e/helpers/certops-adcs-result-service");

test("stopped service proof requires exact graceful native drainage", () => {
  const value = {
    rootExitCode: 0,
    nodeExitCode: 0,
    allCapturedHandlesExited: true,
    capturedLineageAbsent: true,
    fixtureCommandPathsAbsent: true,
    readOnlyObservation: true,
    nativeHandlesClosed: true,
    atomicTreeContainmentQualified: false,
  };
  assert.equal(subject.verifyStoppedResult(value), true);
  for (const key of Object.keys(value)) {
    const altered = {
      ...value,
      [key]: typeof value[key] === "boolean" ? !value[key] : 86,
    };
    assert.throws(() => subject.verifyStoppedResult(altered));
  }
});

test("actual stopped inventory pipeline inspects each process command", () => {
  const script = subject.stoppedInventoryScript(
    ["C:\\PUBLIC\\host.exe", "C:\\PUBLIC\\agent.js", "C:\\PUBLIC\\agent"],
    4242,
  );
  assert.match(script, /\$p=\$_/);
  assert.throws(() => subject.stoppedInventoryScript(["one"], 4242));
  // This supporting parser/pipeline control is portable through pwsh where
  // installed; the Windows qualification host always has powershell.exe.
  const executable = process.platform === "win32" ? "powershell.exe" : "pwsh";
  for (const [command, expected] of [
    ["C:\\PUBLIC\\agent.js", "refused"],
    ["C:\\unrelated\\app.js", "stopped"],
  ]) {
    const fixture = `function Get-CimInstance { [pscustomobject]@{ProcessId=45678;CommandLine='${command}'} };try { ${script} }catch { 'refused' }`;
    const result = spawnSync(
      executable,
      ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", fixture],
      { encoding: "utf8", timeout: 10000 },
    );
    if (
      result.error &&
      result.error.code === "ENOENT" &&
      process.platform !== "win32"
    ) {
      // Portable source assertions above remain useful without PowerShell.
      return;
    }
    assert.equal(result.status, 0, "Managed pipeline control must execute");
    assert.equal(result.stdout.trim(), expected);
  }
});
