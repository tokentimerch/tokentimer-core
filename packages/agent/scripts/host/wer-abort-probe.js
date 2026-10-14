"use strict";
/* Experimental positive-control probe, explicitly selected on a disposable
 * hosted Windows runner. Owns its benign SYSTEM child/dump directory and exact
 * WER registry snapshot; caller must restore recorded values. This can observe
 * custom dump behavior, but cannot qualify agent heap-dump suppression. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
async function probeWerCustomDump({ workDir, powershell }) {
  assert.equal(process.platform, "win32");
  assert.equal(process.env.GITHUB_ACTIONS, "true");
  assert.equal(process.env.RUNNER_ENVIRONMENT, "github-hosted");
  assert.equal(process.env.CERTOPS_WER_EXPERIMENTAL_PROBE, "1");
  assert.equal(powershell("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value"), "S-1-5-18", "probe must run as SYSTEM");
  assert.equal(path.basename(process.execPath).toLowerCase(), "node.exe");
  const root = path.resolve(workDir);
  const relative = path.relative(path.resolve(process.env.RUNNER_TEMP), root);
  assert.ok(relative && !relative.startsWith("..") && !path.isAbsolute(relative), "probe root must be owned runner scratch");
  const sourcePolicy = JSON.parse(powershell("$k=Get-Item -LiteralPath 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps\\node.exe'; $flags=$null; if ($k.GetValueNames() -contains 'CustomDumpFlags') { if ([string]$k.GetValueKind('CustomDumpFlags') -ne 'DWord') { throw 'Unexpected custom dump flags kind' }; $flags=$k.GetValue('CustomDumpFlags') }; [pscustomobject]@{dumpType=$k.GetValue('DumpType');customFlags=$flags} | ConvertTo-Json -Compress"));
  assert.equal(sourcePolicy.dumpType, 0, "expected actual installer custom-dump policy");
  if (sourcePolicy.customFlags !== null) assert.ok(Number.isInteger(sourcePolicy.customFlags) && sourcePolicy.customFlags >= -2147483648 && sourcePolicy.customFlags <= 2147483647);
  const scratch = fs.mkdtempSync(path.join(root, "benign-wer-probe-"));
  const folder = path.join(scratch, "dumps"); fs.mkdirSync(folder);
  // Isolate the WER application name as well as its output folder. Changing
  // node.exe's sink could otherwise capture another live process's context.
  const name = `certops-benign-wer-${crypto.randomUUID()}.exe`;
  const executable = path.join(scratch, name);
  fs.copyFileSync(process.execPath, executable);
  const digest = (file) => crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
  assert.equal(digest(executable), digest(process.execPath));
  const registry = `HKLM:\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps\\${name}`;
  assert.equal(powershell(`[bool](Test-Path -LiteralPath '${registry}')`), "False", "refuse an existing WER fixture key");
  const env = { SystemRoot: process.env.SystemRoot, WINDIR: process.env.WINDIR, TEMP: scratch, TMP: scratch };
  assert.equal(spawnSync(executable, ["--version"], { cwd: scratch, env, stdio: "ignore", timeout: 10000 }).status, 0,
    "identical renamed native Node binary must actually run");
  fs.writeFileSync(path.join(scratch, "ownership.json"), JSON.stringify({ registry, folder, sourcePolicy, binarySha256: digest(executable), previousKeyPresent: false }));
  let changed = false;
  let originalFailure;
  try {
    changed = true;
    const customFlags = sourcePolicy.customFlags === null ? "" : `New-ItemProperty -LiteralPath $p -Name CustomDumpFlags -PropertyType DWord -Value ([int]${sourcePolicy.customFlags}) -Force | Out-Null;`;
    powershell(`$p='${registry}'; New-Item -Path $p -Force | Out-Null; New-ItemProperty -LiteralPath $p -Name DumpType -PropertyType DWord -Value 0 -Force | Out-Null; ${customFlags} New-ItemProperty -LiteralPath $p -Name DumpFolder -PropertyType ExpandString -Value '${folder.replace(/'/g, "''")}' -Force | Out-Null; New-ItemProperty -LiteralPath $p -Name DumpCount -PropertyType DWord -Value 1 -Force | Out-Null`);
    // Fresh child receives no API/database/bootstrap/DNS/job environment and
    // never loads the agent. Its memory is disposable diagnostic material.
    const child = spawnSync(executable, ["-e", "process.abort()"], { cwd: scratch, env, stdio: "ignore", timeout: 60000 });
    assert.ifError(child.error);
    assert.notEqual(child.status, 0, "benign child must actually abort");
    const deadline = Date.now() + 30000;
    let observed = false;
    while (Date.now() < deadline) {
      const files = fs.readdirSync(folder).filter((file) => file.toLowerCase().startsWith(name.toLowerCase() + ".") && file.toLowerCase().endsWith(".dmp"));
      if (files.some((file) => fs.statSync(path.join(folder, file)).size > 0)) { observed = true; break; }
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
    assert.ok(observed, "custom dump positive control was inconclusive; absence does not qualify suppression");
    // Prototype a supported debugger contract before changing the service
    // host. It observes exception/exit events without reading child memory.
    const clearDeadline = Date.now() + 30000;
    for (const file of fs.readdirSync(folder)) {
      while (true) {
        try { fs.rmSync(path.join(folder, file), { force: true }); break; }
        catch (error) { if (!["EBUSY", "EPERM"].includes(error.code) || Date.now() >= clearDeadline) throw error; await new Promise((resolve) => setTimeout(resolve, 500)); }
      }
    }
    const helper = path.join(scratch, "wer-debugger-prototype.exe");
    const serviceHost = path.resolve(__dirname, "../../windows-service-host");
    const source = path.join(__dirname, "fixtures/wer-debugger-prototype.go");
    const built = spawnSync("go", ["build", "-trimpath", "-buildvcs=false", "-o", helper, source],
      { cwd: serviceHost, env: { ...process.env, GOOS: "windows", GOARCH: process.arch === "arm64" ? "arm64" : "amd64" }, stdio: "ignore", timeout: 180000 });
    assert.equal(built.status, 0, "diagnostic debugger prototype must build");
    const modes = { exit17: 17, exit86: 86, handled: 0, abort: 1 };
    for (const [mode, expected] of Object.entries(modes)) {
      const result = spawnSync(helper, [executable, mode], { cwd: scratch, encoding: "utf8", timeout: 70000,
        env: { ...env, GITHUB_ACTIONS: "true", RUNNER_ENVIRONMENT: "github-hosted", CERTOPS_WER_EXPERIMENTAL_PROBE: "1" } });
      assert.equal(result.status, 0, "diagnostic debugger must finish its bounded event loop");
      const evidence = JSON.parse(result.stdout);
      assert.equal(evidence.mode, mode);
      assert.equal(evidence.childExitCode, expected, "debugger prototype must preserve normal exits and terminate a last-chance fault");
      assert.equal(evidence.secondChanceTerminated, mode === "abort");
      // Positive control already proved WER is enabled for this exact binary
      // and owned sink. Silence alone is insufficient without that control.
      const noDumpDeadline = Date.now() + 5000;
      while (Date.now() < noDumpDeadline) {
        assert.equal(fs.readdirSync(folder).length, 0, "debugged benign child unexpectedly created a dump");
        await new Promise((resolve) => setTimeout(resolve, 500));
      }
    }
    return { diagnosticOnly: true, suppressionQualified: false, customDumpObserved: true, isolatedExecutable: true,
      prototypeNoDumpObserved: true, prototypeNormalExitsPreserved: true };
  } catch (error) { originalFailure = error; throw error; }
  finally {
    try {
      if (changed) powershell(`$p='${registry}'; if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Recurse -Force }; if (Test-Path -LiteralPath $p) { throw 'Owned WER fixture key remains' }`);
      const cleanupDeadline = Date.now() + 30000;
      while (true) {
        try { fs.rmSync(scratch, { recursive: true, force: true }); break; }
        catch (error) { if (!["EBUSY", "EPERM"].includes(error.code) || Date.now() >= cleanupDeadline) throw error; await new Promise((resolve) => setTimeout(resolve, 500)); }
      }
    } catch (cleanupError) { throw new AggregateError(originalFailure ? [originalFailure, cleanupError] : [cleanupError], "benign WER probe cleanup failed", { cause: originalFailure }); }
  }
}
module.exports = { probeWerCustomDump };
