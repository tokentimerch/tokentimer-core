"use strict";
/** Static installer regression only: DumpType=0 selects a custom dump. These
 * checks refuse the former false suppression contract; they cannot qualify
 * native crash containment, which still requires a disposable positive control. */
const { test } = require("node:test"), assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path");
const { validateWindowsInstaller } = require("./ci-guards/core-dump-suppression.cjs");
const source = fs.readFileSync(path.resolve(__dirname, "../packages/agent/scripts/install-agent.ps1"), "utf8");
test("candidate preserves operator WER policy and explicitly leaves containment unqualified", () => assert.deepEqual(validateWindowsInstaller(source), []));
test("custom dump registry writes and false successful suppression claims are refused", () => {
  for (const addition of ['New-ItemProperty -Path $key -Name "DumpType" -PropertyType DWord -Value 0', 'Set-WindowsDumpSuppression -ExeName "node.exe"', 'Write-Log "Crash dumps are suppressed for node.exe"']) assert.ok(validateWindowsInstaller(source + "\n" + addition).length);
  assert.ok(validateWindowsInstaller(source.replace("Windows crash-dump containment is not qualified.", "Qualified")).length);
});
