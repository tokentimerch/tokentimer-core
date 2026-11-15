"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { supportsNode } = require("./check-node-engine");
const packageRoot = path.resolve(__dirname, "..");
const range = require("../package.json").engines.node;

test("checks both declared bounds, including patch versions and prereleases", () => {
  assert.equal(range, ">=22.0.0 <25.0.0");
  for (const version of ["v22.0.0", "v22.15.0", "v23.0.0", "v24.99.99", "v24.0.0+build.1"]) {
    assert.equal(supportsNode(range, version), true, version);
  }
  for (const version of ["v21.99.99", "v25.0.0", "v26.0.0", "v24.0.0-rc.1", "v24.0", "v024.0.0", "v24.0.0+bad..build"]) {
    assert.equal(supportsNode(range, version), false, version);
  }
  assert.equal(supportsNode(">=22.15.1 <24.6.1", "v22.15.0"), false);
  assert.equal(supportsNode(">=22.15.1 <24.6.1", "v24.6.0"), true);
  assert.equal(supportsNode(">=22.15.1 <24.6.1", "v24.6.1"), false);
  for (const invalid of ["", ">=22", ">=22.0.0", ">=22.0.0 || <25.0.0", ">=25.0.0 <22.0.0"]) {
    assert.equal(supportsNode(invalid, "v24.0.0"), false, invalid);
  }
});

function section(file, start, end) {
  const content = fs.readFileSync(path.join(__dirname, file), "utf8");
  const from = content.indexOf(start);
  const to = content.indexOf(end, from);
  assert.ok(from >= 0 && to > from, `${file}: installer gate not found`);
  return content.slice(from, to);
}

test("both installer gates accept supported versions and stop before installation for unsupported versions", () => {
  const shell = process.platform === "win32" ? "C:/Program Files/Git/bin/bash.exe" : "sh";
  const powershell = process.platform === "win32" ? "powershell.exe" : "pwsh";
  const shSource = section("install-agent.sh", "REQUIRED_RANGE=$(sed", "# Reject ineffective reload grants");
  const psSource = section("install-agent.ps1", "$packageJsonText = Get-Content", "$nodeVersionMatch =");
  const env = { ...process.env, TT_REAL_NODE: process.execPath, TT_PACKAGE: packageRoot.replace(/\\/g, "/"), TT_SCRIPT: __dirname.replace(/\\/g, "/") };
  const available = (cmd) => !spawnSync(cmd, ["--version"], { encoding: "utf8" }).error;
  const gates = [];
  if (available(shell)) {
    gates.push({ name: "shell", run(version) {
      const script = `PACKAGE_DIR="$TT_PACKAGE"\nSCRIPT_DIR="$TT_SCRIPT"\nnode() { if [ "$1" = -v ]; then printf '%s\\n' "$TT_VERSION"; else "$TT_REAL_NODE" "$@"; fi; }\nfail() { printf '%s\\n' "$1" >&2; exit 1; }\nlog() { printf '%s\\n' "$1"; }\n${shSource}\nprintf 'INSTALLATION WOULD BEGIN\\n'`;
      return spawnSync(shell, ["-c", script], { encoding: "utf8", env: { ...env, TT_VERSION: version } });
    } });
  }
  if (available(powershell)) {
    gates.push({ name: "PowerShell", run(version) {
      const script = `$ErrorActionPreference='Stop'\n$PackageDir=$env:TT_PACKAGE\n$ScriptDir=$env:TT_SCRIPT\nfunction Invoke-InstallerNode { param([string[]]$NodeArguments) if ($NodeArguments[0] -eq '-v') { $env:TT_VERSION } else { & $env:TT_REAL_NODE @NodeArguments } }\nfunction Fail { param($Message) throw $Message }\nfunction Write-Log { param($Message) Write-Output $Message }\n${psSource}\nWrite-Output 'INSTALLATION WOULD BEGIN'`;
      return spawnSync(powershell, ["-NoProfile", "-NonInteractive", "-Command", script], { encoding: "utf8", env: { ...env, TT_VERSION: version } });
    } });
  }
  assert.ok(gates.length > 0, "a native shell is required for installer gate tests");
  for (const gate of gates) {
    for (const version of ["v22.0.0", "v23.1.0", "v24.0.0"]) {
      const result = gate.run(version);
      assert.equal(result.status, 0, `${gate.name} ${version}: ${result.stderr}`);
      assert.match(result.stdout, /INSTALLATION WOULD BEGIN/);
    }
    for (const version of ["v21.99.99", "v25.0.0", "v24.0.0-rc.1"]) {
      const result = gate.run(version);
      assert.notEqual(result.status, 0, `${gate.name} ${version}`);
      assert.match(result.stderr, /does not satisfy.*engines\.node/);
      assert.doesNotMatch(result.stdout, /INSTALLATION WOULD BEGIN/);
    }
  }
});

test("the version validator is included in the release package", () => {
  const files = require("../package.json").files;
  assert.ok(files.includes("scripts/check-node-engine.js"));
  assert.ok(fs.existsSync(path.join(packageRoot, "scripts", "check-node-engine.js")));
});
