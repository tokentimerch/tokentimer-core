"use strict";
/* Supporting installer source-gate check called by windows-host.test.js. Parses and executes only
 * the real build-floor AST with explicit build inputs; it never invokes the installer, creates
 * SCM services or claims those Windows versions were run.
 */
const assert = require("node:assert/strict");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

function qualifyInstallerBuildFloor() {
  assert.equal(process.platform, "win32");
  const installer = path.resolve(__dirname, "../install-agent.ps1").replace(/'/g, "''");
  const env = { ...process.env };
  for (const name of Object.keys(env)) if (name.toLowerCase() === "psmodulepath") delete env[name];
  for (const build of [0, 9600, 14392, 14393, 17763, 20348, 26100]) {
    // Parse the actual production source and execute only its existing Fail
    // function, constant assignment and build gate. The installer is never
    // dot-sourced or invoked, so this cannot install a service or copy files.
    const script = `$ErrorActionPreference='Stop'; $tokens=$null; $errors=$null; $ast=[Management.Automation.Language.Parser]::ParseFile('${installer}',[ref]$tokens,[ref]$errors); if($errors.Count){throw 'Installer source parse failed'}; $fail=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Fail'},$true)); $floor=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$MinimumSupportedBuild'},$true)); $gate=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.IfStatementAst] -and $n.Clauses[0].Item1.Extent.Text -eq '$osBuild -lt $MinimumSupportedBuild'},$true)); if($fail.Count -ne 1 -or $floor.Count -ne 1 -or $gate.Count -ne 1){throw 'Exact production build gate not found'}; . ([scriptblock]::Create($fail[0].Extent.Text)); . ([scriptblock]::Create($floor[0].Extent.Text)); if($MinimumSupportedBuild -ne 14393){throw 'Advertised floor and fixture diverged'}; $osBuild=${build}; . ([scriptblock]::Create($gate[0].Extent.Text)); Write-Output 'BUILD_GATE_ACCEPTED'`;
    const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], { env, encoding: "utf8", timeout: 15000 });
    assert.ifError(result.error);
    if (build < 14393) {
      assert.equal(result.status, 1, `production gate must refuse build ${build}`);
      assert.match(result.stderr, new RegExp(`unsupported Windows build ${build}\\b`));
      assert.doesNotMatch(result.stdout, /BUILD_GATE_ACCEPTED/);
    } else {
      assert.equal(result.status, 0, "actual production floor must accept supported numeric boundary");
      assert.equal(result.stdout.trim(), "BUILD_GATE_ACCEPTED");
    }
  }
  return { sourceGuardCases: 7, unsupportedOperatingSystemBooted: false, installerMutationPerformed: false };
}
module.exports = { qualifyInstallerBuildFloor };
if (require.main === module) {
  try { console.log(JSON.stringify(qualifyInstallerBuildFloor())); }
  catch { console.error("Production installer build-floor fixture failed"); process.exitCode = 1; }
}
