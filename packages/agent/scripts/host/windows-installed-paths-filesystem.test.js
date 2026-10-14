"use strict";
/** Supporting Windows PowerShell filesystem-only regression. Executes only
 * AST-selected staging/detection/uninstall file operations on owned public text
 * fixtures. Never invokes service, registration, CA or certificate operations. */
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  os = require("node:os"),
  path = require("node:path");
const { spawnSync } = require("node:child_process");
test(
  "actual installer filesystem branches preserve literal brackets and wildcard siblings",
  // skip-reason: no-host
  { skip: process.platform !== "win32" },
  () => {
    const parent = fs.mkdtempSync(
      path.join(os.tmpdir(), "certops-installer-path-"),
    );
    const literal = path.join(parent, "Windows é [literal]"),
      sibling = path.join(parent, "Windows é l");
    try {
      fs.mkdirSync(literal);
      fs.mkdirSync(sibling);
      fs.writeFileSync(path.join(literal, "owned.txt"), "owned");
      fs.writeFileSync(path.join(sibling, "unrelated.txt"), "preserve");
      const installer = path.resolve(__dirname, "../install-agent.ps1"),
        q = (v) => v.replace(/'/g, "''");
      // Execute only the AST-extracted filesystem expression and uninstall block.
      // Never evaluate installer top-level code or service/registration commands.
      const script = `$ErrorActionPreference='Stop';
$t=$null;
$e=$null;
$ast=[Management.Automation.Language.Parser]::ParseFile('${q(installer)}',[ref]$t,[ref]$e);
if($e.Count){throw 'Installer parse failed'};
$AppDir='${q(literal)}';
$script:AppStaging=$AppDir+'.staging';
$create=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName()-ceq 'New-Item' -and $n.Extent.Text -like '*$script:AppStaging*'},$true));
if($create.Count-ne 1){throw 'Exact staging creation absent'};
$null=& ([scriptblock]::Create($create[0].Extent.Text));
if(!(Test-Path -LiteralPath $script:AppStaging -PathType Container)){throw 'Literal staging directory absent'};
Remove-Item -LiteralPath $script:AppStaging;
$assign=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -ceq '$script:IsUpgrade'},$true));
if($assign.Count-ne 1){throw 'Exact upgrade branch absent'};
if(!(& ([scriptblock]::Create($assign[0].Right.Extent.Text)))){throw 'Literal upgrade not detected'};
$remove=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName()-ceq 'Invoke-Step' -and $n.CommandElements.Count-eq 3 -and $n.CommandElements[1].Extent.Text-ceq '"Remove-Item -Recurse -Force $AppDir"'},$true));
if($remove.Count-ne 1){throw 'Exact filesystem uninstall block absent'};
& $remove[0].CommandElements[2].ScriptBlock.GetScriptBlock();
if(Test-Path -LiteralPath $AppDir){throw 'Literal app survived'};
'actual-filesystem-branches-pass'`;
      const result = spawnSync(
        "powershell.exe",
        [
          "-NoProfile",
          "-NonInteractive",
          "-EncodedCommand",
          Buffer.from(script, "utf16le").toString("base64"),
        ],
        { encoding: "utf8", timeout: 30000 },
      );
      assert.equal(result.status, 0, result.stderr);
      assert.match(result.stdout, /actual-filesystem-branches-pass/);
      assert.equal(fs.existsSync(literal), false);
      assert.equal(
        fs.readFileSync(path.join(sibling, "unrelated.txt"), "utf8"),
        "preserve",
      );
    } finally {
      fs.rmSync(parent, { recursive: true, force: true });
    }
  },
);
