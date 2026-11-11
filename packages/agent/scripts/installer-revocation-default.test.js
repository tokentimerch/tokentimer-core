"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

function section(text, start, end) {
  const from = text.indexOf(start);
  const to = text.indexOf(end, from);
  assert.ok(from >= 0 && to > from, "installer configuration section must exist");
  return text.slice(from, to);
}

function temporaryDirectory(t) {
  const root = fs.realpathSync(os.tmpdir());
  const dir = fs.mkdtempSync(path.join(root, "tt-installer-revocation-"));
  t.after(() => {
    const relative = path.relative(root, fs.realpathSync(dir));
    assert.ok(relative && !relative.startsWith("..") && !path.isAbsolute(relative));
    fs.rmSync(dir, { recursive: true, force: true });
  });
  return dir;
}

const gitBash = "C:\\Program Files\\Git\\bin\\bash.exe";
// skip-reason: platform - the POSIX installer needs a shell on Windows.
test("Linux installer writes the requested default only to a new config", { skip: process.platform === "win32" && !fs.existsSync(gitBash) }, (t) => {
  const source = fs.readFileSync(path.join(__dirname, "install-agent.sh"), "utf8");
  const code = section(source, 'if [ -f "$CONFIG_PATH" ] && [ "$DRY_RUN" -eq 0 ]; then', "# --------------------------------------- bootstrap token");
  const dir = temporaryDirectory(t);
  const target = path.join(dir, "config.json");
  const shellTarget = process.platform === "win32" ? `/${target[0].toLowerCase()}${target.slice(2).replaceAll("\\", "/")}` : target;
  const env = { ...process.env, CONFIG_PATH: shellTarget, API_URL: "https://cp.example.test", WORKSPACE_ID: "workspace", CA_BUNDLE_DEST: "", ALLOW_INSECURE_LOCAL_HTTP: "0", DRY_RUN: "0" };
  const run = () => spawnSync(process.platform === "win32" ? gitBash : "sh", ["-c", `set -eu\nlog() { :; }\nfail() { exit 1; }\n${code}`], { encoding: "utf8", env });
  const first = run();
  assert.equal(first.status, 0, first.stderr);
  assert.deepEqual(JSON.parse(fs.readFileSync(target)).observedRevocation, { enabled: true, allowedOrigins: [] });
  fs.writeFileSync(target, '{"existing":true}');
  const second = run();
  assert.equal(second.status, 0, second.stderr);
  assert.deepEqual(JSON.parse(fs.readFileSync(target)), { existing: true });
  fs.unlinkSync(target);
  env.CA_BUNDLE_DEST = "/tmp/ca.pem";
  env.ALLOW_INSECURE_LOCAL_HTTP = "1";
  const withOptions = run();
  assert.equal(withOptions.status, 0, withOptions.stderr);
  const generated = JSON.parse(fs.readFileSync(target));
  assert.equal(generated.caBundlePath, "/tmp/ca.pem");
  assert.equal(generated.allowInsecureLocalHttp, true);
  assert.deepEqual(generated.observedRevocation, { enabled: true, allowedOrigins: [] });
});

// skip-reason: platform - the Windows installer needs Windows PowerShell.
test("Windows installer writes the requested default only to a new config", { skip: process.platform !== "win32" }, (t) => {
  const source = fs.readFileSync(path.join(__dirname, "install-agent.ps1"), "utf8");
  const code = section(source, 'if (-not $script:DryRun -and (Test-Path -LiteralPath $configPath))', "# --------------------------------------- bootstrap token");
  const dir = temporaryDirectory(t);
  const target = path.join(dir, "config.json");
  const script = `$ErrorActionPreference='Stop'\n$configPath=$env:TT_TEST_CONFIG_PATH\n$caBundleDest=$env:TT_TEST_CA_DEST\n$script:DryRun=$false\n$script:ApiUrl='https://cp.example.test'\n$script:WorkspaceId='workspace'\n$script:AllowInsecureLocalHttp=($env:TT_TEST_ALLOW_HTTP -eq '1')\nfunction Write-Log { param($Message) }\nfunction Invoke-Step { param($Message, $Action) & $Action }\nfunction Invoke-PlatformAcl { param($TargetPath,$Kind,[switch]$IncludeAdministrators) if (-not $IncludeAdministrators -or $TargetPath -ne $configPath) { throw 'wrong ACL target' }; Write-Output 'operator ACL applied' }\nfunction Fail { param($Message) throw $Message }\n${code}`;
  const env = { ...process.env, TT_TEST_CONFIG_PATH: target, TT_TEST_CA_DEST: "", TT_TEST_ALLOW_HTTP: "0" };
  const run = () => spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(script, "utf16le").toString("base64")], { encoding: "utf8", env });
  const first = run();
  assert.equal(first.status, 0, first.stderr);
  assert.deepEqual(JSON.parse(fs.readFileSync(target)).observedRevocation, { enabled: true, allowedOrigins: [] });
  fs.writeFileSync(target, '{"existing":true}');
  const second = run();
  assert.equal(second.status, 0, second.stderr);
  assert.match(second.stdout, /operator ACL applied/);
  assert.deepEqual(JSON.parse(fs.readFileSync(target)), { existing: true });
  fs.unlinkSync(target);
  env.TT_TEST_CA_DEST = "C:\\ProgramData\\TokenTimerAgent\\state\\ca-bundle.pem";
  env.TT_TEST_ALLOW_HTTP = "1";
  const withOptions = run();
  assert.equal(withOptions.status, 0, withOptions.stderr);
  const generated = JSON.parse(fs.readFileSync(target));
  assert.equal(generated.caBundlePath, env.TT_TEST_CA_DEST);
  assert.equal(generated.allowInsecureLocalHttp, true);
  assert.deepEqual(generated.observedRevocation, { enabled: true, allowedOrigins: [] });
});
