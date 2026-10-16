"use strict";
/** Owned hosted-image PostgreSQL prerequisite for the separate manual lane.
 * An unknown start never grants stop authority. Cleanup stops only the captured
 * cluster and preserves its private files; it never deletes an adopted root. */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto"),
  { spawnSync } = require("node:child_process");
const sha = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
function identity(file) {
  const s = fs.lstatSync(file, { bigint: true });
  assert.ok(!s.isSymbolicLink() && s.ino > 0n);
  return {
    dev: String(s.dev),
    ino: String(s.ino),
    birth: String(s.birthtimeNs),
  };
}
function run(exe, args) {
  const r = spawnSync(exe, args, {
    encoding: "utf8",
    windowsHide: true,
    timeout: 180000,
    maxBuffer: 65536,
  });
  assert.ifError(r.error);
  assert.equal(
    r.status,
    0,
    "Owned PostgreSQL prerequisite failed; output withheld",
  );
  return r.stdout.trim();
}
function native(script) {
  const env = { ...process.env };
  for (const key of Object.keys(env))
    if (key.toLowerCase() === "psmodulepath") delete env[key];
  const r = spawnSync(
    "powershell.exe",
    [
      "-NoProfile",
      "-NonInteractive",
      "-EncodedCommand",
      Buffer.from(
        "$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);" +
          script,
        "utf16le",
      ).toString("base64"),
    ],
    {
      env,
      encoding: "utf8",
      windowsHide: true,
      timeout: 180000,
      maxBuffer: 65536,
    },
  );
  assert.ifError(r.error);
  assert.equal(
    r.status,
    0,
    "Owned PostgreSQL identity/stop failed; private cluster preserved",
  );
  return r.stdout.trim();
}
function validate(r, file) {
  const observed =
    require("../tests/e2e/helpers/certops-windows-stop-offline").readPrivate(
      file,
      16384,
    );
  assert.deepEqual(JSON.parse(observed.bytes.toString("utf8")), r);
  assert.equal(r.schemaVersion, 1);
  assert.match(r.nonce, /^[a-f0-9]{32}$/);
  assert.equal(
    r.root,
    path.join(
      path.resolve(process.env.RUNNER_TEMP),
      `certops-stop-offline-pg-${r.nonce}`,
    ),
  );
  assert.equal(file, path.join(r.root, "owner.json"));
  assert.equal(r.data, path.join(r.root, "data"));
  assert.deepEqual(identity(r.root), r.rootIdentity);
  assert.deepEqual(identity(r.data), r.dataIdentity);
  assert.equal(process.env.CERTOPS_STOP_PG_RECEIPT_SHA256, sha(observed.bytes));
  assert.equal(
    process.env.CERTOPS_STOP_PG_RECEIPT_IDENTITY,
    sha(Buffer.from(JSON.stringify(identity(file)))),
  );
}
function validateArguments(argv, data) {
  assert.equal(argv.length, 7);
  assert.deepEqual(argv.slice(3), ["-h", "127.0.0.1", "-p", "55432"]);
  assert.equal(argv[1], "-D");
  assert.equal(
    path.win32.normalize(argv[2]).toLowerCase(),
    path.win32.normalize(data).toLowerCase(),
  );
}
function setup() {
  assert.equal(process.platform, "win32");
  assert.equal(process.env.GITHUB_ACTIONS, "true");
  assert.equal(process.env.RUNNER_ENVIRONMENT, "github-hosted");
  const nonce = crypto.randomBytes(16).toString("hex"),
    root = path.join(
      path.resolve(process.env.RUNNER_TEMP),
      `certops-stop-offline-pg-${nonce}`,
    ),
    data = path.join(root, "data");
  assert.equal(fs.existsSync(root), false);
  fs.mkdirSync(root);
  fs.mkdirSync(data);
  const r = {
    schemaVersion: 1,
    nonce,
    root,
    data,
    rootIdentity: identity(root),
    dataIdentity: identity(data),
    bin: path.resolve(process.env.PGBIN),
  };
  // No cleanup environment is published until initdb/start and independent SQL,
  // listener, command-line and native process observations all succeed.
  const exe = (name) => path.join(r.bin, `${name}.exe`);
  assert.equal(
    native(
      "[string](@(Get-NetTCPConnection -LocalPort 55432 -State Listen -ErrorAction SilentlyContinue).Count)",
    ),
    "0",
  );
  assert.deepEqual(identity(root), r.rootIdentity);
  assert.deepEqual(identity(data), r.dataIdentity);
  run(exe("initdb"), [
    "-D",
    data,
    "-U",
    "postgres",
    "-A",
    "trust",
    "--encoding=UTF8",
  ]);
  assert.deepEqual(identity(root), r.rootIdentity);
  assert.deepEqual(identity(data), r.dataIdentity);
  run(exe("pg_ctl"), [
    "-D",
    data,
    "-l",
    path.join(root, "private-pg.log"),
    "-o",
    "-h 127.0.0.1 -p 55432",
    "-w",
    "start",
  ]);
  assert.equal(
    path.win32
      .normalize(
        run(exe("psql"), [
          "-h",
          "127.0.0.1",
          "-p",
          "55432",
          "-U",
          "postgres",
          "-d",
          "postgres",
          "-Atc",
          "SHOW data_directory",
        ]),
      )
      .toLowerCase(),
    path.win32.normalize(data).toLowerCase(),
  );
  r.pidFileSha256 = sha(fs.readFileSync(path.join(data, "postmaster.pid")));
  const pid = Number(
    fs
      .readFileSync(path.join(data, "postmaster.pid"), "utf8")
      .split(/\r?\n/)[0],
  );
  assert.ok(Number.isSafeInteger(pid) && pid > 0);
  r.process = JSON.parse(
    native(
      `$p=Get-CimInstance Win32_Process -Filter 'ProcessId=${pid}';$l=@(Get-NetTCPConnection -LocalPort 55432 -State Listen);if(!$p-or$l.Count-ne 1-or$l[0].OwningProcess-ne$p.ProcessId){throw 'Cluster listener ownership mismatch'};@{pid=[int]$p.ProcessId;created=$p.CreationDate.ToUniversalTime().ToString('o');exe=$p.ExecutablePath;command=$p.CommandLine}|ConvertTo-Json -Compress`,
    ),
  );
  assert.equal(
    path.win32.normalize(r.process.exe).toLowerCase(),
    path.win32.normalize(exe("postgres")).toLowerCase(),
  );
  // pg_ctl's generated exact command line is independently parsed, not substring-adopted.
  const prelude =
    require("../tests/e2e/helpers/certops-windows-installed-paths")
      .observationScript()
      .split("$s=Get-CimInstance Win32_Service")[0];
  assert.equal(
    typeof prelude,
    "string",
    "Native argv parser contract required",
  );
  const argv = JSON.parse(
    native(
      prelude +
        `$a=[CertOpsPathArgv]::Parse('${r.process.command.replaceAll("'", "''")}');ConvertTo-Json -InputObject @($a) -Compress`,
    ),
  );
  validateArguments(argv, data);
  run(exe("createdb"), [
    "-h",
    "127.0.0.1",
    "-p",
    "55432",
    "-U",
    "postgres",
    "certops_qualification",
  ]);
  const file = path.join(root, "owner.json");
  fs.writeFileSync(file, JSON.stringify(r), { flag: "wx" });
  fs.appendFileSync(
    process.env.GITHUB_ENV,
    `CERTOPS_STOP_PG_RECEIPT=${file}\nCERTOPS_STOP_PG_RECEIPT_SHA256=${sha(fs.readFileSync(file))}\nCERTOPS_STOP_PG_RECEIPT_IDENTITY=${sha(Buffer.from(JSON.stringify(identity(file))))}\n`,
  );
}
function cleanupScript(r) {
  const encoded = Buffer.from(JSON.stringify(r)).toString("base64");
  // Retain the original process object through pg_ctl's graceful request.
  // Release the validated PID-file lock before that request: PostgreSQL must
  // update PM_STATUS_STOPPING and unlink its lock file during normal shutdown.
  // This is bounded owned-fixture admission, not a machine-wide transaction
  // against a privileged actor replacing private paths after the final check.
  // Identity mismatch refuses before signalling; no PID/tree kill fallback.
  return `$r=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${encoded}'))|ConvertFrom-Json;
$pidFile=[IO.File]::Open((Join-Path $r.data 'postmaster.pid'),[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);
try{if($pidFile.Length-le 0-or$pidFile.Length-gt 8192){throw 'Owned cluster PID receipt invalid'};
$hash=[Security.Cryptography.SHA256]::Create();
try{$actual=([BitConverter]::ToString($hash.ComputeHash($pidFile))).Replace('-','').ToLowerInvariant();
if($actual-cne$r.pidFileSha256){throw 'Owned cluster PID receipt changed'}}finally{$hash.Dispose()};
$p=Get-CimInstance Win32_Process -Filter ('ProcessId='+$r.process.pid);
if(!$p-or$p.CreationDate.ToUniversalTime().ToString('o')-cne$r.process.created-or$p.ExecutablePath-ine$r.process.exe-or$p.CommandLine-cne$r.process.command){throw 'Original cluster identity changed'};
$held=[Diagnostics.Process]::GetProcessById($r.process.pid);
$handle=$held.Handle;
try{$again=Get-CimInstance Win32_Process -Filter ('ProcessId='+$r.process.pid);
if(!$again-or$again.CreationDate.ToUniversalTime().ToString('o')-cne$r.process.created){throw 'Cluster changed before stop'};
$pidFile.Dispose();
$pidFile=$null;
& (Join-Path $r.bin 'pg_ctl.exe') -D $r.data -m fast -w stop|Out-Null;
if($LASTEXITCODE-ne 0){throw 'Owned cluster stop failed'};
if(!$held.WaitForExit(30000)){throw 'Owned cluster still live'}}finally{$held.Dispose()}}finally{if($null-ne$pidFile){$pidFile.Dispose()}}`;
}
function cleanup() {
  if (!process.env.CERTOPS_STOP_PG_RECEIPT) return;
  const file = process.env.CERTOPS_STOP_PG_RECEIPT,
    r = JSON.parse(
      require("../tests/e2e/helpers/certops-windows-stop-offline")
        .readPrivate(file, 16384)
        .bytes.toString("utf8"),
    );
  validate(r, file);
  native(cleanupScript(r));
}
if (require.main === module) {
  try {
    const mode = process.argv[2];
    assert.ok(["setup", "cleanup"].includes(mode));
    if (mode === "setup") setup();
    else cleanup();
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
module.exports = { identity, validate, validateArguments, cleanupScript };
