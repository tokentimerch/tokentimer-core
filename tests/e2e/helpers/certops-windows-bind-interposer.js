"use strict";
/** Deterministic, disposable-service-only duplicate HTTP.sys binding fault.
 * Real netsh receives the original candidate argv. No store or key is changed.
 * Unknown process/registry/output ownership preserves the durable guard. */
const assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path"), crypto = require("node:crypto");
const installed = require("./certops-windows-installed-paths");
const observer = require("./certops-windows-stop-observer-process");
const PREFIX = ".bind-failure-interposer-";
const active = new Set();
const SOURCES = ["tests/e2e/helpers/certops-windows-bind-interposer.js", "tests/e2e/helpers/certops-windows-bind-interposer.cs", "tests/e2e/helpers/certops-windows-bind-interposer-build.ps1", "tests/e2e/helpers/certops-windows-contained-process.ps1", "tests/e2e/helpers/certops-windows-stop-observer-process.js", "tests/e2e/helpers/certops-windows-stop-observer.js", "tests/e2e/helpers/certops-windows-stop-observer.ps1"];
const sha = bytes => crypto.createHash("sha256").update(bytes).digest("hex");
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const ENVIRONMENT_COMPARE = "function Same-Environment($left,$right){$left=@($left);$right=@($right);if($left.Count-ne$right.Count){return $false};for($i=0;$i-lt$left.Count;$i++){if($left[$i]-isnot[string]-or$right[$i]-isnot[string]-or![string]::Equals($left[$i],$right[$i],[StringComparison]::Ordinal)){return $false}};return $true};";
function launcherSource(source, program) {
  const matches = [...source.matchAll(/Add-Type\s+-TypeDefinition\s+@'\r?\n([\s\S]*?)\r?\n'@/g)];
  assert.equal(matches.length, 1, "One reviewed native retained-job type required");
  return matches[0][1] + "\n" + program;
}
function verifyNativeReceipt(p, { jobId, selector, predecessor, candidate }) {
  assert.deepEqual(Object.keys(p).sort(), ["jobId", "selector", "candidateThumbprint", "predecessorThumbprint", "candidateFingerprintSha256", "predecessorFingerprintSha256", "seedExitCode", "forwardedExitCode", "nativeErrorCode", "originalArgv", "originalArgvSha256", "systemNetshSha256", "nativeChildrenDrained", "captureOverflow", "drainFailure", "certificateStoreModified"].sort());
  assert.equal(p.jobId, jobId); assert.equal(p.selector, selector);
  assert.match(p.jobId, UUID);
  assert.match(p.selector, /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?:[1-9][0-9]{0,4}$/);
  assert.ok(p.selector.length <= 259 && Number(p.selector.split(":").at(-1)) <= 65535);
  for (const value of [p.predecessorThumbprint, p.candidateThumbprint]) assert.match(value, /^[A-F0-9]{40}$/);
  assert.notEqual(p.predecessorThumbprint, p.candidateThumbprint);
  assert.equal(p.predecessorThumbprint, predecessor); assert.equal(p.candidateThumbprint, candidate);
  assert.equal(p.seedExitCode, 0); assert.ok(Number.isInteger(p.forwardedExitCode) && p.forwardedExitCode > 0 && p.forwardedExitCode !== 197);
  assert.equal(p.nativeErrorCode, 183); assert.equal(p.nativeChildrenDrained, true);
  for (const flag of ["captureOverflow", "drainFailure", "certificateStoreModified"]) assert.equal(p[flag], false);
  for (const field of ["originalArgvSha256", "systemNetshSha256"]) assert.match(p[field], /^[a-f0-9]{64}$/);
  for (const field of ["candidateFingerprintSha256", "predecessorFingerprintSha256"]) assert.match(p[field], /^[a-f0-9]{64}$/);
  assert.ok(Array.isArray(p.originalArgv) && p.originalArgv.length >= 7 && p.originalArgv.length <= 32);
  assert.deepEqual(p.originalArgv.slice(0, 3), ["http", "add", "sslcert"]);
  for (const value of p.originalArgv) assert.ok(typeof value === "string" && value.length <= 4096 && !/[\x00-\x1f]/.test(value));
  const parameterNames = p.originalArgv.slice(3).map(value => { assert.match(value, /^[a-zA-Z][a-zA-Z0-9]*=.+$/); return value.slice(0, value.indexOf("=")).toLowerCase(); });
  assert.equal(new Set(parameterNames).size, parameterNames.length);
  const appIds = p.originalArgv.filter(arg => /^appid=/i.test(arg));
  assert.equal(appIds.length, 1); assert.match(appIds[0], /^appid=\{[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\}$/i);
  for (const [key, expected] of [["hostnameport", selector], ["certhash", candidate], ["certstorename", "My"]]) {
    const matches = p.originalArgv.filter(arg => arg.toLowerCase().startsWith(key + "="));
    assert.equal(matches.length, 1); assert.equal(matches[0].slice(key.length + 1).toLowerCase(), expected.toLowerCase());
  }
  assert.equal(sha(JSON.stringify(p.originalArgv)), p.originalArgvSha256);
  return true;
}
function identityScript(pid) {
  assert.ok(Number.isSafeInteger(pid) && pid > 0);
  return `$p=Get-CimInstance Win32_Process -Filter 'ProcessId=${pid}';if(!$p-or!$p.ExecutablePath-or!$p.CommandLine){throw 'Original process required'};$h=[Security.Cryptography.SHA256]::Create();try{$d=([BitConverter]::ToString($h.ComputeHash([Text.Encoding]::UTF8.GetBytes($p.CommandLine)))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()};@{pid=[int]$p.ProcessId;parentPid=[int]$p.ParentProcessId;createdAt=$p.CreationDate.ToUniversalTime().ToString('o');executable=$p.ExecutablePath;commandSha256=$d}|ConvertTo-Json -Compress`;
}
async function start(c) {
  assert.equal(process.platform, "win32"); assert.equal(process.env.CERTOPS_WINDOWS_BIND_FAILURE_REQUIRED, "1");
  installed.assertOwnedRoot(c.receipt);
  const root = c.receipt.root, directory = path.join(root, PREFIX + crypto.randomBytes(16).toString("hex"));
  assertCleanupSafe(root);
  const expected = { host: path.join(root, "app/bin/tokentimer-agent-host-amd64.exe"), node: process.execPath, entry: path.join(root, "app/bin/tokentimer-agent.js"), config: c.configDir };
  const observe = () => { const result = JSON.parse(c.ps(installed.observationScript())); installed.validateObservation(result, expected); return result; };
  const original = observe();
  fs.mkdirSync(directory, { mode: 0o700 });
  active.add(root);
  const directoryId = fs.lstatSync(directory, { bigint: true }), pins = new Map();
  const guard = { cleanupCompleted: false, async emergencyDrain() { /* SCM cleanup must stop the owned service first; guard remains. */ } };
  c.ownedShadows.push(guard);
  const aclPath = Buffer.from(directory).toString("base64");
  c.ps(`$p=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${aclPath}'));$d=Get-Item -LiteralPath $p;if(!$d.PSIsContainer-or($d.Attributes-band[IO.FileAttributes]::ReparsePoint)-or@(Get-ChildItem -LiteralPath $p -Force).Count){throw 'Fresh empty native directory required'};$acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false);$acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-18'));foreach($sid in @('S-1-5-18','S-1-5-32-544')){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))};Set-Acl -LiteralPath $p -AclObject $acl`);
  function check() {
    installed.assertOwnedRoot(c.receipt); const stat = fs.lstatSync(directory, { bigint: true });
    assert.ok(stat.isDirectory() && !stat.isSymbolicLink() && stat.dev === directoryId.dev && stat.ino === directoryId.ino);
    for (const [name, before] of pins) { const file = path.join(directory, name), now = fs.lstatSync(file, { bigint: true }); assert.ok(now.isFile() && !now.isSymbolicLink() && now.dev === before.dev && now.ino === before.ino && sha(fs.readFileSync(file)) === before.sha); }
  }
  const pin = name => { const file = path.join(directory, name), stat = fs.lstatSync(file, { bigint: true }); pins.set(name, { dev: stat.dev, ino: stat.ino, sha: sha(fs.readFileSync(file)) }); };
  const write = (name, bytes) => { check(); fs.writeFileSync(path.join(directory, name), bytes, { flag: "wx", mode: 0o600 }); pin(name); };
  const powershell = path.join(process.env.SystemRoot, "System32/WindowsPowerShell/v1.0/powershell.exe");
  async function stop() {
    check(); const before = observe();
    const watcher = await observer.startStopObservation({ workDir: root, powershell, ownerIdentity: JSON.parse(c.ps(identityScript(process.pid))), hostIdentity: JSON.parse(c.ps(identityScript(before.hostId))), nodeIdentity: JSON.parse(c.ps(identityScript(before.childId))), commandRoots: [expected.host, expected.entry, c.configDir], onCreated: value => c.ownedShadows.push({ emergencyDrain: () => value.waitForClose() }) });
    c.run("sc.exe", ["stop", "TokenTimerAgent"]); const result = await watcher.waitForCompletion();
    assert.equal(result.rootExitCode, 0); assert.equal(result.nodeExitCode, 0);
    assert.equal(c.ps("[string](Get-Service TokenTimerAgent).Status"), "Stopped");
  }
  const contextPath = path.join(directory, "context.json"), netsh = path.join(process.env.SystemRoot, "System32/netsh.exe");
  const context = { netsh, netshSha256: sha(fs.readFileSync(netsh)), selector: `${c.domain}:${c.port}`, predecessor: c.thumbprint, appId: crypto.randomUUID(), issuedDirectory: path.join(c.configDir, "windows-cert-store/issued-containers") };
  write("context.json", JSON.stringify(context));
  write("combined.cs", launcherSource(fs.readFileSync(path.join(__dirname, "certops-windows-contained-process.ps1"), "utf8"), fs.readFileSync(path.join(__dirname, "certops-windows-bind-interposer.cs"), "utf8")));
  c.run(powershell, ["-NoProfile", "-NonInteractive", "-File", path.join(__dirname, "certops-windows-bind-interposer-build.ps1"), "-Directory", directory]);
  pin("netsh.exe");
  const registry = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\TokenTimerAgent";
  const encoded = Buffer.from(JSON.stringify({ directory, contextPath, original: original.environment })).toString("base64");
  await stop();
  const applied = JSON.parse(c.ps(`${ENVIRONMENT_COMPARE}$c=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${encoded}'))|ConvertFrom-Json;$k=Get-Item '${registry}';if($k.GetValueKind('Environment')-ne[Microsoft.Win32.RegistryValueKind]::MultiString-or!(Same-Environment @($k.GetValue('Environment')) @($c.original))){throw 'Original service environment changed'};$path=@($c.original|Where-Object{$_-match'^(?i)PATH='});if($path.Count-gt 1){throw 'Ambiguous PATH'};$base=if($path.Count){$path[0].Substring(5)}else{[Environment]::GetEnvironmentVariable('Path','Machine')};$v=@($c.original|Where-Object{$_-notmatch'^(?i)(PATH|CERTOPS_BIND_INTERPOSER_CONTEXT)='})+@('PATH='+$c.directory+';'+$base,'CERTOPS_BIND_INTERPOSER_CONTEXT='+$c.contextPath);Set-ItemProperty -LiteralPath '${registry}' -Name Environment -Value ([string[]]$v);if(!(Same-Environment @((Get-Item '${registry}').GetValue('Environment')) @($v))){throw 'Applied service environment mismatch'};ConvertTo-Json -InputObject @($v) -Compress`));
  write("registry-applied.json", JSON.stringify(applied));
  c.run("sc.exe", ["start", "TokenTimerAgent"]); await c.waitUntil(() => { try { return observe(); } catch { return false; } });
  let admitted;
  return {
    admit(jobId) { assert.equal(admitted, undefined); assert.match(jobId, UUID); write("admission.json", JSON.stringify({ jobId })); admitted = jobId; },
    receipt(candidate) { check(); const file = path.join(directory, "native-result.json"); assert.ok(fs.statSync(file).size <= 65536); const result = JSON.parse(fs.readFileSync(file)); verifyNativeReceipt(result, { jobId: admitted, selector: context.selector, predecessor: context.predecessor, candidate }); assert.equal(result.systemNetshSha256, context.netshSha256); pin("native-result.json"); const consumed = JSON.parse(fs.readFileSync(path.join(directory, "consumed.json"))); assert.deepEqual(Object.keys(consumed).sort(), ["candidate", "jobId"]); assert.equal(consumed.jobId, admitted); assert.equal(consumed.candidate.toUpperCase(), candidate); pin("consumed.json"); return result; },
    async restore() {
      check(); await stop(); const restore = Buffer.from(JSON.stringify({ applied, original: original.environment })).toString("base64");
      c.ps(`${ENVIRONMENT_COMPARE}$c=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${restore}'))|ConvertFrom-Json;$k=Get-Item '${registry}';if($k.GetValueKind('Environment')-ne[Microsoft.Win32.RegistryValueKind]::MultiString-or!(Same-Environment @($k.GetValue('Environment')) @($c.applied))){throw 'Changed service environment preserved'};Set-ItemProperty -LiteralPath '${registry}' -Name Environment -Value ([string[]]$c.original);if(!(Same-Environment @((Get-Item '${registry}').GetValue('Environment')) @($c.original))){throw 'Original service environment not restored'}`);
      check(); assert.ok(fs.readdirSync(directory).every(name => pins.has(name)), "Unowned or undrained capture preserves fixture");
      for (const name of fs.readdirSync(directory)) fs.unlinkSync(path.join(directory, name)); fs.rmdirSync(directory); guard.cleanupCompleted = true; active.delete(root);
      c.run("sc.exe", ["start", "TokenTimerAgent"]); await c.waitUntil(() => { try { return observe(); } catch { return false; } });
    },
  };
}
function assertCleanupSafe(root) { assert.equal(active.has(path.resolve(root)), false, "Unrestored native service environment preserves fixture"); assert.ok(!fs.readdirSync(root).some(name => name.startsWith(PREFIX)), "Durable interposer guard preserves fixture"); }
module.exports = { start, SOURCES, PREFIX, UUID, ENVIRONMENT_COMPARE, launcherSource, verifyNativeReceipt, assertCleanupSafe };
