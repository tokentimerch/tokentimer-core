"use strict";

// Narrow real-Windows check for the two changed native boundaries. No domain,
// CA, agent registration, trust-root installation, or persistent lab is used.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const https = require("node:https");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const SOURCE_SHA = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const OWNER = /^tt-core-delta-[a-f0-9]{24}$/;
const hash = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");

function parseArgs(argv) {
  const allowed = new Set(["archive", "archive-sha256", "source-sha", "out"]);
  const options = {};
  for (let i = 0; i < argv.length; i += 2) {
    const name = argv[i]?.replace(/^--/, "");
    assert.ok(argv[i]?.startsWith("--") && allowed.has(name) && argv[i + 1] && !argv[i + 1].startsWith("--") && !options[name], "Expected each --option once with a value");
    options[name] = argv[i + 1];
  }
  for (const name of allowed) assert.ok(options[name], "Missing --" + name);
  assert.match(options["source-sha"], SOURCE_SHA);
  assert.match(options["archive-sha256"], SHA256);
  return options;
}

function assertOwnedState(state, directory) {
  assert.match(state.owner || "", OWNER);
  assert.equal(state.site, state.owner);
  assert.equal(state.pool, state.owner);
  assert.equal(state.store, "TokenTimerSmoke" + state.owner.slice("tt-core-delta-".length));
  assert.equal(path.resolve(state.directory), path.resolve(directory));
  assert.ok(path.basename(directory).startsWith(state.owner + "-"));
  assert.ok(Number.isInteger(state.port) && state.port >= 1024 && state.port <= 65535);
  assert.ok(Array.isArray(state.certificates) && state.certificates.length <= 2);
  assert.equal(new Set(state.certificates.map((entry) => entry.kind)).size, state.certificates.length);
  for (const entry of state.certificates) {
    assert.ok(entry.kind === "old" || entry.kind === "new");
    assert.equal(entry.friendlyName, state.owner + "-" + entry.kind);
    assert.equal(entry.subject, "CN=" + state.owner + ".invalid");
    assert.match(entry.thumbprint || "", /^[A-F0-9]{40}$/);
    const certificate = new crypto.X509Certificate(Buffer.from(entry.publicDer, "base64"));
    assert.equal(certificate.fingerprint.replace(/:/g, ""), entry.thumbprint);
  }
  if (state.sanThumbprint !== undefined) assert.match(state.sanThumbprint, /^[A-F0-9]{40}$/);
}

function assertArchivePaths(entries, modes) {
  assert.ok(entries.length > 0 && entries.every((name) => name.startsWith("package/") && !name.split("/").includes("..") && !/[\\\u0000-\u001f]/.test(name)), "Unsafe archive paths");
  assert.ok(modes.length === entries.length && modes.every((line) => line[0] === "-" || line[0] === "d"), "Only regular archive files and directories are allowed");
}

function assertOwnedObservation(observation, expected) {
  assert.ok(observation, "Owned SAN-only certificate was not discovered");
  assert.equal(observation.fingerprintSha256, expected.fingerprint);
  assert.equal(observation.subject, null, "An empty native subject must be null");
  assert.equal(observation.keyPresent, false, "Public discovery fixture acquired a private key");
  assert.ok(observation.subjectAltNames.includes(expected.san), "SAN was lost at the Windows discovery boundary");
  assert.equal(observation.storeName, expected.store);
}

// Windows PowerShell uses the inbox IIS/PKI modules. The manifest contains
// public identities only and is updated after each owned resource is created.
const SETUP = String.raw`
$ErrorActionPreference='Stop'
Import-Module WebAdministration -ErrorAction Stop
Import-Module PKI -ErrorAction Stop
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if(-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'An elevated disposable Windows runner is required'}
$s=Get-Content -LiteralPath $env:TT_WINDOWS_SMOKE_MANIFEST -Raw | ConvertFrom-Json
function Save-State { [IO.File]::WriteAllText($env:TT_WINDOWS_SMOKE_MANIFEST,($s|ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false)) }
if(Test-Path ('IIS:\Sites\'+$s.site)){throw 'Site already exists'}
if(Test-Path ('IIS:\AppPools\'+$s.pool)){throw 'App pool already exists'}
if(Test-Path ('HKLM:\SOFTWARE\Microsoft\SystemCertificates\'+$s.store)){throw 'Certificate store already exists'}
if(@(Get-WebBinding | Where-Object {$_.bindingInformation -match (':'+$s.port+':')}).Count){throw 'IIS port is already configured'}
New-Item -ItemType Directory -Path (Join-Path $s.directory 'www') -ErrorAction Stop | Out-Null
[IO.File]::WriteAllText((Join-Path $s.directory 'www\index.html'),$s.owner,[Text.UTF8Encoding]::new($false))
foreach($kind in @('old','new')){
  $c=New-SelfSignedCertificate -DnsName ($s.owner+'.invalid') -CertStoreLocation 'Cert:\LocalMachine\My' -FriendlyName ($s.owner+'-'+$kind) -NotAfter (Get-Date).AddDays(1) -KeyAlgorithm RSA -KeyLength 2048 -Provider 'Microsoft Software Key Storage Provider' -KeyExportPolicy NonExportable -Type SSLServerAuthentication
  $entry=[PSCustomObject]@{kind=$kind;thumbprint=$c.Thumbprint;friendlyName=$c.FriendlyName;subject=$c.Subject;keyName=$null;publicDer=[Convert]::ToBase64String($c.RawData)}
  $s.certificates=@($s.certificates)+@($entry);Save-State
  $key=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c)
  try{if($key -isnot [Security.Cryptography.RSACng]){throw 'Expected a CNG key'};$entry.keyName=$key.Key.KeyName;Save-State}finally{if($key){$key.Dispose()};$c.Dispose()}
}
New-WebAppPool -Name $s.pool | Out-Null
$s.poolCreated=$true;Save-State
Set-ItemProperty ('IIS:\AppPools\'+$s.pool) -Name managedRuntimeVersion -Value ''
$acl=Get-Acl -LiteralPath (Join-Path $s.directory 'www')
$rule=[Security.AccessControl.FileSystemAccessRule]::new(('IIS AppPool\'+$s.pool),'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow')
$acl.AddAccessRule($rule)
Set-Acl -LiteralPath (Join-Path $s.directory 'www') -AclObject $acl
New-Website -Name $s.site -PhysicalPath (Join-Path $s.directory 'www') -ApplicationPool $s.pool -IPAddress '*' -Port $s.port -Ssl | Out-Null
$s.siteCreated=$true;Save-State
Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location $s.site -Filter 'system.webServer/security/authentication/anonymousAuthentication' -Name userName -Value ''
(Get-WebBinding -Name $s.site -Protocol https).AddSslCertificate($s.certificates[0].thumbprint,'My')
Start-Website -Name $s.site
$store=[Security.Cryptography.X509Certificates.X509Store]::new($s.store,[Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
try{
  $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
  $s.storeCreated=$true;Save-State
  $public=[Security.Cryptography.X509Certificates.X509Certificate2]::new((Join-Path $s.directory 'san-only.cer'))
  try{if($public.HasPrivateKey -or $public.Thumbprint -ne $s.sanThumbprint -or $public.Subject -ne ''){throw 'Expected the exact public SAN-only fixture'};$store.Add($public)}finally{$public.Dispose()}
}finally{$store.Close()}
@{identity=$identity.Name;osVersion=[Environment]::OSVersion.Version.ToString();language=(Get-UICulture).Name;site=$s.site;port=$s.port}|ConvertTo-Json -Compress
`;

const CLEANUP = String.raw`
$ErrorActionPreference='Stop'
Import-Module WebAdministration -ErrorAction Stop
Import-Module PKI -ErrorAction Stop
$s=Get-Content -LiteralPath $env:TT_WINDOWS_SMOKE_MANIFEST -Raw | ConvertFrom-Json
$errors=[Collections.Generic.List[string]]::new()
function Attempt([scriptblock]$body){try{& $body}catch{$errors.Add($_.Exception.Message)}}
Attempt {
  if($s.siteCreated -and (Test-Path ('IIS:\Sites\'+$s.site))){
    if(-not $s.allowIisRemoval){throw 'Site preserved because http.sys ownership could not be confirmed'}
    $site=Get-Item ('IIS:\Sites\'+$s.site)
    $bindings=@(Get-WebBinding -Name $s.site)
    if($site.physicalPath -ne (Join-Path $s.directory 'www') -or $site.applicationPool -ne $s.pool -or $bindings.Count -ne 1 -or $bindings[0].protocol -ne 'https' -or $bindings[0].bindingInformation -ne ('*:'+$s.port+':')){throw 'Owned IIS site identity changed; preserved'}
    Remove-Website -Name $s.site
    if(Test-Path ('IIS:\Sites\'+$s.site)){throw 'Owned site remains'}
  }
}
Attempt {
  if($s.poolCreated -and (Test-Path ('IIS:\AppPools\'+$s.pool))){
    if(@(Get-Website | Where-Object {$_.applicationPool -eq $s.pool}).Count -or @(Get-WebApplication | Where-Object {$_.applicationPool -eq $s.pool}).Count){throw 'App pool still has a consumer; preserved'}
    Remove-WebAppPool -Name $s.pool
    if(Test-Path ('IIS:\AppPools\'+$s.pool)){throw 'Owned app pool remains'}
  }
}
foreach($entry in @($s.certificates)){
  Attempt {
    if($entry.thumbprint -in @($s.protectedThumbprints)){throw 'Certificate preserved because a binding may still reference it'}
    $certPath='Cert:\LocalMachine\My\'+$entry.thumbprint
    if(Test-Path -LiteralPath $certPath){
      $c=Get-Item -LiteralPath $certPath
      $key=$null
      try{
        if($c.FriendlyName -ne $entry.friendlyName -or $c.Subject -ne $entry.subject -or [Convert]::ToBase64String($c.RawData) -ne $entry.publicDer){throw 'Certificate identity changed; preserved'}
        if($entry.keyName){$key=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c);if($key.Key.KeyName -ne $entry.keyName){throw 'Private key identity changed; preserved'}}
      }finally{if($key){$key.Dispose()};$c.Dispose()}
      Remove-Item -LiteralPath $certPath -DeleteKey
      if(Test-Path -LiteralPath $certPath){throw 'Owned certificate remains'}
    }
    if($entry.keyName){
      $provider=[Security.Cryptography.CngProvider]::new('Microsoft Software Key Storage Provider')
      if([Security.Cryptography.CngKey]::Exists($entry.keyName,$provider,[Security.Cryptography.CngKeyOpenOptions]::MachineKey)){throw 'Owned CNG key remains'}
    }
  }
}
Attempt {
  if($s.storeCreated){
    $registry='HKLM:\SOFTWARE\Microsoft\SystemCertificates\'+$s.store
    if(Test-Path -LiteralPath $registry){
      $store=[Security.Cryptography.X509Certificates.X509Store]::new($s.store,[Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
      try{
        $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        foreach($c in @($store.Certificates)){if($c.Thumbprint -ne $s.sanThumbprint -or $c.HasPrivateKey){throw 'Foreign certificate in owned store; preserved'}}
        foreach($c in @($store.Certificates)){$store.Remove($c)}
        if($store.Certificates.Count){throw 'Owned public store is not empty'}
      }finally{$store.Close()}
      # Only the exact randomly named store created by this run is removable.
      Remove-Item -LiteralPath $registry -Recurse
      if(Test-Path -LiteralPath $registry){throw 'Owned public store remains'}
    }
  }
}
@{complete=($errors.Count -eq 0);errors=@($errors)}|ConvertTo-Json -Depth 4 -Compress
`;

async function reservePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  const port = server.address().port;
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  return port;
}

async function inspectTls(port, expectedFingerprint, owner) {
  return new Promise((resolve, reject) => {
    const request = https.get({ host: "127.0.0.1", port, path: "/index.html", rejectUnauthorized: false, agent: false, timeout: 15000 }, (response) => {
      try {
        const peer = response.socket.getPeerCertificate();
        assert.ok(peer.raw, "TLS peer sent no certificate");
        assert.equal(hash(peer.raw), expectedFingerprint, "TLS served a different certificate");
        assert.equal(response.statusCode, 200);
      } catch (error) { response.destroy(); reject(error); return; }
      let body = "";
      response.setEncoding("utf8");
      response.on("data", (chunk) => { body += chunk; if (body.length > 4096) response.destroy(new Error("Unexpected response size")); });
      response.on("error", reject);
      response.on("end", () => { try { assert.equal(body, owner); resolve({ peerFingerprintSha256: expectedFingerprint, ownedIisContent: true }); } catch (error) { reject(error); } });
    });
    request.on("timeout", () => request.destroy(new Error("TLS probe timed out")));
    request.on("error", reject);
  });
}

async function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  assert.equal(process.platform, "win32", "This smoke requires a disposable Windows runner");
  const root = path.resolve(__dirname, "..");
  const owner = "tt-core-delta-" + crypto.randomBytes(12).toString("hex");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), owner + "-"));
  const manifest = path.join(directory, "owned-resources.json");
  let state = { owner, site: owner, pool: owner, store: "TokenTimerSmoke" + owner.slice("tt-core-delta-".length), directory, port: await reservePort(), certificates: [], siteCreated: false, poolCreated: false, storeCreated: false, allowIisRemoval: false, protectedThumbprints: [] };
  const receipt = { schemaVersion: 1, scope: "windows-iis-wildcard-and-san-store-discovery", sourceSha: options["source-sha"], archiveSha256: options["archive-sha256"], startedAt: new Date().toISOString(), status: "failed", checks: [], notQualifiedByThisRun: ["AD CS or domain authentication", "Windows service install/upgrade", "arm64 execution", "other Windows versions or languages", "trusted-chain validation of the self-signed fixture", "network evidence ingestion", "whole-release qualification"] };
  const saveState = () => { assertOwnedState(state, directory); fs.writeFileSync(manifest, JSON.stringify(state), { mode: 0o600 }); };
  const readState = () => { state = JSON.parse(fs.readFileSync(manifest, "utf8").replace(/^\uFEFF/, "")); assertOwnedState(state, directory); return state; };
  function command(file, args, { timeout = 120000, env = process.env } = {}) {
    const result = spawnSync(file, args, { cwd: root, encoding: "utf8", timeout, maxBuffer: 8 * 1024 * 1024, windowsHide: true, env });
    assert.ok(!result.error && result.status === 0, path.basename(file) + " failed: " + String(result.error?.message || result.stderr || result.stdout).slice(-2500));
    return result.stdout.trim();
  }
  function powershell(script) {
    const env = { ...process.env, TT_WINDOWS_SMOKE_MANIFEST: manifest };
    for (const key of Object.keys(env)) if (key.toLowerCase() === "psmodulepath") delete env[key];
    const executable = path.join(process.env.SystemRoot || "C:\\Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
    return JSON.parse(command(executable, ["-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(script, "utf16le").toString("base64")], { env }));
  }
  async function check(name, fn) {
    const evidence = await fn(); receipt.checks.push({ name, status: "passed", evidence }); process.stdout.write("PASS " + name + "\n"); return evidence;
  }
  let iis, discovery, lock;
  try {
    saveState();
    const archive = path.resolve(options.archive);
    await check("selected-source-and-actual-package", () => {
      assert.equal(command("git", ["rev-parse", "HEAD"]), options["source-sha"]);
      assert.equal(command("git", ["diff", "--name-only", "HEAD", "--", "packages/agent"]), "");
      assert.equal(hash(fs.readFileSync(archive)), options["archive-sha256"], "Candidate archive checksum mismatch");
      assertArchivePaths(command("tar", ["-tzf", archive]).split(/\r?\n/), command("tar", ["-tvzf", archive]).split(/\r?\n/));
      command("tar", ["-xzf", archive, "-C", directory]);
      const packageRoot = path.join(directory, "package");
      const pkg = JSON.parse(fs.readFileSync(path.join(packageRoot, "package.json"), "utf8"));
      assert.equal(pkg.name, "@tokentimer/agent"); assert.equal(pkg.version, "0.18.0");
      let matchedFiles = 0;
      const walk = (relative = "") => { for (const entry of fs.readdirSync(path.join(packageRoot, relative), { withFileTypes: true })) { const name = path.join(relative, entry.name); if (entry.isDirectory()) walk(name); else if (/\.(?:js|cjs|mjs|json|ps1|sh)$/.test(name)) { assert.equal(hash(fs.readFileSync(path.join(packageRoot, name))), hash(fs.readFileSync(path.join(root, "packages/agent", name))), "Packaged source mismatch: " + name); matchedFiles++; } } };
      walk(); assert.ok(matchedFiles > 50);
      iis = require(path.join(packageRoot, "src/windows-iis"));
      discovery = require(path.join(packageRoot, "src/windows-discovery"));
      return { matchedPackageSourceFiles: matchedFiles, version: pkg.version };
    });
    const publicPem = fs.readFileSync(path.join(root, "packages/agent/src/verify/fixtures/san-only.crt.pem"), "utf8");
    const publicCertificate = new crypto.X509Certificate(publicPem);
    assert.ok(!publicCertificate.subject, "Fixture is not SAN-only");
    state.sanThumbprint = publicCertificate.fingerprint.replace(/:/g, "").toUpperCase();
    fs.writeFileSync(path.join(directory, "san-only.cer"), publicCertificate.raw);
    saveState();
    const existing = await discovery.listHttpSysBindings();
    assert.equal(existing.ok, true, "Cannot establish native binding ownership");
    assert.ok(existing.bindings.every((binding) => !binding.ipPort?.endsWith(":" + state.port)), "Chosen port already has an http.sys binding");
    receipt.environment = await check("create-owned-self-signed-iis-and-public-san-store", () => powershell(SETUP));
    readState();
    const binding = { address: "*", port: state.port, site: state.site, store: "My" };
    const oldCertificate = new crypto.X509Certificate(Buffer.from(state.certificates[0].publicDer, "base64"));
    const newCertificate = new crypto.X509Certificate(Buffer.from(state.certificates[1].publicDer, "base64"));
    await inspectTls(state.port, hash(oldCertificate.raw), owner);
    lock = require(path.join(directory, "package/src/windows-cert-store")).acquireStoreLock(path.join(directory, "agent-state"), "My");
    await check("real-wildcard-iis-rebind-and-independent-tls", async () => {
      const result = await lock.run((signal) => iis.deployIisBinding({ binding, certificatePem: newCertificate.toString(), signal }));
      assert.equal(result.ok, true, "Native IIS deployment failed: " + JSON.stringify(result));
      assert.equal(result.outgoingThumbprint, state.certificates[0].thumbprint);
      assert.equal(result.boundThumbprint, state.certificates[1].thumbprint);
      assert.equal(result.skippedMutation, undefined, "Expected an actual rebind");
      const rawNetsh = command("netsh.exe", ["http", "show", "sslcert", "ipport=0.0.0.0:" + state.port]);
      assert.ok(rawNetsh.toUpperCase().includes(state.certificates[1].thumbprint), "Independent netsh query found a different certificate");
      const tls = await inspectTls(state.port, hash(newCertificate.raw), owner);
      return { selector: "0.0.0.0:" + state.port, outgoingThumbprint: result.outgoingThumbprint, boundThumbprint: result.boundThumbprint, ...tls };
    });
    lock.release(); lock = null;
    const expected = { store: state.store, fingerprint: hash(publicCertificate.raw), san: "nginx.wildcard.test" };
    await check("real-san-only-windows-store-discovery", async () => {
      const store = await discovery.listMachineStoreCertificates({ store: state.store });
      assert.equal(store.ok, true, "Real Windows store query failed");
      const certificate = store.certificates.find((entry) => entry.thumbprint === state.sanThumbprint);
      assert.ok(certificate); assert.equal(certificate.subject, null); assert.equal(certificate.hasPrivateKey, false);
      const warnings = [];
      const observations = await require(path.join(directory, "package/src/discovery/windows")).collectWindowsDiscoveryObservations({ stores: [state.store], onWarning: (warning) => warnings.push(warning) });
      const owned = observations.find((entry) => entry.locationKind === "windows_store" && entry.storeName === state.store && entry.fingerprintSha256 === expected.fingerprint);
      assertOwnedObservation(owned, expected);
      return { store: state.store, subject: owned.subject, fingerprintSha256: owned.fingerprintSha256, subjectAltNames: owned.subjectAltNames, keyPresent: owned.keyPresent, warningCount: warnings.length };
    });
    await check("native-discovery-through-production-evidence-builder", async () => {
      const bodies = [];
      const { runWindowsDiscoveryScan } = require(path.join(directory, "package/src/index"));
      await runWindowsDiscoveryScan({ stores: [state.store], client: { reportEvidence: async (body) => { bodies.push(body); } } });
      const item = bodies.flatMap((body) => body.evidenceItems).find((entry) => entry.fingerprintSha256 === expected.fingerprint && entry.metadata.some((field) => field.name === "locationSlot" && field.value.startsWith("LocalMachine/" + state.store + "/")));
      assert.ok(item, "Production evidence builder omitted the native observation");
      assert.equal(item.metadata.find((field) => field.name === "subject")?.value, null);
      assert.ok(JSON.stringify(item.metadata.find((field) => field.name === "subjectAltNames")?.value).includes(expected.san));
      return { eventType: item.eventType, fingerprintSha256: item.fingerprintSha256, subject: null, transport: "captured locally; no API ingestion claim" };
    });
    receipt.status = "passed";
  } catch (error) { receipt.error = error.message; process.stderr.write(error.message + "\n"); }
  finally {
    if (lock) lock.release();
    const errors = [];
    if (fs.existsSync(manifest)) {
      try {
        readState();
        state.protectedThumbprints = state.certificates.map((entry) => entry.thumbprint);
        if (iis && discovery && state.siteCreated) {
          const selected = await iis.queryCurrentBinding({ binding: { address: "*", port: state.port } });
          assert.equal(selected.ok, true, "Cleanup could not query binding");
          assert.ok(selected.thumbprint === null || state.protectedThumbprints.includes(selected.thumbprint), "Foreign certificate replaced the owned selector; preserving native resources");
          if (selected.thumbprint !== null) command("netsh.exe", ["http", "delete", "sslcert", "ipport=0.0.0.0:" + state.port]);
          const after = await iis.queryCurrentBinding({ binding: { address: "*", port: state.port } });
          assert.equal(after.ok, true); assert.equal(after.thumbprint, null, "Owned binding remains");
          state.allowIisRemoval = true;
        } else if (!state.siteCreated) state.allowIisRemoval = true;
        if (discovery) {
          const remaining = await discovery.listHttpSysBindings();
          assert.equal(remaining.ok, true, "Cannot exclude certificate references during cleanup");
          state.protectedThumbprints = state.protectedThumbprints.filter((thumbprint) => remaining.bindings.some((entry) => entry.thumbprint === thumbprint));
        }
      } catch (error) { errors.push(error.message); }
      try {
        saveState();
        if (state.siteCreated || state.poolCreated || state.storeCreated || state.certificates.length) {
          const cleaned = powershell(CLEANUP); errors.push(...cleaned.errors);
          if (!cleaned.complete && cleaned.errors.length === 0) errors.push("Native cleanup did not complete");
        }
      } catch (error) { errors.push(error.message); }
    }
    if (errors.length === 0) {
      try { fs.rmSync(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }); }
      catch (error) { errors.push("Owned temporary directory cleanup failed: " + error.message); }
    }
    receipt.cleanup = { complete: errors.length === 0, errors, ...(errors.length ? { ownedStateDirectory: directory } : {}) };
    if (errors.length) receipt.status = "failed";
    receipt.finishedAt = new Date().toISOString();
    fs.mkdirSync(path.dirname(path.resolve(options.out)), { recursive: true });
    fs.writeFileSync(options.out, JSON.stringify(receipt, null, 2) + "\n");
  }
  if (receipt.status !== "passed") process.exitCode = 1;
  return receipt;
}

module.exports = { parseArgs, assertOwnedState, assertArchivePaths, assertOwnedObservation };
if (require.main === module) main().catch((error) => { console.error(error.message); process.exitCode = 1; });
