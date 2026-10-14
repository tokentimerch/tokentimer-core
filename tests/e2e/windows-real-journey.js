"use strict";
/* Installed Windows SYSTEM-agent certificate E2E, invoked by the trusted Windows ACME workflow.
 * Owns the SCM service, protected config, local IIS fixtures and genuine API jobs; public Pebble
 * DNS/CA material and independent TLS prove issuance/renewal. Cleanup preserves only bounded
 * public evidence.
 */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const https = require("node:https");
const http = require("node:http");
const tls = require("node:tls");
const net = require("node:net");
const { spawnSync } = require("node:child_process");

function nativeCommandEnvironment(file, additions = {}) {
  const env = { ...process.env, ...additions };
  if (path.basename(file).toLowerCase() === "powershell.exe") for (const name of Object.keys(env)) if (name.toLowerCase() === "psmodulepath") delete env[name];
  return env;
}
function command(program, args) {
  const result = spawnSync(program, args, { encoding: "utf8", timeout: 180000, env: nativeCommandEnvironment(program) });
  assert.ifError(result.error);
  assert.equal(result.status, 0, `${program} failed (status ${result.status})`);
  return result.stdout.trim();
}
function ps(script) { return command("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", `$ErrorActionPreference='Stop'; ${script}`]); }
async function waitUntil(check, timeout = 180000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) { const result = await check(); if (result) return result; await new Promise((resolve) => setTimeout(resolve, 500)); }
  throw new Error("Windows real journey timed out");
}
async function fetchPem(endpoint) {
  return new Promise((resolve, reject) => {
    const request = https.get(endpoint, { rejectUnauthorized: false, timeout: 5000 }, (response) => {
      let data = ""; response.on("data", (chunk) => { data += chunk; }); response.on("end", () => response.statusCode === 200 ? resolve(data) : reject(new Error("Pebble CA fetch failed")));
    }); request.on("error", reject); request.on("timeout", () => request.destroy(new Error("CA fetch timeout")));
  });
}

module.exports = async function qualifyWindows({ pool, baseUrl, workspaceId, userId, createBootstrap, repoRoot }) {
  const keyProfiles = { "rsa-2048": { keyAlgorithm: "rsa", keySize: 2048 }, "rsa-3072": { keyAlgorithm: "rsa", keySize: 3072 }, "rsa-4096": { keyAlgorithm: "rsa", keySize: 4096 }, "ec-p256": { keyAlgorithm: "ecdsa", keySize: 256 }, "ec-p384": { keyAlgorithm: "ecdsa", keySize: 384 } };
  const keyProfile = keyProfiles[process.env.CERTOPS_WINDOWS_KEY_PROFILE || "rsa-2048"];
  assert.ok(keyProfile, "unknown Windows qualification key profile");
  const privateKeyGetter = keyProfile.keyAlgorithm === "rsa" ? "[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c)" : "[Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($c)";
  assert.equal(process.platform, "win32");
  assert.equal(process.arch, "x64", "current full installed-agent matrix qualifies native amd64 execution");
  assert.equal(process.env.GITHUB_ACTIONS, "true");
  assert.equal(process.env.RUNNER_ENVIRONMENT, "github-hosted");
  assert.equal(process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST, "1");
  assert.ok(process.env.RUNNER_TEMP && fs.statSync(process.env.RUNNER_TEMP).isDirectory());
  assert.equal(ps("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value"), "S-1-5-18", "installed-agent qualification harness must run as SYSTEM to observe restricted agent state");
  assert.equal(ps("([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"), "True");
  assert.notEqual(spawnSync("sc.exe", ["query", "TokenTimerAgent"]).status, 0, "refuse to replace an existing agent service");
  const caEndpoint = new URL(process.env.CERTOPS_PEBBLE_DIRECTORY);
  const dnsEndpoint = new URL(process.env.CERTOPS_PEBBLE_DNS_API);
  assert.equal(caEndpoint.protocol, "https:"); assert.equal(dnsEndpoint.protocol, "http:");
  for (const endpoint of [caEndpoint, dnsEndpoint]) assert.ok(["localhost", "127.0.0.1"].includes(endpoint.hostname));
  const workDir = fs.mkdtempSync(path.join(process.env.RUNNER_TEMP, "certops-windows-journey-"));
  const configDir = path.join(workDir, "state"); fs.mkdirSync(configDir);
  let outputPrivacy;
  let publicSession, publicIssuanceFacts, publicIssueInput;
  const publicIssueProofPath=path.join(repoRoot,"qualification-results",`windows-public-issue-${process.env.CERTOPS_WINDOWS_KEY_PROFILE || "rsa-2048"}.json`);
  assert.equal(fs.existsSync(publicIssueProofPath),false,"Refuse stale public admission proof");
  const domain = `certops-${crypto.randomBytes(6).toString("hex")}.example.test`;
  const adoptionDomain = `certops-adopt-${crypto.randomBytes(6).toString("hex")}.example.test`;
  const site = `CertOps-${crypto.randomUUID()}`;
  const agentId = `windows-${crypto.randomUUID()}`;
  const socket = net.createServer(); await new Promise((resolve, reject) => { socket.once("error", reject); socket.listen(0, "127.0.0.1", resolve); });
  const port = socket.address().port; await new Promise((resolve) => socket.close(resolve));
  const roots = [];
  const ownedJobs = [];
  let serviceOwned = false;
  let siteOwned = false;
  let certificateId;
  let deployedThumbprint;
  let journeyFailure;
  let werSnapshot;
  let werTouched = false;
  const readWerPolicy = () => JSON.parse(ps("$p='HKLM:\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps\\node.exe'; $exists=Test-Path $p; $v=$null; $kind=$null; if ($exists) { $k=Get-Item $p; if ($k.GetValueNames() -contains 'DumpType') { $v=$k.GetValue('DumpType',$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames); $kind=[string]$k.GetValueKind('DumpType') } }; [pscustomobject]@{exists=$exists;value=$v;kind=$kind} | ConvertTo-Json -Compress"));
  let installerFixture;
  let candidateRoot;
  const errors = [];
  let holdDns = false;
  let heldDnsObserved = false;
  const heldResponses = new Set();
  const dnsProxy = http.createServer((request, response) => {
    if (holdDns && request.method === "POST") {
      heldDnsObserved = true; request.resume(); heldResponses.add(response);
      response.once("close", () => heldResponses.delete(response)); return;
    }
    const upstream = http.request(new URL(request.url, dnsEndpoint), { method: request.method, headers: request.headers }, (incoming) => { response.writeHead(incoming.statusCode, incoming.headers); incoming.pipe(response); });
    upstream.on("error", () => { response.statusCode = 502; response.end(); }); request.pipe(upstream);
  });
  await new Promise((resolve, reject) => { dnsProxy.once("error", reject); dnsProxy.listen(0, "127.0.0.1", resolve); });
  const cleanup = async (action) => { try { await action(); } catch (error) { errors.push(error); } };
  try {
    const management = "https://127.0.0.1:15000";
    for (const [endpoint, store] of [["roots/0", "Root"], ["intermediates/0", "CA"]]) {
      const pem = await fetchPem(`${management}/${endpoint}`);
      const thumbprint = new crypto.X509Certificate(pem).fingerprint.replace(/:/g, "");
      assert.equal(ps(`[bool](Test-Path 'Cert:\\LocalMachine\\${store}\\${thumbprint}')`), "False", "refuse ownership of pre-existing CA trust");
      roots.push({ store, thumbprint, pem });
      const file = path.join(workDir, `${store}.pem`); fs.writeFileSync(file, pem);
      command("certutil.exe", ["-addstore", store, file]);
    }
    const credentialsFile = path.join(configDir, "dns.json");
    fs.writeFileSync(credentialsFile, JSON.stringify({ baseUrl: `http://127.0.0.1:${dnsProxy.address().port}`, allowInsecureLocalHttp: true }));
    const bash = process.env.CERTOPS_WINDOWS_BASH;
    const acmeSh = process.env.CERTOPS_WINDOWS_ACMESH;
    assert.ok(bash && acmeSh && fs.existsSync(bash) && fs.existsSync(acmeSh));
    // Leave headroom below the shared machine-route limiter for discovery, logs and results.
    outputPrivacy=await require("./helpers/certops-windows-output-privacy").prepareOutputPrivacy(workDir,bash,[acmeSh,"--insecure","--accountemail","certops@example.test"],baseUrl);
    fs.writeFileSync(path.join(configDir, "config.json"), JSON.stringify({ serverUrl: outputPrivacy.agentUrl, agentId, allowInsecureLocalHttp: true, pollIntervalMs: 2000, heartbeatIntervalMs: 5000, windowsDiscovery: { enabled: true, intervalMs: 5000, stores: ["My"] }, declaredTargetSelectors: [domain, adoptionDomain], declaredCommandProfileNames: ["qualification-acmesh"], execution: { enabled: true, dryRun: false }, policy: { allowedPaths: [workDir], allowedCommands: { "qualification-acmesh": { argv: outputPrivacy.argv } }, allowedCaEndpoints: [caEndpoint.href], allowedDnsZones: ["example.test"], allowedDnsProviders: ["pebble-challtestsrv"] }, dnsProviders: { "pebble-challtestsrv": { credentialsFile }, zoneProviderMap: { "example.test": "pebble-challtestsrv" } }, dnsPropagation: { resolvers: [process.env.CERTOPS_PEBBLE_DNS_RESOLVER], checkAuthoritative: false, intervalMs: 500, timeoutMs: 30000 } }));
    const platform = require(path.join(repoRoot, "packages/agent/src/platform"));
    platform.applyRestrictivePermissions(configDir, { kind: "directory" });
    platform.applyRestrictivePermissions(path.join(configDir, "config.json"), { kind: "file" });
    platform.applyRestrictivePermissions(credentialsFile, { kind: "file" });
    siteOwned = true;
    ps(`Import-Module WebAdministration; New-Website -Name '${site}' -PhysicalPath '${workDir.replace(/'/g, "''")}' -IPAddress '*' -Port ${port} -HostHeader '${domain}' -Ssl | Out-Null; Set-WebBinding -Name '${site}' -BindingInformation '*:${port}:${domain}' -PropertyName sslFlags -Value 1`);
    const { plaintextToken } = await createBootstrap();
    // Run the exact freshly packed candidate bytes, rather than resolving
    // runtime modules from the checkout. The source packer has no signing
    // authority; this proves candidate completeness, not release provenance.
    const packaged = require(path.join(repoRoot, "packages/agent/scripts/pack-release")).main(["--out-dir", path.join(workDir, "release-package")]);
    const checkedArchiveDigest = require(path.join(repoRoot, "packages/agent/scripts/host/package-fixture")).verifyArchiveDigest(packaged.tarballPath, packaged.checksumPath);
    const packageDirectory = path.join(workDir, "candidate-package");
    fs.mkdirSync(packageDirectory);
    command("tar.exe", ["-xzf", packaged.tarballPath, "-C", packageDirectory]);
    candidateRoot = path.join(packageDirectory, "package");
    const candidateVersion = JSON.parse(fs.readFileSync(path.join(candidateRoot, "package.json"))).version;
    assert.equal(candidateVersion, JSON.parse(fs.readFileSync(path.join(repoRoot, "packages/agent/package.json"))).version);
    const host = path.join(candidateRoot, "bin", "tokentimer-agent-host-amd64.exe");
    require(path.join(repoRoot, "packages/agent/scripts/host/package-fixture")).verifyPeArchitecture(host, 0x8664);
    const publicPackageEvidence = { version: candidateVersion, archiveSha256: checkedArchiveDigest, unsignedCandidate: true,
      installerAdapter: "temporary-owned-root", nativeExecutionArchitecture: process.arch, helperDigests: {} };
    for (const arch of ["amd64", "arm64"]) {
      const name = `tokentimer-agent-host-${arch}.exe`;
      publicPackageEvidence.helperDigests[name] = crypto.createHash("sha256").update(fs.readFileSync(path.join(candidateRoot, "bin", name))).digest("hex");
    }
    const reportDirectory = path.join(repoRoot, "qualification-results"); fs.mkdirSync(reportDirectory, { recursive: true });
    fs.writeFileSync(path.join(reportDirectory, `windows-candidate-${process.env.CERTOPS_WINDOWS_KEY_PROFILE || "rsa-2048"}.json`), JSON.stringify(publicPackageEvidence));
    const installerSource = fs.readFileSync(path.join(candidateRoot, "scripts/install-agent.ps1"), "utf8");
    const fixedRoot = '$InstallRoot = "C:\\ProgramData\\TokenTimerAgent"';
    assert.ok(installerSource.includes(fixedRoot));
    installerFixture = path.join(candidateRoot, "scripts/qualification-install.ps1");
    fs.writeFileSync(installerFixture, "\uFEFF" + installerSource.replace(fixedRoot, `$InstallRoot = '${workDir.replace(/'/g, "''")}'`));
    let initialInstaller = installerFixture;
    let initialHost = host;
    let historicalEvidence;
    if (process.env.CERTOPS_WINDOWS_HISTORICAL_PACKAGE) {
      const historicalPackage = path.resolve(process.env.CERTOPS_WINDOWS_HISTORICAL_PACKAGE);
      const runnerRoot = path.resolve(process.env.RUNNER_TEMP);
      const relative = path.relative(runnerRoot, historicalPackage);
      assert.ok(relative && !relative.startsWith("..") && !path.isAbsolute(relative), "historical fixture package must be inside runner temporary directory");
      historicalEvidence = JSON.parse(fs.readFileSync(path.join(historicalPackage, "historical-source-build.json")));
      const historical = require(path.join(repoRoot, "scripts/certops-historical-windows-package")).historical;
      assert.equal(historicalEvidence.provenance, "historical-source-build");
      assert.equal(historicalEvidence.commit, historical.commit);
      assert.equal(historicalEvidence.tagObject, historical.tagObject);
      assert.equal(historicalEvidence.version, historical.version);
      assert.equal(historicalEvidence.publishedArchiveUsedForInstallation, false);
      assert.notEqual(candidateVersion, historical.version, "historical lane requires genuine distinct package versions");
      const historicalArchive = path.join(historicalPackage, `tokentimer-agent-${historical.version}.tgz`);
      assert.equal(require(path.join(repoRoot, "packages/agent/scripts/host/package-fixture")).verifyArchiveDigest(historicalArchive, `${historicalArchive}.sha256`), historicalEvidence.archiveSha256);
      const historicalExtract = path.join(workDir, "historical-package"); fs.mkdirSync(historicalExtract);
      command("tar.exe", ["-xzf", historicalArchive, "-C", historicalExtract]);
      const historicalRoot = path.join(historicalExtract, "package");
      assert.equal(JSON.parse(fs.readFileSync(path.join(historicalRoot, "package.json"))).version, historical.version);
      for (const arch of ["amd64", "arm64"]) {
        const helper = path.join(historicalRoot, "bin", `tokentimer-agent-host-${arch}.exe`);
        require(path.join(repoRoot, "packages/agent/scripts/host/package-fixture")).verifyPeArchitecture(helper, arch === "amd64" ? 0x8664 : 0xaa64);
        assert.equal(crypto.createHash("sha256").update(fs.readFileSync(helper)).digest("hex"), historicalEvidence.helpers[arch]);
      }
      const historicalInstallerSource = fs.readFileSync(path.join(historicalRoot, "scripts/install-agent.ps1"), "utf8");
      assert.ok(historicalInstallerSource.includes(fixedRoot));
      initialInstaller = path.join(historicalRoot, "scripts/qualification-install.ps1");
      fs.writeFileSync(initialInstaller, "\uFEFF" + historicalInstallerSource.replace(fixedRoot, `$InstallRoot = '${workDir.replace(/'/g, "''")}'`));
      initialHost = path.join(historicalRoot, "bin/tokentimer-agent-host-amd64.exe");
    }
    werSnapshot = readWerPolicy();
    if (initialInstaller !== installerFixture) assert.ok(werSnapshot.kind === null || werSnapshot.kind === "DWord", "refuse a historical installer overwrite of non-DWORD WER policy");
    if (werSnapshot.kind === "DWord") assert.ok(Number.isInteger(werSnapshot.value) && werSnapshot.value >= -2147483648 && werSnapshot.value <= 2147483647);
    // Receipt exists before invoking a script that may fail after creating
    // its service. Only the historical installer may change WER policy; the
    // candidate must preserve it. This root and service are ours.
    fs.writeFileSync(path.join(workDir, "installer-ownership.json"), JSON.stringify({ service: "TokenTimerAgent", root: workDir, wer: werSnapshot }));
    serviceOwned = true;
    werTouched = initialInstaller !== installerFixture;
    const installed = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", initialInstaller,
      "--api-url", baseUrl, "--workspace-id", String(workspaceId), "--allow-insecure-local-http", "--no-trust-store"],
    { encoding: "utf8", timeout: 180000, env: nativeCommandEnvironment("powershell.exe", { TOKENTIMER_AGENT_BOOTSTRAP_TOKEN: plaintextToken }) });
    assert.equal(installed.status, 0, "checked candidate product installer failed on owned root");
    if (!werTouched) assert.deepEqual(readWerPolicy(), werSnapshot, "Candidate installer must preserve existing WER policy");
    if (process.env.CERTOPS_WER_EXPERIMENTAL_PROBE === "1") {
      const probe = await require(path.join(repoRoot, "packages/agent/scripts/host/wer-abort-probe")).probeWerCustomDump({ workDir, powershell: ps });
      console.log(JSON.stringify({ werDiagnostic: probe }));
    }
    assert.equal(crypto.createHash("sha256").update(fs.readFileSync(path.join(workDir, "app/bin/tokentimer-agent-host-amd64.exe"))).digest("hex"),
      crypto.createHash("sha256").update(fs.readFileSync(initialHost)).digest("hex"), "product installer must activate the checked native helper bytes");
    await waitUntil(async () => (await pool.query("SELECT 1 FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2 AND retired_at IS NULL", [workspaceId, agentId])).rows.length);
    const identity = JSON.parse(ps("$s=Get-CimInstance Win32_Service -Filter \"Name='TokenTimerAgent'\"; $p=Get-CimInstance Win32_Process -Filter \"ProcessId=$($s.ProcessId)\"; $owner=Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid; [pscustomobject]@{state=$s.State; ownerSid=$owner.Sid} | ConvertTo-Json -Compress"));
    assert.equal(identity.state, "Running");
    assert.equal(identity.ownerSid, "S-1-5-18", "real service host must execute as LocalSystem");
    const environmentAfterRegistration = command("reg.exe", ["query", "HKLM\\SYSTEM\\CurrentControlSet\\Services\\TokenTimerAgent", "/v", "Environment"]);
    assert.equal(/TOKENTIMER_AGENT_BOOTSTRAP_TOKEN(?:=|_ID=)/.test(environmentAfterRegistration), false, "bootstrap credentials must be scrubbed after registration");
    if (historicalEvidence) {
      await waitUntil(async () => (await pool.query("SELECT 1 FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2 AND agent_version=$3 AND last_seen_at IS NOT NULL", [workspaceId, agentId, historicalEvidence.version])).rows.length);
      await require("./helpers/certops-windows-source-upgrade").qualifySourceUpgrade({ workDir, repoRoot, ps, waitUntil, reportDirectory, historicalEvidence, candidateVersion, migrate: async () => {
      const historyJob=await require(path.join(repoRoot,"apps/api/services/certops/jobs")).createCertificateJob({client:pool,workspaceId,operation:"noop",source:"api",mode:"dry_run",requestedByUserId:userId});
      ownedJobs.push(historyJob.id);
      const historySql="SELECT id,status,operation,mode,completed_at,claimed_by_agent_id,result_metadata FROM certificate_jobs WHERE workspace_id=$1 AND id=$2";
      const historicalJob=await waitUntil(async()=>{const row=(await pool.query(historySql,[workspaceId,historyJob.id])).rows[0];if(["failed","rejected","cancelled"].includes(row?.status))throw new Error("Historical agent did not complete genuine scheduled noop");return row?.status==="succeeded"?row:null;});
      assert.equal((await pool.query("SELECT 1 FROM certops_agents WHERE id=$1 AND workspace_id=$2 AND agent_id=$3",[historicalJob.claimed_by_agent_id,workspaceId,agentId])).rows.length,1,"Historical scheduled job must belong to this actual registered service agent");
      await waitUntil(() => fs.existsSync(path.join(configDir,"signing-key-pin.json")));
      const migrationWerPolicy=readWerPolicy();
      const historicalCredential = fs.readFileSync(path.join(configDir, "credential"));
      const historicalConfig = fs.readFileSync(path.join(configDir, "config.json"));
      const historicalPin = fs.readFileSync(path.join(configDir, "signing-key-pin.json"));
      const historicalSeen = (await pool.query("SELECT last_seen_at FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2", [workspaceId, agentId])).rows[0].last_seen_at;
      const migratedBootstrap = await createBootstrap();
      const migrated = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", installerFixture,
        "--api-url", baseUrl, "--workspace-id", String(workspaceId), "--allow-insecure-local-http", "--no-trust-store"],
      { encoding: "utf8", timeout: 180000, env: nativeCommandEnvironment("powershell.exe", { TOKENTIMER_AGENT_BOOTSTRAP_TOKEN: migratedBootstrap.plaintextToken }) });
      assert.ifError(migrated.error); assert.equal(migrated.status, 0, "distinct historical-source version upgrade must succeed");
      assert.deepEqual(readWerPolicy(),migrationWerPolicy,"Candidate upgrade must preserve existing legacy WER policy without claiming dump suppression");
      assert.deepEqual(fs.readFileSync(path.join(configDir, "credential")), historicalCredential);
      assert.deepEqual(fs.readFileSync(path.join(configDir, "config.json")), historicalConfig);
      assert.deepEqual(fs.readFileSync(path.join(configDir, "signing-key-pin.json")), historicalPin, "upgrade must preserve the actual operational signing-key pin");
      assert.deepEqual(fs.readFileSync(path.join(workDir, "app/bin/tokentimer-agent-host-amd64.exe")), fs.readFileSync(host));
      await waitUntil(async () => (await pool.query("SELECT 1 FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2 AND agent_version=$3 AND last_seen_at>$4", [workspaceId, agentId, candidateVersion, historicalSeen])).rows.length);
      assert.deepEqual((await pool.query(historySql,[workspaceId,historyJob.id])).rows[0],historicalJob,"Upgrade must preserve actual previously completed scheduler history");
      return { werPolicyPreserved:true,schedulerHistoryPreserved:true, distinctVersionObserved:true, credentialPreserved:true, configurationPreserved:true, signingKeyPinPreserved:true, sameAgentIdentity:true, authenticatedCandidateHeartbeat:true, candidateHelperActivated:true };
      } });
    }
    await require("./windows-adoption-retention-journey")({ pool, baseUrl, workspaceId, agentId, configDir, workDir, repoRoot, domain: adoptionDomain, keyProfile, caEndpoint: caEndpoint.href, caRoots: roots.map(root => root.pem), ps, command });
    publicSession = await require("./helpers/certops-api-fixture").createApiFixture(baseUrl);
    const publicAdmission = require("./helpers/certops-windows-public-issuance");
    const input = publicIssueInput = publicAdmission.buildPublicWindowsIssue({ workspaceId, keyProfile, domain, site, port, caEndpoint: caEndpoint.href });
    const admitted = await publicAdmission.admitPublicWindowsIssue({ baseUrl, pool, workspaceId, session: publicSession, input, ownedJobs });
    publicIssuanceFacts = admitted.facts;
    const job = admitted.job; certificateId = job.subjectId;
    assert.ok(job.id && certificateId);
    await waitUntil(async () => { const row = (await pool.query("SELECT status FROM certificate_jobs WHERE id=$1", [job.id])).rows[0]; if (["failed", "rejected", "cancelled"].includes(row?.status)) throw new Error(`Windows real job terminated ${row.status}`); return row?.status === "succeeded"; });
    const observed = await new Promise((resolve, reject) => { const connection = tls.connect({ host: "127.0.0.1", port, servername: domain, ca: roots.map((root) => root.pem), rejectUnauthorized: true }, () => { resolve(connection.getPeerCertificate()); connection.end(); }); connection.once("error", reject); connection.setTimeout(10000, () => connection.destroy(new Error("Independent IIS TLS timeout"))); });
    const thumbprint = observed.fingerprint.replace(/:/g, "");
    deployedThumbprint = thumbprint;
    assert.equal(new crypto.X509Certificate(observed.raw).checkHost(domain), domain);
    assert.equal(ps(`$c=Get-Item 'Cert:\\LocalMachine\\My\\${thumbprint}'; [bool]$c.HasPrivateKey`), "True");
    assert.equal(ps(`$c=Get-Item 'Cert:\\LocalMachine\\My\\${thumbprint}'; $k=$null; try { $k=${privateKeyGetter}; [string]$k.Key.ExportPolicy } finally { if ($k) { $k.Dispose() }; $c.Dispose() }`), "None", "issued CNG key must remain non-exportable");
    assert.equal(Number(ps(`$c=Get-Item 'Cert:\\LocalMachine\\My\\${thumbprint}'; $k=$null; try { $k=${privateKeyGetter}; $k.KeySize } finally { if ($k) { $k.Dispose() }; $c.Dispose() }`)), keyProfile.keySize);
    assert.ok(command("netsh.exe", ["http", "show", "sslcert", `hostnameport=${domain}:${port}`]).toLowerCase().includes(thumbprint.toLowerCase()));
    assert.ok((await pool.query("SELECT 1 FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2", [workspaceId, job.id])).rows.length, "agent result evidence must persist");
    publicIssuanceFacts.nativeJobSucceeded = true;
    publicIssuanceFacts.nativeCngIisTrustedTlsVerified = true;
    const credentialFile = path.join(configDir, "credential");
    for (const protectedPath of [configDir, credentialFile]) {
      assert.equal(ps(`$a=Get-Acl -LiteralPath '${protectedPath.replace(/'/g, "''")}'; if (!$a.AreAccessRulesProtected) { throw 'Inherited service state ACL' }; foreach ($r in $a.Access) { if ($r.AccessControlType -eq 'Allow') { $sid=$r.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value; if ($sid -notin @('S-1-5-18','S-1-5-32-544')) { throw 'Unexpected service state trustee' } } }; 'restricted'`),
        "restricted", "independent native state/credential ACL must allow only SYSTEM and Administrators");
    }
    const credentialDigest = crypto.createHash("sha256").update(fs.readFileSync(credentialFile)).digest("hex");
    let lastSeenBeforeRestart = (await pool.query("SELECT last_seen_at FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2", [workspaceId, agentId])).rows[0].last_seen_at;
    const preUpgradeConfig = fs.readFileSync(path.join(configDir, "config.json"));
    const preUpgradeServicePid = ps("[string](Get-CimInstance Win32_Service -Filter \"Name='TokenTimerAgent'\").ProcessId");
    const upgradeBootstrap = await createBootstrap();
    const upgrade = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", installerFixture,
      "--api-url", baseUrl, "--workspace-id", String(workspaceId), "--allow-insecure-local-http", "--no-trust-store"],
    { encoding: "utf8", timeout: 180000, env: nativeCommandEnvironment("powershell.exe", { TOKENTIMER_AGENT_BOOTSTRAP_TOKEN: upgradeBootstrap.plaintextToken }) });
    assert.equal(upgrade.status, 0, "product installer re-run must activate the candidate through its upgrade path");
    assert.notEqual(ps("[string](Get-CimInstance Win32_Service -Filter \"Name='TokenTimerAgent'\").ProcessId"), preUpgradeServicePid,
      "installer upgrade path must restart the real service host");
    assert.deepEqual(fs.readFileSync(path.join(configDir, "config.json")), preUpgradeConfig, "installer re-run must preserve operator configuration");
    assert.equal(crypto.createHash("sha256").update(fs.readFileSync(credentialFile)).digest("hex"), credentialDigest);
    await waitUntil(async () => { const row = (await pool.query("SELECT last_seen_at FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2", [workspaceId, agentId])).rows[0]; return row && Date.parse(row.last_seen_at) > Date.parse(lastSeenBeforeRestart); });
    assert.ok(fs.existsSync(path.join(workDir, "app/bin/tokentimer-agent.js")));
    assert.equal(fs.existsSync(path.join(configDir, "bootstrap.env")), false, "existing credential startup must remove the newly staged bootstrap environment");
    lastSeenBeforeRestart = (await pool.query("SELECT last_seen_at FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2", [workspaceId, agentId])).rows[0].last_seen_at;
    // A native ReadData denial on one disposable public fixture file forces
    // the real copy stage to fail, before activation or a service restart.
    const unreadableFixture = path.join(candidateRoot, "qualification-copy-denied.txt");
    fs.writeFileSync(unreadableFixture, "public fixture: staging must fail closed\n");
    const fixturePsPath = unreadableFixture.replace(/'/g, "''");
    const originalFixtureAcl = ps(`(Get-Acl -LiteralPath '${fixturePsPath}').Sddl`);
    const stageServicePid = ps("[string](Get-CimInstance Win32_Service -Filter \"Name='TokenTimerAgent'\").ProcessId");
    const stagingBootstrap = await createBootstrap();
    let stagingFailure;
    try {
      ps(`$acl=Get-Acl -LiteralPath '${fixturePsPath}'; $sid=New-Object Security.Principal.SecurityIdentifier('S-1-5-18'); $rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,[Security.AccessControl.FileSystemRights]::ReadData,[Security.AccessControl.AccessControlType]::Deny); $acl.AddAccessRule($rule); Set-Acl -LiteralPath '${fixturePsPath}' -AclObject $acl`);
      assert.throws(() => fs.readFileSync(unreadableFixture), "native SYSTEM file read must actually be denied before invoking the installer");
      stagingFailure = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", installerFixture,
        "--api-url", baseUrl, "--workspace-id", String(workspaceId), "--allow-insecure-local-http", "--no-trust-store"],
      { encoding: "utf8", timeout: 180000, env: nativeCommandEnvironment("powershell.exe", { TOKENTIMER_AGENT_BOOTSTRAP_TOKEN: stagingBootstrap.plaintextToken }) });
    } finally {
      ps(`$acl=Get-Acl -LiteralPath '${fixturePsPath}'; $acl.SetSecurityDescriptorSddlForm('${originalFixtureAcl.replace(/'/g, "''")}'); Set-Acl -LiteralPath '${fixturePsPath}' -AclObject $acl`);
      fs.rmSync(unreadableFixture);
    }
    assert.ifError(stagingFailure.error);
    assert.notEqual(stagingFailure.status, 0);
    assert.ok(/failed to stage the agent package/.test(`${stagingFailure.stdout}\n${stagingFailure.stderr}`),
      "real installer must report its staging-copy failure; subprocess output is not published");
    assert.equal(ps("[string](Get-CimInstance Win32_Service -Filter \"Name='TokenTimerAgent'\").ProcessId"), stageServicePid,
      "staging failure must not replace or restart the healthy previous service");
    assert.deepEqual(fs.readFileSync(path.join(configDir, "config.json")), preUpgradeConfig);
    assert.equal(crypto.createHash("sha256").update(fs.readFileSync(credentialFile)).digest("hex"), credentialDigest);
    assert.deepEqual(fs.readFileSync(path.join(workDir, "app/bin/tokentimer-agent-host-amd64.exe")), fs.readFileSync(host));
    // A real loader failure exercises the installer's existing rollback path.
    // Only the extracted disposable candidate is sabotaged; the archive and
    // previously installed bytes remain the checked candidate.
    const intactCandidateHost = fs.readFileSync(host);
    const rollbackBootstrap = await createBootstrap();
    let failedUpgrade;
    try {
      fs.writeFileSync(host, Buffer.from("MZ qualification intentionally invalid native executable"));
      failedUpgrade = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", installerFixture,
        "--api-url", baseUrl, "--workspace-id", String(workspaceId), "--allow-insecure-local-http", "--no-trust-store"],
      { encoding: "utf8", timeout: 180000, env: nativeCommandEnvironment("powershell.exe", { TOKENTIMER_AGENT_BOOTSTRAP_TOKEN: rollbackBootstrap.plaintextToken }) });
    } finally { fs.writeFileSync(host, intactCandidateHost); }
    assert.ifError(failedUpgrade.error);
    assert.notEqual(failedUpgrade.status, 0, "invalid native candidate must fail upgrade qualification");
    assert.ok(/rolled back to the previous version/.test(`${failedUpgrade.stdout}\n${failedUpgrade.stderr}`),
      "failure must reach the product health-check rollback, not an unrelated prerequisite error");
    assert.deepEqual(fs.readFileSync(path.join(workDir, "app/bin/tokentimer-agent-host-amd64.exe")), intactCandidateHost,
      "rollback must restore exact previously installed native helper bytes");
    assert.deepEqual(fs.readFileSync(path.join(configDir, "config.json")), preUpgradeConfig);
    assert.equal(crypto.createHash("sha256").update(fs.readFileSync(credentialFile)).digest("hex"), credentialDigest);
    await waitUntil(() => ps("[string](Get-Service -Name TokenTimerAgent).Status") === "Running");
    await waitUntil(async () => { const row = (await pool.query("SELECT last_seen_at FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2", [workspaceId, agentId])).rows[0]; return row && Date.parse(row.last_seen_at) > Date.parse(lastSeenBeforeRestart); });
    lastSeenBeforeRestart = (await pool.query("SELECT last_seen_at FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2", [workspaceId, agentId])).rows[0].last_seen_at;
    // Negative startup and crash fixtures own the restart decision; suppress
    // installer recovery so independent observations cannot race a 5s restart.
    command("sc.exe", ["failure", "TokenTimerAgent", "reset=", "60", "actions=", ""]);
    ps("$s=Get-Service -Name TokenTimerAgent; Stop-Service -Name TokenTimerAgent; $s.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(20))");
    const persistedConfigPath = path.join(configDir, "config.json");
    const persistedConfig = fs.readFileSync(persistedConfigPath);
    const serviceLog = path.join(configDir, "host.log");
    const inconsistentConfig = JSON.parse(persistedConfig.toString("utf8"));
    delete inconsistentConfig.agentId;
    try {
      for (const startupFailure of [
        { content: "{", expected: /failed to parse/, name: "malformed configuration" },
        { content: JSON.stringify(inconsistentConfig), expected: /stored credential but no agentId/, name: "inconsistent registered identity" },
      ]) {
      const previousLogSize = fs.existsSync(serviceLog) ? fs.statSync(serviceLog).size : 0;
      fs.writeFileSync(persistedConfigPath, startupFailure.content);
      // Start may race the immediate child failure. Require independently
      // observed STOPPED and new parse evidence instead of its transient code.
      spawnSync("sc.exe", ["start", "TokenTimerAgent"], { encoding: "utf8", timeout: 30000 });
      await waitUntil(() => /STOPPED/.test(command("sc.exe", ["query", "TokenTimerAgent"])) &&
        fs.existsSync(serviceLog) && startupFailure.expected.test(fs.readFileSync(serviceLog).subarray(previousLogSize).toString("utf8")), 30000);
      assert.equal(crypto.createHash("sha256").update(fs.readFileSync(credentialFile)).digest("hex"), credentialDigest,
        `${startupFailure.name} must preserve the real registered credential`);
      assert.ok(command("netsh.exe", ["http", "show", "sslcert", `hostnameport=${domain}:${port}`]).toLowerCase().includes(thumbprint.toLowerCase()),
        "failed agent startup must preserve the already-deployed certificate binding");
      assert.equal((await pool.query("SELECT COUNT(*)::int AS count FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2", [workspaceId, agentId])).rows[0].count, 1,
        "refused startup must not duplicate the registered identity");
      }
    } finally { fs.writeFileSync(persistedConfigPath, persistedConfig); }
    ps("$s=Get-Service -Name TokenTimerAgent; Start-Service -Name TokenTimerAgent; $s.WaitForStatus('Running',[TimeSpan]::FromSeconds(20))");
    await waitUntil(async () => { const row = (await pool.query("SELECT last_seen_at FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2", [workspaceId, agentId])).rows[0]; return row && Date.parse(row.last_seen_at) > Date.parse(lastSeenBeforeRestart); });
    assert.equal(crypto.createHash("sha256").update(fs.readFileSync(credentialFile)).digest("hex") === credentialDigest, true, "service restart must reuse its persisted credential without bootstrap");
    const afterRestart = await new Promise((resolve, reject) => { const connection = tls.connect({ host: "127.0.0.1", port, servername: domain, ca: roots.map((root) => root.pem), rejectUnauthorized: true }, () => { resolve(connection.getPeerCertificate().fingerprint256); connection.end(); }); connection.once("error", reject); connection.setTimeout(10000, () => connection.destroy(new Error("Restart IIS TLS timeout"))); });
    assert.equal(afterRestart, observed.fingerprint256, "agent restart must leave deployed IIS certificate intact");
    const managed = (await pool.query("SELECT mc.profile_id,mc.not_after,cp.renew_before_days,cp.public_metadata FROM managed_certificates mc LEFT JOIN certificate_profiles cp ON cp.workspace_id=mc.workspace_id AND cp.id=mc.profile_id WHERE mc.workspace_id=$1 AND mc.id=$2", [workspaceId, certificateId])).rows[0];
    assert.ok(managed, "issued managed certificate must persist");
    assert.ok(managed.profile_id, "successful issuance must derive a renewal profile");
    const profile = managed.public_metadata?.renewalProfile;
    assert.equal(profile?.target?.type, "windows-iis");
    assert.equal(profile.target.store, "My");
    assert.equal(profile.target.binding.site, site);
    assert.equal(profile.target.binding.port, port);
    assert.equal(profile.acme.commandRef, "qualification-acmesh");
    assert.equal(profile.keyAlgorithm, keyProfile.keyAlgorithm);
    assert.equal(profile.keySize, keyProfile.keySize);
    assert.equal(profile.ca.endpoint, caEndpoint.href);
    assert.equal(profile.dns.provider, "pebble-challtestsrv");
    assert.ok(Date.parse(managed.not_after) <= Date.now() + (managed.renew_before_days || 30) * 86400000, "disposable Pebble leaf must naturally fall within the renewal window");
    const automation = await pool.query("SELECT 1 FROM certops_management_periods WHERE workspace_id=$1 AND managed_certificate_id=$2 AND ended_at IS NULL AND automation_enabled=TRUE", [workspaceId, certificateId]);
    assert.equal(automation.rows.length, 1, "derived profile must enable the active management period");
    await require("./helpers/certops-windows-wrong-leaf").qualifyWrongLeaf({publicSession,pool,workspaceId,agentId,certificateId,configDir,workDir,repoRoot,domain,port,roots,thumbprint,powershell:ps,run:command,waitUntil,ownedJobs});
    const worker = await import(require("node:url").pathToFileURL(path.join(repoRoot, "apps/worker/src/certops-worker.js")).href);
    const schedulerEnv = { ...process.env, CERTOPS_ENABLED: "true" };
    for (const [name, settings] of Object.entries(worker.CERTOPS_SWEEP_CONFIG)) schedulerEnv[settings.enableEnv] = name === "renewal-scheduler" ? "true" : "false";
    await worker.runCertOpsMaintenance({ dbPool: pool, env: schedulerEnv });
    const renewalJob = await waitUntil(async () => (await pool.query("SELECT id,status,payload FROM certificate_jobs WHERE workspace_id=$1 AND subject_id=$2 AND operation='renew' AND source='automation' ORDER BY created_at DESC LIMIT 1", [workspaceId, String(certificateId)])).rows[0]);
    ownedJobs.push(renewalJob.id);
    assert.ok(renewalJob.payload?.renewalProfile, "worker renewal must carry persisted renewal profile");
    await waitUntil(async () => { const row = (await pool.query("SELECT status FROM certificate_jobs WHERE id=$1", [renewalJob.id])).rows[0]; if (["failed", "rejected", "cancelled"].includes(row?.status)) throw new Error(`Windows real renewal terminated ${row.status}`); return row?.status === "succeeded"; });
    const renewed = await new Promise((resolve, reject) => { const connection = tls.connect({ host: "127.0.0.1", port, servername: domain, ca: roots.map((root) => root.pem), rejectUnauthorized: true }, () => { resolve(connection.getPeerCertificate()); connection.end(); }); connection.once("error", reject); connection.setTimeout(10000, () => connection.destroy(new Error("Renewed IIS TLS timeout"))); });
    assert.notEqual(renewed.fingerprint256, observed.fingerprint256, "unattended renewal must replace served leaf");
    deployedThumbprint = renewed.fingerprint.replace(/:/g, "");
    assert.equal(new crypto.X509Certificate(renewed.raw).checkHost(domain), domain);
    assert.ok(command("netsh.exe", ["http", "show", "sslcert", `hostnameport=${domain}:${port}`]).toLowerCase().includes(deployedThumbprint.toLowerCase()), "renewal must update native binding");
    assert.equal(ps(`[bool](Test-Path 'Cert:\\LocalMachine\\My\\${thumbprint}')`), "True", "superseded issued certificate must survive its rollback window");
    assert.ok((await pool.query("SELECT 1 FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2", [workspaceId, renewalJob.id])).rows.length, "unattended renewal evidence must persist");
    const logs = await waitUntil(async () => { const rows = (await pool.query("SELECT message,fields,redaction_count FROM certops_agent_job_log WHERE workspace_id=$1 AND job_id=$2 ORDER BY seq", [workspaceId, job.id])).rows; return rows.length ? rows : null; });
    const serializedLogs = JSON.stringify(logs);
    assert.equal(serializedLogs.includes(plaintextToken), false, "bootstrap credential must not persist in streamed logs");
    assert.equal(/BEGIN (?:RSA |EC )?PRIVATE KEY/.test(serializedLogs), false, "private key material must not persist in streamed logs");
    // Pause the next genuine DNS mutation outside the agent. By this point
    // its real CNG key exists and the local mutation journal is durable.
    holdDns = true;
    await worker.runCertOpsMaintenance({ dbPool: pool, env: schedulerEnv });
    const interruptedJob = await waitUntil(async () => (await pool.query("SELECT id,status,attempt_count FROM certificate_jobs WHERE workspace_id=$1 AND subject_id=$2 AND operation='renew' AND id<>$3 ORDER BY created_at DESC LIMIT 1", [workspaceId, String(certificateId), renewalJob.id])).rows[0]);
    ownedJobs.push(interruptedJob.id);
    await waitUntil(() => heldDnsObserved);
    const journalDir = path.join(configDir, "job-journal");
    const readInterrupted = () => fs.existsSync(journalDir) ? fs.readdirSync(journalDir).filter((name) => name.endsWith(".json")).map((name) => JSON.parse(fs.readFileSync(path.join(journalDir, name), "utf8"))).find((row) => row.jobId === interruptedJob.id && row.windowsCngContainerName) : null;
    const interrupted = await waitUntil(readInterrupted);
    assert.ok(command("certutil.exe", ["-csp", "Microsoft Software Key Storage Provider", "-key"]).includes(interrupted.windowsCngContainerName), "interruption must follow real native key generation");
    const childPid = Number(ps("$s=Get-CimInstance Win32_Service -Filter \"Name='TokenTimerAgent'\"; $children=@(Get-CimInstance Win32_Process -Filter \"ParentProcessId=$($s.ProcessId)\" | Where-Object { $_.Name -eq 'node.exe' }); if ($children.Count -ne 1) { throw 'Expected one owned service child' }; $children[0].ProcessId"));
    assert.ok(Number.isSafeInteger(childPid) && childPid > 0);
    command("taskkill.exe", ["/PID", String(childPid), "/T", "/F"]);
    await waitUntil(() => /STOPPED/.test(command("sc.exe", ["query", "TokenTimerAgent"])), 20000);
    for (const response of heldResponses) response.destroy();
    heldResponses.clear();
    // Advance only this fixture lease deadline after the observed hard
    // crash. A side-effect-capable running attempt must never be requeued.
    const crashed = (await pool.query("SELECT status,attempt_count FROM certificate_jobs WHERE workspace_id=$1 AND id=$2", [workspaceId, interruptedJob.id])).rows[0];
    assert.equal(crashed.status, "running");
    await pool.query("UPDATE certificate_jobs SET lease_expires_at=NOW()-INTERVAL '1 second' WHERE workspace_id=$1 AND id=$2", [workspaceId, interruptedJob.id]);
    const reaperClient = await pool.connect();
    try {
      const result = await worker.reapExpiredLeases({ client: reaperClient, offlineAfterMs: 1, hardGraceMs: 0 });
      assert.ok(result.failed >= 1);
      assert.equal(result.requeued, 0, "real mutation crash must not be silently retried");
    } finally { reaperClient.release(); }
    const orphaned = (await pool.query("SELECT status,attempt_count,needs_operator_reconciliation FROM certificate_jobs WHERE workspace_id=$1 AND id=$2", [workspaceId, interruptedJob.id])).rows[0];
    assert.equal(orphaned.status, "orphaned_unknown_effect");
    assert.equal(orphaned.needs_operator_reconciliation, true);
    assert.equal(orphaned.attempt_count, crashed.attempt_count);
    command("sc.exe", ["start", "TokenTimerAgent"]);
    await waitUntil(() => readInterrupted()?.windowsCngContainerReconciledAt);
    assert.ok(!command("certutil.exe", ["-csp", "Microsoft Software Key Storage Provider", "-key"]).includes(interrupted.windowsCngContainerName), "startup must reconcile orphaned native key");
    const postCrash = await new Promise((resolve, reject) => { const connection = tls.connect({ host: "127.0.0.1", port, servername: domain, ca: roots.map((root) => root.pem), rejectUnauthorized: true }, () => { resolve(connection.getPeerCertificate().fingerprint256); connection.end(); }); connection.once("error", reject); connection.setTimeout(10000, () => connection.destroy(new Error("Post-crash IIS TLS timeout"))); });
    assert.equal(postCrash, renewed.fingerprint256, "mid-renewal hard crash must preserve prior served certificate");
    assert.equal((await pool.query("SELECT attempt_count FROM certificate_jobs WHERE workspace_id=$1 AND id=$2", [workspaceId, interruptedJob.id])).rows[0].attempt_count, crashed.attempt_count, "restart must not repeat an unresolved mutating attempt");
    command("sc.exe", ["failure", "TokenTimerAgent", "reset=", "60", "actions=", "restart/1000"]);
    const retirementLogOffset = fs.statSync(serviceLog).size;
    const registered = (await pool.query("SELECT id FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2", [workspaceId, agentId])).rows[0];
    assert.ok(registered?.id);
    const retirement = await require(path.join(repoRoot, "apps/api/services/certops/agentRegistry")).retireAgent({
      client: pool, workspaceId, agentId: registered.id, retiredBy: userId, reason: "disposable installed Windows qualification" });
    assert.equal(retirement.retiredNow, true);
    await waitUntil(() => /STOPPED/.test(command("sc.exe", ["query", "TokenTimerAgent"])) &&
      /retirement code \(86\)/.test(fs.readFileSync(serviceLog).subarray(retirementLogOffset).toString("utf8")), 30000);
    assert.equal(ps("[string](Get-CimInstance Win32_Service -Filter \"Name='TokenTimerAgent'\").ExitCode"), "0",
      "real authenticated retirement must reach SCM as a clean exit");
    // Five times the explicitly configured recovery delay: retirement may
    // not launch a new service host, despite failure recovery being enabled.
    await new Promise((resolve) => setTimeout(resolve, 5000));
    assert.equal(ps("[string](Get-CimInstance Win32_Service -Filter \"Name='TokenTimerAgent'\").ProcessId"), "0");
    assert.match(command("sc.exe", ["query", "TokenTimerAgent"]), /STOPPED/);
    await require("./helpers/certops-windows-reregistration").qualifyWindowsReregistration({
      baseUrl, workspaceId, oldAgentId: agentId, pool, createBootstrap,
      packageRoot: path.join(workDir, "app"), workDir,
    });
    assert.equal(crypto.createHash("sha256").update(fs.readFileSync(credentialFile)).digest("hex"), credentialDigest,
      "fresh registration in a separate protected state must preserve predecessor credential bytes");
    const afterReregistration = await new Promise((resolve, reject) => { const connection = tls.connect({ host: "127.0.0.1", port, servername: domain, ca: roots.map((root) => root.pem), rejectUnauthorized: true }, () => { resolve(connection.getPeerCertificate().fingerprint256); connection.end(); }); connection.once("error", reject); connection.setTimeout(10000, () => connection.destroy(new Error("Registration preservation TLS timeout"))); });
    assert.equal(afterReregistration, renewed.fingerprint256, "replacement registration must preserve native served certificate");
    const removed = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", installerFixture, "--uninstall"],
      { encoding: "utf8", timeout: 180000 });
    assert.equal(removed.status, 0, "actual candidate product uninstaller failed");
    await waitUntil(() => spawnSync("sc.exe", ["query", "TokenTimerAgent"]).status !== 0, 20000);
    assert.equal(fs.existsSync(path.join(workDir, "app")), false, "uninstaller must remove the installed candidate app");
    assert.equal(crypto.createHash("sha256").update(fs.readFileSync(credentialFile)).digest("hex"), credentialDigest,
      "product uninstaller must preserve the actual registered credential");
    assert.ok(fs.existsSync(path.join(configDir, "config.json")), "product uninstaller must preserve operator state");
    const outputPrivacyReport=await require("./helpers/certops-windows-output-privacy").verifyOutputPrivacy({pool,workspaceId,jobId:job.id,configDir,proof:outputPrivacy,waitUntil,ps,keyProfile});
    fs.mkdirSync("qualification-results",{recursive:true});fs.writeFileSync(`qualification-results/windows-output-privacy-${process.env.CERTOPS_WINDOWS_KEY_PROFILE||"rsa-2048"}.json`,JSON.stringify(outputPrivacyReport));

  } catch (error) {
    journeyFailure = error;
    throw error;
  } finally {
    if (serviceOwned) {
      await cleanup(async () => { ps("$s=Get-Service -Name TokenTimerAgent -ErrorAction SilentlyContinue; if ($s) { if ($s.Status -ne 'Stopped') { Stop-Service -Name TokenTimerAgent }; $s.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(20)) }"); });
      await cleanup(async () => { if (spawnSync("sc.exe", ["query", "TokenTimerAgent"]).status === 0) { command("sc.exe", ["delete", "TokenTimerAgent"]); await waitUntil(() => spawnSync("sc.exe", ["query", "TokenTimerAgent"]).status !== 0, 20000); } });
    }
    if (werTouched) await cleanup(async () => {
      assert.notEqual(spawnSync("sc.exe", ["query", "TokenTimerAgent"]).status, 0, "Restore historical installer policy only after owned service removal");
      const snapshotLiteral = JSON.stringify(werSnapshot).replace(/'/g, "''");
      ps(`$s=ConvertFrom-Json '${snapshotLiteral}'; $p='HKLM:\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps\\node.exe'; if (!$s.exists) { if (Test-Path $p) { Remove-Item -LiteralPath $p -Recurse -Force } } elseif ($null -eq $s.kind) { Remove-ItemProperty -LiteralPath $p -Name DumpType -ErrorAction SilentlyContinue } else { $v=$s.value; switch ($s.kind) { 'Binary' { $v=[byte[]]$v } 'MultiString' { $v=[string[]]$v } 'DWord' { $v=[int]$v } 'QWord' { $v=[long]$v } }; (Get-Item $p).SetValue('DumpType',$v,[Microsoft.Win32.RegistryValueKind]$s.kind) }`);
    });
    if (!werTouched && werSnapshot) await cleanup(async () => { assert.deepEqual(readWerPolicy(), werSnapshot, "Candidate lifecycle must preserve operator WER policy"); });
    await cleanup(async () => { for (const response of heldResponses) response.destroy(); dnsProxy.closeAllConnections(); await new Promise((resolve) => dnsProxy.close(resolve)); });
    if (siteOwned) await cleanup(async () => { ps(`Import-Module WebAdministration; if (Test-Path 'IIS:\\Sites\\${site}') { Remove-Website -Name '${site}' }; & netsh.exe http show sslcert hostnameport=${domain}:${port} | Out-Null; if ($LASTEXITCODE -eq 0) { & netsh.exe http delete sslcert hostnameport=${domain}:${port} | Out-Null; if ($LASTEXITCODE -ne 0) { throw 'Owned binding cleanup failed' } }`); });
    // A lost HTTP response may precede tracking the actual admitted job. Recover
    // only this run's exact public idempotency identity before native cleanup.
    if(publicIssueInput)await cleanup(async()=>{const rows=(await pool.query("SELECT id,subject_id FROM certificate_jobs WHERE workspace_id=$1 AND idempotency_key=$2",[workspaceId,publicIssueInput.body.idempotencyKey])).rows;assert.ok(rows.length<=1);for(const row of rows){if(!ownedJobs.includes(row.id))ownedJobs.push(row.id);if(certificateId)assert.equal(row.subject_id,certificateId);else certificateId=row.subject_id;}});
    const receipts = path.join(configDir, "windows-cert-store", "issued-containers");
    if (fs.existsSync(receipts)) for (const file of fs.readdirSync(receipts)) await cleanup(async () => {
      const record = JSON.parse(fs.readFileSync(path.join(receipts, file), "utf8"));
      if (String(record.certificateId) !== String(certificateId)) return;
      const store = require(path.join(repoRoot, "packages/agent/src/windows-cert-store"));
      const result = record.acceptedThumbprint ? await store.removeCertificateAndKeyContainer({ thumbprint: record.acceptedThumbprint, containerName: record.containerName, store: record.acceptedStore || "My" }) : await store.removeAbandonedKeyContainer({ containerName: record.containerName });
      assert.equal(result.ok, true, "owned agent-issued key cleanup failed");
      assert.ok(!command("certutil.exe", ["-csp", "Microsoft Software Key Storage Provider", "-key"]).includes(record.containerName), "owned issued key remains");
    });
    // The agent records issuance best-effort. Recover only containers whose
    // name embeds this fixture's newly allocated certificate identity if a
    // failure occurred between native key generation and receipt writing.
    if (certificateId) await cleanup(async () => {
      const prefix = `tokentimer-${String(certificateId).replace(/[^A-Za-z0-9_-]/g, "-").slice(0, 64)}-`;
      const leftovers = command("certutil.exe", ["-csp", "Microsoft Software Key Storage Provider", "-key"]).split(/\r?\n/).map((line) => line.trim()).filter((line) => line.startsWith(prefix) && /^[a-f0-9]{8}$/.test(line.slice(prefix.length)));
      for (const containerName of leftovers) {
        const matches = JSON.parse(ps(`$found=@(); Get-ChildItem Cert:\\LocalMachine\\My | ForEach-Object { $c=$_; $k=$null; try { $k=${privateKeyGetter}; if ($k -and $k.Key.KeyName -eq '${containerName}') { $found += $c.Thumbprint } } catch {} finally { if ($k) { $k.Dispose() }; $c.Dispose() } }; ConvertTo-Json -InputObject @($found) -Compress`));
        for (const thumbprint of matches) { assert.match(thumbprint, /^[A-F0-9]{40}$/); ps(`Remove-Item -LiteralPath 'Cert:\\LocalMachine\\My\\${thumbprint}'`); }
        const removed = await require(path.join(repoRoot, "packages/agent/src/windows-cert-store")).removeAbandonedKeyContainer({ containerName });
        assert.equal(removed.ok, true, "partially generated fixture key cleanup failed");
      }
      if (deployedThumbprint) ps(`$p='Cert:\\LocalMachine\\My\\${deployedThumbprint}'; if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p }; if (Test-Path -LiteralPath $p) { throw 'Deployed fixture certificate remains' }`);
    });
    for (const root of roots) await cleanup(async () => ps(`$p='Cert:\\LocalMachine\\${root.store}\\${root.thumbprint}'; if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p }; if (Test-Path -LiteralPath $p) { throw 'Fixture CA trust remains' }`));
    for (const jobId of ownedJobs) for (const table of ["certificate_evidence", "certops_agent_job_log", "certificate_job_log", "certificate_jobs"]) await cleanup(() => pool.query(`DELETE FROM ${table} WHERE workspace_id=$1 AND ${table === "certificate_jobs" ? "id" : "job_id"}=$2`, [workspaceId, jobId]));
    if (certificateId) await cleanup(() => pool.query("DELETE FROM managed_certificates WHERE workspace_id=$1 AND id=$2", [workspaceId, certificateId]));
    if (publicSession) await cleanup(async () => { assert.equal((await pool.query("SELECT COUNT(*)::int AS count FROM certificate_jobs WHERE requested_by_user_id=$1",[publicSession.userId])).rows[0].count,0,"Retain owned actor until all requesting jobs are removed"); await publicSession.cleanup(); if (publicIssuanceFacts) publicIssuanceFacts.ownedActorCleanup = true; });
    if(outputPrivacy)await cleanup(()=>outputPrivacy.close());
    await cleanup(async () => { assert.notEqual(spawnSync("sc.exe", ["query", "TokenTimerAgent"]).status, 0, "retain owned files while a service remains"); fs.rmSync(workDir, { recursive: true, force: true }); });
    if (!journeyFailure && errors.length === 0) {
      require("./helpers/certops-windows-public-issuance").verifyPublicIssuanceFacts(publicIssuanceFacts);
      fs.writeFileSync(publicIssueProofPath,JSON.stringify(publicIssuanceFacts),{flag:"wx"});
    }
    if (errors.length) throw new AggregateError(journeyFailure ? [journeyFailure, ...errors] : errors, "Windows real journey owned cleanup failed", { cause: journeyFailure });
  }
};
