/*
 * Qualification notes: installer-cli-second-rename
 * Shared setup, dispatch and evidence rules: docs/certops/e2e-qualification.md.
 * Canonical-root Server2022/2025 lane requires
 * windows-cli-second-rename-owned-fixture,preserves-installed-service,owned-cleanup. Original packed
 * CLI runs byte-identically: measured same-process launcher waits for holder acknowledgment; real
 * source-file oplock holds copy until holder opens staging without delete sharing. Observe actual
 * predecessor rename/restoration after activation fails and explicit incomplete-stage cleanup while
 * handle held. Preserve directory/file identities,running service
 * PID/creation/config/credential/pin,fresh heartbeat and trusted owned self-signed CNG/IIS endpoint;
 * no agent issuance claim. Active guards block uninstall/root deletion until retained exact installer
 * handle exits, holder releases and both children close; timeout10s keeps custody until exit, never
 * kill by name. Public windows-cli-second-rename.json holds3 cases/bounded facts/hashes. IIS reboot
 * request fails; exclude private receipts and native inventories. Separate from function-only
 * mechanics/published upgrades/ARM64/dump containment.
 */
"use strict";
/** Genuine, byte-identical installer CLI at the canonical owned root. A source
 * oplock establishes the staging handle before actual copy resumes. The native
 * CNG/IIS/TLS fixture is operator-created; no agent issuance is claimed.
 * An external test-only launcher invokes the byte-identical original CLI in
 * the same measured PowerShell process after holder registration. This source
 * requires the fresh-host SYSTEM lane and is not run on developer hosts. */
const assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), crypto = require("node:crypto"), net = require("node:net"), tls = require("node:tls");
const mechanics = require("./certops-windows-cli-oplock");
const { canonicalRoot } = require("./certops-windows-fixed-root");
const suite = "windows-installer-cli-second-rename";
const requiredScenarios = ["windows-cli-second-rename-owned-fixture", "windows-cli-second-rename-preserves-installed-service", "windows-cli-second-rename-owned-cleanup"];
const fields = [...mechanics.fields, "originalInstallerCliBytes", "sameRunningLocalSystemServicePid", "configurationCredentialAndPinUnchanged", "freshAuthenticatedHeartbeat", "nonExportableMachineCngCustodyUnchanged", "nativeBindingAndTrustedTlsUnchanged", "ownedCertificateKeyAndEndpointRemoved"];
const requiredSources = ["tests/e2e/helpers/certops-windows-cli-second-rename.js", "tests/e2e/helpers/certops-windows-cli-oplock.js", "tests/e2e/helpers/certops-windows-cli-oplock-driver.ps1", "tests/e2e/helpers/certops-windows-cli-oplock-launcher.ps1", "tests/e2e/helpers/certops-windows-fixed-root.js", "packages/agent/scripts/install-agent.ps1", "packages/agent/src/windows-cert-store/index.js", "packages/agent/src/windows-key-survivors/index.js", "packages/agent/src/issuers/chain-helper.js", "scripts/certops-windows-fixed-root.js", "scripts/certops-windows-fixed-root-cleanup.js", ".github/workflows/certops-windows-fixed-root.yml", "packages/agent/scripts/pack-release.js", "packages/agent/scripts/build-windows-chain-helper.js", "packages/agent/scripts/build-windows-service-host.js"];
function verifyProof(proof) {
  assert.ok(proof && typeof proof === "object" && !Array.isArray(proof)); assert.deepEqual(Object.keys(proof).sort(), [...fields, "scope"].sort());
  assert.equal(proof.scope, "unmodified-installer-cli-canonical-root-operator-cng-binding"); for (const field of fields) assert.equal(proof[field], true, field); return true;
}
function assertEndpointOwned(current, expected) {
  if (current === "absent") return false;
  assert.ok(expected && expected !== "absent", "Endpoint creation ownership was not established");
  const normalize = text => { const value = JSON.parse(text); assert.deepEqual(Object.keys(value).sort(), ["appid", "hash", "store"]); return [value.hash, String(value.store).toLowerCase(), String(value.appid).toLowerCase()]; };
  assert.equal(JSON.stringify(normalize(current)) === JSON.stringify(normalize(expected)), true, "Refuse changed endpoint ownership"); return true;
}
function assertCertificateCustodyOwned(facts, { containerName, thumbprint, der }) {
  assert.ok(facts && typeof facts === "object", "Native certificate custody must be readable");
  assert.equal(facts.container === containerName, true, "Refuse foreign certificate key association");
  assert.equal(facts.provider === "Microsoft Software Key Storage Provider", true, "Refuse foreign key provider");
  assert.equal(facts.machine, true, "Refuse non-machine key custody");
  assert.equal(facts.exportPolicy, 0, "Refuse changed protected key custody"); assert.equal(facts.bits, 2048);
  assert.match(facts.thumbprint, /^[A-F0-9]{40}$/); assert.equal(typeof facts.der, "string"); assert.ok(facts.der.length > 0);
  if (thumbprint) assert.equal(facts.thumbprint === thumbprint, true, "Refuse changed public certificate identity");
  if (der) assert.equal(facts.der === der, true, "Refuse changed public certificate bytes");
}
function assertServiceStable(before, after) {
  const host = path.win32.join(canonicalRoot, "app/bin/tokentimer-agent-host-amd64.exe");
  assert.ok(Number.isInteger(before.pid) && before.pid > 0); assert.equal(before.state, "Running"); assert.equal(before.owner, "S-1-5-18");
  assert.ok(Number.isFinite(Date.parse(before.created))); assert.equal(path.win32.resolve(before.executable).toLowerCase(), host.toLowerCase());
  assert.equal(before.servicePath.toLowerCase().startsWith(('"' + host + '" ').toLowerCase()), true);
  assert.equal(JSON.stringify(before) === JSON.stringify(after), true, "Original LocalSystem service process identity changed");
}
async function freePort() { const server = net.createServer(); await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); }); const port = server.address().port; await new Promise(resolve => server.close(resolve)); return port; }
function trustedPeer(port, pem) { return new Promise((resolve, reject) => { const socket = tls.connect({ host: "127.0.0.1", port, servername: "localhost", ca: pem, rejectUnauthorized: true }, () => { try { assert.equal(socket.authorized, true); resolve(socket.getPeerCertificate().fingerprint.replace(/:/g, "")); } catch (error) { reject(error); } finally { socket.destroy(); } }); socket.once("error", reject); socket.setTimeout(10000, () => socket.destroy(new Error("CLI fault trusted TLS deadline exceeded"))); }); }
async function qualifyCliSecondRename({ pool, workspaceId, agentId, repoRoot, installer, workDir, createBootstrap, baseUrl, configDir, ps, assertRoot }) {
  assert.equal(process.platform, "win32"); assert.equal(process.env.RUNNER_ENVIRONMENT, "github-hosted"); assert.equal(process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST, "1");
  assert.equal(path.resolve(configDir).toLowerCase(), path.join(canonicalRoot, "state").toLowerCase()); assertRoot();
  const original = fs.readFileSync(path.join(repoRoot, "packages/agent/scripts/install-agent.ps1")); assert.deepEqual(fs.readFileSync(installer), original);
  const packageDirectory = path.resolve(installer, "../.."), sourceFile = path.join(packageDirectory, "bin/tokentimer-agent.js");
  const quote = value => value.replace(/'/g, "''"), site = `CertOpsCliOplock-${crypto.randomUUID()}`, subject = `CN=${site}`, port = await freePort();
  const container = `tokentimer-cli-oplock-${crypto.randomBytes(8).toString("hex")}-${crypto.randomBytes(4).toString("hex")}`;
  const directory = fs.mkdtempSync(path.join(workDir, "cli-second-rename-")); fs.writeFileSync(path.join(directory, "index.htm"), "Public CLI fault fixture");
  const receipt = path.join(directory, "public-certificate.receipt");
  const keyExists = () => ps(`[Security.Cryptography.CngKey]::Exists('${container}',[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider,[Security.Cryptography.CngKeyOpenOptions]::MachineKey)`);
  const proof = { scope: "unmodified-installer-cli-canonical-root-operator-cng-binding" };
  let certificate, keyOwned = false, siteOwned = false, bindingOwned = false, primary, beforeEndpoint; const errors = [];
  const assertSite = () => ps(`Import-Module WebAdministration;$s=Get-Website -Name '${site}';if(!$s -or !([IO.Path]::GetFullPath($s.physicalPath)).Equals('${quote(directory)}',[StringComparison]::OrdinalIgnoreCase)){throw 'Refuse changed CLI fixture site'};$b=@(Get-WebBinding -Name '${site}');if($b.Count -ne 1 -or $b[0].protocol -ne 'https' -or $b[0].bindingInformation -ne '127.0.0.1:${port}:'){throw 'Refuse changed CLI fixture bindings'}`);
  const endpoint = () => ps(`$p='HKLM:\\SYSTEM\\CurrentControlSet\\Services\\HTTP\\Parameters\\SslBindingInfo\\127.0.0.1:${port}';if(!(Test-Path -LiteralPath $p)){'absent'}else{$v=Get-ItemProperty -LiteralPath $p;@{hash=[Convert]::ToBase64String($v.SslCertHash);store=[string]$v.SslCertStoreName;appid=([guid]::new([byte[]]$v.AppId)).ToString()}|ConvertTo-Json -Compress}`);
  const hash = file => ({ file, sha256: crypto.createHash("sha256").update(fs.readFileSync(path.join(repoRoot, file))).digest("hex") });
  const gate = require("../../../packages/agent/scripts/host-gate").createHostGate({ suite, strict: true, evidenceLevel: "e2e", reportPath: "qualification-results/windows-cli-second-rename.json", fixtureSource: hash(requiredSources[0]), requiredCapabilities: ["windows", "system", "installedAgent", "api", "iis"], probeCapabilities: () => ({ windows: { available: process.platform === "win32" }, system: { available: ps("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value") === "S-1-5-18" }, installedAgent: { available: ps("(Get-Service TokenTimerAgent).Status") === "Running" }, api: { available: true }, iis: { available: ps("[bool](Get-Module -ListAvailable WebAdministration)") === "True" } }) });
  gate.report.fixtureSources = requiredSources.map(hash); await gate.preflight(); gate.report.qualificationEnvironment.identity = "LocalSystem"; gate.report.qualificationEnvironment.keyProfile = "rsa-2048";
  try {
    let pem, beforeKey, beforeBinding;
    const key = () => JSON.parse(ps(`$c=Get-Item 'Cert:\\LocalMachine\\My\\${certificate.thumbprint}';$k=$null;try{$k=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c);@{container=$k.Key.KeyName;provider=$k.Key.Provider.Provider;machine=$k.Key.IsMachineKey;exportPolicy=[int]$k.Key.ExportPolicy;bits=$k.KeySize;der=[Convert]::ToBase64String($c.RawData)}|ConvertTo-Json -Compress}finally{if($k){$k.Dispose()};$c.Dispose()}`));
    const binding = () => ps(`Import-Module WebAdministration;Get-WebBinding -Name '${site}' -Protocol https|Select-Object bindingInformation,sslFlags,certificateHash,certificateStoreName|ConvertTo-Json -Compress`);
    await gate.scenario(requiredScenarios[0], () => {
      assert.equal(keyExists(), "False"); assert.equal(ps(`[bool](Get-ChildItem Cert:\\LocalMachine\\My | Where-Object Subject -eq '${subject}')`), "False");
      ps(`& netsh.exe http show sslcert ipport=127.0.0.1:${port} | Out-Null;if($LASTEXITCODE -eq 0){throw 'Refuse occupied CLI fixture endpoint'}`);
      keyOwned = true; // Exact random container ownership recorded before native creation.
      certificate = JSON.parse(ps(`$c=New-SelfSignedCertificate -Subject '${subject}' -DnsName localhost -Container '${container}' -Provider 'Microsoft Software Key Storage Provider' -KeyAlgorithm RSA -KeyLength 2048 -KeyExportPolicy NonExportable -CertStoreLocation Cert:\\LocalMachine\\My;try{[IO.File]::WriteAllText('${quote(receipt)}',$c.Thumbprint);@{thumbprint=$c.Thumbprint;der=[Convert]::ToBase64String($c.RawData)}|ConvertTo-Json -Compress}finally{$c.Dispose()}`));
      assert.match(certificate.thumbprint, /^[A-F0-9]{40}$/); pem = new crypto.X509Certificate(Buffer.from(certificate.der, "base64")).toString();
      beforeKey = key(); assert.equal(beforeKey.container, container); assert.equal(beforeKey.provider, "Microsoft Software Key Storage Provider"); assert.equal(beforeKey.machine, true); assert.equal(beforeKey.exportPolicy, 0); assert.equal(beforeKey.bits, 2048);
      assert.equal(ps(`Import-Module WebAdministration;[bool](Test-Path 'IIS:\\Sites\\${site}')`), "False");
      siteOwned = true; ps(`Import-Module WebAdministration;New-Website -Name '${site}' -PhysicalPath '${quote(directory)}' -IPAddress '127.0.0.1' -Port ${port} -Ssl | Out-Null`); assertSite();
      bindingOwned = true; ps(`Import-Module WebAdministration;(Get-WebBinding -Name '${site}' -Protocol https).AddSslCertificate('${certificate.thumbprint}','My')`); beforeBinding = binding(); beforeEndpoint = endpoint(); assert.notEqual(beforeEndpoint, "absent");
      const endpointIdentity = JSON.parse(beforeEndpoint); assert.equal(Buffer.from(endpointIdentity.hash, "base64").toString("hex").toUpperCase(), certificate.thumbprint); assert.equal(endpointIdentity.store.toLowerCase(), "my"); assert.ok(endpointIdentity.appid);
    });
    await gate.scenario(requiredScenarios[1], async () => {
      assert.equal(await trustedPeer(port, pem), certificate.thumbprint);
      const stateIdentity = () => ["config.json", "credential", "signing-key-pin.json"].map(file => crypto.createHash("sha256").update(fs.readFileSync(path.join(configDir, file))).digest("hex"));
      const state = stateIdentity();
      const identity = () => JSON.parse(ps("$s=Get-CimInstance Win32_Service -Filter \"Name='TokenTimerAgent'\";$p=Get-CimInstance Win32_Process -Filter \"ProcessId=$($s.ProcessId)\";@{pid=$s.ProcessId;state=$s.State;owner=(Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid).Sid;created=$p.CreationDate.ToUniversalTime().ToString('o');executable=$p.ExecutablePath;servicePath=$s.PathName}|ConvertTo-Json -Compress"));
      const beforeIdentity = identity(); assertServiceStable(beforeIdentity, beforeIdentity);
      const bootstrap = await createBootstrap();
      const facts = await mechanics.runFault({ installer, installerArgs: ["--api-url", baseUrl, "--workspace-id", String(workspaceId), "--allow-insecure-local-http", "--no-trust-store"], sourceFile, installRoot: canonicalRoot, protocolParent: workDir, environment: { TOKENTIMER_AGENT_BOOTSTRAP_TOKEN: bootstrap.plaintextToken }, onRestored: async () => {
        assertRoot(); assert.deepEqual(fs.readFileSync(installer), original); assertServiceStable(beforeIdentity, identity());
        assert.equal(JSON.stringify(stateIdentity()) === JSON.stringify(state), true, "Protected operator state changed");
        assert.deepEqual(key(), beforeKey); assert.equal(binding(), beforeBinding); assert.equal(await trustedPeer(port, pem), certificate.thumbprint);
        const seen = async () => (await pool.query("SELECT last_seen_at FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2 AND retired_at IS NULL", [workspaceId, agentId])).rows[0]?.last_seen_at;
        const baseline = await seen(); assert.ok(baseline); const until = Date.now() + 60000; let fresh = false;
        while (Date.now() < until) { if (new Date(await seen()).getTime() > new Date(baseline).getTime()) { fresh = true; break; } await new Promise(resolve => setTimeout(resolve, 250)); }
        assert.equal(fresh, true); assertServiceStable(beforeIdentity, identity());
      } });
      Object.assign(proof, facts, { originalInstallerCliBytes: true, sameRunningLocalSystemServicePid: true, configurationCredentialAndPinUnchanged: true, freshAuthenticatedHeartbeat: true, nonExportableMachineCngCustodyUnchanged: true, nativeBindingAndTrustedTlsUnchanged: true });
    });
  } catch (error) { primary = error; }
  finally {
    await gate.scenario(requiredScenarios[2], async () => {
      const clean = action => { try { action(); } catch (error) { errors.push(error); } };
      clean(() => { mechanics.assertCleanupSafe(canonicalRoot); mechanics.assertCleanupSafe(workDir); });
      if (errors.length) throw new AggregateError(errors, "Refuse native fixture cleanup while installer drain is unproven");
      if (bindingOwned) clean(() => { if (!assertEndpointOwned(endpoint(), beforeEndpoint)) return; assertSite(); ps(`& netsh.exe http delete sslcert ipport=127.0.0.1:${port} | Out-Null;if($LASTEXITCODE){throw 'Owned CLI endpoint cleanup failed'}`); });
      if (siteOwned) clean(() => { assertSite(); if (endpoint() !== "absent") throw new Error("Refuse site removal while endpoint ownership is unresolved"); ps(`Import-Module WebAdministration;Remove-Website -Name '${site}';if(Test-Path 'IIS:\\Sites\\${site}'){throw 'Owned CLI fixture site remains'}`); });
      if (errors.length) throw new AggregateError(errors, "Preserve certificate/key while endpoint or site ownership is unresolved");
      if (keyOwned) {
        // The random subject only locates a candidate after partial creation;
        // it never grants deletion authority. Open that certificate's actual
        // RSA CNG association before deleting either public or private state.
        let thumbprint = certificate?.thumbprint;
        clean(() => { const found = JSON.parse(ps(`$found=@(Get-ChildItem Cert:\\LocalMachine\\My | Where-Object Subject -eq '${subject}' | ForEach-Object Thumbprint);ConvertTo-Json -InputObject @($found) -Compress`)); assert.ok(found.length <= 1); if (found.length) { assert.match(found[0], /^[A-F0-9]{40}$/); if (thumbprint) assert.equal(found[0], thumbprint); thumbprint = found[0]; } });
        if (errors.length) throw new AggregateError(errors, "Preserve native custody after certificate identity verification failed");
        try {
          const store = require(path.join(repoRoot, "packages/agent/src/windows-cert-store"));
          if (!thumbprint) {
            assert.equal(keyExists(), "False", "Preserve key without a readable owned certificate association");
          } else {
            const custody = JSON.parse(ps(`$c=Get-Item 'Cert:\\LocalMachine\\My\\${thumbprint}' -ErrorAction Stop;$k=$null;try{$k=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c);if(!$k){throw 'Owned certificate RSA custody unavailable'};@{thumbprint=$c.Thumbprint;container=$k.Key.KeyName;provider=$k.Key.Provider.Provider;machine=$k.Key.IsMachineKey;exportPolicy=[int]$k.Key.ExportPolicy;bits=$k.KeySize;der=[Convert]::ToBase64String($c.RawData)}|ConvertTo-Json -Compress}finally{if($k){$k.Dispose()};$c.Dispose()}`));
            assertCertificateCustodyOwned(custody, { containerName: container, thumbprint: certificate?.thumbprint || thumbprint, der: certificate?.der });
            const result = await store.removeCertificateAndKeyContainer({ thumbprint, containerName: container, store: "My" });
            assert.equal(result.ok, true, "Owned CLI CNG fixture cleanup failed");
          }
          assert.equal(keyExists(), "False");
          if (thumbprint) assert.equal(ps(`[bool](Test-Path 'Cert:\\LocalMachine\\My\\${thumbprint}')`), "False");
        } catch (error) { errors.push(error); }
      }
      if (errors.length) throw new AggregateError(errors, "CLI fixture cleanup failed");
      proof.ownedCertificateKeyAndEndpointRemoved = true;
      if (!primary) { verifyProof(proof); gate.report.nativeCliSecondRename = proof; }
    }).catch(error => errors.push(error));
    await gate.finish({ requiredScenarios }).catch(error => errors.push(error));
  }
  if (primary || errors.length) throw new AggregateError([...(primary ? [primary] : []), ...errors], "Actual installer CLI second-rename qualification failed");
  return gate.report;
}
module.exports = { qualifyCliSecondRename, verifyProof, suite, fields, requiredScenarios, requiredSources, assertEndpointOwned, assertCertificateCustodyOwned, assertServiceStable };
