"use strict";
/* Disposable Windows IIS helper used by windows-host.test.js. Owns uniquely named sites/bindings
 * and public certificate receipts; checks production binding operations with independently
 * trusted TLS and restores only recorded resources. Requires elevated opted-in host, IIS and
 * OpenSSL.
 */

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const net = require("node:net");
const tls = require("node:tls");
const childProcess = require("node:child_process");
const { deployIisBinding: deployNativeIisBinding, checkSniPrecedenceConflict } = require("../../src/windows-iis");
const { listHttpSysBindings } = require("../../src/windows-discovery");

function selectNativeEndpoint(listing, keyedBy, selector) {
  assert.equal(listing?.ok, true, "Complete native endpoint inventory required");
  assert.ok(Array.isArray(listing.bindings));
  for (const row of listing.bindings) {
    assert.ok(row && ["ipport", "hostnameport"].includes(row.keyedBy) && typeof row.ipPort === "string" && row.ipPort.length > 0, "Malformed native endpoint inventory");
  }
  const matches = listing.bindings.filter(row => row.keyedBy === keyedBy && row.ipPort.toLowerCase() === selector.toLowerCase());
  assert.ok(matches.length <= 1, "Ambiguous native endpoint");
  return matches[0] || null;
}
function assertOwnedNativeEndpoint(current, receipt, certificates) {
  assert.ok(receipt && typeof receipt.appId === "string" && receipt.appId, "Exact endpoint receipt required");
  if (current === null) return;
  const normalize = value => String(value).toLowerCase().replace(/[{}]/g, "");
  const appIds = new Set((receipt.appIds?.length ? receipt.appIds : [receipt.appId]).map(normalize));
  assert.ok(appIds.has(normalize(current.appId)), "Preserve replaced endpoint app ID");
  assert.equal(String(current.storeName).toLowerCase(), "my", "Preserve replaced endpoint store");
  assert.ok(certificates.some(c => c.thumbprint === current.thumbprint), "Preserve foreign endpoint certificate");
}
function recordOwnedAppId(args, selectors, certificates, receipts) {
  if (!Array.isArray(args) || args[0] !== "http" || !["add", "update"].includes(args[1]) || args[2] !== "sslcert") return;
  const selector = args.find(value => typeof value === "string" && /^(?:ipport|hostnameport)=/i.test(value));
  const appId = args.find(value => typeof value === "string" && /^appid=\{?[a-f0-9-]{36}\}?$/i.test(value));
  const thumb = args.find(value => typeof value === "string" && /^certhash=[a-f0-9]{40}$/i.test(value));
  if (!selector || !selectors.includes(selector.toLowerCase()) || !appId || !thumb || !args.some(value => /^certstorename=my$/i.test(String(value)))) return;
  if (!certificates.some(c => c.thumbprint.toLowerCase() === thumb.slice(9).toLowerCase())) return;
  const key = selector.toLowerCase();
  receipts.set(key, appId.slice(6).toLowerCase().replace(/[{}]/g, ""));
}

async function freePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  const { port } = server.address();
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  return port;
}
async function servedThumbprint(port, servername, ca) {
  assert.equal(typeof ca,"string");assert.ok(ca.includes("-----BEGIN CERTIFICATE-----"),"Explicit fixture certificate trust is required");
  return new Promise((resolve, reject) => {
    let thumbprint, failure;
    const socket = tls.connect({ host: "127.0.0.1", port, servername, ca, rejectUnauthorized: true }, () => {
      try {
        assert.equal(socket.authorized,true,"Independent TLS probe requires certificate authentication");
        thumbprint=socket.getPeerCertificate().fingerprint.replace(/:/g, "");
      } catch(error) { failure=error; }
      finally { socket.destroy(); }
    });
    socket.setTimeout(10000, () => socket.destroy(new Error("Independent TLS probe timeout")));
    socket.once("error", error=>{failure=error;socket.destroy();});
    // Binding/key cleanup cannot race the fixture's own live TLS connection.
    socket.once("close",()=>{if(failure)reject(failure);else if(thumbprint)resolve(thumbprint);else reject(new Error("Independent TLS probe closed before authentication"));});
  });
}
async function expectServedWithTrust(port, expected, servername, ca) {
  const deadline = Date.now() + 20000;
  let failure;
  do {
    try { assert.equal(await servedThumbprint(port, servername, ca), expected); return; }
    catch (error) { failure = error; }
    await new Promise((resolve) => setTimeout(resolve, 250));
  } while (Date.now() < deadline);
  throw failure;
}

async function qualifyIis({ powershell, run, workDir, sni = false, nativeFlags = false, gate }) {
  const site = `CertOps-${crypto.randomUUID()}`;
  const port = await freePort();
  let unrelatedPort = await freePort();
  while (unrelatedPort === port) unrelatedPort = await freePort();
  const directory = path.join(workDir, site);
  fs.mkdirSync(directory);
  fs.writeFileSync(path.join(directory, "index.htm"), "Certificate qualification fixture");
  const certificates = [];
  const pem = (certificate) => `-----BEGIN CERTIFICATE-----\n${certificate.der}\n-----END CERTIFICATE-----\n`;
  const expectServed=(probePort,expected,probeServername)=>{const certificate=certificates.find(value=>value.thumbprint===expected);assert.ok(certificate?.der,"Owned public certificate required for independent TLS trust");return expectServedWithTrust(probePort,expected,probeServername,pem(certificate));};
  const ownedKeys = new Set();
  let siteCreated = false;
  let sslOwned = false;
  let unrelatedOwned = false;
  let shadowOwned = false;
  let sslReceipt, unrelatedReceipt, shadowReceipt;
  const binding = { address: "127.0.0.1", port, store: "My", site, ...(sni ? { sniHost: "localhost" } : {}) };
  const endpoint = sni ? `hostnameport=localhost:${port}` : `ipport=127.0.0.1:${port}`;
  const selectors = [endpoint.toLowerCase(), `ipport=127.0.0.1:${unrelatedPort}`, `ipport=127.0.0.1:${port}`];
  const issuedAppIds = new Map();
  const trackedExec = (file, args, options, callback) => childProcess.execFile(file, args, options, (error, stdout, stderr) => {
    if (!error && /(?:^|[\\/])netsh(?:\.exe)?$/i.test(file)) recordOwnedAppId(args, selectors, certificates, issuedAppIds);
    callback(error, stdout, stderr);
  });
  const deployIisBinding = options => deployNativeIisBinding({ ...options, execFileImpl: trackedExec });
  const trackedRun = (file, args, options) => {
    const result = run(file, args, options);
    if (/(?:^|[\\/])netsh(?:\.exe)?$/i.test(file)) recordOwnedAppId(args, selectors, certificates, issuedAppIds);
    return result;
  };
  const servername = sni ? "localhost" : undefined;
  const failures = [];
  let primaryError;
  let originalFlags;
  const readFlags = () => Number(powershell(`$k=Get-Item -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\HTTP\\Parameters\\SslBindingInfo\\127.0.0.1:${port}'; [uint32]$k.GetValue('DefaultFlags',0)`));
  const readHash = () => powershell(`$k=Get-Item -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\HTTP\\Parameters\\SslBindingInfo\\127.0.0.1:${port}'; [BitConverter]::ToString([byte[]]$k.GetValue('SslCertHash')).Replace('-','')`);
  const readEndpoint = async (keyedBy, selector) => selectNativeEndpoint(await listHttpSysBindings({}), keyedBy, selector);
  try {
    assert.equal(await readEndpoint(sni ? "hostnameport" : "ipport", sni ? `localhost:${port}` : `127.0.0.1:${port}`), null, "Refusing to replace an existing HTTP.sys binding");
    assert.equal(await readEndpoint("ipport", `127.0.0.1:${unrelatedPort}`), null, "Refusing to replace unrelated fixture endpoint");
    for (let i = 0; i < 4; i += 1) {
      const receipt = path.join(directory, `certificate-${i}.receipt`).replace(/'/g, "''");
      const keyReceipt = path.join(directory, `certificate-${i}.key-receipt`).replace(/'/g, "''");
      const output = powershell(`$c=New-SelfSignedCertificate -Subject 'CN=localhost' -TextExtension @('2.5.29.17={text}DNS=localhost&IPAddress=127.0.0.1') -KeyAlgorithm RSA -KeyLength 2048 -Provider 'Microsoft Software Key Storage Provider' -CertStoreLocation Cert:\\LocalMachine\\My; [IO.File]::WriteAllText('${receipt}', $c.Thumbprint); $k=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c); try { [IO.File]::WriteAllText('${keyReceipt}', $k.Key.KeyName); [pscustomobject]@{thumbprint=$c.Thumbprint; der=[Convert]::ToBase64String($c.RawData)} | ConvertTo-Json -Compress } finally { if ($null -ne $k) { $k.Dispose() }; $c.Dispose() }`);
      const certificate = JSON.parse(output);
      assert.match(certificate.thumbprint, /^[A-F0-9]{40}$/);
      const parsed=new crypto.X509Certificate(Buffer.from(certificate.der,"base64"));assert.equal(parsed.checkHost("localhost"),"localhost");assert.equal(parsed.checkIP("127.0.0.1"),"127.0.0.1");assert.equal(parsed.fingerprint.replace(/:/g,""),certificate.thumbprint);
      certificates.push(certificate);
      fs.writeFileSync(path.join(directory, "owned-certificates.json"), JSON.stringify(certificates.map((c) => c.thumbprint)));
    }
    const physicalPath = directory.replace(/'/g, "''");
    // New-Website creates the binding atomically; mark ownership before setup
    // so a partially completed PowerShell invocation still gets teardown.
    siteCreated = true;
    powershell(`Import-Module WebAdministration; New-Website -Name '${site}' -PhysicalPath '${physicalPath}' -IPAddress '127.0.0.1' -Port ${port} -Ssl ${sni ? "-HostHeader 'localhost'" : ""} | Out-Null; ${sni ? `Set-WebBinding -Name '${site}' -BindingInformation '127.0.0.1:${port}:localhost' -PropertyName sslFlags -Value 1` : ""}`);
    sslOwned = true;
    powershell(`Import-Module WebAdministration; (Get-WebBinding -Name '${site}' -Protocol https).AddSslCertificate('${certificates[0].thumbprint}', 'My')`);
    sslReceipt = await readEndpoint(sni ? "hostnameport" : "ipport", sni ? `localhost:${port}` : `127.0.0.1:${port}`);
    assertOwnedNativeEndpoint(sslReceipt, sslReceipt, certificates);
    unrelatedOwned = true;
    powershell(`Import-Module WebAdministration; New-WebBinding -Name '${site}' -Protocol https -IPAddress '127.0.0.1' -Port ${unrelatedPort}; (Get-WebBinding -Name '${site}' -Protocol https | Where-Object { $_.bindingInformation -eq '127.0.0.1:${unrelatedPort}:' }).AddSslCertificate('${certificates[0].thumbprint}', 'My')`);
    unrelatedReceipt = await readEndpoint("ipport", `127.0.0.1:${unrelatedPort}`);
    assertOwnedNativeEndpoint(unrelatedReceipt, unrelatedReceipt, certificates);
    if (nativeFlags) {
      assert.equal(sni, false, "native registry oracle is for an IP binding");
      run("netsh.exe", ["http", "update", "sslcert", endpoint, `certhash=${certificates[0].thumbprint}`, `appid={${crypto.randomUUID()}}`, "certstorename=My", "disablehttp2=enable", "disablelegacytls=enable"]);
      sslReceipt = await readEndpoint("ipport", `127.0.0.1:${port}`);
      assertOwnedNativeEndpoint(sslReceipt, sslReceipt, certificates);
      originalFlags = readFlags();
      assert.equal(originalFlags & 0x410, 0x410, "native flags must actually be set, not just return exit zero");
      assert.equal(readHash(), certificates[0].thumbprint, "registry must confirm original certificate");
    }
    await expectServed(unrelatedPort, certificates[0].thumbprint);
    await expectServed(port, certificates[0].thumbprint, servername);
    if (nativeFlags && gate) await gate.scenario("windows-iis-client-revocation-policy-preservation", async () => {
      const helper = require("./iis-client-settings-fixture");
      gate.report.nativeHttpSysClientSettings = await helper.qualifyClientSettings({ binding, certificates, powershell, run: trackedRun, unrelatedPort, expectServed, pem, deploy: deployIisBinding });
      helper.verifyProof(gate.report.nativeHttpSysClientSettings);
    }, { evidenceLevel: "real-host", oracle: "Raw HTTP.sys check-mode/timer DWORDs survive genuine owned cutover and native rollback; independent trusted TLS and unrelated endpoint remain unchanged, without a client-auth handshake claim" });
    if (gate && !sni && !nativeFlags) await gate.scenario("windows-iis-unsupported-targets", () => require("./unsupported-target-fixture").qualifyUnsupportedTargets({ binding, certificatePem: pem(certificates[1]), thumbprints: certificates.map(certificate => certificate.thumbprint), powershell, expectServed, originalThumbprint: certificates[0].thumbprint }), { evidenceLevel: "real-host", oracle: "Actual native-platform executor refuses unsupported standalone IIS deploy and multiple SNI renewal destinations; independently read owned store and binding metadata plus live TLS stay unchanged" });
    const result = await deployIisBinding({ binding, certificatePem: pem(certificates[1]), verifyTimeoutMs: 15000 });
    fs.writeFileSync(path.join(directory, "deploy.json"), JSON.stringify(result));
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.equal(result.outgoingThumbprint, certificates[0].thumbprint);
    await expectServed(port, certificates[1].thumbprint, servername);
    const replay = await deployIisBinding({ binding, certificatePem: pem(certificates[1]), verifyTimeoutMs: 15000 });
    assert.equal(replay.ok, true, JSON.stringify(replay));
    assert.equal(replay.skippedMutation, true, "same certificate must verify without rebind");
    const missingQuery = await deployIisBinding({ binding, certificatePem: pem(certificates[3]),
      powershellPath: path.join(directory, "missing-native-query.exe"), verifyTimeoutMs: 3000 });
    assert.equal(missingQuery.ok, false);
    assert.equal(missingQuery.code, "QUERY_FAILED", JSON.stringify(missingQuery));
    assert.equal(missingQuery.rolledBack, false, "query failure must occur before any binding mutation");
    await expectServed(port, certificates[1].thumbprint, servername);
    if (nativeFlags) { assert.equal(readFlags(), originalFlags, "rebind must preserve every native DefaultFlags bit"); assert.equal(readHash(), certificates[1].thumbprint); }
    if (nativeFlags) {
      const registryPath = `HKLM:\\SYSTEM\\CurrentControlSet\\Services\\HTTP\\Parameters\\SslBindingInfo\\127.0.0.1:${port}`;
      const faults = [
        { name: "CertOpsQualificationUnknownSetting", value: "1", type: "DWord" },
        { name: "DefaultSslCtlStoreName", value: "'My'", type: "String" },
        { name: "DefaultFlags", value: `[int](${originalFlags}-2147483648)`, type: "DWord" },
      ];
      for (const fault of faults) {
        if (fault.name !== "DefaultFlags") {
          powershell(`$k=Get-Item -LiteralPath '${registryPath}'; if ($k.GetValueNames() -contains '${fault.name}') { throw 'Refusing pre-existing fixture setting' }; ${fault.name === "DefaultSslCtlStoreName" ? "if ($k.GetValueNames() -contains 'DefaultSslCtlIdentifier') { throw 'Fixture already has CTL identifier' }" : ""}`);
        }
        try {
          // Corrupt only this owned endpoint's persisted native metadata.
          // The real query must refuse to discard an unknown flag/value or
          // incomplete CTL pair, while its live TLS certificate stays intact.
          powershell(`New-ItemProperty -LiteralPath '${registryPath}' -Name '${fault.name}' -Value (${fault.value}) -PropertyType ${fault.type} -Force | Out-Null`);
          const refused = await deployIisBinding({ binding, certificatePem: pem(certificates[3]), verifyTimeoutMs: 3000 });
          assert.equal(refused.ok, false);
          assert.equal(refused.code, "UNSUPPORTED_BINDING_SETTINGS", JSON.stringify(refused));
          assert.equal(refused.rolledBack, false);
          assert.equal(readHash(), certificates[1].thumbprint, "unsupported settings must prevent rebind");
          await expectServed(port, certificates[1].thumbprint);
        } finally {
          powershell(fault.name === "DefaultFlags"
            ? `New-ItemProperty -LiteralPath '${registryPath}' -Name 'DefaultFlags' -Value ([int]${originalFlags}) -PropertyType DWord -Force | Out-Null`
            : `$k=Get-Item -LiteralPath '${registryPath}'; if ($k.GetValueNames() -contains '${fault.name}') { Remove-ItemProperty -LiteralPath '${registryPath}' -Name '${fault.name}' }`);
        }
      }
      assert.equal(readFlags(), originalFlags);
    }
    assert.equal(powershell(`Import-Module WebAdministration; [int](Get-WebBinding -Name '${site}' -Protocol https | Where-Object { $_.bindingInformation -eq '127.0.0.1:${port}:${sni ? "localhost" : ""}' }).sslFlags`), sni ? "1" : "0", "deployment must preserve IIS sslFlags");
    await expectServed(unrelatedPort, certificates[0].thumbprint);
    powershell(`Remove-Item -LiteralPath 'Cert:\\LocalMachine\\My\\${certificates[2].thumbprint}' -DeleteKey`);
    const rollback = await deployIisBinding({ binding, certificatePem: pem(certificates[2]), verifyTimeoutMs: 5000 });
    fs.writeFileSync(path.join(directory, "rollback.json"), JSON.stringify(rollback));
    assert.equal(rollback.ok, false);
    assert.ok(["BIND_FAILED", "VERIFY_FAILED"].includes(rollback.code), JSON.stringify(rollback));
    assert.equal(rollback.rolledBack, true, JSON.stringify(rollback));
    await expectServed(port, certificates[1].thumbprint, servername);
    if (nativeFlags) { assert.equal(readFlags(), originalFlags, "rollback must preserve native flags"); assert.equal(readHash(), certificates[1].thumbprint); }
    if(!sni&&!nativeFlags){
      const association=require("./iis-public-only-fixture"),discovery=require("../../src/windows-discovery");
      const nativeEndpoint=async probePort=>{const listing=await discovery.listHttpSysBindings({});assert.equal(listing.ok,true,"Complete native endpoint inventory required");const rows=listing.bindings.filter(row=>row.keyedBy==="ipport"&&row.ipPort===`127.0.0.1:${probePort}`);assert.equal(rows.length,1,"Exact owned native endpoint required");return{nativeThumb:rows[0].thumbprint,nativeStore:rows[0].storeName};};
      const readPrimary=async()=>{let output;try{output=powershell(`Import-Module WebAdministration;$s=Get-Website -Name '${site}' -ErrorAction Stop;$b=@(Get-WebBinding -Name '${site}' -Protocol https|Where-Object {[string]$_.bindingInformation-ceq'127.0.0.1:${port}:'});if(!$s-or$b.Count-ne 1){throw 'Exact owned IP site required'};$h=$b[0].certificateHash;if($h -is [byte[]]){$h=[BitConverter]::ToString($h).Replace('-','')}else{$h=[string]$h};if($h -notmatch '^[a-fA-F0-9]{40}$'){throw 'Exact native binding hash required'};@{site=[string]$s.Name;id=[long]$s.Id;path=[string]$s.physicalPath;coordinates=[string]$b[0].bindingInformation;flags=[int]$b[0].sslFlags;store=[string]$b[0].certificateStoreName;thumb=$h.ToUpperInvariant()}|ConvertTo-Json -Compress`);}catch(error){const codes=["InvalidCastExceptionScalarToArray","ParameterBindingException","ItemNotFoundException","CommandNotFoundException","RuntimeException"];const code=codes.find(value=>String(error.message).includes(value));error.code=`CERTOPS_IIS_PRIMARY_READ_${code ? code.toUpperCase() : "FAILED"}`;throw error;}const iis=JSON.parse(output);return{...iis,...await nativeEndpoint(port)};};
      let sibling;
      await gate.scenario(association.SCENARIO,async()=>{gate.report.nativeIisPublicOnly=await association.qualify({workDir,certificate:certificates[2],containerName:fs.readFileSync(path.join(directory,"certificate-2.key-receipt"),"utf8").trim(),predecessor:certificates[1],binding,powershell,readPrimary,deploy:deployIisBinding,assertPrimaryTls:()=>expectServed(port,certificates[1].thumbprint,servername),assertSibling:async()=>{await expectServed(unrelatedPort,certificates[0].thumbprint);const actual=await nativeEndpoint(unrelatedPort);assert.equal(actual.nativeThumb,certificates[0].thumbprint);assert.equal(String(actual.nativeStore).toLowerCase(),"my");if(sibling)assert.deepEqual(actual,sibling);else sibling=actual;}});},{evidenceLevel:"real-host",oracle:"Actual public-only My certificate/key absence, production refusal and rollback, independent native predecessor/sibling binding and trusted TLS, exact public-copy removal without key deletion"});
    }
    const raw = run("netsh.exe", ["http", "show", "sslcert", endpoint]);
    assert.ok(raw.toLowerCase().includes(certificates[1].thumbprint.toLowerCase()));
    await expectServed(unrelatedPort, certificates[0].thumbprint);
    assert.ok(run("netsh.exe", ["http", "show", "sslcert", `ipport=127.0.0.1:${unrelatedPort}`]).toLowerCase().includes(certificates[0].thumbprint.toLowerCase()), "unrelated binding changed");
    if (!sni && !nativeFlags) {
      const sharedTarget = { ...binding, port: unrelatedPort };
      const sharedRollout = await deployIisBinding({ binding: sharedTarget,
        certificatePem: pem(certificates[1]), verifyTimeoutMs: 15000 });
      assert.equal(sharedRollout.ok, true, JSON.stringify(sharedRollout));
      assert.equal(sharedRollout.outgoingThumbprint, certificates[0].thumbprint);
      await expectServed(port, certificates[1].thumbprint);
      await expectServed(unrelatedPort, certificates[1].thumbprint);
      const failedTarget = await deployIisBinding({ binding,
        certificatePem: pem(certificates[2]), verifyTimeoutMs: 3000 });
      assert.equal(failedTarget.ok, false);
      assert.equal(failedTarget.rolledBack, true);
      await expectServed(port, certificates[1].thumbprint);
      await expectServed(unrelatedPort, certificates[1].thumbprint);
    }
    if (sni) {
      assert.equal(await checkSniPrecedenceConflict({ binding }), undefined, "control SNI binding must have no false shadow warning");
      assert.equal(await readEndpoint("ipport", `127.0.0.1:${port}`), null, "Refusing to replace pre-existing shadow endpoint");
      shadowOwned = true;
      run("netsh.exe", ["http", "add", "sslcert", `ipport=127.0.0.1:${port}`, `certhash=${certificates[0].thumbprint}`, `appid={${crypto.randomUUID()}}`, "certstorename=My"]);
      shadowReceipt = await readEndpoint("ipport", `127.0.0.1:${port}`);
      assertOwnedNativeEndpoint(shadowReceipt, shadowReceipt, certificates);
      assert.ok(run("netsh.exe", ["http", "show", "sslcert", `ipport=127.0.0.1:${port}`]).toLowerCase().includes(certificates[0].thumbprint.toLowerCase()));
      const warning = await checkSniPrecedenceConflict({ binding });
      assert.ok(warning?.includes(`ipport=127.0.0.1:${port}`), "native concrete-IP shadow must be detected");
      assert.ok(warning.includes(`hostnameport=localhost:${port}`));
      // This real concrete-IP binding wins over the hostname binding. A new
      // valid SNI certificate therefore binds successfully but fails the
      // independent TLS oracle, exercising actual post-bind rollback.
      const verifyFailure = await deployIisBinding({ binding, certificatePem: pem(certificates[3]), verifyTimeoutMs: 3000 });
      assert.equal(verifyFailure.ok, false);
      assert.equal(verifyFailure.code, "VERIFY_FAILED", JSON.stringify(verifyFailure));
      assert.equal(verifyFailure.rolledBack, true, JSON.stringify(verifyFailure));
      assert.ok(run("netsh.exe", ["http", "show", "sslcert", endpoint]).toLowerCase().includes(certificates[1].thumbprint.toLowerCase()), "failed verification must restore the SNI endpoint certificate");
      await expectServed(port, certificates[0].thumbprint, servername);
      run("netsh.exe", ["http", "delete", "sslcert", `ipport=127.0.0.1:${port}`]);
      shadowOwned = false;
      assert.equal(await checkSniPrecedenceConflict({ binding }), undefined, "removing owned shadow must clear warning");
      await expectServed(port, certificates[1].thumbprint, servername);
      if (gate) await gate.scenario("windows-iis-ipv4-wildcard-sni-precedence", async () => {
        // Each variant completes exact owned cleanup before the next borrows
        // the same certificate custody. No installed-agent claim is inferred.
        const fixture = require("./ipv4-wildcard-fixture");
        gate.report.nativeIpv4WildcardPrecedence = await fixture.qualifyIpv4Wildcard({ certificates, powershell, run, workDir });
        fixture.verifyProof(gate.report.nativeIpv4WildcardPrecedence);
        gate.report.fixtureSources ||= [];
        for (const file of fixture.REQUIRED_SOURCES) if (!gate.report.fixtureSources.some(source => source.file === file)) gate.report.fixtureSources.push({file,sha256:crypto.createHash("sha256").update(fs.readFileSync(path.resolve(__dirname,"../../../..",file))).digest("hex")});
      }, { evidenceLevel: "real-host", oracle: "Actual IPv4 wildcard yields to exact SNI; production cutover and trusted TLS succeed while the IPv4 sibling stays unchanged" });
      if (gate) await gate.scenario("windows-iis-ipv6-native-shadow-rollback", async () => {
        const fixture = require("./ipv6-shadow-fixture");
        gate.report.nativeIpv6SniShadow = await fixture.qualifyIpv6Shadow({ certificates, powershell, run, workDir });
        fixture.verifyProof(gate.report.nativeIpv6SniShadow);
        gate.report.fixtureSources ||= [];
        for (const file of fixture.REQUIRED_SOURCES) if (!gate.report.fixtureSources.some(source => source.file === file)) gate.report.fixtureSources.push({file,sha256:crypto.createHash("sha256").update(fs.readFileSync(path.resolve(__dirname,"../../../..",file))).digest("hex")});
      }, { evidenceLevel: "real-host", oracle: "Actual IPv6 HTTP.sys shadow causes real production verification failure and rollback; native endpoint and independently trusted IPv6 TLS recover, separate IPv4 sibling stays unchanged" });
      if (gate) await gate.scenario("windows-iis-ipv6-wildcard-sni-precedence", async () => {
        const fixture = require("./ipv6-wildcard-fixture");
        gate.report.nativeIpv6WildcardPrecedence = await fixture.qualifyIpv6Wildcard({ certificates, powershell, run, workDir });
        fixture.verifyProof(gate.report.nativeIpv6WildcardPrecedence);
        for (const file of fixture.REQUIRED_SOURCES) if (!gate.report.fixtureSources.some(source => source.file === file)) gate.report.fixtureSources.push({file,sha256:crypto.createHash("sha256").update(fs.readFileSync(path.resolve(__dirname,"../../../..",file))).digest("hex")});
      }, { evidenceLevel: "real-host", oracle: "Actual IPv6 wildcard yields to exact SNI; production cutover and trusted TLS succeed while the IPv4 sibling stays unchanged" });
      if (gate) await gate.scenario("windows-iis-rollback-failure", async () => {
        // Remove only the owned predecessor's public store copy. Its exact
        // recorded CNG key remains owned and is deleted by outer teardown.
        run("certutil.exe", ["-delstore", "My", certificates[1].thumbprint]);
        powershell(`if (Test-Path -LiteralPath 'Cert:\\LocalMachine\\My\\${certificates[1].thumbprint}') { throw 'Owned predecessor certificate still present' }`);
        shadowOwned = true;
        run("netsh.exe", ["http", "add", "sslcert", `ipport=127.0.0.1:${port}`, `certhash=${certificates[0].thumbprint}`, `appid={${crypto.randomUUID()}}`, "certstorename=My"]);
        shadowReceipt = await readEndpoint("ipport", `127.0.0.1:${port}`);
        assertOwnedNativeEndpoint(shadowReceipt, shadowReceipt, certificates);
        const failedRestore = await deployIisBinding({ binding, certificatePem: pem(certificates[3]), verifyTimeoutMs: 3000 });
        assert.equal(failedRestore.ok, false);
        assert.equal(failedRestore.code, "VERIFY_FAILED");
        assert.equal(failedRestore.rolledBack, false);
        assert.ok(failedRestore.rollbackDetail, "failed native restore must expose diagnostic evidence");
        assert.equal(failedRestore.outgoingThumbprint, certificates[1].thumbprint);
        fs.writeFileSync(path.join(directory, "rollback-failure.json"), JSON.stringify(failedRestore));
        const retainedKey = fs.readFileSync(path.join(directory, "certificate-1.key-receipt"), "utf8").trim();
        assert.match(retainedKey, /^[A-Za-z0-9_.{}-]{1,256}$/);
        powershell(`$provider=[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider; if (-not [Security.Cryptography.CngKey]::Exists('${retainedKey}', $provider, [Security.Cryptography.CngKeyOpenOptions]::MachineKey)) { throw 'Predecessor key unexpectedly removed' }`);
        const restoredEndpoint = await readEndpoint("hostnameport", `localhost:${port}`);
        assert.notEqual(restoredEndpoint?.thumbprint, certificates[1].thumbprint, "Absent predecessor incorrectly reported restored");
        // An unsuccessful restore must never be presented as restored TLS.
        await expectServed(port, certificates[0].thumbprint, servername);
        await expectServed(unrelatedPort, certificates[0].thumbprint);
        assert.ok(run("netsh.exe", ["http", "show", "sslcert", `ipport=127.0.0.1:${unrelatedPort}`]).toLowerCase().includes(certificates[0].thumbprint.toLowerCase()));
      }, { evidenceLevel: "real-host", oracle: "Owned predecessor public copy absent, real shadow endpoint forces verification failure, native restore fails explicitly, independent live TLS and unrelated binding remain measured" });
    }
  } catch (error) { primaryError = error; throw error; }
  finally {
    require("./iis-public-only-fixture").assertCleanupSafe(workDir);
    // Preserve certificate keys still borrowed by an unresolved nested fixture.
    require("./ipv6-shadow-fixture").assertCleanupSafe(workDir);
    for (let i = 0; i < 4; i += 1) {
      const receipt = path.join(directory, `certificate-${i}.receipt`);
      if (fs.existsSync(receipt)) {
        const thumbprint = fs.readFileSync(receipt, "utf8").trim();
        if (/^[A-F0-9]{40}$/.test(thumbprint) && !certificates.some((c) => c.thumbprint === thumbprint)) certificates.push({ thumbprint });
      }
      const keyReceipt = path.join(directory, `certificate-${i}.key-receipt`);
      if (fs.existsSync(keyReceipt)) {
        const name = fs.readFileSync(keyReceipt, "utf8").trim();
        if (/^[A-Za-z0-9_.{}-]{1,256}$/.test(name)) ownedKeys.add(name);
        else failures.push(new Error("Malformed owned IIS key receipt"));
      }
    }
    const cleanupEndpoints = [
      ...(sslOwned ? [{ keyedBy: sni ? "hostnameport" : "ipport", selector: sni ? `localhost:${port}` : `127.0.0.1:${port}`, receipt: sslReceipt }] : []),
      ...(unrelatedOwned ? [{ keyedBy: "ipport", selector: `127.0.0.1:${unrelatedPort}`, receipt: unrelatedReceipt }] : []),
      ...(shadowOwned ? [{ keyedBy: "ipport", selector: `127.0.0.1:${port}`, receipt: shadowReceipt }] : []),
    ];
    for (const item of cleanupEndpoints) if (item.receipt) { const latest = issuedAppIds.get(`${item.keyedBy}=${item.selector}`.toLowerCase()); item.receipt = { ...item.receipt, appIds: latest ? [latest] : [] }; }
    // Inspect every endpoint before deleting the site or any certificate.
    for (const item of cleanupEndpoints) assertOwnedNativeEndpoint(await readEndpoint(item.keyedBy, item.selector), item.receipt, certificates);
    if (siteCreated) {
      try { powershell(`Import-Module WebAdministration; if (Test-Path 'IIS:\\Sites\\${site}') { Remove-Website -Name '${site}' }; if (Test-Path 'IIS:\\Sites\\${site}') { throw 'Fixture site remains' }`); }
      catch (error) { failures.push(error); }
    }
    for (const item of cleanupEndpoints) {
      try {
        const current = await readEndpoint(item.keyedBy, item.selector);
        assertOwnedNativeEndpoint(current, item.receipt, certificates);
        if (current) run("netsh.exe", ["http", "delete", "sslcert", `${item.keyedBy}=${item.selector}`]);
        assert.equal(await readEndpoint(item.keyedBy, item.selector), null, "Owned SSL binding remains");
      } catch (error) { failures.push(error); }
    }
    if (failures.length) throw new AggregateError(primaryError ? [primaryError, ...failures] : failures, "IIS fixture endpoint cleanup failed", { cause: primaryError });
    for (const certificate of certificates) {
      try { powershell(`$p='Cert:\\LocalMachine\\My\\${certificate.thumbprint}'; if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -DeleteKey }; if (Test-Path -LiteralPath $p) { throw 'Fixture certificate remains' }`); }
      catch (error) { failures.push(error); }
    }
    for (const name of ownedKeys) {
      try { powershell(`$provider=[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider; $options=[Security.Cryptography.CngKeyOpenOptions]::MachineKey; if ([Security.Cryptography.CngKey]::Exists('${name}', $provider, $options)) { $k=[Security.Cryptography.CngKey]::Open('${name}', $provider, $options); try { $k.Delete() } finally { $k.Dispose() } }; if ([Security.Cryptography.CngKey]::Exists('${name}', $provider, $options)) { throw 'Owned IIS key remains' }`); }
      catch (error) { failures.push(error); }
    }
    if (failures.length) throw new AggregateError(primaryError ? [primaryError, ...failures] : failures, "IIS fixture cleanup failed", { cause: primaryError });
  }
}

module.exports = { qualifyIis, freePort, expectServed:expectServedWithTrust, servedThumbprint, selectNativeEndpoint, assertOwnedNativeEndpoint, recordOwnedAppId };
