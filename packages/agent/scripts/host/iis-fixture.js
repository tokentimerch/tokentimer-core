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
const { deployIisBinding, checkSniPrecedenceConflict } = require("../../src/windows-iis");

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
    const socket = tls.connect({ host: "127.0.0.1", port, servername, ca, rejectUnauthorized: true }, () => {
      try {
        assert.equal(socket.authorized,true,"Independent TLS probe requires certificate authentication");
        const certificate = socket.getPeerCertificate();
        resolve(certificate.fingerprint.replace(/:/g, ""));
      } catch(error) { reject(error); }
      finally { socket.end(); }
    });
    socket.setTimeout(10000, () => socket.destroy(new Error("Independent TLS probe timeout")));
    socket.once("error", reject);
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
  const binding = { address: "127.0.0.1", port, store: "My", site, ...(sni ? { sniHost: "localhost" } : {}) };
  const endpoint = sni ? `hostnameport=localhost:${port}` : `ipport=127.0.0.1:${port}`;
  const servername = sni ? "localhost" : undefined;
  const failures = [];
  let primaryError;
  let originalFlags;
  const readFlags = () => Number(powershell(`$k=Get-Item -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\HTTP\\Parameters\\SslBindingInfo\\127.0.0.1:${port}'; [uint32]$k.GetValue('DefaultFlags',0)`));
  const readHash = () => powershell(`$k=Get-Item -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\HTTP\\Parameters\\SslBindingInfo\\127.0.0.1:${port}'; [BitConverter]::ToString([byte[]]$k.GetValue('SslCertHash')).Replace('-','')`);
  try {
    powershell(`& netsh.exe http show sslcert ${endpoint} | Out-Null; if ($LASTEXITCODE -eq 0) { throw 'Refusing to replace an existing HTTP.sys binding' }`);
    powershell(`& netsh.exe http show sslcert ipport=127.0.0.1:${unrelatedPort} | Out-Null; if ($LASTEXITCODE -eq 0) { throw 'Refusing to replace unrelated fixture endpoint' }`);
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
    unrelatedOwned = true;
    powershell(`Import-Module WebAdministration; New-WebBinding -Name '${site}' -Protocol https -IPAddress '127.0.0.1' -Port ${unrelatedPort}; (Get-WebBinding -Name '${site}' -Protocol https | Where-Object { $_.bindingInformation -eq '127.0.0.1:${unrelatedPort}:' }).AddSslCertificate('${certificates[0].thumbprint}', 'My')`);
    if (nativeFlags) {
      assert.equal(sni, false, "native registry oracle is for an IP binding");
      run("netsh.exe", ["http", "update", "sslcert", endpoint, `certhash=${certificates[0].thumbprint}`, `appid={${crypto.randomUUID()}}`, "certstorename=My", "disablehttp2=enable", "disablelegacytls=enable"]);
      originalFlags = readFlags();
      assert.equal(originalFlags & 0x410, 0x410, "native flags must actually be set, not just return exit zero");
      assert.equal(readHash(), certificates[0].thumbprint, "registry must confirm original certificate");
    }
    await expectServed(unrelatedPort, certificates[0].thumbprint);
    await expectServed(port, certificates[0].thumbprint, servername);
    if (nativeFlags && gate) await gate.scenario("windows-iis-client-revocation-policy-preservation", async () => {
      const helper = require("./iis-client-settings-fixture");
      gate.report.nativeHttpSysClientSettings = await helper.qualifyClientSettings({ binding, certificates, powershell, run, unrelatedPort, expectServed, pem });
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
          powershell(`$k=Get-Item -LiteralPath '${registryPath}'; $k.SetValue('${fault.name}', ${fault.value}, [Microsoft.Win32.RegistryValueKind]::${fault.type})`);
          const refused = await deployIisBinding({ binding, certificatePem: pem(certificates[3]), verifyTimeoutMs: 3000 });
          assert.equal(refused.ok, false);
          assert.equal(refused.code, "UNSUPPORTED_BINDING_SETTINGS", JSON.stringify(refused));
          assert.equal(refused.rolledBack, false);
          assert.equal(readHash(), certificates[1].thumbprint, "unsupported settings must prevent rebind");
          await expectServed(port, certificates[1].thumbprint);
        } finally {
          powershell(fault.name === "DefaultFlags"
            ? `$k=Get-Item -LiteralPath '${registryPath}'; $k.SetValue('DefaultFlags', [int]${originalFlags}, [Microsoft.Win32.RegistryValueKind]::DWord)`
            : `Remove-ItemProperty -LiteralPath '${registryPath}' -Name '${fault.name}' -ErrorAction SilentlyContinue`);
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
      powershell(`& netsh.exe http show sslcert ipport=127.0.0.1:${port} | Out-Null; if ($LASTEXITCODE -eq 0) { throw 'Refusing to replace pre-existing shadow endpoint' }`);
      shadowOwned = true;
      run("netsh.exe", ["http", "add", "sslcert", `ipport=127.0.0.1:${port}`, `certhash=${certificates[0].thumbprint}`, `appid={${crypto.randomUUID()}}`, "certstorename=My"]);
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
      if (gate) await gate.scenario("windows-iis-rollback-failure", async () => {
        // Remove only the owned predecessor's public store copy. Its exact
        // recorded CNG key remains owned and is deleted by outer teardown.
        run("certutil.exe", ["-delstore", "My", certificates[1].thumbprint]);
        powershell(`if (Test-Path -LiteralPath 'Cert:\\LocalMachine\\My\\${certificates[1].thumbprint}') { throw 'Owned predecessor certificate still present' }`);
        shadowOwned = true;
        run("netsh.exe", ["http", "add", "sslcert", `ipport=127.0.0.1:${port}`, `certhash=${certificates[0].thumbprint}`, `appid={${crypto.randomUUID()}}`, "certstorename=My"]);
        const failedRestore = await deployIisBinding({ binding, certificatePem: pem(certificates[3]), verifyTimeoutMs: 3000 });
        assert.equal(failedRestore.ok, false);
        assert.equal(failedRestore.code, "VERIFY_FAILED");
        assert.equal(failedRestore.rolledBack, false);
        assert.ok(failedRestore.rollbackDetail, "failed native restore must expose diagnostic evidence");
        assert.equal(failedRestore.outgoingThumbprint, certificates[1].thumbprint);
        fs.writeFileSync(path.join(directory, "rollback-failure.json"), JSON.stringify(failedRestore));
        const retainedKey = fs.readFileSync(path.join(directory, "certificate-1.key-receipt"), "utf8").trim();
        assert.match(retainedKey, /^[A-Za-z0-9_.{}-]{1,256}$/);
        powershell(`$provider=[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider; if (-not [Security.Cryptography.CngKey]::Exists('${retainedKey}', $provider, [Security.Cryptography.CngKeyOpenOptions]::MachineKey)) { throw 'Predecessor key unexpectedly removed' }; $output=& netsh.exe http show sslcert ${endpoint}; if ($LASTEXITCODE -eq 0 -and (($output -join '\n') -replace '\\s','').Contains('${certificates[1].thumbprint}')) { throw 'Absent predecessor incorrectly reported restored' }`);
        // An unsuccessful restore must never be presented as restored TLS.
        await expectServed(port, certificates[0].thumbprint, servername);
        await expectServed(unrelatedPort, certificates[0].thumbprint);
        assert.ok(run("netsh.exe", ["http", "show", "sslcert", `ipport=127.0.0.1:${unrelatedPort}`]).toLowerCase().includes(certificates[0].thumbprint.toLowerCase()));
      }, { evidenceLevel: "real-host", oracle: "Owned predecessor public copy absent, real shadow endpoint forces verification failure, native restore fails explicitly, independent live TLS and unrelated binding remain measured" });
    }
  } catch (error) { primaryError = error; throw error; }
  finally {
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
    if (siteCreated) {
      try { powershell(`Import-Module WebAdministration; if (Test-Path 'IIS:\\Sites\\${site}') { Remove-Website -Name '${site}' }; if (Test-Path 'IIS:\\Sites\\${site}') { throw 'Fixture site remains' }`); }
      catch (error) { failures.push(error); }
    }
    if (sslOwned) {
      try { powershell(`$output=& netsh.exe http show sslcert ${endpoint}; if ($LASTEXITCODE -eq 0) { & netsh.exe http delete sslcert ${endpoint} | Out-Null; if ($LASTEXITCODE -ne 0) { throw 'SSL binding cleanup failed' } }; & netsh.exe http show sslcert ${endpoint} | Out-Null; if ($LASTEXITCODE -eq 0) { throw 'SSL binding remains' }`); }
      catch (error) { failures.push(error); }
    }
    if (unrelatedOwned) {
      try { powershell(`& netsh.exe http show sslcert ipport=127.0.0.1:${unrelatedPort} | Out-Null; if ($LASTEXITCODE -eq 0) { & netsh.exe http delete sslcert ipport=127.0.0.1:${unrelatedPort} | Out-Null; if ($LASTEXITCODE -ne 0) { throw 'Unrelated fixture binding cleanup failed' } }; & netsh.exe http show sslcert ipport=127.0.0.1:${unrelatedPort} | Out-Null; if ($LASTEXITCODE -eq 0) { throw 'Unrelated fixture binding remains' }`); }
      catch (error) { failures.push(error); }
    }
    if (shadowOwned) {
      try { powershell(`& netsh.exe http show sslcert ipport=127.0.0.1:${port} | Out-Null; if ($LASTEXITCODE -eq 0) { & netsh.exe http delete sslcert ipport=127.0.0.1:${port} | Out-Null; if ($LASTEXITCODE -ne 0) { throw 'Owned shadow cleanup failed' } }`); }
      catch (error) { failures.push(error); }
    }
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

module.exports = { qualifyIis, freePort, expectServed:expectServedWithTrust, servedThumbprint };
