"use strict";
/* Native retention guard scenarios on recorded local certificate/key and unique IIS bindings.
 * windows-host.test.js supplies ownership facts; production sweep decisions are compared with
 * native store/key/TLS observations, with only fixture sites and directories cleaned.
 */
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { freePort, expectServed } = require("./iis-fixture");
const { createLedgerRow } = require("../../src/windows-retention");
const { runWindowsRetentionSweep } = require("../../src/index");
// These host-suite leaves are signed by the owned CA and carry this exact
// DNS SAN. Keep hostname authentication even though transport is loopback/IP.
function createRetentionTlsProbe({caPem,servername="certops-host.invalid"}={}){
 assert.equal(typeof caPem,"string");assert.equal(new crypto.X509Certificate(caPem).ca,true,"Retention TLS requires the owned public CA");assert.match(servername,/^[a-z0-9.-]+$/i);
 return (port,thumbprint)=>expectServed(port,thumbprint,servername,caPem);
}
async function qualifyRetentionGuards({ powershell, run, workDir, oldThumbprint, replacementThumbprint, containerName }) {
  const expectOwnedServed=createRetentionTlsProbe({caPem:fs.readFileSync(path.join(workDir,"ca.pem"),"utf8")});
  const site = `CertOps-Retention-${crypto.randomUUID()}`;
  const oldPort = await freePort();
  let newPort = await freePort();
  while (newPort === oldPort) newPort = await freePort();
  const directory = path.join(workDir, site);
  fs.mkdirSync(directory);
  fs.writeFileSync(path.join(directory, "index.htm"), "Retention guard qualification");
  const stateDir = path.join(directory, "state");
  const ledgerDir = path.join(stateDir, "windows-retention");
  let siteOwned = false;
  let oldBindingOwned = false;
  let replacementBindingOwned = false;
  let sharedThumbprint;
  let sharedOwned = false;
  let primaryError;
  const cleanupErrors = [];
  try {
    for (const port of [oldPort, newPort]) powershell(`& netsh.exe http show sslcert ipport=127.0.0.1:${port} | Out-Null; if ($LASTEXITCODE -eq 0) { throw 'Refuse existing retention fixture endpoint' }`);
    siteOwned = true;
    powershell(`Import-Module WebAdministration; New-Website -Name '${site}' -PhysicalPath '${directory.replace(/'/g, "''")}' -IPAddress '127.0.0.1' -Port ${oldPort} -Ssl | Out-Null; New-WebBinding -Name '${site}' -Protocol https -IPAddress '127.0.0.1' -Port ${newPort}`);
    oldBindingOwned = true;
    powershell(`Import-Module WebAdministration; (Get-WebBinding -Name '${site}' -Protocol https | Where-Object { $_.bindingInformation -eq '127.0.0.1:${oldPort}:' }).AddSslCertificate('${oldThumbprint}','My')`);
    replacementBindingOwned = true;
    powershell(`Import-Module WebAdministration; (Get-WebBinding -Name '${site}' -Protocol https | Where-Object { $_.bindingInformation -eq '127.0.0.1:${newPort}:' }).AddSslCertificate('${replacementThumbprint}','My')`);
    await expectOwnedServed(oldPort, oldThumbprint);
    await expectOwnedServed(newPort, replacementThumbprint);
    const oldNotAfter = powershell(`(Get-Item 'Cert:\\LocalMachine\\My\\${oldThumbprint}').NotAfter.ToUniversalTime().ToString('o')`);
    createLedgerRow({ ledgerDir, oldThumbprint, replacementThumbprint, cngKeyContainerId: containerName,
      verifiedCutoverAt: new Date().toISOString(), oldNotAfter, ownershipProvenance: "tokentimer_installed", store: "My" });
    const sweep = () => runWindowsRetentionSweep({ stateDir, retentionHours: 24, log: { info() {}, error() {} } });
    let result = await sweep();
    assert.equal(result.removed.length, 0);
    assert.ok(result.deferred.some((row) => row.oldThumbprint === oldThumbprint && row.reason === "binding_still_present"));
    // Issue a second public certificate for the actual old CSR, then repair
    // its association to the same real machine key without any key export.
    const sharedCertificate = path.join(directory, "shared-public.pem");
    run("openssl", ["x509", "-req", "-in", path.join(workDir, "rsa-3072-My", "signing.csr"),
      "-copy_extensions", "copy", "-CA", path.join(workDir, "ca.pem"), "-CAkey", path.join(workDir, "ca.key"),
      "-set_serial", "9001", "-days", "1", "-out", sharedCertificate]);
    sharedThumbprint = new crypto.X509Certificate(fs.readFileSync(sharedCertificate)).fingerprint.replace(/:/g, "");
    assert.notEqual(sharedThumbprint, oldThumbprint);
    assert.equal(powershell(`[bool](Test-Path 'Cert:\\LocalMachine\\My\\${sharedThumbprint}')`), "False");
    sharedOwned = true;
    run("certutil.exe", ["-addstore", "My", sharedCertificate]);
    run("certutil.exe", ["-repairstore", "My", sharedThumbprint]);
    assert.equal(powershell(`$c=Get-Item 'Cert:\\LocalMachine\\My\\${sharedThumbprint}'; $k=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c); try { $k.Key.KeyName } finally { if ($null -ne $k) { $k.Dispose() }; $c.Dispose() }`), containerName,
      "the second certificate must actually share the old CNG key");
    run("netsh.exe", ["http", "delete", "sslcert", `ipport=127.0.0.1:${oldPort}`]);
    oldBindingOwned = false;
    result = await sweep();
    assert.equal(result.removed.length, 0);
    assert.ok(result.deferred.some((row) => row.oldThumbprint === oldThumbprint && row.reason === "shared_key_container"));
    // Remove only the fixture's public copy; its key remains owned by the
    // original certificate and must survive both this removal and the sweep.
    run("certutil.exe", ["-delstore", "My", sharedThumbprint]);
    result = await sweep();
    assert.equal(result.removed.length, 0);
    assert.ok(result.deferred.some((row) => row.oldThumbprint === oldThumbprint && row.reason === "deadline_not_reached"));
    assert.equal(powershell(`[bool]((Get-Item 'Cert:\\LocalMachine\\My\\${oldThumbprint}').HasPrivateKey)`), "True");
    await expectOwnedServed(newPort, replacementThumbprint);
  } catch (error) { primaryError = error; throw error; }
  finally {
    const clean = (action) => { try { action(); } catch (error) { cleanupErrors.push(error); } };
    if (sharedOwned) clean(() => powershell(`$p='Cert:\\LocalMachine\\My\\${sharedThumbprint}'; if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p }; if (Test-Path -LiteralPath $p) { throw 'Owned public shared-key certificate remains' }`));
    if (siteOwned) clean(() => powershell(`Import-Module WebAdministration; if (Test-Path 'IIS:\\Sites\\${site}') { Remove-Website -Name '${site}' }; if (Test-Path 'IIS:\\Sites\\${site}') { throw 'Retention fixture site remains' }`));
    for (const [port, owned] of [[oldPort, oldBindingOwned], [newPort, replacementBindingOwned]]) {
      if (owned) clean(() => powershell(`& netsh.exe http show sslcert ipport=127.0.0.1:${port} | Out-Null; if ($LASTEXITCODE -eq 0) { & netsh.exe http delete sslcert ipport=127.0.0.1:${port} | Out-Null; if ($LASTEXITCODE -ne 0) { throw 'Owned retention endpoint cleanup failed' } }; & netsh.exe http show sslcert ipport=127.0.0.1:${port} | Out-Null; if ($LASTEXITCODE -eq 0) { throw 'Owned retention endpoint remains' }`));
    }
    if (cleanupErrors.length) throw new AggregateError(primaryError ? [primaryError, ...cleanupErrors] : cleanupErrors,
      "Retention fixture cleanup failed", { cause: primaryError });
  }
}
module.exports = { qualifyRetentionGuards, createRetentionTlsProbe };
