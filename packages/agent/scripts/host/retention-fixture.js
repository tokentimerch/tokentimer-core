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
const { inventoryScript, hasSelector } = require("./discovery-http-sys-fixture");
function ownedBinding(rows, port, thumbprint) {
  assert.ok(Array.isArray(rows));
  const selector = `127.0.0.1:${port}`;
  const matches = rows.filter(row => row.kind === "SslBindingInfo" && typeof row.selector === "string" && row.selector.toLowerCase() === selector.toLowerCase());
  assert.equal(matches.length, 1, "Expected exactly one owned retention selector");
  const row = matches[0];
  assert.equal(row.thumbprint, thumbprint);
  assert.equal(String(row.store).toLowerCase(), "my");
  assert.match(row.appId, /^[0-9a-f-]{36}$/i);
  return row;
}
function verifyBindingReceipt(rows, port, thumbprint, receipt) {
  assert.ok(receipt, "Preserve an endpoint without an ownership receipt");
  assert.deepEqual(ownedBinding(rows, port, thumbprint), receipt, "Preserve a changed endpoint");
}
// These host-suite leaves are signed by the owned CA and carry this exact
// DNS SAN. Keep hostname authentication even though transport is loopback/IP.
function createRetentionTlsProbe({caPem,servername="certops-host.invalid"}={}){
 assert.equal(typeof caPem,"string");assert.equal(new crypto.X509Certificate(caPem).ca,true,"Retention TLS requires the owned public CA");assert.match(servername,/^[a-z0-9.-]+$/i);
 return (port,thumbprint)=>expectServed(port,thumbprint,servername,caPem);
}
async function qualifyRetentionGuards({ powershell, run, workDir, oldThumbprint, replacementThumbprint, containerName, gate }) {
  assert.ok(gate && typeof gate.scenario === "function", "Required native reference qualification gate missing");
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
  let oldBindingReceipt, replacementBindingReceipt;
  const nativeBindings = () => JSON.parse(powershell(inventoryScript));
  let sharedThumbprint;
  let sharedOwned = false;
  const crossStoreCopies = [];
  let primaryError;
  const cleanupErrors = [];
  try {
    for (const port of [oldPort, newPort]) assert.equal(hasSelector(nativeBindings(), `127.0.0.1:${port}`), false, "Refuse existing retention fixture endpoint");
    siteOwned = true;
    powershell(`Import-Module WebAdministration; New-Website -Name '${site}' -PhysicalPath '${directory.replace(/'/g, "''")}' -IPAddress '127.0.0.1' -Port ${oldPort} -Ssl | Out-Null; New-WebBinding -Name '${site}' -Protocol https -IPAddress '127.0.0.1' -Port ${newPort}`);
    oldBindingOwned = true;
    powershell(`Import-Module WebAdministration; (Get-WebBinding -Name '${site}' -Protocol https | Where-Object { $_.bindingInformation -eq '127.0.0.1:${oldPort}:' }).AddSslCertificate('${oldThumbprint}','My')`);
    oldBindingReceipt = ownedBinding(nativeBindings(), oldPort, oldThumbprint);
    replacementBindingOwned = true;
    powershell(`Import-Module WebAdministration; (Get-WebBinding -Name '${site}' -Protocol https | Where-Object { $_.bindingInformation -eq '127.0.0.1:${newPort}:' }).AddSslCertificate('${replacementThumbprint}','My')`);
    replacementBindingReceipt = ownedBinding(nativeBindings(), newPort, replacementThumbprint);
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
    verifyBindingReceipt(nativeBindings(), oldPort, oldThumbprint, oldBindingReceipt);
    run("netsh.exe", ["http", "delete", "sslcert", `ipport=127.0.0.1:${oldPort}`]);
    assert.equal(hasSelector(nativeBindings(), `127.0.0.1:${oldPort}`), false);
    oldBindingOwned = false;
    result = await sweep();
    assert.equal(result.removed.length, 0);
    assert.ok(result.deferred.some((row) => row.oldThumbprint === oldThumbprint && row.reason === "shared_key_container"));
    // Remove only the fixture's public copy; its key remains owned by the
    // original certificate and must survive both this removal and the sweep.
    run("certutil.exe", ["-delstore", "My", sharedThumbprint]);
    // Machine KSP custody is shared across stores. Exercise a distinct public
    // leaf and then the exact same certificate mirrored into another store;
    // excluding by thumbprint alone would incorrectly discard the latter.
    for (const [thumbprint, publicFile] of [[sharedThumbprint, sharedCertificate], [oldThumbprint, path.join(workDir, "rsa-3072-My", "issued.pem")]]) {
      assert.equal(powershell(`[bool](Test-Path 'Cert:\\LocalMachine\\WebHosting\\${thumbprint}')`), "False");
      crossStoreCopies.push(thumbprint); // ownership recorded before addstore
      run("certutil.exe", ["-addstore", "WebHosting", publicFile]);
      run("certutil.exe", ["-repairstore", "WebHosting", thumbprint]);
      assert.equal(powershell(`$c=Get-Item 'Cert:\\LocalMachine\\WebHosting\\${thumbprint}';$k=$null;try{$k=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c);$k.Key.KeyName}finally{if($k){$k.Dispose()};$c.Dispose()}`), containerName);
      result = await sweep();
      assert.equal(result.removed.length, 0);
      assert.ok(result.deferred.some(row => row.oldThumbprint === oldThumbprint && row.reason === "shared_key_container"));
      assert.equal(powershell(`[bool]((Get-Item 'Cert:\\LocalMachine\\My\\${oldThumbprint}').HasPrivateKey)`), "True");
      assert.ok(run("certutil.exe", ["-csp", "Microsoft Software Key Storage Provider", "-key"]).includes(containerName));
      await expectOwnedServed(newPort, replacementThumbprint);
      run("certutil.exe", ["-delstore", "WebHosting", thumbprint]);
      assert.equal(powershell(`[bool](Test-Path 'Cert:\\LocalMachine\\WebHosting\\${thumbprint}')`), "False");
    }
    result = await sweep();
    assert.equal(result.removed.length, 0);
    assert.ok(result.deferred.some((row) => row.oldThumbprint === oldThumbprint && row.reason === "deadline_not_reached"));
    assert.equal(powershell(`[bool]((Get-Item 'Cert:\\LocalMachine\\My\\${oldThumbprint}').HasPrivateKey)`), "True");
    await expectOwnedServed(newPort, replacementThumbprint);
    gate.report.nativeRetentionReferences = await require("./retention-reference-fixture").qualifyRetentionReferences({ gate, powershell, ledgerDir, oldThumbprint, replacementThumbprint, containerName, sweep, expectReplacementServed: thumbprint => expectOwnedServed(newPort, thumbprint) });
    return { differentCertificateCrossStoreProtected: true, sameCertificateCrossStoreProtected: true, originalKeyPreserved: true, replacementTrustedTlsPreserved: true, ownedCrossStoreCopiesRemoved: true };
  } catch (error) { primaryError = error; throw error; }
  finally {
    const clean = (action) => { try { action(); } catch (error) { cleanupErrors.push(error); } };
    for (const thumbprint of crossStoreCopies) clean(() => powershell(`$p='Cert:\\LocalMachine\\WebHosting\\${thumbprint}';if(Test-Path -LiteralPath $p){Remove-Item -LiteralPath $p};if(Test-Path -LiteralPath $p){throw 'Owned cross-store public copy remains'}`));
    if (sharedOwned) clean(() => powershell(`$p='Cert:\\LocalMachine\\My\\${sharedThumbprint}'; if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p }; if (Test-Path -LiteralPath $p) { throw 'Owned public shared-key certificate remains' }`));
    if (siteOwned) clean(() => powershell(`Import-Module WebAdministration; if (Test-Path 'IIS:\\Sites\\${site}') { Remove-Website -Name '${site}' }; if (Test-Path 'IIS:\\Sites\\${site}') { throw 'Retention fixture site remains' }`));
    for (const [port, owned, thumbprint, receipt] of [[oldPort, oldBindingOwned, oldThumbprint, oldBindingReceipt], [newPort, replacementBindingOwned, replacementThumbprint, replacementBindingReceipt]]) {
      if (owned) clean(() => {
        const rows = nativeBindings();
        if (!hasSelector(rows, `127.0.0.1:${port}`)) return;
        verifyBindingReceipt(rows, port, thumbprint, receipt);
        run("netsh.exe", ["http", "delete", "sslcert", `ipport=127.0.0.1:${port}`]);
        assert.equal(hasSelector(nativeBindings(), `127.0.0.1:${port}`), false, "Owned retention endpoint remains");
      });
    }
    if (cleanupErrors.length) throw new AggregateError(primaryError ? [primaryError, ...cleanupErrors] : cleanupErrors,
      "Retention fixture cleanup failed", { cause: primaryError });
  }
}
module.exports = { qualifyRetentionGuards, createRetentionTlsProbe, ownedBinding, verifyBindingReceipt };
