"use strict";
/* Actual elapsed native retention qualification invoked by windows-host.test.js. Uses owned
 * certificates/ledger state and the supported short grace period, retaining real clock semantics;
 * checks deletion and interruption recovery without claiming a default 24-hour wait.
 */
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const tls = require("node:tls");
const { freePort } = require("./iis-fixture");
const { generateCsrViaCng, buildEnrollmentContainerName, acceptCertificateViaCng, removeAbandonedKeyContainer } = require("../../src/windows-cert-store");
const { deployIisBinding } = require("../../src/windows-iis");
const retention = require("../../src/windows-retention");
const { runWindowsRetentionSweep } = require("../../src/index");
async function trustedLeaf(port, ca, expected) {
  const once = () => new Promise((resolve, reject) => {
    const socket = tls.connect({ host: "127.0.0.1", port, servername: "certops-host.invalid", ca, rejectUnauthorized: true }, () => {
      try { assert.equal(socket.authorized, true); assert.equal(socket.getPeerCertificate().fingerprint.replace(/:/g, ""), expected); resolve(); }
      catch (error) { reject(error); }
      finally { socket.destroy(); }
    });
    socket.setTimeout(10000, () => socket.destroy(new Error("Trusted retention handshake timed out")));
    socket.once("error", reject);
  });
  const deadline = Date.now() + 20000;
  let failure;
  do {
    try { await once(); return; }
    catch (error) { failure = error; }
    await new Promise((resolve) => setTimeout(resolve, 250));
  } while (Date.now() < deadline);
  throw failure;
}
async function qualifyElapsedRetention({ gate, powershell, run, workDir, replacementPem, replacementThumbprint }) {
  const enrollmentId = crypto.randomUUID();
  const containerName = buildEnrollmentContainerName(enrollmentId);
  const directory = path.join(workDir, `elapsed-retention-${enrollmentId}`); fs.mkdirSync(directory);
  const site = `CertOps-Elapsed-${enrollmentId}`;
  const port = await freePort();
  const quote = (value) => value.replace(/'/g, "''");
  let siteOwned = false, endpointOwned = false, keyOwned = false, certificateOwned = false, oldThumbprint;
  let primaryError;
  try {
    assert.ok(!run("certutil.exe", ["-csp", "Microsoft Software Key Storage Provider", "-key"]).includes(containerName));
    keyOwned = true; // deterministic key ownership precedes certreq mutation
    const csr = await generateCsrViaCng({ commonName: "certops-host.invalid", altNames: ["certops-host.invalid"], algorithm: "rsa-2048", enrollmentId, workDir: directory });
    assert.equal(csr.ok, true);
    const csrPath = path.join(directory, "short-lived.csr"); fs.writeFileSync(csrPath, csr.csrPem);
    const ca = fs.readFileSync(path.join(workDir, "ca.pem"), "utf8");
    const opensslPath = (file) => '"' + file.replaceAll("\\", "/") + '"';
    fs.writeFileSync(path.join(directory, "index.txt"), ""); fs.writeFileSync(path.join(directory, "serial"), "B001\n");
    const signer = path.join(directory, "signer.cnf");
    fs.writeFileSync(signer, `[ca]\ndefault_ca=qualification\n[qualification]\ndatabase=${opensslPath(path.join(directory, "index.txt"))}\nserial=${opensslPath(path.join(directory, "serial"))}\nnew_certs_dir=${opensslPath(directory)}\ncertificate=${opensslPath(path.join(workDir, "ca.pem"))}\nprivate_key=${opensslPath(path.join(workDir, "ca.key"))}\ndefault_md=sha256\npolicy=subject\ncopy_extensions=copy\ndefault_days=1\n[subject]\ncommonName=supplied\n`);
    const stamp = (date) => date.toISOString().replace(/[-:]/g, "").replace("T", "").replace(/\.\d+Z$/, "Z");
    const leafPath = path.join(directory, "short-lived.pem");
    const signingTime = Date.now();
    run("openssl", ["ca", "-batch", "-notext", "-config", signer, "-in", csrPath, "-out", leafPath,
      "-startdate", stamp(new Date(signingTime - 60000)), "-enddate", stamp(new Date(signingTime + 120000))]);
    const oldPem = fs.readFileSync(leafPath, "utf8");
    const oldCertificate = new crypto.X509Certificate(oldPem);
    assert.equal(oldCertificate.verify(new crypto.X509Certificate(ca).publicKey), true);
    oldThumbprint = oldCertificate.fingerprint.replace(/:/g, "");
    assert.equal(powershell(`[bool](Test-Path 'Cert:\\LocalMachine\\My\\${oldThumbprint}')`), "False");
    certificateOwned = true;
    assert.equal((await acceptCertificateViaCng({ certificatePem: oldPem, workDir: directory, store: "My" })).ok, true);
    const custody = JSON.parse(powershell(`$c=Get-Item 'Cert:\\LocalMachine\\My\\${oldThumbprint}'; $k=$null; try { $k=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c); [pscustomobject]@{name=$k.Key.KeyName;exportPolicy=[string]$k.Key.ExportPolicy} | ConvertTo-Json -Compress } finally { if ($null -ne $k) { $k.Dispose() }; $c.Dispose() }`));
    assert.equal(custody.name, containerName);
    assert.equal(custody.exportPolicy, "None");
    const nativeExpiry = powershell(`(Get-Item 'Cert:\\LocalMachine\\My\\${oldThumbprint}').NotAfter.ToUniversalTime().ToString('o')`);
    assert.equal(Date.parse(nativeExpiry), Date.parse(oldCertificate.validTo));
    powershell(`& netsh.exe http show sslcert ipport=127.0.0.1:${port} | Out-Null; if ($LASTEXITCODE -eq 0) { throw 'Refuse preexisting elapsed-retention endpoint' }; Import-Module WebAdministration; if (Test-Path 'IIS:\\Sites\\${site}') { throw 'Refuse preexisting fixture site' }`);
    fs.writeFileSync(path.join(directory, "index.htm"), "Elapsed retention fixture");
    siteOwned = true;
    powershell(`Import-Module WebAdministration; New-Website -Name '${site}' -PhysicalPath '${quote(directory)}' -IPAddress '127.0.0.1' -Port ${port} -Ssl | Out-Null`);
    endpointOwned = true;
    powershell(`Import-Module WebAdministration; (Get-WebBinding -Name '${site}' -Protocol https | Where-Object { $_.bindingInformation -eq '127.0.0.1:${port}:' }).AddSslCertificate('${oldThumbprint}','My')`);
    await trustedLeaf(port, ca, oldThumbprint);
    assert.ok(Date.now() < Date.parse(nativeExpiry), "old certificate must really be valid at cutover");
    assert.equal((await deployIisBinding({ binding: { site, address: "127.0.0.1", port, store: "My" }, certificatePem: replacementPem, verifyTimeoutMs: 15000 })).ok, true);
    await trustedLeaf(port, ca, replacementThumbprint);
    const cutover = new Date().toISOString();
    const stateDir = path.join(directory, "state"); const ledgerDir = path.join(stateDir, "windows-retention");
    retention.createLedgerRow({ ledgerDir, oldThumbprint, replacementThumbprint, cngKeyContainerId: containerName,
      verifiedCutoverAt: cutover, oldNotAfter: nativeExpiry, ownershipProvenance: "tokentimer_installed", store: "My" });
    const deadline = retention.computeCleanupDeadline({ verifiedCutoverAt: cutover, oldNotAfter: nativeExpiry, retentionHours: 24 });
    assert.equal(deadline.getTime(), Date.parse(nativeExpiry) + 300000, "qualify actual supported expiry-grace deadline, not shortened configured retention");
    assert.ok(deadline.getTime() > Date.now() && deadline.getTime() - Date.now() < 600000);
    const sweep = () => runWindowsRetentionSweep({ stateDir, retentionHours: 24, log: { info() {}, error() {} } });
    const early = await sweep();
    assert.equal(early.removed.length, 0);
    assert.ok(early.deferred.some((row) => row.oldThumbprint === oldThumbprint && row.reason === "deadline_not_reached"));
    // Wait the real wall clock; no injected clock, ledger date rewrite,
    // eligibility context, tool or TLS implementation is supplied.
    const waitStarted = process.hrtime.bigint();
    while (Date.now() <= deadline.getTime()) {
      assert.ok(process.hrtime.bigint() - waitStarted < 600000000000n, "real-clock deadline wait exceeded its independent ten-minute monotonic bound");
      await new Promise((resolve) => setTimeout(resolve, Math.min(5000, deadline.getTime() - Date.now() + 250)));
    }
    await gate.scenario("windows-retention-native-interrupted-delete", async () => {
      const child = require("node:child_process").spawnSync(process.execPath, [path.join(__dirname, "retention-interrupted-child.js"), stateDir, oldThumbprint, containerName], { encoding: "utf8", timeout: 90000, windowsHide: true });
      assert.ifError(child.error); assert.equal(child.signal, null); assert.equal(child.status, 86, "Actual native certificate deletion must reach the required child fault boundary");
      const fault = JSON.parse(fs.readFileSync(path.join(stateDir, "interrupted-native-delete.json"), "utf8"));
      assert.equal(fault.nativeCommandSucceeded, true); assert.equal(fault.thumbprint, oldThumbprint); assert.equal(fault.containerName, containerName); assert.ok(Number.isInteger(fault.pid) && fault.pid > 0); assert.equal(fault.pid, child.pid, "Fault evidence must identify the exact completed owned child");
      const lockPath = path.join(stateDir, "windows-cert-store", "My.lock"); const marker = fs.readFileSync(lockPath, "utf8").trim().split(/\r?\n/); assert.equal(marker.length, 3); assert.equal(marker[0], String(child.pid)); assert.ok(Number.isFinite(Date.parse(marker[1]))); assert.match(marker[2], /^[a-f0-9]{32}$/);
      assert.equal(powershell(`[bool](Test-Path 'Cert:\\LocalMachine\\My\\${oldThumbprint}')`), "False");
      assert.ok(run("certutil.exe", ["-csp", "Microsoft Software Key Storage Provider", "-key"]).includes(containerName), "Crash must leave the actual owned key awaiting cleanup");
      assert.notEqual(retention.readLedgerRow(ledgerDir, oldThumbprint).lifecycleState, "removed", "Interrupted native collector cannot record a completed cleanup");
      await trustedLeaf(port, ca, replacementThumbprint);
      const retryDeadline = Date.now() + 30000; let resumed;
      do { resumed = await sweep(); if (resumed.removed.includes(oldThumbprint)) break; await new Promise(resolve => setTimeout(resolve, 1000)); } while (Date.now() < retryDeadline);
      assert.equal(fs.existsSync(lockPath), false, "Completed native retry must remove its own lock marker");
      assert.deepEqual(resumed.removed, [oldThumbprint], "Native retry must reclaim the dead owned store lock, remove the retained key and persist cleanup");
      assert.equal(retention.readLedgerRow(ledgerDir, oldThumbprint).lifecycleState, "removed");
      assert.ok(!run("certutil.exe", ["-csp", "Microsoft Software Key Storage Provider", "-key"]).includes(containerName));
      await trustedLeaf(port, ca, replacementThumbprint);
    }, { evidenceLevel: "real-host", oracle: "real expired eligible certificate, actual native delstore success followed by owned child crash before delkey, independently observed retained key/incomplete ledger, actual native sweep resumes and persists cleanup while trusted replacement survives" });
    assert.equal(retention.readLedgerRow(ledgerDir, oldThumbprint).lifecycleState, "removed");
    assert.equal(powershell(`[bool](Test-Path 'Cert:\\LocalMachine\\My\\${oldThumbprint}')`), "False");
    assert.ok(!run("certutil.exe", ["-csp", "Microsoft Software Key Storage Provider", "-key"]).includes(containerName));
    await trustedLeaf(port, ca, replacementThumbprint);
    fs.writeFileSync(path.join(workDir, "windows-retention-elapsed.log"), JSON.stringify({ mode: "real-clock-expiry-grace", configuredRetentionHours: 24,
      oldNotAfter: nativeExpiry, verifiedCutoverAt: cutover, cleanupDeadline: deadline.toISOString(), observedCleanupAt: new Date().toISOString(),
      waitedMonotonicMs: Number(process.hrtime.bigint() - waitStarted) / 1000000,
      oldCertificateAndKeyAbsent: true, replacementTrustedTls: true, interruptedNativeDeletionQualified: true, faultMode: "owned-child-exit-after-native-delstore-before-delkey", fullRetentionWindowQualified: false }));
  } catch (error) { primaryError = error; throw error; }
  finally {
    const failures = [];
    const clean = (action) => { try { action(); } catch (error) { failures.push(error); } };
    if (siteOwned) clean(() => powershell(`Import-Module WebAdministration; if (Test-Path 'IIS:\\Sites\\${site}') { Remove-Website -Name '${site}' }; if (Test-Path 'IIS:\\Sites\\${site}') { throw 'Elapsed-retention site remains' }`));
    if (endpointOwned) clean(() => powershell(`& netsh.exe http show sslcert ipport=127.0.0.1:${port} | Out-Null; if ($LASTEXITCODE -eq 0) { & netsh.exe http delete sslcert ipport=127.0.0.1:${port} | Out-Null; if ($LASTEXITCODE -ne 0) { throw 'Elapsed-retention endpoint cleanup failed' } }; & netsh.exe http show sslcert ipport=127.0.0.1:${port} | Out-Null; if ($LASTEXITCODE -eq 0) { throw 'Elapsed-retention endpoint remains' }; 'absent'`));
    if (certificateOwned) clean(() => powershell(`$p='Cert:\\LocalMachine\\My\\${oldThumbprint}'; if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p }; if (Test-Path -LiteralPath $p) { throw 'Owned elapsed-retention certificate remains' }`));
    if (keyOwned) {
      try {
        assert.equal((await removeAbandonedKeyContainer({ containerName, allowAlreadyAbsent: true })).ok, true);
        assert.ok(!run("certutil.exe", ["-csp", "Microsoft Software Key Storage Provider", "-key"]).includes(containerName), "owned elapsed-retention key must be absent after cleanup");
      }
      catch (error) { failures.push(error); }
    }
    if (failures.length) throw new AggregateError(primaryError ? [primaryError, ...failures] : failures, "Elapsed-retention cleanup failed", { cause: primaryError });
  }
}
module.exports = { qualifyElapsedRetention };
