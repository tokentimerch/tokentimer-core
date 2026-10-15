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
const {
  generateCsrViaCng,
  buildEnrollmentContainerName,
  acceptCertificateViaCng,
  removeAbandonedKeyContainer,
} = require("../../src/windows-cert-store");
const { deployIisBinding } = require("../../src/windows-iis");
const retention = require("../../src/windows-retention");
const { runWindowsRetentionSweep } = require("../../src/index");
async function trustedLeaf(port, ca, expected) {
  const once = () =>
    new Promise((resolve, reject) => {
      const socket = tls.connect(
        {
          host: "127.0.0.1",
          port,
          servername: "certops-host.invalid",
          ca,
          rejectUnauthorized: true,
        },
        () => {
          try {
            assert.equal(socket.authorized, true);
            assert.equal(
              socket.getPeerCertificate().fingerprint.replace(/:/g, ""),
              expected,
            );
            resolve();
          } catch (error) {
            reject(error);
          } finally {
            socket.destroy();
          }
        },
      );
      socket.setTimeout(10000, () =>
        socket.destroy(new Error("Trusted retention handshake timed out")),
      );
      socket.once("error", reject);
    });
  const deadline = Date.now() + 20000;
  let failure;
  do {
    try {
      await once();
      return;
    } catch (error) {
      failure = error;
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  } while (Date.now() < deadline);
  throw failure;
}
function verifyElapsedProof(proof) {
  require("./retention-interrupted-process").verifyProof(
    proof.ownedInterruption,
  );
  assert.equal(proof.mode, "real-clock-two-cutover-expiry-grace");
  for (const field of [
    "successfulCutovers",
    "predecessorCertificatesRemoved",
    "predecessorKeysRemoved",
    "lineageRowsFinalized",
  ])
    assert.equal(proof[field], 2, field);
  for (const field of [
    "immediateDeferralPreservedCustody",
    "immutableHistoryPreserved",
    "replacementTrustedBoundCustodyUnchanged",
    "interruptedNativeDeleteRecovered",
  ])
    assert.equal(proof[field], true, field);
  assert.equal(proof.configuredRetentionHours, 24);
  assert.equal(proof.fullRetentionWindowQualified, false);
  assert.ok(
    Number.isFinite(proof.waitedMonotonicMs) &&
      proof.waitedMonotonicMs >= 300000 &&
      proof.waitedMonotonicMs < 600000,
  );
  return true;
}
async function qualifyElapsedRetention({
  gate,
  powershell,
  run,
  workDir,
  replacementPem,
  replacementThumbprint,
  retentionHours = 24,
}) {
  assert.ok([24, 168, 720].includes(retentionHours));
  const policyVariant = retentionHours !== 24;
  const fixtureId = crypto.randomUUID();
  const directory = path.join(workDir, `elapsed-retention-${fixtureId}`);
  fs.mkdirSync(directory);
  const site = `CertOps-Elapsed-${fixtureId}`,
    port = await freePort();
  const quote = (value) => value.replace(/'/g, "''");
  const predecessors = [];
  let siteOwned = false,
    endpointOwned = false,
    primaryError,
    ownedInterruption;
  const nativeCustody = (thumb) => {
    assert.match(thumb, /^[A-F0-9]{40}$/);
    return JSON.parse(
      powershell(
        `$c=Get-Item 'Cert:\\LocalMachine\\My\\${thumb}';$k=$null;try{$k=if($c.PublicKey.Oid.Value -eq '1.2.840.113549.1.1.1'){[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c)}else{[Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($c)};@{name=$k.Key.KeyName;unique=$k.Key.UniqueName;exportPolicy=[string]$k.Key.ExportPolicy;provider=$k.Key.Provider.Provider;machine=$k.Key.IsMachineKey;der=[Convert]::ToBase64String($c.RawData);expiry=$c.NotAfter.ToUniversalTime().ToString('o')}|ConvertTo-Json -Compress}finally{if($k){$k.Dispose()};$c.Dispose()}`,
      ),
    );
  };
  const nativeKeyExists = (container) => {
    assert.match(
      container,
      /^tokentimer-enr-[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/,
    );
    const value = powershell(
      `[string][Security.Cryptography.CngKey]::Exists('${container}',[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider,[Security.Cryptography.CngKeyOpenOptions]::MachineKey)`,
    );
    assert.ok(
      value === "True" || value === "False",
      "Exact native key existence unavailable",
    );
    return value === "True";
  };
  const history = (row) =>
    Object.fromEntries(
      [
        "oldThumbprint",
        "replacementThumbprint",
        "cngKeyContainerId",
        "verifiedCutoverAt",
        "oldNotAfter",
        "ownershipProvenance",
        "store",
        "jobOrRollbackJournalRefs",
      ].map((field) => [field, row[field]]),
    );
  try {
    const ca = fs.readFileSync(path.join(workDir, "ca.pem"), "utf8"),
      authority = new crypto.X509Certificate(ca);
    const replacementCertificate = new crypto.X509Certificate(replacementPem);
    assert.equal(
      replacementCertificate.fingerprint.replace(/:/g, ""),
      replacementThumbprint,
    );
    assert.equal(
      replacementCertificate.checkHost("certops-host.invalid"),
      "certops-host.invalid",
    );
    assert.equal(replacementCertificate.verify(authority.publicKey), true);
    const replacementCustody = nativeCustody(replacementThumbprint);
    assert.equal(replacementCustody.exportPolicy, "None");
    assert.equal(replacementCustody.machine, true);
    assert.equal(
      new crypto.X509Certificate(Buffer.from(replacementCustody.der, "base64"))
        .fingerprint256,
      replacementCertificate.fingerprint256,
    );
    const opensslPath = (file) => '"' + file.replaceAll("\\", "/") + '"';
    fs.writeFileSync(path.join(directory, "index.txt"), "");
    fs.writeFileSync(
      path.join(directory, "index.txt.attr"),
      "unique_subject = no\n",
    );
    fs.writeFileSync(path.join(directory, "serial"), "B001\n");
    const signer = path.join(directory, "signer.cnf");
    fs.writeFileSync(
      signer,
      `[ca]\ndefault_ca=qualification\n[qualification]\ndatabase=${opensslPath(path.join(directory, "index.txt"))}\nserial=${opensslPath(path.join(directory, "serial"))}\nnew_certs_dir=${opensslPath(directory)}\ncertificate=${opensslPath(path.join(workDir, "ca.pem"))}\nprivate_key=${opensslPath(path.join(workDir, "ca.key"))}\ndefault_md=sha256\npolicy=subject\ncopy_extensions=copy\nunique_subject=no\ndefault_days=1\n[subject]\ncommonName=supplied\n`,
    );
    const stamp = (date) =>
      date
        .toISOString()
        .replace(/[-:]/g, "")
        .replace("T", "")
        .replace(/\.\d+Z$/, "Z");
    for (const label of ["A", "B"]) {
      const enrollmentId = crypto.randomUUID(),
        containerName = buildEnrollmentContainerName(enrollmentId);
      const item = {
        label,
        containerName,
        keyOwned: false,
        certificateOwned: false,
      };
      predecessors.push(item);
      assert.equal(nativeKeyExists(containerName), false);
      item.keyOwned = true; // exact deterministic ownership before native mutation
      const csr = await generateCsrViaCng({
        commonName: "certops-host.invalid",
        altNames: ["certops-host.invalid"],
        algorithm: "rsa-2048",
        enrollmentId,
        workDir: directory,
      });
      assert.equal(csr.ok, true);
      const csrPath = path.join(directory, `${label}.csr`),
        leafPath = path.join(directory, `${label}.pem`);
      fs.writeFileSync(csrPath, csr.csrPem, { flag: "wx" });
      const signingTime = Date.now();
      run("openssl", [
        "ca",
        "-batch",
        "-notext",
        "-config",
        signer,
        "-in",
        csrPath,
        "-out",
        leafPath,
        "-startdate",
        stamp(new Date(signingTime - 60000)),
        "-enddate",
        stamp(new Date(signingTime + 120000)),
      ]);
      item.pem = fs.readFileSync(leafPath, "utf8");
      item.certificate = new crypto.X509Certificate(item.pem);
      assert.equal(item.certificate.verify(authority.publicKey), true);
      item.thumbprint = item.certificate.fingerprint.replace(/:/g, "");
      assert.equal(
        powershell(
          `[bool](Test-Path 'Cert:\\LocalMachine\\My\\${item.thumbprint}')`,
        ),
        "False",
      );
      item.certificateOwned = true;
      assert.equal(
        (
          await acceptCertificateViaCng({
            certificatePem: item.pem,
            workDir: directory,
            store: "My",
          })
        ).ok,
        true,
      );
      item.custody = nativeCustody(item.thumbprint);
      assert.equal(item.custody.name, containerName);
      assert.equal(item.custody.exportPolicy, "None");
      assert.equal(item.custody.machine, true);
      item.nativeExpiry = item.custody.expiry;
      assert.equal(
        Date.parse(item.nativeExpiry),
        Date.parse(item.certificate.validTo),
      );
    }
    const [a, b] = predecessors;
    assert.equal(
      new Set([a.thumbprint, b.thumbprint, replacementThumbprint]).size,
      3,
    );
    const spki = (certificate) =>
      crypto
        .createHash("sha256")
        .update(certificate.publicKey.export({ type: "spki", format: "der" }))
        .digest("hex");
    assert.equal(
      new Set([
        spki(a.certificate),
        spki(b.certificate),
        spki(replacementCertificate),
      ]).size,
      3,
    );
    powershell(
      `& netsh.exe http show sslcert ipport=127.0.0.1:${port} | Out-Null;if($LASTEXITCODE -eq 0){throw 'Refuse preexisting elapsed-retention endpoint'};Import-Module WebAdministration;if(Test-Path 'IIS:\\Sites\\${site}'){throw 'Refuse preexisting fixture site'}`,
    );
    fs.writeFileSync(
      path.join(directory, "index.htm"),
      "Elapsed two-cutover retention fixture",
    );
    siteOwned = true;
    powershell(
      `Import-Module WebAdministration;New-Website -Name '${site}' -PhysicalPath '${quote(directory)}' -IPAddress '127.0.0.1' -Port ${port} -Ssl | Out-Null`,
    );
    endpointOwned = true;
    powershell(
      `Import-Module WebAdministration;(Get-WebBinding -Name '${site}' -Protocol https|Where-Object {$_.bindingInformation -eq '127.0.0.1:${port}:'}).AddSslCertificate('${a.thumbprint}','My')`,
    );
    await trustedLeaf(port, ca, a.thumbprint);
    const stateDir = path.join(directory, "state"),
      ledgerDir = path.join(stateDir, "windows-retention");
    for (const [old, replacement] of [
      [a, b],
      [b, { pem: replacementPem, thumbprint: replacementThumbprint }],
    ]) {
      assert.ok(
        Date.now() < Date.parse(old.nativeExpiry),
        "Each actual predecessor must still be valid at its real cutover",
      );
      assert.equal(
        (
          await deployIisBinding({
            binding: { site, address: "127.0.0.1", port, store: "My" },
            certificatePem: replacement.pem,
            verifyTimeoutMs: 15000,
          })
        ).ok,
        true,
      );
      await trustedLeaf(port, ca, replacement.thumbprint);
      old.cutover = new Date().toISOString();
      old.replacement = replacement.thumbprint;
      old.row = retention.createLedgerRow({
        ledgerDir,
        oldThumbprint: old.thumbprint,
        replacementThumbprint: replacement.thumbprint,
        cngKeyContainerId: old.containerName,
        verifiedCutoverAt: old.cutover,
        oldNotAfter: old.nativeExpiry,
        ownershipProvenance: "tokentimer_installed",
        store: "My",
      });
      old.deadline = retention.computeCleanupDeadline({
        verifiedCutoverAt: old.cutover,
        oldNotAfter: old.nativeExpiry,
        retentionHours,
      });
      assert.equal(
        old.deadline.getTime(),
        Date.parse(old.nativeExpiry) + 300000,
        "Actual supported expiry grace must win without shortening configured retention",
      );
    }
    const binding = () =>
      JSON.parse(
        powershell(
          `Import-Module WebAdministration;$x=@(Get-WebBinding -Name '${site}' -Protocol https|Where-Object {$_.bindingInformation -eq '127.0.0.1:${port}:'});if($x.Count -ne 1){throw 'Missing exact elapsed-retention binding'};$h=$x[0].certificateHash;if($h -is [byte[]]){$h=[BitConverter]::ToString($h).Replace('-','')};@{hash=([string]$h).ToUpperInvariant();store=[string]$x[0].certificateStoreName;flags=[int]$x[0].sslFlags}|ConvertTo-Json -Compress`,
        ),
      );
    const finalBinding = binding();
    assert.equal(finalBinding.hash, replacementThumbprint);
    assert.equal(finalBinding.store, "My");
    const preserveReplacement = async () => {
      assert.deepEqual(binding(), finalBinding);
      assert.deepEqual(
        nativeCustody(replacementThumbprint),
        replacementCustody,
      );
      assert.ok(
        run("netsh.exe", [
          "http",
          "show",
          "sslcert",
          `ipport=127.0.0.1:${port}`,
        ])
          .toUpperCase()
          .includes(replacementThumbprint),
      );
      await trustedLeaf(port, ca, replacementThumbprint);
    };
    const deadline = new Date(
      Math.max(...predecessors.map((item) => item.deadline.getTime())),
    );
    assert.ok(
      deadline.getTime() > Date.now() &&
        deadline.getTime() - Date.now() < 600000,
    );
    const sweep = () =>
      runWindowsRetentionSweep({
        stateDir,
        retentionHours,
        log: { info() {}, error() {} },
      });
    const early = await sweep();
    assert.equal(early.removed.length, 0);
    for (const item of predecessors) {
      assert.ok(
        early.deferred.some(
          (row) =>
            row.oldThumbprint === item.thumbprint &&
            row.reason === "deadline_not_reached",
        ),
      );
      assert.deepEqual(nativeCustody(item.thumbprint), item.custody);
      assert.deepEqual(
        history(retention.readLedgerRow(ledgerDir, item.thumbprint)),
        history(item.row),
      );
    }
    await preserveReplacement();
    assert.ok(
      Math.max(...predecessors.map((item) => Date.parse(item.nativeExpiry))) >
        Date.now(),
      "At least the newest actual predecessor must remain valid when the shared wait starts",
    );
    // One shared real wait qualifies both expiry+300s deadlines, never two
    // serial waits. No clocks, native queries, TLS or eligibility facts injected.
    const preDeadlineObservedAt = new Date().toISOString();
    const waitStartedAt = new Date().toISOString();
    const waitStarted = process.hrtime.bigint();
    while (Date.now() <= deadline.getTime()) {
      assert.ok(
        process.hrtime.bigint() - waitStarted < 600000000000n,
        "Real deadline wait exceeded independent ten-minute monotonic bound",
      );
      await new Promise((resolve) =>
        setTimeout(
          resolve,
          Math.min(5000, deadline.getTime() - Date.now() + 250),
        ),
      );
    }
    assert.ok(
      process.hrtime.bigint() - waitStarted >= 300000000000n,
      "The actual monotonic wait must independently cover the full expiry grace",
    );
    const waitFinishedAt = new Date().toISOString();
    const waitedMonotonicMs =
      Number(process.hrtime.bigint() - waitStarted) / 1000000;
    // Interrupt the first actually enumerated row so no other predecessor can
    // have been silently removed before the delstore-before-delkey boundary.
    const first = retention.listLedgerThumbprints(ledgerDir)[0],
      target = predecessors.find((item) => item.thumbprint === first);
    assert.ok(target);
    await gate.scenario(
      policyVariant
        ? `windows-retention-policy-${retentionHours}-interrupted-delete`
        : "windows-retention-native-interrupted-delete",
      async () => {
        const { receipt: fault, proof: interruptionDrain } =
          await require("./retention-interrupted-process").interruptOwnedCollector(
            {
              workDir,
              stateDir,
              thumbprint: target.thumbprint,
              containerName: target.containerName,
              retentionHours,
            },
          );
        require("./retention-interrupted-process").verifyProof(
          interruptionDrain,
        );
        ownedInterruption = interruptionDrain;
        const lockPath = path.join(stateDir, "windows-cert-store", "My.lock"),
          marker = fs.readFileSync(lockPath, "utf8").trim().split(/\r?\n/);
        assert.equal(marker.length, 3);
        assert.equal(marker[0], String(fault.pid));
        assert.ok(Number.isFinite(Date.parse(marker[1])));
        assert.match(marker[2], /^[a-f0-9]{32}$/);
        assert.equal(
          powershell(
            `[bool](Test-Path 'Cert:\\LocalMachine\\My\\${target.thumbprint}')`,
          ),
          "False",
        );
        assert.equal(nativeKeyExists(target.containerName), true);
        for (const item of predecessors)
          assert.notEqual(
            retention.readLedgerRow(ledgerDir, item.thumbprint).lifecycleState,
            "removed",
          );
        await preserveReplacement();
        const retryDeadline = Date.now() + 30000;
        let resumed;
        do {
          resumed = await sweep();
          if (
            predecessors.every(
              (item) =>
                retention.readLedgerRow(ledgerDir, item.thumbprint)
                  .lifecycleState === "removed",
            )
          )
            break;
          await new Promise((resolve) => setTimeout(resolve, 1000));
        } while (Date.now() < retryDeadline);
        assert.equal(fs.existsSync(lockPath), false);
        assert.ok(resumed);
        for (const item of predecessors)
          assert.equal(
            retention.readLedgerRow(ledgerDir, item.thumbprint).lifecycleState,
            "removed",
            "Real retry must finalize both independently eligible predecessors",
          );
        await preserveReplacement();
      },
      {
        evidenceLevel: "real-host",
        oracle:
          "actual first enumerated eligible A/B delstore then owned child exit before delkey, retained key/incomplete immutable lineage, real sweep resumes both through live C without another elapsed wait",
      },
    );
    for (const item of predecessors) {
      assert.equal(
        powershell(
          `[bool](Test-Path 'Cert:\\LocalMachine\\My\\${item.thumbprint}')`,
        ),
        "False",
      );
      assert.equal(nativeKeyExists(item.containerName), false);
      const removed = retention.readLedgerRow(ledgerDir, item.thumbprint);
      assert.equal(removed.lifecycleState, "removed");
      assert.deepEqual(history(removed), history(item.row));
    }
    await preserveReplacement();
    const proof = {
      ownedInterruption,
      mode: "real-clock-two-cutover-expiry-grace",
      successfulCutovers: 2,
      predecessorCertificatesRemoved: 2,
      predecessorKeysRemoved: 2,
      lineageRowsFinalized: 2,
      immediateDeferralPreservedCustody: true,
      immutableHistoryPreserved: true,
      replacementTrustedBoundCustodyUnchanged: true,
      interruptedNativeDeleteRecovered: true,
      waitedMonotonicMs:
        Number(process.hrtime.bigint() - waitStarted) / 1000000,
      configuredRetentionHours: retentionHours,
      fullRetentionWindowQualified: false,
    };
    let reportProof = proof;
    if (policyVariant) {
      // Choose the genuinely newest predecessor, whose native validity was
      // observed before this shared real wait. The same sweep independently
      // checks/removes BOTH predecessors; no ledger timestamps are rewritten.
      const newest = predecessors.reduce((a, b) =>
        Date.parse(a.nativeExpiry) > Date.parse(b.nativeExpiry) ? a : b,
      );
      const contract = require("./retention-policy-expiry-proof");
      reportProof = {
        ownedInterruption,
        scope: contract.SCOPE,
        configuredRetentionHours: retentionHours,
        verifiedCutoverAt: newest.cutover,
        oldNotAfter: contract.publicNativeTimestamp(newest.nativeExpiry),
        cleanupDeadline: newest.deadline.toISOString(),
        preDeadlineObservedAt,
        cleanupObservedAt: new Date().toISOString(),
        waitStartedAt,
        waitFinishedAt,
        waitedMonotonicMs,
        installedServiceTimerQualified: false,
        fullRetentionWindowQualified: false,
        actualProductionCollectorUsed: true,
        preDeadlineCustodyPreserved: true,
        oldCertificateAbsent: true,
        oldKeyAbsent: true,
        immutableHistoryPreserved: true,
        replacementCustodyUnchanged: true,
        replacementTrustedTlsVerified: true,
        interruptedNativeDeleteRecovered: true,
        successfulCutovers: 2,
        predecessorCertificatesRemoved: 2,
        predecessorKeysRemoved: 2,
        lineageRowsFinalized: 2,
      };
      contract.verifyProof(reportProof);
      gate.report.nativeRetentionPolicyExpiry ||= {};
      gate.report.nativeRetentionPolicyExpiry[String(retentionHours)] =
        reportProof;
    } else {
      verifyElapsedProof(proof);
      gate.report.nativeElapsedRetention = proof;
    }
    fs.writeFileSync(
      path.join(
        workDir,
        policyVariant
          ? `windows-retention-policy-${retentionHours}.log`
          : "windows-retention-elapsed.log",
      ),
      JSON.stringify({
        ...reportProof,
        predecessors: predecessors.map((item) => ({
          oldNotAfter: item.nativeExpiry,
          verifiedCutoverAt: item.cutover,
          cleanupDeadline: item.deadline.toISOString(),
        })),
        sharedCleanupDeadline: deadline.toISOString(),
        observedCleanupAt: new Date().toISOString(),
        faultMode: "owned-child-exit-after-native-delstore-before-delkey",
      }),
    );
  } catch (error) {
    primaryError = error;
    throw error;
  } finally {
    // No site/store/key cleanup may race an uncertain native collector child.
    await require("./retention-interrupted-process").drainBeforeCleanup(
      workDir,
    );
    const failures = [],
      clean = (action) => {
        try {
          action();
        } catch (error) {
          failures.push(error);
        }
      };
    if (siteOwned)
      clean(() =>
        powershell(
          `Import-Module WebAdministration;if(Test-Path 'IIS:\\Sites\\${site}'){Remove-Website -Name '${site}'};if(Test-Path 'IIS:\\Sites\\${site}'){throw 'Elapsed-retention site remains'}`,
        ),
      );
    if (endpointOwned)
      clean(() =>
        powershell(
          `& netsh.exe http show sslcert ipport=127.0.0.1:${port} | Out-Null;if($LASTEXITCODE -eq 0){& netsh.exe http delete sslcert ipport=127.0.0.1:${port} | Out-Null;if($LASTEXITCODE -ne 0){throw 'Elapsed-retention endpoint cleanup failed'}};& netsh.exe http show sslcert ipport=127.0.0.1:${port} | Out-Null;if($LASTEXITCODE -eq 0){throw 'Elapsed-retention endpoint remains'}`,
        ),
      );
    for (const item of predecessors) {
      if (item.certificateOwned)
        clean(() =>
          powershell(
            `$p='Cert:\\LocalMachine\\My\\${item.thumbprint}';if(Test-Path -LiteralPath $p){Remove-Item -LiteralPath $p};if(Test-Path -LiteralPath $p){throw 'Owned elapsed-retention certificate remains'}`,
          ),
        );
      if (item.keyOwned)
        try {
          assert.equal(
            (
              await removeAbandonedKeyContainer({
                containerName: item.containerName,
                allowAlreadyAbsent: true,
              })
            ).ok,
            true,
          );
          assert.equal(nativeKeyExists(item.containerName), false);
        } catch (error) {
          failures.push(error);
        }
    }
    if (failures.length)
      throw new AggregateError(
        primaryError ? [primaryError, ...failures] : failures,
        "Elapsed-retention cleanup failed",
        { cause: primaryError },
      );
  }
}
module.exports = { qualifyElapsedRetention, verifyElapsedProof };
