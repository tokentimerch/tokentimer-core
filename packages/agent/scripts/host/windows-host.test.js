"use strict";
/* Strict supporting Windows host suite, invoked by the protected Windows host workflow. Opted-in
 * disposable runners own temporary CNG/store/IIS/process fixtures; each native oracle and cleanup
 * is reported separately. Go supporting tests are not full API-agent certificate E2E.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { createHostGate } = require("../host-gate.js");

function run(command, args, options = {}) {
  const childOptions = { ...options };
  if (/^powershell(?:\.exe)?$/i.test(path.basename(command))) {
    const environment = { ...process.env, ...(childOptions.env || {}) };
    for (const key of Object.keys(environment)) if (key.toLowerCase() === "psmodulepath") delete environment[key];
    childOptions.env = environment;
  }
  const result = spawnSync(command, args, { encoding: "utf8", timeout: 180000, ...childOptions });
  assert.ifError(result.error);
  assert.equal(result.status, 0, `${command} failed: ${result.stdout}\n${result.stderr}`);
  assert.doesNotMatch(`${result.stdout}\n${result.stderr}`, /^(?:FAIL:|DEVIATION:|UNCAUGHT ERROR:)/m);
  return result.stdout.trim();
}
function powershell(script) {
  return run("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", `$ErrorActionPreference='Stop'; ${script}`]);
}

// Leave the workflow's remaining bounded time for independent cleanup and
// report verification after native builds and required negative operations.
test("Windows real-host discovery and service-host qualification", { timeout: 1200000 }, async (t) => {
  const enabled = process.env.CERTOPS_HOST_TESTS === "1";
  const gate = createHostGate({
    suite: "windows-host",
    fixtureSource: { file: "packages/agent/scripts/host/windows-host.test.js",
      sha256: require("node:crypto").createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") },
    requiredCapabilities: ["windows", "optIn", "elevated", "go", "iis", "openssl", "npm", "tar"],
    probeCapabilities: async () => ({
      windows: { available: process.platform === "win32" },
      optIn: { available: enabled },
      elevated: { available: process.platform === "win32" && enabled && powershell("([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)") === "True" },
      go: { available: spawnSync("go", ["version"], { encoding: "utf8" }).status === 0 },
      npm: { available: spawnSync("npm", ["--version"], { encoding: "utf8", shell: true }).status === 0 },
      tar: { available: spawnSync("tar.exe", ["--version"], { encoding: "utf8" }).status === 0 },
      iis: { available: process.platform === "win32" && enabled && powershell("[bool](Get-Module -ListAvailable WebAdministration)") === "True" },
      openssl: { available: spawnSync("openssl", ["version"], { encoding: "utf8" }).status === 0 },
    }),
  });
  if (!await gate.preflight()) {
    // skip-reason: no-host
    t.skip("requires opted-in elevated Windows and Go"); return;
  }
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "certops-host-"));
  let thumbprint;
  const containers = [];
  const acceptedCertificates = [];
  const acceptedStores = new Map();
  const custodyCertificates = [];
  const keyUsageCases = [];
  try {
    await gate.scenario("windows-discovery-fingerprint", async () => {
      const receipt = path.join(workDir, "discovery.receipt").replace(/'/g, "''");
      thumbprint = powershell(`$c=New-SelfSignedCertificate -DnsName 'certops-host.invalid' -CertStoreLocation Cert:\\LocalMachine\\My; [IO.File]::WriteAllText('${receipt}', $c.Thumbprint); $c.Thumbprint`);
      assert.match(thumbprint, /^[A-F0-9]{40}$/);
      const output = run(process.execPath, [path.resolve(__dirname, "../vm-verify/windows-discovery-fingerprint-verify.js"), workDir]);
      fs.writeFileSync(path.join(workDir, "discovery.log"), output);
      assert.match(output, /ALL CHECKS PASSED/);
      assert.match(output, /certutil -hashfile SHA256 independently confirms/);
    }, { evidenceLevel: "real-host", oracle: "certutil DER export and SHA256 hash" });
    await gate.scenario("windows-discovery-constrained-language", async () => {
      const { fetchRawCertificateDerByThumbprint } = require("../../src/discovery/windows");
      assert.equal(powershell("$ExecutionContext.SessionState.LanguageMode='ConstrainedLanguage'; [string]$ExecutionContext.SessionState.LanguageMode"), "ConstrainedLanguage");
      let nativeCalls = 0;
      const warnings = [];
      const discovered = fetchRawCertificateDerByThumbprint({ storeLocation: "LocalMachine", storeName: "My", onWarning: (message) => warnings.push(message), spawn: (program, args, options) => {
        const commandIndex = args.indexOf("-Command");
        assert.ok(commandIndex >= 0);
        const constrained = [...args];
        constrained[commandIndex + 1] = `$ErrorActionPreference='Stop'; $ExecutionContext.SessionState.LanguageMode='ConstrainedLanguage'; ${args[commandIndex + 1]}`;
        nativeCalls += 1;
        // Only the child session language mode changes. The product's
        // complete query/JSON code executes in a real native PowerShell.
        return spawnSync(program, constrained, options);
      } });
      assert.equal(nativeCalls, 1);
      assert.equal(warnings.length, 0, "constrained discovery must not degrade silently");
      const expectedDer = powershell(`[Convert]::ToBase64String((Get-Item 'Cert:\\LocalMachine\\My\\${thumbprint}').RawData)`);
      assert.equal(discovered.get(thumbprint.toLowerCase()), expectedDer, "constrained query must preserve the actual fixture DER bytes");
    }, { evidenceLevel: "real-host", oracle: "real ConstrainedLanguage PowerShell executes product query; independent full-language certificate DER confirms result" });
    await gate.scenario("windows-user-store-boundary", async () => {
      await require("./user-store-fixture").qualifyUserStoreBoundary({ powershell, workDir });
    }, { evidenceLevel: "real-host", oracle: "actual CurrentUser certificate presence and independent LocalMachine absence; product machine-store query excludes its thumbprint" });
    await gate.scenario("windows-discovery-http-sys-selectors", async () => {
      await require("./discovery-http-sys-fixture").qualifyHttpSysDiscovery({ powershell, run, workDir, gate });
    }, { evidenceLevel: "real-host", oracle: "Independent native registry selectors and public DER agree with actual IPv4/IPv6/hostname HTTP.sys observations and automatically included bound WebHosting store; CCS unsupported" });
    await gate.scenario("windows-cng-csr", async () => {
      const { generateCsrViaCng, buildEnrollmentContainerName, acceptCertificateViaCng } = require("../../src/windows-cert-store");
      await assert.rejects(generateCsrViaCng({ commonName: "", altNames: [], jobId: require("node:crypto").randomUUID(), workDir }), /commonName/);
      await assert.rejects(acceptCertificateViaCng({ certificatePem: "not a certificate", workDir, store: "My" }));
      const caKey = path.join(workDir, "ca.key");
      const caCert = path.join(workDir, "ca.pem");
      run("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", caKey, "-out", caCert, "-days", "1", "-subj", "/CN=CertOps Disposable Qualification CA",
        "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"]);
      const caThumbprint = new (require("node:crypto").X509Certificate)(fs.readFileSync(caCert)).fingerprint.replace(/:/g, "");
      assert.equal(powershell(`[bool](Test-Path 'Cert:\\LocalMachine\\Root\\${caThumbprint}')`), "False", "refuse ownership of existing signing root");
      try {
      run("certutil.exe", ["-addstore", "Root", caCert]);
      const profiles = ["rsa-2048", "ec-p256", "rsa-3072", "rsa-4096", "ec-p384"];
      const matrix = ["My", "WebHosting"].flatMap((store) => profiles.map((algorithm) => [algorithm, store]));
      for (const [index, [algorithm, store]] of matrix.entries()) {
        const directory = path.join(workDir, `${algorithm}-${store}`);
        fs.mkdirSync(directory);
        const enrollmentId = require("node:crypto").randomUUID();
        const containerName = buildEnrollmentContainerName(enrollmentId);
        assert.ok(!run("certutil.exe", ["-csp", "Microsoft Software Key Storage Provider", "-key"]).includes(containerName), "fixture container already exists");
        // Register deterministic ownership before certreq can create a key,
        // including the failure path where generation throws after creation.
        containers.push(containerName);
        const result = await generateCsrViaCng({ commonName: "certops-host.invalid", altNames: ["certops-host.invalid"], algorithm, enrollmentId, workDir: directory });
        assert.equal(result.ok, true, JSON.stringify(result));
        const duplicate = await generateCsrViaCng({ commonName: "certops-host.invalid", altNames: ["certops-host.invalid"], algorithm, enrollmentId, workDir: directory });
        assert.equal(duplicate.ok, false);
        assert.equal(duplicate.reason, "enrollment_container_exists");
        assert.match(result.csrPem, /BEGIN CERTIFICATE REQUEST/);
        const listing = run("certutil.exe", ["-csp", "Microsoft Software Key Storage Provider", "-key"]);
        assert.ok(listing.includes(result.containerName), "independent KSP listing must contain generated container");
        assert.ok(!fs.readdirSync(directory).some((file) => /\.(pfx|p12|key)$/i.test(file)), "no private key exported");
        const csrFile = path.join(directory, "signing.csr");
        const certFile = path.join(directory, "issued.pem");
        fs.writeFileSync(csrFile, result.csrPem);
        run("openssl", ["x509", "-req", "-in", csrFile, "-copy_extensions", "copy", "-CA", caCert, "-CAkey", caKey, "-set_serial", String(index + 1), "-days", "1", "-out", certFile]);
        const certificatePem = fs.readFileSync(certFile, "utf8");
        assert.match(new (require("node:crypto").X509Certificate)(certificatePem).subjectAltName, /DNS:certops-host\.invalid/);
        const issuedThumbprint = new (require("node:crypto").X509Certificate)(certificatePem).fingerprint.replace(/:/g, "");
        // Track the issued public certificate before certreq -accept mutates My.
        acceptedCertificates.push(issuedThumbprint);
        acceptedStores.set(issuedThumbprint, store);
        const accepted = await acceptCertificateViaCng({ certificatePem, workDir: directory, store });
        assert.equal(accepted.ok, true, JSON.stringify(accepted));
        assert.equal(accepted.thumbprint, issuedThumbprint);
        const key = JSON.parse(powershell(`$c=Get-Item 'Cert:\\LocalMachine\\${store}\\${issuedThumbprint}'; $k=$null; try { $k=if ($c.PublicKey.Oid.Value -eq '1.2.840.113549.1.1.1') { [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c) } else { [Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($c) }; $usage=@($c.Extensions|Where-Object {$_.Oid.Value -eq '2.5.29.15'});if($usage.Count -ne 1){throw 'Exactly one actual certificate KeyUsage extension required'};$parsedUsage=[Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new($usage[0],$usage[0].Critical); [pscustomobject]@{certificateUsageFlags=[int]$parsedUsage.KeyUsages;cngAllowedOperations=[uint32]$k.Key.KeyUsage;hasPrivateKey=$c.HasPrivateKey; name=$k.Key.KeyName; exportPolicy=[string]$k.Key.ExportPolicy; provider=$k.Key.Provider.Provider; size=$k.KeySize} | ConvertTo-Json -Compress } finally { if ($null -ne $k) { $k.Dispose() }; $c.Dispose() }`));
        assert.equal(key.hasPrivateKey, true);
        assert.equal(key.name, containerName);
        assert.equal(key.exportPolicy, "None");
        assert.equal(key.provider, "Microsoft Software Key Storage Provider");
        assert.equal(key.size, Number(algorithm.match(/(\d+)$/)[1]), "native key size must match requested algorithm");
        const usage = { caseId: `${algorithm}/${store}`, certificateUsageFlags: key.certificateUsageFlags, cngAllowedOperations: key.cngAllowedOperations };
        require("./cng-key-usage-proof").verifyCase(usage);
        keyUsageCases.push(usage);
        custodyCertificates.push({algorithm,store,thumbprint:issuedThumbprint,containerName});
        if (store !== "My") assert.equal(powershell(`[bool](Test-Path 'Cert:\\LocalMachine\\My\\${issuedThumbprint}')`), "False", "mirror must not leave duplicate My certificate");
      }
      const usageProof = require("./cng-key-usage-proof");
      gate.report.nativeKeyUsage = { scope: usageProof.SCOPE, copiedActualCsrExtensions: true, privateKeyUsageClaim: "signing-permitted-not-exact-default-ncrypt-mask", cases: keyUsageCases };
      usageProof.verifyProof(gate.report.nativeKeyUsage);
      gate.report.fixtureSources ||= [];
      const usageSource = "packages/agent/scripts/host/cng-key-usage-proof.js";
      gate.report.fixtureSources.push({ file: usageSource, sha256: require("node:crypto").createHash("sha256").update(fs.readFileSync(path.resolve(__dirname, "../../../..", usageSource))).digest("hex") });
      await gate.scenario("windows-native-chain-verdicts", async () => {
        await require("./adcs-chain-fixture").qualifyNativeChain({ run, workDir });
      }, { evidenceLevel: "real-host", oracle: "real CryptoAPI chain evaluation of owned CA/CNG leaf: no-CDP revocation, changed CA key pin and actual expired leaf; no enterprise enrollment claim" });
      } finally {
        powershell(`$p='Cert:\\LocalMachine\\Root\\${caThumbprint}'; if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p }; if (Test-Path -LiteralPath $p) { throw 'Owned signing root remains' }`);
      }
    }, { evidenceLevel: "real-host", oracle: "certutil KSP enumeration and independent native .NET accepted certificate/provider/export policy, actual copied-CSR X509 KeyUsage and CNG signing permission across five profiles and two machine stores; no exact default NCrypt policy claim" });
    await gate.scenario("windows-enrollment-lock-cng-contention", async () => {
      gate.report.nativeEnrollmentContention = await require("./enrollment-contention-fixture").qualifyEnrollmentContention({ powershell, run, workDir });
      gate.report.fixtureSources ||= [];
      for (const file of ["packages/agent/scripts/host/enrollment-contention-fixture.js","packages/agent/scripts/host/enrollment-lock-child.js","packages/agent/src/windows-cert-store/index.js","packages/agent/src/windows-cert-store/exclusive-lock-worker.js","packages/agent/src/platform/index.js","packages/agent/src/platform/durability.js"]) gate.report.fixtureSources.push({ file, sha256: require("node:crypto").createHash("sha256").update(fs.readFileSync(path.resolve(__dirname, "../../../..", file))).digest("hex") });
    }, { evidenceLevel: "real-host", oracle: "Actual enrollment lock across CNG CSR: another process refuses before native execution, retry refuses existing container without certreq; unchanged CSR/SPKI and native signatures prove same nonexportable key; verified callback drain and exact cleanup" });
    await gate.scenario("windows-cng-private-export-refusal", async () => {
      await require("./cng-export-fixture").qualifyCngExportRefusal({powershell,records:custodyCertificates,containers,workDir,gate});
    }, {evidenceLevel:"real-host",oracle:"All five key profiles in My/WebHosting sign an independent public nonce, refuse actual PKCS8 private export while same-provider/profile controls export and clear their buffers; native custody remains unchanged and exact controls are removed"});
    await gate.scenario("windows-trust-anchor-lifecycle", async () => {
      const { distributeTrust, revokeTrust } = require("../../src/trust-store");
      const pem = fs.readFileSync(path.join(workDir, "ca.pem"), "utf8");
      const certificate = new (require("node:crypto").X509Certificate)(pem);
      const thumb = certificate.fingerprint.replace(/:/g, "");
      const fingerprintSha256 = certificate.fingerprint256.replace(/:/g, "").toLowerCase();
      const receiptDir = path.join(workDir, "trust-receipts");
      const job = { schemaVersion: 1, jobId: "host-trust-distribute", workspaceId: require("node:crypto").randomUUID(), agentId: require("node:crypto").randomUUID(), trustAnchorId: "host-anchor", action: "distribute-trust", anchorType: "root", fingerprintSha256, pem, mode: "real", requestedAt: new Date().toISOString(), transitionGeneration: 1 };
      assert.equal(powershell(`[bool](Test-Path 'Cert:\\LocalMachine\\Root\\${thumb}')`), "False", "refuse ownership of existing root");
      try {
        const installed = await distributeTrust({ job, family: "windows", receiptDir, workDir });
        assert.equal(installed.outcome, "installed", JSON.stringify(installed));
        assert.equal(powershell(`[bool](Test-Path 'Cert:\\LocalMachine\\Root\\${thumb}')`), "True");
        const replay = await distributeTrust({ job, family: "windows", receiptDir, workDir });
        assert.equal(replay.mutationPerformed, false);
        const removed = await revokeTrust({ job: { ...job, jobId: "host-trust-revoke", action: "revoke-trust" }, family: "windows", receiptDir, workDir });
        assert.equal(removed.outcome, "removed", JSON.stringify(removed));
        assert.equal(powershell(`[bool](Test-Path 'Cert:\\LocalMachine\\Root\\${thumb}')`), "False");
        run("certutil.exe", ["-addstore", "Root", path.join(workDir, "ca.pem")]);
        const unmanagedReceipts = path.join(workDir, "unmanaged-receipts");
        const preexisting = await distributeTrust({ job, family: "windows", receiptDir: unmanagedReceipts, workDir });
        assert.equal(preexisting.outcome, "preexisting");
        assert.equal(preexisting.mutationPerformed, false);
        const refused = await revokeTrust({ job: { ...job, jobId: "host-unmanaged-revoke", action: "revoke-trust" }, family: "windows", receiptDir: unmanagedReceipts, workDir });
        assert.equal(refused.mutationPerformed, false);
        assert.equal(powershell(`[bool](Test-Path 'Cert:\\LocalMachine\\Root\\${thumb}')`), "True", "unmanaged root must survive product revocation");
      } finally {
        powershell(`$p='Cert:\\LocalMachine\\Root\\${thumb}'; if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p }; if (Test-Path -LiteralPath $p) { throw 'Owned root anchor remains' }`);
      }
    }, { evidenceLevel: "real-host", oracle: "independent LocalMachine Root presence, idempotent receipt replay and revocation" });
    await gate.scenario("windows-retention-owned-cleanup", async () => {
      const retention = require("../../src/windows-retention");
      const { removeCertificateAndKeyContainer } = require("../../src/windows-cert-store");
      const ledgerDir = path.join(workDir, "owned-retention-ledger");
      const cutover = new Date();
      retention.createLedgerRow({ ledgerDir, oldThumbprint: acceptedCertificates[0], replacementThumbprint: acceptedCertificates[1], cngKeyContainerId: containers[0], verifiedCutoverAt: cutover.toISOString(), oldNotAfter: new Date(cutover.getTime() + 86400000).toISOString(), ownershipProvenance: "tokentimer_installed", jobOrRollbackJournalRefs: [] });
      const gatherContext = async () => ({ bindingStillReferencesOldThumbprint: false, keyContainerSharedWithSurvivor: false, replacementPassesHandshakeNow: true });
      let cleanupCalls = 0;
      const performCleanup = async () => {
        cleanupCalls += 1;
        const result = await removeCertificateAndKeyContainer({ thumbprint: acceptedCertificates[0], containerName: containers[0], store: "My" });
        assert.equal(result.ok, true, JSON.stringify(result));
      };
      const early = await retention.sweepLedger({ ledgerDir, retentionHours: 24, gatherContext, performCleanup, now: () => cutover });
      assert.equal(early.removed.length, 0);
      assert.equal(cleanupCalls, 0);
      const late = await retention.sweepLedger({ ledgerDir, retentionHours: 24, gatherContext, performCleanup, now: () => new Date(cutover.getTime() + 25 * 3600000) });
      assert.deepEqual(late.removed, [acceptedCertificates[0]]);
      assert.equal(cleanupCalls, 1);
      assert.equal(powershell(`[bool](Test-Path 'Cert:\\LocalMachine\\My\\${acceptedCertificates[0]}')`), "False");
      assert.equal(powershell(`[bool](Test-Path 'Cert:\\LocalMachine\\My\\${acceptedCertificates[1]}')`), "True");
    }, { evidenceLevel: "real-host", oracle: "real owned certificate/key deletion and surviving replacement; synthetic time/context, not served-TLS retention E2E" });
    await gate.scenario("windows-retention-native-guards", async () => {
      gate.report.nativeKeySurvivors = await require("./retention-fixture").qualifyRetentionGuards({ powershell, run, workDir, gate,
        oldThumbprint: acceptedCertificates[2], replacementThumbprint: acceptedCertificates[3], containerName: containers[2] });
      const contract = require("../../../../scripts/certops-native-key-survivor-proof");
      contract.verifyProof(gate.report.nativeKeySurvivors);
      const referenceContract = require("./retention-reference-fixture"); referenceContract.verifyProof(gate.report.nativeRetentionReferences);
      gate.report.fixtureSources ||= [];
      for (const file of [...contract.REQUIRED_SOURCES, ...referenceContract.requiredSources]) {
        if (!gate.report.fixtureSources.some(source => source.file === file)) gate.report.fixtureSources.push({ file, sha256: require("node:crypto").createHash("sha256").update(fs.readFileSync(path.resolve(__dirname, "../../../..", file))).digest("hex") });
      }
    }, { evidenceLevel: "real-host", oracle: "product retention collector reads real HTTP.sys bindings, actual shared CNG key association and replacement TLS; real clock blocks fresh ledger cleanup" });
    await gate.scenario("windows-retention-real-expiry-grace", async () => {
      gate.report.fixtureSources ||= [];
      for (const file of ["packages/agent/scripts/host/retention-elapsed-fixture.js", "packages/agent/scripts/host/retention-interrupted-child.js", "packages/agent/src/index.js", "packages/agent/src/windows-retention/index.js", "packages/agent/src/windows-discovery/index.js"]) {
        if (!gate.report.fixtureSources.some(source => source.file === file)) gate.report.fixtureSources.push({ file, sha256: require("node:crypto").createHash("sha256").update(fs.readFileSync(path.resolve(__dirname, "../../../..", file))).digest("hex") });
      }
      await require("./retention-elapsed-fixture").qualifyElapsedRetention({ gate, powershell, run, workDir,
        replacementPem: fs.readFileSync(path.join(workDir, "ec-p256-My/issued.pem"), "utf8"), replacementThumbprint: acceptedCertificates[1] });
    }, { evidenceLevel: "real-host", oracle: "actual distinct CNG A→B→C cutovers and immutable lineage; unchanged24h policy, one real max(A,B expiry)-plus300s wait, interrupted native deletion recovery and both predecessor cert/key absence with trusted bound C custody unchanged; no full24h claim" });
    await gate.scenario("windows-iis-deploy-rollback", async () => {
      await require("./iis-fixture").qualifyIis({ powershell, run, workDir, gate });
    }, { evidenceLevel: "real-host", oracle: "independent TLS fingerprint and netsh binding" });
    await gate.scenario("windows-iis-sni-flags", async () => {
      await require("./iis-fixture").qualifyIis({ powershell, run, workDir, sni: true, gate });
    }, { evidenceLevel: "real-host", oracle: "SNI TLS fingerprint, hostnameport netsh binding and preserved sslFlags" });
    await gate.scenario("windows-iis-shared-port-sni-isolation", async () => {
      gate.report.nativeSamePortSni = await require("./iis-shared-port-fixture").qualifySamePortSni({ powershell, run, workDir });
      gate.report.fixtureSources ||= [];
      for (const file of ["packages/agent/scripts/host/iis-shared-port-fixture.js", "packages/agent/scripts/host/iis-fixture.js"]) gate.report.fixtureSources.push({ file, sha256: require("node:crypto").createHash("sha256").update(fs.readFileSync(path.resolve(__dirname, "../../../..", file))).digest("hex") });
    }, { evidenceLevel: "real-host", oracle: "Two real IIS sites on one port retain distinct hostnameport selectors, exact native metadata/hash and authenticated TLS; each target cutover/rollback preserves its sibling and exact fixture cleanup succeeds" });
    await gate.scenario("windows-iis-http-sys-flags", async () => {
      await require("./iis-fixture").qualifyIis({ powershell, run, workDir, nativeFlags: true });
    }, { evidenceLevel: "real-host", oracle: "independent HTTP.sys registry DefaultFlags and certificate hash, plus served TLS across rebind and rollback" });
    await gate.scenario("windows-store-lock-worker-death", async () => {
      await require("./store-lock-death-fixture").qualifyStoreLockDeath({ workDir });
    }, { evidenceLevel: "real-host", oracle: "Actual lock Worker terminates during real cooperative child work; STORE_LOCK_LOST aborts and drains child, successor acquires actual IPC, stale release preserves successor marker; no certificate mutation" });
    await gate.scenario("windows-store-lock-drain-timeout", async () => {
      await require("./store-lock-death-fixture").qualifyStoreLockDeath({ workDir, cooperative: false });
    }, { evidenceLevel: "real-host", oracle: "Real non-cooperative benign subprocess outlives actual five-second drain; caller receives STORE_LOCK_LOST, actual successor IPC ownership survives stale release, fixture finally kills and drains only its owned child" });
    await gate.scenario("windows-store-lock-process-death", async () => {
      await require("./store-lock-process-death-fixture").qualifyStoreLockProcessDeath({ workDir });
    }, { evidenceLevel: "real-host", oracle: "Actual independent owner process acquires IPC and blocks a contender, exact owned process is killed, successor acquires without rewriting marker/time and publishes independently read PID/token; no certificate mutation" });
    await gate.scenario("windows-installer-build-floor", () => {
      require("./installer-build-floor-fixture").qualifyInstallerBuildFloor();
    }, { evidenceLevel: "unit", oracle: "Real PowerShell AST extracts only actual production Fail, floor assignment and build guard; three unsupported values refused and four supported boundaries accepted; no unsupported OS boot or installer mutation" });
    await gate.scenario("windows-retention-atomic-replace-refusal", async () => {
      const fixture = require("./retention-ledger-atomic-fixture");
      gate.report.nativeRetentionAtomicReplace = await fixture.qualifyLedgerAtomicReplace();
      gate.report.fixtureSources ||= [];
      for (const file of fixture.REQUIRED_SOURCES) {
        if (!gate.report.fixtureSources.some(source => source.file === file)) gate.report.fixtureSources.push({ file, sha256: require("node:crypto").createHash("sha256").update(fs.readFileSync(path.resolve(__dirname, "../../../..", file))).digest("hex") });
      }
    }, { evidenceLevel: "real-host", oracle: "Actual native file-sharing denial forces production atomic rename refusal, preserves exact prior bytes/file ID, removes only temporary write, then release permits a real replacement independently read by a fresh process with restrictive native ACLs" });
    await gate.scenario("windows-retention-process-durability", async () => {
      const ledgerDir = path.join(workDir, "restart-ledger");
      const driver = path.resolve(__dirname, "../vm-verify/windows-retention-restart.js");
      run(process.execPath, [driver, "create", ledgerDir]);
      const output = run(process.execPath, [driver, "resume", ledgerDir]);
      assert.match(output, /fresh process reached the correct eligibility decision/);
    }, { evidenceLevel: "real-host", oracle: "independent fresh process reads persisted ledger; no real certificate cleanup claimed" });
    await gate.scenario("windows-cross-store-mutex", async () => {
      const driver = path.resolve(__dirname, "../vm-verify/windows-iis-cross-store-mutex.js");
      const stateDir = path.join(workDir, "mutex-state");
      const readyFile = path.join(workDir, "mutex-ready");
      const child = require("node:child_process").spawn(process.execPath, [driver, stateDir, "holder", "WebHosting", "6000", readyFile], { stdio: ["ignore", "pipe", "pipe"] });
      let output = "";
      child.stdout.on("data", (chunk) => { output += chunk; });
      child.stderr.on("data", (chunk) => { output += chunk; });
      const completed = new Promise((resolve, reject) => { child.once("error", reject); child.once("close", (code) => resolve(code)); });
      try {
        const deadline = Date.now() + 10000;
        while (!fs.existsSync(readyFile) && Date.now() < deadline && child.exitCode === null) await new Promise((resolve) => setTimeout(resolve, 100));
        assert.ok(fs.existsSync(readyFile), `lock holder did not signal readiness: ${output}`);
        const collision = JSON.parse(run(process.execPath, [driver, stateDir, "contender", "My", "1"]));
        assert.equal(collision.gotLock, false, "nondefault store must also serialize My access");
        assert.equal(collision.code, "STORE_LOCKED");
        assert.equal(await completed, 0, output);
        assert.equal(JSON.parse(output).gotLock, true);
        const afterRelease = JSON.parse(run(process.execPath, [driver, stateDir, "after-release", "My", "1"]));
        assert.equal(afterRelease.gotLock, true, "released store lock must be reacquirable");
      } finally {
        if (child.exitCode === null) child.kill();
        await completed;
      }
    }, { evidenceLevel: "real-host", oracle: "independent Node processes contend on actual filesystem store locks; not certificate deployment E2E" });
    await gate.scenario("windows-release-package", async () => {
      await require("./package-fixture").qualifyPackage({ powershell, run, workDir });
    }, { evidenceLevel: "real-host", oracle: "actual product release archive, native SHA256, independently parsed amd64/arm64 PE headers, isolated imports and tamper rejection; unsigned candidate, not signed release provenance" });
    await gate.scenario("windows-scm-lifecycle", async () => {
      const output = run(process.execPath, ["--test", "--test-reporter=tap", "--test-name-pattern", "Windows service lifecycle smoke", path.resolve(__dirname, "../installer-smoke.test.js")], { env: { ...process.env, CERTOPS_QUALIFICATION_STRICT: "1" }, timeout: 300000 });
      assert.match(output, /^\s*ok \d+ - reaches Running and survives a Stop-Service \/ Start-Service cycle(?:\s|$)/m,
        "the mandatory SCM testcase must actually pass");
      assert.doesNotMatch(output, /^\s*ok \d+ - reaches Running.*# SKIP|^# skipped [1-9]/m,
        "selected SCM qualification tests may not silently skip");
      assert.doesNotMatch(output, /requires an elevated|pre-existing service|skipping rather than/);
    }, { evidenceLevel: "real-host", oracle: "SCM RUNNING/STOPPED/restart, exit17 recovery, exit86 no-recovery and bootstrap registry token scrub; fixture child, not registered production agent" });
    for (const [id, directory] of [["windows-service-host-go", "windows-service-host"], ["windows-adcs-chain-go", "reference/adcs-chain"], ["windows-adcs-cmc-go", "reference/adcs-cmc"], ["windows-verifier-go", "reference/verifier"]]) {
      await gate.scenario(id, async () => {
        const execution = spawnSync("go", ["test", "-count=1", "-json", "./..."], {
          cwd: path.resolve(__dirname, "../..", directory), timeout: 300000, encoding: "utf8", maxBuffer: 16 * 1024 * 1024,
          env: { ...process.env, GOOS: "windows", GOARCH: process.arch === "arm64" ? "arm64" : "amd64" },
        });
        assert.equal(execution.status, 0, "Go module qualification failed; raw output withheld");
        const report = require("./go-report").verifyGoExecution(execution.stdout);
        fs.writeFileSync(path.join(workDir, `${id}.log`), JSON.stringify(report));
      }, { evidenceLevel: "unit", oracle: "Go test assertions; not domain or SCM E2E evidence" });
    }
  } finally {
    await gate.scenario("windows-host-cleanup", async () => {
      const receipt = path.join(workDir, "discovery.receipt");
      if (!/^[A-F0-9]{40}$/.test(thumbprint || "") && fs.existsSync(receipt)) thumbprint = fs.readFileSync(receipt, "utf8").trim();
      if (thumbprint) assert.match(thumbprint, /^[A-F0-9]{40}$/);
      const { removeAbandonedKeyContainer } = require("../../src/windows-cert-store");
      const cleanupFailures = [];
      for (const issuedThumbprint of acceptedCertificates) {
        // Check both stores because a failed mirror can leave its initial
        // certreq-accepted copy in My before the target store is repaired.
        for (const store of new Set(["My", acceptedStores.get(issuedThumbprint)])) {
          try { powershell(`$p='Cert:\\LocalMachine\\${store}\\${issuedThumbprint}'; if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p }; if (Test-Path -LiteralPath $p) { throw 'Accepted fixture certificate remains' }`); }
          catch (error) { cleanupFailures.push(error); }
        }
      }
      for (const containerName of containers) {
        try {
          if (!run("certutil.exe", ["-csp", "Microsoft Software Key Storage Provider", "-key"]).includes(containerName)) continue;
          const result = await removeAbandonedKeyContainer({ containerName });
          assert.equal(result.ok, true, JSON.stringify(result));
          assert.ok(!run("certutil.exe", ["-csp", "Microsoft Software Key Storage Provider", "-key"]).includes(containerName), "owned CNG container remains");
        } catch (error) { cleanupFailures.push(error); }
      }
      try {
        if (thumbprint) powershell(`Remove-Item -LiteralPath 'Cert:\\LocalMachine\\My\\${thumbprint}' -DeleteKey; if (Test-Path -LiteralPath 'Cert:\\LocalMachine\\My\\${thumbprint}') { throw 'Fixture certificate remains' }`);
      } catch (error) { cleanupFailures.push(error); }
      // Keep diagnostic logs on failure when an artifact directory was requested.
      if (process.env.CERTOPS_HOST_ARTIFACTS) {
        fs.mkdirSync(process.env.CERTOPS_HOST_ARTIFACTS, { recursive: true });
        const artifactDir = path.join(process.env.CERTOPS_HOST_ARTIFACTS, path.basename(workDir));
        fs.mkdirSync(artifactDir, { recursive: true });
        // Explicit evidence allowlist: never upload the full host workdir.
        for (const name of ["discovery.log", "windows-native-chain.log", "windows-retention-elapsed.log", "windows-release-package.log", "windows-service-host-go.log", "windows-adcs-chain-go.log", "windows-adcs-cmc-go.log", "windows-verifier-go.log"]) {
          const source = path.join(workDir, name);
          if (fs.existsSync(source)) fs.copyFileSync(source, path.join(artifactDir, name));
        }
      }
      fs.rmSync(workDir, { recursive: true, force: true });
      if (cleanupFailures.length) throw new AggregateError(cleanupFailures, "Host fixture cleanup failed");
    }, { evidenceLevel: "real-host", oracle: "certificate absence and certutil KSP enumeration" });
    await gate.finish({ requiredScenarios: ["windows-retention-two-open-references-protect", "windows-retention-one-closed-reference-still-protects", "windows-retention-all-closed-respects-real-deadline", "windows-retention-atomic-replace-refusal", "windows-enrollment-lock-cng-contention", "windows-iis-shared-port-sni-isolation", "windows-cng-private-export-refusal", "windows-discovery-http-sys-selectors", "windows-discovery-fingerprint", "windows-discovery-constrained-language", "windows-user-store-boundary", "windows-cng-csr", "windows-native-chain-verdicts", "windows-trust-anchor-lifecycle", "windows-retention-owned-cleanup", "windows-retention-native-guards", "windows-retention-real-expiry-grace", "windows-retention-native-interrupted-delete", "windows-iis-deploy-rollback", "windows-iis-unsupported-targets", "windows-iis-rollback-failure", "windows-iis-sni-flags", "windows-iis-http-sys-flags", "windows-retention-process-durability", "windows-store-lock-worker-death", "windows-store-lock-drain-timeout", "windows-store-lock-process-death", "windows-installer-build-floor", "windows-cross-store-mutex", "windows-release-package", "windows-scm-lifecycle", "windows-service-host-go", "windows-adcs-chain-go", "windows-adcs-cmc-go", "windows-verifier-go", "windows-host-cleanup"] });
  }
});
