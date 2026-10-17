"use strict";
/* Actual Microsoft responder on the existing disposable CA. No native action
 * runs merely by importing this module. The native endpoint fault is an
 * independent CryptoAPI probe, plus an actual signed-agent deferred leaf and
 * same-leaf continuation. Neither path substitutes a native chain verdict.
 * Authoritative revoked status is a separate proof. Native lab execution of
 * that cell is still pending, and a missing disposable lab fails closed. */
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const tls = require("node:tls");
const { promisify, isDeepStrictEqual } = require("node:util");
const { execFile } = require("node:child_process");
const {
  applyRestrictivePermissions,
} = require("../../../packages/agent/src/platform");
const {
  buildEnrollmentContainerName,
  readIssuedContainerRecord,
} = require("../../../packages/agent/src/windows-cert-store");
const {
  readEnrollmentJournal,
} = require("../../../packages/agent/src/issuers/adcs-enrollment");
const {
  resolveAdcsChainHelperPath,
  validateCertificateChain,
} = require("../../../packages/agent/src/issuers/chain-helper");
const {
  verifyInstalledEvidence,
  verifyNativeRequestId,
} = require("./certops-adcs-live-enroll-acl");
const {
  ownedBytes,
  nativeEnvironment,
} = require("./certops-adcs-http-intermediate-crl");
const { verifyCrl } = require("./certops-adcs-http-leaf-crl-der");
const response = require("./certops-adcs-ocsp-response");
const proofContract = require("./certops-adcs-ocsp-proof");
const historicalRevoked = require("./certops-adcs-ocsp-revoked");
const deferredJourney = require("./certops-adcs-ocsp-deferred");
const {
  inspectMachineKeySurvivors,
} = require("../../../packages/agent/src/windows-key-survivors");
const {
  startContainedNativeProcess,
  assertContainedProcessesDrained,
} = require("./certops-windows-contained-process");
const execute = promisify(execFile);
const active = new Map();
const hash = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const fingerprint = (certificate) =>
  certificate.fingerprint256.replace(/:/g, "").toLowerCase();
const q = (text) => text.replace(/'/g, "''");
const REQUIRED_SOURCES = Object.freeze([
  "tests/e2e/helpers/certops-adcs-ocsp.js",
  "tests/e2e/helpers/certops-adcs-ocsp-proof.js",
  "tests/e2e/helpers/certops-adcs-ocsp-response.js",
  "tests/e2e/helpers/certops-adcs-ocsp-revoked.js",
  "infra/certops-adcs/ocsp-revoked-fixture.ps1",
  "packages/agent/src/windows-discovery/index.js",
  "scripts/certops_adcs_ocsp_revoked_proof.py",
  "tests/e2e/helpers/certops-adcs-ocsp-deferred.js",
  "tests/e2e/helpers/certops-adcs-deferred-continuation.js",
  "tests/e2e/helpers/certops-adcs-deferred-identity.js",
  "packages/agent/src/windows-key-survivors/index.js",
  "infra/certops-adcs/ocsp-member-operation.ps1",
  "infra/certops-adcs/ocsp-owned-key.ps1",
  "infra/certops-adcs/ocsp-responder-fixture.ps1",
  "infra/certops-adcs/ocsp-native-survivors.ps1",
  "infra/certops-adcs/ocsp-iis-owned.ps1",
  "tests/e2e/helpers/certops-windows-contained-process.js",
  "tests/e2e/helpers/certops-windows-contained-process.ps1",
  "tests/e2e/helpers/certops-windows-owned-process.ps1",
  "tests/e2e/helpers/certops-adcs-live-enroll-acl.js",
  "tests/e2e/helpers/certops-adcs-http-intermediate-crl.js",
  "tests/e2e/helpers/certops-adcs-http-leaf-crl-der.js",
  "infra/certops-adcs/owned-ca-checkpoint.ps1",
  "infra/certops-adcs/owned-issued-request.ps1",
  "packages/agent/src/platform/index.js",
  "packages/agent/src/windows-cert-store/index.js",
  "packages/agent/src/issuers/adcs-enrollment.js",
  "packages/agent/src/issuers/adcs.js",
  "packages/agent/src/issuers/chain-helper.js",
  "packages/agent/src/issuers/der-extensions.js",
  "packages/agent/reference/adcs-chain/chaincore/chain_windows.go",
  "scripts/certops_adcs_ocsp_proof.py",
]);
function assertCleanupSafe(workDir) {
  const root = path.resolve(workDir);
  assert.ok(
    !active.has(root),
    "Unresolved native OCSP ownership preserves the fixture",
  );
  assert.ok(
    !fs.existsSync(path.join(root, "ocsp-active.json")),
    "Durable native OCSP guard preserves the fixture",
  );
}
function sameOwned(file, original, maximum) {
  const now = ownedBytes(file, maximum);
  assert.ok(
    now.identity === original.identity && now.bytes.equals(original.bytes),
    "Owned OCSP file changed",
  );
  return now;
}
function verifyOperationDrain(value) {
  assert.equal(value.rootExitCode, 0);
  assert.equal(value.activeNativeProcesses, 0);
  assert.equal(value.nativeHandlesClosed, true);
  return value;
}
function requireNativeFlags(value, names) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value));
  for (const name of names)
    assert.equal(value[name], true, `Missing native OCSP completion: ${name}`);
}
async function qualifyOcsp(c) {
  assert.equal(process.platform, "win32");
  assert.equal(process.arch, "x64");
  assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB, "1");
  const {
    gate,
    fixture,
    api,
    agentRowId,
    renewalFixture: current,
    configDir,
    workDir,
    run,
    command,
    ps,
    jobFinished,
    tlsAuthority,
    ownedEnrollmentIds,
    ownedStoreReceipt,
    registerOwnership,
  } = c;
  assert.equal(
    ps("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value"),
    "S-1-5-18",
  );
  assert.ok(process.env.CERTOPS_ADCS_OFFICER_PASSWORD);
  assert.match(run, /^[a-f0-9]{10}$/);
  assert.equal(current.item.template, "TTQualificationRSAShort");
  assert.equal(current.item.domain, `certops-adcs-${run}-rsa2048.example.test`);
  assert.equal(ownedStoreReceipt.store, "My");
  assert.equal(ownedStoreReceipt.certificateId, current.certificateId);
  assert.equal(ownedStoreReceipt.domain, current.item.domain);
  assertCleanupSafe(workDir);
  assert.equal(
    (
      await fixture.pool.query(
        "SELECT count(*)::int AS count FROM certificate_jobs j LEFT JOIN certificate_enrollments e ON e.workspace_id=j.workspace_id AND e.current_job_id=j.id WHERE j.status IN ('pending','pending_approval','approved','claimed','running') OR (j.status='awaiting_issuer' AND e.state IN ('requested','prepared','submitting','pending_issuance','submission_uncertain','issued','validation_deferred','validated','installing','install_failed'))",
      )
    ).rows[0].count,
    0,
  );
  const root = path.resolve(__dirname, "../../..");
  const stateRoot = path.resolve(workDir);
  const token = crypto.randomUUID();
  const templateName = `TTQualificationOcsp${crypto.randomBytes(8).toString("hex")}`;
  const caBytes = Buffer.from(current.authority.certificateB64, "base64");
  const ca = new crypto.X509Certificate(caBytes);
  const caThumbprint = ca.fingerprint.replace(/:/g, "").toUpperCase();
  const helper = resolveAdcsChainHelperPath();
  assert.equal(helper.error, undefined);
  const helperPath = path.resolve(helper.path);
  const helperFile = ownedBytes(helperPath, 6291456);
  const helperSha = hash(helperFile.bytes);
  const sourceFiles = [
    "infra/certops-adcs/ocsp-owned-key.ps1",
    "infra/certops-adcs/ocsp-responder-fixture.ps1",
    "infra/certops-adcs/ocsp-iis-owned.ps1",
    "infra/certops-adcs/ocsp-revoked-fixture.ps1",
    "infra/certops-adcs/ocsp-native-survivors.ps1",
    "tests/e2e/helpers/certops-windows-contained-process.ps1",
    "tests/e2e/helpers/certops-windows-owned-process.ps1",
  ];
  const sourceSnapshots = new Map(
    sourceFiles.map((file) => [
      file,
      ownedBytes(path.join(root, file), 262144),
    ]),
  );
  const sources = Object.fromEntries(
    [...sourceSnapshots].map(([file, value]) => [file, hash(value.bytes)]),
  );
  sources.nativeChainHelper = helperSha;
  const guardPath = path.join(stateRoot, "ocsp-active.json");
  // In-memory authority precedes every possible launch and survives deletion of
  // a durable marker. Unknown remote/native state never authorizes parent cleanup.
  const resources = [];
  const owner = {
    hasLiveChild: () => resources.some((r) => r.hasLiveChild()),
    hasOwnershipReceipt: () => active.has(stateRoot),
    assertCleanupSafe: () => assertCleanupSafe(stateRoot),
  };
  active.set(stateRoot, owner);
  registerOwnership(owner);
  ownedStoreReceipt.ocspPendingVerification = true;
  fs.writeFileSync(
    guardPath,
    JSON.stringify({ schemaVersion: 1, run, token, caThumbprint }),
    { flag: "wx" },
  );
  applyRestrictivePermissions(guardPath, { kind: "file" });
  const guard = ownedBytes(guardPath, 1024);
  let sequence = 0;
  // A drained local WinRM client is not proof that a disconnected remote CA
  // operation stopped. Once dispatch is possible, any missing successful
  // completion is sticky and forbids another remote action, including restore.
  let remoteUncertain = false;
  const privateFiles = new Map([[guardPath, guard]]);
  const powershell = path.join(
    process.env.SystemRoot,
    "System32/WindowsPowerShell/v1.0/powershell.exe",
  );
  async function operation(action, payload = {}) {
    assert.equal(
      remoteUncertain,
      false,
      "Uncertain remote OCSP operation preserves lab without retry",
    );
    sameOwned(guardPath, guard, 1024);
    for (const [file, snapshot] of sourceSnapshots)
      sameOwned(path.join(root, file), snapshot, 262144);
    sameOwned(helperPath, helperFile, 6291456);
    const input = path.join(
      stateRoot,
      `ocsp-${token}-${++sequence}-input.json`,
    );
    const output = input + ".result";
    const go = input + ".go";
    fs.writeFileSync(
      input,
      JSON.stringify({
        schemaVersion: 1,
        action,
        runId: run,
        token,
        caThumbprint,
        templateName,
        payload,
        sources,
        helperPath,
      }),
      { flag: "wx" },
    );
    applyRestrictivePermissions(input, { kind: "file" });
    privateFiles.set(input, ownedBytes(input, 65536));
    let resource, closed;
    try {
      resource = await startContainedNativeProcess({
        executable: powershell,
        args: [
          "-NoProfile",
          "-NonInteractive",
          "-File",
          path.join(root, "infra/certops-adcs/ocsp-member-operation.ps1"),
          "-InputPath",
          input,
          "-OutputPath",
          output,
          "-OwnedGoPath",
          go,
        ],
        environment: {
          ...nativeEnvironment(),
          CERTOPS_ADCS_DISPOSABLE_LAB: "1",
          CERTOPS_ADCS_OFFICER_PASSWORD:
            process.env.CERTOPS_ADCS_OFFICER_PASSWORD,
        },
        workDir: stateRoot,
        maxLifetimeMs: 900000,
        expectedSid: "S-1-5-18",
        onCreated(value) {
          resources.push(value);
          closed = new Promise((resolve) =>
            value.wrapper.once("close", resolve),
          );
        },
      });
      sameOwned(input, privateFiles.get(input), 65536);
      remoteUncertain = true;
      fs.writeFileSync(go, token, { flag: "wx" });
      applyRestrictivePermissions(go, { kind: "file" });
      privateFiles.set(go, ownedBytes(go, 64));
      let timer;
      try {
        await Promise.race([
          closed,
          new Promise((_, reject) => {
            timer = setTimeout(
              () =>
                reject(new Error("Owned OCSP operation exceeded native bound")),
              920000,
            );
          }),
        ]);
      } finally {
        clearTimeout(timer);
      }
      const drained = await resource.stopAndDrain();
      assert.equal(drained.rootExitCode, 0);
      assert.equal(drained.activeNativeProcesses, 0);
      verifyOperationDrain(drained);
      const bytes = ownedBytes(output, 65536);
      privateFiles.set(output, bytes);
      sameOwned(guardPath, guard, 1024);
      const result = JSON.parse(bytes.bytes.toString("utf8"));
      assert.ok(result && typeof result === "object" && !Array.isArray(result));
      remoteUncertain = false;
      return result;
    } finally {
      if (resource || resources.length) {
        // onCreated registers even a rejected launch. Exact retained-job drain
        // is mandatory before any later native or fixture teardown.
        for (const held of resources) await held.stopAndDrain();
      }
    }
  }
  const native = (file, args) =>
    JSON.parse(
      command("powershell.exe", [
        "-NoProfile",
        "-NonInteractive",
        "-File",
        path.join(root, "infra/certops-adcs", file),
        ...args,
      ]),
    );
  const checkpoint = () =>
    native("owned-ca-checkpoint.ps1", ["-RunId", run]).nativeTotalRequestCount;
  function peer() {
    return new Promise((resolve, reject) => {
      let certificate, failure;
      const socket = tls.connect(
        {
          host: "127.0.0.1",
          port: current.port,
          servername: current.item.domain,
          ca: tlsAuthority(current.authority),
          rejectUnauthorized: true,
        },
        () => {
          try {
            assert.equal(socket.authorized, true);
            certificate = new crypto.X509Certificate(
              socket.getPeerCertificate().raw,
            );
          } catch (error) {
            failure = error;
          } finally {
            socket.destroy();
          }
        },
      );
      socket.once("error", (error) => {
        failure = error;
      });
      socket.once("close", () =>
        failure
          ? reject(failure)
          : certificate
            ? resolve(certificate)
            : reject(new Error("Owned OCSP trusted TLS ended without a peer")),
      );
      socket.setTimeout(10000, () =>
        socket.destroy(new Error("Owned OCSP trusted TLS timed out")),
      );
    });
  }
  let leaf = await peer(),
    accepted;
  assert.equal(leaf.fingerprint256, current.observed.fingerprint256);
  const counts = [checkpoint()];
  const generations = [];
  const custodyFor = (certificate, enrollmentId) => {
    const thumb = certificate.fingerprint.replace(/:/g, "").toUpperCase();
    const value = JSON.parse(
      ps(
        `$c=Get-Item 'Cert:\\LocalMachine\\My\\${thumb}';$k=$null;try{$k=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c);@{container=$k.Key.KeyName;unique=$k.Key.UniqueName;policy=[int]$k.Key.ExportPolicy;machine=$k.Key.IsMachineKey;provider=$k.Key.Provider.Provider;bits=$k.KeySize;der=[Convert]::ToBase64String($c.RawData)}|ConvertTo-Json -Compress}finally{if($k){$k.Dispose()};$c.Dispose()}`,
      ),
    );
    assert.ok(
      value.container === buildEnrollmentContainerName(enrollmentId),
      "Owned OCSP native container mismatch",
    );
    assert.equal(value.policy, 0);
    assert.equal(value.machine, true);
    assert.equal(value.bits, 2048);
    assert.equal(value.provider, "Microsoft Software Key Storage Provider");
    assert.ok(value.unique);
    assert.ok(Buffer.from(value.der, "base64").equals(certificate.raw));
    const record = readIssuedContainerRecord({
      stateDir: configDir,
      containerName: value.container,
    });
    assert.equal(record?.status, "enrolled_by_agent");
    assert.equal(record.acceptedStore, "My");
    assert.equal(record.acceptedThumbprint, thumb);
    return { value, record };
  };
  const custody = () => custodyFor(leaf, accepted.enrollmentId);
  const binding = () =>
    ps(
      `Import-Module WebAdministration;$b=@(Get-WebBinding -Name '${current.site}' -Protocol https|Where-Object bindingInformation -eq '*:${current.port}:${current.item.domain}');$s=@(Get-ChildItem -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\HTTP\\Parameters\\SslSniBindingInfo'|Where-Object {[string]$_.GetValue('HostnamePort') -ieq '${current.item.domain}:${current.port}'});if($b.Count -ne 1 -or $s.Count -ne 1 -or [int]$b[0].sslFlags -ne 1 -or [string]$b[0].certificateStoreName -ine 'My' -or ([BitConverter]::ToString([byte[]]$b[0].certificateHash).Replace('-','')) -cne '${leaf.fingerprint.replace(/:/g, "").toUpperCase()}' -or [string]$s[0].GetValue('SslCertStoreName') -ine 'My' -or [BitConverter]::ToString([byte[]]$s[0].GetValue('SslCertHash')).Replace('-','') -cne '${leaf.fingerprint.replace(/:/g, "").toUpperCase()}'){throw 'Owned OCSP native SNI binding changed'};@{coordinates=[string]$b[0].bindingInformation;flags=[int]$b[0].sslFlags;iisHash=[BitConverter]::ToString([byte[]]$b[0].certificateHash).Replace('-','');iisStore=[string]$b[0].certificateStoreName;settings=@($s[0].GetValueNames()|Sort-Object|ForEach-Object {@{name=$_;kind=$s[0].GetValueKind($_).ToString();value=$s[0].GetValue($_)}})}|ConvertTo-Json -Depth 8 -Compress`,
    );
  let deferredRecovery;
  async function renew(ocspOnly) {
    const previous = leaf;
    const outgoing = ocspOnly
      ? custodyFor(previous, current.currentEnrollmentId)
      : null;
    const outgoingBinding = ocspOnly ? binding() : null;
    const result = await fixture.request(`${api}/enrollments`, "POST", {
      issuerId: current.issuerId,
      certificateId: current.certificateId,
      agentId: agentRowId,
      target: {
        type: "windows-iis",
        reference: current.item.domain,
        store: "My",
        binding: {
          site: current.site,
          port: current.port,
          sniHost: current.item.domain,
        },
      },
      authorizedDnsNames: [current.item.domain],
      keyAlgorithm: "rsa",
      keySize: 2048,
    });
    assert.equal(result.status, 201);
    accepted = result.body;
    assert.match(accepted.enrollmentId, /^[a-f0-9-]{36}$/i);
    assert.match(accepted.jobId, /^[a-f0-9-]{36}$/i);
    ownedEnrollmentIds.push(accepted.enrollmentId);
    ownedStoreReceipt.enrollmentIds.push(accepted.enrollmentId);
    if (ocspOnly) {
      deferredRecovery = await deferredJourney.continueDeferredOcsp({
        fixture,
        enrollmentId: accepted.enrollmentId,
        originalJobId: accepted.jobId,
        agentRowId,
        configDir,
        until: c.until,
        jobFinished,
        observeIssued: (journal) =>
          native("owned-issued-request.ps1", [
            "-CommonName",
            current.item.domain,
            "-FingerprintSha256",
            fingerprint(new crypto.X509Certificate(journal.artifacts.leafPem)),
          ]),
        assertUnacceptedAndOutgoing: async (journal) => {
          const deferredLeaf = new crypto.X509Certificate(
            journal.artifacts.leafPem,
          );
          response.assertOcspOnlyLeaf(
            deferredLeaf.raw,
            "http://10.64.0.4/ocsp",
          );
          writeProbeArtifacts(deferredLeaf.raw);
          verifyFirewall();
          await signedStatus(deferredLeaf, false);
          assert.equal((await probe()).verdict, "revocation_unknown");
          const container = buildEnrollmentContainerName(accepted.enrollmentId);
          const challenge = crypto.randomBytes(32);
          const possession = JSON.parse(
            ps(
              `$k=[Security.Cryptography.CngKey]::Open('${q(container)}',[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider,[Security.Cryptography.CngKeyOpenOptions]::MachineKey);$rsa=$null;try{$rsa=[Security.Cryptography.RSACng]::new($k);@{machine=$k.IsMachineKey;policy=[int]$k.ExportPolicy;provider=$k.Provider.Provider;bits=$rsa.KeySize;signature=[Convert]::ToBase64String($rsa.SignData([Convert]::FromBase64String('${challenge.toString("base64")}'),[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1))}|ConvertTo-Json -Compress}finally{if($rsa){$rsa.Dispose()};$k.Dispose()}`,
            ),
          );
          assert.equal(possession.machine, true);
          assert.equal(possession.policy, 0);
          assert.equal(possession.bits, 2048);
          assert.equal(
            possession.provider,
            "Microsoft Software Key Storage Provider",
          );
          assert.equal(
            crypto.verify(
              "sha256",
              challenge,
              deferredLeaf.publicKey,
              Buffer.from(possession.signature, "base64"),
            ),
            true,
            "Actual deferred CNG key must sign for its issued public leaf",
          );
          const survivors = await inspectMachineKeySurvivors({
            containerName: container,
            helperPath,
          });
          assert.equal(survivors.ok, true);
          assert.equal(
            survivors.shared,
            false,
            "Deferred OCSP key already backs a certificate-store entry",
          );
          assert.equal((await peer()).fingerprint256, previous.fingerprint256);
          assert.ok(
            isDeepStrictEqual(
              custodyFor(previous, current.currentEnrollmentId),
              outgoing,
            ),
            "Deferred OCSP changed outgoing native custody",
          );
          assert.equal(binding(), outgoingBinding);
        },
        removeOwnedFault: () => {
          removeFirewall();
          command("certutil.exe", [
            "-setreg",
            "chain\\ChainCacheResyncFiletime",
            "@now",
          ]);
        },
      });
      accepted.jobId = deferredRecovery.continuationJobId;
    }
    await jobFinished(accepted.jobId);
    const row = (
      await fixture.pool.query(
        "SELECT state,request_id,current_job_id FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2",
        [fixture.workspaceId, accepted.enrollmentId],
      )
    ).rows[0];
    assert.equal(row.state, "installed");
    assert.equal(row.current_job_id, accepted.jobId);
    leaf = await peer();
    assert.notEqual(leaf.fingerprint256, previous.fingerprint256);
    assert.notEqual(leaf.serialNumber, previous.serialNumber);
    assert.ok(
      !leaf.publicKey
        .export({ type: "spki", format: "der" })
        .equals(previous.publicKey.export({ type: "spki", format: "der" })),
      "OCSP renewal reused a key",
    );
    assert.equal(leaf.checkHost(current.item.domain), current.item.domain);
    if (ocspOnly)
      response.assertOcspOnlyLeaf(leaf.raw, "http://10.64.0.4/ocsp");
    else
      assert.ok(
        !response.ocspUrls(leaf.raw).includes("http://10.64.0.4/ocsp"),
        "Restored leaf still depends on owned responder",
      );
    const thumb = leaf.fingerprint.replace(/:/g, "").toUpperCase();
    ownedStoreReceipt.thumbprints.push(thumb);
    custody();
    binding();
    const journal = readEnrollmentJournal(configDir, accepted.enrollmentId);
    assert.equal(journal.kind, "valid");
    assert.equal(journal.journal.jobId, accepted.jobId);
    assert.ok(
      journal.journal.containerName ===
        buildEnrollmentContainerName(accepted.enrollmentId),
      "Owned OCSP journal container mismatch",
    );
    const request = native("owned-issued-request.ps1", [
      "-CommonName",
      current.item.domain,
      "-FingerprintSha256",
      fingerprint(leaf),
    ]);
    assert.equal(request.disposition, 20);
    verifyNativeRequestId(
      request.requestId,
      row.request_id,
      journal.journal.requestId,
    );
    const job = (
      await fixture.pool.query(
        "SELECT status,claim_id FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",
        [fixture.workspaceId, accepted.jobId],
      )
    ).rows[0];
    const evidence = (
      await fixture.pool.query(
        "SELECT e.claim_id,e.metadata FROM certificate_evidence e JOIN certificate_jobs j ON j.workspace_id=e.workspace_id AND j.id=e.job_id WHERE e.workspace_id=$1 AND e.job_id=$2 AND e.evidence_type='validation.passed' AND e.claim_id=j.claim_id AND e.metadata->>'step'='verify'",
        [fixture.workspaceId, accepted.jobId],
      )
    ).rows;
    verifyInstalledEvidence(job, evidence, leaf);
    counts.push(checkpoint());
    assert.equal(counts.at(-1) - counts.at(-2), 1);
    const generation = {
      enrollmentId: accepted.enrollmentId,
      jobId: accepted.jobId,
      requestId: request.requestId,
      leaf,
    };
    generations.push(generation);
    current.observed = leaf;
    current.thumbprint = thumb;
    current.currentEnrollmentId = accepted.enrollmentId;
    return generation;
  }
  let prepared = false,
    publicationAttempted = false,
    publicationRestored = false,
    cleanupCompleted = false;
  let signer,
    signerRequestId,
    crl,
    payload,
    firewallOwned = false,
    cache = null,
    cacheRestored = false;
  const firewallName = `TTQualification-Ocsp-${token}`;
  const cachePath = path.join(stateRoot, `ocsp-${token}-cache.xml`);
  const cacheKey =
    "SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CertDllCreateCertificateChainEngine\\Config";
  const leafPath = path.join(stateRoot, `ocsp-${token}-leaf.cer`),
    caPath = path.join(stateRoot, `ocsp-${token}-ca.cer`);
  function writeProbeArtifacts(raw) {
    for (const [file, bytes] of [
      [leafPath, raw],
      [caPath, caBytes],
    ]) {
      if (privateFiles.has(file)) {
        const original = privateFiles.get(file);
        sameOwned(file, original, 65536);
        assert.ok(
          original.bytes.equals(bytes),
          "Owned OCSP probe bytes changed",
        );
        continue;
      }
      fs.writeFileSync(file, bytes, { flag: "wx" });
      applyRestrictivePermissions(file, { kind: "file" });
      privateFiles.set(file, ownedBytes(file, 65536));
    }
  }
  function installFirewall() {
    assert.equal(
      ps(
        `@(Get-NetFirewallRule -Name '${firewallName}' -ErrorAction SilentlyContinue).Count`,
      ),
      "0",
    );
    firewallOwned = true;
    ps(
      `New-NetFirewallRule -Name '${firewallName}' -DisplayName '${firewallName}' -Direction Outbound -Action Block -Enabled True -Profile Any -Program '${q(helperPath)}' -Protocol TCP -RemoteAddress '10.64.0.4' -RemotePort 80 -ErrorAction Stop|Out-Null`,
    );
    verifyFirewall();
  }
  function verifyFirewall() {
    ps(
      `$r=@(Get-NetFirewallRule -Name '${firewallName}' -ErrorAction Stop);if($r.Count -ne 1 -or $r[0].Direction -ne 'Outbound' -or $r[0].Action -ne 'Block' -or $r[0].Enabled -ne 'True'){throw 'Exact OCSP firewall rule required'};$a=@($r[0]|Get-NetFirewallApplicationFilter);$p=@($r[0]|Get-NetFirewallPortFilter);$d=@($r[0]|Get-NetFirewallAddressFilter);if($a.Count -ne 1 -or $p.Count -ne 1 -or $d.Count -ne 1 -or $a[0].Program -ine '${q(helperPath)}' -or [string]$p[0].Protocol -notin @('TCP','6') -or [string]$p[0].RemotePort -cne '80' -or @($d[0].RemoteAddress).Count -ne 1 -or [string]$d[0].RemoteAddress -cne '10.64.0.4'){throw 'Owned OCSP firewall filters changed'}`,
    );
  }
  function removeFirewall() {
    if (!firewallOwned) return;
    verifyFirewall();
    ps(
      `Get-NetFirewallRule -Name '${firewallName}' -ErrorAction Stop|Remove-NetFirewallRule -ErrorAction Stop;if(Get-NetFirewallRule -Name '${firewallName}' -ErrorAction SilentlyContinue){throw 'Owned OCSP firewall survived removal'}`,
    );
    firewallOwned = false;
  }
  function restoreCache() {
    if (!cache || cacheRestored) return;
    sameOwned(cachePath, cache, 8192);
    const encoded = Buffer.from(
      cache.bytes.toString("utf8").replace(/^\uFEFF/, ""),
    ).toString("base64");
    ps(
      `$s=[Management.Automation.PSSerializer]::Deserialize([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${encoded}')));$k=[Microsoft.Win32.Registry]::LocalMachine.CreateSubKey('${cacheKey}');try{if($s.exists){$kind=[Microsoft.Win32.RegistryValueKind][Enum]::Parse([Microsoft.Win32.RegistryValueKind],$s.kind);if($s.kind -eq 'Binary'){$v=[byte[]]$s.value;$k.SetValue('ChainCacheResyncFiletime',$v,$kind);if([Convert]::ToBase64String([byte[]]$k.GetValue('ChainCacheResyncFiletime')) -cne [Convert]::ToBase64String($v)){throw 'OCSP cache bytes not restored'}}else{$k.SetValue('ChainCacheResyncFiletime',[long]$s.value,$kind);if([long]$k.GetValue('ChainCacheResyncFiletime') -ne [long]$s.value){throw 'OCSP cache value not restored'}};if($k.GetValueKind('ChainCacheResyncFiletime').ToString() -cne $s.kind){throw 'OCSP cache kind not restored'}}else{$k.DeleteValue('ChainCacheResyncFiletime',$false);if(@($k.GetValueNames()) -contains 'ChainCacheResyncFiletime'){throw 'OCSP cache absence not restored'}}}finally{$k.Dispose()}`,
    );
    cacheRestored = true;
  }
  const responseDigests = [];
  async function signedStatus(
    certificate = generations[0].leaf,
    record = true,
    expectedStatus = "good",
  ) {
    const request = response.createRequest(certificate.raw, caBytes);
    const answer = await fetch("http://10.64.0.4/ocsp", {
      method: "POST",
      redirect: "error",
      headers: {
        "content-type": "application/ocsp-request",
        accept: "application/ocsp-response",
      },
      body: request,
      signal: AbortSignal.timeout(15000),
    });
    assert.equal(answer.status, 200);
    assert.equal(
      answer.headers.get("content-type")?.split(";")[0].trim().toLowerCase(),
      "application/ocsp-response",
    );
    assert.ok(Number(answer.headers.get("content-length") || 0) <= 65536);
    const reader = answer.body.getReader(),
      pieces = [];
    let length = 0;
    try {
      for (;;) {
        const part = await reader.read();
        if (part.done) break;
        length += part.value.length;
        assert.ok(length <= 65536);
        pieces.push(Buffer.from(part.value));
      }
    } finally {
      await reader.cancel();
    }
    const observed = response.verifyResponse(Buffer.concat(pieces), {
      leafBytes: certificate.raw,
      issuerBytes: caBytes,
      signerBytes: signer,
      expectedCaKeySha256: current.authority.keySha256,
    });
    if (expectedStatus !== null) assert.equal(observed.status, expectedStatus);
    if (record) {
      assert.equal(observed.status, "good");
      responseDigests.push(observed.responseSha256);
    }
    await operation("Observe", payload);
    return observed;
  }
  function probe() {
    sameOwned(helperPath, helperFile, 6291456);
    command("certutil.exe", [
      "-setreg",
      "chain\\ChainCacheResyncFiletime",
      "@now",
    ]);
    return validateCertificateChain({
      helperPath,
      certPath: leafPath,
      caKeySha256: current.authority.keySha256,
      caCertPath: caPath,
      revocationCheck: "require",
      execFileImpl: (file, args, options) =>
        execute(file, args, { ...options, env: nativeEnvironment() }),
    });
  }
  async function cleanup() {
    if (!prepared || !payload)
      throw new Error(
        "Incomplete OCSP setup preserves owned lab for destruction",
      );
    removeFirewall();
    restoreCache();
    if (publicationAttempted && !publicationRestored) {
      await operation("RestorePublication");
      publicationRestored = true;
    }
    requireNativeFlags(await operation("RemoveConfiguration", payload), [
      "nativeConfigurationAbsent",
    ]);
    requireNativeFlags(await operation("StopResponder"), [
      "exactOriginalProcessExited",
      "nativeServiceStopped",
      "ownedServiceDisabled",
    ]);
    const iis = await operation("StopIis");
    requireNativeFlags(iis, [
      "actualWorkersDrained",
      "ownedIisServicesStopped",
      "nativeHttpEndpointAbsent",
    ]);
    assert.equal(iis.sharedServiceHostTerminationQualified, false);
    const signerCleanup = await operation("RemoveSigner");
    requireNativeFlags(signerCleanup, [
      "originalSignerDaclRestored",
      "exactOwnedSignerPublicEntryAbsent",
      "completeNativeSurvivorScanVerified",
      "exactOwnedSignerKeyAbsent",
      "nativeScanHandlesClosed",
    ]);
    assert.equal(signerCleanup.nativeScanRootExitCode, 0);
    assert.equal(signerCleanup.nativeScanActiveProcesses, 0);
    requireNativeFlags(await operation("RestoreTemplate"), [
      "originalPublishedTemplatesRestored",
      "ownedTemplateAbsent",
      "ownedOidAbsent",
    ]);
    assertContainedProcessesDrained(stateRoot);
    cleanupCompleted = true;
  }
  try {
    await gate.scenario(
      proofContract.REQUIRED_SCENARIOS[0],
      async () => {
        await operation("Prepare");
        prepared = true;
        await operation("InstallRoles");
        const template = await operation("CreateTemplate");
        await operation("PublishTemplate");
        const issued = await operation("RequestSigner");
        signer = Buffer.from(issued.certificateBase64, "base64");
        response.verifySignerCertificate(
          signer,
          caBytes,
          current.authority.keySha256,
        );
        response.verifySignerTemplate(signer, template.templateOid);
        assert.equal(hash(signer), issued.facts.certificateSha256);
        signerRequestId = issued.facts.nativeRequestId;
        assert.ok(
          Number.isInteger(signerRequestId) &&
            signerRequestId > 0 &&
            signerRequestId <= 0xffffffff,
        );
        counts.push(checkpoint());
        assert.equal(counts[1] - counts[0], 1);
        await operation("AcceptSigner", { certificateSha256: hash(signer) });
        const publicCrl = await operation("ReadCrl");
        crl = Buffer.from(publicCrl.crlDerBase64, "base64");
        verifyCrl(crl, caBytes, current.authority.keySha256);
        payload = {
          caDerBase64: caBytes.toString("base64"),
          signerDerBase64: signer.toString("base64"),
          crlDerBase64: crl.toString("base64"),
        };
        await operation("Configure", { crlDerBase64: payload.crlDerBase64 });
        await operation("CaptureIis");
      },
      {
        evidenceLevel: "real-host",
        oracle:
          "owned native Microsoft responder/delegated current-CA signer, independent signature/EKU/noCheck/template and native configuration",
      },
    );
    await gate.scenario(
      "adcs-real-ocsp-deferred-same-leaf-signed-continuation",
      async () => {
        publicationAttempted = true;
        await operation("ApplyPublication");
        ps(
          `$k=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('${cacheKey}');try{$s=@{exists=[bool]($k -and @($k.GetValueNames()) -contains 'ChainCacheResyncFiletime')};if($s.exists){$s.kind=$k.GetValueKind('ChainCacheResyncFiletime').ToString();if($s.kind -notin @('QWord','Binary')){throw 'Unsupported OCSP cache policy'};$s.value=$k.GetValue('ChainCacheResyncFiletime')};$s|Export-Clixml -LiteralPath '${q(cachePath)}' -NoClobber -Encoding UTF8}finally{if($k){$k.Dispose()}}`,
        );
        applyRestrictivePermissions(cachePath, { kind: "file" });
        cache = ownedBytes(cachePath, 8192);
        privateFiles.set(cachePath, cache);
        installFirewall();
        command("certutil.exe", [
          "-setreg",
          "chain\\ChainCacheResyncFiletime",
          "@now",
        ]);
        await renew(true);
        await operation("RestorePublication");
        publicationRestored = true;
      },
      {
        evidenceLevel: "real-host",
        oracle:
          "actual signed agent validation_deferred then distinct signed continuation installs the same issued leaf/CSR/CNG key without another CA request",
      },
    );
    await gate.scenario(
      proofContract.REQUIRED_SCENARIOS[1],
      async () => {
        writeProbeArtifacts(generations[0].leaf.raw);
        const originalCustody = custody(),
          originalBinding = binding();
        const unchanged = async () => {
          assert.equal((await peer()).fingerprint256, leaf.fingerprint256);
          assert.ok(
            isDeepStrictEqual(custody(), originalCustody),
            "Native OCSP custody changed",
          );
          assert.ok(
            binding() === originalBinding,
            "Native OCSP binding changed",
          );
        };
        await signedStatus();
        assert.equal((await probe()).verdict, "valid");
        installFirewall();
        await signedStatus();
        assert.equal((await probe()).verdict, "revocation_unknown");
        await unchanged();
        removeFirewall();
        await signedStatus();
        assert.equal((await probe()).verdict, "valid");
        await unchanged();
      },
      {
        evidenceLevel: "real-host",
        oracle:
          "actual signed native OCSP good responses and shipped CryptoAPI valid/unknown/valid under exact helper-program firewall rule, unchanged CNG/IIS/TLS",
      },
    );
    let finalProof;
    await gate.scenario(
      proofContract.REQUIRED_SCENARIOS[2],
      async () => {
        await renew(false);
        const currentCustody = custody(),
          currentBinding = binding();
        let revokedResult;
        await gate.scenario(
          historicalRevoked.SCENARIO,
          async () => {
            revokedResult = await historicalRevoked.qualifyHistoricalRevoked({
              historical: generations[0],
              current: generations[1],
              issuerDer: caBytes,
              signerDer: signer,
              issuerKeySha256: current.authority.keySha256,
              originalCrl: crl,
              ps,
              operation,
              checkpoint,
              assertCurrent: async () => {
                assert.equal(
                  (await peer()).fingerprint256,
                  generations[1].leaf.fingerprint256,
                );
                assert.ok(
                  isDeepStrictEqual(custody(), currentCustody),
                  "Current replacement native key changed during historical revocation",
                );
                assert.ok(
                  binding() === currentBinding,
                  "Current replacement IIS/HTTP.sys changed during historical revocation",
                );
              },
              fetchRevoked: async (verifiedCrl) => {
                payload = {
                  ...payload,
                  crlDerBase64: verifiedCrl.toString("base64"),
                };
                return await c.until(async () => {
                  const observed = await signedStatus(
                    generations[0].leaf,
                    false,
                    null,
                  );
                  return observed.status === "revoked" ? observed : null;
                }, 60000);
              },
              probeRevoked: async (certificate) => {
                writeProbeArtifacts(certificate.raw);
                ps(
                  "& certutil.exe -urlcache 'http://10.64.0.4/ocsp' delete *> $null;$code=([long]$LASTEXITCODE -band 0xffffffffL);if($code -notin @(0L,0x80092004L,0x80070002L)){throw 'Exact owned OCSP URL cache eviction failed'}",
                );
                return await c.until(async () => {
                  const result = await probe();
                  if (result.verdict === "revoked") return result;
                  assert.ok(
                    ["valid", "revocation_unknown"].includes(result.verdict),
                    "Unrelated native chain failure during revoked probe",
                  );
                  return null;
                }, 60000);
              },
            });
          },
          {
            evidenceLevel: "real-host",
            oracle:
              "exact unserved historical native CA leaf revoked, independently signed fresh CRL/provider refresh and delegated OCSP plus CryptoAPI revoked, unchanged successor TLS",
          },
        );
        restoreCache();
        await cleanup();
        assert.equal(
          (await peer()).fingerprint256,
          generations[1].leaf.fingerprint256,
        );
        custody();
        binding();
        for (const [file, snapshot] of privateFiles)
          sameOwned(
            file,
            snapshot,
            file === cachePath ? 8192 : file === guardPath ? 1024 : 65536,
          );
        // All retained jobs and active native consumers are gone. Leave inert
        // newly installed role packages to mandatory disposable-lab destruction.
        for (const file of privateFiles.keys()) fs.unlinkSync(file);
        active.delete(stateRoot);
        ownedStoreReceipt.ocspPendingVerification = false;
        finalProof = proofContract.verifyProof({
          scope: proofContract.SCOPE,
          enrollmentIds: generations.map((g) => g.enrollmentId),
          jobIds: generations.map((g) => g.jobId),
          requestIds: generations.map((g) => g.requestId),
          signerRequestId,
          leafFingerprints: generations.map((g) => fingerprint(g.leaf)),
          signerFingerprint: fingerprint(new crypto.X509Certificate(signer)),
          issuerKeySha256: current.authority.keySha256,
          nativeHelperSha256: helperSha,
          publicCrlSha256: hash(crl),
          responseSha256: responseDigests,
          caRequestCounts: counts,
          nativeVerdicts: ["valid", "revocation_unknown", "valid"],
          deferredRecovery,
          ...Object.fromEntries(
            proofContract.FLAGS.map((flag) => [flag, true]),
          ),
          ...Object.fromEntries(
            proofContract.FALSE_FLAGS.map((flag) => [flag, false]),
          ),
        });
        gate.report.nativeOcspRevoked = historicalRevoked.verifyCrossProof(
          {
            ...revokedResult.facts,
            ...Object.fromEntries(
              historicalRevoked.FLAGS.map((flag) => [flag, true]),
            ),
            ...Object.fromEntries(
              historicalRevoked.FALSE_FLAGS.map((flag) => [flag, false]),
            ),
          },
          finalProof,
        );
      },
      {
        evidenceLevel: "real-host",
        oracle:
          "actual restored-publication second renewal then exact native responder/IIS/config/template/signing key drainage; inert packages remain for lab destruction",
      },
    );
    gate.report.fixtureSources ??= [];
    for (const file of REQUIRED_SOURCES)
      gate.report.fixtureSources.push({
        file,
        sha256: hash(fs.readFileSync(path.join(root, file))),
      });
    return finalProof;
  } finally {
    // Failed execution never clears either durable or in-memory custody.
    // Restoration can remove an exact firewall/publication fault, but cannot
    // turn an incomplete native operation into successful qualification.
    try {
      removeFirewall();
    } finally {
      try {
        restoreCache();
      } finally {
        try {
          if (publicationAttempted && !publicationRestored)
            await operation("RestorePublication");
        } finally {
          for (const held of resources) await held.stopAndDrain();
        }
      }
    }
    if (!cleanupCompleted)
      assert.ok(
        active.has(stateRoot),
        "Failed OCSP fixture lost ownership guard",
      );
  }
}
module.exports = {
  verifyOperationDrain,
  ...proofContract,
  REQUIRED_SOURCES,
  qualifyOcsp,
  assertCleanupSafe,
};
