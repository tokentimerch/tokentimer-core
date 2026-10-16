"use strict";
/* Real installed-agent renewal with a temporarily HTTP-only leaf CDP. Restore
 * the issuing CA's publication before withdrawing this exact owned endpoint.
 * Native verdicts come exclusively from the shipped CryptoAPI helper. No
 * OCSP, signed CMC or issuing-CA outage qualification is implied.
 */
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
const { assertHttpOnlyLeafCdp } = require("./certops-adcs-http-leaf-crl-der");
const {
  continueDeferredIssuedLeaf,
} = require("./certops-adcs-deferred-continuation");
const {
  inspectMachineKeySurvivors,
} = require("../../../packages/agent/src/windows-key-survivors");
const {
  createOwnedListener,
  verifyPublication,
  assertCleanupSafe,
} = require("./certops-adcs-http-leaf-crl-server");
const execute = promisify(execFile);
const SCOPE =
  "real-installed-adcs-http-only-leaf-crl-endpoint-unavailable-and-recovered";
const REQUIRED_SCENARIOS = Object.freeze([
  "adcs-real-http-only-leaf-crl-public-renewal",
  "adcs-real-http-only-leaf-crl-endpoint-recovers",
  "adcs-real-http-only-leaf-crl-signed-deferred-continuation",
]);
const FLAGS = Object.freeze([
  "originalCaPublicationReceiptBound",
  "actualSignedPinnedPublicCrl",
  "actualHttpOnlyLeafCdp",
  "publicRenewalInstalled",
  "currentClaimBoundEvidence",
  "independentNativeRequestId",
  "exactCaPublicationRestoredBeforeFault",
  "freshNativeChainValidBefore",
  "actualOwnedHttp503",
  "freshNativeRevocationUnknown",
  "sameSignedCrlRecovered",
  "freshNativeChainValidAfter",
  "sameNonexportableCngCustody",
  "sameNativeBindingAndTrustedTls",
  "originalCachePolicyRestored",
  "ownedListenerClosed",
  "ownedGuardReleased",
  "restoredPublicationLeafInstalledBeforeListenerClose",
  "installedAgentFaultRecoveryQualified",
]);
const REQUIRED_SOURCES = Object.freeze([
  "tests/e2e/helpers/certops-adcs-http-leaf-crl.js",
  "tests/e2e/helpers/certops-adcs-http-leaf-crl-server.js",
  "tests/e2e/helpers/certops-adcs-http-leaf-crl-der.js",
  "tests/e2e/helpers/certops-adcs-http-intermediate-crl.js",
  "tests/e2e/helpers/certops-adcs-live-enroll-acl.js",
  "tests/e2e/helpers/certops-adcs-deferred-continuation.js",
  "tests/e2e/helpers/certops-adcs-deferred-identity.js",
  "packages/agent/src/windows-key-survivors/index.js",
  "infra/certops-adcs/http-leaf-crl-publication.ps1",
  "infra/certops-adcs/owned-ca-checkpoint.ps1",
  "infra/certops-adcs/owned-issued-request.ps1",
  "packages/agent/src/platform/index.js",
  "packages/agent/src/windows-cert-store/index.js",
  "packages/agent/src/issuers/adcs-enrollment.js",
  "packages/agent/src/issuers/adcs.js",
  "packages/agent/src/issuers/chain-helper.js",
  "packages/agent/src/issuers/der-extensions.js",
  "packages/agent/reference/adcs-chain/chaincore/chain_windows.go",
  "scripts/certops_adcs_http_leaf_crl_proof.py",
]);
const hash = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const normalized = (fingerprint) => fingerprint.replace(/:/g, "").toLowerCase();
const uuid = (value) =>
  typeof value === "string" &&
  /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(value);
function verifyProof(value) {
  assert.deepEqual(
    Object.keys(value).sort(),
    [
      "scope",
      "enrollmentId",
      "jobId",
      "requestId",
      "leafFingerprint",
      "restoredEnrollmentId",
      "restoredJobId",
      "restoredRequestId",
      "restoredLeafFingerprint",
      "publicCrlSha256",
      "nativeHelperSha256",
      "originalPublicationSha256",
      "appliedPublicationSha256",
      "caRequestCounts",
      "nativeVerdicts",
      "endpointStatusCodes",
      "ocspQualified",
      "caOutageQualified",
      "signedCmcRenewalQualified",
      "deferredRecovery",
      ...FLAGS,
    ].sort(),
  );
  assert.equal(value.scope, SCOPE);
  for (const key of [
    "enrollmentId",
    "jobId",
    "restoredEnrollmentId",
    "restoredJobId",
  ])
    assert.ok(uuid(value[key]));
  assert.notEqual(
    value.enrollmentId.toLowerCase(),
    value.restoredEnrollmentId.toLowerCase(),
  );
  assert.notEqual(value.jobId.toLowerCase(), value.restoredJobId.toLowerCase());
  assert.ok(
    Number.isInteger(value.requestId) &&
      value.requestId > 0 &&
      value.requestId <= 0xffffffff,
  );
  assert.ok(
    Number.isInteger(value.restoredRequestId) &&
      value.restoredRequestId > 0 &&
      value.restoredRequestId <= 0xffffffff,
  );
  assert.notEqual(value.requestId, value.restoredRequestId);
  for (const key of [
    "leafFingerprint",
    "restoredLeafFingerprint",
    "publicCrlSha256",
    "nativeHelperSha256",
    "originalPublicationSha256",
    "appliedPublicationSha256",
  ])
    assert.match(value[key], /^[a-f0-9]{64}$/);
  assert.notEqual(
    value.originalPublicationSha256,
    value.appliedPublicationSha256,
  );
  assert.notEqual(value.leafFingerprint, value.restoredLeafFingerprint);
  assert.equal(value.caRequestCounts.length, 3);
  for (const count of value.caRequestCounts)
    assert.ok(Number.isInteger(count) && count >= 0 && count <= 2048);
  assert.equal(value.caRequestCounts[1] - value.caRequestCounts[0], 1);
  assert.equal(value.caRequestCounts[2] - value.caRequestCounts[1], 1);
  assert.deepEqual(value.nativeVerdicts, [
    "valid",
    "revocation_unknown",
    "valid",
  ]);
  assert.deepEqual(value.endpointStatusCodes, [200, 503, 200]);
  for (const flag of FLAGS) assert.equal(value[flag], true, flag);
  for (const flag of [
    "ocspQualified",
    "caOutageQualified",
    "signedCmcRenewalQualified",
  ])
    assert.equal(value[flag], false);
  const recovery = value.deferredRecovery;
  assert.ok(
    recovery && typeof recovery === "object" && !Array.isArray(recovery),
  );
  assert.deepEqual(
    Object.keys(recovery).sort(),
    [
      "originalJobId",
      "originalClaimId",
      "continuationJobId",
      "continuationClaimId",
      "requestId",
    ].sort(),
  );
  for (const key of [
    "originalJobId",
    "originalClaimId",
    "continuationJobId",
    "continuationClaimId",
  ])
    assert.ok(uuid(recovery[key]));
  assert.ok(
    ![value.jobId, value.restoredJobId]
      .map((id) => id.toLowerCase())
      .includes(recovery.originalJobId.toLowerCase()),
  );
  assert.notEqual(
    recovery.originalClaimId.toLowerCase(),
    recovery.continuationClaimId.toLowerCase(),
  );
  assert.equal(recovery.continuationJobId, value.jobId);
  assert.equal(recovery.requestId, value.requestId);
  return value;
}

async function qualifyHttpOnlyLeafCrl(c) {
  assert.equal(process.platform, "win32");
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
  const { item, issuerId, certificateId, site, port, authority } = current;
  assert.equal(item.template, "TTQualificationRSAShort");
  assert.equal(item.algorithm, "rsa");
  assert.equal(item.size, 2048);
  assert.match(
    item.domain,
    /^certops-adcs-[a-f0-9]{10}-rsa2048\.example\.test$/,
  );
  assert.equal(item.domain, `certops-adcs-${run}-rsa2048.example.test`);
  assert.equal(site, `TTADCS-${run}-rsa2048`);
  assert.ok(Number.isInteger(port) && port > 0 && port < 65536);
  assert.equal(ownedStoreReceipt.store, "My");
  assert.equal(ownedStoreReceipt.domain, item.domain);
  assert.equal(ownedStoreReceipt.certificateId, certificateId);
  assert.ok(
    Array.isArray(ownedStoreReceipt.enrollmentIds) &&
      Array.isArray(ownedStoreReceipt.thumbprints),
  );
  // Global publication can only change in this bounded otherwise-idle lab.
  assert.equal(
    (
      await fixture.pool.query(
        "SELECT count(*)::int AS count FROM certificate_jobs j LEFT JOIN certificate_enrollments e ON e.workspace_id=j.workspace_id AND e.current_job_id=j.id WHERE j.status IN ('pending','pending_approval','approved','claimed','running') OR (j.status='awaiting_issuer' AND e.state IN ('requested','prepared','submitting','pending_issuance','submission_uncertain','issued','validation_deferred','validated','installing','install_failed'))",
      )
    ).rows[0].count,
    0,
  );
  const root = path.resolve(__dirname, "../../..");
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
  const checkpoint = () => native("owned-ca-checkpoint.ps1", ["-RunId", run]);
  const peer = () =>
    new Promise((resolve, reject) => {
      let observed;
      const socket = tls.connect(
        {
          host: "127.0.0.1",
          port,
          servername: item.domain,
          ca: tlsAuthority(authority),
          rejectUnauthorized: true,
        },
        () => {
          try {
            assert.equal(socket.authorized, true);
            observed = new crypto.X509Certificate(
              socket.getPeerCertificate().raw,
            );
          } catch (error) {
            reject(error);
          } finally {
            socket.destroy();
          }
        },
      );
      socket.once("close", () => {
        if (observed) resolve(observed);
        else
          reject(
            new Error(
              "HTTP leaf CRL TLS closed before native certificate observation",
            ),
          );
      });
      socket.once("error", reject);
      socket.setTimeout(10000, () =>
        socket.destroy(
          new Error("HTTP leaf CRL trusted TLS observation timed out"),
        ),
      );
    });
  const original = await peer();
  assert.equal(original.fingerprint256, current.observed.fingerprint256);
  const caBytes = Buffer.from(authority.certificateB64, "base64");
  const ca = new crypto.X509Certificate(caBytes);
  const caThumbprint = ca.fingerprint.replace(/:/g, "").toUpperCase();
  const selected = resolveAdcsChainHelperPath();
  assert.equal(selected.error, undefined);
  const program = path.resolve(selected.path);
  const programFile = ownedBytes(program, 16 * 1024 * 1024);
  const programHash = hash(programFile.bytes);
  // This pending bit also fences broad parent My/key cleanup on unknown results.
  ownedStoreReceipt.httpLeafCrlPendingVerification = true;
  const listener = await createOwnedListener({
    workDir,
    run,
    registerOwnership,
  });
  const expected = {
    runId: run,
    token: listener.token,
    caThumbprint,
    httpUrl: listener.httpUrl,
    caBytes,
    caKeySha256: authority.keySha256,
  };
  const publication = (action) =>
    native("http-leaf-crl-publication.ps1", [
      "-Action",
      action,
      "-RunId",
      run,
      "-OwnershipToken",
      listener.token,
      "-ExpectedCaThumbprint",
      caThumbprint,
      "-HttpPort",
      String(listener.httpPort),
    ]);
  let attemptedPublication = false,
    restored = false,
    applied,
    successful,
    leaf,
    custodyBefore,
    bindingBefore,
    cacheRestored = false,
    cache = null,
    deferredRecovery;
  const leafPath = path.join(workDir, `http-leaf-crl-${listener.token}.cer`);
  const caPath = path.join(workDir, `http-leaf-crl-ca-${listener.token}.cer`);
  const cachePath = path.join(
    workDir,
    `http-leaf-crl-cache-${listener.token}.xml`,
  );
  const q = (text) => text.replace(/'/g, "''");
  const cacheKey =
    "SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CertDllCreateCertificateChainEngine\\Config";
  const clearCache = () => {
    // Only this fixture's unique URL is evicted. A missing entry is harmless;
    // actual new HTTP requests remain mandatory for every native verdict.
    ps(
      `& certutil.exe -urlcache '${listener.httpUrl}' delete *> $null;$code=([long]$LASTEXITCODE -band 0xffffffffL);if($code -notin @(0L,0x80092004L,0x80070002L)){throw 'Exact owned CRL cache eviction failed'}`,
    );
    command("certutil.exe", [
      "-setreg",
      "chain\\ChainCacheResyncFiletime",
      "@now",
    ]);
  };
  const captureCache = () => {
    assert.equal(
      cache,
      null,
      "Cache policy must be captured before its first mutation",
    );
    ps(
      `$k=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('${cacheKey}');try{$s=@{exists=[bool]($k -and @($k.GetValueNames()) -contains 'ChainCacheResyncFiletime')};if($s.exists){$s.kind=$k.GetValueKind('ChainCacheResyncFiletime').ToString();if($s.kind -notin @('QWord','Binary')){throw 'Unsupported cache policy'};$s.value=$k.GetValue('ChainCacheResyncFiletime')};$s|Export-Clixml -LiteralPath '${q(cachePath)}' -NoClobber -Encoding UTF8}finally{if($k){$k.Dispose()}}`,
    );
    applyRestrictivePermissions(cachePath, { kind: "file" });
    cache = ownedBytes(cachePath, 8192);
  };
  const restoreCache = () => {
    if (!cache || cacheRestored) return;
    const now = ownedBytes(cachePath, 8192);
    assert.ok(
      now.identity === cache.identity && now.bytes.equals(cache.bytes),
      "Original cache policy receipt changed",
    );
    const encoded = Buffer.from(
      cache.bytes.toString("utf8").replace(/^\uFEFF/, ""),
    ).toString("base64");
    ps(
      `$s=[Management.Automation.PSSerializer]::Deserialize([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${encoded}')));$k=[Microsoft.Win32.Registry]::LocalMachine.CreateSubKey('${cacheKey}');try{if($s.exists){$kind=[Microsoft.Win32.RegistryValueKind][Enum]::Parse([Microsoft.Win32.RegistryValueKind],$s.kind);if($s.kind -eq 'Binary'){$v=[byte[]]$s.value;$k.SetValue('ChainCacheResyncFiletime',$v,$kind);if([Convert]::ToBase64String([byte[]]$k.GetValue('ChainCacheResyncFiletime')) -cne [Convert]::ToBase64String($v)){throw 'Cache bytes not restored'}}else{$k.SetValue('ChainCacheResyncFiletime',[long]$s.value,$kind);if([long]$k.GetValue('ChainCacheResyncFiletime') -ne [long]$s.value){throw 'Cache value not restored'}};if($k.GetValueKind('ChainCacheResyncFiletime').ToString() -cne $s.kind){throw 'Cache kind not restored'}}else{$k.DeleteValue('ChainCacheResyncFiletime',$false);if(@($k.GetValueNames()) -contains 'ChainCacheResyncFiletime'){throw 'Cache absence not restored'}}}finally{$k.Dispose()}`,
    );
    cacheRestored = true;
  };
  const custodyFor = (certificate, enrollmentId) => {
    const thumb = certificate.fingerprint.replace(/:/g, "").toUpperCase();
    const value = JSON.parse(
      ps(
        `$c=Get-Item 'Cert:\\LocalMachine\\My\\${thumb}';$k=$null;try{$k=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c);@{container=$k.Key.KeyName;unique=$k.Key.UniqueName;policy=[int]$k.Key.ExportPolicy;machine=$k.Key.IsMachineKey;provider=$k.Key.Provider.Provider;bits=$k.KeySize;der=[Convert]::ToBase64String($c.RawData)}|ConvertTo-Json -Compress}finally{if($k){$k.Dispose()};$c.Dispose()}`,
      ),
    );
    assert.equal(value.policy, 0);
    assert.equal(value.machine, true);
    assert.equal(value.bits, 2048);
    assert.equal(value.provider, "Microsoft Software Key Storage Provider");
    assert.ok(
      value.container === buildEnrollmentContainerName(enrollmentId),
      "HTTP leaf native container ownership changed",
    );
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
  const custody = () => custodyFor(leaf, successful.enrollmentId);
  const binding = () =>
    ps(
      `Import-Module WebAdministration;$b=@(Get-WebBinding -Name '${site}' -Protocol https|Where-Object bindingInformation -eq '*:${port}:${item.domain}');$keys=@(Get-ChildItem -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\HTTP\\Parameters\\SslSniBindingInfo'|Where-Object {[string]$_.GetValue('HostnamePort') -ieq '${item.domain}:${port}'});if($b.Count -ne 1 -or $keys.Count -ne 1){throw 'Exact owned SNI binding required'};$h=[BitConverter]::ToString([byte[]]$keys[0].GetValue('SslCertHash')).Replace('-','');$store=[string]$keys[0].GetValue('SslCertStoreName');if($h -cne '${leaf.fingerprint.replace(/:/g, "").toUpperCase()}' -or $store -ine 'My' -or [int]$b[0].sslFlags -ne 1){throw 'HTTP leaf native binding mismatch'};@{hash=$h;store=$store;coordinates=[string]$b[0].bindingInformation;flags=[int]$b[0].sslFlags;settings=@($keys[0].GetValueNames()|Sort-Object|ForEach-Object {@{name=$_;kind=$keys[0].GetValueKind($_).ToString();value=$keys[0].GetValue($_)}})}|ConvertTo-Json -Depth 8 -Compress`,
    );
  const unchanged = async () => {
    assert.equal((await peer()).fingerprint256, leaf.fingerprint256);
    assert.ok(
      isDeepStrictEqual(custody(), custodyBefore),
      "HTTP-only leaf CNG custody changed",
    );
    assert.equal(
      binding() === bindingBefore,
      true,
      "HTTP-only leaf SNI settings changed",
    );
  };
  const counts = [checkpoint().nativeTotalRequestCount];
  const performEnrollment = async (httpOnly) => {
    const previous = leaf || original;
    const outgoing = httpOnly
      ? custodyFor(previous, current.currentEnrollmentId)
      : null;
    if (httpOnly) leaf = previous;
    const outgoingBinding = httpOnly ? binding() : null;
    const unavailableBefore = listener.observations().unavailable;
    const response = await fixture.request(`${api}/enrollments`, "POST", {
      issuerId,
      certificateId,
      agentId: agentRowId,
      target: {
        type: "windows-iis",
        reference: item.domain,
        store: "My",
        binding: { site, port, sniHost: item.domain },
      },
      authorizedDnsNames: [item.domain],
      keyAlgorithm: "rsa",
      keySize: 2048,
    });
    assert.equal(response.status, 201);
    successful = response.body;
    assert.ok(uuid(successful.enrollmentId) && uuid(successful.jobId));
    ownedEnrollmentIds.push(successful.enrollmentId);
    ownedStoreReceipt.enrollmentIds.push(successful.enrollmentId);
    if (httpOnly) {
      let servedBeforeContinuation;
      deferredRecovery = await continueDeferredIssuedLeaf({
        fixture,
        enrollmentId: successful.enrollmentId,
        originalJobId: successful.jobId,
        agentRowId,
        configDir,
        until: c.until,
        jobFinished,
        observeIssued: (journal) =>
          native("owned-issued-request.ps1", [
            "-CommonName",
            item.domain,
            "-FingerprintSha256",
            normalized(
              new crypto.X509Certificate(journal.artifacts.leafPem)
                .fingerprint256,
            ),
          ]),
        assertUnacceptedAndOutgoing: async (journal) => {
          assert.ok(
            listener.observations().unavailable > unavailableBefore,
            "Actual installed agent must encounter owned HTTP503",
          );
          const deferredLeaf = new crypto.X509Certificate(
            journal.artifacts.leafPem,
          );
          assertHttpOnlyLeafCdp(deferredLeaf.raw, listener.httpUrl);
          const container = buildEnrollmentContainerName(
              successful.enrollmentId,
            ),
            challenge = crypto.randomBytes(32);
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
            helperPath: program,
          });
          assert.equal(survivors.ok, true);
          assert.equal(
            survivors.shared,
            false,
            "Deferred HTTP leaf already backs a certificate-store entry",
          );
          assert.equal((await peer()).fingerprint256, previous.fingerprint256);
          assert.ok(
            isDeepStrictEqual(
              custodyFor(previous, current.currentEnrollmentId),
              outgoing,
            ),
            "Deferred HTTP changed outgoing native custody",
          );
          assert.equal(binding(), outgoingBinding);
        },
        removeOwnedFault: () => {
          servedBeforeContinuation = listener.observations().served;
          listener.setUnavailable(false);
          clearCache();
        },
      });
      assert.ok(
        listener.observations().served > servedBeforeContinuation,
        "Actual signed continuation must refetch the same owned CRL after HTTP503",
      );
      successful.jobId = deferredRecovery.continuationJobId;
    }
    await jobFinished(successful.jobId);
    const row = (
      await fixture.pool.query(
        "SELECT state,request_id,current_job_id FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2",
        [fixture.workspaceId, successful.enrollmentId],
      )
    ).rows[0];
    assert.equal(row.state, "installed");
    assert.equal(row.current_job_id, successful.jobId);
    leaf = await peer();
    assert.notEqual(leaf.fingerprint256, previous.fingerprint256);
    assert.notEqual(leaf.serialNumber, previous.serialNumber);
    assert.equal(
      leaf.publicKey
        .export({ type: "spki", format: "der" })
        .equals(previous.publicKey.export({ type: "spki", format: "der" })),
      false,
      "Actual renewal must use a distinct native key",
    );
    assert.equal(leaf.checkHost(item.domain), item.domain);
    if (httpOnly) assertHttpOnlyLeafCdp(leaf.raw, listener.httpUrl);
    else {
      const extensions =
        require("../../../packages/agent/src/issuers/der-extensions").listCertificateExtensions(
          leaf.raw,
        );
      const cdp = extensions.filter(
        (extension) => extension.oid === "2.5.29.31",
      );
      assert.equal(cdp.length, 1);
      assert.equal(
        cdp[0].value.includes(Buffer.from(listener.httpUrl, "ascii")),
        false,
        "Restored publication leaf still depends on owned endpoint",
      );
    }
    const thumb = leaf.fingerprint.replace(/:/g, "").toUpperCase();
    ownedStoreReceipt.thumbprints.push(thumb);
    custodyBefore = custody();
    bindingBefore = binding();
    const journal = readEnrollmentJournal(configDir, successful.enrollmentId);
    assert.equal(journal.kind, "valid");
    assert.equal(journal.journal.jobId, successful.jobId);
    assert.ok(
      journal.journal.containerName ===
        buildEnrollmentContainerName(successful.enrollmentId),
      "HTTP leaf journal container ownership changed",
    );
    const request = native("owned-issued-request.ps1", [
      "-CommonName",
      item.domain,
      "-FingerprintSha256",
      normalized(leaf.fingerprint256),
    ]);
    assert.equal(request.disposition, 20);
    verifyNativeRequestId(
      request.requestId,
      row.request_id,
      journal.journal.requestId,
    );
    successful.requestId = request.requestId;
    const job = (
      await fixture.pool.query(
        "SELECT status,claim_id FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",
        [fixture.workspaceId, successful.jobId],
      )
    ).rows[0];
    const evidence = (
      await fixture.pool.query(
        "SELECT e.claim_id,e.metadata FROM certificate_evidence e JOIN certificate_jobs j ON j.workspace_id=e.workspace_id AND j.id=e.job_id WHERE e.workspace_id=$1 AND e.job_id=$2 AND e.evidence_type='validation.passed' AND e.claim_id=j.claim_id AND e.metadata->>'step'='verify'",
        [fixture.workspaceId, successful.jobId],
      )
    ).rows;
    verifyInstalledEvidence(job, evidence, leaf);
    counts.push(checkpoint().nativeTotalRequestCount);
    assert.equal(counts.at(-1) - counts.at(-2), 1);
    current.observed = leaf;
    current.thumbprint = thumb;
    current.currentEnrollmentId = successful.enrollmentId;
    return { ...successful, leaf };
  };
  let proof, httpIssued, repaired;
  try {
    await gate.scenario(
      REQUIRED_SCENARIOS[2],
      async () => {
        attemptedPublication = true;
        applied = verifyPublication(publication("Apply"), expected, "Apply");
        listener.setVerifiedCrl(applied.crl, caBytes, authority.keySha256);
        captureCache();
        listener.setUnavailable(true);
        clearCache();
        httpIssued = await performEnrollment(true);
        const restoredPublication = publication("Restore");
        verifyPublication(
          restoredPublication,
          { ...expected, ...applied.publication },
          "Restore",
        );
        restored = true;
      },
      {
        evidenceLevel: "real-host",
        oracle:
          "actual signed HTTP503 validation-deferred result, unaccepted CNG key/outgoing TLS preservation, then same-leaf signed continuation without another CA request",
      },
    );
    await gate.scenario(
      REQUIRED_SCENARIOS[0],
      async () => {
        assert.equal(
          (await peer()).fingerprint256,
          httpIssued.leaf.fingerprint256,
        );
        custody();
        binding();
        assert.equal(deferredRecovery.continuationJobId, httpIssued.jobId);
        assert.equal(deferredRecovery.requestId, httpIssued.requestId);
      },
      {
        evidenceLevel: "real-host",
        oracle:
          "actual public HTTP-only renewal installed by the current signed continuation, independently bound CA/CNG/IIS/trusted TLS",
      },
    );
    await gate.scenario(
      REQUIRED_SCENARIOS[1],
      async () => {
        fs.writeFileSync(leafPath, leaf.raw, { flag: "wx" });
        fs.writeFileSync(caPath, caBytes, { flag: "wx" });
        const probe = () => {
          const actual = ownedBytes(program, 16 * 1024 * 1024);
          assert.ok(
            actual.identity === programFile.identity &&
              hash(actual.bytes) === programHash,
            "Native chain helper changed",
          );
          clearCache();
          return validateCertificateChain({
            helperPath: program,
            certPath: leafPath,
            caKeySha256: authority.keySha256,
            caCertPath: caPath,
            revocationCheck: "require",
            execFileImpl: (file, args, options) =>
              execute(file, args, { ...options, env: nativeEnvironment() }),
          });
        };
        const publicFetch = async (status) => {
          const response = await fetch(listener.httpUrl, {
            redirect: "error",
            signal: AbortSignal.timeout(10000),
          });
          assert.equal(response.status, status);
          const bytes = Buffer.from(await response.arrayBuffer());
          if (status === 200) assert.ok(bytes.equals(applied.crl));
          else assert.equal(bytes.length, 0);
        };
        await publicFetch(200);
        let before = listener.observations();
        assert.equal((await probe()).verdict, "valid");
        assert.ok(
          listener.observations().served > before.served,
          "Native helper must actually fetch the exact CRL",
        );
        listener.setUnavailable(true);
        await publicFetch(503);
        before = listener.observations();
        assert.equal((await probe()).verdict, "revocation_unknown");
        assert.ok(
          listener.observations().unavailable > before.unavailable,
          "Native helper must actually encounter owned HTTP503",
        );
        await unchanged();
        listener.setUnavailable(false);
        await publicFetch(200);
        before = listener.observations();
        assert.equal((await probe()).verdict, "valid");
        assert.ok(
          listener.observations().served > before.served,
          "Native helper must actually refetch the same CRL",
        );
        await unchanged();
        // The HTTP-only leaf cannot outlive its listener: install a genuinely
        // new leaf under the restored original publication before drainage.
        listener.setUnavailable(true);
        const beforeRepair = listener.observations().unavailable;
        repaired = await performEnrollment(false);
        fs.writeFileSync(leafPath, leaf.raw);
        assert.equal((await probe()).verdict, "valid");
        assert.equal(
          listener.observations().unavailable,
          beforeRepair,
          "Restored native chain still contacted owned endpoint",
        );
        await unchanged();
        restoreCache();
        await listener.close();
        listener.complete();
        ownedStoreReceipt.httpLeafCrlPendingVerification = false;
        proof = verifyProof({
          scope: SCOPE,
          enrollmentId: httpIssued.enrollmentId,
          jobId: httpIssued.jobId,
          requestId: httpIssued.requestId,
          leafFingerprint: normalized(httpIssued.leaf.fingerprint256),
          restoredEnrollmentId: repaired.enrollmentId,
          restoredJobId: repaired.jobId,
          restoredRequestId: repaired.requestId,
          restoredLeafFingerprint: normalized(repaired.leaf.fingerprint256),
          publicCrlSha256: applied.crlProof.sha256,
          nativeHelperSha256: programHash,
          originalPublicationSha256: applied.publication.originalSha256,
          appliedPublicationSha256: applied.publication.appliedSha256,
          caRequestCounts: counts,
          nativeVerdicts: ["valid", "revocation_unknown", "valid"],
          endpointStatusCodes: [200, 503, 200],
          ocspQualified: false,
          caOutageQualified: false,
          signedCmcRenewalQualified: false,
          deferredRecovery,
          ...Object.fromEntries(FLAGS.map((flag) => [flag, true])),
        });
      },
      {
        evidenceLevel: "real-host",
        oracle:
          "same signed HTTP CRL200/503/200 actual endpoint and fresh native valid/revocation_unknown/valid, unchanged installed custody/binding/TLS and exact restoration",
      },
    );
    gate.report.fixtureSources ??= [];
    for (const file of REQUIRED_SOURCES)
      gate.report.fixtureSources.push({
        file,
        sha256: hash(fs.readFileSync(path.join(root, file))),
      });
    return proof;
  } finally {
    // Policy restoration and listener drainage never clear a failed native
    // acceptance/proof guard; the parent preserves all borrowed custody.
    try {
      if (attemptedPublication && !restored) publication("Restore");
    } finally {
      try {
        restoreCache();
      } finally {
        await listener.close();
      }
    }
  }
}

module.exports = {
  SCOPE,
  REQUIRED_SCENARIOS,
  REQUIRED_SOURCES,
  FLAGS,
  verifyProof,
  assertCleanupSafe,
  qualifyHttpOnlyLeafCrl,
};
