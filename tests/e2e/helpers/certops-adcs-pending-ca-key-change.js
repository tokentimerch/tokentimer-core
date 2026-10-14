"use strict";
/** Source-only root-lab pending request across the existing single new-key CA
 * rekey. Public reconfirmation creates a fresh snapshot; the rejected original
 * is never repinned. Existing durable My receipt blocks cleanup on uncertainty.
 * Native execution is required before this source can qualify a release. */
const assert = require("node:assert/strict"),
  crypto = require("node:crypto"),
  fs = require("node:fs"),
  path = require("node:path"),
  tls = require("node:tls"),
  { isDeepStrictEqual } = require("node:util");
const {
  readEnrollmentJournal,
} = require("../../../packages/agent/src/issuers/adcs-enrollment");
const {
  extractSpkiFromCsr,
  readCertificateTemplateOid,
} = require("../../../packages/agent/src/issuers/der-extensions");
const {
  parseDnsSans,
} = require("../../../packages/agent/src/issuers/issued-certificate-validation");
const {
  buildEnrollmentContainerName,
  readIssuedContainerRecord,
} = require("../../../packages/agent/src/windows-cert-store");
const SCOPE =
  "real-pending-request-refused-across-ca-new-key-and-fresh-reconfirmation";
const REQUIRED_SCENARIOS = Object.freeze([
  "adcs-real-pending-request-refuses-new-ca-key",
  "adcs-real-pending-issuer-reconfirmation-fresh-request-recovers",
]);
const FLAGS = Object.freeze([
  "actualPendingBeforeRekey",
  "pendingNativeSignatureVerified",
  "actualSingleNewKeyRekey",
  "originalSnapshotNeverRepinned",
  "signedContinuationRefusedChangedKey",
  "oldUnacceptedKeyRemoved",
  "oldRequestDeniedByOwnedOfficer",
  "oldRequestNeverResubmitted",
  "predecessorCustodyAndTlsPreserved",
  "sameIssuerPublicReconfirmed",
  "freshSnapshotAndCngKey",
  "freshActualPendingApproved",
  "freshSignedNativeInstallation",
  "claimBoundNativeEvidence",
  "nativeIisAndTrustedTls",
  "registeredCleanupResolved",
]);
const REQUIRED_SOURCES = Object.freeze([
  "tests/e2e/helpers/certops-adcs-pending-ca-key-change.js",
  "tests/e2e/helpers/certops-adcs-pending-ca-renewal.js",
  "tests/e2e/certops-adcs-real-e2e.test.js",
  "tests/e2e/helpers/certops-adcs-webhosting-renewal.js",
  "tests/e2e/helpers/certops-adcs-capacity.js",
  "infra/certops-adcs/ca-rekey.ps1",
  "infra/certops-adcs/officer-action.ps1",
  "infra/certops-adcs/owned-request-observation.ps1",
  "infra/certops-adcs/owned-ca-request-certificate.ps1",
  "apps/api/services/certops/certificateEnrollments.js",
  "apps/api/services/certops/enrollmentLifecycle.js",
  "packages/agent/src/adcs-windows-iis.js",
  "packages/agent/src/windows-cert-store/index.js",
  "packages/agent/src/windows-key-survivors/index.js",
  "packages/agent/src/issuers/adcs-enrollment.js",
  "packages/agent/src/issuers/adcs-enrollment-journal.js",
  "packages/agent/src/issuers/der-extensions.js",
  "packages/agent/src/issuers/issued-certificate-validation.js",
]);
const uuid = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/,
  hex = /^[a-f0-9]{64}$/;
const normalized = (value) => String(value).replace(/:/g, "").toLowerCase();
function verifyProof(value) {
  assert.deepEqual(
    Object.keys(value).sort(),
    [
      "scope",
      "schedulerClock",
      "backgroundWorkerIntervalQualified",
      "issuerId",
      "oldEnrollmentId",
      "oldOriginalJobId",
      "oldContinuationJobId",
      "freshEnrollmentId",
      "freshOriginalJobId",
      "freshContinuationJobId",
      "preflightJobId",
      "oldRequestId",
      "freshRequestId",
      "oldCaKeySha256",
      "newCaKeySha256",
      "oldSnapshotSha256",
      "freshSnapshotSha256",
      "oldSpkiSha256",
      "freshSpkiSha256",
      "predecessorFingerprint",
      "freshFingerprint",
      "subjectCountBefore",
      "subjectCountAfter",
      ...FLAGS,
    ].sort(),
  );
  assert.equal(value.scope, SCOPE);
  assert.equal(value.schedulerClock, "supported-scheduler-now-input");
  assert.equal(value.backgroundWorkerIntervalQualified, false);
  const ids = [
    "issuerId",
    "oldEnrollmentId",
    "oldOriginalJobId",
    "oldContinuationJobId",
    "freshEnrollmentId",
    "freshOriginalJobId",
    "freshContinuationJobId",
    "preflightJobId",
  ].map((key) => {
    assert.match(value[key], uuid);
    return value[key];
  });
  assert.equal(new Set(ids).size, ids.length);
  for (const key of ["oldRequestId", "freshRequestId"]) {
    assert.match(value[key], /^[1-9][0-9]{0,9}$/);
    assert.ok(Number(value[key]) <= 0xffffffff);
  }
  assert.notEqual(value.oldRequestId, value.freshRequestId);
  for (const key of [
    "oldCaKeySha256",
    "newCaKeySha256",
    "oldSnapshotSha256",
    "freshSnapshotSha256",
    "oldSpkiSha256",
    "freshSpkiSha256",
    "predecessorFingerprint",
    "freshFingerprint",
  ])
    assert.match(value[key], hex);
  for (const [a, b] of [
    ["oldCaKeySha256", "newCaKeySha256"],
    ["oldSnapshotSha256", "freshSnapshotSha256"],
    ["oldSpkiSha256", "freshSpkiSha256"],
    ["predecessorFingerprint", "freshFingerprint"],
  ])
    assert.notEqual(value[a], value[b]);
  assert.ok(
    Number.isSafeInteger(value.subjectCountBefore) &&
      value.subjectCountBefore >= 1 &&
      value.subjectCountBefore < 2048,
  );
  assert.equal(value.subjectCountAfter, value.subjectCountBefore + 1);
  for (const flag of FLAGS) assert.equal(value[flag], true);
  return true;
}
function verifyCrossProof(value, control) {
  verifyProof(value);
  require("./certops-adcs-pending-ca-renewal").verifyProof(control);
  assert.equal(value.predecessorFingerprint, control.leafFingerprint);
  assert.equal(value.oldCaKeySha256, control.caKeySha256);
  return true;
}
async function qualifyPendingCaKeyChange(context) {
  const {
    gate,
    fixture,
    api,
    agentRowId,
    configDir,
    run,
    caConfig,
    pendingRecoveryFixtures,
    ownedCapacityStoreCertificates,
    ownedEnrollmentIds,
    command,
    ps,
    until,
    jobFinished,
    tlsAuthority,
    rekeyAndObserve,
    reservePrimaryPreflights,
  } = context;
  assert.equal(process.platform, "win32");
  assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB, "1");
  assert.notEqual(
    process.env.CERTOPS_ADCS_HIERARCHY,
    "subordinate",
    "Offline-parent subordinate renewal is outside this root-CA fixture",
  );
  assert.match(run, /^[a-f0-9]{10}$/);
  assert.equal(typeof rekeyAndObserve, "function");
  const root = path.resolve(__dirname, "../../.."),
    query = (sql, values = []) => fixture.pool.query(sql, values),
    owned = pendingRecoveryFixtures.cancel;
  assert.ok(owned);
  gate.report.fixtureSources ??= [];
  for (const file of REQUIRED_SOURCES) {
    const sha256 = crypto
        .createHash("sha256")
        .update(fs.readFileSync(path.join(root, file)))
        .digest("hex"),
      existing = gate.report.fixtureSources.filter((row) => row.file === file);
    if (existing.length) {
      assert.equal(existing.length, 1);
      assert.equal(existing[0].sha256, sha256);
    } else gate.report.fixtureSources.push({ file, sha256 });
  }
  const capacity = gate.report.nativeAdcsCapacity;
  require("./certops-adcs-capacity").verifyProof(capacity);
  const receipts = ownedCapacityStoreCertificates.filter((row) =>
    row.enrollmentIds.includes(capacity.enrollmentIds[1]),
  );
  assert.equal(receipts.length, 1);
  const receipt = receipts[0];
  assert.equal(receipt.store, "My");
  assert.match(
    receipt.domain,
    new RegExp(`^certops-adcs-${run}-capacity[0-5]\\.example\\.test$`),
  );
  const prior = (
    await query(
      "SELECT certificate_id,deploy_target FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2",
      [fixture.workspaceId, capacity.enrollmentIds[1]],
    )
  ).rows[0];
  assert.equal(prior.certificate_id, receipt.certificateId);
  const target = prior.deploy_target;
  assert.equal(target.type, "windows-iis");
  assert.equal(target.reference, receipt.domain);
  assert.equal(target.store, "My");
  assert.match(target.binding.site, new RegExp(`^TTAdcsCapacity${run}[0-5]$`));
  assert.equal(target.binding.sniHost, receipt.domain);
  assert.ok(
    Number.isInteger(target.binding.port) &&
      target.binding.port > 1024 &&
      target.binding.port < 65536,
  );
  const domain = receipt.domain,
    site = target.binding.site,
    port = target.binding.port;
  const peer = () =>
    new Promise((resolve, reject) => {
      const socket = tls.connect(
        {
          host: "127.0.0.1",
          port,
          servername: domain,
          ca: tlsAuthority(owned.authority),
          rejectUnauthorized: true,
        },
        () => {
          try {
            assert.equal(socket.authorized, true);
            const leaf = new crypto.X509Certificate(
              socket.getPeerCertificate().raw,
            );
            assert.equal(leaf.checkHost(domain), domain);
            resolve(leaf);
          } catch (error) {
            reject(error);
          } finally {
            socket.destroy();
          }
        },
      );
      socket.once("error", reject);
      socket.setTimeout(10000, () =>
        socket.destroy(new Error("Pending CA renewal trusted TLS timed out")),
      );
    });
  const previous = await peer(),
    matches = receipt.enrollmentIds
      .map((id) => ({ id, ...readEnrollmentJournal(configDir, id) }))
      .filter(
        (value) =>
          value.kind === "valid" &&
          value.journal.state === "installed" &&
          value.artifacts.leafPem &&
          new crypto.X509Certificate(value.artifacts.leafPem).fingerprint256 ===
            previous.fingerprint256,
      );
  assert.equal(
    matches.length,
    1,
    "Current served leaf must match one actual installed owned journal",
  );
  const current = matches[0];
  const custody = (leaf) =>
    JSON.parse(
      ps(
        `$c=Get-Item 'Cert:\\LocalMachine\\My\\${normalized(leaf.fingerprint).toUpperCase()}';$k=$null;try{$k=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c);if(!$k-or$k.Key.Provider.Provider-ne'Microsoft Software Key Storage Provider'-or!$k.Key.IsMachineKey-or[int]$k.Key.ExportPolicy-ne 0-or$k.KeySize-ne 2048){throw 'Protected owned My custody required'};@{container=$k.Key.KeyName;unique=$k.Key.UniqueName;der=[Convert]::ToBase64String($c.RawData)}|ConvertTo-Json -Compress}finally{if($k){$k.Dispose()};$c.Dispose()}`,
      ),
    );
  const binding = () =>
    JSON.parse(
      ps(
        `Import-Module WebAdministration;$b=@(Get-WebBinding -Name '${site}' -Protocol https|Where-Object bindingInformation -eq '*:${port}:${domain}');$h=@(Get-ChildItem -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\HTTP\\Parameters\\SslSniBindingInfo'|Where-Object {[string]$_.GetValue('HostnamePort') -ieq '${domain}:${port}'});if($b.Count-ne 1-or$h.Count-ne 1){throw 'Exact owned SNI selector required'};@{store=[string]$b[0].certificateStoreName;flags=[int]$b[0].sslFlags;hash=[BitConverter]::ToString([byte[]]$h[0].GetValue('SslCertHash')).Replace('-','');httpStore=[string]$h[0].GetValue('SslCertStoreName')}|ConvertTo-Json -Compress`,
      ),
    );
  const predecessorCustody = custody(previous),
    predecessorBinding = binding();
  assert.equal(
    predecessorCustody.container,
    buildEnrollmentContainerName(current.id),
  );
  assert.equal(predecessorBinding.store, "My");
  assert.equal(predecessorBinding.httpStore, "My");
  assert.equal(predecessorBinding.flags, 1);
  assert.equal(
    predecessorBinding.hash,
    normalized(previous.fingerprint).toUpperCase(),
  );
  const acceptedBefore = readIssuedContainerRecord({
    stateDir: configDir,
    containerName: predecessorCustody.container,
  });
  assert.equal(acceptedBefore?.certificateId, receipt.certificateId);
  assert.equal(acceptedBefore.status, "enrolled_by_agent");
  assert.equal(acceptedBefore.acceptedStore, "My");
  assert.equal(acceptedBefore.acceptedThumbprint, predecessorBinding.hash);
  const issuer = async () =>
    (
      await query(
        "SELECT i.current_version,i.revalidation_required,v.ca_key_sha256,v.confirmed_at,v.template,v.ca_config FROM certificate_issuers i JOIN certificate_issuer_versions v ON v.workspace_id=i.workspace_id AND v.issuer_id=i.id AND v.version=i.current_version WHERE i.workspace_id=$1 AND i.id=$2",
        [fixture.workspaceId, owned.issuerId],
      )
    ).rows[0];
  const issuerBefore = await issuer();
  assert.equal(issuerBefore.revalidation_required, false);
  assert.equal(issuerBefore.template, "TTQualificationPending");
  assert.equal(issuerBefore.ca_config, caConfig);
  assert.equal(issuerBefore.ca_key_sha256, owned.authority.keySha256);
  require("./certops-adcs-pending-ca-renewal").verifyProof(
    gate.report.nativePendingCaRenewal,
  );
  assert.equal(
    normalized(previous.fingerprint256),
    gate.report.nativePendingCaRenewal.leafFingerprint,
    "Predecessor must be the actual same-key pending installation control",
  );
  assert.equal(
    issuerBefore.ca_key_sha256,
    gate.report.nativePendingCaRenewal.caKeySha256,
  );
  const row = async (id) =>
    (
      await query(
        "SELECT e.state,e.request_id,e.next_poll_at,e.current_job_id,e.snapshot_sha256,j.status AS job_status,j.claim_id,j.assigned_agent_id,j.result_metadata FROM certificate_enrollments e JOIN certificate_jobs j ON j.workspace_id=e.workspace_id AND j.id=e.current_job_id WHERE e.workspace_id=$1 AND e.id=$2",
        [fixture.workspaceId, id],
      )
    ).rows[0];
  const invoke = (file, args) =>
    JSON.parse(
      command("powershell.exe", [
        "-NoProfile",
        "-NonInteractive",
        "-File",
        path.join(root, "infra/certops-adcs", file),
        ...args,
      ]),
    );

  assert.equal(typeof reservePrimaryPreflights, "function");
  const journal = (id) => {
    const value = readEnrollmentJournal(configDir, id);
    assert.equal(value.kind, "valid");
    return value;
  };
  const sign = (value) => {
    const challenge = crypto.randomBytes(32),
      key = JSON.parse(
        ps(
          `$k=[Security.Cryptography.CngKey]::Open('${value.journal.containerName}',[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider,[Security.Cryptography.CngKeyOpenOptions]::MachineKey);$rsa=$null;try{$rsa=[Security.Cryptography.RSACng]::new($k);if(!$k.IsMachineKey-or[int]$k.ExportPolicy-ne 0-or$rsa.KeySize-ne 2048){throw 'Owned protected machine RSA required'};@{unique=$k.UniqueName;signature=[Convert]::ToBase64String($rsa.SignData([Convert]::FromBase64String('${challenge.toString("base64")}'),[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1))}|ConvertTo-Json -Compress}finally{if($rsa){$rsa.Dispose()};$k.Dispose()}`,
        ),
      );
    assert.equal(
      crypto.verify(
        "sha256",
        challenge,
        crypto.createPublicKey({
          key: extractSpkiFromCsr(value.artifacts.csrPem),
          format: "der",
          type: "spki",
        }),
        Buffer.from(key.signature, "base64"),
      ),
      true,
    );
    return key.unique;
  };
  const observe = (id) =>
    invoke("owned-request-observation.ps1", [
      "-CommonName",
      domain,
      "-RequestId",
      id,
    ]);
  const officer = (id, action) =>
    command("powershell.exe", [
      "-NoProfile",
      "-NonInteractive",
      "-File",
      path.join(root, "infra/certops-adcs/officer-action.ps1"),
      "-RequestId",
      id,
      "-Action",
      action,
      "-CommonName",
      domain,
    ]);
  const post = async () => {
    const response = await fixture.request(`${api}/enrollments`, "POST", {
      issuerId: owned.issuerId,
      certificateId: receipt.certificateId,
      agentId: agentRowId,
      target,
      authorizedDnsNames: [domain],
      keyAlgorithm: "rsa",
      keySize: 2048,
    });
    assert.equal(response.status, 201);
    assert.match(response.body.enrollmentId, uuid);
    receipt.enrollmentIds.push(response.body.enrollmentId);
    ownedEnrollmentIds.push(response.body.enrollmentId);
    return response.body;
  };
  const continuePending = async (id, pending) => {
    const scheduled = (
      await require("../../../apps/api/services/certops/certificateEnrollments").scheduleDueEnrollments(
        {
          client: fixture.pool,
          now: new Date(new Date(pending.next_poll_at).getTime() + 1000),
        },
      )
    ).find((value) => value.enrollmentId === id);
    assert.ok(scheduled);
    await jobFinished(scheduled.jobId);
    return scheduled.jobId;
  };
  const predecessorUnchanged = async () => {
    assert.ok(
      isDeepStrictEqual(custody(previous), predecessorCustody),
      "Original protected predecessor custody changed",
    );
    assert.ok(
      isDeepStrictEqual(binding(), predecessorBinding),
      "Original native endpoint changed",
    );
    assert.ok(
      isDeepStrictEqual(
        readIssuedContainerRecord({
          stateDir: configDir,
          containerName: predecessorCustody.container,
        }),
        acceptedBefore,
      ),
      "Original accepted ownership changed",
    );
    assert.equal((await peer()).fingerprint256, previous.fingerprint256);
  };
  assert.equal(
    (await fixture.request(`${api}/settings`)).body
      .certOpsRequireApprovalAlways,
    false,
  );
  // This durable parent-owned receipt already exists before the first public POST;
  // lost responses or unknown acceptance must preserve all native/public state.
  receipt.pendingCaRenewalUnresolved = true;
  let old,
    oldPending,
    original,
    oldRequestId,
    nativeBefore,
    oldContinuationJobId,
    fresh,
    freshPending,
    freshJournal,
    freshContinuationJobId,
    preflightJobId,
    newAuthority,
    leaf;
  await gate.scenario(
    REQUIRED_SCENARIOS[0],
    async () => {
      old = await post();
      oldPending = await until(async () => {
        const value = await row(old.enrollmentId);
        return value?.state === "pending_issuance" &&
          value.job_status === "awaiting_issuer" &&
          value.request_id
          ? value
          : null;
      });
      assert.equal(oldPending.current_job_id, old.jobId);
      assert.equal(oldPending.assigned_agent_id, agentRowId);
      assert.match(oldPending.claim_id, uuid);
      original = journal(old.enrollmentId);
      assert.equal(original.journal.state, "pending");
      assert.equal(
        original.journal.containerName,
        buildEnrollmentContainerName(old.enrollmentId),
      );
      assert.equal(original.journal.snapshotSha256, oldPending.snapshot_sha256);
      oldRequestId = String(oldPending.request_id);
      assert.equal(String(original.journal.requestId), oldRequestId);
      const keyIdentity = sign(original);
      nativeBefore = observe(oldRequestId);
      assert.equal(nativeBefore.disposition, 9);
      await rekeyAndObserve();
      assert.ok(
        isDeepStrictEqual(observe(oldRequestId), nativeBefore),
        "CA rekey must not change or duplicate the old pending request",
      );
      const after = journal(old.enrollmentId);
      assert.ok(
        isDeepStrictEqual(after, original),
        "Frozen pending journal/CSR must remain exact across rekey",
      );
      assert.ok(
        sign(after) === keyIdentity,
        "Pending native key identity changed before signed refusal",
      );
      await predecessorUnchanged();
      oldContinuationJobId = await continuePending(
        old.enrollmentId,
        oldPending,
      );
      const refused = await until(async () => {
        const value = await row(old.enrollmentId);
        return value?.current_job_id === oldContinuationJobId &&
          value.job_status === "failed" &&
          value.state === "rejected_invalid"
          ? value
          : null;
      });
      assert.equal(refused.current_job_id, oldContinuationJobId);
      assert.equal(refused.job_status, "failed");
      assert.equal(refused.state, "rejected_invalid");
      assert.equal(
        refused.result_metadata.enrollmentResult.errorCode,
        "ADCS_CA_KEY_CHANGED",
      );
      assert.match(refused.claim_id, uuid);
      assert.equal(refused.assigned_agent_id, agentRowId);
      assert.equal(String(refused.request_id), oldRequestId);
      assert.equal(refused.snapshot_sha256, original.journal.snapshotSha256);
      const rejected = journal(old.enrollmentId);
      assert.equal(rejected.journal.state, "rejected_invalid");
      for (const field of [
        "containerName",
        "csrSha256",
        "csrSpkiSha256",
        "snapshotSha256",
        "templateOid",
        "requestId",
      ])
        assert.equal(rejected.journal[field], original.journal[field]);
      assert.equal(rejected.artifacts.csrPem, original.artifacts.csrPem);
      assert.equal(
        ps(
          `[Security.Cryptography.CngKey]::Exists('${original.journal.containerName}',[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider,[Security.Cryptography.CngKeyOpenOptions]::MachineKey)`,
        ),
        "False",
      );
      assert.equal(
        readIssuedContainerRecord({
          stateDir: configDir,
          containerName: original.journal.containerName,
        }),
        null,
      );
      assert.ok(isDeepStrictEqual(observe(oldRequestId), nativeBefore));
      await predecessorUnchanged();
      assert.equal((await issuer()).revalidation_required, true);
      // A terminal invalid local request is not abandoned or borrowed. The officer
      // denies only this independently owned still-pending CA request.
      officer(oldRequestId, "deny");
      const denied = observe(oldRequestId);
      assert.equal(denied.disposition, 30);
      assert.equal(
        denied.subjectRequestCount,
        nativeBefore.subjectRequestCount,
      );
    },
    {
      evidenceLevel: "real-host",
      oracle:
        "Actual pending request predates sole real CA new-key rekey; signed continuation refuses changed signer without resubmission, exact terminal key cleanup and preserved predecessor",
    },
  );
  await gate.scenario(
    REQUIRED_SCENARIOS[1],
    async () => {
      reservePrimaryPreflights(1);
      const check = await fixture.request(
        `${api}/issuers/${owned.issuerId}/preflight`,
        "POST",
        { agentId: agentRowId, caConfig, template: "TTQualificationPending" },
      );
      assert.equal(check.status, 201);
      preflightJobId = check.body.job.id;
      await jobFinished(preflightJobId);
      const checked = await until(async () => {
        const value = (
          await query(
            "SELECT last_preflight,last_preflight_job_id FROM certificate_issuers WHERE workspace_id=$1 AND id=$2",
            [fixture.workspaceId, owned.issuerId],
          )
        ).rows[0];
        return value?.last_preflight_job_id === preflightJobId
          ? value.last_preflight
          : null;
      });
      assert.equal(checked.caCheck.verdict, "safe");
      assert.equal(checked.templateCheck.verdict, "safe");
      const candidates = checked.caCertificates.filter(
        (value) => value.keySha256 !== issuerBefore.ca_key_sha256,
      );
      assert.equal(new Set(candidates.map((value) => value.keySha256)).size, 1);
      assert.ok(candidates.length >= 1);
      newAuthority = candidates[0];
      assert.match(newAuthority.keySha256, hex);
      const confirmation = await fixture.request(
        `${api}/issuers/${owned.issuerId}/confirm`,
        "POST",
        {
          caKeySha256: newAuthority.keySha256,
          caConfig,
          template: "TTQualificationPending",
        },
      );
      assert.equal(confirmation.status, 200);
      const refreshed = await issuer();
      assert.equal(refreshed.revalidation_required, false);
      assert.equal(refreshed.ca_key_sha256, newAuthority.keySha256);
      assert.notEqual(refreshed.current_version, issuerBefore.current_version);
      fresh = await post();
      freshPending = await until(async () => {
        const value = await row(fresh.enrollmentId);
        return value?.state === "pending_issuance" &&
          value.job_status === "awaiting_issuer" &&
          value.request_id
          ? value
          : null;
      });
      assert.equal(freshPending.current_job_id, fresh.jobId);
      freshJournal = journal(fresh.enrollmentId);
      assert.equal(freshJournal.journal.state, "pending");
      assert.equal(
        freshJournal.journal.containerName,
        buildEnrollmentContainerName(fresh.enrollmentId),
      );
      assert.notEqual(
        freshJournal.journal.snapshotSha256,
        original.journal.snapshotSha256,
      );
      assert.notEqual(
        freshJournal.journal.csrSpkiSha256,
        original.journal.csrSpkiSha256,
      );
      const freshKey = sign(freshJournal),
        requestId = String(freshPending.request_id);
      assert.notEqual(requestId, oldRequestId);
      assert.equal(String(freshJournal.journal.requestId), requestId);
      const pendingNative = observe(requestId);
      assert.equal(pendingNative.disposition, 9);
      assert.equal(
        pendingNative.subjectRequestCount,
        nativeBefore.subjectRequestCount + 1,
      );
      assert.equal(observe(oldRequestId).disposition, 30);
      await predecessorUnchanged();
      officer(requestId, "approve");
      const actual = invoke("owned-ca-request-certificate.ps1", [
        "-CommonName",
        domain,
        "-RequestId",
        requestId,
      ]);
      assert.equal(String(actual.requestId), requestId);
      leaf = new crypto.X509Certificate(
        Buffer.from(actual.certificateB64, "base64"),
      );
      assert.equal(
        leaf.verify(
          new crypto.X509Certificate(
            Buffer.from(newAuthority.certificateB64, "base64"),
          ).publicKey,
        ),
        true,
      );
      assert.equal(leaf.checkHost(domain), domain);
      assert.ok(isDeepStrictEqual(parseDnsSans(leaf.subjectAltName), [domain]));
      assert.equal(
        readCertificateTemplateOid(leaf.raw),
        freshJournal.journal.templateOid,
      );
      assert.equal(
        crypto
          .createHash("sha256")
          .update(leaf.publicKey.export({ format: "der", type: "spki" }))
          .digest("hex"),
        freshJournal.journal.csrSpkiSha256,
      );
      freshContinuationJobId = await continuePending(
        fresh.enrollmentId,
        freshPending,
      );
      const installed = await until(async () => {
        const value = await row(fresh.enrollmentId);
        return value?.current_job_id === freshContinuationJobId &&
          value.job_status === "succeeded" &&
          value.state === "installed"
          ? value
          : null;
      });
      assert.equal(installed.state, "installed");
      assert.equal(installed.job_status, "succeeded");
      assert.equal(installed.current_job_id, freshContinuationJobId);
      assert.match(installed.claim_id, uuid);
      assert.equal(installed.assigned_agent_id, agentRowId);
      const installedJournal = journal(fresh.enrollmentId);
      assert.equal(
        installedJournal.journal.snapshotSha256,
        freshJournal.journal.snapshotSha256,
      );
      assert.equal(
        installedJournal.journal.requestId,
        freshJournal.journal.requestId,
      );
      assert.equal(
        new crypto.X509Certificate(installedJournal.artifacts.leafPem)
          .fingerprint256,
        leaf.fingerprint256,
      );
      const socketLeaf = await new Promise((resolve, reject) => {
        const socket = tls.connect(
          {
            host: "127.0.0.1",
            port,
            servername: domain,
            ca: tlsAuthority(newAuthority),
            rejectUnauthorized: true,
          },
          () => {
            try {
              assert.equal(socket.authorized, true);
              resolve(
                new crypto.X509Certificate(socket.getPeerCertificate().raw),
              );
            } catch (error) {
              reject(error);
            } finally {
              socket.destroy();
            }
          },
        );
        socket.once("error", reject);
        socket.setTimeout(10000, () =>
          socket.destroy(
            new Error("Reconfirmed pending issuer trusted TLS timed out"),
          ),
        );
      });
      assert.equal(socketLeaf.fingerprint256, leaf.fingerprint256);
      const active = custody(leaf),
        endpoint = binding();
      assert.equal(active.container, freshJournal.journal.containerName);
      assert.ok(
        active.unique === freshKey,
        "Fresh pending key identity changed at installation",
      );
      assert.equal(active.der, leaf.raw.toString("base64"));
      assert.equal(endpoint.store, "My");
      assert.equal(endpoint.httpStore, "My");
      assert.equal(endpoint.flags, 1);
      assert.equal(endpoint.hash, normalized(leaf.fingerprint).toUpperCase());
      receipt.thumbprints.push(endpoint.hash);
      const accepted = readIssuedContainerRecord({
        stateDir: configDir,
        containerName: active.container,
      });
      assert.equal(accepted?.status, "enrolled_by_agent");
      assert.equal(accepted.certificateId, receipt.certificateId);
      assert.equal(accepted.jobId, fresh.jobId);
      assert.equal(accepted.acceptedStore, "My");
      assert.equal(accepted.acceptedThumbprint, endpoint.hash);
      assert.ok(
        isDeepStrictEqual(custody(previous), predecessorCustody),
        "Outgoing predecessor custody must survive genuine cutover",
      );
      assert.ok(
        isDeepStrictEqual(
          readIssuedContainerRecord({
            stateDir: configDir,
            containerName: predecessorCustody.container,
          }),
          acceptedBefore,
        ),
      );
      assert.equal(
        observe(requestId).subjectRequestCount,
        pendingNative.subjectRequestCount,
      );
      assert.equal(observe(requestId).disposition, 20);
      assert.equal(observe(oldRequestId).disposition, 30);
      const evidence = (
        await query(
          "SELECT e.metadata FROM certificate_evidence e JOIN certificate_jobs j ON j.workspace_id=e.workspace_id AND j.id=e.job_id WHERE e.workspace_id=$1 AND e.job_id=$2 AND e.evidence_type='validation.passed' AND e.claim_id=j.claim_id AND e.metadata->>'step'='verify'",
          [fixture.workspaceId, freshContinuationJobId],
        )
      ).rows;
      assert.ok(
        evidence.some(
          (value) =>
            normalized(value.metadata.fingerprintSha256) ===
            normalized(leaf.fingerprint256),
        ),
      );
      const originalAfter = journal(old.enrollmentId);
      assert.equal(
        originalAfter.journal.snapshotSha256,
        original.journal.snapshotSha256,
      );
      assert.equal(
        originalAfter.journal.csrSpkiSha256,
        original.journal.csrSpkiSha256,
      );
      assert.equal(originalAfter.journal.state, "rejected_invalid");
      const proof = {
        scope: SCOPE,
        schedulerClock: "supported-scheduler-now-input",
        backgroundWorkerIntervalQualified: false,
        issuerId: owned.issuerId,
        oldEnrollmentId: old.enrollmentId,
        oldOriginalJobId: old.jobId,
        oldContinuationJobId,
        freshEnrollmentId: fresh.enrollmentId,
        freshOriginalJobId: fresh.jobId,
        freshContinuationJobId,
        preflightJobId,
        oldRequestId,
        freshRequestId: requestId,
        oldCaKeySha256: issuerBefore.ca_key_sha256,
        newCaKeySha256: newAuthority.keySha256,
        oldSnapshotSha256: original.journal.snapshotSha256,
        freshSnapshotSha256: freshJournal.journal.snapshotSha256,
        oldSpkiSha256: original.journal.csrSpkiSha256,
        freshSpkiSha256: freshJournal.journal.csrSpkiSha256,
        predecessorFingerprint: normalized(previous.fingerprint256),
        freshFingerprint: normalized(leaf.fingerprint256),
        subjectCountBefore: nativeBefore.subjectRequestCount,
        subjectCountAfter: pendingNative.subjectRequestCount,
        ...Object.fromEntries(FLAGS.map((flag) => [flag, true])),
      };
      verifyCrossProof(proof, gate.report.nativePendingCaRenewal);
      gate.report.nativePendingCaKeyChange = proof;
      receipt.pendingCaRenewalUnresolved = false;
    },
    {
      evidenceLevel: "real-host",
      oracle:
        "Same pending-template issuer publicly revalidated with one actual native preflight; a fresh snapshot/request/key is approved and installed without repinning or resubmitting rejected original",
    },
  );
  return gate.report.nativePendingCaKeyChange;
}
module.exports = {
  SCOPE,
  FLAGS,
  REQUIRED_SCENARIOS,
  REQUIRED_SOURCES,
  verifyProof,
  verifyCrossProof,
  qualifyPendingCaKeyChange,
};
