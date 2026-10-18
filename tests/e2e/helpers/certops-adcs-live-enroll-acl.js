"use strict";
/* Disposable-forest qualification only: change the current machine's Enroll
 * permission on the SAME already-confirmed template, observe a genuine native
 * denial, restore its exact DACL, then prove fresh public issuance succeeds.
 * This is distinct from unsafe-template preflight and static NoEnroll tests.
 * No native execution is claimed by the supporting proof tests.
 */
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const tls = require("node:tls");
const { isDeepStrictEqual } = require("node:util");
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

const SCOPE =
  "real-same-template-machine-enroll-denial-exact-dacl-restore-and-issuance";
const REQUIRED_SCENARIOS = Object.freeze([
  "adcs-real-live-machine-enroll-denial",
  "adcs-real-live-enroll-acl-restored-same-template-issuance",
]);
const REQUIRED_SOURCES = Object.freeze([
  "tests/e2e/helpers/certops-adcs-live-enroll-acl.js",
  "infra/certops-adcs/template-enroll-acl.ps1",
  "infra/certops-adcs/templates.ps1",
  "packages/agent/src/platform/index.js",
  "packages/agent/src/issuers/adcs.js",
  "scripts/certops_adcs_live_enroll_acl_proof.py",
  "infra/certops-adcs/owned-ca-checkpoint.ps1",
  "infra/certops-adcs/owned-request-observation.ps1",
  "infra/certops-adcs/owned-issued-request.ps1",
  "packages/agent/src/issuers/adcs-enrollment-journal.js",
  "packages/agent/src/issuers/adcs-disposition.js",
  "packages/agent/src/adcs-windows-iis.js",
  "packages/agent/src/windows-cert-store/index.js",
]);
const FLAGS = Object.freeze([
  "sameConfirmedIssuerTemplateAndAlgorithm",
  "actualMachineSidDenied",
  "nativeTemplateDeniedHresult",
  "deniedKeyAbsentAndJournalRetained",
  "deniedAttemptPreservedNativeCustodyAndTls",
  "exactDaclRestored",
  "actualCaCacheRestartAndPing",
  "freshPublicEnrollmentInstalled",
  "independentIssuedCaRequest",
  "newNonexportableMachineKey",
  "nativeMyAndIisSniCutover",
  "independentTrustedTls",
  "claimBoundEvidence",
  "ownedCleanupRegisteredBeforeObservation",
]);
const hash = (value) => crypto.createHash("sha256").update(value).digest("hex");
const normalized = (value) => String(value).replace(/:/g, "").toLowerCase();
const uuid = (value) =>
  /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(value);
function verifyInstalledEvidence(job, evidence, leaf) {
  assert.equal(job.status, "succeeded");
  assert.ok(uuid(job.claim_id));
  assert.ok(
    evidence.some(
      (row) =>
        row.claim_id === job.claim_id &&
        row.metadata?.step === "verify" &&
        normalized(row.metadata.fingerprintSha256) ===
          normalized(leaf.fingerprint256) &&
        Date.parse(row.metadata.validTo) === Date.parse(leaf.validTo),
    ),
    "Actual current claim must verify the independently observed installed leaf",
  );
}
function verifyNativeRequestId(independent, ...reported) {
  assert.ok(
    Number.isInteger(independent) &&
      independent > 0 &&
      independent <= 0xffffffff,
    "Independent native CA RequestId is mandatory",
  );
  // Immediate issued CMC deliberately omits RequestId. Never invent one in
  // control-plane or journal state; compare every ID that actually exists.
  for (const value of reported)
    if (value != null) {
      assert.match(String(value), /^[1-9][0-9]{0,9}$/);
      assert.equal(
        String(value),
        String(independent),
        "Reported CA RequestId mismatch",
      );
    }
  return independent;
}
function verifyProof(proof) {
  assert.ok(proof && typeof proof === "object" && !Array.isArray(proof));
  const keys = [
    "scope",
    "templateGuid",
    "templateOid",
    "machineSid",
    "originalDaclSha256",
    "appliedDaclSha256",
    "restoredDaclSha256",
    "deniedCaRequestDelta",
    "caRequestCounts",
    "enrollmentIds",
    "jobIds",
    "fingerprints",
    "caHresult",
    "preflightRefusalQualified",
    "signedCmcRenewalQualified",
    ...FLAGS,
  ];
  assert.deepEqual(Object.keys(proof).sort(), keys.sort());
  assert.equal(proof.scope, SCOPE);
  assert.ok(uuid(proof.templateGuid));
  assert.match(proof.templateOid, /^1(?:\.[0-9]+)+$/);
  assert.match(proof.machineSid, /^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$/);
  for (const name of [
    "originalDaclSha256",
    "appliedDaclSha256",
    "restoredDaclSha256",
  ])
    assert.match(proof[name], /^[a-f0-9]{64}$/);
  assert.equal(proof.originalDaclSha256, proof.restoredDaclSha256);
  assert.notEqual(proof.originalDaclSha256, proof.appliedDaclSha256);
  assert.ok([0, 1].includes(proof.deniedCaRequestDelta));
  assert.equal(proof.caRequestCounts.length, 3);
  for (const value of proof.caRequestCounts)
    assert.ok(Number.isSafeInteger(value) && value >= 0 && value <= 2048);
  assert.equal(
    proof.caRequestCounts[1] - proof.caRequestCounts[0],
    proof.deniedCaRequestDelta,
  );
  assert.equal(proof.caRequestCounts[2] - proof.caRequestCounts[1], 1);
  for (const name of ["enrollmentIds", "jobIds"]) {
    assert.equal(proof[name].length, 2);
    assert.ok(proof[name].every(uuid));
    assert.equal(new Set(proof[name]).size, 2);
  }
  assert.equal(proof.fingerprints.length, 2);
  for (const value of proof.fingerprints) assert.match(value, /^[a-f0-9]{64}$/);
  assert.notEqual(...proof.fingerprints);
  assert.equal(proof.caHresult, "0x80094012");
  for (const flag of FLAGS) assert.equal(proof[flag], true, flag);
  assert.equal(proof.preflightRefusalQualified, false);
  assert.equal(proof.signedCmcRenewalQualified, false);
  return proof;
}

async function qualifyLiveEnrollAcl(context) {
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
    until,
    jobFinished,
    ownedEnrollmentIds,
    ownedStoreReceipt,
    tlsAuthority,
  } = context;
  assert.equal(process.platform, "win32");
  assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB, "1");
  assert.equal(
    ps("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value"),
    "S-1-5-18",
  );
  const { item, issuerId, certificateId, site, port, authority } = current;
  assert.equal(item.template, "TTQualificationRSAShort");
  assert.equal(item.algorithm, "rsa");
  assert.equal(item.size, 2048);
  assert.equal(ownedStoreReceipt.store, "My");
  assert.equal(ownedStoreReceipt.domain, item.domain);
  assert.equal(ownedStoreReceipt.certificateId, certificateId);
  assert.ok(
    Array.isArray(ownedStoreReceipt.enrollmentIds) &&
      Array.isArray(ownedStoreReceipt.thumbprints),
  );
  assert.match(run, /^[a-f0-9]{10}$/);
  assert.match(site, /^TTADCS-[a-f0-9]{10}-[a-z0-9-]+$/);
  assert.match(
    item.domain,
    /^certops-adcs-[a-f0-9]{10}-rsa2048\.example\.test$/,
  );
  assert.ok(Number.isInteger(port) && port > 0 && port < 65536);
  const root = path.resolve(__dirname, "../../..");
  const native = (file, args = []) =>
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
  const machineSid = ps(
    "$s=[DirectoryServices.DirectorySearcher]::new();try{$s.Filter='(&(objectClass=computer)(sAMAccountName='+$env:COMPUTERNAME+'$))';$r=$s.FindAll();if($r.Count -ne 1){throw 'Exact current machine SID required'};([Security.Principal.SecurityIdentifier]::new([byte[]]$r[0].Properties['objectsid'][0],0)).Value}finally{$s.Dispose()}",
  );
  assert.match(machineSid, /^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$/);
  const ownershipToken = crypto.randomUUID();
  const guardPath = path.join(workDir, "live-enroll-acl-owner.json");
  const guardBytes = Buffer.from(
    JSON.stringify({ schemaVersion: 1, ownershipToken, run, machineSid }),
  );
  fs.writeFileSync(guardPath, guardBytes, { flag: "wx", mode: 0o600 });
  applyRestrictivePermissions(guardPath, { kind: "file" });
  const guardIdentity = fs.lstatSync(guardPath, { bigint: true });
  assert.ok(
    guardIdentity.isFile() &&
      !guardIdentity.isSymbolicLink() &&
      guardIdentity.ino > 0n,
  );
  ownedStoreReceipt.machineAclPendingVerification = true;
  const mutate = (action) =>
    native("template-enroll-acl.ps1", [
      "-Action",
      action,
      "-RunId",
      run,
      "-OwnershipToken",
      ownershipToken,
      "-MachineSid",
      machineSid,
    ]);
  const peer = () =>
    new Promise((resolve, reject) => {
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
          new Error("Live Enroll ACL trusted TLS observation timed out"),
        ),
      );
    });
  const custody = (leaf) => {
    const thumb = leaf.fingerprint.replace(/:/g, "").toUpperCase();
    const value = JSON.parse(
      ps(
        `$c=Get-Item 'Cert:\\LocalMachine\\My\\${thumb}';$k=$null;try{$k=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c);@{container=$k.Key.KeyName;unique=$k.Key.UniqueName;policy=[int]$k.Key.ExportPolicy;machine=$k.Key.IsMachineKey;provider=$k.Key.Provider.Provider;bits=$k.KeySize}|ConvertTo-Json -Compress}finally{if($k){$k.Dispose()};$c.Dispose()}`,
      ),
    );
    assert.equal(value.policy, 0);
    assert.equal(value.machine, true);
    assert.equal(value.bits, 2048);
    assert.equal(value.provider, "Microsoft Software Key Storage Provider");
    assert.ok(value.unique);
    const record = readIssuedContainerRecord({
      stateDir: configDir,
      containerName: value.container,
    });
    assert.equal(record?.status, "enrolled_by_agent");
    assert.equal(record.acceptedStore, "My");
    assert.equal(record.acceptedThumbprint, thumb);
    return { value, record };
  };
  const binding = (leaf) => {
    const value = JSON.parse(
      ps(
        `Import-Module WebAdministration;$b=@(Get-WebBinding -Name '${site}' -Protocol https|Where-Object bindingInformation -eq '*:${port}:${item.domain}');$keys=@(Get-ChildItem -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\HTTP\\Parameters\\SslSniBindingInfo'|Where-Object {[string]$_.GetValue('HostnamePort') -ieq '${item.domain}:${port}'});if($b.Count -ne 1 -or $keys.Count -ne 1){throw 'Exact owned IIS and HTTP.sys SNI binding required'};@{hash=[BitConverter]::ToString([byte[]]$keys[0].GetValue('SslCertHash')).Replace('-','');store=[string]$keys[0].GetValue('SslCertStoreName');coordinates=[string]$b[0].bindingInformation;flags=[int]$b[0].sslFlags}|ConvertTo-Json -Compress`,
      ),
    );
    assert.equal(value.hash, leaf.fingerprint.replace(/:/g, "").toUpperCase());
    assert.equal(value.store.toUpperCase(), "MY");
    assert.equal(value.flags, 1);
    assert.equal(value.coordinates, `*:${port}:${item.domain}`);
    return value;
  };
  const original = await peer();
  assert.equal(original.fingerprint256, current.observed.fingerprint256);
  const originalCustody = custody(original);
  const originalBinding = binding(original);
  const unchanged = async () => {
    assert.equal((await peer()).fingerprint256, original.fingerprint256);
    assert.ok(
      isDeepStrictEqual(custody(original), originalCustody),
      "Original native key custody changed",
    );
    assert.ok(
      isDeepStrictEqual(binding(original), originalBinding),
      "Original native binding changed",
    );
  };
  const enroll = async () => {
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
    assert.ok(uuid(response.body.enrollmentId));
    assert.ok(uuid(response.body.jobId));
    // Register actual response ownership before waiting for native acceptance.
    ownedEnrollmentIds.push(response.body.enrollmentId);
    ownedStoreReceipt.enrollmentIds.push(response.body.enrollmentId);
    return response.body;
  };
  const counts = [checkpoint().nativeTotalRequestCount];
  let applied;
  let restored;
  let denied;
  let successful;
  let leaf;
  let delta;
  try {
    await gate.scenario(
      REQUIRED_SCENARIOS[0],
      async () => {
        applied = mutate("Apply");
        assert.equal(applied.applied, true);
        assert.equal(applied.actualCaReady, true);
        assert.equal(applied.machineSid, machineSid);
        denied = await enroll();
        const outcome = await until(async () => {
          const row = (
            await fixture.pool.query(
              "SELECT status,claim_id,result_metadata FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",
              [fixture.workspaceId, denied.jobId],
            )
          ).rows[0];
          if (row.status === "succeeded")
            throw new Error("Machine Enroll deny unexpectedly issued a leaf");
          return row.status === "failed" ? row : null;
        });
        assert.equal(outcome.result_metadata.enrollmentResult.state, "denied");
        assert.ok(
          uuid(outcome.claim_id),
          "Denial must come from an actual claimed job",
        );
        assert.equal(
          outcome.result_metadata.enrollmentResult.caHresult.toLowerCase(),
          "0x80094012",
        );
        assert.equal(
          (
            await fixture.pool.query(
              "SELECT state FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2",
              [fixture.workspaceId, denied.enrollmentId],
            )
          ).rows[0].state,
          "denied",
        );
        const container = buildEnrollmentContainerName(denied.enrollmentId);
        assert.equal(
          ps(
            `[Security.Cryptography.CngKey]::Exists('${container}',[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider,[Security.Cryptography.CngKeyOpenOptions]::MachineKey)`,
          ),
          "False",
        );
        const journal = readEnrollmentJournal(configDir, denied.enrollmentId);
        assert.equal(journal.kind, "valid");
        assert.equal(journal.journal.state, "denied");
        assert.equal(journal.journal.containerName, container);
        assert.equal(journal.journal.jobId, denied.jobId);
        assert.equal(journal.journal.templateOid, applied.templateOid);
        assert.equal(journal.journal.caHresult.toLowerCase(), "0x80094012");
        const after = checkpoint();
        counts.push(after.nativeTotalRequestCount);
        delta = counts[1] - counts[0];
        assert.ok([0, 1].includes(delta));
        if (delta === 1) {
          const request = native("owned-request-observation.ps1", [
            "-CommonName",
            item.domain,
            "-RequestId",
            String(after.highestRequestId),
          ]);
          assert.ok([30, 31].includes(request.disposition));
        }
        await unchanged();
      },
      {
        evidenceLevel: "real-host",
        oracle:
          "exact current machine Enroll deny on same confirmed template, actual HRESULT, native key absence, journal and predecessor custody",
      },
    );
    restored = mutate("Restore");
    assert.equal(restored.restored, true);
    assert.equal(restored.actualCaReady, true);
    assert.equal(restored.templateGuid, applied.templateGuid);
    assert.equal(restored.templateOid, applied.templateOid);
    assert.equal(restored.machineSid, machineSid);
    assert.equal(restored.originalDaclSha256, applied.originalDaclSha256);
    assert.equal(restored.appliedDaclSha256, applied.appliedDaclSha256);
    await unchanged();
    await gate.scenario(
      REQUIRED_SCENARIOS[1],
      async () => {
        successful = await enroll();
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
        assert.equal(leaf.checkHost(item.domain), item.domain);
        assert.notEqual(leaf.fingerprint256, original.fingerprint256);
        assert.notEqual(leaf.serialNumber, original.serialNumber);
        assert.ok(
          !leaf.publicKey
            .export({ type: "spki", format: "der" })
            .equals(original.publicKey.export({ type: "spki", format: "der" })),
        );
        const thumb = leaf.fingerprint.replace(/:/g, "").toUpperCase();
        ownedStoreReceipt.thumbprints.push(thumb);
        const observed = custody(leaf);
        assert.equal(
          observed.value.container,
          buildEnrollmentContainerName(successful.enrollmentId),
        );
        binding(leaf);
        const request = native("owned-issued-request.ps1", [
          "-CommonName",
          item.domain,
          "-FingerprintSha256",
          normalized(leaf.fingerprint256),
        ]);
        assert.equal(request.disposition, 20);
        const installedJournal = readEnrollmentJournal(
          configDir,
          successful.enrollmentId,
        );
        assert.equal(installedJournal.kind, "valid");
        assert.equal(installedJournal.journal.jobId, successful.jobId);
        verifyNativeRequestId(
          request.requestId,
          row.request_id,
          installedJournal.journal.requestId,
        );
        counts.push(checkpoint().nativeTotalRequestCount);
        assert.equal(counts[2] - counts[1], 1);
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
        assert.ok(
          isDeepStrictEqual(custody(original), originalCustody),
          "Predecessor native key custody changed after restored issuance",
        );
        current.observed = leaf;
        current.thumbprint = thumb;
        current.currentEnrollmentId = successful.enrollmentId;
      },
      {
        evidenceLevel: "real-host",
        oracle:
          "same restored template and issuer fresh public issuance, independent native CA leaf, nonexportable CNG, My/IIS/SNI and trusted TLS",
      },
    );
    const proof = verifyProof({
      scope: SCOPE,
      templateGuid: applied.templateGuid,
      templateOid: applied.templateOid,
      machineSid,
      originalDaclSha256: applied.originalDaclSha256,
      appliedDaclSha256: applied.appliedDaclSha256,
      restoredDaclSha256: restored.originalDaclSha256,
      deniedCaRequestDelta: delta,
      caRequestCounts: counts,
      enrollmentIds: [denied.enrollmentId, successful.enrollmentId],
      jobIds: [denied.jobId, successful.jobId],
      fingerprints: [
        normalized(original.fingerprint256),
        normalized(leaf.fingerprint256),
      ],
      caHresult: "0x80094012",
      preflightRefusalQualified: false,
      signedCmcRenewalQualified: false,
      ...Object.fromEntries(FLAGS.map((flag) => [flag, true])),
    });
    const descriptor = fs.openSync(guardPath, "r");
    try {
      const now = fs.fstatSync(descriptor, { bigint: true });
      const bytes = Buffer.alloc(4097);
      const length = fs.readSync(descriptor, bytes, 0, bytes.length, 0);
      const named = fs.lstatSync(guardPath, { bigint: true });
      assert.ok(
        now.isFile() &&
          named.isFile() &&
          !named.isSymbolicLink() &&
          now.dev === guardIdentity.dev &&
          now.ino === guardIdentity.ino &&
          named.dev === now.dev &&
          named.ino === now.ino &&
          now.size === BigInt(length) &&
          bytes.subarray(0, length).equals(guardBytes),
        "Live ACL fixture ownership changed",
      );
    } finally {
      fs.closeSync(descriptor);
    }
    fs.unlinkSync(guardPath);
    ownedStoreReceipt.machineAclPendingVerification = false;
    gate.report.fixtureSources ??= [];
    for (const file of REQUIRED_SOURCES)
      gate.report.fixtureSources.push({
        file,
        sha256: hash(fs.readFileSync(path.join(root, file))),
      });
    return proof;
  } finally {
    // Restoring directory permissions never clears an unverified native leaf or
    // parent cleanup guard. A failed/unknown acceptance preserves the fixture.
    if (!restored) mutate("Restore");
  }
}
module.exports = {
  SCOPE,
  FLAGS,
  REQUIRED_SCENARIOS,
  REQUIRED_SOURCES,
  verifyProof,
  verifyInstalledEvidence,
  verifyNativeRequestId,
  qualifyLiveEnrollAcl,
};
