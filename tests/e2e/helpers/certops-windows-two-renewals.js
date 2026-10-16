"use strict";
/** Two genuine unattended generations in the existing installed Windows fixture.
 * This adds one real worker sweep after the first successful renewal, using the
 * actual renewed expiry as generation input. Independent TLS/SPKI, CNG, binding,
 * claim-bound evidence and immutable retention rows prove A -> B -> C. No due
 * time, successful job, journal or ledger row is manufactured. Expiry cleanup
 * remains outside this short journey; the parent owns eventual fixture cleanup. */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto"),
  tls = require("node:tls");
const requiredScenarios = [
  "windows-two-unattended-natural-generations",
  "windows-two-unattended-native-cutovers",
  "windows-two-unattended-preserved-predecessors",
];
const requiredSources = [
  "tests/e2e/helpers/certops-windows-two-renewals.js",
  "tests/e2e/windows-real-journey.js",
  "apps/api/services/certops/renewalScheduler.js",
  "apps/api/services/certops/agentDispatch.js",
  "packages/agent/src/index.js",
  "packages/agent/src/windows-retention/index.js",
];
const fields = [
  "automaticSourceAndRealMode",
  "naturallyDueGenerations",
  "distinctIdempotencyKeys",
  "leafAndSpkiChangedTwice",
  "nativeBindingMatchesLatest",
  "nativeKeyProfilesVerified",
  "persistedEvidenceBothCycles",
  "inventoryMatchesActualLeaf",
  "profileAndManagementLineagePreserved",
  "retentionLineageMatchesBothCutovers",
  "predecessorCustodyPreserved",
  "noExpiryOrClockOverrides",
];
function verifyProof(proof) {
  assert.equal(proof.successfulAutomationCycles, 2);
  for (const field of fields) assert.equal(proof[field], true, field);
  assert.equal(proof.expiryCleanupQualified, false);
  assert.equal(
    proof.scope,
    "two-unattended-cycles-and-preserved-predecessors-not-expiry-cleanup",
  );
  return true;
}
const normalized = (value) => String(value).replace(/:/g, "").toLowerCase();
function describe(peer) {
  const certificate = new crypto.X509Certificate(peer.raw);
  return {
    certificate,
    thumb: certificate.fingerprint.replace(/:/g, "").toUpperCase(),
    fingerprint: normalized(certificate.fingerprint256),
    spki: crypto
      .createHash("sha256")
      .update(certificate.publicKey.export({ type: "spki", format: "der" }))
      .digest("hex"),
    expires: Date.parse(certificate.validTo),
  };
}
async function qualifyTwoRenewals(context) {
  const {
    repoRoot,
    pool,
    workspaceId,
    certificateId,
    configDir,
    domain,
    port,
    site,
    roots,
    initialPeer,
    firstPeer,
    initialManaged,
    profile,
    firstRenewalJobId,
    worker,
    schedulerEnv,
    powershell: ps,
    run,
    waitUntil,
    ownedJobs,
    keyProfile,
  } = context;
  assert.equal(process.platform, "win32");
  assert.equal(process.env.GITHUB_ACTIONS, "true");
  assert.equal(process.env.CERTOPS_REAL_WINDOWS_REQUIRED, "1");
  const hash = (file) => ({
    file,
    sha256: crypto
      .createHash("sha256")
      .update(fs.readFileSync(path.join(repoRoot, file)))
      .digest("hex"),
  });
  const keyProfileName = process.env.CERTOPS_WINDOWS_KEY_PROFILE;
  assert.ok(
    ["rsa-2048", "rsa-3072", "rsa-4096", "ec-p256", "ec-p384"].includes(
      keyProfileName,
    ),
  );
  const gate =
    require("../../../packages/agent/scripts/host-gate").createHostGate({
      suite: "windows-two-unattended-renewals",
      strict: true,
      evidenceLevel: "e2e",
      reportPath: `qualification-results/windows-two-renewals-${keyProfileName}.json`,
      fixtureSource: hash(requiredSources[0]),
      requiredCapabilities: [
        "windows",
        "system",
        "installedAgent",
        "api",
        "pebble",
      ],
      probeCapabilities: () => ({
        windows: { available: true },
        system: {
          available:
            ps(
              "[Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
            ) === "S-1-5-18",
        },
        installedAgent: {
          available: ps("(Get-Service TokenTimerAgent).Status") === "Running",
        },
        api: { available: true },
        pebble: { available: Boolean(process.env.CERTOPS_PEBBLE_DIRECTORY) },
      }),
    });
  gate.report.fixtureSources = requiredSources.map(hash);
  gate.report.qualificationEnvironment.keyProfile = keyProfileName;
  const initial = describe(initialPeer),
    first = describe(firstPeer);
  const loadJob = async (id) =>
    (
      await pool.query(
        "SELECT id,status,source,mode,operation,subject_id,idempotency_key,payload,claim_id FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",
        [workspaceId, id],
      )
    ).rows[0];
  const loadManaged = async () =>
    (
      await pool.query(
        "SELECT mc.profile_id,mc.not_after,mc.fingerprint_sha256,mc.reconciliation_reason,cp.renew_before_days,cp.public_metadata FROM managed_certificates mc JOIN certificate_profiles cp ON cp.workspace_id=mc.workspace_id AND cp.id=mc.profile_id WHERE mc.workspace_id=$1 AND mc.id=$2",
        [workspaceId, certificateId],
      )
    ).rows[0];
  const loadPeriod = async () =>
    (
      await pool.query(
        "SELECT id,current_identity_id,automation_enabled FROM certops_management_periods WHERE workspace_id=$1 AND managed_certificate_id=$2 AND ended_at IS NULL",
        [workspaceId, certificateId],
      )
    ).rows;
  const custody = (thumb) => {
    assert.match(thumb, /^[A-F0-9]{40}$/);
    return JSON.parse(
      ps(
        `$c=Get-Item 'Cert:\\LocalMachine\\My\\${thumb}';$k=$null;try{$k=if($c.PublicKey.Oid.Value -eq '1.2.840.113549.1.1.1'){[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c)}else{[Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($c)};@{thumb=$c.Thumbprint;container=$k.Key.KeyName;unique=$k.Key.UniqueName;policy=[int]$k.Key.ExportPolicy;provider=$k.Key.Provider.Provider;machine=$k.Key.IsMachineKey;bits=$k.KeySize;der=[Convert]::ToBase64String($c.RawData)}|ConvertTo-Json -Compress}finally{if($k){$k.Dispose()};$c.Dispose()}`,
      ),
    );
  };
  let nativeInitial, nativeFirst;
  const store = require(
    path.join(repoRoot, "packages/agent/src/windows-cert-store"),
  );
  const validateCustody = (value, description) => {
    assert.equal(value.policy, 0);
    assert.equal(value.machine, true);
    assert.equal(value.provider, "Microsoft Software Key Storage Provider");
    assert.equal(value.bits, keyProfile.keySize);
    assert.equal(
      description.certificate.publicKey.asymmetricKeyType,
      keyProfile.keyAlgorithm === "rsa" ? "rsa" : "ec",
    );
    assert.equal(
      normalized(
        new crypto.X509Certificate(Buffer.from(value.der, "base64"))
          .fingerprint256,
      ),
      description.fingerprint,
    );
    const record = store.readIssuedContainerRecord({
      stateDir: configDir,
      containerName: value.container,
    });
    assert.equal(record?.status, "enrolled_by_agent");
    assert.equal(record.acceptedThumbprint.toUpperCase(), description.thumb);
    assert.equal(String(record.certificateId), String(certificateId));
  };
  const generation = require(
    path.join(repoRoot, "apps/api/services/certops/renewalScheduler"),
  ).renewalIdempotencyKey;
  const peer = () =>
    new Promise((resolve, reject) => {
      const socket = tls.connect(
        {
          host: "127.0.0.1",
          port,
          servername: domain,
          ca: roots.map((root) => root.pem),
          rejectUnauthorized: true,
        },
        () => {
          try {
            assert.equal(socket.authorized, true);
            resolve(socket.getPeerCertificate());
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
          new Error("Second unattended TLS oracle deadline exceeded"),
        ),
      );
    });
  let secondJob,
    secondPeer,
    second,
    firstJob,
    periodBefore,
    expectedGeneration,
    primary;
  const proof = {
    successfulAutomationCycles: 2,
    automaticSourceAndRealMode: false,
    naturallyDueGenerations: false,
    distinctIdempotencyKeys: false,
    leafAndSpkiChangedTwice: false,
    nativeBindingMatchesLatest: false,
    nativeKeyProfilesVerified: false,
    persistedEvidenceBothCycles: false,
    inventoryMatchesActualLeaf: false,
    profileAndManagementLineagePreserved: false,
    retentionLineageMatchesBothCutovers: false,
    predecessorCustodyPreserved: false,
    noExpiryOrClockOverrides: true,
    expiryCleanupQualified: false,
    scope:
      "two-unattended-cycles-and-preserved-predecessors-not-expiry-cleanup",
  };
  await gate.preflight();
  gate.report.qualificationEnvironment.identity = "LocalSystem";
  try {
    await gate.scenario(requiredScenarios[0], async () => {
      assert.notEqual(first.fingerprint, initial.fingerprint);
      assert.notEqual(first.spki, initial.spki);
      assert.ok(first.expires > initial.expires);
      assert.equal(
        Date.parse(initialManaged.not_after),
        initial.expires,
        "Initial generation must use the actually served leaf expiry",
      );
      nativeInitial = custody(initial.thumb);
      nativeFirst = custody(first.thumb);
      validateCustody(nativeInitial, initial);
      validateCustody(nativeFirst, first);
      assert.notEqual(nativeInitial.container, nativeFirst.container);
      firstJob = await loadJob(firstRenewalJobId);
      assert.equal(firstJob.source, "automation");
      assert.equal(firstJob.mode, "real");
      assert.equal(firstJob.operation, "renew");
      assert.equal(firstJob.status, "succeeded");
      assert.equal(firstJob.subject_id, certificateId);
      assert.equal(
        firstJob.idempotency_key,
        generation(certificateId, initialManaged.not_after),
      );
      assert.equal(firstJob.payload.keyRotation, true);
      const managed = await waitUntil(async () => {
        const row = await loadManaged();
        return row &&
          normalized(row.fingerprint_sha256) === first.fingerprint &&
          Date.parse(row.not_after) === first.expires
          ? row
          : null;
      });
      assert.equal(managed.reconciliation_reason, null);
      assert.equal(managed.profile_id, initialManaged.profile_id);
      assert.deepEqual(managed.public_metadata.renewalProfile, profile);
      const periods = await loadPeriod();
      assert.equal(periods.length, 1);
      periodBefore = periods[0];
      assert.equal(periodBefore.automation_enabled, true);
      assert.ok(
        first.expires <=
          Date.now() + (managed.renew_before_days || 30) * 86400000,
        "The actual first renewal must remain naturally due",
      );
      const expected = (expectedGeneration = generation(
        certificateId,
        managed.not_after,
      ));
      assert.notEqual(expected, firstJob.idempotency_key);
      assert.equal(
        (
          await pool.query(
            "SELECT COUNT(*)::int AS count FROM certificate_jobs WHERE workspace_id=$1 AND idempotency_key=$2",
            [workspaceId, expected],
          )
        ).rows[0].count,
        0,
        "A fresh due generation must have no previous job",
      );
      // Real wait only: ensure the next CA issuance cannot share the previous
      // certificate's second-resolution issuance instant. No clock is replaced.
      await new Promise((resolve) => setTimeout(resolve, 1100));
      await worker.runCertOpsMaintenance({ dbPool: pool, env: schedulerEnv });
      secondJob = await waitUntil(
        async () =>
          (
            await pool.query(
              "SELECT id FROM certificate_jobs WHERE workspace_id=$1 AND subject_id=$2 AND source='automation' AND operation='renew' AND idempotency_key=$3",
              [workspaceId, certificateId, expected],
            )
          ).rows[0],
      );
      assert.notEqual(secondJob.id, firstJob.id);
      ownedJobs.push(secondJob.id);
      secondJob = await loadJob(secondJob.id);
      assert.equal(secondJob.source, "automation");
      assert.equal(secondJob.mode, "real");
      assert.equal(secondJob.payload.keyRotation, true);
      assert.deepEqual(
        secondJob.payload.renewalProfile,
        firstJob.payload.renewalProfile,
      );
      proof.automaticSourceAndRealMode = true;
      proof.naturallyDueGenerations = true;
      proof.distinctIdempotencyKeys = true;
    });
    await gate.scenario(requiredScenarios[1], async () => {
      await waitUntil(async () => {
        const row = await loadJob(secondJob.id);
        if (
          [
            "failed",
            "rejected",
            "cancelled",
            "orphaned_unknown_effect",
          ].includes(row?.status)
        )
          throw new Error("Second unattended renewal failed");
        return row?.status === "succeeded";
      });
      secondJob = await loadJob(secondJob.id);
      secondPeer = await peer();
      second = describe(secondPeer);
      assert.equal(second.certificate.checkHost(domain), domain);
      assert.equal(
        new Set([initial.fingerprint, first.fingerprint, second.fingerprint])
          .size,
        3,
      );
      assert.equal(new Set([initial.spki, first.spki, second.spki]).size, 3);
      assert.ok(second.expires > first.expires);
      const binding = JSON.parse(
        ps(
          `Import-Module WebAdministration;$b=@(Get-WebBinding -Name '${site.replace(/'/g, "''")}' -Protocol https | Where-Object {$_.bindingInformation -eq '*:${port}:${domain}'});if($b.Count -ne 1){throw 'Missing exact second-renewal IIS selector'};$h=$b[0].certificateHash;if($h -is [byte[]]){$h=[BitConverter]::ToString($h).Replace('-','')};@{hash=([string]$h).ToUpperInvariant();store=[string]$b[0].certificateStoreName;flags=[int]$b[0].sslFlags}|ConvertTo-Json -Compress`,
        ),
      );
      assert.equal(binding.hash.toUpperCase(), second.thumb);
      assert.equal(binding.store, "My");
      assert.equal(binding.flags, 1);
      assert.ok(
        run("netsh.exe", [
          "http",
          "show",
          "sslcert",
          `hostnameport=${domain}:${port}`,
        ])
          .toUpperCase()
          .includes(second.thumb),
      );
      const nativeSecond = custody(second.thumb);
      validateCustody(nativeSecond, second);
      assert.equal(
        new Set([
          nativeInitial.container,
          nativeFirst.container,
          nativeSecond.container,
        ]).size,
        3,
      );
      for (const [job, description, input] of [
        [firstJob, first, initialManaged.not_after],
        [secondJob, second, new Date(first.expires)],
      ]) {
        const evidence = (
          await pool.query(
            "SELECT e.metadata FROM certificate_evidence e JOIN certificate_jobs j ON j.workspace_id=e.workspace_id AND j.id=e.job_id WHERE e.workspace_id=$1 AND e.job_id=$2 AND e.evidence_type='validation.passed' AND e.claim_id=j.claim_id AND e.metadata->>'step'='verify'",
            [workspaceId, job.id],
          )
        ).rows;
        assert.ok(
          evidence.some(
            (row) =>
              normalized(row.metadata.fingerprintSha256) ===
                description.fingerprint &&
              Date.parse(row.metadata.validTo) === description.expires,
          ),
        );
        const audits = (
          await pool.query(
            "SELECT metadata FROM audit_events WHERE workspace_id=$1 AND action='CERTOPS_JOB_CREATED_AUTOMATIC' AND metadata->>'jobId'=$2",
            [workspaceId, job.id],
          )
        ).rows;
        assert.equal(audits.length, 1);
        assert.equal(audits[0].metadata.profileId, initialManaged.profile_id);
        assert.equal(
          Date.parse(audits[0].metadata.notAfter),
          Date.parse(input),
        );
      }
      const managed = await waitUntil(async () => {
        const row = await loadManaged();
        return row &&
          normalized(row.fingerprint_sha256) === second.fingerprint &&
          Date.parse(row.not_after) === second.expires
          ? row
          : null;
      });
      assert.equal(managed.profile_id, initialManaged.profile_id);
      assert.equal(managed.reconciliation_reason, null);
      assert.deepEqual(managed.public_metadata.renewalProfile, profile);
      const periods = await loadPeriod();
      assert.equal(periods.length, 1);
      assert.equal(periods[0].id, periodBefore.id);
      assert.equal(periods[0].automation_enabled, true);
      assert.equal(
        (
          await pool.query(
            "SELECT fingerprint_sha256 FROM certops_certificate_identities WHERE workspace_id=$1 AND id=$2",
            [workspaceId, periods[0].current_identity_id],
          )
        ).rows[0]?.fingerprint_sha256,
        second.fingerprint,
      );
      const associations = (
        await pool.query(
          "SELECT i.fingerprint_sha256,a.superseded_at FROM certops_management_associations a JOIN certops_certificate_identities i ON i.workspace_id=a.workspace_id AND i.id=a.identity_id WHERE a.workspace_id=$1 AND a.period_id=$2",
          [workspaceId, periodBefore.id],
        )
      ).rows;
      for (const description of [initial, first, second])
        assert.ok(
          associations.some(
            (row) => row.fingerprint_sha256 === description.fingerprint,
          ),
        );
      assert.ok(
        associations.some(
          (row) =>
            row.fingerprint_sha256 === second.fingerprint &&
            row.superseded_at === null,
        ),
      );
      Object.assign(proof, {
        leafAndSpkiChangedTwice: true,
        nativeBindingMatchesLatest: true,
        nativeKeyProfilesVerified: true,
        persistedEvidenceBothCycles: true,
        inventoryMatchesActualLeaf: true,
        profileAndManagementLineagePreserved: true,
      });
    });
    await gate.scenario(requiredScenarios[2], () => {
      const ledger = require(
          path.join(repoRoot, "packages/agent/src/windows-retention"),
        ),
        dir = path.join(configDir, "windows-retention");
      const rows = [
        [
          ledger.readLedgerRow(dir, initial.thumb),
          initial,
          first,
          nativeInitial,
          firstJob,
        ],
        [
          ledger.readLedgerRow(dir, first.thumb),
          first,
          second,
          nativeFirst,
          secondJob,
        ],
      ];
      for (const [row, old, replacement, native, job] of rows) {
        assert.ok(row);
        assert.equal(row.oldThumbprint, old.thumb);
        assert.equal(row.replacementThumbprint, replacement.thumb);
        assert.equal(row.cngKeyContainerId, native.container);
        assert.equal(row.ownershipProvenance, "tokentimer_installed");
        assert.equal(row.store, "My");
        assert.equal(Date.parse(row.oldNotAfter), old.expires);
        assert.ok(Number.isFinite(Date.parse(row.verifiedCutoverAt)));
        assert.notEqual(row.lifecycleState, "removed");
        assert.ok(
          row.jobOrRollbackJournalRefs.some(
            (ref) => ref.ref === job.id && ref.active === false,
          ),
        );
        assert.ok(old.expires > Date.now());
      }
      assert.ok(
        Date.parse(rows[1][0].verifiedCutoverAt) >=
          Date.parse(rows[0][0].verifiedCutoverAt),
      );
      assert.deepEqual(custody(initial.thumb), nativeInitial);
      assert.deepEqual(custody(first.thumb), nativeFirst);
      proof.retentionLineageMatchesBothCutovers = true;
      proof.predecessorCustodyPreserved = true;
      verifyProof(proof);
      gate.report.nativeTwoRenewals = proof;
    });
  } catch (error) {
    primary = error;
  } finally {
    // Recover only the generation whose absence this fixture checked before
    // triggering the real sweep, even if observing its new job timed out.
    if (expectedGeneration)
      try {
        const jobs = (
          await pool.query(
            "SELECT id FROM certificate_jobs WHERE workspace_id=$1 AND subject_id=$2 AND source='automation' AND idempotency_key=$3",
            [workspaceId, certificateId, expectedGeneration],
          )
        ).rows;
        for (const job of jobs)
          if (!ownedJobs.includes(job.id)) ownedJobs.push(job.id);
      } catch (error) {
        primary = primary
          ? new AggregateError(
              [primary, error],
              "Two-renewal owned job recovery failed",
            )
          : error;
      }
    try {
      await gate.finish({ requiredScenarios });
    } catch (error) {
      primary = primary
        ? new AggregateError(
            [primary, error],
            "Two-renewal qualification/report failed",
          )
        : error;
    }
  }
  if (primary) throw primary;
  return {
    latestPeer: secondPeer,
    latestThumbprint: second.thumb,
    successfulAutomationJobIds: [firstJob.id, secondJob.id],
    nextGenerationKey: generation(certificateId, new Date(second.expires)),
  };
}
module.exports = {
  qualifyTwoRenewals,
  verifyProof,
  requiredScenarios,
  requiredSources,
};
