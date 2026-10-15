"use strict";
/** Actual late CA approval after public cancellation and a distinct real
 * successor installation on the same owned IIS endpoint. Reuses existing
 * requests; no extra preflight, enrollment, timer override or result fixture.
 * An unresolved guard preserves native and durable state for owner cleanup.
 */
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const tls = require("node:tls");
const { isDeepStrictEqual } = require("node:util");
const {
  readEnrollmentJournal,
} = require("../../../packages/agent/src/issuers/adcs-enrollment");
const {
  buildEnrollmentContainerName,
} = require("../../../packages/agent/src/windows-cert-store");
const {
  extractSpkiFromCsr,
  pemToDer,
} = require("../../../packages/agent/src/issuers/der-extensions");
const { verifyIssuedLeaf } = require("./certops-adcs-issued-revocation");

const SCOPE =
  "real-cancelled-request-late-issued-after-distinct-same-endpoint-successor";
const SAME_CERTIFICATE_SCOPE =
  "real-cancelled-request-late-issued-after-same-certificate-renewal";
const REQUIRED_SCENARIOS = Object.freeze([
  "adcs-real-cancelled-late-approval-preserves-installed-successor",
]);
const FLAGS = Object.freeze([
  "publicCancellationAuditVerified",
  "terminalCleanupAlreadyCompleted",
  "distinctActualSuccessorInstalled",
  "nativePendingCsrRequesterTemplateOwned",
  "actualOfficerLateApproval",
  "actualCaLeafMatchesOriginalCsr",
  "defaultClockDoesNotRevive",
  "overdueSchedulerDoesNotRevive",
  "publicInstallationRetryRefused",
  "originalJournalAndJobsUnchanged",
  "cancelledKeyRemainsAbsent",
  "lateLeafNeverAccepted",
  "successorClaimEvidenceUnchanged",
  "successorNativeCustodyBindingTlsUnchanged",
  "noCaResubmission",
  "ownedUnusedLateLeafRevoked",
]);
const REQUIRED_SOURCES = Object.freeze([
  "tests/e2e/helpers/certops-adcs-cancelled-late-approval.js",
  "tests/e2e/helpers/certops-adcs-recovery.js",
  "tests/e2e/helpers/certops-adcs-issued-revocation.js",
  "tests/e2e/certops-adcs-real-e2e.test.js",
  "infra/certops-adcs/owned-request-csr.ps1",
  "infra/certops-adcs/owned-request-observation.ps1",
  "infra/certops-adcs/owned-ca-request-certificate.ps1",
  "infra/certops-adcs/officer-action.ps1",
  "packages/agent/src/issuers/adcs-enrollment.js",
  "packages/agent/src/issuers/adcs-enrollment-journal.js",
  "packages/agent/src/issuers/der-extensions.js",
  "packages/agent/src/windows-cert-store/index.js",
  "apps/api/routes/certops-enrollments.js",
  "apps/api/services/certops/certificateEnrollments.js",
  "apps/api/services/certops/enrollmentLifecycle.js",
]);
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const REQUEST = /^[1-9][0-9]{0,9}$/;
const sha = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");

function verifyProof(value) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value));
  assert.deepEqual(
    Object.keys(value).sort(),
    [
      "scope",
      "cancelledEnrollmentId",
      "successorEnrollmentId",
      "requestIds",
      "fingerprints",
      "sameCertificateRenewalQualified",
      ...FLAGS,
    ].sort(),
  );
  assert.equal(value.scope, SCOPE);
  assert.equal(value.sameCertificateRenewalQualified, false);
  for (const flag of FLAGS) assert.equal(value[flag], true, flag);
  for (const field of ["cancelledEnrollmentId", "successorEnrollmentId"])
    assert.match(value[field], UUID);
  assert.notEqual(value.cancelledEnrollmentId, value.successorEnrollmentId);
  for (const [field, pattern] of [
    ["requestIds", REQUEST],
    ["fingerprints", /^[a-f0-9]{64}$/],
  ]) {
    assert.ok(Array.isArray(value[field]));
    assert.equal(value[field].length, 2);
    assert.equal(new Set(value[field]).size, 2);
    for (const item of value[field]) assert.match(item, pattern);
  }
  for (const id of value.requestIds) assert.ok(Number(id) <= 0xffffffff);
  return true;
}

function verifyCaOwnership(
  native,
  { requestId, domain, journal, csrPem, disposition },
) {
  assert.equal(String(native.requestId), String(requestId));
  assert.equal(native.commonName, domain);
  assert.equal(native.requester.toLowerCase(), "ttqual\\tt-agent$");
  assert.equal(native.disposition, disposition);
  assert.equal(native.templateOid, journal.templateOid);
  assert.equal(typeof native.csrDerB64, "string");
  assert.ok(native.csrDerB64.length <= 90000);
  const der = Buffer.from(native.csrDerB64, "base64");
  assert.ok(der.length >= 100 && der.length <= 65536);
  assert.ok(
    der.equals(pemToDer(csrPem)),
    "Native CA request must carry the original public CSR",
  );
  assert.equal(sha(extractSpkiFromCsr(der)), journal.csrSpkiSha256);
  return true;
}

function assertCleanupSafe(guards) {
  assert.ok(Array.isArray(guards));
  assert.ok(
    guards.every((value) => value.resolved === true),
    "Preserve native and durable state while late approval ownership is unresolved",
  );
}

function nativeCustodyScript({
  thumbprint,
  containerName,
  certificateDerB64,
  domain,
  site,
  port,
}) {
  assert.match(thumbprint, /^[A-F0-9]{40}$/);
  assert.match(containerName, /^tokentimer-enr-[a-f0-9-]{36}$/);
  assert.match(domain, /^certops-adcs-[a-f0-9]{10}-cancel\.example\.test$/);
  assert.match(site, /^TTADCS-[a-f0-9]{10}-cancel$/);
  assert.ok(Number.isInteger(port) && port > 0 && port <= 65535);
  assert.match(certificateDerB64, /^[A-Za-z0-9+/=]+$/);
  return `Import-Module WebAdministration;$c=Get-Item -LiteralPath 'Cert:\\LocalMachine\\My\\${thumbprint}';$k=$null;$public=$null;$hash=[Security.Cryptography.SHA256]::Create();try{
if([Convert]::ToBase64String($c.RawData) -cne '${certificateDerB64}'){throw 'Successor DER changed'}
$k=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c);if(!$k -or $k.Key.KeyName -cne '${containerName}' -or !$k.Key.IsMachineKey -or $k.Key.Provider.Provider -cne 'Microsoft Software Key Storage Provider' -or [int]$k.Key.ExportPolicy -ne 0 -or $k.KeySize -ne 2048){throw 'Successor protected custody changed'}
$nonce=[Text.Encoding]::UTF8.GetBytes([guid]::NewGuid().ToString());$signature=$k.SignData($nonce,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1);$public=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($c);if(!$public.VerifyData($nonce,$signature,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)){throw 'Successor private possession failed'}
$b=@(Get-WebBinding -Name '${site}' -Protocol https|Where-Object bindingInformation -eq '*:${port}:${domain}');$native=@(Get-ChildItem -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\HTTP\\Parameters\\SslSniBindingInfo'|Where-Object {[string]$_.GetValue('HostnamePort') -ieq '${domain}:${port}'});if($b.Count -ne 1 -or $native.Count -ne 1 -or $b[0].certificateStoreName -cne 'My' -or [int]$b[0].sslFlags -ne 1){throw 'Successor IIS selector changed'}
$iisHash=$b[0].certificateHash;if($iisHash -is [byte[]]){$iisHash=[BitConverter]::ToString($iisHash).Replace('-','')};$iisHash=([string]$iisHash).ToUpperInvariant();if($iisHash -cne '${thumbprint}'){throw 'Successor IIS certificate hash changed'}
$nativeHash=[BitConverter]::ToString([byte[]]$native[0].GetValue('SslCertHash')).Replace('-','');$nativeStore=[string]$native[0].GetValue('SslCertStoreName');if($nativeHash -cne '${thumbprint}' -or $nativeStore -cne 'My'){throw 'Successor native HTTP.sys hash or store changed'}
@{uniqueSha256=([BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($k.Key.UniqueName)))).Replace('-','').ToLowerInvariant();iisHash=$iisHash;nativeHash=$nativeHash;nativeStore=$nativeStore;store=[string]$b[0].certificateStoreName;flags=[int]$b[0].sslFlags}|ConvertTo-Json -Compress
}finally{if($public){$public.Dispose()};if($k){$k.Dispose()};$hash.Dispose();$c.Dispose()}`;
}

async function qualifyLateApproval(context, sameCertificateRenewal = false) {
  const {
    gate,
    fixture,
    api,
    configDir,
    pendingRecoveryFixtures,
    ownedEnrollmentIds,
    ownedLateApprovalGuards,
    ps,
    command,
    until,
    tlsAuthority,
  } = context;
  assert.equal(process.platform, "win32");
  assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB, "1");
  assert.equal(
    ps("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value"),
    "S-1-5-18",
  );
  const owned = pendingRecoveryFixtures.cancel;
  assert.ok(owned);
  const oldId = owned.created.enrollmentId;
  assert.match(oldId, UUID);
  assert.ok(ownedEnrollmentIds.includes(oldId));
  const root = path.resolve(__dirname, "../../..");
  gate.report.fixtureSources ||= [];
  for (const file of REQUIRED_SOURCES) {
    const digest = sha(fs.readFileSync(path.join(root, file)));
    const rows = gate.report.fixtureSources.filter(
      (value) => value.file === file,
    );
    if (rows.length) {
      assert.equal(rows.length, 1);
      assert.equal(rows[0].sha256, digest);
    } else gate.report.fixtureSources.push({ file, sha256: digest });
  }
  await gate.scenario(
    sameCertificateRenewal
      ? "adcs-real-same-certificate-cancelled-late-approval-preserves-renewal"
      : REQUIRED_SCENARIOS[0],
    async () => {
      const query = (sql, values) => fixture.pool.query(sql, values);
      const row = async (id) =>
        (
          await query(
            "SELECT id,state,request_id,current_job_id,certificate_id,snapshot_sha256,next_poll_at,last_error_code FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2",
            [fixture.workspaceId, id],
          )
        ).rows[0];
      const jobs = async (id) =>
        (
          await query(
            "SELECT id,status,claim_id,result_metadata FROM certificate_jobs WHERE workspace_id=$1 AND enrollment_id=$2 ORDER BY id",
            [fixture.workspaceId, id],
          )
        ).rows;
      const terminal = await row(oldId);
      assert.equal(terminal.state, "cancelled");
      assert.equal(terminal.next_poll_at, null);
      assert.equal(
        String(terminal.request_id),
        String(owned.pending.request_id),
      );
      const oldJournal = readEnrollmentJournal(configDir, oldId);
      assert.equal(oldJournal.kind, "valid");
      assert.equal(oldJournal.journal.state, "cancelled");
      assert.equal(
        oldJournal.journal.containerName,
        buildEnrollmentContainerName(oldId),
      );
      assert.equal(
        String(oldJournal.journal.requestId),
        String(terminal.request_id),
      );
      assert.ok(oldJournal.artifacts.csrPem);
      const oldJobs = await jobs(oldId);
      assert.ok(
        oldJobs.length >= 2 &&
          oldJobs.every(
            (value) =>
              ![
                "claimed",
                "running",
                "pending",
                "pending_approval",
                "approved",
              ].includes(value.status),
          ),
      );
      // Historical awaiting_issuer jobs remain as evidence. The current
      // cleanup continuation itself must have actually succeeded.
      assert.equal(terminal.current_job_id, owned.continuation.jobId);
      assert.equal(
        oldJobs.find((value) => value.id === terminal.current_job_id)?.status,
        "succeeded",
      );
      const audits = (
        await query(
          "SELECT metadata FROM audit_events WHERE workspace_id=$1 AND action='CERTOPS_ENROLLMENT_CANCELLED' AND metadata->>'enrollmentId'=$2",
          [fixture.workspaceId, oldId],
        )
      ).rows;
      assert.equal(audits.length, 1);
      const peer = () =>
        new Promise((resolve, reject) => {
          const socket = tls.connect(
            {
              host: "127.0.0.1",
              port: owned.port,
              servername: owned.item.domain,
              ca: tlsAuthority(owned.authority),
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
              new Error("Late approval successor trusted TLS timeout"),
            ),
          );
        });
      const successor = await peer();
      const matches = ownedEnrollmentIds
        .map((id) => ({ id, ...readEnrollmentJournal(configDir, id) }))
        .filter(
          (value) =>
            value.kind === "valid" &&
            value.journal.state === "installed" &&
            value.artifacts.leafPem &&
            new crypto.X509Certificate(value.artifacts.leafPem)
              .fingerprint256 === successor.fingerprint256,
        );
      assert.equal(
        matches.length,
        1,
        "Actual serving successor must bind one owned installed journal",
      );
      const current = matches[0];
      assert.notEqual(current.id, oldId);
      const currentRow = await row(current.id);
      assert.equal(currentRow.state, "installed");
      if (sameCertificateRenewal)
        assert.equal(currentRow.certificate_id, terminal.certificate_id);
      else assert.notEqual(currentRow.certificate_id, terminal.certificate_id);
      assert.notEqual(
        String(currentRow.request_id),
        String(terminal.request_id),
      );
      const currentJobs = await jobs(current.id);
      const currentJob = currentJobs.find(
        (value) => value.id === currentRow.current_job_id,
      );
      assert.equal(currentJob.status, "succeeded");
      assert.match(currentJob.claim_id, UUID);
      const evidence = async () =>
        (
          await query(
            "SELECT evidence_type,claim_id,metadata FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2 ORDER BY id",
            [fixture.workspaceId, currentRow.current_job_id],
          )
        ).rows;
      const evidenceBefore = await evidence();
      assert.ok(
        evidenceBefore.some(
          (value) =>
            value.claim_id === currentJob.claim_id &&
            value.evidence_type === "validation.passed" &&
            value.metadata?.step === "verify" &&
            String(value.metadata.fingerprintSha256)
              .replace(/:/g, "")
              .toLowerCase() === sha(successor.raw),
        ),
      );
      const custody = () =>
        JSON.parse(
          ps(
            nativeCustodyScript({
              thumbprint: successor.fingerprint.replace(/:/g, ""),
              containerName: current.journal.containerName,
              certificateDerB64: successor.raw.toString("base64"),
              domain: owned.item.domain,
              site: owned.site,
              port: owned.port,
            }),
          ),
        );
      const before = custody();
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
      const requestId = String(terminal.request_id);
      const args = ["-CommonName", owned.item.domain, "-RequestId", requestId];
      const caOwnership = (disposition) => {
        const native = invoke("owned-request-csr.ps1", args);
        verifyCaOwnership(native, {
          requestId,
          domain: owned.item.domain,
          journal: oldJournal.journal,
          csrPem: oldJournal.artifacts.csrPem,
          disposition,
        });
      };
      const observe = () => invoke("owned-request-observation.ps1", args);
      const initial = observe();
      assert.equal(initial.disposition, 9);
      caOwnership(9);
      const keyAbsent = () =>
        assert.equal(
          ps(
            `[bool](-not [Security.Cryptography.CngKey]::Exists('${oldJournal.journal.containerName}',[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider,[Security.Cryptography.CngKeyOpenOptions]::MachineKey))`,
          ),
          "True",
        );
      keyAbsent();
      const guard = { enrollmentId: oldId, resolved: false };
      ownedLateApprovalGuards.push(guard);
      let lateLeaf, primaryError, cleanupError;
      const absentLeaf = () => {
        assert.ok(lateLeaf);
        const thumbprint = lateLeaf.fingerprint.replace(/:/g, "");
        assert.equal(
          ps(
            `$count=0;$matches=0;Get-ChildItem Cert:\\LocalMachine -Recurse -ErrorAction Stop|ForEach-Object {if($_ -is [Security.Cryptography.X509Certificates.X509Certificate2]){if(++$count -gt 100000){throw 'Bounded native store inventory exceeded'};if($_.Thumbprint -ceq '${thumbprint}'){$matches++}}};[string]$matches`,
          ),
          "0",
        );
      };
      const officer = (action) =>
        command("powershell.exe", [
          "-NoProfile",
          "-NonInteractive",
          "-File",
          path.join(root, "infra/certops-adcs/officer-action.ps1"),
          "-CommonName",
          owned.item.domain,
          "-RequestId",
          requestId,
          "-Action",
          action,
        ]);
      const unchanged = async () => {
        assert.ok(
          isDeepStrictEqual(await row(oldId), terminal),
          "Cancelled enrollment changed",
        );
        assert.ok(
          isDeepStrictEqual(await jobs(oldId), oldJobs),
          "Cancelled jobs changed",
        );
        assert.ok(
          isDeepStrictEqual(
            readEnrollmentJournal(configDir, oldId),
            oldJournal,
          ),
          "Cancelled journal or artifacts changed",
        );
        assert.ok(
          isDeepStrictEqual(await row(current.id), currentRow),
          "Successor enrollment changed",
        );
        assert.ok(
          isDeepStrictEqual(await jobs(current.id), currentJobs),
          "Successor jobs changed",
        );
        assert.ok(
          isDeepStrictEqual(
            { id: current.id, ...readEnrollmentJournal(configDir, current.id) },
            current,
          ),
          "Successor durable journal or artifacts changed",
        );
        assert.ok(
          isDeepStrictEqual(await evidence(), evidenceBefore),
          "Successor claim-bound evidence changed",
        );
        assert.ok(
          isDeepStrictEqual(custody(), before),
          "Successor native key or selectors changed",
        );
        assert.equal((await peer()).fingerprint256, successor.fingerprint256);
        keyAbsent();
        absentLeaf();
      };
      try {
        officer("approve");
        await until(() => observe().disposition === 20);
        caOwnership(20);
        lateLeaf = verifyIssuedLeaf({
          native: invoke("owned-ca-request-certificate.ps1", args),
          authority: owned.authority,
          journal: oldJournal.journal,
          domain: owned.item.domain,
        });
        assert.notEqual(lateLeaf.fingerprint256, successor.fingerprint256);
        assert.notEqual(lateLeaf.serialNumber, successor.serialNumber);
        absentLeaf();
        const scheduler = require("../../../apps/api/services/certops/certificateEnrollments");
        const normal = await scheduler.scheduleDueEnrollments({
          client: fixture.pool,
        });
        assert.equal(
          normal.filter((value) => value.enrollmentId === oldId).length,
          0,
        );
        // Separate supporting eligibility input, never a native or database clock.
        const overdue = await scheduler.scheduleDueEnrollments({
          client: fixture.pool,
          now: new Date(Date.now() + 30 * 86400000),
        });
        assert.equal(
          overdue.filter((value) => value.enrollmentId === oldId).length,
          0,
        );
        const refused = await fixture.request(
          `${api}/enrollments/${oldId}/retry-installation`,
          "POST",
          {},
        );
        assert.equal(refused.status, 400);
        assert.equal(
          refused.body.code,
          "CERTOPS_ENROLLMENT_TRANSITION_INVALID",
        );
        await unchanged();
        assert.equal(
          observe().subjectRequestCount,
          initial.subjectRequestCount,
        );
      } catch (error) {
        primaryError = error;
      } finally {
        try {
          // No serial-based action is authorized by a name alone. Re-read exact
          // CA CSR/requester/template ownership and issued DER before revocation.
          caOwnership(20);
          const leaf = verifyIssuedLeaf({
            native: invoke("owned-ca-request-certificate.ps1", args),
            authority: owned.authority,
            journal: oldJournal.journal,
            domain: owned.item.domain,
          });
          if (lateLeaf)
            assert.ok(
              leaf.raw.equals(lateLeaf.raw),
              "Preserve changed late issuance",
            );
          else lateLeaf = leaf;
          absentLeaf();
          keyAbsent();
          officer("revoke");
          assert.equal(observe().disposition, 21);
          assert.equal(
            observe().subjectRequestCount,
            initial.subjectRequestCount,
          );
        } catch (error) {
          cleanupError = error;
        }
      }
      if (primaryError && cleanupError)
        throw new AggregateError(
          [primaryError, cleanupError],
          "Late approval and owned CA cleanup failed",
        );
      if (primaryError) throw primaryError;
      if (cleanupError) throw cleanupError;
      await unchanged();
      const proof = {
        scope: SCOPE,
        cancelledEnrollmentId: oldId,
        successorEnrollmentId: current.id,
        requestIds: [requestId, String(currentRow.request_id)],
        fingerprints: [sha(lateLeaf.raw), sha(successor.raw)],
        sameCertificateRenewalQualified: false,
        ...Object.fromEntries(FLAGS.map((flag) => [flag, true])),
      };
      verifyProof(proof);
      if (sameCertificateRenewal) {
        const same = {
          ...proof,
          scope: SAME_CERTIFICATE_SCOPE,
          sameCertificateRenewalQualified: true,
          backgroundTimerQualified: false,
          certificateId: terminal.certificate_id,
        };
        verifySameCertificateProof(same);
        gate.report.nativeSameCertificateLateApproval = same;
      } else gate.report.nativeCancelledLateApproval = proof;
      guard.resolved = true;
    },
    {
      evidenceLevel: "real-host",
      oracle:
        "Actual previously cancelled CA request is approved only after a distinct trusted successor installation; terminal public retry and schedulers cannot revive it, no key/leaf acceptance occurs, and exact owned unused issuance is revoked without touching the successor",
    },
  );
}

// The two public qualifiers preserve distinct native lineage contracts; they
// share only read-only custody and guarded late-issuance cleanup oracles.
function verifySameCertificateProof(value) {
  assert.ok(value && typeof value === "object");
  assert.equal(value.scope, SAME_CERTIFICATE_SCOPE);
  assert.equal(value.sameCertificateRenewalQualified, true);
  assert.match(value.certificateId, UUID);
  assert.equal(value.backgroundTimerQualified, false);
  const { certificateId, backgroundTimerQualified, ...old } = value;
  void backgroundTimerQualified;
  void certificateId;
  verifyProof({ ...old, scope: SCOPE, sameCertificateRenewalQualified: false });
  return value;
}
const qualifyCancelledLateApproval = (context) =>
  qualifyLateApproval(context, false);
const qualifySameCertificateLateApproval = (context) =>
  qualifyLateApproval(context, true);

module.exports = {
  SCOPE,
  SAME_CERTIFICATE_SCOPE,
  verifySameCertificateProof,
  qualifySameCertificateLateApproval,
  REQUIRED_SCENARIOS,
  REQUIRED_SOURCES,
  FLAGS,
  verifyProof,
  verifyCaOwnership,
  nativeCustodyScript,
  assertCleanupSafe,
  qualifyCancelledLateApproval,
};
