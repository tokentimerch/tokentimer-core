"use strict";
/** Public RequestId proposal is a candidate, never ownership authority. This
 * source-only disposable-forest actor submits an owned software CSR with the
 * original authorized DNS SAN but a distinct owned CN/SPKI. No foreign private
 * key survives CSR creation. It runs between actual ambiguous recovery and the
 * existing matching-candidate positive installation, without inventing state.
 * Parent cleanup MUST call assertCleanupSafe before deleting native/public state.
 */
const assert = require("node:assert/strict");
const fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto"),
  tls = require("node:tls");
const { isDeepStrictEqual } = require("node:util");
const keys = require("../../../packages/agent/src/keys");
const {
  applyRestrictivePermissions,
} = require("../../../packages/agent/src/platform");
const {
  createAdcsIssuer,
  assertIssuanceOutcome,
  resolveAdcsCmcHelperPath,
  readEnrollmentJournal,
} = require("../../../packages/agent/src/issuers");
const {
  extractSpkiFromCsr,
  readCertificateTemplateOid,
} = require("../../../packages/agent/src/issuers/der-extensions");
const {
  parseDnsSans,
} = require("../../../packages/agent/src/issuers/issued-certificate-validation");
const {
  watermarkPath,
} = require("../../../packages/agent/src/issuers/adcs-enrollment-reconcile");
const {
  readIssuedContainerRecord,
} = require("../../../packages/agent/src/windows-cert-store");
const SCOPE =
  "public-uncertain-request-rejects-owned-same-san-foreign-spki-before-positive-recovery";
const REQUIRED_SCENARIOS = Object.freeze([
  "adcs-real-public-reconcile-foreign-spki-refused",
  "adcs-real-public-reconcile-foreign-spki-positive-recovery",
]);
const FLAGS = Object.freeze([
  "ownedRequestRegisteredBeforeSubmit",
  "softwarePrivateKeyRemovedBeforeSubmit",
  "sameActualCaAndSystemRequester",
  "sameAuthorizedSanAndTemplate",
  "differentOwnedCnAndSpki",
  "actualPublicProposalAccepted",
  "actualSignedSpkiMismatchRefusal",
  "originalUncertainJournalAndWatermarkPreserved",
  "originalCngPossessionPreserved",
  "noForeignCertificateAccepted",
  "servingSiblingTrustedTlsPreserved",
  "noAdditionalCaSubmissionOnRefusal",
  "exactUnusedForeignRequestRevoked",
  "matchingCandidatePositiveRecovery",
  "cleanupOwnershipResolved",
]);
const REQUIRED_SOURCES = Object.freeze([
  "tests/e2e/helpers/certops-adcs-public-foreign-spki.js",
  "tests/e2e/helpers/certops-adcs-uncertain-operator-ambiguity.js",
  "packages/agent/src/keys/index.js",
  "packages/agent/src/platform/index.js",
  "packages/agent/src/issuers/adcs.js",
  "packages/agent/vendor/log-scrub/secret-material.js",
  "packages/agent/src/issuers/adcs-enrollment-reconcile.js",
  "packages/agent/src/issuers/der-extensions.js",
  "packages/agent/src/issuers/issued-certificate-validation.js",
  "packages/agent/src/adcs-windows-iis.js",
  "apps/api/services/certops/certificateEnrollments.js",
  "apps/api/services/certops/enrollmentLifecycle.js",
  "infra/certops-adcs/owned-issued-request.ps1",
  "infra/certops-adcs/owned-request-observation.ps1",
  "infra/certops-adcs/owned-ca-checkpoint.ps1",
  "infra/certops-adcs/officer-action.ps1",
]);
const hex = /^[a-f0-9]{64}$/,
  uuid = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const digest = (value) =>
  crypto.createHash("sha256").update(value).digest("hex");
const registeredReceipts = new WeakSet();
const normalized = (value) => String(value).replace(/:/g, "").toLowerCase();
function verifyProof(value) {
  assert.deepEqual(
    Object.keys(value).sort(),
    [
      "scope",
      "enrollmentId",
      "failedJobId",
      "foreignRequestId",
      "selectedRequestId",
      "foreignFingerprint",
      "selectedFingerprint",
      "foreignSpkiSha256",
      "originalSpkiSha256",
      "foreignCsrSha256",
      "reconcileSearchFrom",
      "foreignSubjectRequestCount",
      "originalSubjectRequestCount",
      ...FLAGS,
    ].sort(),
  );
  assert.equal(value.scope, SCOPE);
  for (const key of ["enrollmentId", "failedJobId"])
    assert.match(value[key], uuid);
  assert.notEqual(value.enrollmentId, value.failedJobId);
  for (const key of ["foreignRequestId", "selectedRequestId"]) {
    assert.match(value[key], /^[1-9][0-9]{0,9}$/);
    assert.ok(Number(value[key]) <= 0xffffffff);
  }
  assert.notEqual(value.foreignRequestId, value.selectedRequestId);
  for (const key of [
    "foreignFingerprint",
    "selectedFingerprint",
    "foreignSpkiSha256",
    "originalSpkiSha256",
    "foreignCsrSha256",
  ])
    assert.match(value[key], hex);
  assert.notEqual(value.foreignFingerprint, value.selectedFingerprint);
  assert.notEqual(value.foreignSpkiSha256, value.originalSpkiSha256);
  assert.ok(
    Number.isSafeInteger(value.reconcileSearchFrom) &&
      value.reconcileSearchFrom >= 1 &&
      value.reconcileSearchFrom <= 0xffffffff,
  );
  assert.ok(Number(value.foreignRequestId) >= value.reconcileSearchFrom);
  assert.equal(value.foreignSubjectRequestCount, 1);
  assert.equal(value.originalSubjectRequestCount, 2);
  for (const flag of FLAGS) assert.equal(value[flag], true);
  return true;
}
function verifyCrossProof(value, positive) {
  verifyProof(value);
  require("./certops-adcs-uncertain-operator-ambiguity").verifyProof(positive);
  assert.equal(value.enrollmentId, positive.enrollmentId);
  assert.equal(value.originalSpkiSha256, positive.csrSpkiSha256);
  assert.equal(value.reconcileSearchFrom, positive.reconcileSearchFrom);
  assert.equal(value.selectedRequestId, positive.selectedRequestId);
  assert.equal(
    value.selectedFingerprint,
    positive.fingerprints[
      positive.requestIds.indexOf(positive.selectedRequestId)
    ],
  );
  assert.ok(!positive.requestIds.includes(value.foreignRequestId));
  assert.ok(!positive.jobIds.includes(value.failedJobId));
  return true;
}
function assertCleanupSafe(receipts) {
  assert.ok(Array.isArray(receipts));
  for (const receipt of receipts) {
    assert.ok(
      registeredReceipts.has(receipt),
      "Unknown foreign-request ownership receipt cannot authorize cleanup",
    );
    assert.equal(
      receipt.resolved,
      true,
      "Preserve public/native ownership until foreign-request refusal, revocation and positive recovery are complete",
    );
  }
}
function identity(file) {
  const stat = fs.lstatSync(file, { bigint: true });
  assert.ok(
    stat.ino > 0n && (stat.isFile() || stat.isDirectory()),
    "Positive stable regular-file/directory identity required",
  );
  assert.ok(!stat.isSymbolicLink());
  assert.equal(
    path.resolve(fs.realpathSync(file)).toLowerCase(),
    path.resolve(file).toLowerCase(),
  );
  return { ino: stat.ino, dev: stat.dev, directory: stat.isDirectory() };
}
function sameIdentity(file, expected) {
  assert.ok(
    isDeepStrictEqual(identity(file), expected),
    "Owned foreign-request file identity changed; preserve state",
  );
}
function createForeignReconcileActor({ ownedForeignRequests }) {
  assert.ok(Array.isArray(ownedForeignRequests));
  let pending;
  return {
    async beforeExplicit(session) {
      assert.equal(pending, undefined);
      assert.equal(process.platform, "win32");
      assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB, "1");
      const {
        context,
        original,
        created,
        domain,
        site,
        port,
        keyIdentity,
        keyIdentityBefore,
      } = session;
      const {
        gate,
        fixture,
        api,
        configDir,
        workDir,
        run,
        command,
        ps,
        until,
        renewalFixture: live,
        tlsAuthority,
      } = context;
      assert.match(run, /^[a-f0-9]{10}$/);
      assert.match(
        domain,
        new RegExp(`^certops-adcs-${run}-[a-z0-9]+\\.example\\.test$`),
      );
      assert.equal(
        ps("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value"),
        "S-1-5-18",
      );
      const id = created.body.enrollmentId;
      assert.match(id, uuid);
      assert.equal(original.journal.containerName, `tokentimer-enr-${id}`);
      assert.equal(original.journal.template, "TTQualificationRSAShort");
      assert.equal(original.journal.caConfig, context.caConfig);
      const root = path.resolve(__dirname, "../../.."),
        query = (sql, values = []) => fixture.pool.query(sql, values);
      const admission = (
        await query(
          "SELECT e.state,e.request_id,e.operator_request_id,j.status,j.claim_id,j.claimed_by_agent_id FROM certificate_enrollments e JOIN certificate_jobs j ON j.workspace_id=e.workspace_id AND j.id=e.current_job_id WHERE e.workspace_id=$1 AND e.id=$2",
          [fixture.workspaceId, id],
        )
      ).rows;
      assert.equal(admission.length, 1);
      assert.equal(admission[0].state, "submission_uncertain");
      assert.equal(admission[0].request_id, null);
      assert.equal(admission[0].operator_request_id, null);
      assert.equal(admission[0].status, "failed");
      assert.match(admission[0].claim_id, uuid);
      assert.equal(admission[0].claimed_by_agent_id, context.agentRowId);
      const active = (
        await query(
          "SELECT id FROM certificate_jobs WHERE workspace_id=$1 AND enrollment_id=$2 AND status IN ('pending','pending_approval','approved','claimed','running')",
          [fixture.workspaceId, id],
        )
      ).rows;
      assert.equal(
        active.length,
        0,
        "Direct foreign CSR submission requires no active signed enrollment work",
      );
      const orphan = (
        await query(
          "SELECT status,needs_operator_reconciliation FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",
          [fixture.workspaceId, created.body.jobId],
        )
      ).rows[0];
      assert.equal(orphan.status, "orphaned_unknown_effect");
      assert.equal(orphan.needs_operator_reconciliation, true);
      for (const observer of context.ownedPhaseObservers)
        await observer.stopAndDrain();
      assert.equal(
        context.ownedPhaseObservers.some((observer) => observer.hasLiveChild()),
        false,
        "Original owned native observer must already be drained",
      );
      gate.report.fixtureSources ??= [];
      for (const file of REQUIRED_SOURCES) {
        const sha256 = digest(fs.readFileSync(path.join(root, file))),
          prior = gate.report.fixtureSources.filter(
            (value) => value.file === file,
          );
        if (prior.length) {
          assert.equal(prior.length, 1);
          assert.equal(prior[0].sha256, sha256);
        } else gate.report.fixtureSources.push({ file, sha256 });
      }
      const native = (name, args) =>
        JSON.parse(
          command("powershell.exe", [
            "-NoProfile",
            "-NonInteractive",
            "-File",
            path.join(root, `infra/certops-adcs/${name}.ps1`),
            ...args,
          ]),
        );
      const checkpoint = () => native("owned-ca-checkpoint", ["-RunId", run]);
      const foreignCn = `certops-adcs-${run}-foreignspki.example.test`,
        owner = { enrollmentId: id, foreignCn, resolved: false };
      // Parent registration precedes key generation, file creation and CA work.
      registeredReceipts.add(owner);
      ownedForeignRequests.push(owner);
      const parentId = identity(workDir),
        directory = fs.mkdtempSync(path.join(workDir, "public-foreign-spki-"));
      applyRestrictivePermissions(directory);
      const directoryId = identity(directory),
        guard = path.join(directory, "ownership.json");
      const guardBytes = Buffer.from(
        JSON.stringify({
          kind: "owned-public-foreign-spki",
          run,
          enrollmentId: id,
          foreignCn,
          authorizedDnsName: domain,
          originalCsrSha256: original.journal.csrSha256,
        }) + "\n",
      );
      fs.writeFileSync(guard, guardBytes, { flag: "wx" });
      applyRestrictivePermissions(guard);
      const guardId = identity(guard);
      owner.directory = directory;
      const checkDirectory = () => {
        sameIdentity(workDir, parentId);
        sameIdentity(directory, directoryId);
      };
      const keyPath = path.join(directory, "temporary-software.key");
      keys.generateKeyPairToFile({ keyPath, algorithm: "rsa-2048" });
      const privateId = identity(keyPath),
        privateHash = digest(fs.readFileSync(keyPath));
      const csr = keys.generateCsr({
        keyPath,
        subject: { commonName: foreignCn },
        altNames: [domain],
      });
      const foreignSpki = digest(extractSpkiFromCsr(csr.csrPem));
      assert.notEqual(foreignSpki, original.journal.csrSpkiSha256);
      checkDirectory();
      sameIdentity(keyPath, privateId);
      assert.ok(
        digest(fs.readFileSync(keyPath)) === privateHash,
        "Owned temporary software key changed",
      );
      fs.unlinkSync(keyPath);
      assert.equal(fs.existsSync(keyPath), false);
      const caPath = path.join(directory, "public-ca.cer");
      fs.writeFileSync(
        caPath,
        Buffer.from(live.authority.certificateB64, "base64"),
        { flag: "wx" },
      );
      const helper = resolveAdcsCmcHelperPath();
      assert.equal(helper.error, undefined);
      const issuer = createAdcsIssuer({
        caConfig: original.journal.caConfig,
        template: original.journal.template,
        caKeySha256: live.authority.keySha256,
        caCertPath: caPath,
        helperPath: helper.path,
        scratchDir: directory,
        jobId: `foreign-spki-${run}-${crypto.randomUUID()}`,
        enrollmentId: id,
        timeoutMs: 30000,
      });
      const before = checkpoint();
      const absence = native("owned-request-observation", [
        "-CommonName",
        foreignCn,
        "-Discover",
      ]);
      assert.equal(absence.subjectRequestCount, 0);
      const issued = assertIssuanceOutcome(
        await issuer.submit({ csrPem: csr.csrPem, domains: [domain] }),
      );
      assert.equal(issued.outcome, "issued");
      const leaf = new crypto.X509Certificate(issued.certificatePem),
        foreignFingerprint = normalized(leaf.fingerprint256);
      assert.equal(leaf.subject, `CN=${foreignCn}`);
      assert.equal(
        leaf.verify(
          new crypto.X509Certificate(
            Buffer.from(live.authority.certificateB64, "base64"),
          ).publicKey,
        ),
        true,
      );
      assert.ok(isDeepStrictEqual(parseDnsSans(leaf.subjectAltName), [domain]));
      assert.equal(leaf.checkHost(domain), domain);
      assert.equal(
        readCertificateTemplateOid(leaf.raw),
        original.journal.templateOid,
      );
      assert.equal(
        digest(leaf.publicKey.export({ format: "der", type: "spki" })),
        foreignSpki,
      );
      const actual = native("owned-issued-request", [
        "-CommonName",
        foreignCn,
        "-FingerprintSha256",
        foreignFingerprint,
      ]);
      assert.equal(actual.disposition, 20);
      assert.equal(actual.subjectRequestCount, 1);
      const foreignRequestId = String(actual.requestId);
      assert.match(foreignRequestId, /^[1-9][0-9]{0,9}$/);
      assert.ok(
        Number(foreignRequestId) >= original.journal.reconcileSearchFrom,
      );
      owner.requestId = foreignRequestId;
      const afterSubmit = checkpoint();
      assert.equal(
        afterSubmit.nativeTotalRequestCount,
        before.nativeTotalRequestCount + 1,
      );
      assert.equal(
        afterSubmit.nativeRequesterCount,
        before.nativeRequesterCount + 1,
      );
      const watermark = watermarkPath(configDir, original.journal.caConfig),
        watermarkBefore = fs.existsSync(watermark)
          ? fs.readFileSync(watermark)
          : null;
      const peer = () =>
        new Promise((resolve, reject) => {
          const socket = tls.connect(
            {
              host: "127.0.0.1",
              port: live.port,
              servername: live.item.domain,
              ca: tlsAuthority(live.authority),
              rejectUnauthorized: true,
            },
            () => {
              try {
                assert.equal(socket.authorized, true);
                resolve(normalized(socket.getPeerCertificate().fingerprint256));
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
              new Error("Foreign candidate predecessor TLS deadline exceeded"),
            ),
          );
        });
      const predecessor = await peer();
      assert.equal(predecessor, normalized(live.observed.fingerprint256));
      const proveOriginalSignature = () => {
        const challenge = crypto.randomBytes(32),
          signature = ps(
            `$k=[Security.Cryptography.CngKey]::Open('${original.journal.containerName}',[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider,[Security.Cryptography.CngKeyOpenOptions]::MachineKey);$rsa=$null;try{$rsa=[Security.Cryptography.RSACng]::new($k);if(!$k.IsMachineKey-or[int]$k.ExportPolicy-ne 0-or$rsa.KeySize-ne 2048){throw 'Original protected machine RSA required'};[Convert]::ToBase64String($rsa.SignData([Convert]::FromBase64String('${challenge.toString("base64")}'),[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1))}finally{if($rsa){$rsa.Dispose()};$k.Dispose()}`,
          );
        assert.equal(
          crypto.verify(
            "sha256",
            challenge,
            crypto.createPublicKey({
              key: extractSpkiFromCsr(original.artifacts.csrPem),
              format: "der",
              type: "spki",
            }),
            Buffer.from(signature, "base64"),
          ),
          true,
        );
      };
      const preserve = async () => {
        const current = readEnrollmentJournal(configDir, id);
        assert.equal(current.kind, "valid");
        assert.equal(current.journal.state, "submission_uncertain");
        for (const field of [
          "containerName",
          "csrSha256",
          "csrSpkiSha256",
          "snapshotSha256",
          "reconcileSearchFrom",
        ])
          assert.equal(current.journal[field], original.journal[field]);
        assert.ok(
          current.artifacts.csrPem === original.artifacts.csrPem,
          "Original public CSR changed",
        );
        assert.equal(current.artifacts.leafPem, null);
        assert.ok(
          keyIdentity(current.journal.containerName) === keyIdentityBefore,
          "Original protected native key identity changed",
        );
        const record = readIssuedContainerRecord({
          stateDir: configDir,
          containerName: current.journal.containerName,
        });
        assert.equal(record?.status, "generated");
        assert.equal(record.acceptedThumbprint, null);
        if (watermarkBefore)
          assert.ok(
            fs.readFileSync(watermark).equals(watermarkBefore),
            "Original watermark changed",
          );
        else assert.equal(fs.existsSync(watermark), false);
        const binding =
          await require("../../../packages/agent/src/windows-iis").queryCurrentBinding(
            { binding: { site, port, sniHost: domain } },
          );
        assert.equal(binding.ok, true);
        assert.equal(binding.thumbprint, null);
        assert.equal(await peer(), predecessor);
      };
      const noForeignAccepted = () =>
        assert.equal(
          ps(
            `$count=0;$matches=0;Get-ChildItem Cert:\\LocalMachine -Recurse -ErrorAction Stop|ForEach-Object{if($_ -is [Security.Cryptography.X509Certificates.X509Certificate2]){if(++$count-gt 100000){throw 'Complete store inventory bound exceeded'};if($_.Thumbprint-eq'${normalized(leaf.fingerprint).toUpperCase()}'){$matches++}}};$matches`,
          ),
          "0",
          "Unused foreign leaf must be absent from every machine store",
        );
      let failedJobId;
      await gate.scenario(
        REQUIRED_SCENARIOS[0],
        async () => {
          await preserve();
          proveOriginalSignature();
          noForeignAccepted();
          assert.equal(
            (
              await fixture.request(
                `${api}/enrollments/${id}/reconcile`,
                "POST",
                { requestId: Number(foreignRequestId) },
              )
            ).status,
            204,
          );
          const proposal = (
            await query(
              "SELECT state,operator_request_id,request_id FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2",
              [fixture.workspaceId, id],
            )
          ).rows[0];
          assert.equal(proposal.state, "submission_uncertain");
          assert.equal(String(proposal.operator_request_id), foreignRequestId);
          assert.equal(proposal.request_id, null);
          const scheduled = (
            await require("../../../apps/api/services/certops/certificateEnrollments").scheduleDueEnrollments(
              { client: fixture.pool },
            )
          ).filter((value) => value.enrollmentId === id);
          assert.equal(scheduled.length, 1);
          failedJobId = scheduled[0].jobId;
          assert.match(failedJobId, uuid);
          owner.failedJobId = failedJobId;
          const failed = await until(async () => {
            const value = (
              await query(
                "SELECT j.status,j.error_message,j.claim_id,j.claimed_by_agent_id,j.result_metadata,e.state,e.request_id FROM certificate_jobs j JOIN certificate_enrollments e ON e.workspace_id=j.workspace_id AND e.current_job_id=j.id WHERE j.workspace_id=$1 AND j.id=$2",
                [fixture.workspaceId, failedJobId],
              )
            ).rows[0];
            if (value?.status === "succeeded")
              throw new Error("Foreign SPKI candidate was installed");
            return value?.status === "failed" &&
              value.state === "submission_uncertain"
              ? value
              : null;
          });
          assert.equal(
            failed.result_metadata.enrollmentResult.errorCode,
            "ADCS_DISPOSITION_UNKNOWN",
          );
          assert.match(
            failed.error_message,
            /Proposed RequestId certificate SPKI does not match this enrollment/,
          );
          assert.match(failed.claim_id, uuid);
          assert.equal(failed.claimed_by_agent_id, context.agentRowId);
          assert.equal(failed.request_id, null);
          await preserve();
          proveOriginalSignature();
          noForeignAccepted();
          assert.ok(
            isDeepStrictEqual(checkpoint(), afterSubmit),
            "Signed candidate refusal must not allocate another CA request",
          );
          const again = native("owned-issued-request", [
            "-CommonName",
            foreignCn,
            "-FingerprintSha256",
            foreignFingerprint,
          ]);
          assert.equal(String(again.requestId), foreignRequestId);
          assert.equal(again.disposition, 20);
          assert.equal(again.subjectRequestCount, 1);
          noForeignAccepted();
          assert.equal(
            command("powershell.exe", [
              "-NoProfile",
              "-NonInteractive",
              "-File",
              path.join(root, "infra/certops-adcs/officer-action.ps1"),
              "-CommonName",
              foreignCn,
              "-RequestId",
              foreignRequestId,
              "-Action",
              "revoke",
            ]),
            "CERTOPS_OFFICER=revoke",
          );
          const revoked = native("owned-request-observation", [
            "-CommonName",
            foreignCn,
            "-RequestId",
            foreignRequestId,
          ]);
          assert.equal(revoked.disposition, 21);
          assert.equal(revoked.subjectRequestCount, 1);
          await preserve();
        },
        {
          evidenceLevel: "real-host",
          oracle:
            "Actual public proposal of owned same-SAN/template/CA but foreign-SPKI RequestId reaches signed native refusal, preserves original uncertain custody/IIS/TLS and allocates no request; exact unused public leaf is safely revoked",
        },
      );
      pending = {
        context,
        owner,
        directory,
        guard,
        guardBytes,
        guardId,
        directoryId,
        parentId,
        id,
        failedJobId,
        foreignRequestId,
        foreignFingerprint,
        foreignSpki,
        foreignCsrSha256: digest(csr.csrPem),
        originalSpki: original.journal.csrSpkiSha256,
        floor: original.journal.reconcileSearchFrom,
      };
      return { additionalProposalCount: 1, failedJobId, foreignRequestId };
    },
    async observeNativeCompletion(positive) {
      assert.ok(pending);
      const {
        context,
        owner,
        directory,
        guard,
        guardBytes,
        guardId,
        directoryId,
        parentId,
      } = pending;
      await context.gate.scenario(
        REQUIRED_SCENARIOS[1],
        () => {
          const value = {
            scope: SCOPE,
            enrollmentId: pending.id,
            failedJobId: pending.failedJobId,
            foreignRequestId: pending.foreignRequestId,
            selectedRequestId: positive.selectedRequestId,
            foreignFingerprint: pending.foreignFingerprint,
            selectedFingerprint:
              positive.fingerprints[
                positive.requestIds.indexOf(positive.selectedRequestId)
              ],
            foreignSpkiSha256: pending.foreignSpki,
            originalSpkiSha256: pending.originalSpki,
            foreignCsrSha256: pending.foreignCsrSha256,
            reconcileSearchFrom: pending.floor,
            foreignSubjectRequestCount: 1,
            originalSubjectRequestCount: 2,
            ...Object.fromEntries(FLAGS.map((flag) => [flag, true])),
          };
          verifyCrossProof(value, positive);
          sameIdentity(context.workDir, parentId);
          sameIdentity(directory, directoryId);
          sameIdentity(guard, guardId);
          assert.ok(
            fs.readFileSync(guard).equals(guardBytes),
            "Owned foreign-request receipt changed; preserve state",
          );
          fs.unlinkSync(guard);
          owner.resolved = true;
          context.gate.report.nativePublicForeignSpki = value;
        },
        {
          evidenceLevel: "real-host",
          oracle:
            "Existing full real operator ambiguity recovery installs matching original CSR/key after foreign candidate refusal; original two-issuance counts and cleanup ownership remain independently bound",
        },
      );
    },
  };
}
module.exports = {
  SCOPE,
  FLAGS,
  REQUIRED_SCENARIOS,
  REQUIRED_SOURCES,
  verifyProof,
  verifyCrossProof,
  assertCleanupSafe,
  createForeignReconcileActor,
};
