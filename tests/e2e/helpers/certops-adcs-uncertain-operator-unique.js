"use strict";
/** One real operator-created same-CSR CA candidate after the established owned
 * zero-request interruption. Public acknowledged recovery must automatically
 * install it without an explicit RequestId or a second submission. This tests
 * native recovery, not RPC response-loss timing or fabricated journal state. */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto");
const { pathToFileURL } = require("node:url");
const {
  createAdcsIssuer,
  assertIssuanceOutcome,
  resolveAdcsCmcHelperPath,
  readEnrollmentJournal,
} = require("../../../packages/agent/src/issuers");
const {
  readIssuedContainerRecord,
} = require("../../../packages/agent/src/windows-cert-store");
const REPORT_FIELD = "nativeUncertainOperatorUnique";
const SCOPE =
  "native-operator-single-candidate-acknowledged-automatic-recovery";
const REQUIRED_SCENARIOS = [
  "adcs-real-uncertain-single-owned-candidate-created",
  "adcs-real-uncertain-single-candidate-auto-installs",
  "adcs-real-uncertain-single-candidate-replay-does-not-resubmit",
];
const FLAGS = [
  "ownedObserverDrained",
  "ownedTransportBlock",
  "observedSubmittingTermination",
  "actualLeaseExpiry",
  "acknowledgedPublicRecovery",
  "sameCsrAndKey",
  "noAutomaticResubmit",
  "originalOrphanPreserved",
  "recoveryPolicyUnchanged",
  "nativeCaOwnershipVerified",
  "automaticUniqueAttachmentSucceeded",
  "noExplicitRequestIdProposed",
  "claimBoundVerification",
  "sameProtectedMachineKeyInstalled",
  "unrelatedTrustedTlsPreserved",
];
const REQUIRED_SOURCES = [
  ...new Set([
    ...require("./certops-adcs-uncertain-operator-ambiguity").REQUIRED_SOURCES,
    "tests/e2e/helpers/certops-adcs-uncertain-operator-unique.js",
  ]),
];
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
function verifyProof(p) {
  assert.ok(p && typeof p === "object" && !Array.isArray(p));
  assert.deepEqual(
    Object.keys(p).sort(),
    [
      "scope",
      "resolvedIssuingCaAddress",
      "leaseRemainingAtFaultMs",
      "recoveryWaitBudgetMs",
      "actualLeaseWaitMs",
      "caRequestsAtFault",
      "caRequestsAfterOperatorSubmission",
      "caRequestsAfterRecovery",
      "responseLossTimingQualified",
      "requestId",
      "enrollmentId",
      "containerName",
      "fingerprint",
      "csrSha256",
      "csrSpkiSha256",
      "jobIds",
      ...FLAGS,
    ].sort(),
  );
  assert.equal(p.scope, SCOPE);
  assert.equal(p.responseLossTimingQualified, false);
  for (const flag of FLAGS) assert.equal(p[flag], true, flag);
  assert.equal(p.caRequestsAtFault, 0);
  assert.equal(p.caRequestsAfterOperatorSubmission, 1);
  assert.equal(p.caRequestsAfterRecovery, 1);
  assert.equal(p.resolvedIssuingCaAddress, "10.64.0.4");
  assert.match(p.requestId, /^[1-9][0-9]{0,9}$/);
  assert.ok(Number(p.requestId) <= 0xffffffff);
  assert.match(p.enrollmentId, UUID);
  assert.equal(p.containerName, `tokentimer-enr-${p.enrollmentId}`);
  for (const field of ["fingerprint", "csrSha256", "csrSpkiSha256"])
    assert.match(p[field], /^[a-f0-9]{64}$/);
  assert.ok(
    Array.isArray(p.jobIds) &&
      p.jobIds.length === 2 &&
      new Set(p.jobIds).size === 2,
  );
  for (const id of p.jobIds) assert.match(id, UUID);
  for (const field of [
    "leaseRemainingAtFaultMs",
    "recoveryWaitBudgetMs",
    "actualLeaseWaitMs",
  ])
    assert.ok(
      Number.isInteger(p[field]) && p[field] >= 0 && p[field] <= 900000,
    );
  assert.equal(p.recoveryWaitBudgetMs, p.leaseRemainingAtFaultMs + 90000);
  assert.ok(p.actualLeaseWaitMs + 1000 >= p.leaseRemainingAtFaultMs + 60000);
  assert.ok(p.actualLeaseWaitMs <= p.recoveryWaitBudgetMs + 1000);
  return true;
}
async function runCandidateRecovery({
  context,
  original,
  created,
  domain,
  site,
  port,
  proof,
  keyIdentity,
  keyIdentityBefore,
  leaseMeasurementStart,
  restartService,
}) {
  const {
    gate,
    fixture,
    api,
    configDir,
    workDir,
    run,
    command,
    until,
    tlsAuthority,
    renewalFixture: live,
    ownedThumbprints,
  } = context;
  const id = created.body.enrollmentId,
    root = path.resolve(__dirname, "../../.."),
    query = (sql, args) => fixture.pool.query(sql, args);
  const job = async (jobId) =>
    (
      await query(
        "SELECT status,needs_operator_reconciliation,error_message,claim_id FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",
        [fixture.workspaceId, jobId],
      )
    ).rows[0];
  const enrollment = async () =>
    (
      await query(
        "SELECT state,request_id,operator_request_id FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2",
        [fixture.workspaceId, id],
      )
    ).rows[0];
  const native = (name, args) =>
    JSON.parse(
      command("powershell.exe", [
        "-NoProfile",
        "-NonInteractive",
        "-File",
        path.join(root, "infra/certops-adcs", name + ".ps1"),
        ...args,
      ]),
    );
  assert.ok(live);
  assert.ok(Array.isArray(context.ownedTlsProbes));
  const probes =
    require("./certops-native-issuer-reassignment").createOwnedTlsProbes();
  context.ownedTlsProbes.push(probes);
  const peer = (targetPort, host, ca) =>
    probes.observe(
      {
        host: "127.0.0.1",
        port: targetPort,
        servername: host,
        ca,
        rejectUnauthorized: true,
      },
      (socket) => {
        assert.equal(socket.authorized, true);
        return new crypto.X509Certificate(socket.getPeerCertificate().raw);
      },
    );
  const unrelated = await peer(
    live.port,
    live.item.domain,
    tlsAuthority(live.authority),
  );
  let candidate, actual, recovery, checkpoint;
  await gate.scenario(
    REQUIRED_SCENARIOS[0],
    async () => {
      const floor = original.journal.reconcileSearchFrom;
      assert.ok(Number.isInteger(floor) && floor >= 1);
      assert.equal(original.journal.caConfig, context.caConfig);
      assert.equal(original.journal.template, "TTQualificationRSAShort");
      const before = native("owned-ca-checkpoint", ["-RunId", run]);
      assert.ok(
        before.highestRequestId + 1 < floor + 16,
        "Do not rewrite the genuine frozen native search window",
      );
      const scratch = path.join(workDir, "operator-created-unique");
      fs.mkdirSync(scratch, { mode: 0o700 });
      const caFile = path.join(scratch, "public-ca.cer");
      fs.writeFileSync(
        caFile,
        Buffer.from(live.authority.certificateB64, "base64"),
        { flag: "wx", mode: 0o600 },
      );
      const helper = resolveAdcsCmcHelperPath();
      assert.equal(helper.error, undefined);
      const issuer = createAdcsIssuer({
        caConfig: original.journal.caConfig,
        template: original.journal.template,
        caKeySha256: live.authority.keySha256,
        caCertPath: caFile,
        helperPath: helper.path,
        scratchDir: scratch,
        jobId: `operator-unique-${run}-${crypto.randomUUID()}`,
        enrollmentId: id,
        timeoutMs: 30000,
      });
      const issued = assertIssuanceOutcome(
        await issuer.submit({
          csrPem: original.artifacts.csrPem,
          domains: [domain],
        }),
      );
      assert.equal(issued.outcome, "issued");
      candidate = new crypto.X509Certificate(issued.certificatePem);
      assert.equal(
        candidate.verify(
          new crypto.X509Certificate(
            Buffer.from(live.authority.certificateB64, "base64"),
          ).publicKey,
        ),
        true,
      );
      assert.equal(candidate.checkHost(domain), domain);
      assert.equal(
        crypto
          .createHash("sha256")
          .update(candidate.publicKey.export({ type: "spki", format: "der" }))
          .digest("hex"),
        original.journal.csrSpkiSha256,
      );
      actual = native("owned-issued-request", [
        "-CommonName",
        domain,
        "-FingerprintSha256",
        candidate.fingerprint256.replace(/:/g, "").toLowerCase(),
      ]);
      assert.equal(actual.disposition, 20);
      assert.equal(actual.subjectRequestCount, 1);
      assert.ok(actual.requestId >= floor && actual.requestId < floor + 16);
      checkpoint = native("owned-ca-checkpoint", ["-RunId", run]);
      assert.equal(
        checkpoint.nativeTotalRequestCount,
        before.nativeTotalRequestCount + 1,
      );
      assert.equal(
        checkpoint.nativeRequesterCount,
        before.nativeRequesterCount + 1,
      );
      assert.deepEqual(readEnrollmentJournal(configDir, id), original);
      assert.equal(
        keyIdentity(original.journal.containerName),
        keyIdentityBefore,
      );
      proof.caRequestsAfterOperatorSubmission = 1;
    },
    {
      evidenceLevel: "real-host",
      oracle:
        "one genuine SYSTEM submission of the untouched public CSR creates exactly one CA-owned same-SPKI candidate while the stopped enrollment journal and private key remain unchanged",
    },
  );
  await gate.scenario(
    REQUIRED_SCENARIOS[1],
    async () => {
      const worker = await import(
        pathToFileURL(path.join(root, "apps/worker/src/certops-worker.js")).href
      );
      await until(
        async () => {
          const client = await fixture.pool.connect();
          try {
            await worker.reapExpiredLeases({
              client,
              hardGraceMs: 60000,
              offlineAfterMs: 60000,
              log: { debug() {}, info() {}, warn() {}, error() {} },
            });
          } finally {
            client.release();
          }
          const row = await job(created.body.jobId);
          return (
            row.status === "orphaned_unknown_effect" &&
            row.needs_operator_reconciliation === true
          );
        },
        Math.max(
          1,
          proof.recoveryWaitBudgetMs -
            Math.floor(performance.now() - leaseMeasurementStart),
        ),
      );
      proof.actualLeaseWaitMs = Math.floor(
        performance.now() - leaseMeasurementStart,
      );
      recovery = await fixture.request(
        `${api}/enrollments/${id}/recover`,
        "POST",
        {
          orphanedJobId: created.body.jobId,
          acknowledgeUnknownEffect: true,
          reason:
            "Owned zero-request interruption; one independently observed operator-created same-CSR candidate; verify automatic bounded reconciliation without proposing a RequestId",
        },
      );
      assert.equal(recovery.status, 201);
      restartService();
      await until(async () => {
        const row = await job(recovery.body.jobId);
        assert.ok(
          !["failed", "rejected", "cancelled", "blocked"].includes(row.status),
          row.error_message || "Single native candidate recovery must succeed",
        );
        return row.status === "succeeded";
      });
      const row = await enrollment();
      assert.equal(row.state, "installed");
      assert.equal(String(row.request_id), String(actual.requestId));
      assert.equal(row.operator_request_id, null);
      const final = readEnrollmentJournal(configDir, id);
      assert.equal(final.kind, "valid");
      assert.equal(final.journal.state, "installed");
      for (const field of [
        "containerName",
        "csrSha256",
        "csrSpkiSha256",
        "snapshotSha256",
      ])
        assert.equal(final.journal[field], original.journal[field]);
      assert.equal(final.artifacts.csrPem, original.artifacts.csrPem);
      assert.equal(
        new crypto.X509Certificate(final.artifacts.leafPem).fingerprint256,
        candidate.fingerprint256,
      );
      assert.equal(keyIdentity(final.journal.containerName), keyIdentityBefore);
      const receipt = readIssuedContainerRecord({
        stateDir: configDir,
        containerName: final.journal.containerName,
      });
      assert.equal(receipt.status, "enrolled_by_agent");
      assert.equal(
        receipt.acceptedThumbprint,
        candidate.fingerprint.replace(/:/g, "").toUpperCase(),
      );
      ownedThumbprints.add(receipt.acceptedThumbprint);
      assert.equal(
        (await peer(port, domain, tlsAuthority(live.authority))).fingerprint256,
        candidate.fingerprint256,
      );
      assert.equal(
        (await peer(live.port, live.item.domain, tlsAuthority(live.authority)))
          .fingerprint256,
        unrelated.fingerprint256,
      );
      const evidence = (
        await query(
          "SELECT e.metadata FROM certificate_evidence e JOIN certificate_jobs j ON j.workspace_id=e.workspace_id AND j.id=e.job_id AND e.claim_id=j.claim_id WHERE e.workspace_id=$1 AND e.job_id=$2 AND e.evidence_type='validation.passed' AND e.metadata->>'step'='verify'",
          [fixture.workspaceId, recovery.body.jobId],
        )
      ).rows;
      assert.ok(
        evidence.some(
          (value) =>
            String(value.metadata.fingerprintSha256)
              .replace(/:/g, "")
              .toLowerCase() ===
            candidate.fingerprint256.replace(/:/g, "").toLowerCase(),
        ),
      );
    },
    {
      evidenceLevel: "real-host",
      oracle:
        "real lease/grace and acknowledged public recovery automatically select and install the unique actual CA candidate with the original protected machine key and claim-bound native verification; no RequestId proposal",
    },
  );
  await gate.scenario(
    REQUIRED_SCENARIOS[2],
    async () => {
      const scheduler = require("../../../apps/api/services/certops/certificateEnrollments");
      for (let i = 0; i < 2; i++)
        assert.equal(
          (
            await scheduler.scheduleDueEnrollments({ client: fixture.pool })
          ).filter((row) => row.enrollmentId === id).length,
          0,
        );
      assert.deepEqual(
        native("owned-ca-checkpoint", ["-RunId", run]),
        checkpoint,
      );
      const after = native("owned-issued-request", [
        "-CommonName",
        domain,
        "-FingerprintSha256",
        candidate.fingerprint256.replace(/:/g, "").toLowerCase(),
      ]);
      assert.equal(after.subjectRequestCount, 1);
      assert.equal(String(after.requestId), String(actual.requestId));
      const orphan = await job(created.body.jobId);
      assert.equal(orphan.status, "orphaned_unknown_effect");
      assert.equal(orphan.needs_operator_reconciliation, true);
      assert.equal(
        (
          await query(
            "SELECT 1 FROM audit_events WHERE workspace_id=$1 AND action='CERTOPS_ENROLLMENT_RECONCILE_PROPOSED' AND metadata->>'enrollmentId'=$2",
            [fixture.workspaceId, id],
          )
        ).rowCount,
        0,
      );
      const audits = (
        await query(
          "SELECT actor_user_id,metadata FROM audit_events WHERE workspace_id=$1 AND action='certops.enrollment.recovery_requested' AND metadata->>'enrollmentId'=$2",
          [fixture.workspaceId, id],
        )
      ).rows;
      assert.equal(audits.length, 1);
      assert.equal(audits[0].metadata.acknowledgeUnknownEffect, true);
      assert.equal(String(audits[0].actor_user_id), String(fixture.userId));
      Object.assign(
        proof,
        {
          scope: SCOPE,
          responseLossTimingQualified: false,
          caRequestsAfterRecovery: 1,
          requestId: String(actual.requestId),
          enrollmentId: id,
          containerName: original.journal.containerName,
          fingerprint: candidate.fingerprint256.replace(/:/g, "").toLowerCase(),
          csrSha256: original.journal.csrSha256,
          csrSpkiSha256: original.journal.csrSpkiSha256,
          jobIds: [created.body.jobId, recovery.body.jobId],
        },
        Object.fromEntries(
          FLAGS.filter(
            (flag) =>
              !["ownedObserverDrained", "recoveryPolicyUnchanged"].includes(
                flag,
              ),
          ).map((flag) => [flag, true]),
        ),
      );
    },
    {
      evidenceLevel: "real-host",
      oracle:
        "installed-state default sweeps allocate no request; actual CA count stays one, explicit proposal audit stays empty and the original orphan remains retained",
    },
  );
}
async function qualifyOperatorCreatedUnique(context) {
  await require("./certops-adcs-uncertain-abandon").qualifyUncertainScenario(
    context,
    "operator-created-unique",
  );
}
module.exports = {
  REPORT_FIELD,
  SCOPE,
  FLAGS,
  REQUIRED_SCENARIOS,
  REQUIRED_SOURCES,
  verifyProof,
  runCandidateRecovery,
  qualifyOperatorCreatedUnique,
};
