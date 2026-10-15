"use strict";
/** Real public cancellation followed by a new enrollment of the SAME managed
 * certificate. The old pending request is approved only after the new leaf is
 * actually installed. No CA response, enrollment state or journal is invented.
 * An unresolved owner is registered before the first admission and prevents
 * parent native/DB cleanup until every late-issuance oracle completes.
 */
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const tls = require("node:tls");
const { isDeepStrictEqual } = require("node:util");
const late = require("./certops-adcs-cancelled-late-approval");
const {
  applyRestrictivePermissions,
} = require("../../../packages/agent/src/platform");
const journal = require("../../../packages/agent/src/issuers/adcs-enrollment");
const {
  buildEnrollmentContainerName,
} = require("../../../packages/agent/src/windows-cert-store");
const scheduler = require("../../../apps/api/services/certops/certificateEnrollments");
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const PREPARE_SCENARIO = "adcs-real-same-certificate-cancel-then-renew";
const REQUIRED_SCENARIOS = Object.freeze([
  PREPARE_SCENARIO,
  "adcs-real-same-certificate-cancelled-late-approval-preserves-renewal",
]);
const REQUIRED_SOURCES = Object.freeze([
  ...new Set([
    "tests/e2e/helpers/certops-adcs-same-certificate-late-approval.js",
    ...late.REQUIRED_SOURCES,
    "packages/agent/src/platform/index.js",
  ]),
]);
const GUARD = ".preserve-same-certificate-late-approval.json";
const active = new Set();
const owner = (workDir) => path.resolve(workDir).toLowerCase();
function verifyLineage(old, current, certificateId) {
  assert.match(certificateId, UUID);
  for (const row of [old, current]) {
    assert.match(row.id, UUID);
    assert.equal(row.certificate_id, certificateId);
    assert.match(String(row.request_id), /^[1-9][0-9]{0,9}$/);
    assert.ok(Number(row.request_id) <= 0xffffffff);
  }
  assert.notEqual(old.id, current.id);
  assert.notEqual(String(old.request_id), String(current.request_id));
  assert.equal(old.state, "cancelled");
  assert.equal(current.state, "installed");
  return true;
}
function assertCleanupSafe(workDir) {
  assert.ok(
    !active.has(owner(workDir)) && !fs.existsSync(path.join(workDir, GUARD)),
    "Preserve unknown same-certificate renewal and late-approval ownership",
  );
}
async function qualifySameCertificateLateApproval(context) {
  const {
    gate,
    fixture,
    api,
    agentRowId,
    configDir,
    workDir,
    pendingRecoveryFixtures,
    ownedEnrollmentIds,
    ownedCertificateIds,
    ownedThumbprints,
    ps,
    command,
    until,
    jobFinished,
    tlsAuthority,
  } = context;
  assert.equal(process.platform, "win32");
  assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB, "1");
  assertCleanupSafe(workDir);
  const parentIdentity = fs.lstatSync(workDir, { bigint: true });
  assert.ok(
    parentIdentity.isDirectory() &&
      !parentIdentity.isSymbolicLink() &&
      parentIdentity.ino > 0n,
  );
  assert.equal(
    fs.realpathSync(workDir).toLowerCase(),
    path.resolve(workDir).toLowerCase(),
  );
  const original = pendingRecoveryFixtures.cancel;
  assert.ok(original);
  assert.match(
    original.item.domain,
    /^certops-adcs-[a-f0-9]{10}-cancel\.example\.test$/,
  );
  const query = (sql, args) => fixture.pool.query(sql, args);
  const row = async (id) =>
    (
      await query(
        "SELECT id,state,request_id,current_job_id,certificate_id,next_poll_at FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2",
        [fixture.workspaceId, id],
      )
    ).rows[0];
  const previousId =
    gate.report.nativeCancelledLateApproval?.successorEnrollmentId;
  assert.match(previousId, UUID);
  assert.ok(ownedEnrollmentIds.includes(previousId));
  const previous = await row(previousId);
  assert.equal(previous.state, "installed");

  const peer = () =>
    new Promise((resolve, reject) => {
      const socket = tls.connect(
        {
          host: "127.0.0.1",
          port: original.port,
          servername: original.item.domain,
          ca: tlsAuthority(original.authority),
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
          new Error("Owned same-certificate TLS observation timed out"),
        ),
      );
    });
  const baseline = await peer();
  const fingerprint = crypto
    .createHash("sha256")
    .update(baseline.raw)
    .digest("hex");
  const discovered = await until(async () => {
    const rows = (
      await query(
        "SELECT DISTINCT mc.id FROM managed_certificates mc JOIN certificate_instances ci ON ci.workspace_id=mc.workspace_id AND ci.managed_certificate_id=mc.id JOIN certificate_targets ct ON ct.workspace_id=ci.workspace_id AND ct.id=ci.target_id WHERE mc.workspace_id=$1 AND ci.observed_fingerprint_sha256=$2 AND ct.windows_site=$3 AND mc.source='agent_windows'",
        [fixture.workspaceId, fingerprint, original.site],
      )
    ).rows;
    assert.ok(
      rows.length <= 1,
      "Owned native certificate inventory identity must be unique",
    );
    return rows[0] || null;
  });
  const certificateId = discovered.id;
  assert.match(certificateId, UUID);
  assert.ok(Array.isArray(ownedCertificateIds));
  if (!ownedCertificateIds.includes(certificateId))
    ownedCertificateIds.push(certificateId);
  const inventory = async () =>
    (
      await query(
        "SELECT id,profile_id,fingerprint_sha256,not_after FROM managed_certificates WHERE workspace_id=$1 AND id=$2",
        [fixture.workspaceId, certificateId],
      )
    ).rows[0];
  const baselineJournal = journal.readEnrollmentJournal(configDir, previousId);
  assert.equal(baselineJournal.kind, "valid");
  assert.equal(baselineJournal.journal.state, "installed");
  assert.equal(
    new crypto.X509Certificate(baselineJournal.artifacts.leafPem)
      .fingerprint256,
    baseline.fingerprint256,
  );
  const root = path.resolve(__dirname, "../../..");
  gate.report.fixtureSources ||= [];
  for (const file of REQUIRED_SOURCES) {
    const sha256 = crypto
      .createHash("sha256")
      .update(fs.readFileSync(path.join(root, file)))
      .digest("hex");
    const rows = gate.report.fixtureSources.filter(
      (value) => value.file === file,
    );
    if (rows.length) {
      assert.equal(rows.length, 1);
      assert.equal(rows[0].sha256, sha256);
    } else gate.report.fixtureSources.push({ file, sha256 });
  }
  const guard = path.join(workDir, GUARD),
    nonce = crypto.randomBytes(32).toString("hex");
  active.add(owner(workDir));
  fs.writeFileSync(guard, nonce, { flag: "wx", mode: 0o600 });
  applyRestrictivePermissions(guard, { kind: "file" });
  const guardStat = fs.lstatSync(guard, { bigint: true });
  assert.ok(
    guardStat.isFile() && !guardStat.isSymbolicLink() && guardStat.ino > 0n,
  );
  const admissions = [];
  const request = async () => {
    const response = await fixture.request(`${api}/enrollments`, "POST", {
      issuerId: original.issuerId,
      certificateId,
      agentId: agentRowId,
      target: {
        type: "windows-iis",
        reference: original.item.domain,
        store: "My",
        binding: {
          site: original.site,
          port: original.port,
          sniHost: original.item.domain,
        },
      },
      authorizedDnsNames: [original.item.domain],
      keyAlgorithm: "rsa",
      keySize: 2048,
    });
    assert.equal(response.status, 201);
    assert.match(response.body.enrollmentId, UUID);
    assert.match(response.body.jobId, UUID);
    // Register actual admission immediately, before waiting for any native result.
    ownedEnrollmentIds.push(response.body.enrollmentId);
    admissions.push(response.body.enrollmentId);
    return response.body;
  };
  const pending = (id) =>
    until(async () => {
      const current = await row(id);
      assert.ok(
        !["denied", "refused", "failed", "expired", "cancelled"].includes(
          current?.state,
        ),
      );
      return current?.state === "pending_issuance" && current.request_id
        ? current
        : null;
    });
  const awaiting = async (admitted) => {
    await jobFinished(admitted.jobId);
    const actual = (
      await query(
        "SELECT id,status,claim_id,enrollment_id FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",
        [fixture.workspaceId, admitted.jobId],
      )
    ).rows[0];
    assert.equal(actual?.status, "awaiting_issuer");
    assert.equal(actual.enrollment_id, admitted.enrollmentId);
    assert.match(actual.claim_id, UUID);
  };
  let cancelled, successor, oldPending, cleanup;
  await gate.scenario(
    PREPARE_SCENARIO,
    async () => {
      cancelled = await request();
      oldPending = await pending(cancelled.enrollmentId);
      await awaiting(cancelled);
      assert.equal(oldPending.certificate_id, certificateId);
      assert.equal((await peer()).fingerprint256, baseline.fingerprint256);
      assert.equal(
        (
          await fixture.request(
            `${api}/enrollments/${cancelled.enrollmentId}/cancel`,
            "POST",
            {},
          )
        ).status,
        204,
      );
      cleanup = (
        await scheduler.scheduleDueEnrollments({ client: fixture.pool })
      ).find((value) => value.enrollmentId === cancelled.enrollmentId);
      assert.ok(
        cleanup,
        "Actual default-clock cancellation cleanup must dispatch",
      );
      await jobFinished(cleanup.jobId);
      const old = await row(cancelled.enrollmentId);
      assert.equal(old.state, "cancelled");
      assert.equal(old.next_poll_at, null);
      const container = buildEnrollmentContainerName(cancelled.enrollmentId);
      assert.equal(
        ps(
          `[Security.Cryptography.CngKey]::Exists('${container}',[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider,[Security.Cryptography.CngKeyOpenOptions]::MachineKey)`,
        ),
        "False",
      );
      assert.equal((await peer()).fingerprint256, baseline.fingerprint256);
      successor = await request();
      const successorPending = await pending(successor.enrollmentId);
      await awaiting(successor);
      assert.notEqual(
        String(successorPending.request_id),
        String(oldPending.request_id),
      );
      command("powershell.exe", [
        "-NoProfile",
        "-NonInteractive",
        "-File",
        path.join(root, "infra/certops-adcs/officer-action.ps1"),
        "-RequestId",
        String(successorPending.request_id),
        "-Action",
        "approve",
        "-CommonName",
        original.item.domain,
      ]);
      // Eligibility selection is explicit here; this does not qualify a timer.
      const continued = (
        await scheduler.scheduleDueEnrollments({
          client: fixture.pool,
          now: new Date(
            new Date(successorPending.next_poll_at).getTime() + 1000,
          ),
        })
      ).find((value) => value.enrollmentId === successor.enrollmentId);
      assert.ok(continued);
      await jobFinished(continued.jobId);
      const installed = await row(successor.enrollmentId);
      verifyLineage(old, installed, certificateId);
      const leaf = await peer();
      assert.notEqual(leaf.fingerprint256, baseline.fingerprint256);
      const durable = journal.readEnrollmentJournal(
        configDir,
        successor.enrollmentId,
      );
      assert.equal(durable.kind, "valid");
      assert.equal(durable.journal.state, "installed");
      assert.equal(
        new crypto.X509Certificate(durable.artifacts.leafPem).fingerprint256,
        leaf.fingerprint256,
      );
      assert.equal(
        String(durable.journal.requestId),
        String(installed.request_id),
      );
      ownedThumbprints.add(leaf.fingerprint.replace(/:/g, ""));
      assert.deepEqual(admissions, [
        cancelled.enrollmentId,
        successor.enrollmentId,
      ]);
    },
    {
      evidenceLevel: "real-host",
      oracle:
        "real public cancel/cleanup and actual officer-approved renewal of the same persisted certificate, distinct RequestIds/keys and trusted native successor",
    },
  );
  const installedLeaf = await peer();
  const expectedFingerprint = crypto
    .createHash("sha256")
    .update(installedLeaf.raw)
    .digest("hex");
  const inventoryBefore = await until(async () => {
    const value = await inventory();
    return String(value?.fingerprint_sha256 || "")
      .replace(/:/g, "")
      .toLowerCase() === expectedFingerprint
      ? value
      : null;
  });
  // Reuse the complete independent native requester/CSR/SPKI, claim/evidence,
  // IIS/HTTP.sys/TLS, terminal-scheduler and unused-leaf revocation oracles.
  await late.qualifySameCertificateLateApproval({
    ...context,
    pendingRecoveryFixtures: {
      cancel: {
        ...original,
        created: cancelled,
        pending: oldPending,
        continuation: cleanup,
      },
    },
  });
  const proof = gate.report.nativeSameCertificateLateApproval;
  late.verifySameCertificateProof(proof);
  assert.equal(proof.certificateId, certificateId);
  assert.ok(
    isDeepStrictEqual(await inventory(), inventoryBefore),
    "Same managed certificate inventory changed after cancelled late issuance",
  );
  assert.equal(proof.cancelledEnrollmentId, cancelled.enrollmentId);
  assert.equal(proof.successorEnrollmentId, successor.enrollmentId);
  const currentParent = fs.lstatSync(workDir, { bigint: true });
  assert.ok(
    currentParent.isDirectory() &&
      !currentParent.isSymbolicLink() &&
      currentParent.dev === parentIdentity.dev &&
      currentParent.ino === parentIdentity.ino,
  );
  const after = fs.lstatSync(guard, { bigint: true });
  assert.ok(
    after.isFile() &&
      !after.isSymbolicLink() &&
      after.dev === guardStat.dev &&
      after.ino === guardStat.ino,
  );
  const fd = fs.openSync(
    guard,
    fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0),
  );
  try {
    const opened = fs.fstatSync(fd, { bigint: true });
    assert.ok(
      opened.isFile() &&
        opened.dev === guardStat.dev &&
        opened.ino === guardStat.ino &&
        opened.size === 64n,
    );
    const bytes = Buffer.alloc(65);
    const length = fs.readSync(fd, bytes, 0, bytes.length, null);
    const end = fs.fstatSync(fd, { bigint: true });
    assert.ok(
      length === 64 && end.size === 64n && end.mtimeNs === opened.mtimeNs,
    );
    assert.ok(
      bytes.subarray(0, length).toString("utf8") === nonce,
      "Owned same-certificate guard bytes changed",
    );
    const current = fs.lstatSync(guard, { bigint: true });
    assert.ok(
      current.isFile() &&
        !current.isSymbolicLink() &&
        current.dev === opened.dev &&
        current.ino === opened.ino,
    );
  } finally {
    fs.closeSync(fd);
  }
  fs.unlinkSync(guard);
  active.delete(owner(workDir));
  return proof;
}
module.exports = {
  REQUIRED_SCENARIOS,
  REQUIRED_SOURCES,
  GUARD,
  verifyLineage,
  assertCleanupSafe,
  qualifySameCertificateLateApproval,
};
