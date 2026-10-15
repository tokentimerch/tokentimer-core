"use strict";
/** Mandatory native source; actual protected host execution remains pending.
 * Real public renewal
 * setup for a previously configured, genuinely owned agent-local certificate.
 * No imported/unknown private-key adoption or unattended-worker claim. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const tls = require("node:tls");
const { pathToFileURL } = require("node:url");
const { isDeepStrictEqual } = require("node:util");
const profileContract = require("../../../apps/api/services/certops/renewalProfile");
const bulk = require("./certops-acme-bulk-renewal");
const SCOPE = "native-agent-local-public-renewal-re-setup";
const SCENARIO = "real-acme-public-native-renewal-setup";
const FLAGS = Object.freeze([
  "actualManualManagementReadd",
  "actualSignedDryRun",
  "dryRunCustodyUnchanged",
  "dryRunCreatesNoIntent",
  "actualPublicRealSetup",
  "actualCurrentClaims",
  "actualNewCaLeafAndKey",
  "trustedTlsReplacement",
  "claimBoundVerification",
  "actualDefaultOutboxDrain",
  "exactIntentConfigured",
  "publicSetupConfigured",
  "executionPolicyPreserved",
  "ownedManagementStopped",
  "originalServingUnchanged",
  "retainedTlsDrained",
  "ownershipGuardReleased",
]);
const REQUIRED_SOURCES = Object.freeze([
  ...new Set([
    ...bulk.REQUIRED_SOURCES,
    ...require("./certops-acme-background-renewals").REQUIRED_SOURCES,
    "tests/e2e/helpers/certops-acme-native-adoption.js",
    "apps/api/services/certops/renewalAdoption.js",
    "apps/api/services/certops/outbox.js",
    "apps/api/services/certops/inventory.js",
    "apps/api/services/certops/workspaceKillSwitch.js",
    "apps/api/services/certops/agentObservations.js",
    "apps/api/services/certops/renewalProfileDerivation.js",
    "apps/api/services/certops/certificateIdentity.js",
  ]),
]);
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i;
const SHA = /^[a-f0-9]{64}$/;
const GUARD = ".native-renewal-adoption-active.json";
const active = new Set();
const sha = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
function verifyProof(value) {
  assert.deepEqual(
    Object.keys(value).sort(),
    [
      "scope",
      "certificateId",
      "profileId",
      "jobIds",
      "claimIds",
      "fingerprints",
      "spkiFingerprints",
      ...FLAGS,
    ].sort(),
  );
  assert.equal(value.scope, SCOPE);
  for (const key of ["certificateId", "profileId"])
    assert.match(value[key], UUID);
  for (const key of [
    "jobIds",
    "claimIds",
    "fingerprints",
    "spkiFingerprints",
  ]) {
    assert.ok(Array.isArray(value[key]) && value[key].length === 2);
    for (const item of value[key])
      assert.match(item, key.endsWith("Ids") ? UUID : SHA);
    assert.equal(new Set(value[key].map((item) => item.toLowerCase())).size, 2);
  }
  for (const flag of FLAGS) assert.equal(value[flag], true);
  return true;
}
function verifyAgainstBulk(value, previous) {
  verifyProof(value);
  bulk.verifyProof(previous);
  assert.equal(value.certificateId, previous.certificateIds[0]);
  assert.equal(value.fingerprints[0], previous.fingerprints[2]);
  assert.equal(value.spkiFingerprints[0], previous.spkiFingerprints[2]);
  assert.equal(
    new Set(
      [...value.jobIds, ...previous.issueJobIds, ...previous.jobIds].map((id) =>
        id.toLowerCase(),
      ),
    ).size,
    6,
  );
  assert.equal(
    new Set(
      [...value.claimIds, ...previous.claimIds].map((id) => id.toLowerCase()),
    ).size,
    4,
  );
  assert.ok(!previous.fingerprints.includes(value.fingerprints[1]));
  assert.ok(!previous.spkiFingerprints.includes(value.spkiFingerprints[1]));
  assert.notEqual(value.fingerprints[1], previous.originalServingFingerprint);
  assert.notEqual(value.spkiFingerprints[1], previous.originalServingSpki);
}
function assertCleanupSafe(root) {
  assert.ok(
    !active.has(path.resolve(root)) &&
      !fs.lstatSync(path.join(root, GUARD), { throwIfNoEntry: false }),
    "Preserve unresolved native renewal setup",
  );
}
function verifyPublicResult(body, row, agentRowId) {
  assert.equal(body.job.id, row.id);
  assert.equal(body.job.status, row.status);
  assert.equal(body.job.operation, "renew");
  assert.equal(body.job.subjectId, row.subject_id);
  assert.equal(body.job.claimId, row.claim_id);
  assert.equal(body.job.claimedByAgentId, agentRowId);
  assert.equal(body.job.attemptCount, 1);
  if (row.mode === "real")
    assert.equal(body.job.resultMetadata.keyRotated, true);
  return true;
}
function readOwnedBytes(file, maximum = 1048576, expected) {
  const resolved = path.resolve(file);
  assert.equal(fs.realpathSync(resolved), resolved);
  const fd = fs.openSync(
    resolved,
    fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW,
  );
  try {
    const before = fs.fstatSync(fd, { bigint: true });
    assert.ok(
      before.isFile() &&
        before.ino > 0n &&
        before.nlink === 1n &&
        before.size > 0n &&
        before.size <= BigInt(maximum) &&
        (before.mode & 0o777n) === 0o600n &&
        before.uid === BigInt(process.getuid()),
    );
    if (expected) {
      assert.equal(before.dev, expected.dev);
      assert.equal(before.ino, expected.ino);
    }
    const bytes = Buffer.alloc(Number(before.size) + 1);
    const count = fs.readSync(fd, bytes, 0, bytes.length, 0);
    const after = fs.fstatSync(fd, { bigint: true }),
      current = fs.lstatSync(resolved, { bigint: true });
    assert.equal(count, Number(before.size));
    for (const key of ["dev", "ino", "size", "mtimeNs", "ctimeNs"])
      assert.equal(before[key], after[key]);
    assert.equal(current.dev, before.dev);
    assert.equal(current.ino, before.ino);
    assert.ok(current.isFile() && !current.isSymbolicLink());
    return bytes.subarray(0, count);
  } finally {
    fs.closeSync(fd);
  }
}
function material(certPath, keyPath, domain) {
  const cert = readOwnedBytes(certPath),
    key = readOwnedBytes(keyPath),
    leaf = new crypto.X509Certificate(cert);
  assert.equal(leaf.checkHost(domain), domain);
  assert.equal(leaf.checkPrivateKey(crypto.createPrivateKey(key)), true);
  return {
    cert,
    key,
    leaf,
    fingerprint: sha(leaf.raw),
    spki: sha(leaf.publicKey.export({ type: "spki", format: "der" })),
    privateSha: sha(key),
    notAfter: Date.parse(leaf.validTo),
  };
}
function materialState(value) {
  return {
    certificateSha: sha(value.cert),
    fingerprint: value.fingerprint,
    spki: value.spki,
    privateSha: value.privateSha,
    notAfter: value.notAfter,
  };
}

function resolveTlsOptions(provider){
  assert.equal(typeof provider,"function");
  const options=provider();
  assert.ok(options && options.ca,"Explicit owned CA trust required");
  return options;
}
async function qualifyNativeAdoption(c) {
  assert.equal(process.platform, "linux");
  assert.equal(c.acmeKind, "certbot");
  bulk.verifyProof(c.bulkProof);
  const primaryTlsOptions=resolveTlsOptions(c.primaryTlsOptions);
  assert.ok(Array.isArray(c.ownedWorkers) && c.ownedWorkers.length > 0);
  for (const worker of c.ownedWorkers) {
    assert.equal(
      worker.hasOwnershipReceipt(),
      false,
      "Native re-setup requires the actual prior worker to be drained",
    );
    require("./certops-acme-background-runner").validateLifecycle(
      worker.getState(),
    );
  }
  assert.ok(
    Array.isArray(c.ownedBulkResources) && c.ownedBulkResources.length > 0,
  );
  for (const previous of c.ownedBulkResources) {
    assert.equal(previous.hasLiveResource(), false);
    assert.equal(previous.hasOwnershipReceipt(), false);
  }
  const root = path.resolve(c.workDir),
    certificateId = c.bulkProof.certificateIds[0];
  assert.equal(fs.realpathSync(root), root);
  assertCleanupSafe(root);
  assert.ok(Array.isArray(c.ownedAdoptionResources));
  const rootIdentity = fs.lstatSync(root, { bigint: true });
  const marker = path.join(root, GUARD),
    markerBytes = crypto.randomBytes(32);
  let server = null,
    serverClosed = true,
    complete = false;
  const sockets = new Set();
  const resource = {
    hasOwnershipReceipt: () =>
      !complete || !!fs.lstatSync(marker, { throwIfNoEntry: false }),
    hasLiveResource: () => !serverClosed || sockets.size > 0,
    async close() {
      for (const socket of sockets) socket.destroy();
      if (server && !serverClosed)
        await new Promise((resolve, reject) =>
          server.close((error) => {
            if (error) reject(new Error("Owned adoption TLS drainage failed"));
            else {
              serverClosed = true;
              resolve();
            }
          }),
        );
      assert.equal(sockets.size, 0);
    },
  };
  active.add(root);
  c.ownedAdoptionResources.push(resource);
  fs.writeFileSync(marker, markerBytes, { flag: "wx", mode: 0o600 });
  const markerIdentity = fs.lstatSync(marker, { bigint: true });
  const query = (sql, params = []) => c.pool.query(sql, params);
  const prefix = `/api/v1/workspaces/${c.workspaceId}/certops`;
  const certPath = path.join(root, "bulk-item-0", "fullchain.pem");
  const keyPath = path.join(c.configDir, "keys", certificateId + ".key.pem");
  const primary = () => material(c.certPath, c.keyPath, c.domain);
  const owned = () => material(certPath, keyPath, c.domain);
  const before = owned(),
    primaryBefore = primary();
  assert.equal(before.fingerprint, c.bulkProof.fingerprints[2]);
  const originalServingProfile = async () =>
    (
      await query(
        "SELECT cp.id,cp.name,cp.status,cp.issuer_id,cp.renew_before_days,cp.description,cp.key_mode,cp.source,cp.source_ref,cp.public_metadata FROM managed_certificates mc JOIN certificate_profiles cp ON cp.workspace_id=mc.workspace_id AND cp.id=mc.profile_id WHERE mc.workspace_id=$1 AND mc.id=$2",
        [c.workspaceId, c.certificateId],
      )
    ).rows;
  const primaryProfile = await originalServingProfile();
  const source = (
    await query(
      "SELECT mc.id,mc.key_mode,mc.profile_id,mc.deployed_cert_path,mc.deployed_agent_id,cp.status AS profile_status,cp.renew_before_days,cp.public_metadata FROM managed_certificates mc JOIN certificate_profiles cp ON cp.workspace_id=mc.workspace_id AND cp.id=mc.profile_id WHERE mc.workspace_id=$1 AND mc.id=$2",
      [c.workspaceId, certificateId],
    )
  ).rows[0];
  assert.ok(source && source.profile_id);
  assert.equal(source.key_mode, "agent-local");
  assert.equal(source.deployed_cert_path, certPath);
  const originalProfile = profileContract.validateRenewalProfile(
    source.public_metadata.renewalProfile,
  );
  assert.equal(originalProfile.keyRotationPolicy.rotateOnRenew, true);
  const agent = (
    await query(
      "SELECT id FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2",
      [c.workspaceId, c.agentId],
    )
  ).rows;
  assert.equal(agent.length, 1);
  assert.equal(source.deployed_agent_id, agent[0].id);
  const noOpenPeriod = async () =>
    assert.equal(
      (
        await query(
          "SELECT id FROM certops_management_periods WHERE workspace_id=$1 AND managed_certificate_id=$2 AND ended_at IS NULL",
          [c.workspaceId, certificateId],
        )
      ).rows.length,
      0,
    );
  await noOpenPeriod();
  assert.equal(
    (await query("SELECT id FROM certops_outbox WHERE status='pending'")).rows
      .length,
    0,
    "Default outbox drain requires isolated real pending intent",
  );
  const expectedExecution =
    profileContract.executionFieldsFromRenewalProfile(originalProfile);
  const jobIds = [],
    claimIds = [];
  try {
    serverClosed = false;
    server = tls.createServer(
      {
        cert: before.cert,
        key: before.key,
        SNICallback(name, callback) {
          try {
            assert.equal(name, c.domain);
            const current = owned();
            callback(
              null,
              tls.createSecureContext({ cert: current.cert, key: current.key }),
            );
          } catch {
            callback(new Error("Owned adoption TLS material unavailable"));
          }
        },
      },
      (socket) => socket.end(),
    );
    server.on("connection", (socket) => {
      sockets.add(socket);
      socket.once("close", () => sockets.delete(socket));
    });
    await new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    const trusted = () =>
      new Promise((resolve, reject) => {
        let fingerprint,
          failed = false;
        const socket = tls.connect(
          {
            host: "127.0.0.1",
            port: server.address().port,
            servername: c.domain,
            ca: primaryTlsOptions.ca,
            rejectUnauthorized: true,
          },
          () => {
            try {
              assert.equal(socket.authorized, true);
              fingerprint = sha(socket.getPeerCertificate().raw);
            } catch {
              failed = true;
            }
            socket.end();
          },
        );
        sockets.add(socket);
        socket.setTimeout(10000, () =>
          socket.destroy(new Error("Owned adoption TLS timeout")),
        );
        socket.on("error", () => {
          failed = true;
        });
        socket.once("close", (hadError) => {
          sockets.delete(socket);
          if (failed || hadError || !fingerprint)
            reject(new Error("Owned adoption TLS failed after drainage"));
          else resolve(fingerprint);
        });
      });
    assert.equal(await trusted(), before.fingerprint);
    const readd = await c.publicSession.request(
      prefix + `/sources/${certificateId}/readd`,
      "POST",
      { renewalProfileId: null, automationEnabled: false },
    );
    assert.equal(readd.status, 201);
    assert.equal(readd.body.managedCertificateId, certificateId);
    const periodId = readd.body.periodId;
    assert.match(periodId, UUID);
    const certificate = async () =>
      (
        await query(
          "SELECT profile_id,fingerprint_sha256 FROM managed_certificates WHERE workspace_id=$1 AND id=$2",
          [c.workspaceId, certificateId],
        )
      ).rows[0];
    assert.equal((await certificate()).profile_id, null);
    const setup = async (dryRun) => {
      const key = crypto.randomUUID(),
        body = { dryRun, idempotencyKey: key, payload: expectedExecution };
      const response = await c.publicSession.request(
        prefix + `/certificates/${certificateId}/renewal-setup`,
        "POST",
        body,
      );
      if (response.body?.job?.id) c.ownedJobIds.push(response.body.job.id);
      assert.equal(response.status, 201);
      const id = response.body.job.id;
      assert.match(id, UUID);
      jobIds.push(id);
      const replay = await c.publicSession.request(
        prefix + `/certificates/${certificateId}/renewal-setup`,
        "POST",
        body,
      );
      if (replay.body?.job?.id && replay.body.job.id !== id)
        c.ownedJobIds.push(replay.body.job.id);
      assert.equal(replay.status, 201);
      assert.equal(replay.body.job.id, id);
      const row = await c.waitUntil(async () => {
        const value = (
          await query(
            "SELECT id,status,mode,operation,subject_id,claimed_by_agent_id,claim_id,attempt_count,payload FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",
            [c.workspaceId, id],
          )
        ).rows[0];
        if (
          [
            "failed",
            "rejected",
            "cancelled",
            "orphaned_unknown_effect",
          ].includes(value?.status)
        )
          throw new Error("Actual native renewal setup failed");
        if (
          (dryRun && value?.status === "succeeded") ||
          (!dryRun && value?.status === "dry_run_complete")
        )
          throw new Error(
            "Actual native renewal setup completed in the wrong mode",
          );
        return value?.status === (dryRun ? "dry_run_complete" : "succeeded")
          ? value
          : null;
      }, 180000);
      assert.equal(row.mode, dryRun ? "dry_run" : "real");
      assert.equal(row.operation, "renew");
      assert.equal(row.subject_id, certificateId);
      assert.equal(row.payload.certificateId, certificateId);
      assert.equal(row.payload.certPath, certPath);
      assert.ok(
        isDeepStrictEqual(
          Object.fromEntries(
            Object.keys(expectedExecution).map((key) => [
              key,
              row.payload[key],
            ]),
          ),
          expectedExecution,
        ),
        "Actual setup execution policy changed",
      );
      assert.equal(row.claimed_by_agent_id, agent[0].id);
      assert.equal(row.attempt_count, 1);
      assert.match(row.claim_id, UUID);
      claimIds.push(row.claim_id);
      const publicResult = await c.publicSession.request(
        prefix + `/jobs/${id}`,
        "GET",
      );
      assert.equal(publicResult.status, 200);
      verifyPublicResult(publicResult.body, row, agent[0].id);
      return row;
    };
    const dry = await setup(true);
    assert.ok(
      isDeepStrictEqual(materialState(owned()), materialState(before)),
      "Dry run changed native custody",
    );
    assert.equal(await trusted(), before.fingerprint);
    await c.verifyDnsCleanup();
    assert.equal((await certificate()).profile_id, null);
    assert.equal(
      (
        await query(
          "SELECT id FROM certops_outbox WHERE workspace_id=$1 AND event_type='profile_derivation_requested' AND payload->>'jobId'=$2",
          [c.workspaceId, dry.id],
        )
      ).rows.length,
      0,
    );
    await new Promise((resolve) => setTimeout(resolve, 1500));
    const real = await setup(false),
      after = owned();
    assert.notEqual(after.fingerprint, before.fingerprint);
    assert.notEqual(after.spki, before.spki);
    assert.notEqual(after.leaf.serialNumber, before.leaf.serialNumber);
    assert.ok(after.notAfter > before.notAfter);
    assert.equal(await trusted(), after.fingerprint);
    await c.verifyDnsCleanup();
    const evidence = (
      await query(
        "SELECT metadata FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2 AND claim_id=$3 AND evidence_type='validation.passed' AND metadata->>'step'='verify'",
        [c.workspaceId, real.id, real.claim_id],
      )
    ).rows;
    assert.ok(
      evidence.some(
        (row) => row.metadata.fingerprintSha256 === after.fingerprint,
      ),
    );
    const intents = (
      await query(
        "SELECT id,workspace_id,event_type,payload,status,attempt_count FROM certops_outbox WHERE status='pending'",
      )
    ).rows;
    assert.equal(intents.length, 1);
    assert.equal(intents[0].workspace_id, c.workspaceId);
    assert.equal(intents[0].event_type, "profile_derivation_requested");
    assert.equal(intents[0].payload.jobId, real.id);
    assert.equal(intents[0].payload.certificateId, certificateId);
    const worker = await import(
      pathToFileURL(
        path.resolve(__dirname, "../../../apps/worker/src/certops-worker.js"),
      ).href
    );
    const drained = await worker.drainCertOpsOutbox({
      dbPool: c.pool,
      env: process.env,
    });
    assert.equal(drained.scanned, 1);
    assert.equal(drained.succeeded, 1);
    for (const key of ["skipped", "deferred", "retried", "failed"])
      assert.equal(drained[key], 0);
    const intent = (
      await query(
        "SELECT status,attempt_count,outcome_reason FROM certops_outbox WHERE id=$1 AND workspace_id=$2",
        [intents[0].id, c.workspaceId],
      )
    ).rows[0];
    assert.equal(intent.status, "succeeded");
    assert.equal(intent.attempt_count, 1);
    const configured = await certificate();
    assert.match(configured.profile_id, UUID);
    assert.equal(configured.fingerprint_sha256, after.fingerprint);
    const publicDetail = await c.publicSession.request(
      prefix + `/certificates/${certificateId}`,
      "GET",
    );
    assert.equal(publicDetail.status, 200);
    assert.equal(
      publicDetail.body.certificate.renewalSetup.state,
      "configured",
    );
    assert.equal(publicDetail.body.certificate.renewalSetup.jobId, real.id);
    const derived = (
      await query(
        "SELECT status,renew_before_days,public_metadata FROM certificate_profiles WHERE workspace_id=$1 AND id=$2",
        [c.workspaceId, configured.profile_id],
      )
    ).rows[0];
    const actualExecution = profileContract.executionFieldsFromRenewalProfile(
      profileContract.validateRenewalProfile(
        derived.public_metadata.renewalProfile,
      ),
    );
    assert.ok(
      isDeepStrictEqual(actualExecution, expectedExecution),
      "Derived execution policy changed",
    );
    assert.equal(
      derived.public_metadata.derivedFrom.certificateId,
      certificateId,
    );
    if (configured.profile_id === source.profile_id) {
      assert.equal(derived.status, source.profile_status);
      assert.equal(derived.renew_before_days, source.renew_before_days);
    }
    assert.ok(
      isDeepStrictEqual(materialState(primary()), materialState(primaryBefore)),
      "Original serving custody changed",
    );
    assert.ok(
      isDeepStrictEqual(await originalServingProfile(), primaryProfile),
      "Original profile changed",
    );
    assert.equal(
      await c.servedFingerprint(),
      primaryBefore.leaf.fingerprint256,
    );
    const period = (
      await query(
        "SELECT id,automation_enabled,renewal_profile_id FROM certops_management_periods WHERE workspace_id=$1 AND managed_certificate_id=$2 AND ended_at IS NULL",
        [c.workspaceId, certificateId],
      )
    ).rows;
    assert.equal(period.length, 1);
    assert.equal(period[0].id, periodId);
    assert.equal(period[0].automation_enabled, false);
    assert.equal(period[0].renewal_profile_id, null);
    const stopped = await c.publicSession.request(
      prefix + `/management-periods/${periodId}/stop`,
      "POST",
      {},
    );
    assert.equal(stopped.status, 200);
    await noOpenPeriod();
    await resource.close();
    const currentRoot = fs.lstatSync(root, { bigint: true }),
      currentMarker = fs.lstatSync(marker, { bigint: true });
    assert.equal(currentRoot.dev, rootIdentity.dev);
    assert.equal(currentRoot.ino, rootIdentity.ino);
    assert.equal(currentMarker.dev, markerIdentity.dev);
    assert.equal(currentMarker.ino, markerIdentity.ino);
    assert.ok(
      readOwnedBytes(marker, 32, markerIdentity).equals(markerBytes),
      "Preserve changed adoption guard",
    );
    fs.unlinkSync(marker);
    complete = true;
    active.delete(root);
    const proof = {
      scope: SCOPE,
      certificateId,
      profileId: configured.profile_id,
      jobIds,
      claimIds,
      fingerprints: [before.fingerprint, after.fingerprint],
      spkiFingerprints: [before.spki, after.spki],
      ...Object.fromEntries(FLAGS.map((flag) => [flag, true])),
    };
    verifyAgainstBulk(proof, c.bulkProof);
    return proof;
  } finally {
    await resource.close();
  }
}

module.exports = {
  SCOPE,
  SCENARIO,
  FLAGS,
  REQUIRED_SOURCES,
  verifyProof,
  verifyAgainstBulk,
  assertCleanupSafe,
  qualifyNativeAdoption,
  resolveTlsOptions,
  readOwnedBytes,
  verifyPublicResult,
};
