/**
 * Qualification: native certificate result outbox restart
 *
 * In the Ubuntu 24.04/certbot/noEAB journey, retain a loopback gateway that forwards
 * unaltered protocol/signatures. Pause a real public renewal at the command barrier,
 * independently bind current claim, then return HTTP 503 only for that job/claim's
 * terminal result; evidence still passes, new claims are refused and foreign result IDs
 * fail closed. Require production succeeded-outbox persistence plus genuine changed CA
 * leaf, matching protected key/trusted TLS/clean TXT while public job stays nonterminal.
 * Record actual claim, nonce, attempt; do not manufacture acknowledgement or CA output.
 * Pin agent pidfd then verify original parent/birth/executable/argv/no children;
 * descriptor-only SIGTERM, real child/controller close with code 0 and closed receipt
 * precede restart. No PID tree fallback/atomic-containment claim. Restart same config,
 * credential and signing pin without bootstrap. Real outbox backoff/time must deliver
 * same job/claim/attempt with one leaf fact, no dead letter/additional CA order, and
 * unchanged deployed bytes/key/TLS. Never rewrite retry timestamps or promise new SPKI.
 * Cross-bind bulk/adoption generations. Keep gateway until native process/socket drain;
 * unknown ownership preserves private root/public rows. Proof excludes private state,
 * credentials, signatures, envelopes; benign controls cannot qualify native execution.
 */
// Shared execution, evidence and cleanup policy: docs/certops/e2e-qualification.md.
"use strict";
/** Genuine completed certificate mutation, transient result delivery outage,
 * exact original agent restart and production outbox retry. No clock rewrites. */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto");
const { isDeepStrictEqual } = require("node:util");
const attachment = require("./certops-acme-agent-attachment");
const { readOwnedBytes } = require("./certops-acme-native-adoption");
const SCOPE = "native-certificate-success-result-outbox-and-agent-restart";
const SCENARIO = "real-acme-certificate-result-outbox-restart";
const FIELD = "nativeAcmeCertificateOutbox";
const SIDECAR = "qualification-results/acme-certificate-outbox-proof.json";
const FLAGS = Object.freeze([
  "actualSignedCurrentClaim",
  "actualNativeSuccessBeforeFixtureStop",
  "actualOwnedOutboxPersisted",
  "actualResultTransportRefused",
  "retainedPidfdOriginalAgentStop",
  "actualOriginalAgentClosed",
  "sameProtectedStateRestart",
  "actualProductionRetryTiming",
  "sameClaimSingleAttemptCompleted",
  "claimBoundLeafEvidence",
  "deployedPairAndTrustedTlsPreserved",
  "noAdditionalCaOrderAfterRestart",
  "noDeadLetter",
  "ownedStateReleased",
]);
const REQUIRED_SOURCES = Object.freeze([
  ...new Set([
    "tests/e2e/helpers/certops-acme-certificate-outbox.js",
    "tests/e2e/helpers/certops-acme-agent-attachment.js",
    "tests/e2e/helpers/certops-acme-agent-pidfd.py",
    "tests/e2e/helpers/certops-acme-result-outage.js",
    ...require("./certops-acme-native-adoption").REQUIRED_SOURCES,
    "packages/agent/src/outbox/index.js",
    "packages/agent/src/platform/index.js",
    "packages/agent/src/platform/durability.js",
  ]),
]);
const active = new Set(),
  GUARD = ".native-certificate-outbox-active";
const sha = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const uuid = (value) =>
  typeof value === "string" &&
  /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(value);
function verifyProof(p) {
  assert.ok(p && typeof p === "object");
  assert.deepEqual(
    Object.keys(p).sort(),
    [
      "scope",
      "certificateId",
      "jobId",
      "claimId",
      "fingerprints",
      "attemptCount",
      "extraCaOrdersAfterRestart",
      "fixtureStopAfterNativeSuccess",
      "jobCancellationQualified",
      ...FLAGS,
    ].sort(),
  );
  assert.equal(p.scope, SCOPE);
  for (const key of ["certificateId", "jobId", "claimId"])
    assert.ok(uuid(p[key]));
  assert.ok(
    Array.isArray(p.fingerprints) &&
      p.fingerprints.length === 2 &&
      p.fingerprints.every(
        (x) => typeof x === "string" && /^[a-f0-9]{64}$/.test(x),
      ) &&
      new Set(p.fingerprints).size === 2,
  );
  assert.equal(p.attemptCount, 1);
  assert.equal(p.extraCaOrdersAfterRestart, 0);
  assert.equal(p.fixtureStopAfterNativeSuccess, true);
  assert.equal(p.jobCancellationQualified, false);
  for (const flag of FLAGS) assert.equal(p[flag], true);
  return true;
}
function assertCleanupSafe(root) {
  assert.ok(
    !active.has(path.resolve(root)) && !fs.existsSync(path.join(root, GUARD)),
    "Preserve unresolved native result/restart ownership",
  );
  attachment.assertCleanupSafe(root);
}
function verifyAgainstJourney(p, previous, adoption) {
  verifyProof(p);
  require("./certops-acme-native-adoption").verifyAgainstBulk(
    adoption,
    previous,
  );
  assert.equal(p.fingerprints[0], previous.originalServingFingerprint);
  assert.ok(!previous.certificateIds.includes(p.certificateId));
  const jobs = [
    ...previous.issueJobIds,
    ...previous.jobIds,
    ...adoption.jobIds,
    p.jobId,
  ];
  const claims = [...previous.claimIds, ...adoption.claimIds, p.claimId];
  assert.equal(new Set(jobs.map((x) => x.toLowerCase())).size, jobs.length);
  assert.equal(new Set(claims.map((x) => x.toLowerCase())).size, claims.length);
  assert.ok(
    ![...previous.fingerprints, ...adoption.fingerprints].includes(
      p.fingerprints[1],
    ),
  );
  return true;
}
async function qualify(c) {
  assert.equal(process.platform, "linux");
  assert.equal(c.acmeKind, "certbot");
  const root = fs.realpathSync(c.workDir);
  assert.equal(root, path.resolve(c.workDir));
  assertCleanupSafe(root);
  const guard = path.join(root, GUARD),
    token = Buffer.from(crypto.randomBytes(32).toString("hex"));
  active.add(root);
  fs.writeFileSync(guard, token, { flag: "wx", mode: 0o600 });
  const guardId = fs.lstatSync(guard, { bigint: true });
  const beforeCert = readOwnedBytes(c.certPath),
    beforeKey = readOwnedBytes(c.keyPath),
    beforeLeaf = new crypto.X509Certificate(beforeCert);
  assert.equal(
    beforeLeaf.checkPrivateKey(crypto.createPrivateKey(beforeKey)),
    true,
  );
  const protectedNames = ["config.json", "credential", "signing-key-pin.json"],
    protectedBefore = protectedNames.map((n) =>
      sha(readOwnedBytes(path.join(c.configDir, n))),
    );
  const arm = path.join(c.barrierDirectory, "armed.json"),
    receipt = path.join(c.barrierDirectory, "process.json"),
    barrierToken = crypto.randomUUID();
  assert.equal(fs.lstatSync(arm, { throwIfNoEntry: false }), undefined);
  assert.equal(fs.lstatSync(receipt, { throwIfNoEntry: false }), undefined);
  const armBytes = Buffer.from(JSON.stringify({ token: barrierToken }));
  fs.writeFileSync(arm, armBytes, { flag: "wx", mode: 0o600 });
  const armId = fs.lstatSync(arm, { bigint: true });
  const made = await c.publicSession.request(
    `/api/v1/workspaces/${c.workspaceId}/certops/jobs`,
    "POST",
    {
      operation: "renew",
      subjectId: c.certificateId,
      subjectType: "managed_certificate",
      idempotencyKey: crypto.randomUUID(),
    },
  );
  if (made.body?.job?.id) c.ownedJobIds.push(made.body.job.id);
  assert.equal(made.status, 201);
  const jobId = made.body.job.id;
  assert.ok(uuid(jobId));
  const job = async () =>
    (
      await c.pool.query(
        "SELECT id,status,operation,source,mode,subject_id,claim_id,attempt_count,claimed_by_agent_id,payload FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",
        [c.workspaceId, jobId],
      )
    ).rows[0];
  const running = await c.waitUntil(async () => {
    const row = await job();
    return row?.status === "running" &&
      uuid(row.claim_id) &&
      fs.existsSync(receipt)
      ? row
      : null;
  });
  const barrier = JSON.parse(readOwnedBytes(receipt, 8192).toString("utf8"));
  const receiptId = fs.lstatSync(receipt, { bigint: true });
  assert.equal(barrier.token, barrierToken);
  assert.equal(barrier.parentPid, c.agent.pid);
  assert.ok(Number.isSafeInteger(barrier.pid) && barrier.pid > 1);
  assert.equal(running.payload.certificateId, c.certificateId);
  assert.equal(running.subject_id, c.certificateId);
  assert.equal(running.operation, "renew");
  assert.equal(running.source, "api");
  assert.equal(running.mode, "real");
  assert.equal(running.attempt_count, 1);
  const dispatches = async () =>
    (
      await c.pool.query(
        "SELECT nonce FROM certops_consumed_nonces WHERE workspace_id=$1 AND job_id=$2 AND issued_to_agent_id=$3",
        [c.workspaceId, jobId, running.claimed_by_agent_id],
      )
    ).rows;
  assert.equal((await dispatches()).length, 1);

  c.resultGateway.arm(jobId, running.claim_id);
  assert.ok(readOwnedBytes(arm, 8192, armId).equals(armBytes));
  fs.unlinkSync(arm);
  const outbox = path.join(c.configDir, "outbox");
  const persisted = await c.waitUntil(() => {
    if (c.resultGateway.observation().refusedResults < 1) return null;
    const values = fs
      .readdirSync(outbox)
      .filter((n) => n.endsWith(".json"))
      .map((name) => ({
        name,
        entry: JSON.parse(
          readOwnedBytes(path.join(outbox, name), 524288).toString("utf8"),
        ),
      }))
      .filter((x) => x.entry.result?.jobId === jobId);
    assert.ok(values.length <= 1);
    return values[0] || null;
  });
  assert.equal(persisted.entry.result.status, "succeeded");
  assert.equal(persisted.entry.result.claimId, running.claim_id);
  assert.ok(["running", "claimed"].includes((await job()).status));
  const deployedCert = readOwnedBytes(c.certPath),
    deployedKey = readOwnedBytes(c.keyPath),
    deployedLeaf = new crypto.X509Certificate(deployedCert);
  assert.equal(
    deployedLeaf.checkPrivateKey(crypto.createPrivateKey(deployedKey)),
    true,
  );
  assert.equal(deployedLeaf.checkHost(c.domain), c.domain);
  assert.notEqual(sha(deployedLeaf.raw), sha(beforeLeaf.raw));
  assert.equal(await c.servedFingerprint(), deployedLeaf.fingerprint256);
  await c.verifyDnsCleanup();
  const caBeforeRestart = c.caGateway.snapshot().acceptedOrders;
  assert.ok(Number.isSafeInteger(caBeforeRestart) && caBeforeRestart > 0);
  const originalAgent = c.agent;
  const owner = await attachment.attachIdleAgent({
    agent: originalAgent,
    entry: c.agentEntry,
    workDir: root,
    resources: c.ownedRestartResources,
    waitUntil: c.waitUntil,
    isAgentClosed: () => c.isAgentClosed(originalAgent),
  });
  await owner.stopAndDrain();
  assert.ok(c.isAgentClosed(originalAgent));
  assert.ok(readOwnedBytes(receipt, 8192, receiptId).length > 0);
  fs.unlinkSync(receipt);
  const credentialAfter = protectedNames.map((n) =>
    sha(readOwnedBytes(path.join(c.configDir, n))),
  );
  assert.ok(
    isDeepStrictEqual(credentialAfter, protectedBefore),
    "Original protected configuration changed",
  );
  c.resultGateway.restoreDelivery();
  const restarted = c.restartAgent();
  assert.ok(
    restarted &&
      restarted.pid !== originalAgent.pid &&
      restarted.exitCode === null,
  );
  await c.waitUntil(async () => {
    const row = await job();
    return row?.status === "succeeded" &&
      !fs.existsSync(path.join(outbox, persisted.name))
      ? row
      : null;
  }, 120000);
  const final = await job();
  assert.equal((await dispatches()).length, 1);
  assert.equal(final.claim_id, running.claim_id);
  assert.equal(final.attempt_count, 1);
  assert.equal(final.claimed_by_agent_id, running.claimed_by_agent_id);
  const evidence = (
    await c.pool.query(
      "SELECT metadata FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2 AND claim_id=$3 AND evidence_type='validation.passed' AND metadata->>'step'='verify'",
      [c.workspaceId, jobId, running.claim_id],
    )
  ).rows;
  assert.equal(
    evidence.length,
    1,
    "One persisted current-claim native verify fact required",
  );
  assert.ok(
    evidence.some(
      (x) =>
        String(x.metadata.fingerprintSha256)
          .replaceAll(":", "")
          .toLowerCase() === sha(deployedLeaf.raw),
    ),
  );
  assert.ok(
    readOwnedBytes(c.certPath).equals(deployedCert) &&
      readOwnedBytes(c.keyPath).equals(deployedKey),
  );
  assert.equal(await c.servedFingerprint(), deployedLeaf.fingerprint256);
  assert.ok(
    isDeepStrictEqual(
      protectedNames.map((n) => sha(readOwnedBytes(path.join(c.configDir, n)))),
      protectedBefore,
    ),
    "Restart protected configuration changed",
  );
  assert.equal(c.caGateway.snapshot().acceptedOrders, caBeforeRestart);
  const dead = path.join(outbox, "dead-letter");
  assert.ok(!fs.existsSync(dead) || fs.readdirSync(dead).length === 0);
  assert.equal(c.resultGateway.observation().mismatchedResults, 0);
  assert.ok(c.resultGateway.observation().forwardedResults >= 1);
  c.resultGateway.disarm();
  owner.release();
  assert.ok(readOwnedBytes(guard, 128, guardId).equals(token));
  fs.unlinkSync(guard);
  active.delete(root);
  const proof = {
    scope: SCOPE,
    certificateId: c.certificateId,
    jobId,
    claimId: running.claim_id,
    fingerprints: [sha(beforeLeaf.raw), sha(deployedLeaf.raw)],
    attemptCount: 1,
    extraCaOrdersAfterRestart: 0,
    fixtureStopAfterNativeSuccess: true,
    jobCancellationQualified: false,
    ...Object.fromEntries(FLAGS.map((x) => [x, true])),
  };
  verifyProof(proof);
  return proof;
}
module.exports = {
  SCOPE,
  SCENARIO,
  FIELD,
  SIDECAR,
  FLAGS,
  REQUIRED_SOURCES,
  verifyProof,
  verifyAgainstJourney,
  assertCleanupSafe,
  qualify,
};
