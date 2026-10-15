"use strict";
/** Public bulk admission followed by genuine candidate-agent/Pebble executions.
 * Runs only in the existing disposable Ubuntu certbot/no-EAB native journey.
 * Database queries are independent observations, never seeded outcomes. */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto"),
  tls = require("node:tls"),
  { isDeepStrictEqual } = require("node:util");
const SCOPE = "native-public-bulk-renew-two-agent-local-certificates";
const SCENARIO = "real-acme-public-bulk-two-native-renewals";
const FLAGS = [
  "actualPublicOwnedIssuances",
  "twoDistinctStoredProfiles",
  "bothRotationPoliciesTrue",
  "mixedPublicBulkAdmission",
  "stablePublicReplay",
  "bothCurrentClaimsOwned",
  "publicCompletedResultsBound",
  "bothRealCaLeavesChanged",
  "bothPrivateKeysMatchAndRotate",
  "bothTrustedTlsFingerprints",
  "claimBoundVerificationEvidence",
  "storedProfilesUnchanged",
  "ownedDnsCleaned",
  "ownedManagementStopped",
  "originalServingCertificateUnchanged",
  "productionWorkerStopped",
  "retainedTlsResourcesDrained",
  "ownershipGuardReleased",
];
const REQUIRED_SOURCES = [
  ...new Set([
    ...require("./certops-acme-stage-faults").REQUIRED_SOURCES,
    "apps/api/services/certops/renewalProfileDerivation.js",
    "apps/api/services/certops/agentObservations.js",
    "apps/api/services/certops/renewalCapacity.js",
    "tests/e2e/helpers/certops-acme-bulk-renewal.js",
    "tests/e2e/helpers/certops-acme-background-runner.js",
    "tests/e2e/helpers/certops-acme-background-pidfd.py",
    "tests/e2e/acme-real-journey.js",
    "scripts/certops-real-acme.js",
    ".github/workflows/certops-real-acme.yml",
    "packages/agent/src/index.js",
    "packages/agent/src/keys/index.js",
    "packages/agent/src/acme/index.js",
    "packages/agent/src/signing/index.js",
    "packages/agent/src/deploy/index.js",
    "apps/api/routes/certops.js",
    "apps/api/services/certops/issuance.js",
    "apps/api/services/certops/jobs.js",
    "apps/api/services/certops/renewalProfile.js",
    "apps/api/services/certops/renewalProfileAdmin.js",
    "apps/api/services/certops/agentDispatch.js",
    "apps/api/services/certops/certificateIdentity.js",
  ]),
];
const sha = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const uuid = (value) =>
  typeof value === "string" &&
  /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(value);
const digest = (value) =>
  typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
function verifyProof(p) {
  assert.ok(p && typeof p === "object" && !Array.isArray(p));
  assert.deepEqual(
    Object.keys(p).sort(),
    [
      "scope",
      "client",
      "certificateIds",
      "jobIds",
      "issueJobIds",
      "claimIds",
      "fingerprints",
      "serials",
      "spkiFingerprints",
      "originalServingFingerprint",
      "originalServingSpki",
      "originalServingProfileId",
      ...FLAGS,
    ].sort(),
  );
  assert.equal(p.scope, SCOPE);
  assert.equal(p.client, "certbot");
  assert.ok(
    digest(p.originalServingFingerprint) &&
      digest(p.originalServingSpki) &&
      uuid(p.originalServingProfileId),
  );
  for (const field of ["certificateIds", "issueJobIds", "jobIds", "claimIds"])
    assert.ok(
      Array.isArray(p[field]) &&
        p[field].length === 2 &&
        p[field].every(uuid) &&
        new Set(p[field].map((x) => x.toLowerCase())).size === 2,
    );
  assert.equal(
    new Set([...p.issueJobIds, ...p.jobIds].map((x) => x.toLowerCase())).size,
    4,
  );
  for (const field of ["fingerprints", "spkiFingerprints"])
    assert.ok(
      Array.isArray(p[field]) &&
        p[field].length === 4 &&
        p[field].every(digest) &&
        new Set(p[field]).size === 4,
    );
  assert.ok(
    Array.isArray(p.serials) &&
      p.serials.length === 4 &&
      p.serials.every(
        (x) => typeof x === "string" && /^[a-f0-9]{1,64}$/i.test(x),
      ) &&
      new Set(
        p.serials.map((x) => x.toLowerCase().replace(/^0+(?=[a-f0-9])/, "")),
      ).size === 4,
  );
  for (const flag of FLAGS) assert.equal(p[flag], true, flag);
  return true;
}
function verifyAdmission(
  body,
  certificateIds,
  unknownId,
  { replay = false } = {},
) {
  assert.ok(body && typeof body === "object");
  assert.deepEqual(body.summary, { requested: 3, succeeded: 2, failed: 1 });
  assert.ok(Array.isArray(body.results) && body.results.length === 3);
  assert.deepEqual(
    body.results.map((x) => x.certificateId),
    [...certificateIds, unknownId],
  );
  const rows = body.results.slice(0, 2);
  for (const row of rows) {
    assert.equal(row.ok, true);
    assert.ok(uuid(row.jobId));
    if (replay) assert.equal(row.replayed, true);
    else assert.notEqual(row.replayed, true);
  }
  assert.equal(new Set(rows.map((x) => x.jobId.toLowerCase())).size, 2);
  const last = body.results[2];
  assert.equal(last.ok, false);
  assert.equal(last.errorCode, "CERTOPS_CERTIFICATE_NOT_FOUND");
  assert.equal(last.jobId, undefined);
  return rows.map((x) => x.jobId);
}
async function qualifyBulk(c) {
  assert.equal(process.platform, "linux");
  assert.equal(c.acmeKind, "certbot");
  assert.ok(!c.eabRef);
  assert.equal(process.env.GITHUB_ACTIONS, "true");
  assert.equal(process.env.RUNNER_ENVIRONMENT, "github-hosted");
  assert.match(fs.readFileSync("/etc/os-release", "utf8"), /^ID=ubuntu$/m);
  assert.match(
    fs.readFileSync("/etc/os-release", "utf8"),
    /^VERSION_ID="?24\.04"?$/m,
  );
  assert.equal(
    fs.existsSync("/.dockerenv"),
    false,
    "Bulk qualification requires the declared Ubuntu host",
  );
  const {
    pool,
    workspaceId,
    agentId,
    agent,
    publicSession,
    certificateId,
    certPath,
    keyPath,
    workDir,
    requestedNames,
    domain,
    commandRef,
    caEndpoint,
    ownedJobIds,
    ownedCertificateIds,
    ownedBulkResources,
    waitUntil,
    verifyNames,
    verifyDnsCleanup,
    primaryTlsOptions,
  } = c;
  assert.ok(Array.isArray(ownedBulkResources));
  assert.equal(fs.realpathSync.native(workDir), workDir);
  const rootStat = fs.lstatSync(workDir, { bigint: true });
  assert.ok(
    rootStat.isDirectory() && !rootStat.isSymbolicLink() && rootStat.ino > 0n,
  );
  const guard = path.join(workDir, "native-bulk-renewal-active.json"),
    guardBytes = crypto.randomBytes(32),
    sockets = new Set();
  const servers = [],
    closedServers = new Set();
  let complete = false;
  const resource = {
    async close() {
      for (const socket of sockets) socket.destroy();
      for (const server of servers)
        if (!closedServers.has(server)) {
          await new Promise((resolve, reject) =>
            server.close((error) =>
              error
                ? reject(new Error("Owned bulk TLS listener drainage failed"))
                : resolve(),
            ),
          );
          closedServers.add(server);
        }
      await waitUntil(() => sockets.size === 0, 5000);
    },
    hasLiveResource: () =>
      servers.some((server) => !closedServers.has(server)) || sockets.size > 0,
    hasOwnershipReceipt: () =>
      !complete || fs.lstatSync(guard, { throwIfNoEntry: false }) !== undefined,
  };
  ownedBulkResources.push(resource);
  fs.writeFileSync(guard, guardBytes, { flag: "wx", mode: 0o600 });
  const guardIdentity = fs.lstatSync(guard, { bigint: true });
  const owned = () => {
    const current = fs.lstatSync(workDir, { bigint: true }),
      marker = fs.lstatSync(guard, { bigint: true });
    assert.ok(
      current.dev === rootStat.dev &&
        current.ino === rootStat.ino &&
        !current.isSymbolicLink(),
    );
    assert.ok(
      marker.isFile() &&
        !marker.isSymbolicLink() &&
        marker.dev === guardIdentity.dev &&
        marker.ino === guardIdentity.ino &&
        marker.size === 32n &&
        fs.readFileSync(guard).equals(guardBytes),
      "Preserve changed bulk ownership receipt",
    );
  };
  const query = (sql, args) => pool.query(sql, args),
    prefix = `/api/v1/workspaces/${workspaceId}/certops`;
  const live = () => {
    owned();
    assert.equal(agent.exitCode, null);
    assert.equal(agent.signalCode, null);
  };
  const waitJob = (id) =>
    waitUntil(async () => {
      live();
      const row = (
        await query(
          "SELECT id,status,operation,source,mode,subject_id,claim_id,claimed_by_agent_id,attempt_count,payload,result_metadata FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",
          [workspaceId, id],
        )
      ).rows[0];
      assert.ok(row);
      if (
        [
          "failed",
          "cancelled",
          "rejected",
          "blocked",
          "orphaned_unknown_effect",
        ].includes(row.status)
      )
        throw new Error("Actual owned bulk fixture job failed");
      return row.status === "succeeded" ? row : false;
    }, 180000);
  const profile = async (id) =>
    (
      await query(
        "SELECT cp.id,cp.status,cp.name,cp.issuer_id,cp.renew_before_days,cp.description,cp.key_mode,cp.source,cp.source_ref,cp.public_metadata FROM managed_certificates mc JOIN certificate_profiles cp ON cp.workspace_id=mc.workspace_id AND cp.id=mc.profile_id WHERE mc.workspace_id=$1 AND mc.id=$2",
        [workspaceId, id],
      )
    ).rows[0];
  const material = (item) => {
    const leaf = new crypto.X509Certificate(fs.readFileSync(item.certPath)),
      key = fs.readFileSync(item.keyPath);
    verifyNames(leaf);
    assert.ok(leaf.checkPrivateKey(crypto.createPrivateKey(key)));
    assert.equal(leaf.checkHost(domain), domain);
    assert.equal(fs.statSync(item.keyPath).mode & 0o777, 0o600);
    return {
      fingerprint: sha(leaf.raw),
      serial: leaf.serialNumber,
      spki: sha(leaf.publicKey.export({ type: "spki", format: "der" })),
      notAfter: Date.parse(leaf.validTo),
      localPrivateSha256: sha(key),
    };
  };
  const trusted = (options) =>
    new Promise((resolve, reject) => {
      let fingerprint, error;
      const socket = tls.connect(
        { ...options, rejectUnauthorized: true },
        () => {
          if (socket.authorized)
            fingerprint = socket
              .getPeerCertificate()
              .fingerprint256.replaceAll(":", "")
              .toLowerCase();
          else error = new Error("Owned bulk TLS was not trusted");
          socket.end();
        },
      );
      sockets.add(socket);
      socket.setTimeout(10000, () =>
        socket.destroy(new Error("Owned bulk TLS timed out")),
      );
      socket.on("error", () => {
        error = new Error("Owned bulk TLS failed");
      });
      socket.once("close", () => {
        sockets.delete(socket);
        if (error) reject(error);
        else if (fingerprint) resolve(fingerprint);
        else reject(new Error("Owned bulk TLS closed without a leaf"));
      });
    });
  let proof;
  try {
    live();
    assert.ok(Array.isArray(c.ownedWorkers) && c.ownedWorkers.length > 0);
    for (const worker of c.ownedWorkers) {
      assert.equal(worker.hasOwnershipReceipt(), false);
      require("./certops-acme-background-runner").validateLifecycle(
        worker.getState(),
      );
    }
    const originalServing = { id: certificateId, certPath, keyPath };
    const originalServingMaterial = material(originalServing),
      originalServingProfile = await profile(certificateId);
    assert.equal(
      await trusted(primaryTlsOptions()),
      originalServingMaterial.fingerprint,
    );
    const expectedAgent = (
      await query(
        "SELECT id FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2",
        [workspaceId, agentId],
      )
    ).rows;
    assert.equal(expectedAgent.length, 1);
    const subjects = [],
      profiles = [],
      issueJobIds = [];
    for (let index = 0; index < 2; index++) {
      const targetPath = path.join(
        workDir,
        "bulk-item-" + index,
        "fullchain.pem",
      );
      assert.equal(
        fs.lstatSync(path.dirname(targetPath), { throwIfNoEntry: false }),
        undefined,
        "Bulk native destination must start absent",
      );
      const issued = await publicSession.request(prefix + "/jobs", "POST", {
        operation: "issue",
        idempotencyKey: crypto.randomUUID(),
        payload: {
          sans: requestedNames,
          target: { type: "domain", reference: domain },
          certPath: targetPath,
          commandRef,
          caEndpoint,
          acmeKind: "certbot",
          dnsProvider: "pebble-challtestsrv",
          dnsZone: "example.test",
        },
      });
      if (issued.body?.job?.id) ownedJobIds.push(issued.body.job.id);
      if (issued.body?.job?.subjectId)
        ownedCertificateIds.push(issued.body.job.subjectId);
      assert.equal(issued.status, 201);
      const id = issued.body.job.subjectId;
      assert.ok(
        uuid(id) &&
          id.toLowerCase() !== certificateId.toLowerCase() &&
          !subjects.some((item) => item.id.toLowerCase() === id.toLowerCase()),
      );
      const actualIssue = await waitJob(issued.body.job.id);
      assert.equal(actualIssue.operation, "issue");
      assert.equal(actualIssue.mode, "real");
      assert.equal(actualIssue.subject_id, id);
      assert.equal(actualIssue.claimed_by_agent_id, expectedAgent[0].id);
      assert.equal(actualIssue.attempt_count, 1);
      assert.ok(uuid(actualIssue.claim_id));
      assert.equal(actualIssue.payload.certPath, targetPath);
      issueJobIds.push(actualIssue.id);
      await verifyDnsCleanup();
      const item = {
        id,
        certPath: targetPath,
        keyPath: path.join(c.configDir, "keys", id + ".key.pem"),
      };
      const stored = await profile(id);
      assert.ok(stored && !profiles.some((other) => other.id === stored.id));
      assert.equal(
        stored.public_metadata.renewalProfile.keyRotationPolicy.rotateOnRenew,
        true,
      );
      const server = tls.createServer(
        {
          cert: fs.readFileSync(item.certPath),
          key: fs.readFileSync(item.keyPath),
          SNICallback: (_name, callback) => {
            try {
              callback(
                null,
                tls.createSecureContext({
                  cert: fs.readFileSync(item.certPath),
                  key: fs.readFileSync(item.keyPath),
                }),
              );
            } catch {
              callback(new Error("Owned bulk TLS material unavailable"));
            }
          },
        },
        (socket) => socket.end(),
      );
      servers.push(server);
      server.on("connection", (socket) => {
        sockets.add(socket);
        socket.once("close", () => sockets.delete(socket));
      });
      server.on("tlsClientError", () => {});
      await new Promise((resolve, reject) => {
        server.once("error", () =>
          reject(new Error("Owned bulk TLS listener failed")),
        );
        server.listen(0, "127.0.0.1", resolve);
      });
      item.tls = { ...primaryTlsOptions(), port: server.address().port };
      subjects.push(item);
      profiles.push(stored);
    }
    const originals = subjects.map(material);
    for (const [index, item] of subjects.entries())
      assert.equal(await trusted(item.tls), originals[index].fingerprint);
    const certificateIds = subjects.map((item) => item.id),
      unknownId = crypto.randomUUID(),
      request = {
        certificateIds: [...certificateIds, unknownId],
        idempotencyKey: crypto.randomUUID(),
      };
    assert.equal(
      (
        await query(
          "SELECT 1 FROM managed_certificates WHERE workspace_id=$1 AND id=$2",
          [workspaceId, unknownId],
        )
      ).rows.length,
      0,
    );
    await new Promise((resolve) => setTimeout(resolve, 1500));
    const admitted = await publicSession.request(
      `${prefix}/jobs/bulk-renew`,
      "POST",
      request,
    );
    for (const row of admitted.body?.results || [])
      if (uuid(row.jobId)) ownedJobIds.push(row.jobId);
    assert.equal(admitted.status, 200);
    const jobs = verifyAdmission(admitted.body, certificateIds, unknownId);
    const replay = await publicSession.request(
      `${prefix}/jobs/bulk-renew`,
      "POST",
      request,
    );
    for (const row of replay.body?.results || [])
      if (uuid(row.jobId) && !ownedJobIds.includes(row.jobId))
        ownedJobIds.push(row.jobId);
    assert.equal(replay.status, 200);
    assert.deepEqual(
      verifyAdmission(replay.body, certificateIds, unknownId, { replay: true }),
      jobs,
    );
    const allocated = (
      await query(
        "SELECT id,subject_id FROM certificate_jobs WHERE workspace_id=$1 AND idempotency_key LIKE $2 ORDER BY id",
        [workspaceId, `bulk-renew:${request.idempotencyKey}:%`],
      )
    ).rows;
    for (const row of allocated)
      if (!ownedJobIds.includes(row.id)) ownedJobIds.push(row.id);
    assert.equal(
      allocated.length,
      2,
      "Bulk request must allocate exactly two actual jobs",
    );
    assert.deepEqual(allocated.map((row) => row.id).sort(), [...jobs].sort());
    assert.deepEqual(
      allocated.map((row) => row.subject_id).sort(),
      [...certificateIds].sort(),
    );
    const claims = [],
      updated = [];
    for (const [index, item] of subjects.entries()) {
      const row = await waitJob(jobs[index]);
      assert.equal(row.operation, "renew");
      assert.equal(row.source, "api");
      assert.equal(row.mode, "real");
      assert.equal(row.subject_id, item.id);
      assert.ok(uuid(row.claim_id));
      assert.equal(row.claimed_by_agent_id, expectedAgent[0].id);
      assert.equal(row.attempt_count, 1);
      assert.equal(row.payload.keyRotation, true);
      assert.equal(row.result_metadata.keyRotated, true);
      const publicResult = await publicSession.request(
        `${prefix}/jobs/${row.id}`,
      );
      assert.equal(publicResult.status, 200);
      assert.equal(publicResult.body.job.id, row.id);
      assert.equal(publicResult.body.job.subjectId, item.id);
      assert.equal(publicResult.body.job.status, "succeeded");
      assert.equal(publicResult.body.job.claimId, row.claim_id);
      assert.equal(publicResult.body.job.claimedByAgentId, expectedAgent[0].id);
      assert.equal(publicResult.body.job.attemptCount, 1);
      assert.equal(publicResult.body.job.resultMetadata.keyRotated, true);
      assert.equal(row.payload.certPath, item.certPath);
      assert.ok(
        isDeepStrictEqual(
          row.payload.renewalProfile,
          profiles[index].public_metadata.renewalProfile,
        ),
        "Bulk signed snapshot changed",
      );
      const actual = material(item);
      assert.notEqual(actual.fingerprint, originals[index].fingerprint);
      assert.notEqual(actual.serial, originals[index].serial);
      assert.notEqual(actual.spki, originals[index].spki);
      assert.ok(actual.notAfter > originals[index].notAfter);
      assert.equal(await trusted(item.tls), actual.fingerprint);
      await waitUntil(async () => {
        const current = (
          await query(
            "SELECT fingerprint_sha256,not_after,profile_id FROM managed_certificates WHERE workspace_id=$1 AND id=$2",
            [workspaceId, item.id],
          )
        ).rows[0];
        return (
          current &&
          String(current.fingerprint_sha256)
            .replaceAll(":", "")
            .toLowerCase() === actual.fingerprint &&
          new Date(current.not_after).getTime() === actual.notAfter &&
          current.profile_id === profiles[index].id
        );
      }, 30000);
      const evidence = (
        await query(
          "SELECT e.metadata FROM certificate_evidence e JOIN certificate_jobs j ON j.workspace_id=e.workspace_id AND j.id=e.job_id WHERE e.workspace_id=$1 AND e.job_id=$2 AND e.claim_id=j.claim_id AND e.evidence_type='validation.passed' AND e.metadata->>'step'='verify'",
          [workspaceId, jobs[index]],
        )
      ).rows;
      assert.ok(
        evidence.some(
          (entry) =>
            String(entry.metadata.fingerprintSha256)
              .replaceAll(":", "")
              .toLowerCase() === actual.fingerprint,
        ),
        "Actual current-claim verification fingerprint missing",
      );
      assert.ok(
        isDeepStrictEqual(await profile(item.id), profiles[index]),
        "Bulk changed stored execution profile",
      );
      claims.push(row.claim_id);
      updated.push(actual);
    }
    await verifyDnsCleanup();
    assert.ok(
      isDeepStrictEqual(material(originalServing), originalServingMaterial),
      "Bulk changed original serving certificate or key",
    );
    assert.ok(
      isDeepStrictEqual(await profile(certificateId), originalServingProfile),
      "Bulk changed original serving profile",
    );
    assert.equal(
      await trusted(primaryTlsOptions()),
      originalServingMaterial.fingerprint,
    );
    for (const item of subjects) {
      const periods = (
        await query(
          "SELECT id FROM certops_management_periods WHERE workspace_id=$1 AND managed_certificate_id=$2 AND ended_at IS NULL",
          [workspaceId, item.id],
        )
      ).rows;
      assert.equal(periods.length, 1);
      const stopped = await publicSession.request(
        `${prefix}/management-periods/${periods[0].id}/stop`,
        "POST",
        {},
      );
      assert.equal(stopped.status, 200);
      assert.equal(
        (
          await query(
            "SELECT 1 FROM certops_management_periods WHERE workspace_id=$1 AND managed_certificate_id=$2 AND ended_at IS NULL",
            [workspaceId, item.id],
          )
        ).rows.length,
        0,
      );
    }
    await resource.close();
    owned();
    fs.unlinkSync(guard);
    complete = true;
    const leaves = [...originals, ...updated];
    proof = {
      scope: SCOPE,
      client: "certbot",
      certificateIds,
      originalServingFingerprint: originalServingMaterial.fingerprint,
      originalServingSpki: originalServingMaterial.spki,
      originalServingProfileId: originalServingProfile.id,
      issueJobIds,
      jobIds: jobs,
      claimIds: claims,
      fingerprints: leaves.map((item) => item.fingerprint),
      serials: leaves.map((item) => item.serial),
      spkiFingerprints: leaves.map((item) => item.spki),
      ...Object.fromEntries(FLAGS.map((flag) => [flag, true])),
    };
    verifyProof(proof);
  } finally {
    await resource.close();
  }
  return proof;
}
module.exports = {
  SCOPE,
  SCENARIO,
  FLAGS,
  REQUIRED_SOURCES,
  verifyProof,
  verifyAdmission,
  qualifyBulk,
};
