/*
 * Qualification notes: stopped-offline-renewal-recovery
 * Shared setup, dispatch and evidence rules: docs/certops/e2e-qualification.md.
 * Separate Azure-free certops-windows-stop-offline.yml Server2022/2025 RSA2048 lane holds real public
 * renewal DNS after signed claim/CNG/journal; owned result gateway may hold exact outcome before API
 * forwarding. Stop installed service; actual persisted900s lease+600s offline threshold must pass with
 * default-clock reaper (unchanged1h alive grace not measured). Original attempt stays
 * orphaned_unknown_effect/reconciliation_required even after fresh successful renewal/new protected
 * leaf/trustedTLS. Genuine durable queued result is distinct from unresolved journal; later key
 * absence alone does not attribute startup cleanup. Read-only observer pins native query/synchronize
 * handles for measured host/descendants,never signals; require exit handles,fresh inventory,closed
 * handles/child before broad cleanup. Periodic observation is not atomic containment; report forced
 * timeout honestly. Nonce PostgreSQL cluster cleanup authority needs exact process/listener/argv/SQL
 * datadir; retain process handle,unlock PID receipt immediately before graceful stop so PG can update
 * it. Never adopt foreign cluster; keep uncertain private state. SIGBREAK Go mock is not SCM
 * session0/full renewal. Strict report requires original source/candidate/native SYSTEM/Server and
 * cleanup.
 */
"use strict";
/** Genuine public renewal interrupted by an owned installed-service stop.
 * The separate parent must await native/database cleanup before publishing
 * returned facts. This never resumes or reconciles the original orphan. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const tls = require("node:tls");
const { isDeepStrictEqual } = require("node:util");
const installed = require("./certops-windows-installed-paths");
const controls = require("./certops-windows-service-controls");
const activeControls = require("./certops-windows-active-service-controls");
const observer = require("./certops-windows-stop-observer-process");
const { classifyObservedStop } = require("./certops-windows-stop-observer");
const {
  reconcileAfterActualOfflineDeadline,
} = require("./certops-windows-stop-offline-reaper");
const contract = require("./certops-windows-stop-offline-proof");
const GUARD = ".installed-stop-offline-active";
const active = new Set();
const sha = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
function assertCleanupSafe(root) {
  assert.ok(
    !active.has(root) && !fs.existsSync(path.join(root, GUARD)),
    "Preserve unresolved installed stop/offline operation",
  );
  observer.assertCleanupSafe(root);
}
function readPrivate(file, maximum = 1048576) {
  const stat = fs.lstatSync(file, { bigint: true });
  assert.ok(
    stat.isFile() &&
      !stat.isSymbolicLink() &&
      stat.size > 0n &&
      stat.size <= BigInt(maximum),
  );
  assert.equal(
    path.win32.normalize(fs.realpathSync.native(file)).toLowerCase(),
    path.win32.normalize(file).toLowerCase(),
    "Private observation must remain at its original nonreparse path",
  );
  const descriptor = fs.openSync(
    file,
    fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0),
  );
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    assert.ok(
      before.isFile() &&
        before.dev === stat.dev &&
        before.ino === stat.ino &&
        before.size === stat.size,
    );
    const buffer = Buffer.alloc(Number(before.size) + 1);
    let used = 0;
    while (used < buffer.length) {
      const count = fs.readSync(
        descriptor,
        buffer,
        used,
        buffer.length - used,
        null,
      );
      if (!count) break;
      used += count;
    }
    const after = fs.fstatSync(descriptor, { bigint: true }),
      current = fs.lstatSync(file, { bigint: true });
    assert.ok(
      used === Number(before.size) &&
        after.dev === before.dev &&
        after.ino === before.ino &&
        after.size === before.size &&
        after.mtimeNs === before.mtimeNs &&
        after.ctimeNs === before.ctimeNs &&
        current.isFile() &&
        !current.isSymbolicLink() &&
        current.dev === before.dev &&
        current.ino === before.ino,
      "Private observation changed during retained-descriptor read",
    );
    return { bytes: buffer.subarray(0, used), stat: before };
  } finally {
    fs.closeSync(descriptor);
  }
}
function peer(c) {
  return new Promise((resolve, reject) => {
    let leaf, failed;
    const socket = tls.connect(controls.tlsOptions(c), () => {
      try {
        assert.equal(socket.authorized, true);
        leaf = new crypto.X509Certificate(socket.getPeerCertificate().raw);
      } catch {
        failed = true;
      }
      socket.end();
    });
    socket.setTimeout(10000, () =>
      socket.destroy(new Error("Owned stop/offline TLS timeout")),
    );
    socket.on("error", () => {
      failed = true;
    });
    socket.once("close", (hadError) =>
      leaf && !failed && !hadError
        ? resolve(leaf)
        : reject(new Error("Owned stop/offline TLS failed after drainage")),
    );
  });
}
function identityScript(pid) {
  assert.ok(Number.isSafeInteger(pid) && pid > 0 && pid <= 0xffffffff);
  return `$p=Get-CimInstance Win32_Process -Filter 'ProcessId=${pid}' -ErrorAction Stop;if(!$p -or !$p.ExecutablePath -or !$p.CommandLine){throw 'Complete native process required'};$h=[Security.Cryptography.SHA256]::Create();try{$digest=([BitConverter]::ToString($h.ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$p.CommandLine)))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()};@{pid=[int]$p.ProcessId;parentPid=[int]$p.ParentProcessId;createdAt=$p.CreationDate.ToUniversalTime().ToString('o');executable=[string]$p.ExecutablePath;commandSha256=$digest}|ConvertTo-Json -Compress`;
}
async function qualifyStoppedOffline(c) {
  assert.equal(process.platform, "win32");
  assert.equal(process.env.CERTOPS_WINDOWS_STOP_OFFLINE_REQUIRED, "1");
  assert.equal(
    process.env.CERTOPS_WINDOWS_KEY_PROFILE || "rsa-2048",
    "rsa-2048",
  );
  const {
    receipt,
    configDir,
    ps,
    powershell,
    run,
    pool,
    workspaceId,
    certificateId,
    agentId,
    profile,
    publicSession,
    ownedJobs,
    ownedObservers,
    waitUntil,
    armDns,
    releaseDns,
    barrierObserved,
    outputPrivacy,
  } = c;
  installed.assertOwnedRoot(receipt);
  assertCleanupSafe(receipt.root);
  assert.ok(Array.isArray(ownedJobs) && Array.isArray(ownedObservers));
  const marker = path.join(receipt.root, GUARD),
    markerBytes = crypto.randomBytes(32);
  active.add(receipt.root);
  fs.writeFileSync(marker, markerBytes, { flag: "wx", mode: 0o600 });
  const markerStat = fs.lstatSync(marker, { bigint: true });
  const expected = {
    host: path.join(receipt.root, "app/bin/tokentimer-agent-host-amd64.exe"),
    node: process.execPath,
    entry: path.join(receipt.root, "app/bin/tokentimer-agent.js"),
    config: configDir,
  };
  const processes = () => {
    installed.assertOwnedRoot(receipt);
    const value = JSON.parse(ps(installed.observationScript()));
    installed.validateObservation(value, expected);
    return value;
  };
  const protectedBytes = () =>
    ["config.json", "credential", "signing-key-pin.json"].map((name) =>
      sha(readPrivate(path.join(configDir, name)).bytes),
    );
  const profiles = async () =>
    (
      await pool.query(
        "SELECT cp.id,cp.name,cp.status,cp.issuer_id,cp.renew_before_days,cp.description,cp.key_mode,cp.source,cp.source_ref,cp.public_metadata FROM managed_certificates mc JOIN certificate_profiles cp ON cp.workspace_id=mc.workspace_id AND cp.id=mc.profile_id WHERE mc.workspace_id=$1 AND mc.id=$2",
        [workspaceId, certificateId],
      )
    ).rows;
  const agentRows = (
    await pool.query(
      "SELECT id,last_seen_at,uptime_seconds FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2",
      [workspaceId, agentId],
    )
  ).rows;
  assert.equal(agentRows.length, 1);
  const agentRowId = agentRows[0].id;
  const profileBefore = await profiles(),
    filesBefore = protectedBytes();
  assert.equal(profileBefore.length, 1);
  assert.ok(
    isDeepStrictEqual(profileBefore[0].public_metadata.renewalProfile, profile),
    "Actual stored profile required",
  );
  const initialLeaf = await peer(c);
  assert.ok(Date.parse(initialLeaf.validTo)-Date.now()>=1800000,"Serving certificate must remain valid throughout actual default-deadline recovery budget");
  assert.equal(initialLeaf.fingerprint.replaceAll(":", ""), c.thumbprint);
  const initialCustody = JSON.parse(ps(controls.custodyScript(c)));
  const createManual = async () => {
    const response = await publicSession.request(
      `/api/v1/workspaces/${workspaceId}/certops/jobs`,
      "POST",
      {
        operation: "renew",
        subjectType: "managed_certificate",
        subjectId: certificateId,
        assignedAgentId: agentRowId,
        idempotencyKey: crypto.randomUUID(),
        payload: { reason: "Owned stopped/offline renewal qualification" },
      },
    );
    if (response.body?.job?.id) ownedJobs.push(response.body.job.id);
    assert.equal(response.status, 201);
    assert.match(
      response.body.job.id,
      /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/,
    );
    return response.body.job.id;
  };
  const job = async (jobId) =>
    (
      await pool.query(
        "SELECT id,status,operation,mode,source,subject_id,claim_id,claimed_by_agent_id,attempt_count,payload,needs_operator_reconciliation FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",
        [workspaceId, jobId],
      )
    ).rows[0];
  armDns();
  const originalJobId = await createManual();
  const original = await waitUntil(async () => {
    const row = await job(originalJobId);
    if (["failed", "rejected", "cancelled", "succeeded"].includes(row?.status))
      throw new Error("Original renewal missed actual held DNS phase");
    return row?.status === "running" && barrierObserved() ? row : null;
  });
  const nonces = (
    await pool.query(
      "SELECT nonce FROM certops_consumed_nonces WHERE workspace_id=$1 AND job_id=$2 AND issued_to_agent_id=$3",
      [workspaceId, originalJobId, agentRowId],
    )
  ).rows;
  assert.equal(nonces.length, 1, "Exactly one actual signed dispatch required");
  const originalNonce = nonces[0].nonce;
  assert.ok(
    typeof originalNonce === "string" &&
      /^[A-Za-z0-9_.:-]{16,128}$/.test(originalNonce),
  );
  assert.equal(original.operation, "renew");
  assert.equal(original.mode, "real");
  assert.equal(original.source, "api");
  assert.equal(original.subject_id, certificateId);
  assert.equal(original.payload.certificateId, certificateId);
  assert.equal(original.claimed_by_agent_id, agentRowId);
  assert.equal(original.attempt_count, 1);
  assert.ok(
    isDeepStrictEqual(original.payload.renewalProfile, profile),
    "Original signed profile changed",
  );
  const journalDir = path.join(configDir, "job-journal");
  const journalMatches = fs
    .readdirSync(journalDir)
    .filter((name) => name.endsWith(".json"))
    .map((name) => {
      const file = path.join(journalDir, name),
        read = readPrivate(file);
      return { file, ...read, entry: JSON.parse(read.bytes) };
    })
    .filter(
      (value) =>
        value.entry.jobId === originalJobId &&
        value.entry.claimId === original.claim_id,
    );
  assert.equal(journalMatches.length, 1);
  const journal = journalMatches[0],
    container = journal.entry.windowsCngContainerName;
  activeControls.validatePendingContainer(container, original);
  const pendingBefore = JSON.parse(
    ps(activeControls.pendingKeyScript(container)),
  );
  assert.equal(pendingBefore.available, true);
  assert.equal(barrierObserved(), true);
  outputPrivacy.armResultBarrier(originalJobId, original.claim_id);
  assert.equal(
    outputPrivacy.resultBarrierObservation().claimId,
    original.claim_id,
  );
  const originalProcesses = processes();
  const ownerIdentity = JSON.parse(ps(identityScript(process.pid)));
  const hostIdentity = JSON.parse(ps(identityScript(originalProcesses.hostId)));
  const nodeIdentity = JSON.parse(
    ps(identityScript(originalProcesses.childId)),
  );
  const hostLog = path.join(configDir, "host.log"),
    logBefore = readPrivate(hostLog, 10485760);
  const stopObserver = await observer.startStopObservation({
    workDir: receipt.root,
    powershell,
    ownerIdentity,
    hostIdentity,
    nodeIdentity,
    commandRoots: [expected.host, expected.entry, configDir],
    onCreated: (resource) => ownedObservers.push(resource),
  });
  assert.equal(barrierObserved(), true);
  run("sc.exe", ["stop", "TokenTimerAgent"]);
  const stoppedNative = await stopObserver.waitForCompletion();
  const stoppedObservedAt = new Date().toISOString();
  const logAfter = readPrivate(hostLog, 10485760);
  assert.ok(
    logAfter.stat.dev === logBefore.stat.dev &&
      logAfter.stat.ino === logBefore.stat.ino &&
      logAfter.bytes.length >= logBefore.bytes.length,
    "Preserve changed installed host log",
  );
  const stopOutcome = classifyObservedStop(
    logAfter.bytes.subarray(logBefore.bytes.length).toString("utf8"),
    {
      nodePid: originalProcesses.childId,
      rootExitCode: stoppedNative.rootExitCode,
      nodeExitCode: stoppedNative.nodeExitCode,
    },
  );
  const stoppedServiceScript = `$s=Get-CimInstance Win32_Service -Filter "Name='TokenTimerAgent'" -ErrorAction Stop;if(!$s -or $s.State -cne 'Stopped' -or $s.ProcessId -ne 0){throw 'Exact installed service must remain stopped'};'stopped'`;
  const assertStopped = () => {
    installed.assertOwnedRoot(receipt);
    assert.equal(ps(stoppedServiceScript), "stopped");
  };
  await assertStopped();
  await releaseDns();
  await outputPrivacy.discardHeldResults();
  const retainedOriginal = () => {
    if (fs.existsSync(journal.file)) {
      const current = readPrivate(journal.file);
      const value = JSON.parse(current.bytes);
      assert.equal(value.jobId, originalJobId);
      assert.equal(value.claimId, original.claim_id);
      assert.ok(
        value.windowsCngContainerName === container,
        "Original native journal identity changed",
      );
      if (
        current.stat.dev === journal.stat.dev &&
        current.stat.ino === journal.stat.ino &&
        current.bytes.equals(journal.bytes)
      )
        return;
      // Production can replace/clear its journal on local terminal completion.
      // A changed object must instead have the actual durable outcome below;
      // matching JSON at a foreign pathname is not original-file authority.
    }
    const outbox = path.join(configDir, "outbox");
    assert.ok(
      fs.existsSync(outbox),
      "Original durable outcome or unresolved journal required",
    );
    const names = fs
      .readdirSync(outbox)
      .filter((name) => name.endsWith(".json"));
    assert.ok(names.length <= 128);
    const matches = names
      .map((name) => JSON.parse(readPrivate(path.join(outbox, name)).bytes))
      .filter(
        (entry) =>
          entry.result?.jobId === originalJobId &&
          entry.result?.claimId === original.claim_id &&
          entry.result?.nonce === originalNonce,
      );
    assert.equal(
      matches.length,
      1,
      "Exact original durable queued outcome required",
    );
  };
  retainedOriginal();
  const pendingAfter = JSON.parse(
    ps(activeControls.pendingKeyScript(container)),
  );
  if (pendingAfter.available)
    assert.ok(
      isDeepStrictEqual(pendingAfter, pendingBefore),
      "Preserve replaced pending native key",
    );
  assert.ok(
    isDeepStrictEqual(
      JSON.parse(ps(controls.custodyScript(c))),
      initialCustody,
    ),
    "Stopped service changed serving custody",
  );
  await activeControls.trustedBoundLeaf(c);
  const timingFacts = await reconcileAfterActualOfflineDeadline({
    pool,
    workspaceId,
    jobId: originalJobId,
    claimId: original.claim_id,
    agentRowId,
    assertStopped: async () => {
      await assertStopped();
      retainedOriginal();
    },
  });
  assert.ok(
    isDeepStrictEqual(protectedBytes(), filesBefore),
    "Stopped service changed protected installed files",
  );
  retainedOriginal();
  run("sc.exe", ["start", "TokenTimerAgent"]);
  const restartedObservedAt = new Date().toISOString();
  const restartedHeartbeat = await waitUntil(async () => {
    const row = (
      await pool.query(
        "SELECT status,last_seen_at,uptime_seconds FROM certops_agents WHERE workspace_id=$1 AND id=$2",
        [workspaceId, agentRowId],
      )
    ).rows[0];
    return row &&
      new Date(row.last_seen_at).getTime() >
        new Date(timingFacts.lastSeenAt).getTime() &&
      Number.isSafeInteger(Number(row.uptime_seconds))
      ? row
      : null;
  });
  await waitUntil(async () => {
    const row = (
      await pool.query(
        "SELECT status,last_seen_at,uptime_seconds FROM certops_agents WHERE workspace_id=$1 AND id=$2",
        [workspaceId, agentRowId],
      )
    ).rows[0];
    return row && controls.hasFreshHeartbeat(restartedHeartbeat, row);
  });
  const restarted = processes();
  assert.ok(
    restarted.hostId !== originalProcesses.hostId ||
      restarted.hostCreation !== originalProcesses.hostCreation,
  );
  assert.ok(
    restarted.childId !== originalProcesses.childId ||
      restarted.childCreation !== originalProcesses.childCreation,
  );
  await waitUntil(
    () =>
      ps(
        `[string][Security.Cryptography.CngKey]::Exists('${container}',[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider,[Security.Cryptography.CngKeyOpenOptions]::MachineKey)`,
      ) === "False",
  );
  const freshJobId = await createManual();
  const fresh = await waitUntil(async () => {
    const row = await job(freshJobId);
    if (
      ["failed", "rejected", "cancelled", "orphaned_unknown_effect"].includes(
        row?.status,
      )
    )
      throw new Error("Fresh independent renewal failed");
    return row?.status === "succeeded" ? row : null;
  });
  assert.equal(fresh.claimed_by_agent_id, agentRowId);
  assert.equal(fresh.attempt_count, 1);
  assert.equal(fresh.operation, "renew");
  assert.equal(fresh.mode, "real");
  assert.equal(fresh.source, "api");
  assert.equal(fresh.subject_id, certificateId);
  assert.ok(
    isDeepStrictEqual(fresh.payload.renewalProfile, profile),
    "Fresh signed profile changed",
  );
  assert.notEqual(fresh.claim_id, original.claim_id);
  const latestLeaf = await peer(c),
    latestThumbprint = latestLeaf.fingerprint.replaceAll(":", "");
  assert.notEqual(sha(latestLeaf.raw), sha(initialLeaf.raw));
  assert.notEqual(latestLeaf.serialNumber, initialLeaf.serialNumber);
  assert.ok(Date.parse(latestLeaf.validTo) > Date.parse(initialLeaf.validTo));
  const spki = (leaf) =>
    sha(leaf.publicKey.export({ type: "spki", format: "der" }));
  assert.notEqual(spki(latestLeaf), spki(initialLeaf));
  const latestCustody = JSON.parse(
    ps(controls.custodyScript({ ...c, thumbprint: latestThumbprint })),
  );
  assert.ok(
    latestCustody.unique !== initialCustody.unique &&
      latestCustody.container !== initialCustody.container,
    "Fresh protected CNG custody required",
  );
  assert.equal(
    latestCustody.provider,
    "Microsoft Software Key Storage Provider",
  );
  assert.equal(latestCustody.bits, 2048);
  const verified = (
    await pool.query(
      "SELECT e.metadata FROM certificate_evidence e JOIN certificate_jobs j ON j.workspace_id=e.workspace_id AND j.id=e.job_id WHERE e.workspace_id=$1 AND e.job_id=$2 AND e.claim_id=j.claim_id AND e.evidence_type='validation.passed' AND e.metadata->>'step'='verify'",
      [workspaceId, freshJobId],
    )
  ).rows;
  assert.ok(
    verified.some(
      (row) =>
        String(row.metadata.fingerprintSha256)
          .replaceAll(":", "")
          .toLowerCase() === sha(latestLeaf.raw),
    ),
    "Actual fresh current-claim trusted leaf evidence required",
  );
  await waitUntil(async () => {
    const current = (
      await pool.query(
        "SELECT fingerprint_sha256,not_after,profile_id FROM managed_certificates WHERE workspace_id=$1 AND id=$2",
        [workspaceId, certificateId],
      )
    ).rows[0];
    return (
      current &&
      String(current.fingerprint_sha256).replaceAll(":", "").toLowerCase() ===
        sha(latestLeaf.raw) &&
      new Date(current.not_after).getTime() ===
        Date.parse(latestLeaf.validTo) &&
      current.profile_id === profileBefore[0].id
    );
  });
  const orphan = await job(originalJobId);
  assert.equal(orphan.status, "orphaned_unknown_effect");
  assert.equal(orphan.needs_operator_reconciliation, true);
  assert.equal(orphan.attempt_count, 1);
  assert.ok(
    isDeepStrictEqual(await profiles(), profileBefore),
    "Independent renewal changed stored profile",
  );
  assert.ok(
    isDeepStrictEqual(protectedBytes(), filesBefore),
    "Independent renewal changed installed credentials or configuration",
  );
  const currentMarker = readPrivate(marker, 32);
  assert.ok(
    currentMarker.stat.dev === markerStat.dev &&
      currentMarker.stat.ino === markerStat.ino &&
      currentMarker.bytes.equals(markerBytes),
  );
  fs.unlinkSync(marker);
  active.delete(receipt.root);
  const facts = {
    scope: contract.SCOPE,
    originalJobId,
    originalClaimId: original.claim_id,
    freshJobId,
    stopOutcome,
    capturedProcessCount: stoppedNative.capturedProcessCount,
    originalAttemptCount: 1,
    originalTerminalStatus: orphan.status,
    ...timingFacts,
    stoppedObservedAt,
    restartedObservedAt,
    freshRenewalObservedAt: new Date().toISOString(),
    atomicTreeContainmentQualified: false,
    originalOperationAutomaticallyRecovered: false,
    fingerprints: [sha(initialLeaf.raw), sha(latestLeaf.raw)],
    spkiFingerprints: [spki(initialLeaf), spki(latestLeaf)],
    ...Object.fromEntries(
      contract.FLAGS.map((name) => [
        name,
        name !== "exactOwnedCleanupCompleted",
      ]),
    ),
  };
  return { facts, latestThumbprint, latestLeaf };
}
module.exports = {
  GUARD,
  assertCleanupSafe,
  qualifyStoppedOffline,
  identityScript,
  readPrivate,
};
