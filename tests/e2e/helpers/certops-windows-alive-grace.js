/*
 * Qualification notes: alive-agent-default-hard-grace
 * Shared setup, dispatch and evidence rules: docs/certops/e2e-qualification.md.
 * Use the separate Azure-free Server2022/2025 RSA2048 lane. Hold the exact successful signed renewal
 * result behind HTTP503 before forwarding, with claim polling held and healthy authenticated
 * heartbeats; do not alter ACME results or clocks. A genuine pre-ACME command barrier follows CNG
 * creation. Persisted lease900s and unchanged hard grace3600s must actually elapse before the
 * default-clock reaper changes the original attempt to orphaned_unknown_effect; heartbeat-only uptime
 * must advance at both observations. Wait for a stable real lease before freezing its timestamps
 * because an in-flight request can finish. Preserve reconciliation after any later renewal. Production
 * outbox backoff starts15s, caps base30min with20% jitter; polling is not retry cadence. Periodic
 * discovery is disabled to observe child absence, so simultaneous discovery/deployed worker scheduling
 * remain outside scope. Cleanup retains original native handles before SCM stop and requires
 * descendant drainage, closed handles and stopped service; this is bounded ownership, not atomic
 * containment.
 */
"use strict";
/** Source-only composition for a separate manual alive/default-grace lane.
 * A completed genuine native mutation remains an unresolved API orphan; this
 * does not recover it, shorten time, or qualify a deployed worker loop. */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto"),
  tls = require("node:tls"),
  { isDeepStrictEqual } = require("node:util");
const installed = require("./certops-windows-installed-paths"),
  controls = require("./certops-windows-service-controls"),
  native = require("./certops-windows-installed-verify-rollback"),
  reaper = require("./certops-windows-alive-grace-reaper"),
  proof = require("./certops-windows-alive-grace-proof");
const sha = (b) => crypto.createHash("sha256").update(b).digest("hex"),
  UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
function verifyDurableSuccess(entry, job, nonce) {
  assert.ok(entry && entry.result);
  assert.match(nonce, /^[A-Za-z0-9_.:-]{16,128}$/);
  assert.match(job.id, UUID);
  assert.match(job.claim_id, UUID);
  assert.equal(entry.result.jobId, job.id);
  assert.equal(entry.result.claimId, job.claim_id);
  assert.equal(entry.result.nonce, nonce);
  assert.equal(entry.result.status, "succeeded");
  assert.ok(Array.isArray(entry.evidence));
  return entry;
}
function ownedCommandScript({
  barrier,
  originalChildId,
  childArgv,
  parentArgv,
}) {
  for (const value of [barrier.pid, barrier.parentPid, originalChildId])
    assert.ok(Number.isSafeInteger(value) && value > 0 && value <= 0xffffffff);
  for (const argv of [childArgv, parentArgv])
    assert.ok(
      Array.isArray(argv) &&
        argv.length >= 2 &&
        argv.every((v) => typeof v === "string" && !v.includes("\0")),
    );
  const encoded = Buffer.from(
    JSON.stringify({ childArgv, parentArgv }),
  ).toString("base64");
  return `$ErrorActionPreference='Stop'
$null=& {${installed.observationScript()}}
$p=Get-CimInstance Win32_Process -Filter 'ProcessId=${barrier.pid}'
$parent=Get-CimInstance Win32_Process -Filter 'ProcessId=${barrier.parentPid}'
if(!$p -or !$parent -or $p.ParentProcessId -ne $parent.ProcessId -or $parent.ParentProcessId -ne ${originalChildId} -or $p.CreationDate -lt $parent.CreationDate){throw 'Actual owned command ancestry required'}
$e=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${encoded}'))|ConvertFrom-Json
foreach($pair in @(@{process=$p;argv=$e.childArgv},@{process=$parent;argv=$e.parentArgv})){
 $sid=Invoke-CimMethod -InputObject $pair.process -MethodName GetOwnerSid
 if($sid.Sid -ne 'S-1-5-18' -or $pair.process.ExecutablePath -ine $pair.argv[0]){throw 'Actual owned SYSTEM Node required'}
 $a=@([CertOpsPathArgv]::Parse($pair.process.CommandLine));$expected=@($pair.argv)
 if($a.Count -ne $expected.Count){throw 'Exact owned command argv required'}
 for($i=0;$i -lt $a.Count;$i++){if(($i -eq 0 -and $a[$i] -ine $expected[$i]) -or ($i -ne 0 -and $a[$i] -cne $expected[$i])){throw 'Exact owned command argv required'}}
}
`;
}
function peer(c) {
  return new Promise((resolve, reject) => {
    let leaf,
      failed = false;
    const s = tls.connect(controls.tlsOptions(c), () => {
      try {
        assert.equal(s.authorized, true);
        leaf = new crypto.X509Certificate(s.getPeerCertificate().raw);
      } catch {
        failed = true;
      }
      s.end();
    });
    s.setTimeout(10000, () => s.destroy());
    s.on("error", () => {
      failed = true;
    });
    s.once("close", (hadError) =>
      leaf && !failed && !hadError
        ? resolve(leaf)
        : reject(Error("Owned alive-grace TLS observation failed after drain")),
    );
  });
}
async function qualifyAliveGrace(c) {
  assert.equal(process.platform, "win32");
  assert.equal(process.env.CERTOPS_WINDOWS_ALIVE_GRACE_REQUIRED, "1");
  assert.equal(
    process.env.CERTOPS_WINDOWS_KEY_PROFILE || "rsa-2048",
    "rsa-2048",
  );
  for (const name of [
    "CERTOPS_JOB_LEASE_SECONDS",
    "CERTOPS_LEASE_HARD_GRACE_MS",
    "CERTOPS_AGENT_OFFLINE_AFTER_MS",
    "TOKENTIMER_AGENT_POLL_MS",
  ])
    assert.equal(
      process.env[name],
      undefined,
      "Unmodified production timing defaults required",
    );
  installed.assertOwnedRoot(c.receipt);
  assert.equal(c.receipt.historicalSupportingOnly, false);
  const owner = native.beginGuard(c.receipt.root, c.ownedShadows),
    { pool, workspaceId, certificateId, agentId, configDir, ps } = c;
  const originalConfig = native.readOwned(
      path.join(configDir, "config.json"),
      65536,
    ),
    parsed = JSON.parse(originalConfig.bytes);
  assert.equal(
    Object.hasOwn(parsed, "pollIntervalMs"),
    false,
    "Separate lane must use actual production polling default",
  );
  assert.equal(
    parsed.windowsDiscovery?.enabled,
    false,
    "Separate lane disables periodic discovery so completed operation child absence is observable",
  );
  const protectedFiles = [
    "config.json",
    "credential",
    "signing-key-pin.json",
  ].map((name) => {
    const file = path.join(configDir, name),
      r = native.readOwned(file, 65536);
    return { file, bytes: r.bytes, dev: r.stat.dev, ino: r.stat.ino };
  });
  const expected = {
    host: path.join(c.receipt.root, "app/bin/tokentimer-agent-host-amd64.exe"),
    node: process.execPath,
    entry: path.join(c.receipt.root, "app/bin/tokentimer-agent.js"),
    config: configDir,
  };
  const observe = () => {
      owner.check();
      installed.assertOwnedRoot(c.receipt);
      const v = JSON.parse(ps(installed.observationScript()));
      installed.validateObservation(v, expected);
      return v;
    },
    processBefore = observe();
  const originalHostIdentity = JSON.parse(
      ps(
        require("./certops-windows-stop-offline").identityScript(
          processBefore.hostId,
        ),
      ),
    ),
    originalNodeIdentity = JSON.parse(
      ps(
        require("./certops-windows-stop-offline").identityScript(
          processBefore.childId,
        ),
      ),
    );
  assert.ok(
    isDeepStrictEqual(observe(), processBefore),
    "Original installed identity must remain stable during capture",
  );
  assert.equal(
    processBefore.environment.some((v) =>
      /^TOKENTIMER_AGENT_POLL_MS=/i.test(v),
    ),
    false,
  );
  const agent = (
    await pool.query(
      "SELECT id FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2",
      [workspaceId, agentId],
    )
  ).rows;
  assert.equal(agent.length, 1);
  const agentRowId = agent[0].id;
  const job = async (id) =>
    (
      await pool.query(
        "SELECT j.id,j.status,j.operation,j.mode,j.source,j.subject_id,j.claim_id,j.claimed_by_agent_id,j.attempt_count,j.payload,j.needs_operator_reconciliation,a.agent_id FROM certificate_jobs j LEFT JOIN certops_agents a ON a.id=j.claimed_by_agent_id AND a.workspace_id=j.workspace_id WHERE j.workspace_id=$1 AND j.id=$2",
        [workspaceId, id],
      )
    ).rows[0];
  const profiles = async () =>
    (
      await pool.query(
        "SELECT cp.id,cp.name,cp.status,cp.issuer_id,cp.renew_before_days,cp.description,cp.key_mode,cp.source,cp.source_ref,cp.public_metadata FROM managed_certificates mc JOIN certificate_profiles cp ON cp.workspace_id=mc.workspace_id AND cp.id=mc.profile_id WHERE mc.workspace_id=$1 AND mc.id=$2",
        [workspaceId, certificateId],
      )
    ).rows;
  const profileBefore = await profiles();
  assert.equal(profileBefore.length, 1);
  assert.ok(
    isDeepStrictEqual(
      profileBefore[0].public_metadata.renewalProfile,
      c.profile,
    ),
    "Actual stored execution profile required",
  );
  const oldNative = JSON.parse(
    ps(native.nativeCertificateScript(c.thumbprint)),
  );
  const oldLeaf = await peer(c);
  assert.equal(oldLeaf.fingerprint.replaceAll(":", ""), c.thumbprint);
  assert.ok(
    Date.parse(oldLeaf.validTo) - Date.now() > 6000000,
    "Actual predecessor validity must cover full default-grace fixture",
  );
  c.commandBarrier.arm();
  const response = await c.publicSession.request(
    `/api/v1/workspaces/${workspaceId}/certops/jobs`,
    "POST",
    {
      operation: "renew",
      subjectType: "managed_certificate",
      subjectId: certificateId,
      assignedAgentId: agentRowId,
      idempotencyKey: crypto.randomUUID(),
    },
  );
  if (response.body?.job?.id) c.ownedJobs.push(response.body.job.id);
  assert.equal(response.status, 201);
  const jobId = response.body.job.id;
  assert.match(jobId, UUID);
  const running = await c.waitUntil(async () => {
    const r = await job(jobId);
    if (["succeeded", "failed", "rejected", "cancelled"].includes(r?.status))
      throw Error("Actual native command barrier missed");
    return r?.status === "running" && c.commandBarrier.observe() ? r : null;
  });
  native.validateClaim(running, c);
  assert.ok(
    isDeepStrictEqual(running.payload.renewalProfile, c.profile),
    "Original signed execution profile changed",
  );
  assert.equal(running.claimed_by_agent_id, agentRowId);
  const nonces = (
    await pool.query(
      "SELECT nonce FROM certops_consumed_nonces WHERE workspace_id=$1 AND job_id=$2 AND issued_to_agent_id=$3",
      [workspaceId, jobId, agentRowId],
    )
  ).rows;
  assert.equal(nonces.length, 1);
  const nonce = nonces[0].nonce;
  c.resultGateway.arm(jobId, running.claim_id);
  const barrier = c.commandBarrier.observe();
  ps(
    ownedCommandScript({
      barrier,
      originalChildId: processBefore.childId,
      childArgv: c.commandBarrier.argv,
      parentArgv: c.outputPrivacy.argv,
    }),
  );
  const pending = require("./certops-windows-active-service-controls"),
    journalDir = path.join(configDir, "job-journal");
  const journals = fs
    .readdirSync(journalDir)
    .filter((n) => n.endsWith(".json"))
    .map((n) =>
      JSON.parse(native.readOwned(path.join(journalDir, n), 65536).bytes),
    )
    .filter((j) => j.jobId === jobId && j.claimId === running.claim_id);
  assert.equal(journals.length, 1);
  pending.validatePendingContainer(
    journals[0].windowsCngContainerName,
    running,
  );
  assert.equal(
    JSON.parse(
      ps(pending.pendingKeyScript(journals[0].windowsCngContainerName)),
    ).available,
    true,
  );
  c.commandBarrier.release();
  const outbox = path.join(configDir, "outbox");
  const readOutbox = () =>
    fs
      .readdirSync(outbox)
      .filter((n) => n.endsWith(".json"))
      .map((n) =>
        JSON.parse(native.readOwned(path.join(outbox, n), 524288).bytes),
      )
      .filter((e) => e.result?.jobId === jobId);
  const completed = await c.waitUntil(() => {
    if (c.resultGateway.observation().refusedResults < 1) return null;
    const entries = readOutbox();
    assert.ok(entries.length <= 1);
    return entries[0] && verifyDurableSuccess(entries[0], running, nonce);
  });
  const records = fs
    .readdirSync(path.join(configDir, "windows-cert-store/issued-containers"))
    .filter((n) => n.endsWith(".json"))
    .map((n) =>
      JSON.parse(
        native.readOwned(
          path.join(configDir, "windows-cert-store/issued-containers", n),
          8192,
        ).bytes,
      ),
    )
    .filter((r) => r.jobId === jobId);
  assert.equal(records.length, 1);
  const record = records[0];
  native.validateIssued(
    record,
    jobId,
    certificateId,
    record.acceptedThumbprint,
  );
  const accepted = JSON.parse(
      ps(native.nativeCertificateScript(record.acceptedThumbprint)),
    ),
    leaf = new crypto.X509Certificate(Buffer.from(accepted.der, "base64"));
  assert.ok(
    accepted.container === record.containerName,
    "Actual accepted key ownership required",
  );
  assert.equal(leaf.checkHost(c.domain), c.domain);
  assert.notEqual(sha(leaf.raw), sha(oldLeaf.raw));
  assert.notEqual(
    sha(leaf.publicKey.export({ type: "spki", format: "der" })),
    sha(oldLeaf.publicKey.export({ type: "spki", format: "der" })),
  );
  assert.ok(
    Date.parse(leaf.validTo) - Date.now() > 6000000,
    "Actual accepted leaf validity must cover default-grace window",
  );
  const verifyEvidence = async () => {
    const rows = (
      await pool.query(
        "SELECT metadata FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2 AND claim_id=$3 AND evidence_type='validation.passed' AND metadata->>'step'='verify'",
        [workspaceId, jobId, running.claim_id],
      )
    ).rows;
    assert.ok(
      rows.some(
        (row) =>
          String(row.metadata.fingerprintSha256)
            .replaceAll(":", "")
            .toLowerCase() === sha(leaf.raw),
      ),
      "Actual signed current-claim native verification required",
    );
  };
  await verifyEvidence();
  c.commandBarrier.finish();
  const nativeCompletedAt = new Date().toISOString(),
    custody = JSON.parse(
      ps(
        controls.custodyScript({ ...c, thumbprint: record.acceptedThumbprint }),
      ),
    ),
    site = JSON.parse(ps(native.nativeSiteScript(c.site, c.domain, c.port)));
  assert.equal(site.thumb, record.acceptedThumbprint);
  const assertAliveAndCustody = async () => {
    owner.check();
    assert.ok(
      isDeepStrictEqual(await profiles(), profileBefore),
      "Operator profile changed during default grace",
    );
    assert.ok(
      isDeepStrictEqual(
        JSON.parse(ps(native.nativeCertificateScript(c.thumbprint))),
        oldNative,
      ),
      "Original predecessor private custody changed",
    );
    assert.ok(
      isDeepStrictEqual(
        JSON.parse(
          ps(native.nativeCertificateScript(record.acceptedThumbprint)),
        ),
        accepted,
      ),
      "Accepted private possession changed",
    );
    assert.ok(
      isDeepStrictEqual(observe(), processBefore),
      "Original installed process tuple changed",
    );
    assert.equal(
      ps(
        `@(Get-CimInstance Win32_Process -Filter 'ParentProcessId=${processBefore.childId}').Count`,
      ),
      "0",
      "Completed execution must have no current native child",
    );
    for (const f of protectedFiles) {
      const r = native.readOwned(f.file, 65536);
      assert.ok(
        r.stat.dev === f.dev && r.stat.ino === f.ino && r.bytes.equals(f.bytes),
        "Original protected agent state changed",
      );
    }
    const entries = readOutbox();
    assert.equal(entries.length, 1);
    verifyDurableSuccess(entries[0], running, nonce);
    assert.ok(
      isDeepStrictEqual(entries[0].result, completed.result),
      "Original durable result changed",
    );
    assert.equal(c.resultGateway.observation().forwardedResults, 0);
    assert.equal(c.resultGateway.observation().mismatchedResults, 0);
    assert.ok(
      isDeepStrictEqual(
        JSON.parse(
          ps(
            controls.custodyScript({
              ...c,
              thumbprint: record.acceptedThumbprint,
            }),
          ),
        ),
        custody,
      ),
      "Accepted native custody changed",
    );
    assert.ok(
      isDeepStrictEqual(
        JSON.parse(ps(native.nativeSiteScript(c.site, c.domain, c.port))),
        site,
      ),
      "Actual IIS endpoint changed",
    );
    assert.equal(sha((await peer(c)).raw), sha(leaf.raw));
  };
  await assertAliveAndCustody();
  const measured = await reaper.reconcileAfterActualAliveGrace({
    pool,
    workspaceId,
    jobId,
    claimId: running.claim_id,
    agentRowId,
    assertAliveAndCustody,
  });
  const original = await job(jobId);
  assert.equal(original.status, "orphaned_unknown_effect");
  assert.equal(original.needs_operator_reconciliation, true);
  assert.equal(original.attempt_count, 1);
  await verifyEvidence();
  // Keep exact result503 until ordinary parent service drainage. No late result
  // ACK, original reconciliation, or post-reaper renewal is invented here.
  // Pin original native identities before ordinary SCM stop; uncertain drainage
  // preserves the fixture instead of authorizing certificate/key cleanup.
  const stopped = require("./certops-windows-stop-offline"),
    observer = require("./certops-windows-stop-observer-process");
  const ownerIdentity = JSON.parse(ps(stopped.identityScript(process.pid))),
    hostIdentity = JSON.parse(ps(stopped.identityScript(processBefore.hostId))),
    nodeIdentity = JSON.parse(
      ps(stopped.identityScript(processBefore.childId)),
    );
  assert.ok(
    isDeepStrictEqual(hostIdentity, originalHostIdentity) &&
      isDeepStrictEqual(nodeIdentity, originalNodeIdentity),
    "Original native identities must remain unchanged before stop",
  );
  assert.ok(
    isDeepStrictEqual(observe(), processBefore),
    "Original SCM tuple must remain unchanged before stop",
  );
  const retained = await observer.startStopObservation({
    workDir: c.receipt.root,
    powershell: c.powershell,
    ownerIdentity,
    hostIdentity,
    nodeIdentity,
    commandRoots: [expected.host, expected.entry, configDir],
    onCreated: (resource) => c.ownedObservers.push(resource),
  });
  c.run("sc.exe", ["stop", "TokenTimerAgent"]);
  await retained.waitForCompletion();
  assert.equal(
    ps(
      "$s=Get-CimInstance Win32_Service -Filter \"Name='TokenTimerAgent'\" -ErrorAction Stop;if(!$s -or $s.State -cne 'Stopped' -or $s.ProcessId -ne 0){throw 'Exact installed service must remain stopped'};'stopped'",
    ),
    "stopped",
  );
  owner.release();
  return {
    facts: {
      scope: proof.SCOPE,
      jobId,
      claimId: running.claim_id,
      attemptCount: 1,
      terminalStatus: original.status,
      atomicTreeContainmentQualified: false,
      claimPollingAvailabilityQualified: false,
      fingerprints: [sha(oldLeaf.raw), sha(leaf.raw)],
      spkiFingerprints: [
        sha(oldLeaf.publicKey.export({ type: "spki", format: "der" })),
        sha(leaf.publicKey.export({ type: "spki", format: "der" })),
      ],
      defaultLeaseMs: 900000,
      defaultHardGraceMs: 3600000,
      defaultOfflineMs: 600000,
      nativeCompletedAt,
      ...measured,
      ...Object.fromEntries(
        proof.FLAGS.map((f) => [f, f !== "exactOwnedCleanupCompleted"]),
      ),
    },
    latestLeaf: leaf,
    latestThumbprint: record.acceptedThumbprint,
  };
}
module.exports = {
  verifyDurableSuccess,
  ownedCommandScript,
  qualifyAliveGrace,
  assertCleanupSafe: native.assertCleanupSafe,
};
