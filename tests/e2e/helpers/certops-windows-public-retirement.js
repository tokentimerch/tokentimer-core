"use strict";
/** Public idle retirement of the existing installed Windows agent. Real HTTP
 * authorization/idempotency and native SCM exit/custody observations are needed;
 * this source does not force-retire active jobs or manufacture lease state. */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto"),
  tls = require("node:tls"),
  { isDeepStrictEqual } = require("node:util");
const installed = require("./certops-windows-installed-paths"),
  scm = require("./certops-windows-service-controls");
const SCOPE = "public-idle-installed-windows-agent-retirement";
const SCENARIO = "windows-installed-public-idle-retirement";
const FLAGS = Object.freeze([
  "sameOwnedSystemRuntimeBeforeRetirement",
  "anonymousAndViewerRefused",
  "authorizedManagerPublicRetirement",
  "sameActorAppendOnlyAudit",
  "idempotentWithoutDuplicateAudit",
  "actualAuthenticatedRetirementExit86",
  "nativeScmCleanExitZero",
  "measuredNoRespawnWindow",
  "capturedHostAndChildAbsent",
  "nativeCustodyAndTrustedTlsPreserved",
  "credentialConfigurationAndPinPreserved",
  "noJobClaimMutation",
  "ownedRetirementGuardCleared",
]);
const REQUIRED_SOURCES = Object.freeze([
  "tests/e2e/helpers/certops-windows-public-retirement.js",
  "tests/e2e/helpers/certops-windows-service-controls.js",
  "tests/e2e/helpers/certops-windows-installed-paths.js",
  "tests/e2e/helpers/certops-api-fixture.js",
  "tests/e2e/windows-real-journey.js",
  "apps/api/routes/certops.js",
  "apps/api/index.js",
  "apps/api/services/rbac.js",
  "apps/api/services/audit.js",
  "apps/api/middleware/auth.js",
  "apps/api/middleware/workspace-access-policy.js",
  "apps/api/services/certops/agentRegistry.js",
  "apps/api/services/certops/jobs.js",
  "apps/api/services/certops/agentDispatch.js",
  "packages/agent/src/index.js",
  "packages/agent/windows-service-host/service_windows.go",
]);
const GUARD = ".installed-public-retirement-active.json",
  active = new Set(),
  owner = (root) => path.resolve(root).toLowerCase();
function verifyProof(p) {
  assert.ok(p && typeof p === "object" && !Array.isArray(p));
  assert.deepEqual(
    Object.keys(p).sort(),
    [
      "scope",
      "inFlightRetirementQualified",
      "anonymousStatus",
      "viewerStatus",
      "managerStatus",
      "replayStatus",
      "retirementAuditCount",
      "noRespawnObservedMs",
      ...FLAGS,
    ].sort(),
  );
  assert.equal(p.scope, SCOPE);
  assert.equal(p.inFlightRetirementQualified, false);
  for (const [key, value] of Object.entries({
    anonymousStatus: 401,
    viewerStatus: 403,
    managerStatus: 200,
    replayStatus: 200,
    retirementAuditCount: 1,
  }))
    assert.equal(p[key], value);
  assert.ok(
    Number.isSafeInteger(p.noRespawnObservedMs) &&
      p.noRespawnObservedMs >= 5000 &&
      p.noRespawnObservedMs <= 30000,
  );
  for (const flag of FLAGS) assert.equal(p[flag], true, flag);
  return true;
}
function assertCleanupSafe(root) {
  assert.ok(
    !active.has(owner(root)) && !fs.existsSync(path.join(root, GUARD)),
    "Preserve unresolved public retirement native state",
  );
}
function verifyPublicResult(value, expectedStatus) {
  assert.equal(
    value.status,
    expectedStatus,
    "Unexpected public retirement admission result",
  );
  if (expectedStatus === 403)
    assert.equal(value.body.code, "INSUFFICIENT_ROLE");
}
function verifyIdleJobs(rows) {
  assert.ok(Array.isArray(rows) && rows.length <= 1000);
  const terminal = new Set([
    "rejected",
    "succeeded",
    "failed",
    "cancelled",
    "dry_run_complete",
    "orphaned_unknown_effect",
  ]);
  assert.ok(
    rows.every((row) => row && terminal.has(row.status)),
    "Public idle retirement requires terminal-only certificate job inventory",
  );
}
function retirementObserved(fresh) {
  assert.equal(typeof fresh, "string");
  assert.ok(Buffer.byteLength(fresh, "utf8") <= 4194304);
  return /retirement code \(86\)/.test(fresh);
}
function peer(c) {
  return new Promise((resolve, reject) => {
    let fingerprint;
    const socket = tls.connect(scm.tlsOptions(c), () => {
      const leaf = socket.getPeerCertificate().raw;
      if (!socket.authorized || !Buffer.isBuffer(leaf)) {
        socket.destroy(new Error("Owned TLS leaf unavailable"));
        return;
      }
      fingerprint = crypto.createHash("sha256").update(leaf).digest("hex");
      socket.end();
    });
    socket.setTimeout(10000, () =>
      socket.destroy(new Error("Public retirement TLS deadline")),
    );
    socket.once("error", () =>
      reject(new Error("Public retirement trusted TLS failed")),
    );
    socket.once("close", (bad) =>
      !bad && fingerprint
        ? resolve(fingerprint)
        : reject(new Error("Public retirement TLS drainage unproven")),
    );
  });
}
async function until(check, label) {
  const start = performance.now();
  do {
    const value = await check();
    if (value) return value;
    await new Promise((resolve) => setTimeout(resolve, 200));
  } while (performance.now() - start < 30000);
  throw new Error(`Public retirement observation timed out: ${label}`);
}
async function qualifyPublicRetirement(c) {
  assert.equal(process.platform, "win32");
  const {
    receipt,
    configDir,
    publicSession: session,
    pool,
    workspaceId,
    agentId,
    ps,
    baseUrl,
  } = c;
  installed.assertOwnedRoot(receipt);
  assert.equal(receipt.historicalSupportingOnly, false);
  assertCleanupSafe(receipt.root);
  const guard = path.join(receipt.root, GUARD),
    guardBytes = Buffer.from(
      JSON.stringify({ schemaVersion: 1, nonce: crypto.randomUUID() }),
    );
  active.add(owner(receipt.root));
  fs.writeFileSync(guard, guardBytes, { flag: "wx", mode: 0o600 });
  const guardStat = fs.lstatSync(guard, { bigint: true });
  assert.ok(
    guardStat.isFile() && !guardStat.isSymbolicLink() && guardStat.ino > 0n,
  );
  const expected = {
    host: path.join(receipt.root, "app/bin/tokentimer-agent-host-amd64.exe"),
    node: process.execPath,
    entry: path.join(receipt.root, "app/bin/tokentimer-agent.js"),
    config: configDir,
  };
  const runtime = JSON.parse(ps(installed.observationScript()));
  installed.validateObservation(runtime, expected);
  const credentials = ["config.json", "credential", "signing-key-pin.json"].map(
    (file) => path.join(configDir, file),
  );
  const hashes = () =>
    credentials.map((file) =>
      crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex"),
    );
  const originalHashes = hashes();
  const custody = () => JSON.parse(ps(scm.custodyScript(c))),
    originalCustody = custody(),
    originalPeer = await peer(c);
  const agent = async () => {
    const rows = (
      await pool.query(
        "SELECT id,agent_id,status,retired_at,retired_by_user_id,retire_reason FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2",
        [workspaceId, agentId],
      )
    ).rows;
    assert.equal(rows.length, 1);
    return rows[0];
  };
  const initial = await until(async () => {
    const value = await agent();
    return value.status === "active" ? value : false;
  }, "healthy registered agent");
  const jobs = async () => {
    const rows = (
      await pool.query(
        "SELECT id,status,claim_id,attempt_count FROM certificate_jobs WHERE workspace_id=$1 ORDER BY id LIMIT 1001",
        [workspaceId],
      )
    ).rows;
    assert.ok(rows.length <= 1000);
    return rows;
  };
  const originalJobs = await jobs();
  verifyIdleJobs(originalJobs);
  const audit = async () =>
    (
      await pool.query(
        "SELECT actor_user_id,metadata FROM audit_events WHERE workspace_id=$1 AND action='CERTOPS_AGENT_RETIRED' AND metadata->>'agentId'=$2 ORDER BY id LIMIT 3",
        [workspaceId, agentId],
      )
    ).rows;
  assert.equal((await audit()).length, 0);
  const roleRows = (
    await pool.query(
      "SELECT role FROM workspace_memberships WHERE workspace_id=$1 AND user_id=$2",
      [workspaceId, session.userId],
    )
  ).rows;
  assert.equal(roleRows.length, 1);
  assert.equal(roleRows[0].role, "workspace_manager");
  const route = `/api/v1/workspaces/${workspaceId}/certops/agents/${initial.id}/retire`;
  let originalRoleRestored = false;
  try {
    const anonymous = await fetch(new URL(route, baseUrl), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ force: false }),
      signal: AbortSignal.timeout(10000),
    });
    verifyPublicResult({ status: anonymous.status }, 401);
    await anonymous.body?.cancel();
    await pool.query(
      "UPDATE workspace_memberships SET role='viewer' WHERE workspace_id=$1 AND user_id=$2",
      [workspaceId, session.userId],
    );
    const viewer = await session.request(route, "POST", { force: false });
    verifyPublicResult(viewer, 403);
    assert.ok(
      isDeepStrictEqual(await agent(), initial),
      "Unauthorized retirement changed registered agent",
    );
    assert.equal((await audit()).length, 0);
    assert.ok(
      isDeepStrictEqual(await jobs(), originalJobs),
      "Unauthorized retirement changed job claims",
    );
    await pool.query(
      "UPDATE workspace_memberships SET role=$3 WHERE workspace_id=$1 AND user_id=$2",
      [workspaceId, session.userId, roleRows[0].role],
    );
    originalRoleRestored = true;
    assert.ok(
      isDeepStrictEqual(JSON.parse(ps(installed.observationScript())), runtime),
      "Installed runtime changed before authorized retirement",
    );
    const log = path.join(configDir, "host.log"),
      offset = fs.statSync(log).size;
    assert.ok(offset <= 4194304);
    const manager = await session.request(route, "POST", { force: false });
    verifyPublicResult(manager, 200);
    assert.ok(
      manager.body.agent.id === initial.id &&
        manager.body.agent.status === "retired",
      "Public retirement target mismatch",
    );
    const retired = await agent();
    assert.equal(retired.status, "retired");
    assert.ok(
      String(retired.retired_by_user_id) === String(session.userId),
      "Retirement actor attribution mismatch",
    );
    const replay = await session.request(route, "POST", { force: false });
    verifyPublicResult(replay, 200);
    assert.ok(
      isDeepStrictEqual(await agent(), retired),
      "Idempotent retirement changed terminal state",
    );
    const events = await audit();
    assert.equal(events.length, 1);
    assert.ok(
      String(events[0].actor_user_id) === String(session.userId) &&
        events[0].metadata.agentId === agentId &&
        events[0].metadata.force === false &&
        events[0].metadata.leasedJobs === 0,
      "Public idle retirement audit mismatch",
    );
    const state = () =>
      JSON.parse(
        ps(
          "$s=Get-CimInstance Win32_Service -Filter \"Name='TokenTimerAgent'\" -ErrorAction Stop;@{state=$s.State;pid=[int]$s.ProcessId;exitCode=[int]$s.ExitCode}|ConvertTo-Json -Compress",
        ),
      );
    await until(() => {
      const value = state();
      if (value.state !== "Stopped" || value.pid !== 0) return false;
      assert.equal(value.exitCode, 0);
      const size = fs.statSync(log).size;
      assert.ok(size >= offset && size <= 4194304);
      return retirementObserved(
        fs.readFileSync(log).subarray(offset).toString("utf8"),
      );
    }, "actual authenticated retirement86 and clean SCM stop");
    const capturedAbsent = () =>
      ps(
        `$all=@(Get-CimInstance Win32_Process -ErrorAction Stop);$h=@($all|Where-Object {$_.ProcessId -eq ${runtime.hostId} -and [string]$_.CreationDate -ceq '${runtime.hostCreation.replace(/'/g, "''")}'});$c=@($all|Where-Object {$_.ProcessId -eq ${runtime.childId} -and [string]$_.CreationDate -ceq '${runtime.childCreation.replace(/'/g, "''")}'});[bool]($h.Count -eq 0 -and $c.Count -eq 0)`,
      ) === "True";
    await until(capturedAbsent, "original host and child absence");
    const start = performance.now();
    do {
      const value = state();
      assert.ok(
        value.state === "Stopped" && value.pid === 0 && value.exitCode === 0,
        "Retired service unexpectedly restarted",
      );
      assert.equal(capturedAbsent(), true);
      const remaining = 5000 - (performance.now() - start);
      if (remaining > 0)
        await new Promise((resolve) =>
          setTimeout(resolve, Math.min(200, remaining)),
        );
    } while (performance.now() - start < 5000);
    const noRespawnObservedMs = Math.floor(performance.now() - start);
    assert.ok(noRespawnObservedMs <= 30000);
    installed.assertOwnedRoot(receipt);
    assert.ok(
      isDeepStrictEqual(custody(), originalCustody),
      "Retirement changed native custody",
    );
    assert.equal(
      await peer(c),
      originalPeer,
      "Retirement changed trusted served leaf",
    );
    assert.ok(
      isDeepStrictEqual(hashes(), originalHashes),
      "Retirement changed registered private state",
    );
    assert.ok(
      isDeepStrictEqual(await jobs(), originalJobs),
      "Idle retirement changed job claims",
    );
    const current = fs.lstatSync(guard, { bigint: true });
    assert.ok(
      current.isFile() &&
        !current.isSymbolicLink() &&
        current.ino === guardStat.ino &&
        current.dev === guardStat.dev &&
        fs.readFileSync(guard).equals(guardBytes),
      "Public retirement guard ownership changed",
    );
    fs.unlinkSync(guard);
    active.delete(owner(receipt.root));
    const proof = {
      scope: SCOPE,
      inFlightRetirementQualified: false,
      anonymousStatus: anonymous.status,
      viewerStatus: viewer.status,
      managerStatus: manager.status,
      replayStatus: replay.status,
      retirementAuditCount: events.length,
      noRespawnObservedMs,
      ...Object.fromEntries(FLAGS.map((flag) => [flag, true])),
    };
    verifyProof(proof);
    return proof;
  } catch {
    throw new Error(
      "Public installed retirement qualification failed; preserve guarded native state",
    );
  } finally {
    if (!originalRoleRestored)
      await pool.query(
        "UPDATE workspace_memberships SET role=$3 WHERE workspace_id=$1 AND user_id=$2",
        [workspaceId, session.userId, roleRows[0].role],
      );
  }
}
module.exports = {
  SCOPE,
  SCENARIO,
  FLAGS,
  REQUIRED_SOURCES,
  GUARD,
  verifyProof,
  verifyPublicResult,
  verifyIdleJobs,
  retirementObserved,
  assertCleanupSafe,
  qualifyPublicRetirement,
};
