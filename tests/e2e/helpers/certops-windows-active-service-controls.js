"use strict";
/** Nonmutating SCM controls during an actual installed-agent DNS operation.
 * The owning journey holds its real DNS POST after CNG generation. This fixture
 * never advances clocks, changes a lease, kills a process or claims interruption. */
const assert = require("node:assert/strict");
const fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
const { isDeepStrictEqual } = require("node:util");
const installed = require("./certops-windows-installed-paths");
const controls = require("./certops-windows-service-controls");
const SCOPE = "installed-scm-controls-during-real-cng-dns-renewal";
const SCENARIO = "windows-installed-scm-controls-active-certificate-phase";
const FLAGS = Object.freeze([
  "actualDnsPostBarrier",
  "sameCurrentClaimAndAttempt",
  "sameDurablePendingJournal",
  "samePendingNonexportableCngKey",
  "interrogateSucceeded",
  "pauseAndContinueRefused",
  "sameInstalledSystemProcesses",
  "sameServingCngBindingAndTrustedTls",
  "sameProtectedStateBytes",
  "ownedControlGuardCleared",
]);
const GUARD = ".installed-active-scm-controls.json";
const active = new Set();
const REQUIRED_SOURCES = Object.freeze([
  ...new Set([
    "tests/e2e/helpers/certops-windows-active-service-controls.js",
    ...controls.REQUIRED_SOURCES,
  ]),
]);
function verifyProof(value) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value));
  assert.deepEqual(
    Object.keys(value).sort(),
    [
      "scope",
      "controlCount",
      "certificateOperationInterruptionQualified",
      "defaultLeaseGraceQualified",
      ...FLAGS,
    ].sort(),
  );
  assert.equal(value.scope, SCOPE);
  assert.equal(value.controlCount, 3);
  assert.equal(value.certificateOperationInterruptionQualified, false);
  assert.equal(value.defaultLeaseGraceQualified, false);
  for (const flag of FLAGS) assert.equal(value[flag], true, flag);
  return true;
}
function assertCleanupSafe(root) {
  assert.ok(
    !active.has(root) && !fs.existsSync(path.join(root, GUARD)),
    "Preserve unresolved active certificate SCM control state",
  );
}
function validateRunningClaim(value, agentId) {
  assert.ok(
    value &&
      value.status === "running" &&
      value.operation === "renew" &&
      value.mode === "real" &&
      value.source === "automation" &&
      value.agent_id === agentId &&
      Number.isSafeInteger(value.attempt_count) &&
      value.attempt_count > 0 &&
      /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(value.claim_id),
    "Actual active signed renewal claim required",
  );
}
function pendingKeyScript(container) {
  assert.match(container, /^tokentimer-[A-Za-z0-9_-]{1,64}-[a-f0-9]{8}$/);
  return `$k=$null;try{$k=[Security.Cryptography.CngKey]::Open('${container}',[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider,[Security.Cryptography.CngKeyOpenOptions]::MachineKey);if(!$k.IsMachineKey -or [int]$k.ExportPolicy -ne 0){throw 'Pending protected machine key required'};@{available=$true;name=$k.KeyName;unique=$k.UniqueName;provider=$k.Provider.Provider;machine=$k.IsMachineKey;export=[int]$k.ExportPolicy}|ConvertTo-Json -Compress}catch{@{available=$false}|ConvertTo-Json -Compress}finally{if($k){$k.Dispose()}}`;
}
function trustedBoundLeaf(c, connect = require("node:tls").connect) {
  return new Promise((resolve, reject) => {
    let accepted = false,
      failed = false;
    const socket = connect(controls.tlsOptions(c), () => {
      try {
        const fingerprint = socket.getPeerCertificate().fingerprint;
        accepted =
          socket.authorized &&
          typeof fingerprint === "string" &&
          fingerprint.replace(/:/g, "") === c.thumbprint;
      } catch {
        failed = true;
      }
      socket.end();
    });
    socket.setTimeout(10000, () =>
      socket.destroy(new Error("Active SCM TLS timeout")),
    );
    socket.on("error", () => {
      failed = true;
    });
    socket.once("close", (hadError) =>
      accepted && !failed && !hadError
        ? resolve()
        : reject(new Error("Active SCM trusted TLS failed after drainage")),
    );
  });
}
async function qualifyActiveServiceControls(c) {
  assert.equal(process.platform, "win32");
  const {
    receipt,
    configDir,
    ps,
    pool,
    workspaceId,
    agentId,
    jobId,
    journalPath,
    journal,
    barrierObserved,
  } = c;
  installed.assertOwnedRoot(receipt);
  assert.equal(receipt.historicalSupportingOnly, false);
  assertCleanupSafe(receipt.root);
  assert.equal(typeof barrierObserved, "function");
  assert.equal(
    barrierObserved(),
    true,
    "Genuine owned DNS POST must still be held",
  );
  const guard = path.join(receipt.root, GUARD),
    bytes = Buffer.from(crypto.randomBytes(32).toString("hex"));
  active.add(receipt.root);
  fs.writeFileSync(guard, bytes, { flag: "wx", mode: 0o600 });
  const guardId = fs.lstatSync(guard, { bigint: true });
  const claim = async () => {
    const row = (
      await pool.query(
        "SELECT j.status,j.operation,j.mode,j.source,j.claim_id,j.attempt_count,a.agent_id FROM certificate_jobs j JOIN certops_agents a ON a.id=j.claimed_by_agent_id AND a.workspace_id=j.workspace_id WHERE j.workspace_id=$1 AND j.id=$2",
        [workspaceId, jobId],
      )
    ).rows;
    assert.equal(row.length, 1);
    validateRunningClaim(row[0], agentId);
    return row[0];
  };
  const beforeClaim = await claim();
  const journalRoot = path.join(configDir, "job-journal");
  assert.ok(
    path.dirname(journalPath) === journalRoot &&
      path.extname(journalPath) === ".json",
    "Exact owned journal path required",
  );
  const fileId = fs.lstatSync(journalPath, { bigint: true });
  assert.ok(
    fileId.isFile() &&
      !fileId.isSymbolicLink() &&
      fileId.size > 0n &&
      fileId.size <= 1048576n,
  );
  const journalBytes = fs.readFileSync(journalPath);
  const parsed = JSON.parse(journalBytes);
  assert.equal(parsed.jobId, jobId);
  assert.equal(parsed.claimId, beforeClaim.claim_id);
  assert.ok(
    journal.windowsCngContainerName.startsWith(`tokentimer-${jobId}-`),
    "Pending native key must belong to exact job",
  );
  assert.ok(
    isDeepStrictEqual(parsed, journal),
    "Actual parent journal differs",
  );
  const pending = () => {
    const value = JSON.parse(
      ps(pendingKeyScript(journal.windowsCngContainerName)),
    );
    assert.equal(
      value.available,
      true,
      "Pending native key observation unavailable",
    );
    return value;
  };
  const beforeKey = pending();
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
  const beforeProcesses = processes();
  const native = () => JSON.parse(ps(controls.custodyScript(c)));
  const beforeNative = native();
  const protectedBytes = () =>
    ["config.json", "credential", "signing-key-pin.json"].map((name) =>
      crypto
        .createHash("sha256")
        .update(fs.readFileSync(path.join(configDir, name)))
        .digest("hex"),
    );
  const beforeBytes = protectedBytes();
  for (const control of ["interrogate", "pause", "continue"]) {
    assert.equal(
      barrierObserved(),
      true,
      "DNS barrier ended before SCM control",
    );
    controls.classifyControlResult(
      control,
      spawnSync("sc.exe", [control, "TokenTimerAgent"], {
        encoding: "utf8",
        timeout: 10000,
        windowsHide: true,
      }),
    );
    assert.ok(
      isDeepStrictEqual(processes(), beforeProcesses),
      "Installed process changed during active SCM control",
    );
    assert.ok(
      isDeepStrictEqual(await claim(), beforeClaim),
      "Active renewal claim changed during SCM control",
    );
    assert.ok(
      isDeepStrictEqual(pending(), beforeKey),
      "Pending native key changed during SCM control",
    );
    const current = fs.lstatSync(journalPath, { bigint: true });
    assert.ok(
      current.dev === fileId.dev &&
        current.ino === fileId.ino &&
        fs.readFileSync(journalPath).equals(journalBytes),
      "Pending native journal changed during SCM control",
    );
    assert.ok(
      isDeepStrictEqual(native(), beforeNative),
      "Serving native custody changed during SCM control",
    );
    assert.ok(
      isDeepStrictEqual(protectedBytes(), beforeBytes),
      "Protected installed state changed during SCM control",
    );
    assert.equal(
      barrierObserved(),
      true,
      "DNS barrier ended during SCM control",
    );
  }
  // Independent trusted TLS uses the owning journey's exact current leaf and roots;
  // await actual socket close before releasing the pending-operation guard.
  await trustedBoundLeaf(c);
  assert.equal(
    barrierObserved(),
    true,
    "DNS barrier ended before native proof completed",
  );
  assert.ok(
    isDeepStrictEqual(await claim(), beforeClaim),
    "Active renewal claim changed before proof completion",
  );
  assert.ok(
    isDeepStrictEqual(processes(), beforeProcesses),
    "Installed process changed before active proof completion",
  );
  assert.ok(
    isDeepStrictEqual(pending(), beforeKey),
    "Pending native key changed before active proof completion",
  );
  assert.ok(
    isDeepStrictEqual(native(), beforeNative),
    "Serving native custody changed before active proof completion",
  );
  assert.ok(
    isDeepStrictEqual(protectedBytes(), beforeBytes),
    "Protected state changed before active proof completion",
  );
  const finalJournal = fs.lstatSync(journalPath, { bigint: true });
  assert.ok(
    finalJournal.dev === fileId.dev &&
      finalJournal.ino === fileId.ino &&
      fs.readFileSync(journalPath).equals(journalBytes),
    "Pending journal changed before active proof completion",
  );
  installed.assertOwnedRoot(receipt);
  const finalGuard = fs.lstatSync(guard, { bigint: true });
  assert.ok(
    finalGuard.dev === guardId.dev &&
      finalGuard.ino === guardId.ino &&
      fs.readFileSync(guard).equals(bytes),
    "Active SCM ownership receipt changed",
  );
  fs.unlinkSync(guard);
  active.delete(receipt.root);
  const proof = {
    scope: SCOPE,
    controlCount: 3,
    certificateOperationInterruptionQualified: false,
    defaultLeaseGraceQualified: false,
    ...Object.fromEntries(FLAGS.map((x) => [x, true])),
  };
  verifyProof(proof);
  return proof;
}
module.exports = {
  SCOPE,
  SCENARIO,
  FLAGS,
  REQUIRED_SOURCES,
  GUARD,
  verifyProof,
  assertCleanupSafe,
  validateRunningClaim,
  pendingKeyScript,
  qualifyActiveServiceControls,
  trustedBoundLeaf,
};
