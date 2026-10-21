/*
 * Qualification notes: installed-service-controls
 * Shared setup, dispatch and evidence rules: docs/certops/e2e-qualification.md.
 * Actual SCM Interrogate must succeed; unsupported Pause/Continue must return
 * ERROR_INVALID_SERVICE_CONTROL1052, not permission/state errors. Before each independently decode SCM
 * argv and observe original SYSTEM host+Node identity. Require unchanged config/credential/pin, CNG
 * association/export policy, HTTP.sys metadata/TLS and job claims; authenticated heartbeat-only uptime
 * must increase, not merely last-seen from polling. Sticky original-root guard clears only after every
 * observation; unknown controls preserve fixture. Ten-cell source does not qualify forced shutdown or
 * in-flight interruption. Native contract:
 * https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-controlservice .
 */
"use strict";
/** Installed production SCM control qualification. Interrogate and unsupported
 * Pause/Continue controls use the existing owned service; no service, key or
 * certificate is created here. Unknown control outcomes preserve a sticky guard.
 * This is not forced shutdown or certificate-operation interruption coverage. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const tls = require("node:tls");
const { spawnSync } = require("node:child_process");
const { isDeepStrictEqual } = require("node:util");
const installed = require("./certops-windows-installed-paths");
const SCOPE =
  "installed-system-service-interrogate-and-unsupported-pause-continue";
const SCENARIO = "windows-installed-scm-control-contract";
const FLAGS = Object.freeze([
  "exactOwnedInstalledService",
  "interrogateSucceeded",
  "pauseAndContinueRefused",
  "sameNativeHostAndChild",
  "unchangedCredentialAndConfiguration",
  "unchangedNativeCngAndBinding",
  "trustedTlsPreserved",
  "freshAuthenticatedHeartbeat",
  "unchangedJobClaims",
  "ownedControlGuardCleared",
]);
const REQUIRED_SOURCES = Object.freeze([
  "tests/e2e/helpers/certops-windows-service-controls.js",
  "tests/e2e/helpers/certops-windows-installed-paths.js",
  "tests/e2e/windows-real-journey.js",
  "packages/agent/windows-service-host/service_windows.go",
  "packages/agent/windows-service-host/host.go",
  "packages/agent/src/index.js",
  "apps/api/services/certops/agentDispatch.js",
]);
const GUARD = ".installed-scm-controls-active.json";
const active = new Set();
function verifyProof(p) {
  assert.ok(p && typeof p === "object" && !Array.isArray(p));
  assert.deepEqual(
    Object.keys(p).sort(),
    [
      "scope",
      "controlCount",
      "certificateOperationInterruptionQualified",
      ...FLAGS,
    ].sort(),
  );
  assert.equal(p.scope, SCOPE);
  assert.equal(p.controlCount, 3);
  assert.equal(p.certificateOperationInterruptionQualified, false);
  for (const flag of FLAGS) assert.equal(p[flag], true, flag);
  return true;
}
function assertCleanupSafe(root) {
  assert.ok(
    !active.has(root) && !fs.existsSync(path.join(root, GUARD)),
    "Preserve state after unresolved installed SCM control",
  );
}
function classifyControlResult(control, result) {
  assert.ok(["interrogate", "pause", "continue"].includes(control));
  assert.ok(
    result &&
      !result.error &&
      result.signal === null &&
      Number.isSafeInteger(result.status),
    "Native SCM command did not close normally",
  );
  assert.equal(
    control === "interrogate" ? result.status === 0 : result.status === 1052,
    true,
    "SCM accepted-control contract changed",
  );
}
function custodyScript({ thumbprint, domain, port }) {
  assert.match(thumbprint, /^[A-F0-9]{40}$/);
  assert.match(domain, /^[a-z0-9.-]+$/);
  assert.ok(Number.isSafeInteger(port) && port > 0 && port <= 65535);
  return `$c=Get-Item -LiteralPath 'Cert:\\LocalMachine\\My\\${thumbprint}' -ErrorAction Stop;$k=$null;try{if($c.PublicKey.Oid.Value -eq '1.2.840.113549.1.1.1'){$k=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c)}else{$k=[Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($c)};if(!$k -or !$k.Key.IsMachineKey -or [int]$k.Key.ExportPolicy -ne 0){throw 'Protected installed CNG custody required'};$b=Get-ItemProperty -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\HTTP\\Parameters\\SslSniBindingInfo\\${domain}:${port}' -ErrorAction Stop;$hash=([BitConverter]::ToString([byte[]]$b.SslCertHash)).Replace('-','');if($hash -cne '${thumbprint}' -or [string]$b.SslCertStoreName -ine 'My'){throw 'Owned native hostname binding changed'};@{thumb=$c.Thumbprint;unique=$k.Key.UniqueName;container=$k.Key.KeyName;provider=$k.Key.Provider.Provider;policy=[int]$k.Key.ExportPolicy;machine=$k.Key.IsMachineKey;bits=$k.KeySize;bindingHash=$hash;bindingStore=$b.SslCertStoreName;bindingAppId=[string]$b.AppId}|ConvertTo-Json -Compress}finally{if($k){$k.Dispose()};$c.Dispose()}`;
}
function tlsOptions({ domain, port, roots }) {
  assert.ok(Array.isArray(roots) && roots.length > 0);
  const ca = roots.map((root) => {
    assert.ok(
      root &&
        typeof root.pem === "string" &&
        root.pem.includes("-----BEGIN CERTIFICATE-----"),
      "Actual parent TLS root PEM required",
    );
    return root.pem;
  });
  return {
    host: "127.0.0.1",
    port,
    servername: domain,
    ca,
    rejectUnauthorized: true,
  };
}
function trustedLeaf({ domain, port, roots }) {
  return new Promise((resolve, reject) => {
    let fingerprint;
    const socket = tls.connect(tlsOptions({ domain, port, roots }), () => {
      const leaf = socket.getPeerCertificate().raw;
      if (!socket.authorized || !Buffer.isBuffer(leaf)) {
        socket.destroy();
        reject(new Error("Owned trusted TLS observation unavailable"));
        return;
      }
      fingerprint = crypto.createHash("sha256").update(leaf).digest("hex");
      socket.end();
    });
    socket.setTimeout(10000, () =>
      socket.destroy(new Error("Owned SCM TLS observation timed out")),
    );
    socket.on("error", () =>
      reject(new Error("Owned SCM trusted TLS observation failed")),
    );
    socket.once("close", (hadError) => {
      if (!hadError && fingerprint) resolve(fingerprint);
      else reject(new Error("Owned SCM TLS drainage unproven"));
    });
  });
}
function hasFreshHeartbeat(before, after) {
  const uptime = (value) => {
    assert.ok(typeof value === "number" || typeof value === "string");
    assert.match(String(value), /^[0-9]+$/);
    const parsed = Number(value);
    assert.ok(Number.isSafeInteger(parsed) && parsed >= 0);
    return parsed;
  };
  assert.equal(before.status, "active");
  assert.equal(after.status, "active");
  const prior = Date.parse(before.last_seen_at),
    current = Date.parse(after.last_seen_at);
  assert.ok(Number.isFinite(prior) && Number.isFinite(current));
  return (
    current > prior &&
    uptime(after.uptime_seconds) > uptime(before.uptime_seconds)
  );
}
async function qualifyServiceControls(c) {
  assert.equal(process.platform, "win32");
  const { receipt, configDir, ps, pool, workspaceId, agentId } = c;
  installed.assertOwnedRoot(receipt);
  assert.equal(
    receipt.historicalSupportingOnly,
    false,
    "Current-candidate installed service required",
  );
  assertCleanupSafe(receipt.root);
  const guard = path.join(receipt.root, GUARD),
    bytes = Buffer.from(
      JSON.stringify({ nonce: crypto.randomUUID(), schemaVersion: 1 }),
    );
  active.add(receipt.root);
  fs.writeFileSync(guard, bytes, { flag: "wx", mode: 0o600 });
  const guardId = fs.lstatSync(guard, { bigint: true });
  const expected = {
    host: path.join(receipt.root, "app/bin/tokentimer-agent-host-amd64.exe"),
    node: process.execPath,
    entry: path.join(receipt.root, "app/bin/tokentimer-agent.js"),
    config: configDir,
  };
  const observe = () => {
    installed.assertOwnedRoot(receipt);
    const value = JSON.parse(ps(installed.observationScript()));
    installed.validateObservation(value, expected);
    return value;
  };
  const original = observe();
  const custody = () => JSON.parse(ps(custodyScript(c)));
  const originalCustody = custody(),
    leaf = await trustedLeaf(c);
  const files = [
    path.join(configDir, "config.json"),
    path.join(configDir, "credential"),
    path.join(configDir, "signing-key-pin.json"),
  ];
  const digests = () =>
    files.map((file) =>
      crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex"),
    );
  const originalDigests = digests();
  const jobs = async () =>
    (
      await pool.query(
        "SELECT id,status,claim_id,claimed_by_agent_id FROM certificate_jobs WHERE workspace_id=$1 ORDER BY id LIMIT 1001",
        [workspaceId],
      )
    ).rows;
  const originalJobs = await jobs();
  assert.ok(
    originalJobs.length <= 1000,
    "Bounded isolated SCM job inventory required",
  );
  const heartbeat = async () =>
    (
      await pool.query(
        "SELECT last_seen_at,status,uptime_seconds FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2",
        [workspaceId, agentId],
      )
    ).rows;
  const before = await heartbeat();
  assert.equal(before.length, 1);
  assert.equal(before[0].status, "active");
  assert.ok(
    before[0].uptime_seconds !== null &&
      Number.isFinite(Number(before[0].uptime_seconds)),
    "Actual baseline heartbeat uptime required",
  );
  for (const control of ["interrogate", "pause", "continue"]) {
    assert.ok(
      isDeepStrictEqual(observe(), original),
      "Installed SCM identity changed before control",
    );
    classifyControlResult(
      control,
      spawnSync("sc.exe", [control, "TokenTimerAgent"], {
        encoding: "utf8",
        timeout: 30000,
        windowsHide: true,
      }),
    );
    assert.ok(
      isDeepStrictEqual(observe(), original),
      "Installed SCM identity changed after control",
    );
    assert.ok(
      isDeepStrictEqual(custody(), originalCustody),
      "Native CNG or hostname binding changed after SCM control",
    );
    assert.ok(
      isDeepStrictEqual(digests(), originalDigests),
      "Persisted installed identity changed after SCM control",
    );
    assert.equal(
      await trustedLeaf(c),
      leaf,
      "Trusted installed leaf changed after SCM control",
    );
  }
  const start = performance.now();
  let fresh = false;
  do {
    const rows = await heartbeat();
    assert.equal(rows.length, 1);
    assert.equal(rows[0].status, "active");
    fresh = hasFreshHeartbeat(before[0], rows[0]);
    if (fresh) break;
    await new Promise((resolve) => setTimeout(resolve, 200));
  } while (performance.now() - start < 30000);
  assert.equal(
    fresh,
    true,
    "Actual post-control authenticated heartbeat required",
  );
  assert.ok(
    isDeepStrictEqual(await jobs(), originalJobs),
    "SCM controls changed certificate job claims",
  );
  assert.ok(
    isDeepStrictEqual(observe(), original),
    "Installed process identity changed during heartbeat observation",
  );
  assert.ok(
    isDeepStrictEqual(custody(), originalCustody),
    "Native custody changed during heartbeat observation",
  );
  assert.ok(
    isDeepStrictEqual(digests(), originalDigests),
    "Installed credentials changed during heartbeat observation",
  );
  assert.equal(
    await trustedLeaf(c),
    leaf,
    "Trusted TLS changed during heartbeat observation",
  );
  installed.assertOwnedRoot(receipt);
  const current = fs.lstatSync(guard, { bigint: true });
  assert.ok(
    current.isFile() &&
      !current.isSymbolicLink() &&
      current.dev === guardId.dev &&
      current.ino === guardId.ino &&
      fs.readFileSync(guard).equals(bytes),
    "SCM control guard ownership changed",
  );
  fs.unlinkSync(guard);
  active.delete(receipt.root);
  const proof = {
    scope: SCOPE,
    controlCount: 3,
    certificateOperationInterruptionQualified: false,
    ...Object.fromEntries(FLAGS.map((flag) => [flag, true])),
  };
  verifyProof(proof);
  return proof;
}
module.exports = {
  SCOPE,
  SCENARIO,
  FLAGS,
  REQUIRED_SOURCES,
  verifyProof,
  assertCleanupSafe,
  classifyControlResult,
  hasFreshHeartbeat,
  custodyScript,
  tlsOptions,
  qualifyServiceControls,
  GUARD,
};
