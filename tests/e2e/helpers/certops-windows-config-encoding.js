"use strict";
/** Public encoding prerequisites for real installed-agent startup refusals.
 * Only fixture-owned copies of the original UTF-8 operator configuration are
 * encoded. This module never starts SCM or mutates native state by import. */
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const CASES = Object.freeze(["utf8-bom", "utf16le-bom", "utf16be-bom"]);
const SCENARIO = "windows-installed-config-encoding-refusals";
const SCOPE = "installed-system-unsupported-config-encoding-startup-refusal";
const FLAGS = Object.freeze([
  "threeActualSystemStartupParseFailures",
  "freshStoppedServiceForEach",
  "credentialAndPinPreserved",
  "nativeCngAndBindingPreserved",
  "trustedTlsPreserved",
  "noNewAgentOrJob",
  "exactOriginalConfigurationRestored",
  "actualRepairedSystemChild",
  "freshAuthenticatedHeartbeat",
  "ownedEncodingGuardCleared",
]);
const REQUIRED_SOURCES = Object.freeze([
  "tests/e2e/helpers/certops-windows-config-encoding.js",
  "tests/e2e/helpers/certops-windows-service-controls.js",
  "packages/agent/src/platform/index.js",
  "apps/api/services/certops/agentDispatch.js",
  "tests/e2e/windows-real-journey.js",
  "packages/agent/src/config/index.js",
  "packages/agent/src/index.js",
  "packages/agent/windows-service-host/service_windows.go",
  "tests/e2e/helpers/certops-windows-installed-paths.js",
]);
function encodingCases(original) {
  assert.ok(
    Buffer.isBuffer(original) &&
      original.length > 0 &&
      original.length <= 1048576,
    "Bounded original owned UTF-8 configuration required",
  );
  const text = new TextDecoder("utf-8", { fatal: true }).decode(original);
  assert.ok(
    Buffer.from(text, "utf8").equals(original),
    "Original configuration must already be UTF-8 without BOM",
  );
  const value = JSON.parse(text);
  assert.ok(value && typeof value === "object" && !Array.isArray(value));
  const le = Buffer.from(text, "utf16le"),
    be = Buffer.from(le);
  be.swap16();
  return [
    {
      id: CASES[0],
      content: Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), original]),
    },
    { id: CASES[1], content: Buffer.concat([Buffer.from([0xff, 0xfe]), le]) },
    { id: CASES[2], content: Buffer.concat([Buffer.from([0xfe, 0xff]), be]) },
  ].map((row) => ({
    ...row,
    sha256: crypto.createHash("sha256").update(row.content).digest("hex"),
  }));
}
function verifyProof(proof) {
  assert.ok(proof && typeof proof === "object" && !Array.isArray(proof));
  assert.deepEqual(
    Object.keys(proof).sort(),
    ["scope", "encodings", "startupFailureCount", ...FLAGS].sort(),
  );
  assert.equal(proof.scope, SCOPE);
  assert.deepEqual(proof.encodings, CASES);
  assert.equal(proof.startupFailureCount, 3);
  for (const flag of FLAGS) assert.equal(proof[flag], true, flag);
  return true;
}
// Native entrypoint requires the existing fixture to have stopped its exact
// service and disabled automatic recovery. Failures retain both guard and the
// private original configuration backup; no PID termination is attempted.
const fs = require("node:fs");
const path = require("node:path");
const tls = require("node:tls");
const { spawnSync } = require("node:child_process");
const { isDeepStrictEqual } = require("node:util");
const installed = require("./certops-windows-installed-paths");
const scm = require("./certops-windows-service-controls");
const {
  applyRestrictivePermissions,
} = require("../../../packages/agent/src/platform");
const GUARD = ".installed-config-encoding-active.json";
const POLICY_GUARD = ".installed-retention-policy-active.json";
const CREDENTIAL_GUARD = ".installed-credential-refusal-active.json";
const PIN_GUARD = ".installed-signing-pin-refusal-active.json";
const active = new Set();
const owner = (root) => path.resolve(root).toLowerCase();
function assertCleanupSafe(root) {
  assert.ok(
    !active.has(owner(root)) &&
      !fs.existsSync(path.join(root, GUARD)) &&
      !fs.existsSync(path.join(root, POLICY_GUARD)) &&
      !fs.existsSync(path.join(root, CREDENTIAL_GUARD)) &&
      !fs.existsSync(path.join(root, PIN_GUARD)),
    "Preserve unresolved installed configuration encoding state",
  );
}
function validateStoppedService(value, expected) {
  assert.ok(
    value &&
      value.state === "Stopped" &&
      value.pid === 0 &&
      value.identity === "LocalSystem",
    "Exact stopped LocalSystem service required",
  );
  const match = /^"([^"\r\n]+)"\s+"([^"\r\n]+)"\s+"([^"\r\n]+)"$/.exec(
    value.path,
  );
  assert.ok(match, "Exact three quoted installed SCM paths required");
  assert.ok(
    match
      .slice(1)
      .every(
        (v, i) =>
          path.win32.normalize(v).toLowerCase() ===
          path.win32.normalize(expected[i]).toLowerCase(),
      ),
    "Stopped SCM path ownership changed",
  );
}
function id(file) {
  const st = fs.lstatSync(file, { bigint: true });
  assert.ok(
    st.isFile() && !st.isSymbolicLink() && st.ino > 0n,
    "Original owned regular file required",
  );
  return `${st.dev}:${st.ino}`;
}
function writeOwnedConfig(fd, file, expectedId, expectedBytes, nextBytes) {
  assert.equal(
    id(file),
    expectedId,
    "Configuration path no longer names original object",
  );
  const before = fs.fstatSync(fd, { bigint: true });
  assert.equal(`${before.dev}:${before.ino}`, expectedId);
  assert.ok(before.isFile() && before.size <= 2097155n);
  const current = Buffer.alloc(Number(before.size));
  assert.equal(fs.readSync(fd, current, 0, current.length, 0), current.length);
  assert.ok(
    current.equals(expectedBytes),
    "Original configuration bytes changed",
  );
  // A concurrent pathname replacement cannot redirect this write to a foreign
  // file. The final path check refuses the qualification if ownership changed.
  assert.equal(id(file), expectedId);
  let written = 0;
  while (written < nextBytes.length) {
    const count = fs.writeSync(
      fd,
      nextBytes,
      written,
      nextBytes.length - written,
      written,
    );
    assert.ok(
      count > 0,
      "Owned configuration descriptor made no write progress",
    );
    written += count;
  }
  fs.ftruncateSync(fd, nextBytes.length);
  fs.fsyncSync(fd);
  assert.equal(id(file), expectedId);
}
function peer(c) {
  return new Promise((resolve, reject) => {
    let result;
    const socket = tls.connect(scm.tlsOptions(c), () => {
      const leaf = socket.getPeerCertificate().raw;
      if (!socket.authorized || !Buffer.isBuffer(leaf)) {
        socket.destroy(new Error("Owned TLS leaf unavailable"));
        return;
      }
      result = crypto.createHash("sha256").update(leaf).digest("hex");
      socket.end();
    });
    socket.setTimeout(10000, () =>
      socket.destroy(new Error("Owned encoding TLS deadline")),
    );
    socket.once("error", () =>
      reject(new Error("Owned encoding trusted TLS failed")),
    );
    socket.once("close", (bad) =>
      !bad && result
        ? resolve(result)
        : reject(new Error("Owned encoding TLS drainage unproven")),
    );
  });
}
async function until(read, label) {
  const start = performance.now();
  do {
    const result = await read();
    if (result) return result;
    await new Promise((resolve) => setTimeout(resolve, 200));
  } while (performance.now() - start < 30000);
  throw new Error(`Installed encoding observation timed out: ${label}`);
}
function verifyProcessCount(value) {
  assert.ok(
    typeof value === "string" && /^(0|[1-9][0-9]{0,6})$/.test(value),
    "Native process count must be an explicit bounded decimal",
  );
  return value === "0";
}
async function qualifyStartupConfiguration(c, mode = "encoding") {
  assert.ok(["encoding", "policy", "credential", "pin", "weak-acl"].includes(mode));
  const aclMode=mode==="weak-acl";
  const acl=aclMode?require("./certops-windows-installed-weak-acl"):null;
  const policyMode = mode === "policy",
    credentialMode = mode === "credential" || aclMode,
    pinMode = mode === "pin";
  const pin = pinMode ? require("./certops-windows-signing-pin-refusal") : null;
  const credential = credentialMode
    ? require("./certops-windows-credential-refusal")
    : null;
  const policy = policyMode
    ? require("./certops-windows-retention-config")
    : null;
  assert.equal(process.platform, "win32");
  const { receipt, configDir, ps, pool, workspaceId, agentId } = c;
  installed.assertOwnedRoot(receipt);
  assert.equal(receipt.historicalSupportingOnly, false);
  assertCleanupSafe(receipt.root);
  assert.equal(path.resolve(configDir), path.join(receipt.root, "state"));
  const guard = path.join(
    receipt.root,
    pinMode
      ? PIN_GUARD
      : credentialMode
        ? CREDENTIAL_GUARD
        : policyMode
          ? POLICY_GUARD
          : GUARD,
  );
  const guardBytes = Buffer.from(
    JSON.stringify({ schemaVersion: 1, nonce: crypto.randomUUID() }),
  );
  active.add(owner(receipt.root));
  fs.writeFileSync(guard, guardBytes, { flag: "wx", mode: 0o600 });
  applyRestrictivePermissions(guard, { kind: "file" });
  const guardId = id(guard);
  const expected = [
    path.join(receipt.root, "app/bin/tokentimer-agent-host-amd64.exe"),
    process.execPath,
    path.join(receipt.root, "app/bin/tokentimer-agent.js"),
  ];
  const stopped = () => {
    installed.assertOwnedRoot(receipt);
    const value = JSON.parse(
      ps(
        `$s=Get-CimInstance Win32_Service -Filter "Name='TokenTimerAgent'" -ErrorAction Stop;if(!$s){throw 'Owned service absent'};@{state=$s.State;pid=[int]$s.ProcessId;identity=$s.StartName;path=$s.PathName}|ConvertTo-Json -Compress`,
      ),
    );
    validateStoppedService(value, expected);
    return value;
  };
  const escaped = (value) => value.replace(/'/g, "''");
  const noFixtureProcesses = () =>
    verifyProcessCount(
      ps(
        `$all=@(Get-CimInstance Win32_Process -ErrorAction Stop);$owned=@($all|Where-Object {($_.ExecutablePath -ieq '${escaped(expected[0])}') -or (($_.ExecutablePath -ieq '${escaped(expected[1])}') -and $_.CommandLine -and $_.CommandLine.IndexOf('${escaped(expected[2])}',[StringComparison]::OrdinalIgnoreCase) -ge 0)});$owned.Count`,
      ),
    );
  // This is an absence guard only: an ambiguous command reference refuses the
  // fixture. It never adopts a process or signals a rediscovered numeric PID.
  await until(
    noFixtureProcesses,
    "preexisting stopped fixture process drainage",
  );
  const originalService = stopped(),
    file = path.join(
      configDir,
      pinMode
        ? "signing-key-pin.json"
        : credentialMode
          ? "credential"
          : "config.json",
    ),
    fileId = id(file),
    original = fs.readFileSync(file),
    cases = aclMode ? [{id:"weak-credential-dacl",content:original,expectedError:"tokentimer-agent platform: refusing to use credential file: its ACL grants access to S-1-1-0"}] : pinMode
      ? pin.pinCases(original)
      : credentialMode
        ? credential.credentialCases(original)
        : policyMode
          ? policy.policyCases(original)
          : encodingCases(original);
  const log = path.join(configDir, "host.log"),
    backup = path.join(
      receipt.root,
      pinMode
        ? ".original-signing-pin-before-refusal.json"
        : credentialMode
          ? ".original-credential-before-refusal"
          : policyMode
            ? ".original-config-before-retention-policy.json"
            : ".original-config-before-encoding.json",
    );
  const files = pinMode
    ? [path.join(configDir, "config.json"), path.join(configDir, "credential")]
    : [
        path.join(configDir, credentialMode ? "config.json" : "credential"),
        path.join(configDir, "signing-key-pin.json"),
      ];
  const native = () => JSON.parse(ps(scm.custodyScript(c)));
  const protectedFiles = () =>
    files.map((f) => ({
      identity: id(f),
      hash: crypto
        .createHash("sha256")
        .update(fs.readFileSync(f))
        .digest("hex"),
    }));
  const originalNative = native(),
    originalFiles = protectedFiles(),
    originalPeer = await peer(c);
  const jobs = async () => {
    const rows = (
      await pool.query(
        "SELECT id,status,claim_id,claimed_by_agent_id FROM certificate_jobs WHERE workspace_id=$1 ORDER BY id LIMIT 1001",
        [workspaceId],
      )
    ).rows;
    assert.ok(rows.length <= 1000);
    return rows;
  };
  const agents = async () => {
    const rows = (
      await pool.query(
        "SELECT id,status,last_seen_at,uptime_seconds FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2",
        [workspaceId, agentId],
      )
    ).rows;
    assert.equal(rows.length, 1);
    assert.equal(rows[0].status, "active");
    return rows[0];
  };
  const agentInventory = async () => {
    const rows = (
      await pool.query(
        "SELECT id,agent_id FROM certops_agents WHERE workspace_id=$1 ORDER BY id LIMIT 1001",
        [workspaceId],
      )
    ).rows;
    assert.ok(rows.length <= 1000);
    return rows;
  };
  const originalAgents = await agentInventory();
  const originalJobs = await jobs(),
    originalAgent = await agents();
  assert.ok(
    originalJobs.every(
      (row) =>
        ![
          "pending",
          "pending_approval",
          "approved",
          "claimed",
          "running",
        ].includes(row.status),
    ),
    "Encoding fault requires no active certificate jobs",
  );
  assert.ok(originalAgent.uptime_seconds !== null);
  const same = async (repaired = false) => {
    installed.assertOwnedRoot(receipt);
    if(aclMode&&!repaired)assert.ok(isDeepStrictEqual(await agents(),originalAgent),"Weak ACL refusal must not authenticate a heartbeat");
    assert.equal(id(file), fileId);
    assert.ok(
      isDeepStrictEqual(native(), originalNative),
      "Native custody changed during encoding refusal",
    );
    const currentFiles = protectedFiles();
    assert.ok(
      repaired
        ? currentFiles.every(
            (value, index) =>
              value.hash === originalFiles[index].hash &&
              ((!pinMode && index === 1) ||
                value.identity === originalFiles[index].identity),
          )
        : isDeepStrictEqual(currentFiles, originalFiles),
      "Registered private state changed during encoding refusal",
    );
    assert.equal(
      await peer(c),
      originalPeer,
      "Trusted served leaf changed during encoding refusal",
    );
    assert.ok(
      isDeepStrictEqual(await jobs(), originalJobs),
      "Encoding refusal changed job claims",
    );
    assert.ok(
      isDeepStrictEqual(await agentInventory(), originalAgents),
      "Encoding refusal added or removed registered identity",
    );
    assert.equal(
      (await agents()).id,
      originalAgent.id,
      "Encoding refusal replaced registered identity",
    );
  };
  fs.writeFileSync(backup, original, { flag: "wx", mode: 0o600 });
  applyRestrictivePermissions(backup, { kind: "file" });
  const backupId = id(backup);
  const originalFd = fs.openSync(
    file,
    (aclMode?fs.constants.O_RDONLY:fs.constants.O_RDWR) | (fs.constants.O_NOFOLLOW || 0),
  );
  assert.equal(
    `${fs.fstatSync(originalFd, { bigint: true }).dev}:${fs.fstatSync(originalFd, { bigint: true }).ino}`,
    fileId,
  );
  let lastWritten = original,
    fdClosed = false;
  try {
    const runCase=async row=>{
      assert.ok(
        isDeepStrictEqual(stopped(), originalService),
        "Stopped service identity changed",
      );
      await same();
      assert.ok(
        fs.readFileSync(file).equals(lastWritten),
        "Owned configuration bytes changed externally",
      );
      const logSize = fs.existsSync(log) ? fs.statSync(log).size : 0;
      assert.ok(logSize <= 4194304, "Bounded startup log required");
      if(!aclMode)writeOwnedConfig(originalFd, file, fileId, lastWritten, row.content);
      lastWritten = row.content;
      assert.equal(id(file), fileId);
      const result = spawnSync("sc.exe", ["start", "TokenTimerAgent"], {
        encoding: "utf8",
        windowsHide: true,
        timeout: 30000,
      });
      assert.ok(
        !result.error && result.signal === null,
        "Owned native startup command did not drain",
      );
      await until(() => {
        const state = JSON.parse(
          ps(
            `$s=Get-CimInstance Win32_Service -Filter "Name='TokenTimerAgent'";@{state=$s.State;pid=[int]$s.ProcessId;identity=$s.StartName;path=$s.PathName}|ConvertTo-Json -Compress`,
          ),
        );
        if (state.state !== "Stopped") return false;
        validateStoppedService(state, expected);
        if (!fs.existsSync(log)) return false;
        const size = fs.statSync(log).size;
        assert.ok(
          size >= logSize && size <= 4194304,
          "Startup log ownership bound changed",
        );
        const fresh = fs.readFileSync(log).subarray(logSize).toString("utf8");
        return (
          fresh.includes(row.expectedError || "failed to parse") &&
          (policyMode || credentialMode || fresh.includes(file))
        );
      }, row.id);
      await until(
        noFixtureProcesses,
        "failed startup fixture process drainage",
      );
      await same();
      assert.ok(
        fs.readFileSync(file).equals(row.content),
        "Failed startup rewrote invalid configuration",
      );
    };
    if(aclMode){
      const restored=await require("../../../packages/agent/scripts/host/credential-weak-acl-fixture").withInstalledCredential({workDir:receipt.root,configDir,onWeak:()=>runCase(cases[0])});
      assert.deepEqual(restored,{originalHandleRestored:true,exactCredentialBytesPreserved:true,actualWeakAclReadRefused:true});
    }else for(const row of cases)await runCase(row);
    assert.ok(isDeepStrictEqual(stopped(), originalService));
    assert.equal(id(file), fileId);
    assert.ok(fs.readFileSync(file).equals(lastWritten));
    if(!aclMode)writeOwnedConfig(originalFd, file, fileId, lastWritten, original);
    lastWritten = original;
    assert.equal(id(file), fileId);
    assert.ok(fs.readFileSync(file).equals(original));
    const started = spawnSync("sc.exe", ["start", "TokenTimerAgent"], {
      encoding: "utf8",
      windowsHide: true,
      timeout: 30000,
    });
    assert.ok(
      !started.error && started.signal === null,
      "Repaired native startup command did not drain",
    );
    await until(() => {
      try {
        const observed = JSON.parse(ps(installed.observationScript()));
        installed.validateObservation(observed, {
          host: expected[0],
          node: expected[1],
          entry: expected[2],
          config: configDir,
        });
        return observed;
      } catch {
        return false;
      }
    }, "repaired owned SYSTEM child");
    await until(async () => {
      const now = await agents();
      return (
        Date.parse(now.last_seen_at) > Date.parse(originalAgent.last_seen_at) &&
        now.uptime_seconds !== null &&
        String(now.uptime_seconds) !== String(originalAgent.uptime_seconds)
      );
    }, "actual repaired heartbeat uptime");
    await same(true);
    const observed = JSON.parse(ps(installed.observationScript()));
    installed.validateObservation(observed, {
      host: expected[0],
      node: expected[1],
      entry: expected[2],
      config: configDir,
    });
    fs.closeSync(originalFd);
    fdClosed = true;
    assert.equal(id(backup), backupId);
    assert.ok(fs.readFileSync(backup).equals(original));
    fs.unlinkSync(backup);
    assert.equal(id(guard), guardId);
    assert.ok(fs.readFileSync(guard).equals(guardBytes));
    fs.unlinkSync(guard);
    active.delete(owner(receipt.root));
    const proof = aclMode ? {scope:acl.SCOPE,untrustedSid:"S-1-1-0",readMask:1,startupFailureCount:1,inFlightMutationQualified:false,...Object.fromEntries(acl.FLAGS.map(flag=>[flag,true]))} : pinMode
      ? {
          scope: pin.SCOPE,
          pins: [...pin.CASES],
          startupFailureCount: 2,
          missingPinQualified: false,
          inFlightMutationQualified: false,
          ...Object.fromEntries(pin.FLAGS.map((flag) => [flag, true])),
        }
      : credentialMode
        ? {
            scope: credential.SCOPE,
            credentials: [...credential.CASES],
            startupFailureCount: 2,
            inFlightMutationQualified: false,
            ...Object.fromEntries(credential.FLAGS.map((flag) => [flag, true])),
          }
        : policyMode
          ? {
              scope: policy.SCOPE,
              policies: [...policy.CASES],
              startupFailureCount: 3,
              retentionTimerQualified: false,
              ...Object.fromEntries(policy.FLAGS.map((flag) => [flag, true])),
            }
          : {
              scope: SCOPE,
              encodings: [...CASES],
              startupFailureCount: 3,
              ...Object.fromEntries(FLAGS.map((flag) => [flag, true])),
            };
    (aclMode ? acl.verifyProof : pinMode
      ? pin.verifyProof
      : credentialMode
        ? credential.verifyProof
        : policyMode
          ? policy.verifyProof
          : verifyProof)(proof);
    return proof;
  } catch {
    // Restore only the original file object and exactly our last written bytes.
    // Even successful byte restoration cannot clear unknown native ownership.
    try {
      if (
        !fdClosed &&
        id(file) === fileId &&
        fs.readFileSync(file).equals(lastWritten)
      ) {
        if(!aclMode)writeOwnedConfig(originalFd, file, fileId, lastWritten, original);
        assert.equal(id(file), fileId);
      }
    } catch {}
    throw new Error(
      "Installed encoding qualification failed; preserve guarded native state",
    );
  } finally {
    if (!fdClosed) fs.closeSync(originalFd);
  }
}
const qualifyConfigEncoding = (c) => qualifyStartupConfiguration(c, "encoding");
const qualifyRetentionConfig = (c) => qualifyStartupConfiguration(c, "policy");
const qualifyCredentialRefusal = (c) =>
  qualifyStartupConfiguration(c, "credential");
const qualifySigningPinRefusal = (c) => qualifyStartupConfiguration(c, "pin");
module.exports = {
  qualifyWeakCredentialAcl:c=>qualifyStartupConfiguration(c,"weak-acl"),
  qualifySigningPinRefusal,
  qualifyCredentialRefusal,
  qualifyRetentionConfig,
  verifyProcessCount,
  CASES,
  SCENARIO,
  SCOPE,
  FLAGS,
  REQUIRED_SOURCES,
  encodingCases,
  verifyProof,
  validateStoppedService,
  writeOwnedConfig,
  assertCleanupSafe,
  qualifyConfigEncoding,
  GUARD,
};
