"use strict";
/** Read-only same-process observer of the REAL installed production timer.
 * Its only writes are exclusive ownership/readiness/result receipts outside the
 * agent directory. It never invokes runWindowsRetentionSweep or changes clocks.
 */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const tls = require("node:tls");
const https = require("node:https");
const { spawnSync } = require("node:child_process");
const { performance } = require("node:perf_hooks");
const { isDeepStrictEqual } = require("node:util");
const c = require("./certops-retention-cadence-contract");
const ledger = require("./certops-retention-cadence-ledger");
const retention = require("../packages/agent/src/windows-retention");
const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
function hash(file) {
  return crypto
    .createHash("sha256")
    .update(fs.readFileSync(file))
    .digest("hex");
}
function verifyConfig(config, configPath) {
  c.verifyLease(config.lease);
  assert.equal(config.lease.phase, "preparing");
  for (const key of ["hostSha256", "agentEntrySha256"])
    assert.match(config[key], /^[a-f0-9]{64}$/);
  const directory = `C:\\ttqualification\\retention-cadence\\${config.lease.nonce}`;
  assert.equal(configPath, path.win32.join(directory, "observer-config.json"));
  assert.equal(config.stateDir, path.win32.join(directory, "agent"));
  assert.match(
    config.domain,
    /^certops-adcs-[a-f0-9]{10}-cadence\.example\.test$/,
  );
  assert.equal(config.site, `TTADCS-${config.domain.split("-")[2]}-cadence`);
  assert.ok(
    Number.isInteger(config.port) && config.port > 0 && config.port <= 65535,
  );
  assert.equal(config.noOtherActiveJobsVerified, true);
  assert.equal(typeof config.apiTrustPem, "string");
  assert.ok(config.apiTrustPem.length <= 65536);
  assert.match(config.apiFingerprintSha256, /^[a-f0-9]{64}$/);
  assert.equal(config.httpSysBinding?.keyedBy, "hostnameport");
  assert.equal(
    config.httpSysBinding?.ipPort?.toLowerCase(),
    `${config.domain}:${config.port}`,
  );
  assert.equal(config.httpSysBinding?.storeName?.toLowerCase(), "my");
  assert.equal(
    config.httpSysBinding?.thumbprint?.toUpperCase(),
    config.replacement.thumbprint,
  );
  assert.ok(
    Array.isArray(config.requiredSources) &&
      config.requiredSources.length > 5 &&
      config.requiredSources.length <= 128,
  );
  const seen = new Set();
  for (const item of config.requiredSources) {
    assert.match(
      item.file,
      /^(?:scripts|tests|packages|infra|apps|\.github)\/[a-zA-Z0-9_./-]+$/,
    );
    assert.ok(!item.file.split("/").includes(".."));
    assert.ok(!seen.has(item.file));
    seen.add(item.file);
    assert.match(item.sha256, /^[a-f0-9]{64}$/);
  }
  for (const name of [
    "scripts/certops-retention-cadence-runtime.js",
    "scripts/certops-retention-cadence-native.ps1",
    "scripts/certops-retention-cadence-ledger.js",
    "scripts/certops-retention-cadence-contract.js",
    "packages/agent/src/index.js",
    "packages/agent/src/protocol/index.js",
    "packages/agent/src/config/index.js",
    "packages/agent/src/windows-retention/index.js",
  ])
    assert.ok(seen.has(name), "Missing cadence critical source");
  const row = retention.validateLedgerRow(config.pendingSnapshot.row);
  assert.equal(row.lifecycleState, "pending_retention");
  assert.equal(row.deferralReason, null);
  assert.equal(row.oldThumbprint, config.predecessor.thumbprint);
  assert.equal(row.replacementThumbprint, config.replacement.thumbprint);
  assert.equal(row.cngKeyContainerId, config.predecessor.containerName);
  for (const item of [config.predecessor, config.replacement]) {
    assert.match(item.thumbprint, /^[A-F0-9]{40}$/);
    assert.match(
      item.containerName,
      /^tokentimer-enr-[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/,
    );
    const cert = new crypto.X509Certificate(
      Buffer.from(item.certificateDerB64, "base64"),
    );
    assert.equal(cert.fingerprint.replace(/:/g, ""), item.thumbprint);
  }
  assert.notEqual(config.predecessor.thumbprint, config.replacement.thumbprint);
  assert.ok(
    Date.parse(row.oldNotAfter) > c.epoch(config.lease.hardExpiresAt) + c.HOUR,
  );
  return config;
}
async function trustedTls(config) {
  await new Promise((resolve, reject) => {
    const socket = tls.connect(
      {
        host: "127.0.0.1",
        port: config.port,
        servername: config.domain,
        ca: config.caPem,
        rejectUnauthorized: true,
      },
      () => {
        try {
          assert.equal(socket.authorized, true);
          assert.equal(
            new crypto.X509Certificate(
              socket.getPeerCertificate().raw,
            ).fingerprint.replace(/:/g, ""),
            config.replacement.thumbprint,
          );
          resolve();
        } catch (error) {
          reject(error);
        } finally {
          socket.destroy();
        }
      },
    );
    socket.once("error", reject);
    socket.setTimeout(10000, () =>
      socket.destroy(new Error("Owned cadence TLS deadline")),
    );
  });
}
async function inspect(config, configPath, configSha) {
  assert.equal(hash(configPath), configSha);
  assert.equal(
    hash(
      path.resolve(
        __dirname,
        "../packages/agent/bin/tokentimer-agent-host-amd64.exe",
      ),
    ),
    config.hostSha256,
    "Installed host artifact changed",
  );
  assert.equal(
    hash(path.resolve(__dirname, "../packages/agent/bin/tokentimer-agent.js")),
    config.agentEntrySha256,
    "Installed entry artifact changed",
  );
  for (const item of config.requiredSources)
    assert.equal(
      hash(path.resolve(__dirname, "..", item.file)),
      item.sha256,
      "Cadence source changed",
    );
  const agentConfig = JSON.parse(
    fs.readFileSync(path.join(config.stateDir, "config.json"), "utf8"),
  );
  assert.ok(agentConfig.windows && typeof agentConfig.windows === "object");
  for (const key of ["sweepIntervalMs", "supersededRetentionHours"])
    assert.equal(
      Object.hasOwn(agentConfig.windows, key),
      false,
      "Production timing default was overridden",
    );
  let result;
  const idleDeadline = performance.now() + 60000;
  for (;;) {
    result = spawnSync(
      "powershell.exe",
      [
        "-NoProfile",
        "-NonInteractive",
        "-File",
        path.join(__dirname, "certops-retention-cadence-native.ps1"),
        "-ConfigPath",
        configPath,
        "-ConfigSha256",
        configSha,
      ],
      { encoding: "utf8", windowsHide: true, timeout: 30000, maxBuffer: 8192 },
    );
    assert.ifError(result.error);
    // The genuine timer performs native reads in an agent child. Retry only
    // that explicit busy observation; never mask identity/custody/API errors.
    if (result.status === 0) break;
    assert.ok(
      result.stderr.includes("RETENTION_CADENCE_NATIVE_CHILD_BUSY") &&
        performance.now() < idleDeadline,
      "Independent cadence native observation failed",
    );
    await pause(500);
  }
  assert.equal(
    result.status,
    0,
    "Independent cadence native observation failed",
  );
  const native = JSON.parse(result.stdout);
  for (const key of [
    "nativeCustodyVerified",
    "defaultsOmittedVerified",
    "soleInstalledAgentVerified",
    "soleLedgerWriterVerified",
  ])
    assert.equal(native[key], true);
  assert.equal(native.principalSid, "S-1-5-18");
  await trustedTls(config);
  // Native HttpQueryServiceConfiguration-backed inventory includes the store,
  // AppId and all supported settings; TLS alone cannot distinguish a mirror.
  const bindings =
    await require("../packages/agent/src/windows-discovery").listHttpSysBindings();
  assert.equal(bindings.ok, true, "Native HTTP.sys inventory unavailable");
  const matches = bindings.bindings.filter(
    (item) =>
      item.keyedBy === "hostnameport" &&
      item.ipPort?.toLowerCase() === `${config.domain}:${config.port}`,
  );
  assert.equal(matches.length, 1);
  assert.ok(
    isDeepStrictEqual(matches[0], config.httpSysBinding),
    "Original native HTTP.sys coordinates/store/settings changed",
  );
  await new Promise((resolve, reject) => {
    const request = https.get(
      "https://10.64.0.6/health",
      { ca: config.apiTrustPem, rejectUnauthorized: true, timeout: 10000 },
      (response) => {
        try {
          assert.equal(response.statusCode, 200);
          assert.equal(
            crypto
              .createHash("sha256")
              .update(response.socket.getPeerCertificate().raw)
              .digest("hex"),
            config.apiFingerprintSha256,
          );
        } catch (error) {
          response.destroy();
          reject(error);
          return;
        }
        let bytes = 0;
        response.on("data", (chunk) => {
          bytes += chunk.length;
          if (bytes > 8192)
            response.destroy(new Error("Bounded API health response required"));
        });
        response.once("error", reject);
        response.once("end", resolve);
      },
    );
    request.once("error", reject);
    request.once("timeout", () =>
      request.destroy(new Error("Trusted API health deadline")),
    );
  });
  return {
    ...native,
    trustedTlsVerified: true,
    configSha256: hash(path.join(config.stateDir, "config.json")),
  };
}
async function main(configPath, configSha) {
  assert.equal(process.platform, "win32");
  assert.match(configSha, /^[a-f0-9]{64}$/);
  assert.equal(hash(configPath), configSha);
  const config = verifyConfig(
    JSON.parse(fs.readFileSync(configPath, "utf8")),
    configPath,
  );
  assert.equal(hash(process.execPath), config.lease.nodeSha256);
  assert.equal(hash(__filename), config.lease.observerSha256);
  process.env.CERTOPS_ADCS_DISPOSABLE_LAB = "1";
  const directory = path.dirname(configPath),
    ledgerDir = path.join(config.stateDir, "windows-retention");
  const ledgerPath = retention.ledgerRowPath(
    ledgerDir,
    config.predecessor.thumbprint,
  );
  const pending = ledger.readSnapshot(ledgerPath);
  assert.ok(
    isDeepStrictEqual(pending, config.pendingSnapshot),
    "Prepared ledger changed before observer ownership",
  );
  const startedAt = new Date().toISOString(),
    started = performance.now();
  const tracker = ledger.createTracker(
    pending,
    Date.parse(startedAt),
    Math.round(started),
  );
  // Registered SYSTEM task owns these wx receipts; no trigger/restart can splice it.
  const creation = spawnSync(
    "powershell.exe",
    [
      "-NoProfile",
      "-NonInteractive",
      "-Command",
      `(Get-CimInstance Win32_Process -Filter 'ProcessId=${process.pid}').CreationDate.ToUniversalTime().ToString('o')`,
    ],
    { encoding: "utf8", windowsHide: true, timeout: 10000, maxBuffer: 1024 },
  );
  assert.ifError(creation.error);
  assert.equal(creation.status, 0);
  const processCreatedAt = creation.stdout.trim();
  assert.ok(Number.isFinite(Date.parse(processCreatedAt)));
  fs.writeFileSync(
    path.join(directory, "observer-started.json"),
    JSON.stringify({
      schemaVersion: 1,
      startedAt,
      processId: process.pid,
      processCreatedAt,
      configSha256: configSha,
    }),
    { flag: "wx" },
  );
  let initial = null,
    lastNative = 0,
    lastSample = performance.now(),
    immediate = null;
  for (;;) {
    await pause(1000);
    const now = performance.now();
    assert.ok(now - lastSample <= 5000, "Observer sampling gap exceeds bound");
    lastSample = now;
    assert.ok(
      Date.now() < c.epoch(config.lease.hardExpiresAt),
      "Original hard lease expired",
    );
    const leasePath = path.join(directory, "observer-lease.json");
    if (fs.existsSync(leasePath)) {
      const current = JSON.parse(fs.readFileSync(leasePath, "utf8"));
      c.verifyOriginalLease(current, config.lease);
      assert.equal(current.phase, "observer-owned");
    } else
      assert.ok(
        Date.now() < c.epoch(config.lease.expiresAt),
        "Authenticated observer handoff was not received",
      );
    assert.deepEqual(retention.listLedgerThumbprints(ledgerDir), [
      config.predecessor.thumbprint,
    ]);
    const snapshot = ledger.readSnapshot(ledgerPath),
      transition = tracker.observe(snapshot, Date.now(), Math.round(now));
    if (transition || now - lastNative >= 60000) {
      const native = await inspect(config, configPath, configSha);
      lastNative = performance.now();
      lastSample = lastNative;
      if (!initial) initial = native;
      else
        assert.ok(
          isDeepStrictEqual(native, initial),
          "Installed writer, boot, configuration or custody changed",
        );
    }
    if (transition && !immediate) {
      immediate = transition.immediate;
      fs.writeFileSync(
        path.join(directory, "immediate-ready.json"),
        JSON.stringify({
          schemaVersion: 1,
          startedAt,
          immediate,
          native: initial,
          pendingFileId: pending.fileId,
          immediateFileId: snapshot.fileId,
          immutableLedgerSha256: ledger.sha(
            Buffer.from(JSON.stringify(ledger.immutable(snapshot.row))),
          ),
        }),
        { flag: "wx" },
      );
    }
    if (transition?.timer) {
      const completed = tracker.result();
      c.verifyTimerWindow(
        completed.immediate.monotonicMs,
        completed.timer.monotonicMs,
        Math.round(performance.now()),
      );
      const report = {
        schemaVersion: 1,
        scope:
          "observed-installed-default-timer-awaiting-independent-finalization",
        startedAt,
        finishedAt: new Date().toISOString(),
        ...completed,
        native: initial,
        configSha256: configSha,
        defaultIntervalMs: c.BASE_INTERVAL,
        defaultRetentionHours: 168,
        actualCleanupQualified: false,
        full168HourRetentionQualified: false,
      };
      fs.writeFileSync(
        path.join(directory, "observer-result.json"),
        JSON.stringify(report),
        { flag: "wx" },
      );
      return report;
    }
  }
}
async function readObservation(configPath, configSha, completed = false) {
  assert.equal(process.platform, "win32");
  assert.equal(hash(configPath), configSha);
  const config = verifyConfig(
      JSON.parse(fs.readFileSync(configPath, "utf8")),
      configPath,
    ),
    directory = path.dirname(configPath);
  process.env.CERTOPS_ADCS_DISPOSABLE_LAB = "1";
  const ready = JSON.parse(
    fs.readFileSync(path.join(directory, "immediate-ready.json"), "utf8"),
  );
  const started = JSON.parse(
    fs.readFileSync(path.join(directory, "observer-started.json"), "utf8"),
  );
  const native = await inspect(config, configPath, configSha);
  assert.ok(
    isDeepStrictEqual(native, ready.native),
    "Original installed service identity changed",
  );
  const observed = {
    ...Object.fromEntries(c.IDENTITY.map((key) => [key, config.lease[key]])),
    ...Object.fromEntries(c.FLAGS.map((key) => [key, true])),
    principalSid: "S-1-5-18",
    taskState: "Running",
    processId: started.processId,
    processCreatedAt: started.processCreatedAt,
    bootTime: native.bootTime,
    serviceHostPid: native.serviceHostPid,
    serviceHostCreatedAt: native.serviceHostCreatedAt,
    agentPid: native.agentPid,
    agentCreatedAt: native.agentCreatedAt,
    configSha256: native.configSha256,
    observerConfigSha256: configSha,
    immutableLedgerSha256: ready.immutableLedgerSha256,
    pendingLedgerFileId: ready.pendingFileId,
    immediateLedgerFileId: ready.immediateFileId,
    immediateObservedAt: ready.immediate.observedAt,
    immediateMonotonicMs: ready.immediate.monotonicMs,
    oldNotAfter: config.pendingSnapshot.row.oldNotAfter,
    verifiedAt: new Date().toISOString(),
  };
  // Running and completed observations are distinct; never feed a completed task
  // through the initial four-hour handoff validator.
  if (!completed) {
    c.verifyObservation(observed, config.lease);
    return observed;
  }
  const result = JSON.parse(
    fs.readFileSync(path.join(directory, "observer-result.json"), "utf8"),
  );
  assert.equal(result.configSha256, configSha);
  assert.ok(
    isDeepStrictEqual(result.native, native),
    "Final installed identity changed",
  );
  c.verifyTimerWindow(
    result.immediate.monotonicMs,
    result.timer.monotonicMs,
    result.timer.monotonicMs,
  );
  return {
    schemaVersion: 1,
    scope: "completed-installed-default-timer-awaiting-owned-cleanup",
    originalObservation: {
      ...observed,
      verifiedAt: ready.immediate.observedAt,
    },
    result,
    currentNativeVerified: true,
    verifiedAt: new Date().toISOString(),
  };
}
function writeLease(configPath, configSha, encoded) {
  assert.equal(process.platform, "win32");
  assert.equal(hash(configPath), configSha);
  const config = verifyConfig(
    JSON.parse(fs.readFileSync(configPath, "utf8")),
    configPath,
  );
  assert.match(encoded, /^[a-zA-Z0-9+/]+={0,2}$/);
  assert.ok(encoded.length <= 8192);
  const value = JSON.parse(Buffer.from(encoded, "base64").toString("utf8"));
  c.verifyOriginalLease(value, config.lease);
  assert.equal(value.phase, "observer-owned");
  assert.ok(Date.now() < c.epoch(config.lease.expiresAt));
  const file = path.join(path.dirname(configPath), "observer-lease.json");
  // Exclusive publish: a repeated controller request may read back the identical
  // original lease, but cannot renew or substitute a different authority.
  if (!fs.existsSync(file))fs.writeFileSync(file, JSON.stringify(value), { flag: "wx",mode:0o600 });
  const written=fs.lstatSync(file);assert.equal(written.isSymbolicLink(),false);assert.ok(written.isFile()&&written.size>0&&written.size<=8192);
  const readback=ledger.readSnapshot(file).row;c.verifyOriginalLease(readback,config.lease);assert.ok(isDeepStrictEqual(readback,value),"Published original-bound lease readback differs");
  return { schemaVersion: 1, scope: "original-bound-observer-lease-published" };
}
module.exports = {
  verifyConfig,
  trustedTls,
  inspect,
  main,
  readObservation,
  writeLease,
};
if (require.main === module) {
  const mode = process.argv[2];
  Promise.resolve()
    .then(() =>
      mode === "--write-lease"
        ? writeLease(process.argv[3], process.argv[4], process.argv[5])
        : mode === "--observe" || mode === "--final-observe"
          ? readObservation(
              process.argv[3],
              process.argv[4],
              mode === "--final-observe",
            )
          : main(process.argv[2], process.argv[3]),
    )
    .then((value) => {
      if (mode?.startsWith("--")) process.stdout.write(JSON.stringify(value));
    })
    .catch(() => {
      process.stderr.write(
        "Owned cadence observer failed; preserve fixture for independent teardown.\n",
      );
      process.exitCode = 1;
    });
}
