"use strict";
/** Isolated real certificate execution across operator signing-key retirement.
 * An unarmed predecessor issue creates the certificate. The owned renewal is
 * held only after the production agent verifies that original signed claim.
 * No shared fleet is adopted or retired. The native command, CA response,
 * clock and signed claim bytes are never fabricated. Unknown custody preserves
 * DB/private state; only exact retained pidfd resources may request a stop. */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  os = require("node:os"),
  crypto = require("node:crypto"),
  tls = require("node:tls");
const { spawn, spawnSync } = require("node:child_process");
const { createApiFixture } = require("./certops-api-fixture");
const { startClaimGateway } = require("./certops-acme-signing-observer");
const commandOwner = require("./certops-acme-lease-attachment");
const agentOwner = require("./certops-acme-agent-attachment");
const { readOwnedBytes } = require("./certops-acme-native-adoption");
const SCOPE = "isolated-native-certificate-inflight-operator-signing-rotation";
const SCENARIO = "certificate-inflight-old-key-retirement-and-new-key-renewal";
const FLAGS = Object.freeze([
  "initialDatabaseEmpty",
  "soleOwnedActiveAgent",
  "originalUnmodifiedV2ClaimObserved",
  "actualOldClaimAuthenticatedBeforeRotation",
  "oldCommandHeldBeforeNativeCa",
  "operatorBeginSupersededOriginalKey",
  "actualHeartbeatPinAcknowledged",
  "nonforceCompleteBeforeOldCommandRelease",
  "oldKeyJobRealCaKeyAndTrustedTls",
  "newKeyJobRealCaKeyAndTrustedTls",
  "currentClaimEvidenceAndSingleDispatch",
  "operatorProfileAndProtectedConfigurationPreserved",
  "originalAgentIdentityPreserved",
  "naturalCommandPidfdDrain",
  "ownedAgentPidfdDrain",
  "ownedTlsAndGatewayDrain",
  "ownedDatabaseAndPrivateCleanup",
]);
const sha = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const uuid = (value) =>
  typeof value === "string" &&
  /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(value);
function verifyProof(p) {
  assert.ok(p && typeof p === "object" && !Array.isArray(p));
  assert.deepEqual(
    Object.keys(p).sort(),
    [
      "scope",
      "certificateId",
      "jobIds",
      "claimIds",
      "signingKeyIds",
      "fingerprints",
      "spkiFingerprints",
      "client",
      "rotatePrivateKey",
      "sharedFleetQualified",
      "forcedCompletionQualified",
      "atomicTreeContainmentQualified",
      ...FLAGS,
    ].sort(),
  );
  assert.equal(p.scope, SCOPE);
  assert.equal(p.client, "certbot");
  assert.ok(uuid(p.certificateId));
  assert.equal(typeof p.rotatePrivateKey, "boolean");
  for (const key of ["jobIds", "claimIds"])
    assert.ok(
      Array.isArray(p[key]) &&
        p[key].length === 2 &&
        p[key].every(uuid) &&
        new Set(p[key]).size === 2,
    );
  assert.ok(
    Array.isArray(p.signingKeyIds) &&
      p.signingKeyIds.length === 2 &&
      p.signingKeyIds.every(
        (x) => typeof x === "string" && /^[A-Za-z0-9_.:-]{1,128}$/.test(x),
      ) &&
      new Set(p.signingKeyIds).size === 2,
  );
  for (const key of ["fingerprints", "spkiFingerprints"])
    assert.ok(
      Array.isArray(p[key]) &&
        p[key].length === 2 &&
        p[key].every((x) => typeof x === "string" && /^[a-f0-9]{64}$/.test(x)),
    );
  assert.notEqual(p.fingerprints[0], p.fingerprints[1]);
  assert.equal(
    p.spkiFingerprints[0] !== p.spkiFingerprints[1],
    p.rotatePrivateKey,
  );
  for (const key of [
    "sharedFleetQualified",
    "forcedCompletionQualified",
    "atomicTreeContainmentQualified",
  ])
    assert.equal(p[key], false);
  for (const key of FLAGS) assert.equal(p[key], true, key);
  return true;
}
async function waitUntil(check, maximum = 180000) {
  const end = Date.now() + maximum;
  while (Date.now() < end) {
    const result = await check();
    if (result) return result;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw Error("Owned certificate signing phase deadline exceeded");
}
function identity(directory) {
  const s = fs.lstatSync(directory, { bigint: true });
  assert.ok(s.isDirectory() && !s.isSymbolicLink() && s.ino > 0n);
  assert.equal(fs.realpathSync(directory), path.resolve(directory));
  return `${s.dev}:${s.ino}`;
}
function cli(root, command) {
  assert.ok(["status", "begin", "complete"].includes(command));
  assert.equal(
    fs.existsSync(path.join(root, ".env")),
    false,
    "Isolated operator CLI refuses a repository .env",
  );
  const result = spawnSync(
    process.execPath,
    [
      path.join(root, "scripts/certops-rotate-signing-key.js"),
      command,
      "--json",
    ],
    { env: process.env, encoding: "utf8", timeout: 20000, maxBuffer: 65536 },
  );
  assert.ifError(result.error);
  assert.equal(
    result.status,
    0,
    "Owned operator CLI refused; raw output withheld",
  );
  const match = result.stdout.match(/(?:^|\n)(\{[\s\S]*\})\s*$/);
  assert.ok(match);
  return JSON.parse(match[1]);
}
async function qualifyFixture({ baseUrl, repoRoot, fixture, phase }) {
  assert.equal(process.platform, "linux");
  assert.equal(process.env.CERTOPS_CERTIFICATE_SIGNING_DISPOSABLE_STACK, "1");
  assert.equal(process.env.CERTOPS_REAL_ACME_CLIENT, "certbot");
  assert.equal(process.env.CERTOPS_REAL_ACME_EAB || "none", "none");
  assert.equal(fs.existsSync(path.join(repoRoot, ".env")), false);
  const pool = fixture.pool;
  const empty = (
    await pool.query(
      "SELECT (SELECT count(*) FROM certops_agents)::int AS agents,(SELECT count(*) FROM certops_signing_keys)::int AS keys,(SELECT count(*) FROM certificate_jobs)::int AS jobs,(SELECT count(*) FROM managed_certificates)::int AS certificates,(SELECT count(*) FROM certificate_profiles)::int AS profiles",
    )
  ).rows[0];
  assert.deepEqual(empty, {
    agents: 0,
    keys: 0,
    jobs: 0,
    certificates: 0,
    profiles: 0,
  });
  const root = fs.mkdtempSync(
      path.join(os.tmpdir(), "certops-certificate-signing-"),
    ),
    rootId = identity(root),
    configDir = path.join(root, "agent"),
    barrierDirectory = path.join(root, "command");
  fs.mkdirSync(configDir, { mode: 0o700 });
  fs.mkdirSync(barrierDirectory, { mode: 0o700 });
  const configId = identity(configDir),
    barrierId = identity(barrierDirectory),
    marker = path.join(root, ".certificate-signing.guard"),
    markerBytes = crypto.randomBytes(32);
  fs.writeFileSync(marker, markerBytes, { flag: "wx", mode: 0o600 });
  const markerId = fs.lstatSync(marker, { bigint: true });
  const owned = () => {
    assert.equal(identity(root), rootId);
    assert.equal(identity(configDir), configId);
    assert.equal(identity(barrierDirectory), barrierId);
    assert.ok(readOwnedBytes(marker, 32, markerId).equals(markerBytes));
  };
  const resources = [],
    commands = [],
    jobs = [],
    sockets = new Set();
  let agent,
    agentClosed = false,
    originalBirth,
    gateway,
    server,
    proof,
    primary;
  const prefix = `/api/v1/workspaces/${fixture.workspaceId}/certops`,
    agentId = `certificate-signing-${crypto.randomUUID()}`,
    domain = "signing.example.test",
    entry = path.join(repoRoot, "packages/agent/bin/tokentimer-agent.js"),
    wrapper = path.join(__dirname, "certops-acme-signing-command.js");
  const certPath = path.join(root, "deployed/server.pem");
  let certificateId, keyPath;
  const readPin = () =>
    JSON.parse(
      readOwnedBytes(path.join(configDir, "signing-key-pin.json"), 8192),
    ).signingKeyId;
  async function soleFleet() {
    const rows = (
      await pool.query(
        "SELECT id,workspace_id,agent_id,pinned_signing_key_id,status FROM certops_agents WHERE status<>'retired'",
      )
    ).rows;
    assert.equal(rows.length, 1);
    assert.equal(rows[0].workspace_id, fixture.workspaceId);
    assert.equal(rows[0].agent_id, agentId);
    assert.equal(rows[0].status, "active");
    assert.equal(agent.exitCode, null);
    assert.equal(agent.signalCode, null);
    const observed = fs.readFileSync(`/proc/${agent.pid}/stat`, "utf8");
    const fields = observed.slice(observed.lastIndexOf(") ") + 2).split(/\s+/);
    assert.equal(fields[19], originalBirth);
    assert.equal(Number(fields[1]), process.pid);
    assert.equal(
      fs.readlinkSync(`/proc/${agent.pid}/exe`),
      fs.realpathSync(process.execPath),
    );
    assert.deepEqual(
      fs
        .readFileSync(`/proc/${agent.pid}/cmdline`, "utf8")
        .split("\0")
        .filter(Boolean),
      [process.execPath, entry],
    );
    return rows[0];
  }
  async function job(id) {
    return (
      await pool.query(
        "SELECT id,status,operation,mode,source,claim_id,attempt_count,claimed_by_agent_id,subject_id FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",
        [fixture.workspaceId, id],
      )
    ).rows[0];
  }
  async function terminal(id) {
    return waitUntil(async () => {
      const row = await job(id);
      if (["failed", "rejected", "cancelled"].includes(row?.status))
        throw Error("Owned real certificate job failed");
      return row?.status === "succeeded" ? row : null;
    });
  }
  async function validateResult(id, expectedKey) {
    const row = await terminal(id),
      agentRow = await soleFleet();
    assert.ok(uuid(row.claim_id));
    assert.equal(row.attempt_count, 1);
    assert.equal(row.mode, "real");
    assert.equal(row.operation, "renew");
    assert.equal(String(row.subject_id), certificateId);
    assert.equal(row.claimed_by_agent_id, agentRow.id);
    assert.equal(gateway.signingKeyFor(id), expectedKey);
    const nonces = (
      await pool.query(
        "SELECT nonce FROM certops_consumed_nonces WHERE workspace_id=$1 AND job_id=$2 AND issued_to_agent_id=$3",
        [fixture.workspaceId, id, agentRow.id],
      )
    ).rows;
    assert.equal(nonces.length, 1);
    const leaf = new crypto.X509Certificate(fs.readFileSync(certPath));
    assert.equal(leaf.checkHost(domain), domain);
    assert.ok(
      leaf.checkPrivateKey(crypto.createPrivateKey(fs.readFileSync(keyPath))),
    );
    const fingerprint = sha(leaf.raw),
      evidence = (
        await pool.query(
          "SELECT metadata FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2 AND claim_id=$3 AND evidence_type='validation.passed' AND metadata->>'step'='verify'",
          [fixture.workspaceId, id, row.claim_id],
        )
      ).rows;
    assert.ok(
      evidence.some(
        (x) =>
          String(x.metadata.fingerprintSha256)
            .replaceAll(":", "")
            .toLowerCase() === fingerprint,
      ),
    );
    return {
      row,
      leaf,
      fingerprint,
      spki: sha(leaf.publicKey.export({ type: "spki", format: "der" })),
    };
  }
  async function trusted() {
    return new Promise((resolve, reject) => {
      let result, failure;
      const socket = tls.connect(
        {
          host: "127.0.0.1",
          port: server.address().port,
          servername: domain,
          ca: fs.readFileSync(process.env.CERTOPS_PEBBLE_ISSUER_ROOT),
          rejectUnauthorized: true,
        },
        () => {
          try {
            assert.equal(socket.authorized, true);
            result = sha(socket.getPeerCertificate().raw);
          } catch (error) {
            failure = error;
          } finally {
            socket.destroy();
          }
        },
      );
      socket.once("error", (error) => {
        failure = error;
        socket.destroy();
      });
      socket.once("close", () =>
        failure
          ? reject(failure)
          : result
            ? resolve(result)
            : reject(Error("Trusted signing TLS closed before observation")),
      );
      socket.setTimeout(10000, () =>
        socket.destroy(Error("Trusted signing TLS deadline exceeded")),
      );
    });
  }
  try {
    gateway = await startClaimGateway(baseUrl);
    const dns = path.join(configDir, "dns.json");
    fs.writeFileSync(
      dns,
      JSON.stringify({
        baseUrl: process.env.CERTOPS_PEBBLE_DNS_API,
        allowInsecureLocalHttp: true,
      }),
      { mode: 0o600 },
    );
    const config = {
      serverUrl: gateway.agentUrl,
      agentId,
      allowInsecureLocalHttp: true,
      pollIntervalMs: 500,
      heartbeatIntervalMs: 1000,
      windowsDiscovery: { enabled: false },
      discovery: { directories: [] },
      declaredTargetSelectors: [domain],
      declaredCommandProfileNames: ["signing-certbot"],
      execution: { enabled: true, dryRun: false },
      policy: {
        allowedPaths: [root],
        allowedCommands: {
          "signing-certbot": {
            argv: [
              process.execPath,
              wrapper,
              barrierDirectory,
              "certbot",
              "--no-verify-ssl",
              "--agree-tos",
              "--register-unsafely-without-email",
            ],
          },
        },
        allowedCaEndpoints: [process.env.CERTOPS_PEBBLE_DIRECTORY],
        allowedDnsZones: ["example.test"],
        allowedDnsProviders: ["pebble-challtestsrv"],
      },
      dnsProviders: {
        "pebble-challtestsrv": { credentialsFile: dns },
        zoneProviderMap: { "example.test": "pebble-challtestsrv" },
      },
      dnsPropagation: {
        resolvers: [process.env.CERTOPS_PEBBLE_DNS_RESOLVER],
        checkAuthoritative: false,
        intervalMs: 500,
        timeoutMs: 30000,
      },
    };
    fs.writeFileSync(
      path.join(configDir, "config.json"),
      JSON.stringify(config),
      { flag: "wx", mode: 0o600 },
    );
    const bootstrap = await fixture.request(
      `${prefix}/agent-bootstrap-tokens`,
      "POST",
      {
        name: "Isolated certificate signing agent",
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
      },
    );
    assert.equal(bootstrap.status, 201);
    phase.nativeStarted = true;
    agent = spawn(process.execPath, [entry], {
      cwd: repoRoot,
      stdio: "ignore",
      env: {
        PATH: process.env.PATH,
        HOME: process.env.HOME,
        LANG: "C.UTF-8",
        TOKENTIMER_AGENT_CONFIG_DIR: configDir,
        TOKENTIMER_AGENT_BOOTSTRAP_TOKEN: bootstrap.body.plaintextToken,
        TOKENTIMER_AGENT_BOOTSTRAP_TOKEN_ID: String(bootstrap.body.token.id),
      },
    });
    agent.once("close", () => {
      agentClosed = true;
    });
    agent.once("error", () => {});
    await waitUntil(() => {
      assert.equal(agent.exitCode, null);
      try {
        const raw = fs.readFileSync(`/proc/${agent.pid}/stat`, "utf8");
        originalBirth = raw.slice(raw.lastIndexOf(") ") + 2).split(/\s+/)[19];
        return originalBirth;
      } catch (error) {
        if (error.code === "ENOENT") return false;
        throw error;
      }
    }, 10000);
    await waitUntil(
      async () =>
        (
          await pool.query(
            "SELECT 1 FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2",
            [fixture.workspaceId, agentId],
          )
        ).rows.length &&
        fs.existsSync(path.join(configDir, "signing-key-pin.json")),
    );
    await soleFleet();
    const oldKey = cli(repoRoot, "status").active.signingKeyId;
    assert.equal(readPin(), oldKey);
    const protectedFiles = ["config.json", "credential"].map((name) => {
      const file = path.join(configDir, name),
        id = fs.lstatSync(file, { bigint: true });
      return { file, id, bytes: readOwnedBytes(file, 1048576, id) };
    });
    const issued = await fixture.request(`${prefix}/jobs`, "POST", {
      operation: "issue",
      idempotencyKey: crypto.randomUUID(),
      payload: {
        sans: [domain],
        target: { type: "domain", reference: domain },
        certPath,
        commandRef: "signing-certbot",
        caEndpoint: process.env.CERTOPS_PEBBLE_DIRECTORY,
        acmeKind: "certbot",
        dnsProvider: "pebble-challtestsrv",
        dnsZone: "example.test",
      },
    });
    assert.equal(issued.status, 201);
    certificateId = issued.body.job.subjectId;
    assert.ok(uuid(certificateId));
    keyPath = path.join(configDir, "keys", `${certificateId}.key.pem`);
    await terminal(issued.body.job.id);
    const predecessor = new crypto.X509Certificate(fs.readFileSync(certPath));
    assert.equal(predecessor.checkHost(domain), domain);
    assert.ok(
      predecessor.checkPrivateKey(
        crypto.createPrivateKey(fs.readFileSync(keyPath)),
      ),
    );
    const predecessorFingerprint = sha(predecessor.raw),
      predecessorSpki = sha(
        predecessor.publicKey.export({ type: "spki", format: "der" }),
      ),
      currentFingerprint = () =>
        sha(new crypto.X509Certificate(fs.readFileSync(certPath)).raw);
    const profile = (
      await pool.query(
        "SELECT cp.id,cp.public_metadata FROM managed_certificates mc JOIN certificate_profiles cp ON cp.workspace_id=mc.workspace_id AND cp.id=mc.profile_id WHERE mc.workspace_id=$1 AND mc.id=$2",
        [fixture.workspaceId, certificateId],
      )
    ).rows[0];
    assert.ok(profile?.public_metadata?.renewalProfile);
    const rotate =
      profile.public_metadata.renewalProfile.keyRotationPolicy.rotateOnRenew;
    assert.equal(typeof rotate, "boolean");
    await new Promise((resolve) => setTimeout(resolve, 1500));
    const processFile = path.join(barrierDirectory, "process.json");
    assert.equal(fs.existsSync(processFile), false);
    const token = crypto.randomUUID(),
      arm = path.join(barrierDirectory, "armed.json");
    fs.writeFileSync(arm, JSON.stringify({ token }), {
      flag: "wx",
      mode: 0o600,
    });
    const admitted = await fixture.request(`${prefix}/jobs`, "POST", {
      operation: "renew",
      subjectType: "managed_certificate",
      subjectId: certificateId,
      idempotencyKey: crypto.randomUUID(),
    });
    if (admitted.body?.job?.id) jobs.push(admitted.body.job.id);
    assert.equal(admitted.status, 201);
    await waitUntil(() => fs.existsSync(processFile), 60000);
    const native = JSON.parse(readOwnedBytes(processFile, 8192));
    const observer = commandOwner.attach({
      proof: native,
      token,
      agent,
      barrierDirectory,
      ownedResources: commands,
      waitUntil,
      commandWrapper: wrapper,
    });
    await observer.ready;
    const claimed = await job(jobs[0]),
      ownedAgent = await soleFleet();
    assert.ok(["claimed", "running"].includes(claimed.status));
    assert.ok(uuid(claimed.claim_id));
    assert.equal(claimed.attempt_count, 1);
    assert.equal(claimed.claimed_by_agent_id, ownedAgent.id);
    assert.equal(gateway.signingKeyFor(jobs[0]), oldKey);
    assert.equal(currentFingerprint(), predecessorFingerprint);
    assert.equal(
      (
        await pool.query(
          "SELECT nonce FROM certops_consumed_nonces WHERE workspace_id=$1 AND job_id=$2 AND issued_to_agent_id=$3",
          [fixture.workspaceId, jobs[0], ownedAgent.id],
        )
      ).rows.length,
      1,
    );
    const begun = cli(repoRoot, "begin"),
      newKey = begun.signingKeyId;
    assert.equal(begun.supersedesSigningKeyId, oldKey);
    assert.notEqual(newKey, oldKey);
    await waitUntil(
      async () =>
        readPin() === newKey &&
        (await soleFleet()).pinned_signing_key_id === newKey,
    );
    const acknowledged = cli(repoRoot, "status");
    assert.equal(acknowledged.activeAgents, 1);
    assert.equal(acknowledged.ackCount, 1);
    assert.equal(acknowledged.fullyAcked, true);
    const completed = cli(repoRoot, "complete");
    assert.equal(completed.completed, true);
    assert.equal(completed.forced, false);
    assert.equal(completed.retiredSigningKeyId, oldKey);
    assert.equal((await job(jobs[0])).claim_id, claimed.claim_id);
    assert.equal(currentFingerprint(), predecessorFingerprint);
    assert.equal(cli(repoRoot, "status").rotationInProgress, false);
    owned();
    fs.writeFileSync(path.join(barrierDirectory, "go"), token, {
      flag: "wx",
      mode: 0o600,
    });
    const goId = fs.lstatSync(path.join(barrierDirectory, "go"), {
      bigint: true,
    });
    const first = await validateResult(jobs[0], oldKey);
    assert.equal(first.row.claim_id, claimed.claim_id);
    assert.notEqual(first.fingerprint, predecessorFingerprint);
    assert.equal(first.spki !== predecessorSpki, rotate);
    await observer.waitForNativeExit();
    await observer.stopAndDrain();
    observer.removeOwnedBarriersAndRelease();
    assert.ok(
      readOwnedBytes(path.join(barrierDirectory, "go"), 36, goId).equals(
        Buffer.from(token),
      ),
    );
    fs.unlinkSync(path.join(barrierDirectory, "go"));
    server = tls.createServer(
      {
        cert: fs.readFileSync(certPath),
        key: fs.readFileSync(keyPath),
        SNICallback: (_name, callback) => {
          try {
            callback(
              null,
              tls.createSecureContext({
                cert: fs.readFileSync(certPath),
                key: fs.readFileSync(keyPath),
              }),
            );
          } catch (error) {
            callback(error);
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
    assert.equal(await trusted(), first.fingerprint);
    assert.deepEqual(
      (
        await pool.query(
          "SELECT cp.id,cp.public_metadata FROM managed_certificates mc JOIN certificate_profiles cp ON cp.workspace_id=mc.workspace_id AND cp.id=mc.profile_id WHERE mc.workspace_id=$1 AND mc.id=$2",
          [fixture.workspaceId, certificateId],
        )
      ).rows[0],
      profile,
    );
    await new Promise((resolve) => setTimeout(resolve, 1500));
    const fresh = await fixture.request(`${prefix}/jobs`, "POST", {
      operation: "renew",
      subjectType: "managed_certificate",
      subjectId: certificateId,
      idempotencyKey: crypto.randomUUID(),
    });
    if (fresh.body?.job?.id) jobs.push(fresh.body.job.id);
    assert.equal(fresh.status, 201);
    const second = await validateResult(jobs[1], newKey);
    assert.equal(await trusted(), second.fingerprint);
    assert.notEqual(first.leaf.serialNumber, second.leaf.serialNumber);
    assert.ok(Date.parse(second.leaf.validTo) > Date.parse(first.leaf.validTo));
    assert.equal(first.spki !== second.spki, rotate);
    assert.deepEqual(
      (
        await pool.query(
          "SELECT cp.id,cp.public_metadata FROM managed_certificates mc JOIN certificate_profiles cp ON cp.workspace_id=mc.workspace_id AND cp.id=mc.profile_id WHERE mc.workspace_id=$1 AND mc.id=$2",
          [fixture.workspaceId, certificateId],
        )
      ).rows[0],
      profile,
    );
    for (const item of protectedFiles)
      assert.ok(readOwnedBytes(item.file, 1048576, item.id).equals(item.bytes));
    assert.equal(readPin(), newKey);
    await soleFleet();
    proof = {
      scope: SCOPE,
      certificateId,
      jobIds: jobs,
      claimIds: [first.row.claim_id, second.row.claim_id],
      signingKeyIds: [oldKey, newKey],
      fingerprints: [first.fingerprint, second.fingerprint],
      spkiFingerprints: [first.spki, second.spki],
      client: "certbot",
      rotatePrivateKey: rotate,
      sharedFleetQualified: false,
      forcedCompletionQualified: false,
      atomicTreeContainmentQualified: false,
      ...Object.fromEntries(FLAGS.map((flag) => [flag, true])),
    };
  } catch (error) {
    primary = error;
  }
  const failures = [];
  const cleanup = async (action) => {
    try {
      await action();
    } catch (error) {
      failures.push(error);
    }
  };
  for (const command of commands) await cleanup(() => command.stopAndDrain());
  if (agent && !agentClosed)
    await cleanup(async () => {
      await waitUntil(() => {
        const raw = fs.readFileSync(
          `/proc/${agent.pid}/task/${agent.pid}/children`,
          "utf8",
        );
        return !raw.trim();
      }, 660000);
      const resource = await agentOwner.attachIdleAgent({
        agent,
        entry,
        workDir: root,
        resources,
        waitUntil,
        isAgentClosed: () => agentClosed,
        expectedStartTicks: originalBirth,
      });
      await resource.stopAndDrain();
      resource.release();
    });
  if (server)
    await cleanup(async () => {
      const completion = new Promise((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
      for (const socket of sockets) socket.destroy();
      await completion;
      assert.equal(sockets.size, 0);
    });
  if (gateway) await cleanup(() => gateway.close());
  if (failures.length) {
    await pool.end();
    throw new AggregateError(
      [...(primary ? [primary] : []), ...failures],
      "Owned signing consumers unresolved; preserve DB/private state",
    );
  }
  try {
    commandOwner.assertCleanupSafe(barrierDirectory);
    agentOwner.assertCleanupSafe(root);
    assert.ok(!agent || agentClosed);
    gateway?.assertClean();
    owned();
    // A failed operation never authorizes discarding uncertain command receipts.
    assert.equal(
      commands.some((item) => item.hasOwnershipReceipt()),
      false,
    );
    if (primary) throw primary;
  } catch (error) {
    await pool.end();
    throw error;
  }
  await fixture.cleanup();
  phase.cleanupCompleted = true;
  owned();
  fs.rmSync(root, { recursive: true });
  if (primary) throw primary;
  verifyProof(proof);
  return proof;
}
async function qualify(context) {
  assert.equal(process.platform, "linux");
  assert.equal(process.env.CERTOPS_CERTIFICATE_SIGNING_DISPOSABLE_STACK, "1");
  const fixture = await createApiFixture(context.baseUrl);
  const phase = { nativeStarted: false, cleanupCompleted: false };
  try {
    return await qualifyFixture({ ...context, fixture, phase });
  } catch (error) {
    if (!phase.nativeStarted && !phase.cleanupCompleted)
      await fixture.cleanup();
    throw error;
  }
}
module.exports = {
  SCOPE,
  SCENARIO,
  FLAGS,
  verifyProof,
  waitUntil,
  cli,
  qualify,
};
