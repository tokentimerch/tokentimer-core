/**
 * Qualification: same-process paired filesystem rotation
 *
 * Install a distinct genuine baseline, then start two production deployCertificateAndKey
 * calls for the SAME certificate/key/chain before awaiting either. Use default backups,
 * real filesystem/clock and no injected delay. Destination mutex must preserve call
 * order: both mutate, final disk pair equals second contender, first contender backups
 * equal baseline, second contender backups equal first contender, all six backup paths
 * distinct/exact. Native ACL/ mode oracle, original staged keys and outside sentinel
 * must remain valid. One retained TLS listener reads disk for baseline and settled-final
 * connections; both require exact CA/hostname and final fingerprint. These checkpoints
 * do not claim uninterrupted file-write availability, cross-process locking, API
 * dispatch, ACME issuance or daemon reload. Await every deploy promise and all retained
 * sockets/ listener close before cleanup. Unknown drain/ownership retains durable guard;
 * keys/private hashes/receipt paths never enter public proof. Ubuntu 22.04/24.04 and
 * Windows Server 2022/2025 require their own native report/current source fingerprints.
 */
// Shared execution, evidence and cleanup policy: docs/certops/e2e-qualification.md.
"use strict";
/** Native direct-deployer concurrency qualification. Two real same-process calls
 * target one certificate/key/chain set, using the unmodified default backup directory alongside the target.
 * No filesystem/clock substitution or cross-process lock claim is made. The
 * loopback TLS listener reads actual deployed files only at stable checkpoints.
 * Private files/receipts stay local; an unknown listener drain blocks cleanup. */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  os = require("node:os"),
  crypto = require("node:crypto"),
  tls = require("node:tls");
const { isDeepStrictEqual } = require("node:util");
const deploy = require("../packages/agent/src/deploy"),
  policy = require("../packages/agent/src/policy");
const SCENARIO = "filesystem-concurrent-paired-rotation";
const SCOPE = "native-filesystem-same-process-paired-rotation";
const FLAGS = Object.freeze([
  "actualBaselineDeployed",
  "bothSubmittedBeforeAwait",
  "bothNativeMutationsCompleted",
  "finalPairAndChainVerified",
  "serialBackupLineageVerified",
  "privateKeyPermissionsVerified",
  "privateStagingPreserved",
  "outsideSentinelUnchanged",
  "trustedBaselineAndFinalTlsVerified",
  "nativeListenerClosed",
  "ownedCleanupCompleted",
]);
const REQUIRED_SOURCES = Object.freeze([
  "scripts/certops-filesystem-concurrent.js",
  "scripts/certops-filesystem-host.js",
  "packages/agent/src/deploy/index.js",
  "packages/agent/src/verify/index.js",
  "packages/agent/src/policy/index.js",
  "packages/agent/src/platform/index.js",
  "packages/agent/src/platform/durability.js",
  "packages/agent/scripts/host-gate.js",
]);
const owners = new Map(),
  PREFIX = ".preserve-filesystem-concurrency-";
const hash = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const fingerprint = (certificate) =>
  certificate.fingerprint256.replaceAll(":", "").toLowerCase();
function canonicalDirectory(file) {
  const before = fs.lstatSync(file, { bigint: true });
  assert.ok(
    before.isDirectory() && !before.isSymbolicLink() && before.ino > 0n,
    "Owned temporary directory must be regular before canonicalization",
  );
  const canonical = fs.realpathSync.native(file),
    after = fs.lstatSync(canonical, { bigint: true });
  assert.ok(
    after.isDirectory() &&
      !after.isSymbolicLink() &&
      after.ino === before.ino &&
      after.dev === before.dev,
    "Owned temporary directory changed during native canonicalization",
  );
  return path.resolve(canonical);
}
function identity(file, directory = false) {
  const stat = fs.lstatSync(file, { bigint: true });
  assert.ok(
    stat.ino > 0n &&
      !stat.isSymbolicLink() &&
      (directory ? stat.isDirectory() : stat.isFile()),
  );
  assert.equal(
    path.resolve(fs.realpathSync.native(file)).toLowerCase(),
    path.resolve(file).toLowerCase(),
  );
  return `${stat.dev}:${stat.ino}`;
}
function snapshot(file) {
  return { id: identity(file), sha256: hash(fs.readFileSync(file)) };
}
function assertUnchanged(files, before) {
  assert.ok(
    isDeepStrictEqual(files.map(snapshot), before),
    "Owned filesystem identity changed; private diagnostics withheld",
  );
}
function verifyLineage(value) {
  const digest = (v) => typeof v === "string" && /^[a-f0-9]{64}$/.test(v);
  assert.ok(
    Array.isArray(value.fingerprints) &&
      value.fingerprints.length === 3 &&
      value.fingerprints.every(digest) &&
      new Set(value.fingerprints).size === 3,
  );
  assert.ok(
    Array.isArray(value.spkiFingerprints) &&
      value.spkiFingerprints.length === 3 &&
      value.spkiFingerprints.every(digest) &&
      new Set(value.spkiFingerprints).size === 3,
  );
  assert.deepEqual(
    value.completionOrder,
    ["contender-b", "contender-c"],
    "Native target mutex must preserve actual invocation order",
  );
  const index = (name) => (name === "contender-b" ? 1 : 2);
  assert.deepEqual(value.backupPredecessors, [
    value.fingerprints[0],
    value.fingerprints[index(value.completionOrder[0])],
  ]);
  assert.equal(value.servedBeforeFingerprint, value.fingerprints[0]);
  assert.equal(
    value.servedAfterFingerprint,
    value.fingerprints[index(value.completionOrder[1])],
  );
  return true;
}
function verifyProof(value) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value));
  assert.deepEqual(
    Object.keys(value).sort(),
    [
      "schemaVersion",
      "scope",
      "processScope",
      "contenderCount",
      "completedMutations",
      "backupNamespaces",
      "fingerprints",
      "spkiFingerprints",
      "completionOrder",
      "backupPredecessors",
      "servedBeforeFingerprint",
      "servedAfterFingerprint",
      ...FLAGS,
    ].sort(),
  );
  assert.equal(value.schemaVersion, 1);
  assert.equal(value.scope, SCOPE);
  assert.equal(value.processScope, "one-native-node-process");
  assert.equal(value.contenderCount, 2);
  assert.equal(value.completedMutations, 2);
  assert.equal(value.backupNamespaces, "default-alongside-target");
  for (const name of FLAGS) assert.equal(value[name], true, name);
  verifyLineage(value);
  return true;
}
function assertCleanupSafe(workDir) {
  const root = canonicalDirectory(workDir);
  assert.equal(
    [...owners.values()].some((owner) => owner.root === root),
    false,
    "Preserve unresolved native filesystem listener ownership",
  );
  assert.equal(
    fs.readdirSync(root).some((name) => name.startsWith(PREFIX)),
    false,
    "Preserve durable filesystem listener ownership",
  );
}
async function qualifyConcurrentRotation({
  workDir,
  materials,
  independentlyCheckKeyPermissions,
}) {
  assert.ok(["linux", "win32"].includes(process.platform));
  assert.equal(process.env.GITHUB_ACTIONS, "true");
  assert.equal(process.env.RUNNER_ENVIRONMENT, "github-hosted");
  assert.equal(process.env.CERTOPS_FILESYSTEM_DISPOSABLE_HOST, "1");
  assert.ok(Array.isArray(materials) && materials.length === 3);
  assert.equal(typeof independentlyCheckKeyPermissions, "function");
  const root = canonicalDirectory(workDir);
  assert.equal(
    path.dirname(root),
    path.resolve(fs.realpathSync.native(os.tmpdir())),
  );
  assert.ok(path.basename(root).startsWith("certops-filesystem-"));
  const rootId = identity(root, true);
  const directory = fs.mkdtempSync(path.join(root, "concurrent-")),
    directoryId = identity(directory, true),
    token = crypto.randomUUID(),
    guard = path.join(root, PREFIX + token + ".json");
  const guardBytes = Buffer.from(
    JSON.stringify({ schemaVersion: 1, token, directory }),
  );
  fs.writeFileSync(guard, guardBytes, { flag: "wx", mode: 0o600 });
  const owner = {
    root,
    rootId,
    directory,
    directoryId,
    guard,
    guardId: identity(guard),
    guardHash: hash(guardBytes),
  };
  owners.set(guard, owner);
  const sockets = new Set();
  let server,
    serverBound = false,
    serverFailed = false,
    cleanupComplete = false,
    proof;
  const checkOwned = () => {
    assert.equal(identity(root, true), rootId);
    assert.equal(identity(directory, true), directoryId);
    assert.equal(identity(guard), owner.guardId);
    assert.ok(
      hash(fs.readFileSync(guard)) === owner.guardHash,
      "Filesystem owner receipt changed",
    );
  };
  async function closeListener() {
    const closing = [...sockets].map((socket) => {
      if (socket.closed) {
        sockets.delete(socket);
        return Promise.resolve();
      }
      return new Promise((resolve) => socket.once("close", resolve));
    });
    for (const socket of sockets) socket.destroy();
    if (serverBound)
      closing.push(
        new Promise((resolve, reject) =>
          server.close((error) =>
            error
              ? reject(new Error("Owned TLS listener close failed"))
              : resolve(),
          ),
        ),
      );
    else
      assert.ok(
        !server || !server.listening,
        "Unknown native listener state; preserve files",
      );
    let timer;
    try {
      await Promise.race([
        Promise.all(closing),
        new Promise((_, reject) => {
          timer = setTimeout(
            () =>
              reject(
                new Error(
                  "Owned TLS listener/socket drainage unknown; preserve files",
                ),
              ),
            10000,
          );
        }),
      ]);
    } finally {
      clearTimeout(timer);
    }
    assert.equal(
      sockets.size,
      0,
      "Owned native sockets remain; preserve files",
    );
    if (server) assert.equal(server.listening, false);
    serverBound = false;
  }

  try {
    const deployed = path.join(directory, "deployed");
    fs.mkdirSync(deployed, { mode: 0o700 });
    const sentinel = path.join(directory, "outside-sentinel");
    fs.writeFileSync(sentinel, crypto.randomBytes(48), {
      flag: "wx",
      mode: 0o600,
    });
    const sentinelBefore = [snapshot(sentinel)];
    const target = {
      type: "domain",
      reference: "filesystem.example.test",
      certPath: path.join(deployed, "leaf.pem"),
      keyPath: path.join(deployed, "key.pem"),
      chainPath: path.join(deployed, "chain.pem"),
    };
    const files = [target.certPath, target.keyPath, target.chainPath];
    const checkPath = policy.createPolicyEngine(
      policy.loadPolicyConfig({ allowedPaths: [deployed] }),
    ).checkPath;
    for (const material of materials)
      assert.equal(
        path.dirname(path.resolve(material.privateKeyPath)),
        root,
        "Use only original owned fixture key paths",
      );
    const sourceKeys = materials.map((material) => material.privateKeyPath),
      sourceBefore = sourceKeys.map(snapshot);
    const certificates = materials.map(
      (material) => new crypto.X509Certificate(material.certificatePem),
    );
    const fingerprints = certificates.map(fingerprint),
      spkiFingerprints = certificates.map((certificate) =>
        hash(certificate.publicKey.export({ type: "spki", format: "der" })),
      );
    assert.equal(new Set(fingerprints).size, 3);
    assert.equal(new Set(spkiFingerprints).size, 3);
    const invoke = (index) =>
      deploy.deployCertificateAndKey({
        target,
        certificatePem: materials[index].certificatePem,
        privateKeyPath: materials[index].privateKeyPath,
        chainPem: materials[index].chainPem,
        checkPath,
        retainPrivateKeyStaging: true,
      });
    function observeMaterial(index, paths = files) {
      const material = materials[index],
        certificate = new crypto.X509Certificate(fs.readFileSync(paths[0]));
      assert.equal(fingerprint(certificate), fingerprints[index]);
      assert.equal(certificate.checkHost(target.reference), target.reference);
      assert.ok(
        certificate.checkPrivateKey(
          crypto.createPrivateKey(fs.readFileSync(paths[1])),
        ),
        "Native deployed/backup key correspondence failed",
      );
      assert.ok(
        hash(fs.readFileSync(paths[1])) ===
          hash(fs.readFileSync(material.privateKeyPath)),
        "Owned private key bytes changed",
      );
      assert.equal(fs.readFileSync(paths[2], "utf8"), material.chainPem);
      assert.equal(
        certificate.verify(
          new crypto.X509Certificate(material.chainPem).publicKey,
        ),
        true,
      );
      for (const file of paths) identity(file);
      independentlyCheckKeyPermissions(paths[1]);
    }
    const baseline = await invoke(0);
    assert.equal(baseline.deployed, true);
    observeMaterial(0);
    const context = () => ({
      key: fs.readFileSync(target.keyPath),
      cert:
        fs.readFileSync(target.certPath, "utf8") +
        "\n" +
        fs.readFileSync(target.chainPath, "utf8"),
    });
    server = tls.createServer(
      {
        ...context(),
        SNICallback: (name, callback) => {
          try {
            assert.equal(name, target.reference);
            callback(null, tls.createSecureContext(context()));
          } catch {
            callback(new Error("Owned TLS file context unavailable"));
          }
        },
      },
      (socket) => socket.end(),
    );
    server.on("connection", (socket) => {
      sockets.add(socket);
      socket.once("close", () => sockets.delete(socket));
    });
    server.on("tlsClientError", () => {});
    server.on("error", () => {
      serverFailed = true;
    });
    await new Promise((resolve, reject) => {
      const onError = () => reject(new Error("Owned TLS listener failed"));
      server.once("error", onError);
      server.listen(0, "127.0.0.1", () => {
        server.removeListener("error", onError);
        serverBound = true;
        resolve();
      });
    });
    function served() {
      return new Promise((resolve, reject) => {
        const socket = tls.connect({
          host: "127.0.0.1",
          port: server.address().port,
          servername: target.reference,
          ca: materials[0].chainPem,
          rejectUnauthorized: true,
        });
        sockets.add(socket);
        socket.once("close", () => sockets.delete(socket));
        socket.setTimeout(10000, () => {
          socket.destroy();
          reject(new Error("Owned trusted TLS observation timed out"));
        });
        socket.once("error", () =>
          reject(new Error("Owned trusted TLS observation failed")),
        );
        socket.once("secureConnect", () => {
          try {
            assert.equal(socket.authorized, true);
            const raw = socket.getPeerCertificate().raw;
            assert.ok(raw);
            const observed = fingerprint(new crypto.X509Certificate(raw));
            socket.end();
            resolve(observed);
          } catch {
            socket.destroy();
            reject(new Error("Owned served certificate unavailable"));
          }
        });
      });
    }
    const servedBeforeFingerprint = await served();
    assert.equal(servedBeforeFingerprint, fingerprints[0]);
    const completions = [];
    let submitted = 0;
    const contenders = [1, 2].map((index) => {
      submitted++;
      return invoke(index).then((result) => {
        completions.push({ index, result });
        return result;
      });
    });
    assert.equal(submitted, 2);
    assert.equal(
      completions.length,
      0,
      "Both actual native calls must be submitted before awaiting either",
    );
    const settled = await Promise.allSettled(contenders);
    assert.ok(
      settled.every((row) => row.status === "fulfilled"),
      "Native contenders must both settle successfully before cleanup",
    );
    assert.equal(completions.length, 2);
    for (const { result } of completions) {
      assert.equal(result.deployed, true);
      assert.equal(result.skipped, false);
    }
    const backupPredecessors = [];
    const backupPaths = [];
    for (const [order, { result }] of completions.entries()) {
      const paths = [
        result.backupPaths.cert,
        result.backupPaths.key,
        result.backupPaths.chain,
      ];
      for (const file of paths) {
        assert.equal(path.dirname(file), deployed);
        backupPaths.push(path.resolve(file));
      }
      const preceding = order === 0 ? 0 : completions[0].index;
      observeMaterial(preceding, paths);
      backupPredecessors.push(fingerprints[preceding]);
    }
    assert.equal(new Set(backupPaths).size, 6);
    const winner = completions[1].index;
    observeMaterial(winner);
    assertUnchanged(sourceKeys, sourceBefore);
    assertUnchanged([sentinel], sentinelBefore);
    const servedAfterFingerprint = await served();
    assert.equal(servedAfterFingerprint, fingerprints[winner]);
    proof = {
      schemaVersion: 1,
      scope: SCOPE,
      processScope: "one-native-node-process",
      contenderCount: 2,
      completedMutations: 2,
      backupNamespaces: "default-alongside-target",
      fingerprints,
      spkiFingerprints,
      completionOrder: completions.map(({ index }) =>
        index === 1 ? "contender-b" : "contender-c",
      ),
      backupPredecessors,
      servedBeforeFingerprint,
      servedAfterFingerprint,
      ...Object.fromEntries(FLAGS.map((name) => [name, true])),
    };
    verifyLineage(proof);
  } finally {
    await closeListener();
    checkOwned();
    fs.rmSync(directory, { recursive: true });
    assert.equal(fs.existsSync(directory), false);
    assert.equal(identity(guard), owner.guardId);
    assert.ok(hash(fs.readFileSync(guard)) === owner.guardHash);
    fs.unlinkSync(guard);
    owners.delete(guard);
    cleanupComplete = true;
  }
  assert.equal(cleanupComplete, true);
  assert.equal(
    serverFailed,
    false,
    "Owned TLS listener reported a native failure",
  );
  verifyProof(proof);
  return proof;
}
module.exports = {
  SCENARIO,
  SCOPE,
  FLAGS,
  REQUIRED_SOURCES,
  verifyProof,
  verifyLineage,
  canonicalDirectory,
  snapshot,
  assertUnchanged,
  assertCleanupSafe,
  qualifyConcurrentRotation,
};
