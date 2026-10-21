/**
 * Qualification: independent native trust ownership
 *
 * Generate two unrelated roots/leaves. Default OS OpenSSL rejects both before native
 * production distribution/finalized receipt, accepts both after; never bypass inventory
 * with -CAfile/-untrusted. Revoke only first root:first leaf untrusted, second leaf
 * still trusted, second root source/receipt bytes/identity/modes exact. Ubuntu
 * independently checks derived /etc/ssl/certs source-link names/targets still resolve
 * second root; Alma checks derived directory. Refresh may regenerate link inodes, so do
 * not require those unchanged. Finally revoke second root and prove both untrusted.
 * Register exact source before mutation; durable guard blocks parent recursion after
 * uncertain state/ownership. Keep public CA inputs for parent's independent absence
 * checks before private root removal. Proof excludes keys, PEM, paths/store inventory.
 * Sequential selective ownership is not simultaneous refresh, cross-process
 * serialization or signed API/service dispatch; all Ubuntu/Alma slots need native closed
 * proof/current source fingerprints.
 */
// Shared execution, evidence and cleanup policy: docs/certops/e2e-qualification.md.
"use strict";
/** Native source only: selective receipt-owned root removal must preserve an
 * independently installed root and its actual default OS-derived leaf trust.
 * The parent disposable trust harness owns all registered source paths. No
 * private key, raw certificate, path or system-store inventory is reported. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { isDeepStrictEqual } = require("node:util");
const trust = require("../packages/agent/src/trust-store");
const receipts = require("../packages/agent/src/trust-store/receipt");
const SCENARIO = "linux-trust-independent-root-selective-revoke";
const SCOPE = "native-linux-two-independent-roots-selective-owned-revocation";
const PREFIX = ".preserve-independent-trust-";
const FLAGS = [
  "twoActualIndependentRoots",
  "twoActualIssuedLeaves",
  "bothInitiallyUntrusted",
  "bothNativeDistributionsFinalized",
  "bothDefaultDerivedLeafTrustVerified",
  "firstActualOwnedRevoke",
  "firstLeafNowUntrusted",
  "secondSourceBytesAndIdentityUnchanged",
  "secondReceiptBytesAndIdentityUnchanged",
  "secondDerivedReferencePreserved",
  "secondDefaultLeafTrustPreserved",
  "secondActualOwnedRevoke",
  "bothFinallyUntrusted",
  "ownershipGuardReleased",
];
const REQUIRED_SOURCES = [
  "scripts/certops-linux-trust-independent-roots.js",
  "scripts/certops-linux-trust.js",
  "scripts/certops-linux-trust-receipt-fault.js",
  "packages/agent/src/index.js",
  "packages/agent/src/policy/index.js",
  "packages/agent/src/trust-store/index.js",
  "packages/agent/src/trust-store/receipt.js",
  "packages/agent/src/platform/index.js",
  "packages/agent/src/platform/durability.js",
  "packages/agent/vendor/log-scrub/secret-material.js",
  "packages/agent/scripts/host-gate.js",
];
const sha = (value) => crypto.createHash("sha256").update(value).digest("hex");
function verifyProof(value) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value));
  assert.deepEqual(
    Object.keys(value).sort(),
    [
      "schemaVersion",
      "scope",
      "family",
      "derivedReferenceKind",
      "rootFingerprints",
      "leafFingerprints",
      ...FLAGS,
    ].sort(),
  );
  assert.equal(value.schemaVersion, 1);
  assert.equal(value.scope, SCOPE);
  assert.ok(["debian", "rhel"].includes(value.family));
  assert.equal(
    value.derivedReferenceKind,
    value.family === "debian"
      ? "native-source-symlink"
      : "native-derived-certificate",
  );
  for (const field of ["rootFingerprints", "leafFingerprints"])
    assert.ok(
      Array.isArray(value[field]) &&
        value[field].length === 2 &&
        value[field].every(
          (v) => typeof v === "string" && /^[a-f0-9]{64}$/.test(v),
        ) &&
        new Set(value[field]).size === 2,
    );
  assert.equal(
    new Set([...value.rootFingerprints, ...value.leafFingerprints]).size,
    4,
  );
  for (const flag of FLAGS) assert.equal(value[flag], true, flag);
  return true;
}
function identity(file, directory = false) {
  const st = fs.lstatSync(file, { bigint: true });
  assert.ok(
    !st.isSymbolicLink() &&
      (directory ? st.isDirectory() : st.isFile()) &&
      st.ino > 0n,
    "Actual owned native identity required",
  );
  assert.equal(fs.realpathSync.native(file), file);
  return `${st.dev}:${st.ino}`;
}
function snapshot(file) {
  const st = fs.lstatSync(file, { bigint: true });
  return {
    identity: identity(file),
    sha256: sha(fs.readFileSync(file)),
    mode: String(st.mode),
    uid: String(st.uid),
    gid: String(st.gid),
  };
}
function unchanged(file, before) {
  assert.ok(
    isDeepStrictEqual(snapshot(file), before),
    "Independent native trust ownership changed",
  );
}
function assertCleanupSafe(workDir) {
  assert.ok(
    !fs.readdirSync(workDir).some((file) => file.startsWith(PREFIX)),
    "Preserve unresolved independent trust ownership",
  );
}
async function qualifyIndependentRoots({
  family,
  workDir,
  receiptDir,
  input,
  job,
  sourcePath,
  ownedPaths,
  ownedAnchors,
  native,
}) {
  assert.equal(process.platform, "linux");
  assert.equal(process.getuid(), 0);
  assert.equal(process.env.GITHUB_ACTIONS, "true");
  assert.equal(process.env.RUNNER_ENVIRONMENT, "github-hosted");
  assert.equal(process.env.CERTOPS_LINUX_TRUST_DISPOSABLE_HOST, "1");
  assert.ok(
    !Object.keys(process.env).some((name) =>
      [
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "OPENSSL_CONF",
        "OPENSSL_MODULES",
      ].includes(name.toUpperCase()),
    ),
    "Default OS trust oracle refuses environment overrides",
  );
  assert.ok(["debian", "rhel"].includes(family));
  for (const fn of [input, job, sourcePath, native])
    assert.equal(typeof fn, "function");
  assert.ok(ownedPaths instanceof Set && Array.isArray(ownedAnchors));
  const root = fs.realpathSync.native(workDir),
    rootId = identity(root, true);
  const directory = fs.mkdtempSync(path.join(root, "independent-roots-"));
  fs.chmodSync(directory, 0o700);
  const dirId = identity(directory, true),
    token = crypto.randomUUID();
  const marker = path.join(root, PREFIX + token + ".json");
  fs.writeFileSync(
    marker,
    JSON.stringify({ schemaVersion: 1, token, directory }),
    { flag: "wx", mode: 0o600 },
  );
  const markerBefore = snapshot(marker);
  const owned = () => {
    assert.equal(identity(root, true), rootId);
    assert.equal(identity(directory, true), dirId);
    unchanged(marker, markerBefore);
  };
  const openssl = (args) => native("openssl", args);
  const fingerprint = (file) =>
    sha(new crypto.X509Certificate(fs.readFileSync(file)).raw);
  const pairs = [];
  for (const label of ["a", "b"]) {
    const key = path.join(directory, `${label}-root.key`),
      pem = path.join(directory, `${label}-root.crt`),
      leafKey = path.join(directory, `${label}-leaf.key`),
      csr = path.join(directory, `${label}-leaf.csr`),
      leaf = path.join(directory, `${label}-leaf.crt`),
      ext = path.join(directory, `${label}.ext`);
    openssl([
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-keyout",
      key,
      "-out",
      pem,
      "-days",
      "2",
      "-subj",
      `/CN=CertOps-independent-${label}-${token}`,
      "-addext",
      "basicConstraints=critical,CA:TRUE",
      "-addext",
      "keyUsage=critical,keyCertSign,cRLSign",
    ]);
    fs.chmodSync(key, 0o600);
    openssl([
      "req",
      "-new",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-keyout",
      leafKey,
      "-out",
      csr,
      "-subj",
      `/CN=independent-${label}.example.test`,
    ]);
    fs.chmodSync(leafKey, 0o600);
    fs.writeFileSync(
      ext,
      `basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:independent-${label}.example.test\n`,
      { flag: "wx", mode: 0o600 },
    );
    openssl([
      "x509",
      "-req",
      "-in",
      csr,
      "-CA",
      pem,
      "-CAkey",
      key,
      "-set_serial",
      `0x${crypto.randomUUID().replaceAll("-", "")}`,
      "-days",
      "2",
      "-extfile",
      ext,
      "-out",
      leaf,
    ]);
    const ca = new crypto.X509Certificate(fs.readFileSync(pem)),
      certificate = new crypto.X509Certificate(fs.readFileSync(leaf));
    assert.ok(
      ca.ca &&
        !certificate.ca &&
        ca.verify(ca.publicKey) &&
        certificate.verify(ca.publicKey),
    );
    assert.ok(
      certificate.checkPrivateKey(
        crypto.createPrivateKey(fs.readFileSync(leafKey)),
      ),
    );
    assert.equal(
      certificate.checkHost(`independent-${label}.example.test`),
      `independent-${label}.example.test`,
    );
    pairs.push({
      key,
      pem,
      text: fs.readFileSync(pem, "utf8"),
      fingerprint: fingerprint(pem),
      leaf,
      leafFingerprint: fingerprint(leaf),
      hostname: `independent-${label}.example.test`,
    });
  }
  assert.equal(new Set(pairs.map((pair) => pair.fingerprint)).size, 2);
  const systemVerify = (pair, success) => {
    const result = native(
      "openssl",
      [
        "verify",
        "-purpose",
        "sslserver",
        "-verify_hostname",
        pair.hostname,
        pair.leaf,
      ],
      false,
    );
    assert.ok(
      Number.isInteger(result.status) &&
        !result.error &&
        (success ? result.status === 0 : result.status !== 0),
      "Actual default derived trust result differs",
    );
  };
  const store =
    family === "debian" ? "debian-ca-certificates" : "rhel-ca-trust";
  const leafPaths = pairs.map((pair) => pair.leaf);
  function derived(pair) {
    const directory =
      family === "debian"
        ? trust.DEBIAN_DERIVED_ANCHORS_DIR
        : trust.RHEL_DERIVED_ANCHORS_DIR;
    const rows = [];
    for (const name of fs.readdirSync(directory)) {
      const file = path.join(directory, name);
      try {
        if (family === "debian") {
          if (
            fs.lstatSync(file).isSymbolicLink() &&
            fs.realpathSync.native(file) === sourcePath(pair)
          )
            rows.push({
              name,
              target: fs.readlinkSync(file),
              fingerprint: fingerprint(file),
            });
        } else {
          for (const block of fs
            .readFileSync(file, "utf8")
            .match(
              /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g,
            ) || [])
            if (sha(new crypto.X509Certificate(block).raw) === pair.fingerprint)
              rows.push({ name, fingerprint: pair.fingerprint });
        }
      } catch {
        /* Unrelated system entries are not qualification material. */
      }
    }
    assert.ok(
      rows.length > 0 &&
        rows.every((row) => row.fingerprint === pair.fingerprint),
      "Actual derived native reference missing",
    );
    return rows.sort((a, b) => a.name.localeCompare(b.name));
  }
  for (const pair of pairs) {
    systemVerify(pair, false);
    assert.equal(fs.existsSync(sourcePath(pair)), false);
    ownedPaths.add(sourcePath(pair));
    ownedAnchors.push(pair); // Before mutation, including lost responses.
    const result = await trust.distributeTrust(input(job(pair, "root")));
    assert.equal(result.failureCategory, null);
    assert.equal(result.outcome, "installed");
    assert.equal(result.receipt.state, "finalized");
    assert.equal(
      new crypto.X509Certificate(
        fs.readFileSync(sourcePath(pair)),
      ).fingerprint256
        .replaceAll(":", "")
        .toLowerCase(),
      pair.fingerprint,
    );
    systemVerify(pair, true);
  }
  const [first, second] = pairs;
  const secondSource = snapshot(sourcePath(second)),
    secondReceiptPath = receipts.receiptRowPath(
      receiptDir,
      store,
      second.fingerprint,
    ),
    secondReceipt = snapshot(secondReceiptPath),
    secondDerived = derived(second);
  const actualReceipt = receipts.readReceipt(
    receiptDir,
    store,
    second.fingerprint,
  );
  assert.ok(
    actualReceipt?.row &&
      actualReceipt.row.state === "installed" &&
      actualReceipt.row.fingerprintSha256 === second.fingerprint &&
      actualReceipt.row.store === store,
    "Second receipt must independently prove ownership",
  );
  const revoked = await trust.revokeTrust(
    input(job(first, "root", "revoke-trust")),
  );
  assert.equal(revoked.failureCategory, null);
  assert.equal(revoked.outcome, "removed");
  assert.equal(fs.existsSync(sourcePath(first)), false);
  systemVerify(first, false);
  systemVerify(second, true);
  unchanged(sourcePath(second), secondSource);
  unchanged(secondReceiptPath, secondReceipt);
  assert.ok(
    isDeepStrictEqual(derived(second), secondDerived),
    "Second native derived source reference changed",
  );
  const removed = await trust.revokeTrust(
    input(job(second, "root", "revoke-trust")),
  );
  assert.equal(removed.failureCategory, null);
  assert.equal(removed.outcome, "removed");
  for (const pair of pairs) {
    assert.equal(fs.existsSync(sourcePath(pair)), false);
    systemVerify(pair, false);
  }
  assert.equal(new Set(leafPaths).size, 2);
  owned();
  fs.unlinkSync(marker);
  // Keep public CA files for the parent's independent final absence oracles;
  // private local fixture directory is removed only by the parent after those.
  const proof = {
    schemaVersion: 1,
    scope: SCOPE,
    family,
    derivedReferenceKind:
      family === "debian"
        ? "native-source-symlink"
        : "native-derived-certificate",
    rootFingerprints: pairs.map((pair) => pair.fingerprint),
    leafFingerprints: pairs.map((pair) => pair.leafFingerprint),
    ...Object.fromEntries(FLAGS.map((flag) => [flag, true])),
  };
  verifyProof(proof);
  return proof;
}
module.exports = {
  SCENARIO,
  SCOPE,
  FLAGS,
  REQUIRED_SOURCES,
  verifyProof,
  assertCleanupSafe,
  snapshot,
  unchanged,
  qualifyIndependentRoots,
};
