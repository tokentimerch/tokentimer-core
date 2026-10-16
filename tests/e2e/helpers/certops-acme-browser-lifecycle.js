"use strict";
/** Source-only native ACME UI actor. The disposable parent owns the real agent,
 * CA, files and TLS service; this actor independently observes their identities.
 * Incomplete admission/native/browser cleanup stays sticky in the parent registry. */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto"),
  tls = require("node:tls");
const admission = require("./certops-acme-browser-job-admission"),
  ownership = require("./certops-acme-browser-console");
const SCOPE = "actual-browser-issued-and-renewed-native-acme-certificate";
const FLAGS = Object.freeze([
  "actualIssueAndRenewForms",
  "cancelBothFormsWithoutMutation",
  "exactPublicIssueAndRenewAdmission",
  "sameOwnedCertificate",
  "actualNativeClaimsAndActor",
  "claimBoundFingerprintEvidence",
  "independentNativeCertificateKeyPairs",
  "distinctLeafSerialAndSpki",
  "trustedTlsBothGenerations",
  "ownedBrowserClosed",
  "nativeOperationGuardCleared",
]);
function ownedPath(file, root) {
  assert.ok(
    path.isAbsolute(file) &&
      path.resolve(file) === file &&
      file.startsWith(root + path.sep),
    "Native lifecycle file must be canonical and owned",
  );
  assert.equal(
    fs.realpathSync.native(file),
    file,
    "Native lifecycle intermediate aliases refused",
  );
  return file;
}
function readNative(file, root, rootIdentity) {
  ownedPath(file, root);
  const parent = fs.lstatSync(root, { bigint: true }),
    original = fs.lstatSync(file, { bigint: true });
  assert.ok(
    parent.isDirectory() &&
      !parent.isSymbolicLink() &&
      parent.ino === rootIdentity.ino &&
      parent.dev === rootIdentity.dev &&
      original.isFile() &&
      !original.isSymbolicLink() &&
      original.size > 0n &&
      original.size <= 1048576n,
  );
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const before = fs.fstatSync(fd, { bigint: true });
    assert.ok(
      before.ino === original.ino &&
        before.dev === original.dev &&
        before.size === original.size &&
        before.uid === BigInt(process.getuid()) &&
        before.nlink === 1n &&
        (before.mode & 0o777n) === 0o600n,
    );
    const bytes = Buffer.alloc(Number(before.size) + 1),
      count = fs.readSync(fd, bytes, 0, bytes.length, 0),
      after = fs.fstatSync(fd, { bigint: true }),
      current = fs.lstatSync(file, { bigint: true });
    assert.ok(
      count === Number(before.size) &&
        after.size === before.size &&
        after.mtimeNs === before.mtimeNs &&
        after.ctimeNs === before.ctimeNs &&
        current.ino === before.ino &&
        current.dev === before.dev,
    );
    ownedPath(file, root);
    return bytes.subarray(0, count);
  } finally {
    fs.closeSync(fd);
  }
}
function readGuard(file, bytes, identity) {
  const fd = fs.openSync(file, "r");
  try {
    const before = fs.fstatSync(fd, { bigint: true });
    assert.ok(
      before.isFile() &&
        before.ino === identity.ino &&
        before.dev === identity.dev &&
        before.size === BigInt(bytes.length),
    );
    const buffer = Buffer.alloc(bytes.length + 1),
      count = fs.readSync(fd, buffer, 0, buffer.length, 0);
    assert.ok(
      count === bytes.length && buffer.subarray(0, count).equals(bytes),
    );
    const after = fs.fstatSync(fd, { bigint: true }),
      current = fs.lstatSync(file, { bigint: true });
    assert.ok(
      after.size === before.size &&
        current.isFile() &&
        !current.isSymbolicLink() &&
        current.ino === identity.ino &&
        current.dev === identity.dev,
    );
  } finally {
    fs.closeSync(fd);
  }
}
function verifyProof(p) {
  assert.ok(p && typeof p === "object" && !Array.isArray(p));
  assert.deepEqual(
    Object.keys(p).sort(),
    [
      "scope",
      "jobIds",
      "certificateId",
      "fingerprints",
      "spkiHashes",
      ...FLAGS,
    ].sort(),
  );
  assert.equal(p.scope, SCOPE);
  const uuid = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i;
  assert.match(p.certificateId, uuid);
  assert.ok(
    Array.isArray(p.jobIds) &&
      p.jobIds.length === 2 &&
      new Set(
        p.jobIds.map((id) => (typeof id === "string" ? id.toLowerCase() : id)),
      ).size === 2,
  );
  for (const id of p.jobIds) assert.match(id, uuid);
  for (const name of ["fingerprints", "spkiHashes"]) {
    assert.ok(
      Array.isArray(p[name]) &&
        p[name].length === 2 &&
        new Set(p[name]).size === 2,
    );
    for (const hash of p[name]) assert.match(hash, /^[a-f0-9]{64}$/);
  }
  for (const flag of FLAGS) assert.equal(p[flag], true, flag);
  return true;
}
function peer(options) {
  return new Promise((resolve, reject) => {
    let leaf;
    const socket = tls.connect({ ...options, rejectUnauthorized: true }, () => {
      try {
        assert.equal(socket.authorized, true);
        leaf = new crypto.X509Certificate(socket.getPeerCertificate().raw);
        socket.end();
      } catch {
        socket.destroy();
      }
    });
    socket.setTimeout(10000, () => socket.destroy());
    socket.once("error", () =>
      reject(new Error("Native lifecycle trusted TLS unavailable")),
    );
    socket.once("close", (bad) =>
      !bad && leaf
        ? resolve(leaf)
        : reject(new Error("Native lifecycle TLS drainage unproven")),
    );
  });
}
async function createLifecycleActor(c) {
  assert.equal(process.platform, "linux");
  assert.equal(c.acmeKind, "certbot");
  assert.equal(c.eabRef, undefined);
  assert.ok(Array.isArray(c.ownedBrowserResources));
  const root = fs.lstatSync(c.workDir, { bigint: true });
  assert.equal(fs.realpathSync.native(c.workDir), c.workDir);
  assert.ok(root.isDirectory() && !root.isSymbolicLink() && root.ino > 0n);
  const uiOrigin = ownership.ownedOrigin(c.uiOrigin),
    apiOrigin = ownership.ownedOrigin(c.apiOrigin),
    guard = path.join(c.workDir, "native-browser-lifecycle-active.json"),
    bytes = Buffer.from(
      JSON.stringify({
        nonce: crypto.randomUUID(),
        candidateSha: process.env.GITHUB_SHA,
      }),
    );
  let cleanup;
  const resource = ownership.createBrowserOwnership((value) => {
    cleanup = ownership.nativeCleanupResource(value, () =>
      fs.existsSync(guard),
    );
    c.ownedBrowserResources.push(cleanup);
  });
  fs.writeFileSync(guard, bytes, { flag: "wx", mode: 0o600 });
  const guardId = fs.lstatSync(guard, { bigint: true });
  const pin = require("../../../package.json").devDependencies.playwright;
  assert.equal(require("playwright/package.json").version, pin);
  let page,
    writes = 0;
  const admitted = [],
    observed = [];
  try {
    resource.begin();
    const server = await require("playwright").chromium.launchServer({
      headless: true,
      host: "127.0.0.1",
    });
    resource.attach(server);
    const browser = await require("playwright").chromium.connect(
      server.wsEndpoint(),
    );
    const context = await browser.newContext({ ignoreHTTPSErrors: false });
    page = await context.newPage();
    page.setDefaultTimeout(30000);
    await page.goto(uiOrigin + "/login");
    await page.getByLabel("Email", { exact: true }).fill(c.identity.email);
    await page
      .getByLabel("Password", { exact: true })
      .fill(c.identity.password);
    await page.getByRole("button", { name: "Sign In", exact: true }).click();
    await page.waitForURL((url) => !url.pathname.includes("login"));
    page.on("request", (request) => {
      if (admission.isWrite(request)) writes++;
    });
  } catch {
    throw new Error(
      "Native lifecycle browser launch/authentication incomplete; preserve owner",
    );
  }
  return {
    close: () => resource.close(),
    assertCleanupSafe: () => cleanup.assertCleanupSafe(),
    async admit(expectedBody) {
      assert.equal(
        expectedBody.operation,
        admitted.length === 0 ? "issue" : "renew",
      );
      assert.ok(admitted.length < 2);
      if (admitted.length === 1) {
        assert.equal(observed.length, 1);
        assert.equal(expectedBody.subjectId, admitted[0].certificateId);
      }
      const result = await admission.admitBrowserJob({
        page,
        uiOrigin,
        apiOrigin,
        workspaceId: c.workspaceId,
        expectedBody,
        pool: c.pool,
        registerOwnedJob: c.registerOwnedJob,
      });
      admitted.push(result);
      return result;
    },
    async observeNative({
      jobId,
      certificateId,
      certPath,
      keyPath,
      tlsOptions,
    }) {
      const index = observed.length;
      assert.ok(index < 2);
      assert.equal(admitted[index].jobId, jobId);
      assert.equal(admitted[index].certificateId, certificateId);
      const rows = (
        await c.pool.query(
          "SELECT j.id,j.status,j.operation,j.source,j.subject_id,j.claim_id,j.requested_by_user_id,a.agent_id FROM certificate_jobs j JOIN certops_agents a ON a.id=j.claimed_by_agent_id AND a.workspace_id=j.workspace_id WHERE j.workspace_id=$1 AND j.id=$2",
          [c.workspaceId, jobId],
        )
      ).rows;
      assert.equal(rows.length, 1);
      const job = rows[0];
      assert.equal(job.status, "succeeded");
      assert.equal(job.operation, index === 0 ? "issue" : "renew");
      assert.equal(job.source, "api");
      assert.equal(job.subject_id, certificateId);
      assert.equal(job.agent_id, c.agentId);
      assert.ok(
        String(job.requested_by_user_id) === String(c.identity.userId),
        "Actual browser actor differs from native claimant request",
      );
      assert.match(job.claim_id, /^[a-f0-9-]{36}$/i);
      for (const file of [certPath, keyPath]) {
        ownedPath(file, c.workDir);
        const s = fs.lstatSync(file);
        assert.ok(s.isFile() && !s.isSymbolicLink() && s.nlink === 1);
        assert.equal(s.uid, process.getuid());
        assert.equal(s.mode & 0o777, 0o600);
      }
      const leaf = new crypto.X509Certificate(
        readNative(certPath, c.workDir, root),
      );
      assert.ok(
        leaf.checkPrivateKey(
          crypto.createPrivateKey(readNative(keyPath, c.workDir, root)),
        ),
        "Native browser operation certificate and key differ",
      );
      const served = await peer(tlsOptions);
      assert.equal(served.fingerprint256, leaf.fingerprint256);
      const fingerprint = crypto
          .createHash("sha256")
          .update(leaf.raw)
          .digest("hex"),
        spkiHash = crypto
          .createHash("sha256")
          .update(leaf.publicKey.export({ type: "spki", format: "der" }))
          .digest("hex");
      const evidence = await c.pool.query(
        "SELECT 1 FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2 AND claim_id=$3 AND evidence_type='validation.passed' AND metadata->>'step'='verify' AND metadata->>'fingerprintSha256'=$4",
        [c.workspaceId, jobId, job.claim_id, fingerprint],
      );
      assert.ok(evidence.rows.length > 0);
      const managed = (
        await c.pool.query(
          "SELECT status,fingerprint_sha256 FROM managed_certificates WHERE workspace_id=$1 AND id=$2",
          [c.workspaceId, certificateId],
        )
      ).rows;
      assert.equal(managed.length, 1);
      assert.equal(managed[0].status, "active");
      assert.equal(
        managed[0].fingerprint_sha256.replace(/:/g, "").toLowerCase(),
        fingerprint,
      );
      if (index) {
        assert.notEqual(leaf.serialNumber, observed[0].serial);
        assert.notEqual(fingerprint, observed[0].fingerprint);
        assert.notEqual(spkiHash, observed[0].spkiHash);
      }
      observed.push({ serial: leaf.serialNumber, fingerprint, spkiHash });
    },
    async finish() {
      assert.equal(admitted.length, 2);
      assert.equal(observed.length, 2);
      assert.equal(writes, 2);
      assert.equal(admitted[0].certificateId, admitted[1].certificateId);
      await resource.close();
      assert.equal(writes, 2);
      const current = fs.lstatSync(guard, { bigint: true }),
        parent = fs.lstatSync(c.workDir, { bigint: true });
      assert.ok(
        current.isFile() &&
          !current.isSymbolicLink() &&
          current.ino === guardId.ino &&
          current.dev === guardId.dev &&
          parent.isDirectory() &&
          !parent.isSymbolicLink() &&
          parent.ino === root.ino &&
          parent.dev === root.dev,
      );
      readGuard(guard, bytes, guardId);
      const proof = {
        scope: SCOPE,
        jobIds: admitted.map((row) => row.jobId),
        certificateId: admitted[0].certificateId,
        fingerprints: observed.map((row) => row.fingerprint),
        spkiHashes: observed.map((row) => row.spkiHash),
        ...Object.fromEntries(FLAGS.map((flag) => [flag, true])),
      };
      verifyProof(proof);
      fs.unlinkSync(guard);
      cleanup.completeNativeOperation();
      return proof;
    },
  };
}
module.exports = {
  REQUIRED_SOURCES: [
    ...new Set([
      "tests/e2e/helpers/certops-acme-browser-lifecycle.js",
      ...admission.REQUIRED_SOURCES,
      ...ownership.REQUIRED_SOURCES,
    ]),
  ],
  SCOPE,
  FLAGS,
  verifyProof,
  ownedPath,
  readGuard,
  createLifecycleActor,
};
