"use strict";
/** Exercise the real coordinator against owned files and a loopback TLS fixture.
 * This regression emits no host qualification receipt and requires no service,
 * certificate-store, cloud, or machine configuration changes. */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
const { qualifyPairedRollback, verifyRollbackProof, ROLLBACK_FLAGS, ROLLBACK_SCOPE } = require("./certops-filesystem-host");
const deploy = require("../packages/agent/src/deploy");
const policy = require("../packages/agent/src/policy");

test("paired rollback proof refuses missing facts, unrelated scope, identical leaves, and leaked material", () => {
  const proof = { schemaVersion: 1, scope: ROLLBACK_SCOPE, fingerprints: ["a".repeat(64), "b".repeat(64)], ...Object.fromEntries(ROLLBACK_FLAGS.map(flag => [flag, true])) };
  assert.equal(verifyRollbackProof(proof), true);
  for (const flag of ROLLBACK_FLAGS) {
    assert.throws(() => verifyRollbackProof({ ...proof, [flag]: false }));
    const absent = { ...proof }; delete absent[flag];
    assert.throws(() => verifyRollbackProof(absent));
  }
  for (const change of [{ fingerprints: [proof.fingerprints[0], proof.fingerprints[0]] }, { scope: "local-contract" }, { privateKeyPem: "withheld" }]) assert.throws(() => verifyRollbackProof({ ...proof, ...change }));
});

test("real coordinator restores predecessor bytes after an independently observed stale TLS leaf and drains on oracle failure", { timeout: 60000 }, async () => {
  const temporary = fs.realpathSync.native(os.tmpdir());
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(temporary, "certops-paired-rollback-test-")));
  const identity = fs.statSync(root, { bigint: true });
  let safe = true;
  const native = args => {
    const result = spawnSync("openssl", args, { cwd: root, encoding: "utf8", timeout: 15000 });
    assert.equal(result.status, 0, "Owned OpenSSL fixture creation failed; private output withheld");
  };
  try {
    native(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.crt", "-days", "2", "-subj", "/CN=Owned-Rollback-CA", "-addext", "basicConstraints=critical,CA:TRUE"]);
    fs.writeFileSync(path.join(root, "leaf.ext"), "basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:filesystem.example.test\nextendedKeyUsage=serverAuth\n");
    const materials = ["old", "new"].map((name, index) => {
      native(["req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", `${name}.key`, "-out", `${name}.csr`, "-subj", "/CN=filesystem.example.test"]);
      native(["x509", "-req", "-in", `${name}.csr`, "-CA", "ca.crt", "-CAkey", "ca.key", "-set_serial", String(index + 1), "-days", "2", "-extfile", "leaf.ext", "-out", `${name}.crt`]);
      return { certificatePem: fs.readFileSync(path.join(root, `${name}.crt`), "utf8"), privateKeyPath: path.join(root, `${name}.key`), chainPem: fs.readFileSync(path.join(root, "ca.crt"), "utf8"), retainPrivateKeyStaging: true };
    });
    // Distinct valid chain bundles expose an observer that incorrectly assumes
    // the pair-only coordinator also installs the candidate's chain bytes.
    native(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "alternate-ca.key", "-out", "alternate-ca.crt", "-days", "2", "-subj", "/CN=Owned-Alternate-Rollback-CA", "-addext", "basicConstraints=critical,CA:TRUE"]);
    materials[1].chainPem += fs.readFileSync(path.join(root, "alternate-ca.crt"), "utf8");
    assert.notEqual(materials[0].chainPem, materials[1].chainPem);
    const target = { type: "domain", reference: "filesystem.example.test", certPath: path.join(root, "deployed.crt"), keyPath: path.join(root, "deployed.key"), chainPath: path.join(root, "chain.pem"), backupDir: path.join(root, "backups") };
    fs.mkdirSync(target.backupDir);
    const checkPath = policy.createPolicyEngine(policy.loadPolicyConfig({ allowedPaths: [root] })).checkPath;
    assert.equal((await deploy.deployCertificateAndKey({ target, ...materials[0], checkPath })).deployed, true);
    const observe = material => {
      const leaf = new crypto.X509Certificate(fs.readFileSync(target.certPath));
      assert.equal(leaf.fingerprint256, new crypto.X509Certificate(material.certificatePem).fingerprint256);
      assert.equal(leaf.checkPrivateKey(crypto.createPrivateKey(fs.readFileSync(target.keyPath))), true);
      assert.equal(fs.readFileSync(target.chainPath, "utf8"), material.chainPem);
    };
    const args = { root, target, predecessor: materials[0], candidate: materials[1], independentlyObserve: observe, onCleanupSafety: value => { safe = value; } };
    const proof = await qualifyPairedRollback(args);
    assert.equal(proof.productionRollbackObserved, true);
    assert.equal(proof.ownedListenerAndConnectionsDrained, true);
    assert.notEqual(proof.fingerprints[0], proof.fingerprints[1]);
    observe(materials[0]);
    await assert.rejects(qualifyPairedRollback({ ...args, independentlyObserve: () => { throw new Error("Read-only oracle refused"); } }), /Independent rollback observer failed/);
    assert.equal(safe, true, "Failed observation must still drain the owned listener");
    observe(materials[0]);
  } finally {
    assert.equal(safe, true, "Preserve test fixture while listener ownership is uncertain");
    assert.equal(path.dirname(root), temporary);
    assert.ok(path.basename(root).startsWith("certops-paired-rollback-test-"));
    const current = fs.lstatSync(root, { bigint: true });
    assert.equal(current.isSymbolicLink(), false);
    assert.equal(current.ino, identity.ino); assert.equal(current.dev, identity.dev);
    fs.rmSync(root, { recursive: true });
  }
});
