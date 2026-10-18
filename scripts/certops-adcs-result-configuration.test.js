"use strict";
// Actual owned plaintext-file controls only. Native SCM and native ACL checks
// are deliberately not replaced by these tests and are not qualified here.
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  os = require("node:os"),
  path = require("node:path");
const subject = require("../tests/e2e/helpers/certops-adcs-result-configuration");
function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "certops-result-config-")),
    configDir = path.join(root, "agent"),
    file = path.join(configDir, "config.json");
  fs.mkdirSync(configDir);
  const original = Buffer.from(
    JSON.stringify({
      serverUrl: "https://10.64.0.5:3443/",
      publicFixture: "unchanged",
    }),
  );
  fs.writeFileSync(file, original);
  const stat = fs.lstatSync(file, { bigint: true }),
    expectedIdentity = `${stat.dev}:${stat.ino}`;
  const rootStat=fs.lstatSync(root,{bigint:true});
  return {
    root,
    configDir,
    file,
    original,
    expectedIdentity,
    remove: () => {
      assert.equal(path.dirname(path.resolve(root)),path.resolve(os.tmpdir()));
      assert.ok(path.basename(root).startsWith("certops-result-config-"));
      const current=fs.lstatSync(root,{bigint:true});assert.ok(current.isDirectory()&&!current.isSymbolicLink()&&current.dev===rootStat.dev&&current.ino===rootStat.ino);
      fs.rmSync(root, { recursive: true, force: true });
    },
  };
}
test("configuration writes retain original file identity, require stopped checks and restore exact original bytes", () => {
  const f = fixture();
  let owner,
    stopped = false,
    asynchronous = false,
    calls = 0;
  try {
    owner = subject.createConfigurationOwner({
      workDir: f.root,
      configDir: f.configDir,
      expectedIdentity: f.expectedIdentity,
      ps: () => "D:P(A;;FA;;;SY)",
      verifyStopped: () => {
        calls++;
        assert.equal(stopped, true);
        if (asynchronous) return Promise.resolve(true);
        return true;
      },
    });
    assert.throws(() => owner.applyGateway("http://127.0.0.1:12345"));
    assert.ok(fs.readFileSync(f.file).equals(f.original));
    stopped = true;
    asynchronous = true;
    assert.throws(() => owner.applyGateway("http://127.0.0.1:12345"));
    assert.ok(fs.readFileSync(f.file).equals(f.original));
    asynchronous = false;
    owner.applyGateway("http://127.0.0.1:12345");
    const applied = JSON.parse(fs.readFileSync(f.file));
    assert.equal(applied.serverUrl, "http://127.0.0.1:12345");
    assert.equal(applied.allowInsecureLocalHttp, true);
    assert.equal(applied.publicFixture, "unchanged");
    owner.restore();
    owner.complete();
    owner = null;
    assert.ok(fs.readFileSync(f.file).equals(f.original));
    subject.assertCleanupSafe(f.root);
    assert.equal(calls, 6);
  } finally {
    owner?.close();
    f.remove();
  }
});
test("foreign bytes and a missing guard never authorize restoration or outer cleanup", () => {
  const f = fixture();
  let owner;
  try {
    owner = subject.createConfigurationOwner({
      workDir: f.root,
      configDir: f.configDir,
      expectedIdentity: f.expectedIdentity,
      ps: () => "D:P(A;;FA;;;SY)",
      verifyStopped: () => true,
    });
    owner.applyGateway("http://127.0.0.1:12345");
    const foreign = Buffer.from('{"PUBLIC":"foreign owner"}');
    fs.writeFileSync(f.file, foreign);
    assert.throws(() => owner.restore());
    assert.ok(fs.readFileSync(f.file).equals(foreign));
    fs.unlinkSync(path.join(f.root, ".adcs-result-configuration-active.json"));
    assert.throws(() => subject.assertCleanupSafe(f.root));
  } finally {
    owner?.close();
    f.remove();
  }
});
test("identical-byte foreign replacement and changed ACL are preserved", () => {
  const f = fixture();
  let owner,
    acl = "D:P(A;;FA;;;SY)";
  try {
    owner = subject.createConfigurationOwner({
      workDir: f.root,
      configDir: f.configDir,
      expectedIdentity: f.expectedIdentity,
      ps: () => acl,
      verifyStopped: () => true,
    });
    acl = "D:P(A;;FR;;;WD)";
    assert.throws(() => owner.applyGateway("http://127.0.0.1:12345"));
    assert.ok(fs.readFileSync(f.file).equals(f.original));
    acl = "D:P(A;;FA;;;SY)";
    fs.renameSync(f.file, f.file + ".original");
    fs.writeFileSync(f.file, f.original);
    assert.throws(() => owner.applyGateway("http://127.0.0.1:12345"));
    assert.ok(fs.readFileSync(f.file).equals(f.original));
  } finally {
    owner?.close();
    f.remove();
  }
});
