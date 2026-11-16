"use strict";
const test = require("node:test"), assert = require("node:assert/strict"), fs = require("node:fs"), os = require("node:os"), path = require("node:path");
const h = require("../tests/e2e/helpers/certops-linux-installed-discovery");
const nativeTest = process.platform === "linux" && process.getuid?.() === 0 ? test : test.skip;
function fixture(fn) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tt-pre-discovery-"));
  const receipt = { installedDiscoveryRequired: true, installedDiscoveryNonce: "a".repeat(64), installedDiscoveryCompletion: h.completionPath(root) };
  try { h.preparePreDiscovery(receipt, root); fn(root, receipt); }
  finally { assert.ok(path.basename(root).startsWith("tt-pre-discovery-")); fs.rmSync(root, { recursive: true, force: true }); }
}
nativeTest("bound pre-discovery proof authorizes owned cleanup", () => fixture((root, receipt) => {
  assert.deepEqual(h.assertCleanupSafe(receipt, root), { state: "pre" });
  h.removePreDiscovery(receipt, root, { state: "pre" });
  assert.equal(fs.existsSync(h.prePath(root)), false);
}));
nativeTest("missing, replaced and altered pre-discovery proofs refuse cleanup", () => {
  fixture((root, receipt) => { fs.unlinkSync(h.prePath(root)); assert.throws(() => h.assertCleanupSafe(receipt, root)); });
  fixture((root, receipt) => { const file = h.prePath(root), data = fs.readFileSync(file); fs.renameSync(file, file + ".old"); fs.writeFileSync(file, data, {mode: 0o600}); assert.throws(() => h.assertCleanupSafe(receipt, root)); });
  fixture((root, receipt) => { fs.writeFileSync(h.prePath(root), "{}"); assert.throws(() => h.assertCleanupSafe(receipt, root)); });
  fixture((root, receipt) => { fs.chmodSync(h.prePath(root), 0o644); assert.throws(() => h.assertCleanupSafe(receipt, root)); });
});
nativeTest("ambiguous and started states fail closed even when active marker disappears", () => fixture((root, receipt) => {
  fs.linkSync(h.prePath(root), h.guardPath(root));
  assert.throws(() => h.assertCleanupSafe(receipt, root));
  fs.unlinkSync(h.guardPath(root));
  h.startPreDiscovery(receipt, root);
  assert.throws(() => h.assertCleanupSafe(receipt, root));
  fs.unlinkSync(h.guardPath(root));
  assert.throws(() => h.assertCleanupSafe(receipt, root));
}));
nativeTest("removed pre-discovery proof cannot be silently accepted after initial check", () => fixture((root, receipt) => {
  const state = h.assertCleanupSafe(receipt, root);
  fs.unlinkSync(h.prePath(root));
  assert.throws(() => h.removePreDiscovery(receipt, root, state));
}));
nativeTest("interruption during marker transition preserves a blocked state", () => fixture((root, receipt) => {
  const original = fs.unlinkSync;
  try { fs.unlinkSync = () => { throw Error("simulated interruption"); }; assert.throws(() => h.startPreDiscovery(receipt, root)); }
  finally { fs.unlinkSync = original; }
  assert.throws(() => h.assertCleanupSafe(receipt, root));
}));
nativeTest("directory sync failure at either transition boundary refuses cleanup", () => {
  for (const failingCall of [1, 2]) fixture((root, receipt) => {
    const original = fs.fsyncSync; let calls = 0;
    try { fs.fsyncSync = (fd) => { if (++calls === failingCall) throw Error("sync failure"); return original(fd); }; assert.throws(() => h.startPreDiscovery(receipt, root)); }
    finally { fs.fsyncSync = original; }
    assert.throws(() => h.assertCleanupSafe(receipt, root));
  });
});
nativeTest("completed cleanup checks the retained completion identity without reopening removed config", () => fixture((root, receipt) => {
  const crypto = require("node:crypto");
  fs.unlinkSync(h.prePath(root));
  const file = h.completionPath(root), bytes = Buffer.from('{"bound":"proof"}');
  fs.writeFileSync(file, bytes, {mode: 0o600});
  const stat = fs.lstatSync(file, {bigint: true});
  const proof = {state: "completed", dev: stat.dev.toString(), ino: stat.ino.toString(), sha256: crypto.createHash("sha256").update(bytes).digest("hex")};
  assert.doesNotThrow(() => h.removePreDiscovery(receipt, root, proof));
  fs.renameSync(file, file + ".old"); fs.writeFileSync(file, bytes, {mode: 0o600});
  assert.throws(() => h.removePreDiscovery(receipt, root, proof));
}));
