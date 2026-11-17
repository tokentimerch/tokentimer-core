"use strict";
// Linux-only preflight: ACLs, host security policy and actual role-denial probes
// remain independent obligations. No credential contents are read or returned.
const assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path").posix;
function check({ issuer, consumer }, io = fs, platform = process.platform) {
  assert.equal(platform, "linux", "Linux host required");
  const roots = [issuer, consumer].map((role, index) => {
    assert.ok(path.isAbsolute(role?.directory || ""), "absolute sink directory required");
    const original = io.lstatSync(role.directory);
    assert.ok(original.isDirectory() && !original.isSymbolicLink(), "sink must be a real directory");
    const root = io.realpathSync(role.directory), stat = io.statSync(root);
    assert.equal(stat.uid, index === 0 ? 10001 : 10002, "sink owner mismatch");
    assert.equal(stat.mode & 0o077, 0, "sink directory must deny group/other access");
    const file = path.join(root, "token.json"), token = io.lstatSync(file);
    assert.ok(token.isFile() && !token.isSymbolicLink(), "token sink must be a regular file");
    assert.equal(token.uid, stat.uid, "token owner mismatch");
    assert.equal(token.mode & 0o077, 0, "token sink must deny group/other access");
    return root;
  });
  const contains = (a, b) => b === a || b.startsWith(a + path.sep);
  assert.ok(!contains(roots[0], roots[1]) && !contains(roots[1], roots[0]), "sink directories overlap");
  return { status: "local-check-only", roleDenialProbes: "required", releaseQualification: "not-established" };
}
module.exports = { check };
