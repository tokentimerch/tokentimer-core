"use strict";
const assert = require("node:assert/strict"), path = require("node:path");
const { spawnSync } = require("node:child_process");
const LIMIT = 24 * 1024 * 1024;
function read(bytes) {
  assert.ok(Buffer.isBuffer(bytes) && bytes.length >= 22 && bytes.length <= LIMIT);
  const result = spawnSync(process.platform === "win32" ? "python" : "python3",
    [path.join(__dirname, "certops-artifact-zip.py")], { input: bytes, timeout: 30000, maxBuffer: LIMIT * 2, windowsHide: true });
  assert.ifError(result.error); assert.equal(result.status, 0, "Artifact ZIP refused");
  return new Map(Object.entries(JSON.parse(result.stdout.toString("utf8"))).map(([name, value]) => [name, Buffer.from(value, "base64")]));
}
module.exports = { LIMIT, read };
