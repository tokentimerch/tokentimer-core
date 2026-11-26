"use strict";
const assert = require("node:assert/strict"), path = require("node:path");
const { createHash } = require("node:crypto");
const { spawnSync } = require("node:child_process");
const LIMIT = 24 * 1024 * 1024;
function read(bytes) {
  assert.ok(Buffer.isBuffer(bytes) && bytes.length >= 22 && bytes.length <= LIMIT);
  const result = spawnSync(process.platform === "win32" ? "python" : "python3",
    [path.join(__dirname, "certops-artifact-zip.py")], { input: bytes, timeout: 30000, maxBuffer: LIMIT * 2, windowsHide: true });
  assert.ifError(result.error); assert.equal(result.status, 0, "Artifact ZIP refused");
  return new Map(Object.entries(JSON.parse(result.stdout.toString("utf8"))).map(([name, value]) => [name, Buffer.from(value, "base64")]));
}
async function download(repository, artifactId, artifact, token, limit = LIMIT) {
  assert.match(repository, /^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/);
  assert.match(String(artifactId), /^[1-9][0-9]{0,15}$/);
  assert.ok(Number.isSafeInteger(artifact.size_in_bytes) && artifact.size_in_bytes > 0 && artifact.size_in_bytes <= limit);
  assert.match(artifact.digest, /^sha256:[a-f0-9]{64}$/);
  const response = await fetch(`https://api.github.com/repos/${repository}/actions/artifacts/${artifactId}/zip`, {
    headers: { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28" },
    redirect: "manual", signal: AbortSignal.timeout(60000),
  });
  assert.equal(response.status, 302);
  const url = new URL(response.headers.get("location"));
  assert.ok(url.protocol === "https:" && !url.port && !url.username && !url.password && !url.hash &&
    (url.hostname.endsWith(".blob.core.windows.net") || url.hostname.endsWith(".actions.githubusercontent.com")));
  // The signed download URL is sufficient on its own.
  const archive = await fetch(url, { redirect: "error", signal: AbortSignal.timeout(60000) });
  assert.equal(archive.status, 200);
  const chunks = [];
  let size = 0;
  for await (const chunk of archive.body) {
    size += chunk.length;
    assert.ok(size <= artifact.size_in_bytes);
    chunks.push(chunk);
  }
  const bytes = Buffer.concat(chunks);
  assert.equal(size, artifact.size_in_bytes);
  assert.equal(`sha256:${createHash("sha256").update(bytes).digest("hex")}`, artifact.digest);
  return bytes;
}

module.exports = { LIMIT, read, download };
