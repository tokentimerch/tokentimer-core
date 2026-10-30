"use strict";

// The worker image copies a hand-picked list of files from apps/api. A module the
// worker requires that is missing from that list builds and scans fine, then fails
// with MODULE_NOT_FOUND at start. This follows every relative require from the
// worker entrypoints and checks each file is in a COPY line of Dockerfile.worker.

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const repoRoot = path.join(__dirname, "..", "..");
const ENTRYPOINTS = [
  "queue-manager.js",
  "delivery-worker.js",
  "weekly-digest-runner.js",
  "auto-sync-worker.js",
  "endpoint-check-worker.js",
  "certops-worker.js",
  "runner.js",
].map((name) => path.join(repoRoot, "apps", "worker", "src", name));

function copiedSources(dockerfile) {
  return dockerfile
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => /^COPY\s/i.test(line) && !/--from=/.test(line))
    .map((line) => line.replace(/^COPY\s+(--\S+\s+)*/i, "").split(/\s+/)[0])
    .filter((source) => source && !source.startsWith("$"))
    .map((source) => path.resolve(repoRoot, source.replace(/\/$/, "")));
}

function resolveRequire(from, spec) {
  const base = path.resolve(path.dirname(from), spec);
  for (const candidate of [base, `${base}.js`, `${base}.cjs`, `${base}.json`, path.join(base, "index.js")]) {
    if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) return candidate;
  }
  return null;
}

// Returns the files reachable from the entrypoints that no COPY line covers.
function filesMissingFromImage(dockerfileText, entrypoints = ENTRYPOINTS) {
  const copied = copiedSources(dockerfileText);
  const isCopied = (file) => copied.some((source) => file === source || file.startsWith(source + path.sep));
  const seen = new Set();
  const missing = new Map();
  const queue = [...entrypoints];
  while (queue.length) {
    const file = queue.pop();
    if (seen.has(file)) continue;
    seen.add(file);
    if (!/\.c?js$/.test(file)) continue;
    const source = fs.readFileSync(file, "utf8");
    // A trailing comma is allowed so a formatter wrapping the call does not hide it.
    for (const match of source.matchAll(/require\(\s*["'](\.{1,2}\/[^"']+)["']\s*,?\s*\)/g)) {
      const target = resolveRequire(file, match[1]);
      if (!target) continue;
      queue.push(target);
      if (!isCopied(target) && !missing.has(target)) missing.set(target, file);
    }
  }
  const rel = (file) => path.relative(repoRoot, file).replace(/\\/g, "/");
  return [...missing].map(([file, by]) => `${rel(file)} (required by ${rel(by)})`);
}

describe("worker image contents", () => {
  const dockerfile = fs.readFileSync(path.join(repoRoot, "deploy", "compose", "Dockerfile.worker"), "utf8");

  it("copies every file the worker entrypoints can reach", () => {
    assert.deepEqual(filesMissingFromImage(dockerfile), []);
  });

  it("notices a module that was left out of the COPY list", () => {
    // Without this, a bug in the scan itself would let the first test pass for nothing.
    const withoutOne = dockerfile
      .split("\n")
      .filter((line) => !line.includes("COPY apps/api/services/operator "))
      .join("\n");
    assert.ok(withoutOne.length < dockerfile.length, "the operator sweep module is listed in the Dockerfile");
    const missing = filesMissingFromImage(withoutOne);
    assert.ok(missing.some((file) => /apps\/api\/services\/operator\/requestMaintenance\.js \(required by apps\/worker\/src\/certops-worker\.js\)/.test(file)));
    assert.ok(missing.some((file) => file.includes("services/operator/jobAuthority.js")));
  });
});
