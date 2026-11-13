"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const root = path.resolve(__dirname, "..");
const workflow = fs.readFileSync(path.join(root, ".github/workflows/release.yml"), "utf8").replace(/\r\n/g, "\n");
const marker = "      - name: Create GitHub Release with agent tarball attached";
const job = workflow.slice(workflow.indexOf(marker));
assert.ok(job.startsWith(marker), "release creation step is required");
const body = job.split("        run: |\n")[1];
assert.ok(body, "release creation script is required");
const lines = [];
for (const line of body.split("\n")) {
  if (line && !line.startsWith("          ")) break;
  lines.push(line.slice(10));
}
const script = lines.join("\n").replaceAll("${{ github.repository }}", "test/repo");
const bash = process.platform === "win32" ? "C:\\Program Files\\Git\\bin\\bash.exe" : "bash";

function runRelease({ windows = false, linux = true } = {}) {
  const parent = fs.realpathSync(os.tmpdir());
  const dir = fs.mkdtempSync(path.join(parent, "tt-release-assets-"));
  try {
    const artifacts = path.join(dir, "agent-dist");
    fs.mkdirSync(artifacts);
    const names = [];
    if (linux) names.push("tokentimer-agent-0.18.2.tgz", "tokentimer-agent-0.18.2.tgz.sha256");
    if (windows) for (const arch of ["amd64", "arm64"]) names.push(`tokentimer-agent-0.18.2-windows-${arch}.tgz`, `tokentimer-agent-0.18.2-windows-${arch}.tgz.sha256`);
    for (const name of names) fs.writeFileSync(path.join(artifacts, name), "fixture");
    const mock = "function gh() { printf 'ARG:%s\\n' \"$@\"; }\n";
    const result = spawnSync(bash, ["-c", mock + script], { cwd: dir, env: { ...process.env, GITHUB_REF: "refs/tags/v0.18.2" }, encoding: "utf8" });
    if (result.error) throw result.error;
    return result;
  } finally {
    if (path.dirname(dir) !== parent) throw new Error("refusing unsafe test cleanup");
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test("release creation retains Linux but never passes unqualified Windows archives to gh", () => {
  const result = runRelease({ windows: true });
  assert.equal(result.status, 0, result.stderr);
  const args = result.stdout.split("\n").filter((line) => line.startsWith("ARG:agent-dist/"));
  assert.deepEqual(args, ["ARG:agent-dist/tokentimer-agent-0.18.2.tgz", "ARG:agent-dist/tokentimer-agent-0.18.2.tgz.sha256"]);
  assert.match(result.stdout, /Windows bundled-runtime archives are withheld/);
});

test("Linux-only release works and missing Linux archive fails", () => {
  const normal = runRelease();
  assert.equal(normal.status, 0, normal.stderr);
  assert.doesNotMatch(normal.stdout, /::warning::/);
  const missing = runRelease({ windows: true, linux: false });
  assert.notEqual(missing.status, 0);
  assert.doesNotMatch(missing.stdout, /ARG:release/);
});
