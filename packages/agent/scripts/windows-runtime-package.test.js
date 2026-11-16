"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { VERSION, RUNTIMES, markBundledPackage, markBundledInstaller, buildWindowsArchives } = require("./windows-runtime-package");

test("marks only a Windows artifact as bundled and refuses an ambiguous source flavor", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tt-node-flavor-test-"));
  try {
    const filename = path.join(dir, "package.json");
    fs.writeFileSync(filename, JSON.stringify({ name: "agent", version: "1.2.3" }));
    markBundledPackage(dir);
    assert.deepEqual(JSON.parse(fs.readFileSync(filename, "utf8")), { name: "agent", version: "1.2.3", windowsBundledRuntime: true });
    assert.throws(() => markBundledPackage(dir), /already declares/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test("sets the bundled flag in the packaged installer and rejects missing or ambiguous flags", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tt-node-installer-flavor-"));
  try {
    fs.mkdirSync(path.join(dir, "scripts"));
    const filename = path.join(dir, "scripts", "install-agent.ps1");
    const legacy = "$script:RequiresBundledRuntime = $false\r\nWrite-Host ok\r\n";
    fs.writeFileSync(filename, legacy);
    markBundledInstaller(dir);
    assert.equal(fs.readFileSync(filename, "utf8"), legacy.replace("$false", "$true"));
    assert.throws(() => markBundledInstaller(dir), /exactly one false/);
    fs.writeFileSync(filename, "Write-Host ok\n");
    assert.throws(() => markBundledInstaller(dir), /exactly one false/);
    fs.writeFileSync(filename, legacy + legacy);
    assert.throws(() => markBundledInstaller(dir), /exactly one false/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test("rejects a changed upstream runtime before extraction or creating an archive", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tt-node-package-test-"));
  try {
    const out = path.join(dir, "out");
    fs.mkdirSync(out);
    fs.writeFileSync(path.join(dir, `node-v${VERSION}-win-${RUNTIMES.amd64.upstream}.zip`), "changed archive");
    assert.throws(() => buildWindowsArchives("unused.tgz", dir, out, "0.0.0"), /Node archive checksum mismatch/);
    assert.deepEqual(fs.readdirSync(out), []);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
