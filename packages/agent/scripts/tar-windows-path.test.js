"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs"), os = require("node:os"), path = require("node:path");
const { spawnSync } = require("node:child_process");
const { assertNoPrivateKeyMaterial } = require("./pack-release");

test("absolute archive paths scan safely under the available Windows tar implementations", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tt-tar-path-"));
  const previousPath = process.env.PATH;
  try {
    const payload = path.join(root, "payload"); fs.mkdirSync(payload);
    fs.writeFileSync(path.join(payload, "public.txt"), "public fixture");
    const tarPrograms = ["tar"];
    if (process.platform === "win32") {
      for (const file of ["C:/Windows/System32/tar.exe", "C:/Program Files/Git/usr/bin/tar.exe"]) if (fs.existsSync(file)) tarPrograms.push(file);
    }
    const create = spawnSync(tarPrograms[0], ["-czf", "fixture.tgz", "-C", "payload", "."], { cwd: root, encoding: "utf8" });
    assert.equal(create.status, 0, create.stderr);
    for (const program of tarPrograms) {
      if (program !== "tar") process.env.PATH = path.dirname(program) + path.delimiter + previousPath;
      assert.doesNotThrow(() => assertNoPrivateKeyMaterial(path.join(root, "fixture.tgz")), program);
    }
    fs.writeFileSync(path.join(payload, "bad.key.pem"), "-----BEGIN PRIVATE KEY-----\nMIIBVQ==\n-----END PRIVATE KEY-----\n");
    const bad = spawnSync(tarPrograms[0], ["-czf", "bad.tgz", "-C", "payload", "."], { cwd: root, encoding: "utf8" });
    assert.equal(bad.status, 0, bad.stderr);
    for (const program of tarPrograms) {
      if (program !== "tar") process.env.PATH = path.dirname(program) + path.delimiter + previousPath;
      assert.throws(() => assertNoPrivateKeyMaterial(path.join(root, "bad.tgz")), /refusing to ship a tarball containing private-key material/, program);
    }
  } finally { process.env.PATH = previousPath; fs.rmSync(root, { recursive: true, force: true }); }
});
