"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
const { collect, OWNED } = require("./windows-signing-targets.cjs");

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agent-sign-targets-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const name of [...OWNED, "runtime/amd64/node.exe"]) {
    const file = path.join(root, ...name.split("/"));
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, "fixture");
  }
  return root;
}

test("selects every first-party executable and leaves the Node runtime untouched", t => {
  const root = fixture(t);
  const list = collect(root, "amd64");
  assert.equal(list.length, OWNED.length);
  assert.ok(list.every(name => !name.toLowerCase().endsWith("node.exe")));
});

test("fails closed for unexpected, missing or linked executable material", async t => {
  await t.test("unexpected executable", t => {
    const root = fixture(t);
    fs.writeFileSync(path.join(root, "extra.exe"), "unknown");
    assert.throws(() => collect(root, "amd64"), /Unexpected/);
  });
  await t.test("unexpected PowerShell modules and data files", t => {
    for (const extension of ["psm1", "psd1"]) {
      const root = fixture(t);
      fs.writeFileSync(path.join(root, `extra.${extension}`), "unknown");
      assert.throws(() => collect(root, "amd64"), /Unexpected/);
    }
  });
  await t.test("unsupported Windows executable scripts", t => {
    for (const extension of ["cmd", "bat", "vbs", "vbe", "wsf", "hta"]) {
      const root = fixture(t);
      fs.writeFileSync(path.join(root, `extra.${extension}`), "unknown");
      assert.throws(() => collect(root, "amd64"), /Unsupported Windows executable script/);
    }
  });
  await t.test("unsupported native formats, including case variations", t => {
    for (const extension of ["dll", "COM", "node", "msi", "sys", "scr", "ocx", "cpl", "drv", "efi", "msp", "msix", "msixbundle", "appx", "appxbundle", "pif", "xll", "ax", "acm", "tsp", "ime"]) {
      const root = fixture(t);
      fs.writeFileSync(path.join(root, `extra.${extension}`), "unknown");
      assert.throws(() => collect(root, "amd64"), /Unsupported Windows native executable/);
    }
  });
  await t.test("rejects a renamed PE but accepts ordinary JavaScript", t => {
    const root = fixture(t);
    const file = path.join(root, "extra.js");
    fs.writeFileSync(file, "console.log('agent JavaScript')");
    assert.equal(collect(root, "amd64").length, OWNED.length);
    const executable = Buffer.alloc(128);
    executable.write("MZ");
    executable.writeUInt32LE(64, 0x3c);
    executable.write("PE\0\0", 64, "ascii");
    fs.writeFileSync(file, executable);
    assert.throws(() => collect(root, "amd64"), /Unsupported Windows native executable/);
  });
  await t.test("missing script", t => {
    const root = fixture(t);
    fs.unlinkSync(path.join(root, "scripts", "install-agent.ps1"));
    assert.throws(() => collect(root, "amd64"), /missing/);
  });
  await t.test("wrong runtime architecture", t => {
    const root = fixture(t);
    assert.throws(() => collect(root, "arm64"), /missing/);
  });
  await t.test("hard link", t => {
    const root = fixture(t);
    const source = path.join(root, "bin", "tokentimer-agent-host-amd64.exe");
    fs.linkSync(source, path.join(root, "linked.txt"));
    assert.throws(() => collect(root, "amd64"), /Nonregular/);
  });
});

test("preflight requires an independently configured public profile, issuer and runtime pin", t => {
  const root = fixture(t);
  const output = path.join(root, "output.txt");
  const runtimeHash = crypto.createHash("sha256").update("fixture").digest("hex");
  const env = { ...process.env, TT_SIGNING_PACKAGE_ROOT: root, TT_SIGNING_ARCHITECTURE: "amd64",
    TT_SIGNING_NODE_EXPECTED: runtimeHash, TT_SIGNING_ISSUER_SHA256: "b".repeat(64),
    TT_SIGNING_PROFILE_EKU: "1.3.6.1.4.1.311.97.990309390.766961637.194916062.941502583", GITHUB_OUTPUT: output };
  const run = patch => spawnSync(process.execPath, [require.resolve("./windows-signing-targets.cjs")], { env: { ...env, ...patch }, encoding: "utf8" });
  assert.equal(run({}).status, 0);
  assert.match(fs.readFileSync(output, "utf8"), new RegExp(`node_sha256=${runtimeHash}`));
  for (const patch of [
    { TT_SIGNING_NODE_EXPECTED: "a".repeat(64) },
    { TT_SIGNING_ISSUER_SHA256: "" },
    { TT_SIGNING_PROFILE_EKU: "1.3.6.1.4.1.311.97.1.0" },
    { TT_SIGNING_PROFILE_EKU: "1.3.6.1.4.1.311.97.1.3.1.123.456" },
    { TT_SIGNING_PACKAGE_ROOT: `${root},evil` },
  ]) assert.notEqual(run(patch).status, 0);
});
