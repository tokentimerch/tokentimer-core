"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const Module = require("node:module");
const child = require("node:child_process");

test("default and Windows modes dispatch the expected builders without a full build", (t) => {
  const serviceArchitectures = require("../packages/agent/scripts/build-windows-service-host").TARGET_ARCHES;
  const chainArchitectures = require("../packages/agent/scripts/build-windows-chain-helper").TARGET_ARCHES;
  assert.deepEqual(serviceArchitectures, ["amd64", "arm64"]);
  assert.deepEqual(chainArchitectures, ["amd64", "arm64"]);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tt-pack-modes-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const script = path.resolve(__dirname, "../packages/agent/scripts/pack-release.js");
  const version = require("../packages/agent/package.json").version;
  const originalLoad = Module._load, originalSpawn = child.spawnSync;
  const calls = [];
  try {
    Module._load = function(request, parent, ...rest) {
      if (parent?.filename === script && request === "./build-windows-service-host.js")
        return { main: () => calls.push("service-host") };
      if (parent?.filename === script && request === "./build-windows-chain-helper.js")
        return { main: () => calls.push("chain"), TARGET_ARCHES: chainArchitectures,
          buildOne: (arch) => calls.push(`cmc-${arch}`) };
      if (parent?.filename === script && request === "./windows-runtime-package.js")
        return { buildWindowsArchives: (generic, runtime, output) => {
          calls.push(`runtime:${runtime}`);
          return ["amd64", "arm64"].map(architecture => {
            const archive = path.join(output, `windows-${architecture}.tgz`);
            fs.writeFileSync(archive, "fixture");
            return { architecture, archive, sha256: "fixture" };
          });
        } };
      return originalLoad.call(this, request, parent, ...rest);
    };
    child.spawnSync = (command, args) => {
      if (command === "npm") {
        const output = args[args.indexOf("--pack-destination") + 1];
        const name = `tokentimer-agent-${version}.tgz`;
        fs.writeFileSync(path.join(output, name), "fixture");
        return { status: 0, stdout: `${name}\n`, stderr: "" };
      }
      if (command === "tar") return { status: 0, stdout: "-rwxr-xr-x root root 0 2026-01-01 package/scripts/install-agent.sh\n", stderr: "" };
      throw new Error(`Unexpected process: ${command}`);
    };
    delete require.cache[script];
    const { main } = require(script);
    const generic = main(["--out-dir", path.join(root, "generic")]);
    assert.equal(generic.windowsArchives.length, 0);
    assert.deepEqual(calls, ["service-host", "chain", "cmc-amd64", "cmc-arm64"]);
    calls.length = 0;
    const runtime = path.join(root, "runtime");
    const windows = main(["--out-dir", path.join(root, "windows"), "--windows-runtime-dir", runtime]);
    assert.equal(windows.windowsArchives.length, 2);
    assert.deepEqual(calls, ["service-host", "chain", "cmc-amd64", "cmc-arm64", `runtime:${runtime}`]);
  } finally {
    child.spawnSync = originalSpawn;
    Module._load = originalLoad;
    delete require.cache[script];
  }
});
