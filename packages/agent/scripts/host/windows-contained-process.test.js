"use strict";
/** Ordinary public-file child containment regression; no agent, SCM, CNG, IIS,
 * certificate or CA operation runs. This repeats the real suspended-image and
 * native/CIM timestamp bridge that portable protocol fixtures cannot exercise. */
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  { spawnSync } = require("node:child_process");
const helper = require("../../../../tests/e2e/helpers/certops-windows-contained-process");
const pause = () => new Promise((resolve) => setTimeout(resolve, 50));
async function until(check) {
  const end = performance.now() + 15000;
  while (performance.now() < end) {
    const value = check();
    if (value) return value;
    await pause();
  }
  throw new Error("Owned benign fixture deadline exceeded");
}
function observe(processId) {
  assert.ok(
    Number.isInteger(processId) && processId > 0 && processId <= 0xffffffff,
  );
  const script = `$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);$p=Get-CimInstance Win32_Process -Filter 'ProcessId=${processId}';if(!$p){'null'}else{[pscustomobject]@{pid=[int]$p.ProcessId;parentPid=[int]$p.ParentProcessId;creation=$p.CreationDate.ToUniversalTime().ToString('o')}|ConvertTo-Json -Compress}`;
  const result = spawnSync(
    path.join(
      process.env.SystemRoot,
      "System32/WindowsPowerShell/v1.0/powershell.exe",
    ),
    [
      "-NoProfile",
      "-NonInteractive",
      "-EncodedCommand",
      Buffer.from(script, "utf16le").toString("base64"),
    ],
    {
      encoding: "utf8",
      timeout: 10000,
      windowsHide: true,
      env: helper.nativeEnvironment(),
    },
  );
  assert.ifError(result.error);
  assert.equal(
    result.status,
    0,
    "Independent benign process observation failed",
  );
  return JSON.parse(result.stdout);
}
test(
  "real owned JobObject preserves suspended identity and drains an actual descendant",
  // skip-reason: no-host
  { skip: process.platform !== "win32", timeout: 180000 },
  async () => {
    const base = path.resolve(__dirname, "../../../../.build");
    fs.mkdirSync(base, { recursive: true });
    const root = fs.mkdtempSync(path.join(base, "contained-native-smoke-")),
      rootId = fs.lstatSync(root, { bigint: true }).ino;
    const main = path.join(root, "owned-main.js"),
      grandchild = path.join(root, "owned-descendant.js"),
      release = path.join(root, "release"),
      rootOutput = path.join(root, "root-public.txt"),
      descendantOutput = path.join(root, "descendant-public.json");
    fs.writeFileSync(
      grandchild,
      "require('node:fs').writeFileSync(process.argv[2],JSON.stringify({pid:process.pid}));setInterval(()=>{},1000);\n",
    );
    fs.writeFileSync(
      main,
      "const fs=require('node:fs');require('node:child_process').spawn(process.execPath,[process.argv[2],process.argv[3]],{stdio:'ignore',windowsHide:true});fs.writeFileSync(process.argv[4],'actual-owned-main');setInterval(()=>{if(fs.existsSync(process.argv[5]))process.exit(0);},20);\n",
    );
    let resource, primary, descendant;
    try {
      resource = await helper.startContainedNativeProcess({
        executable: process.execPath,
        args: [main, grandchild, descendantOutput, rootOutput, release],
        workDir: root,
        maxLifetimeMs: 60000,
        onCreated: (value) => {
          resource = value;
        },
      });
      assert.equal(fs.readFileSync(rootOutput, "utf8"), "actual-owned-main");
      const child = await until(
        () =>
          fs.existsSync(descendantOutput) &&
          JSON.parse(fs.readFileSync(descendantOutput, "utf8")),
      );
      descendant = observe(child.pid);
      assert.ok(descendant);
      assert.equal(descendant.parentPid, resource.rootIdentity.pid);
      fs.writeFileSync(release, "release-exact-owned-main", { flag: "wx" });
      await until(() => !resource.hasLiveChild());
      const result = await resource.stopAndDrain();
      assert.equal(result.launchOccurred, true);
      assert.equal(result.rootExitCode, 0);
      assert.equal(result.activeNativeProcesses, 0);
      assert.equal(result.nativeHandlesClosed, true);
      assert.equal(resource.hasLiveChild(), false);
      assert.equal(resource.hasOwnershipReceipt(), false);
      const after = observe(descendant.pid);
      assert.ok(
        !after || after.creation !== descendant.creation,
        "Original descendant still live after actual retained-job drainage",
      );
      helper.assertCleanupSafe(root);
    } catch (error) {
      primary = error;
      throw error;
    } finally {
      try {
        if (resource) await resource.stopAndDrain();
        helper.assertCleanupSafe(root);
        assert.equal(fs.lstatSync(root, { bigint: true }).ino, rootId);
        const allowed = new Set([
          "owned-main.js",
          "owned-descendant.js",
          "root-public.txt",
          "descendant-public.json",
          "release",
        ]);
        for (const name of fs.readdirSync(root)) {
          assert.ok(allowed.has(name));
          const file = path.join(root, name);
          assert.ok(
            fs.lstatSync(file).isFile() && !fs.lstatSync(file).isSymbolicLink(),
          );
          fs.unlinkSync(file);
        }
        fs.rmdirSync(root);
      } catch (cleanup) {
        throw new AggregateError(
          [...(primary ? [primary] : []), cleanup],
          "Benign contained process ownership unproven; preserve fixture",
        );
      }
    }
  },
);
