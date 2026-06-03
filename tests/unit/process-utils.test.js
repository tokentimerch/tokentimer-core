"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert");
const { once } = require("node:events");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  createWindowsPackageManagerCommandLine,
  killProcessTree,
  spawnCommand,
} = require("../../scripts/process-utils");

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitFor(predicate, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;

  while (Date.now() < deadline) {
    if (predicate()) return;
    await delay(50);
  }

  throw new Error("Timed out waiting for condition");
}

function isProcessAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error.code === "EPERM";
  }
}

describe("process utils", () => {
  it("builds the Windows package-manager command line used by root scripts", () => {
    assert.strictEqual(
      createWindowsPackageManagerCommandLine("pnpm", [
        "--filter",
        "@tokentimer/api",
        "migrate",
      ]),
      "pnpm --filter @tokentimer/api migrate",
    );
  });

  it("rejects shell metacharacters before invoking cmd.exe", () => {
    assert.throws(
      () => createWindowsPackageManagerCommandLine("pnpm", ["dev", "&", "whoami"]),
      /Unsafe Windows command argument/,
    );
    assert.throws(
      () => createWindowsPackageManagerCommandLine("pnpm", ["bad arg"]),
      /Unsafe Windows command argument/,
    );
  });

  it("kills a spawned command and its grandchild", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tokentimer-process-"));
    const childScript = path.join(tempDir, "child.js");
    const readyFile = path.join(tempDir, "ready");
    const grandchildPidFile = path.join(tempDir, "grandchild.pid");

    fs.writeFileSync(
      childScript,
      `
const { spawn } = require("node:child_process");
const fs = require("node:fs");

const [readyFile, grandchildPidFile] = process.argv.slice(2);
const grandchild = spawn(process.execPath, [
  "-e",
  "setInterval(() => {}, 1000);",
], {
  stdio: "ignore",
});

fs.writeFileSync(grandchildPidFile, String(grandchild.pid));
fs.writeFileSync(readyFile, String(process.pid));
setInterval(() => {}, 1000);
`,
    );

    const child = spawnCommand(
      process.execPath,
      [childScript, readyFile, grandchildPidFile],
      {
        stdio: "ignore",
        windowsHide: true,
      },
    );

    let grandchildPid;

    try {
      await waitFor(
        () => fs.existsSync(readyFile) && fs.existsSync(grandchildPidFile),
      );

      grandchildPid = Number(fs.readFileSync(grandchildPidFile, "utf8"));

      assert.ok(isProcessAlive(child.pid), "expected child to be running");
      assert.ok(
        isProcessAlive(grandchildPid),
        "expected grandchild to be running",
      );

      killProcessTree(child);

      await Promise.race([once(child, "exit"), delay(5000)]);
      await waitFor(
        () => !isProcessAlive(child.pid) && !isProcessAlive(grandchildPid),
      );

      assert.ok(!isProcessAlive(child.pid), "expected child to be stopped");
      assert.ok(
        !isProcessAlive(grandchildPid),
        "expected grandchild to be stopped",
      );
    } finally {
      killProcessTree(child);
      if (grandchildPid && isProcessAlive(grandchildPid)) {
        try {
          process.kill(grandchildPid, "SIGTERM");
        } catch {}
      }
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });
});
