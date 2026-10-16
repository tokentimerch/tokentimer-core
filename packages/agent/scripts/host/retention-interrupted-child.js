"use strict";
// Fault controller: execute the actual native collector and terminate this
// owned child only after its exact certificate deletion succeeds, before the
// native key deletion callback or durable ledger completion can execute.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const childProcess = require("node:child_process");
const retention = require("../../src/windows-retention");
const { isAgentOwnedContainerName } = require("../../src/windows-cert-store");

// Pure admission is shared by actual main and supporting CLI regression tests.
function parseArguments(args) {
  assert.ok(
    Array.isArray(args) && args.every((value) => typeof value === "string"),
  );
  const inputs = [...args];
  let ownedGo;
  if (inputs.at(-1)?.startsWith("--owned-go=")) {
    ownedGo = inputs.pop().slice("--owned-go=".length);
    assert.ok(path.win32.isAbsolute(ownedGo));
  }
  let store = "My",
    explicitStore = false;
  if (inputs.at(-1)?.startsWith("--store=")) {
    const flag = inputs.pop();
    assert.match(flag, /^--store=(My|WebHosting)$/);
    store = flag.slice("--store=".length);
    explicitStore = true;
  }
  const [stateDir, thumbprint, containerName, inputMode, residentConfigSha256] =
    inputs;
  let residentConfigPath = inputMode,
    retentionHours = 24;
  if (
    typeof inputMode === "string" &&
    inputMode.startsWith("--retention-hours=")
  ) {
    assert.match(inputMode, /^--retention-hours=(168|720)$/);
    assert.equal(inputs.length, 4);
    retentionHours = Number(inputMode.split("=")[1]);
    residentConfigPath = undefined;
  } else if (inputMode === undefined) assert.equal(inputs.length, 3);
  else {
    assert.equal(inputs.length, 5);
    assert.equal(
      explicitStore,
      false,
      "Resident campaign retains its original My-store contract",
    );
    assert.ok(path.win32.isAbsolute(residentConfigPath));
    assert.match(residentConfigSha256, /^[a-f0-9]{64}$/);
    assert.equal(
      ownedGo,
      undefined,
      "Resident launch uses its separate original config-bound gate",
    );
  }
  if (store === "WebHosting") {
    assert.equal(
      retentionHours,
      24,
      "WebHosting source retains the reviewed24h policy",
    );
    assert.ok(
      ownedGo,
      "WebHosting interruption requires its contained launch gate",
    );
  }
  assert.equal(typeof stateDir, "string");
  assert.match(thumbprint, /^[A-F0-9]{40}$/);
  assert.equal(isAgentOwnedContainerName(containerName), true);
  return {
    stateDir,
    thumbprint,
    containerName,
    residentConfigPath,
    residentConfigSha256,
    retentionHours,
    ...(store === "My" ? {} : { store }),
    ownedGo,
  };
}
async function main() {
  assert.equal(process.platform, "win32");
  assert.equal(process.env.CERTOPS_HOST_TESTS, "1");
  const {
    stateDir,
    thumbprint,
    containerName,
    residentConfigPath,
    residentConfigSha256,
    retentionHours,
    store = "My",
    ownedGo,
  } = parseArguments(process.argv.slice(2));
  assert.match(thumbprint, /^[A-F0-9]{40}$/);
  assert.equal(isAgentOwnedContainerName(containerName), true);
  const absoluteState = path.resolve(stateDir);
  if (residentConfigPath !== undefined) {
    // The real-day campaign uses its original protected state, never a copied or aged ledger.
    assert.match(residentConfigSha256, /^[a-f0-9]{64}$/);
    const bytes = fs.readFileSync(residentConfigPath);
    const digest = require("node:crypto")
      .createHash("sha256")
      .update(bytes)
      .digest("hex");
    assert.equal(digest, residentConfigSha256);
    const config = JSON.parse(bytes);
    require("../../../../scripts/certops-retention24h-runtime").verifyConfig(
      config,
      residentConfigPath,
    );
    assert.equal(absoluteState, path.resolve(config.stateDir));
    assert.equal(thumbprint, config.predecessor.thumbprint);
    assert.equal(containerName, config.predecessor.containerName);
    assert.ok(
      Date.now() > Date.parse(config.cleanupDeadline),
      "The actual production deadline must already have elapsed",
    );
    for (const source of config.requiredSources)
      assert.equal(
        require("node:crypto")
          .createHash("sha256")
          .update(
            fs.readFileSync(
              path.resolve(__dirname, "../../../..", source.file),
            ),
          )
          .digest("hex"),
        source.sha256,
      );
  } else {
    assert.match(
      path.basename(path.dirname(absoluteState)),
      /^elapsed-retention-[a-f0-9-]{36}$/,
    );
    assert.equal(path.basename(absoluteState), "state");
  }
  const row = retention.readLedgerRow(
    path.join(absoluteState, "windows-retention"),
    thumbprint,
  );
  assert.equal(row.oldThumbprint, thumbprint);
  assert.equal(row.cngKeyContainerId, containerName);
  assert.equal(row.ownershipProvenance, "tokentimer_installed");
  assert.equal(row.store, store);
  let nativeDeletionObserved = false;
  const execFileImpl = (file, args, options, callback) =>
    childProcess.execFile(file, args, options, (error, stdout, stderr) => {
      if (
        !error &&
        path.basename(file).toLowerCase() === "certutil.exe" &&
        args.length === 3 &&
        args[0] === "-delstore" &&
        args[1] === store &&
        args[2] === thumbprint
      ) {
        assert.equal(nativeDeletionObserved, false);
        nativeDeletionObserved = true;
        fs.writeFileSync(
          path.join(absoluteState, "interrupted-native-delete.json"),
          JSON.stringify({
            fault: "process-exit-after-native-delstore-before-delkey",
            thumbprint,
            containerName,
            nativeCommandSucceeded: true,
            pid: process.pid,
            observedAt: new Date().toISOString(),
          }),
          { flag: "wx" },
        );
        process.exit(86);
      }
      callback(error, stdout, stderr);
    });
  if (ownedGo !== undefined) {
    assert.equal(
      residentConfigPath,
      undefined,
      "Resident gate has separate fixed ownership",
    );
    assert.equal(
      ownedGo,
      path.join(path.dirname(absoluteState), "interrupted-native-go"),
    );
    const deadline = Date.now() + 30000;
    while (!fs.existsSync(ownedGo)) {
      assert.ok(
        Date.now() < deadline,
        "Owned short native launch gate timed out",
      );
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    assert.equal(fs.lstatSync(ownedGo).isSymbolicLink(), false);
    assert.equal(fs.readFileSync(ownedGo, "utf8"), "1");
  }
  if (residentConfigPath !== undefined) {
    const go = path.join(
      path.dirname(residentConfigPath),
      "interrupted-delete-go",
    );
    const until = Date.now() + 30000;
    while (!fs.existsSync(go)) {
      assert.ok(
        Date.now() < until,
        "Resident interruption launch gate timed out",
      );
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    assert.equal(fs.lstatSync(go).isSymbolicLink(), false);
    assert.equal(fs.readFileSync(go, "utf8"), "1");
  }
  await require("../../src/index").runWindowsRetentionSweep({
    stateDir: absoluteState,
    retentionHours,
    execFileImpl,
    log: { info() {}, error() {} },
  });
  throw new Error("Required native deletion fault boundary was not observed");
}
if (require.main === module)
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });

module.exports = { parseArguments };
