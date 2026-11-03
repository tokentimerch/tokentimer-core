"use strict";
/** Explicit Windows supporting regression, invoked by the PowerShell installer
 * filesystem check. Creates only a unique temporary app/package, runs the real
 * activation-function fault driver, and removes files after verified child exit.
 * It never installs, queries or changes a service/certificate/registry setting. */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  os = require("node:os");
function failureSummary(error, depth = 0) {
  if (depth >= 4) return { name: "Truncated" };
  const result = {
    name: [
      "Error",
      "AssertionError",
      "AggregateError",
      "TypeError",
      "SyntaxError",
      "RangeError",
    ].includes(error?.name)
      ? error.name
      : "UnknownError",
  };
  if (
    [
      "ERR_ASSERTION",
      "ENOENT",
      "EEXIST",
      "EACCES",
      "EPERM",
      "ETIMEDOUT",
    ].includes(error?.code)
  )
    result.code = error.code;
  if (
    [
      "launch",
      "identity",
      "publish-go",
      "restoration",
      "verify-restoration",
      "host-oracles",
      "publish-release",
      "wait-wrapper",
      "closed-receipt",
      "native-drain",
    ].includes(error?.activationPhase)
  )
    result.phase = error.activationPhase;
  if (
    Number.isSafeInteger(error?.nativeRootExitCode) &&
    error.nativeRootExitCode >= 0 &&
    error.nativeRootExitCode <= 0xffffffff
  )
    result.nativeRootExitCode = error.nativeRootExitCode;
  const reasons = new Map([
    [
      "Contained wrapper closed before required native phase",
      "native-wrapper-closed",
    ],
    [
      "Contained native phase exceeded bounded deadline",
      "native-startup-deadline",
    ],
    ["Owned activation protocol deadline exceeded", "activation-deadline"],
  ]);
  if (reasons.has(error?.message)) result.reason = reasons.get(error.message);
  const native =
    /^Contained native failure at ([a-z-]+): System\.[A-Za-z0-9_.]{1,160} \((-?\d+), native (null|\d+)\)$/.exec(
      error?.message || "",
    );
  if (
    native &&
    [
      "wait-run",
      "launch-manifest",
      "executable-lock",
      "command-render",
      "launch-ancestry",
      "native-create",
      "suspended-identity",
      "publish-started",
      "wait-resume",
      "native-resume",
      "native-drain",
    ].includes(native[1])
  ) {
    const hresult = Number(native[2]);
    const nativeErrorCode = native[3] === "null" ? null : Number(native[3]);
    if (
      Number.isInteger(hresult) &&
      hresult >= -2147483648 &&
      hresult <= 2147483647 &&
      (nativeErrorCode === null ||
        (Number.isInteger(nativeErrorCode) &&
          nativeErrorCode >= 0 &&
          nativeErrorCode <= 2147483647))
    ) {
      result.nativeFailure = { stage: native[1], hresult, nativeErrorCode };
    }
  }
  if (Array.isArray(error?.errors))
    result.causes = error.errors
      .slice(0, 4)
      .map((cause) => failureSummary(cause, depth + 1));
  return result;
}
async function main() {
  assert.equal(process.platform, "win32");
  const root = fs.mkdtempSync(
    path.join(os.tmpdir(), "certops-second-rename-support-"),
  );
  const app = path.join(root, "app"),
    pkg = path.join(root, "candidate");
  fs.mkdirSync(app);
  fs.mkdirSync(pkg);
  fs.writeFileSync(path.join(app, "version.txt"), "actual predecessor fixture");
  fs.writeFileSync(path.join(pkg, "version.txt"), "actual candidate fixture");
  let drained = false;
  try {
    const facts =
      await require("../tests/e2e/helpers/certops-windows-second-rename").runActivationFault(
        {
          repoRoot: path.resolve(__dirname, ".."),
          workDir: root,
          packageDir: pkg,
        },
      );
    drained = facts.ownedChildDrained;
    for (const field of [
      "childIdentityVerifiedBeforeActivation",
      "nativeOrderedRestoreEvents",
      "originalDirectoryIdentityRestored",
      "explicitStagingCleanupFailure",
      "predecessorFilesUnchanged",
      "nativeHandleReleased",
      "ownedStagingRemoved",
      "ownedChildDrained",
    ])
      assert.equal(facts[field], true, field);
    assert.equal(
      fs.readFileSync(path.join(app, "version.txt"), "utf8"),
      "actual predecessor fixture",
    );
    console.log(
      "Second-rename supporting regression passed: actual ordered native restoration events and temporary filesystem only",
    );
  } finally {
    // The protocol helper throws on uncertain process drainage. Retain its exact
    // temporary root for diagnostics rather than recursively deleting live state.
    if (drained) {
      assert.equal(path.dirname(root), path.resolve(os.tmpdir()));
      assert.match(path.basename(root), /^certops-second-rename-support-/);
      fs.rmSync(root, { recursive: true, force: true });
      assert.equal(fs.existsSync(root), false);
    }
  }
}
if (require.main === module)
  main().catch((error) => {
    console.error(
      "Second-rename supporting regression failed: " +
        JSON.stringify(failureSummary(error)),
    );
    process.exitCode = 1;
  });
module.exports = { main, failureSummary };
