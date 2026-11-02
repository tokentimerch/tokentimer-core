"use strict";
// Pure contract controls only: no Win32 process or service operations execute.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const helper = require("../tests/e2e/helpers/certops-windows-owned-process");
const identity = {
  pid: 123,
  parentPid: 122,
  createdAt: "2026-10-14T10:00:00.1234567Z",
  executable: "C:\\fixture\\node.exe",
  commandSha256: "a".repeat(64),
};
function proof() {
  return {
    scope: "exact-owned-native-process-handle-termination",
    rootPid: 123,
    rootNativeCreatedTicks: "134000000000000000",
    capturedProcessCount: 2,
    atomicTreeContainmentQualified: false,
    ...Object.fromEntries(helper.FLAGS.map((key) => [key, true])),
  };
}
test("exact original identity and finite native termination proof are required", () => {
  assert.equal(helper.validateIdentity(identity), true);
  assert.equal(helper.verifyProof(proof(), identity), true);
  for (const key of [
    "pid",
    "parentPid",
    "createdAt",
    "executable",
    "commandSha256",
  ]) {
    const changed = {
      ...identity,
      [key]:
        key === "pid" || key === "parentPid"
          ? 999
          : key === "createdAt"
            ? "2026-10-14T10:00:00.1234568Z"
            : key === "executable"
              ? "C:\\foreign\\node.exe"
              : "b".repeat(64),
    };
    assert.throws(() => helper.sameIdentity(changed, identity));
  }
  for (const key of helper.FLAGS) {
    assert.throws(() =>
      helper.verifyProof({ ...proof(), [key]: false }, identity),
    );
    const missing = proof();
    delete missing[key];
    assert.throws(() => helper.verifyProof(missing, identity));
  }
  assert.throws(() =>
    helper.verifyProof(
      { ...proof(), atomicTreeContainmentQualified: true },
      identity,
    ),
  );
  assert.throws(() =>
    helper.verifyProof({ ...proof(), rootPid: 999 }, identity),
  );
  assert.throws(() =>
    helper.terminateOwnedProcessTree({
      identity,
      run: () => assert.fail("No unowned process invocation"),
    }),
  );
});
test("native driver retains handles in one invocation and refuses ambiguous ancestry", () => {
  const source = fs.readFileSync(
    require.resolve("../tests/e2e/helpers/certops-windows-owned-process.ps1"),
    "utf8",
  );
  assert.match(source, /Immediate-parent ancestry creation mismatch/);
  assert.match(source, /CreatedMicroseconds/);
  assert.match(source, /ReadAllBytes/);
  assert.match(source, /ComputeHash\(\$bytes\)/);
  assert.match(source, /UTF8.GetString\(\$bytes\)/);
  assert.doesNotMatch(source, /taskkill|Stop-Process/);
  assert.match(source, /TerminateProcess\(handle,238\)/);
  assert.match(source, /rootNativeCreatedTicks=/);
});

test("failed identity capture remains sticky even if its guard disappears", () => {
  const os = require("node:os"),
    path = require("node:path");
  const root = fs.mkdtempSync(
    path.join(os.tmpdir(), "certops-owned-process-contract-"),
  );
  try {
    assert.throws(() =>
      helper.captureProcessIdentity({
        expectedIdentity: identity,
        powershell: () => JSON.stringify({ ...identity, parentPid: 999 }),
        workDir: root,
        commandRoots: [path.join(root, "exact-agent.js")],
      }),
    );
    fs.unlinkSync(path.join(root, helper.guardName));
    assert.throws(
      () => helper.assertCleanupSafe(root),
      /ownership remains active/,
    );
  } finally {
    // This pure control never starts a child. Only its exact private temp files exist.
    fs.rmSync(root, { recursive: true });
  }
});
