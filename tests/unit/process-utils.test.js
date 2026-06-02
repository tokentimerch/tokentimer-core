"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert");

const {
  createWindowsPackageManagerCommandLine,
} = require("../../scripts/process-utils");

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
});
