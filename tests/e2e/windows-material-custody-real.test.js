"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

test(
  "native Windows existing-key custody and association reject unsafe reuse without mutation",
  // skip-reason: no-host — requires an elevated disposable Windows host for isolated machine keys/stores.
  { skip: process.env.TT_WINDOWS_MATERIAL_REAL !== "1", timeout: 180000 },
  async (t) => {
    assert.equal(process.platform, "win32");
    for (const scenario of [
      "valid-reuse",
      "exportable",
      "user-key",
      "incorrect-acl",
      "private-key-mismatch",
      "cng-provider-policy",
      "legacy-csp",
    ]) {
      await t.test(scenario, () => {
        const script =
          "$ErrorActionPreference='Stop';Add-Type -Path @($env:TT_TEST_IMPORT_CS,$env:TT_TEST_CUSTODY_CS);[TokenTimerTests.MaterialCustodyTests]::Run($env:TT_TEST_CUSTODY_CASE);'verified'";
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
            windowsHide: true,
            timeout: 30000,
            env: {
              ...process.env,
              TT_TEST_IMPORT_CS: path.resolve(
                __dirname,
                "../../packages/agent/src/windows-material/MaterialImport.cs",
              ),
              TT_TEST_CUSTODY_CS: path.join(
                __dirname,
                "fixtures/MaterialCustodyTests.cs",
              ),
              TT_TEST_CUSTODY_CASE: scenario,
              PSModulePath: path.join(
                process.env.SystemRoot,
                "System32/WindowsPowerShell/v1.0/Modules",
              ),
            },
          },
        );
        assert.equal(result.status, 0, result.stderr);
        assert.match(result.stdout, /verified/);
      });
    }
  },
);
