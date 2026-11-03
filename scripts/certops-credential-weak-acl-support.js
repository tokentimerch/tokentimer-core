"use strict";
// Supporting control on an ephemeral hosted Windows runner; never run on a user's host.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { createHostGate } = require("../packages/agent/scripts/host-gate");
const fixture = require("../packages/agent/scripts/host/credential-weak-acl-fixture");

async function main() {
  assert.equal(process.platform, "win32");
  assert.equal(process.env.GITHUB_ACTIONS, "true");
  assert.equal(process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST, "1");
  assert.ok(process.env.RUNNER_TEMP);
  const root = fs.mkdtempSync(path.join(fs.realpathSync.native(process.env.RUNNER_TEMP), "credential-acl-support-"));
  const gate = createHostGate({ suite: "credential-acl-support", strict: true, reportPath: null });
  try {
    await gate.preflight();
    await fixture.qualify({ gate, workDir: root });
    fixture.assertCleanupSafe(root);
    fs.rmdirSync(root);
    console.log("Temporary credential ACL control passed");
  } catch (error) {
    const allowed = ["CERTOPS_WEAK_ACL_TREATED_AS_MISSING", "CERTOPS_WEAK_ACL_ACCEPTED", "CERTOPS_WEAK_ACL_OTHER_SID", "CERTOPS_WEAK_ACL_PERMISSION_ERROR", "CERTOPS_WEAK_ACL_UNEXPECTED_REFUSAL"];
    console.error(`Temporary credential ACL control failed: ${allowed.includes(error?.code) ? error.code : "OTHER"}`);
    // Preserve any unresolved ownership guard and its temporary files.
    process.exitCode = 1;
  }
}
main().catch(() => { console.error("Temporary credential ACL control setup failed"); process.exitCode = 1; });
