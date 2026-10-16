#!/usr/bin/env node
"use strict";

// Static readiness guard for ADR-0012 decision 19. Linux still requires
// LimitCORE=0 and independent native limit checks. Windows DumpType=0 means
// custom dump, so a registry write must never count as suppression. The
// installer preserves operator policy and states that containment is unqualified.
// This guard does not turn source inspection into native crash evidence.

const fs = require("node:fs");
const path = require("node:path");

const repoRoot = path.resolve(__dirname, "..", "..");
const unitPath = path.join(repoRoot, "packages/agent/scripts/tokentimer-agent.service");
const relUnitPath = path.relative(repoRoot, unitPath).replace(/\\/g, "/");
const installScriptPath = path.join(repoRoot, "packages/agent/scripts/install-agent.ps1");
const relInstallScriptPath = path.relative(repoRoot, installScriptPath).replace(/\\/g, "/");

function checkLinux() {
  if (!fs.existsSync(unitPath)) {
    console.log(
      "core-dump-suppression: ok (vacuous pass - packages/agent/scripts/tokentimer-agent.service does not exist yet)",
    );
    return;
  }

  const content = fs.readFileSync(unitPath, "utf8");
  const serviceSectionMatch = content.match(/\[Service\]([\s\S]*?)(\n\[|$)/);
  if (!serviceSectionMatch) {
    console.error(
      `::error file=${relUnitPath}::core-dump-suppression: could not find a [Service] section in the unit file`,
    );
    process.exit(1);
  }

  const serviceSection = serviceSectionMatch[1];
  const hasLimitCoreZero = /^\s*LimitCORE\s*=\s*0\s*$/m.test(serviceSection);

  if (!hasLimitCoreZero) {
    console.error(
      `::error file=${relUnitPath}::core-dump-suppression: [Service] section is missing "LimitCORE=0" ` +
        "(ADR-0012 decision 19) -- without it, the process's RLIMIT_CORE hard limit is left at " +
        "whatever this distribution defaults to, and a soft-limit-only mitigation elsewhere would not be " +
        "authoritative since a process may raise its own soft limit back up to that hard ceiling",
    );
    process.exit(1);
  }

  console.log(`core-dump-suppression: ok (${relUnitPath} sets LimitCORE=0 in [Service])`);
}

function validateWindowsInstaller(content) {
  const errors = [];
  if (/Set-WindowsDumpSuppression/.test(content) || /New-ItemProperty[^\r\n]*Name\s+"DumpType"[^\r\n]*Value\s+0/.test(content)) errors.push("DumpType=0 must not be installed as suppression");
  if (/Crash dumps[^\r\n]*suppressed/i.test(content)) errors.push("Installer must not claim unqualified dump suppression");
  if (!content.includes("Windows crash-dump containment is not qualified.")) errors.push("Windows containment qualification status must be explicit");
  return errors;
}
function checkWindows() {
  if (!fs.existsSync(installScriptPath)) {
    console.log(
      "core-dump-suppression: ok (vacuous pass - packages/agent/scripts/install-agent.ps1 does not exist yet)",
    );
    return;
  }

  const content = fs.readFileSync(installScriptPath, "utf8");
  const errors = validateWindowsInstaller(content);
  if (errors.length) {
    console.error(`::error file=${relInstallScriptPath}::${errors.join("; ")}`);
    process.exit(1);
  }

  console.log("core-dump-suppression: Windows installer preserves WER policy; native containment remains unqualified");
}

function main() {
  checkLinux();
  checkWindows();
}

if (require.main === module) main();
module.exports = { validateWindowsInstaller };
