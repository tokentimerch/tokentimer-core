#!/usr/bin/env node
"use strict";

// Guard: regression test for ADR-0012 decision 19's core-dump suppression,
// both platform halves: Linux and Windows. Statically asserts the shipped
// systemd unit sets
// LimitCORE=0, and that the Windows installer sets the WER LocalDumps
// DumpType=0 registry value for node.exe.
//
// This is deliberately static, not the live checks
// themselves: those require reading back real running-process/registry
// state on a real deployed host to prove the mitigation actually governs
// what runs, which source alone cannot prove (a unit file or installer
// script can be present and not be the one actually governing the
// process -- ADR-0012 says so explicitly for both halves). This guard
// exists only to catch a future edit that silently drops either line.
// The Linux unit had no LimitCORE directive at all until this guard's
// sibling fix, so `Max core file size` on a real running agent process
// read "0 / unlimited" (soft/hard) instead of "0 / 0"; the Windows
// installer had no LocalDumps write at all until the fix this guard's
// other half covers, despite ADR-0012 documenting it as already
// implemented.

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

function checkWindows() {
  if (!fs.existsSync(installScriptPath)) {
    console.log(
      "core-dump-suppression: ok (vacuous pass - packages/agent/scripts/install-agent.ps1 does not exist yet)",
    );
    return;
  }

  const content = fs.readFileSync(installScriptPath, "utf8");
  const hasLocalDumpsKey = /LocalDumps\\\$ExeName/.test(content) || /LocalDumps\\node\.exe/.test(content);
  const hasDumpTypeZero = /Name\s+"DumpType"[\s\S]{0,80}Value\s+0/.test(content);
  const setsForNodeExe = /Set-WindowsDumpSuppression\s+-ExeName\s+"node\.exe"/.test(content);

  if (!hasLocalDumpsKey || !hasDumpTypeZero || !setsForNodeExe) {
    console.error(
      `::error file=${relInstallScriptPath}::core-dump-suppression: install-agent.ps1 is missing the WER ` +
        "LocalDumps DumpType=0 write for node.exe (ADR-0012 decision 19) -- without it, the Windows " +
        "Error Reporting default for the process that holds agent key material is left unspecified rather " +
        "than explicitly disabled",
    );
    process.exit(1);
  }

  console.log(`core-dump-suppression: ok (${relInstallScriptPath} sets WER LocalDumps DumpType=0 for node.exe)`);
}

function main() {
  checkLinux();
  checkWindows();
}

main();
