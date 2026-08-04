#!/usr/bin/env node
"use strict";

// Guard: regression test for ADR-0012 decision 19's Linux core-dump
// suppression (KEY-03 in the manual acceptance checklist). Statically
// asserts the shipped systemd unit sets LimitCORE=0 in its [Service]
// section.
//
// This is deliberately static, not the KEY-03 live check itself:
// KEY-03 requires reading /proc/<pid>/limits on a real deployed service
// to prove the limit actually governs the running process, which a unit
// file alone cannot prove (a unit file can be present and not be the one
// actually governing the process -- ADR-0012 says so explicitly). This
// guard exists only to catch a future edit that silently drops the line
// this repo already had a real, previously-unfixed gap for: the shipped
// unit had no LimitCORE directive at all until this guard's sibling fix,
// so `Max core file size` on a real running agent process read
// "0 / unlimited" (soft/hard) instead of "0 / 0", the hard limit left at
// whatever the host distribution defaulted to.

const fs = require("node:fs");
const path = require("node:path");

const repoRoot = path.resolve(__dirname, "..", "..");
const unitPath = path.join(repoRoot, "packages/agent/scripts/tokentimer-agent.service");
const relUnitPath = path.relative(repoRoot, unitPath).replace(/\\/g, "/");

function main() {
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
        "(ADR-0012 decision 19, KEY-03) -- without it, the process's RLIMIT_CORE hard limit is left at " +
        "whatever this distribution defaults to, and a soft-limit-only mitigation elsewhere would not be " +
        "authoritative since a process may raise its own soft limit back up to that hard ceiling",
    );
    process.exit(1);
  }

  console.log(`core-dump-suppression: ok (${relUnitPath} sets LimitCORE=0 in [Service])`);
}

main();
