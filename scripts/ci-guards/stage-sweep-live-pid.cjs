#!/usr/bin/env node
"use strict";

// Guard: regression test for a race in stage_sweep_residue (the bash
// reference client's startup sweep for crash residue, packages/agent/
// reference/tokentimer-protocol.sh). The staging-directory name embeds
// the PID of the run that created it; an earlier version of the sweep
// matched every "tokentimer-protocol.*.d" glob hit unconditionally, so
// a second, overlapping invocation by the same operator would delete
// the FIRST run's still-active staging directory mid-verify, since a
// bare glob cannot distinguish "a prior run crashed" from "a prior run
// is still running". The fix extracts the embedded PID from each
// candidate name and skips any directory whose PID is still alive
// (`kill -0`).
//
// This is a dynamic test, not a static one: it extracts the actual
// stage_sweep_residue function body from the script under test (so a
// future edit to the function is exercised, not a copy of today's
// logic) and runs it in a real bash process against two synthetic
// candidate directories -- one named with this bash process's own PID
// (guaranteed alive for the duration of the test) and one named with a
// PID chosen to be very unlikely to be alive. Asserts the live one
// survives and the dead one is swept.

const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const repoRoot = path.resolve(__dirname, "..", "..");
const targetFile = path.join(repoRoot, "packages/agent/reference/tokentimer-protocol.sh");
const relTarget = path.relative(repoRoot, targetFile).replace(/\\/g, "/");

function shQuote(value) {
  return `'${String(value).replace(/'/g, `'\\''`)}'`;
}

// Mirrors two-decode-gate.cjs's bash-runner discovery.
function commandSubstitutionWorks(command, prefixArgs) {
  const probe = spawnSync(command, [...prefixArgs, "-c", "x=$(echo tokentimer-probe-ok); printf '%s' \"$x\""], {
    encoding: "utf8",
  });
  return !probe.error && probe.status === 0 && probe.stdout === "tokentimer-probe-ok";
}

function findBashRunner() {
  const direct = spawnSync("bash", ["--version"], { encoding: "utf8" });
  if (!direct.error && direct.status === 0 && commandSubstitutionWorks("bash", [])) {
    return { command: "bash", prefixArgs: [] };
  }
  if (process.platform === "win32") {
    const wsl = spawnSync("wsl", ["-e", "bash", "--version"], { encoding: "utf8" });
    if (!wsl.error && wsl.status === 0 && commandSubstitutionWorks("wsl", ["-e", "bash"])) {
      return { command: "wsl", prefixArgs: ["-e", "bash"] };
    }
  }
  if (!direct.error && direct.status === 0) {
    return { command: "bash", prefixArgs: [] };
  }
  return null;
}

function toWslPath(winPath) {
  const m = winPath.match(/^([A-Za-z]):[\\/](.*)$/);
  if (!m) return winPath.replace(/\\/g, "/");
  const drive = m[1].toLowerCase();
  const rest = m[2].replace(/\\/g, "/");
  return `/mnt/${drive}/${rest}`;
}

function runnerNeedsPathTranslation(runner, repoRootPath) {
  const probeNative = spawnSync(runner.command, [...runner.prefixArgs, "-c", `test -d ${shQuote(repoRootPath)}`], {
    encoding: "utf8",
  });
  if (probeNative.status === 0) return false;
  const translated = toWslPath(repoRootPath);
  const probeTranslated = spawnSync(
    runner.command,
    [...runner.prefixArgs, "-c", `test -d ${shQuote(translated)}`],
    { encoding: "utf8" },
  );
  return probeTranslated.status === 0;
}

function main() {
  if (!fs.existsSync(targetFile)) {
    console.log("stage-sweep-live-pid: ok (vacuous pass - packages/agent/reference/tokentimer-protocol.sh does not exist yet)");
    return;
  }

  const runner = findBashRunner();
  if (!runner) {
    console.log(
      "stage-sweep-live-pid: skipped (no bash found on PATH and no usable `wsl bash`; this guard needs a real shell to dynamically test the sweep's live-PID exclusion)",
    );
    return;
  }

  const isWsl = runnerNeedsPathTranslation(runner, repoRoot);
  const scriptPathForBash = isWsl ? toWslPath(targetFile) : targetFile;

  // A PID chosen to be implausibly alive on any real system (Linux's
  // /proc/sys/kernel/pid_max defaults well below this, and Windows PIDs
  // are also far smaller), so kill -0 against it should reliably report
  // "no such process" without depending on scanning the live process
  // table for an actually-free PID.
  const DEAD_PID = 999999999;

  const script = `
set -e
eval "$(sed -n '/^stage_sweep_residue()/,/^}/p' ${shQuote(scriptPathForBash)})"
dir=$(mktemp -d)
export TMPDIR="$dir"
live_dir="$dir/tokentimer-protocol.$$.11112222.d"
dead_dir="$dir/tokentimer-protocol.${DEAD_PID}.33334444.d"
mkdir -m 700 "$live_dir"
mkdir -m 700 "$dead_dir"
stage_sweep_residue
if [ -d "$live_dir" ]; then echo "LIVE_PRESERVED=1"; else echo "LIVE_PRESERVED=0"; fi
if [ -d "$dead_dir" ]; then echo "DEAD_SWEPT=0"; else echo "DEAD_SWEPT=1"; fi
rm -rf "$dir"
`;

  const result = spawnSync(runner.command, [...runner.prefixArgs, "-c", script], {
    encoding: "utf8",
    timeout: 15000,
  });

  if (result.status !== 0) {
    console.error(`::error file=${relTarget}::stage-sweep-live-pid: test script exited ${result.status}`);
    console.error(result.stderr || "");
    process.exit(1);
  }

  const stdout = result.stdout || "";
  const livePreserved = /LIVE_PRESERVED=1/.test(stdout);
  const deadSwept = /DEAD_SWEPT=1/.test(stdout);

  const failures = [];
  if (!livePreserved) {
    failures.push(
      "stage_sweep_residue removed a staging directory whose embedded PID is this test process's own PID (alive by construction) -- a live, overlapping run's staging directory would be deleted mid-verify",
    );
  }
  if (!deadSwept) {
    failures.push(
      "stage_sweep_residue left behind a staging directory whose embedded PID cannot be alive -- crash residue would never be cleaned up",
    );
  }

  if (failures.length > 0) {
    for (const f of failures) {
      console.error(`::error file=${relTarget}::stage-sweep-live-pid: ${f}`);
    }
    process.exit(1);
  }

  console.log("stage-sweep-live-pid: ok (live-PID staging directory preserved, dead-PID residue swept)");
}

main();
