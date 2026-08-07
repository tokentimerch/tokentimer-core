"use strict";

// Real-host verification for real restart-across-cleanup
// survival. Creates a ledger row in one process, "kills" that process
// (just exits normally here, simulating the crash boundary via a fresh
// process invocation), then a SECOND, independent node process re-reads
// the row and reaches the same eligibility decision purely from the
// on-disk row (no in-memory state carried over).
//
// Usage:
//   node windows-retention-restart.js create <ledgerDir>   (process 1)
//   node windows-retention-restart.js resume <ledgerDir>   (process 2, fresh)

const retMod = require("C:\\TokenTimerAgentTest\\src\\windows-retention\\index.js");

const THUMBPRINT = "AA00000000000000000000000000000000009A".slice(0, 40).padEnd(40, "0").toUpperCase();

async function create(ledgerDir) {
  const now = new Date();
  const row = retMod.createLedgerRow({
    ledgerDir,
    oldThumbprint: THUMBPRINT,
    replacementThumbprint: "BB".repeat(20),
    cngKeyContainerId: "tokentimer-retention-restart-test",
    verifiedCutoverAt: now.toISOString(),
    oldNotAfter: new Date(now.getTime() + 1000 * 60 * 60 * 24 * 30).toISOString(),
    ownershipProvenance: "tokentimer_installed",
    jobOrRollbackJournalRefs: [],
  });
  console.log("PROCESS 1 (create): row written ->", JSON.stringify(row));
  console.log("PROCESS 1: exiting now (simulating a crash boundary before any cleanup deadline)");
}

async function resume(ledgerDir) {
  // A brand-new process, no shared memory/module state with process 1
  // whatsoever beyond the file on disk.
  const row = retMod.readLedgerRow(ledgerDir, THUMBPRINT);
  if (row === null) {
    console.log("FAIL: fresh process could not find the row written by process 1");
    process.exitCode = 1;
    return;
  }
  console.log("PROCESS 2 (resume, fresh node.exe): row read back ->", JSON.stringify(row));

  const eligibility = retMod.evaluateEligibility(row, {
    retentionHours: 24,
    bindingStillReferencesOldThumbprint: false,
    keyContainerSharedWithSurvivor: false,
    replacementPassesHandshakeNow: true,
    now: () => new Date(Date.parse(row.verifiedCutoverAt) + 1000 * 60 * 60 * 25),
  });
  console.log("PROCESS 2: eligibility decision from persisted row alone ->", JSON.stringify(eligibility));
  if (eligibility.eligible !== true) {
    console.log("FAIL: expected eligible:true from a fresh process reading only the persisted row");
    process.exitCode = 1;
    return;
  }
  console.log("OK: a fresh process reached the correct eligibility decision using only the on-disk ledger row");

  // Clean up test row.
  retMod.writeLedgerRow(ledgerDir, { ...row, lifecycleState: "removed", deferralReason: null });
  console.log("PROCESS 2: test row marked removed (cleanup)");
}

async function main() {
  const [mode, ledgerDir] = process.argv.slice(2);
  if (mode === "create") return create(ledgerDir);
  if (mode === "resume") return resume(ledgerDir);
  throw new Error(`unknown mode ${mode}; expected 'create' or 'resume'`);
}

main().catch((err) => {
  console.error("UNCAUGHT ERROR:", err);
  process.exitCode = 1;
});
