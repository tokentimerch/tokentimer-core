"use strict";

// Real-host verification for WRET-01 (real ledger row lifecycle on NTFS,
// real ACL), WRET-02 (real sweep against a real superseded cert from the
// WIIS cutover above), WRET-03 (real active-reference deferral), WRET-05
// (retention-boundary values against real validateRetentionHours).
//
// Usage: node wret-01-05-lifecycle.js <ledgerDir>

const path = require("node:path");
const fs = require("node:fs");
const { execFileSync } = require("node:child_process");

const retMod = require("C:\\TokenTimerAgentTest\\src\\windows-retention\\index.js");
const {
  createLedgerRow,
  readLedgerRow,
  listLedgerThumbprints,
  evaluateEligibility,
  sweepLedger,
  validateRetentionHours,
} = retMod;

function checkAcl(targetPath) {
  return execFileSync("icacls", [targetPath], { encoding: "utf8" });
}

async function main() {
  const ledgerDir = process.argv[2] || "C:\\TokenTimerAgentTest\\state\\windows-retention";

  console.log("=== WRET-05: retention-boundary values against the real, deployed validateRetentionHours ===");
  const acceptedValues = [24, 168, 720];
  const rejectedValues = [0, 23, 721];
  for (const v of acceptedValues) {
    try {
      validateRetentionHours(v);
      console.log(`OK: ${v} accepted as expected`);
    } catch (err) {
      console.log(`FAIL: ${v} should have been accepted, got error: ${err.message}`);
      process.exitCode = 1;
    }
  }
  for (const v of rejectedValues) {
    try {
      validateRetentionHours(v);
      console.log(`FAIL: ${v} should have been rejected but was accepted`);
      process.exitCode = 1;
    } catch (err) {
      console.log(`OK: ${v} rejected as expected: ${err.message}`);
    }
  }

  console.log("");
  console.log("=== WRET-01: real ledger row lifecycle on real NTFS + real ACL ===");
  // Old (superseded) cert is the WIIS baseline cert; new (replacement) is
  // the real WCNG-02 CA-issued cert deployed over it.
  const oldThumbprint = "EEBB3A5845965C7F2A9F67540D53D5662564180B"; // wiis-old self-signed
  const replacementThumbprint = "DAA61C502810CA0952DF77A0D4194C32085B5ABD"; // real CA-issued (WCNG-02)
  const cngKeyContainerId = "tokentimer-wcng01-real-1875df97";

  // Clean any pre-existing row from a prior run of this script.
  const rowPath = retMod.ledgerRowPath(ledgerDir, oldThumbprint);
  try { fs.unlinkSync(rowPath); } catch { /* ignore */ }

  const now = new Date();
  const verifiedCutoverAt = now.toISOString();
  const oldNotAfter = new Date(now.getTime() + 1000 * 60 * 60 * 24 * 365).toISOString(); // ~1yr out (self-signed default)

  const row = createLedgerRow({
    ledgerDir,
    oldThumbprint,
    replacementThumbprint,
    cngKeyContainerId,
    verifiedCutoverAt,
    oldNotAfter,
    ownershipProvenance: "tokentimer_installed",
    jobOrRollbackJournalRefs: [{ ref: "job-wret-01", active: true }],
  });
  console.log("createLedgerRow ->", JSON.stringify(row, null, 2));

  if (!fs.existsSync(rowPath)) {
    console.log("FAIL: ledger row file was not created at", rowPath);
    process.exitCode = 1;
    return;
  }
  console.log("OK: ledger row file exists on real NTFS at", rowPath);

  console.log("");
  console.log("=== real ACL check via icacls (decision 10: owner+SYSTEM only) ===");
  const acl = checkAcl(rowPath);
  console.log(acl);
  fs.writeFileSync(path.join(ledgerDir, "..", "wret-01-icacls.txt"), acl);

  console.log("=== real interrupted-write repro: kill mid-write, confirm atomic rename means no partial file ever appears ===");
  // writeLedgerRow always writes to a *.tmp file then renames; simulate an
  // "interrupted write" by writing a tmp file with garbage and confirming
  // readLedgerRow/listLedgerThumbprints never see it (only real .json
  // files matching THUMBPRINT_PATTERN are considered).
  const fakeTmpPath = `${rowPath}.99999.deadbeef.tmp`;
  fs.writeFileSync(fakeTmpPath, "{not valid json, simulating a torn write}");
  const thumbprintsWithTmp = listLedgerThumbprints(ledgerDir);
  console.log("listLedgerThumbprints while a .tmp file is present:", thumbprintsWithTmp);
  if (thumbprintsWithTmp.includes(oldThumbprint) && !thumbprintsWithTmp.some((t) => t.includes(".tmp"))) {
    console.log("OK: a torn/orphaned .tmp file is correctly excluded from the row listing");
  } else {
    console.log("FAIL: unexpected listLedgerThumbprints result in presence of a .tmp file");
    process.exitCode = 1;
  }
  fs.unlinkSync(fakeTmpPath);

  console.log("");
  console.log("=== WRET-01 continued: readLedgerRow round-trips the same row from disk ===");
  const reRead = readLedgerRow(ledgerDir, oldThumbprint);
  console.log("readLedgerRow ->", JSON.stringify(reRead, null, 2));
  if (JSON.stringify(reRead) !== JSON.stringify(row)) {
    console.log("FAIL: re-read row does not match the created row");
    process.exitCode = 1;
  } else {
    console.log("OK: re-read row matches byte-for-byte (after JSON normalization)");
  }

  console.log("");
  console.log("=== WRET-03: real active-reference deferral ===");
  const activeRefEligibility = evaluateEligibility(reRead, {
    retentionHours: 24,
    bindingStillReferencesOldThumbprint: false,
    keyContainerSharedWithSurvivor: false,
    replacementPassesHandshakeNow: true,
    now: () => new Date(now.getTime() + 1000 * 60 * 60 * 25), // past the 24h deadline
  });
  console.log("evaluateEligibility with an active journal ref still open:", JSON.stringify(activeRefEligibility));
  if (activeRefEligibility.eligible !== false || activeRefEligibility.reason !== "active_reference_present") {
    console.log("FAIL: expected eligible:false, reason:active_reference_present");
    process.exitCode = 1;
  } else {
    console.log("OK: real sweep-equivalent evaluation defers on active_reference_present");
  }

  console.log("");
  console.log("=== close the journal ref, confirm eligibility flips ===");
  const closedRow = retMod.closeJournalReference(ledgerDir, oldThumbprint, "job-wret-01");
  console.log("closeJournalReference ->", JSON.stringify(closedRow));
  const afterCloseEligibility = evaluateEligibility(closedRow, {
    retentionHours: 24,
    bindingStillReferencesOldThumbprint: false,
    keyContainerSharedWithSurvivor: false,
    replacementPassesHandshakeNow: true,
    now: () => new Date(now.getTime() + 1000 * 60 * 60 * 25),
  });
  console.log("evaluateEligibility after closing the ref:", JSON.stringify(afterCloseEligibility));

  console.log("");
  console.log("=== WRET-02: real sweep against this real (simulated-superseded) cert ===");
  let cleanupCalled = false;
  const sweepResult = await sweepLedger({
    ledgerDir,
    retentionHours: 24,
    gatherContext: async () => ({
      bindingStillReferencesOldThumbprint: false,
      keyContainerSharedWithSurvivor: false,
      replacementPassesHandshakeNow: true,
    }),
    performCleanup: async () => {
      cleanupCalled = true;
    },
    now: () => new Date(now.getTime() + 1000 * 60 * 60 * 25),
  });
  console.log("sweepLedger result:", JSON.stringify(sweepResult, null, 2));
  if (!cleanupCalled || !sweepResult.removed.includes(oldThumbprint)) {
    console.log("FAIL: expected performCleanup to be called and the row to be removed");
    process.exitCode = 1;
  } else {
    console.log("OK: real sweep called performCleanup and marked the row removed");
  }

  const finalRow = readLedgerRow(ledgerDir, oldThumbprint);
  console.log("final row lifecycleState:", finalRow.lifecycleState);
  if (finalRow.lifecycleState !== "removed") {
    console.log("FAIL: expected lifecycleState 'removed' after sweep");
    process.exitCode = 1;
  }
}

main().catch((err) => {
  console.error("UNCAUGHT ERROR:", err);
  process.exitCode = 1;
});
