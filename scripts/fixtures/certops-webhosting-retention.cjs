"use strict";
// Supporting public proof fixture only; no native execution or qualification claim.
const h=require("../../packages/agent/scripts/host/retention-webhosting-fixture");
function elapsed() {
  return {
    mode: "real-clock-two-cutover-expiry-grace",
    successfulCutovers: 2,
    predecessorCertificatesRemoved: 2,
    predecessorKeysRemoved: 2,
    lineageRowsFinalized: 2,
    immediateDeferralPreservedCustody: true,
    immutableHistoryPreserved: true,
    replacementTrustedBoundCustodyUnchanged: true,
    interruptedNativeDeleteRecovered: true,
    configuredRetentionHours: 24,
    fullRetentionWindowQualified: false,
    waitedMonotonicMs: 420000,
    ownedInterruption: {
      scope: "owned-short-retention-native-interruption-drain",
      assignedBeforeResume: true,
      rootExit86: true,
      nativeActiveZero: true,
      nativeHandlesClosed: true,
      wrapperClosed: true,
    },
  };
}
function proof() {
  return {
    schemaVersion: 1,
    scope: h.SCOPE,
    store: "WebHosting",
    storeReceipt: {
      store: "WebHosting",
      ...Object.fromEntries(h.FLAGS.map((x) => [x, true])),
    },
    elapsed: elapsed(),
    borrowedReplacement: {
      sameOriginalMyCustodyAndInventory: true,
      sameOriginalMyPrivateKeyPossession: true,
      mirrorRemovedWithoutDeletingSharedKey: true,
      originalFixtureCertificateAndKeyRemoved: true,
    },
    fullRetentionWindowQualified: false,
    installedServiceTimerQualified: false,
  };
}
module.exports={proof};
