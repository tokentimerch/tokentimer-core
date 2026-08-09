"use strict";

// Real-host verification for non-default certificate-store targeting and the
// complete superseded-certificate retention lifecycle. All certificate and
// key deletion is limited to material created and provenance-recorded by this
// run through the production CNG helpers.
// Usage: node nondefault-store-verify.js <workDir> <caConfig> [targetStore]
//   caConfig example: "tt-win2019\\TokenTimer Test Root CA"

const path = require("node:path");
const fs = require("node:fs");
const { execFileSync } = require("node:child_process");

const modRoot = "C:\\TokenTimerAgentTest\\src\\windows-cert-store";
const {
  generateCsrViaCng,
  acceptCertificateViaCng,
  acquireStoreLock,
  isAgentOwnedContainerName,
  markIssuedContainerAccepted,
  readIssuedContainerRecord,
  recordIssuedContainer,
  removeCertificateAndKeyContainer,
  removeIssuedContainerRecord,
} = require(
  path.join(modRoot, "index.js"),
);
const retention = require("C:\\TokenTimerAgentTest\\src\\windows-retention\\index.js");
const { recordSupersededWindowsCertificate } = require(
  "C:\\TokenTimerAgentTest\\src\\index.js",
);

function runCaptured(cmd, args) {
  try {
    const stdout = execFileSync(cmd, args, { encoding: "utf8" });
    return { stdout, stderr: "", exitCode: 0 };
  } catch (err) {
    return {
      stdout: err.stdout ? err.stdout.toString() : "",
      stderr: err.stderr ? err.stderr.toString() : String(err.message || err),
      exitCode: typeof err.status === "number" ? err.status : null,
    };
  }
}

async function enrollTestCertificate({
  workDir,
  stateDir,
  caConfig,
  targetStore,
  stem,
  commonName,
}) {
  const csr = await generateCsrViaCng({ commonName, jobId: stem, workDir });
  if (csr.ok === false) throw new Error(`${stem}: CNG CSR generation failed`);
  recordIssuedContainer({
    stateDir,
    containerName: csr.containerName,
    jobId: stem,
    certificateId: commonName,
  });
  const csrPath = path.join(workDir, `${stem}.csr`);
  const cerPath = path.join(workDir, `${stem}.cer`);
  fs.writeFileSync(csrPath, csr.csrPem, "utf8");
  try { fs.unlinkSync(cerPath); } catch { /* absent is expected */ }
  const submit = runCaptured("certreq", ["-submit", "-config", caConfig, csrPath, cerPath]);
  const match = `${submit.stdout}\n${submit.stderr}`.match(/RequestId:\s*(\d+)/i);
  if (!fs.existsSync(cerPath) && match) {
    const resubmit = runCaptured("certutil", ["-config", caConfig, "-resubmit", match[1]]);
    if (resubmit.exitCode !== 0) throw new Error(`${stem}: certutil resubmit failed`);
    runCaptured("certreq", ["-retrieve", "-config", caConfig, match[1], cerPath]);
  }
  if (!fs.existsSync(cerPath)) throw new Error(`${stem}: issued certificate was not retrieved`);
  const certificatePem = fs.readFileSync(cerPath, "utf8");
  const accepted = await acceptCertificateViaCng({ certificatePem, workDir, store: targetStore });
  if (accepted.ok === false) throw new Error(`${stem}: certificate acceptance failed`);
  if (
    !markIssuedContainerAccepted({
      stateDir,
      containerName: csr.containerName,
      acceptedThumbprint: accepted.thumbprint,
      store: targetStore,
    })
  ) {
    throw new Error(`${stem}: could not mark the issued container accepted`);
  }
  const issuanceRecord = readIssuedContainerRecord({
    stateDir,
    containerName: csr.containerName,
  });
  if (
    issuanceRecord?.status !== "enrolled_by_agent" ||
    issuanceRecord.acceptedThumbprint !== accepted.thumbprint.toUpperCase()
  ) {
    throw new Error(`${stem}: accepted-container provenance was not persisted`);
  }
  return { ...csr, ...accepted, certificatePem, issuanceRecord };
}

async function main() {
  const workDir = process.argv[2] || "C:\\TokenTimerAgentTest\\work";
  const caConfig = process.argv[3];
  const targetStore = process.argv[4] || "WebHosting";
  const stateDir = path.join(workDir, "nondefault-store-state");
  const commonName = "nondefaultstore.tokentimer-verify.local";
  if (!caConfig) {
    throw new Error("caConfig is required, e.g. \"tt-win2019\\TokenTimer Test Root CA\"");
  }

  console.log("=== step 1: generate a fresh real CNG CSR ===");
  const csrResult = await generateCsrViaCng({
    commonName,
    jobId: "nondefault-store-verify",
    workDir,
  });
  if (csrResult.ok === false) {
    console.log("FAIL: generateCsrViaCng ->", JSON.stringify(csrResult, null, 2));
    process.exitCode = 1;
    return;
  }
  recordIssuedContainer({
    stateDir,
    containerName: csrResult.containerName,
    jobId: "nondefault-store-verify",
    certificateId: commonName,
  });
  console.log("container name:", csrResult.containerName);
  const csrPath = path.join(workDir, "nondefault-store-verify.csr");
  fs.writeFileSync(csrPath, csrResult.csrPem, { encoding: "utf8" });

  console.log("");
  console.log("=== step 2: submit CSR to the real test CA ===");
  const cerPath = path.join(workDir, "nondefault-store-verify.cer");
  try {
    fs.unlinkSync(cerPath);
  } catch {
    // fine if it didn't exist
  }
  let requestId = null;
  const submit = runCaptured("certreq", ["-submit", "-config", caConfig, csrPath, cerPath]);
  console.log("certreq -submit stdout:", submit.stdout);
  console.log("certreq -submit stderr:", submit.stderr);
  const combined = `${submit.stdout}\n${submit.stderr}`;
  const idMatch = combined.match(/RequestId:\s*(\d+)/i);
  if (idMatch) requestId = idMatch[1];

  if (!fs.existsSync(cerPath)) {
    if (!requestId) {
      throw new Error("certreq -submit did not produce a cerPath and no RequestId could be parsed from its output");
    }
    console.log("Request is pending admin approval, RequestId =", requestId, "-- approving via certutil -resubmit");
    const resubmit = runCaptured("certutil", ["-config", caConfig, "-resubmit", requestId]);
    console.log("certutil -resubmit stdout:", resubmit.stdout);
    console.log("certutil -resubmit stderr:", resubmit.stderr);

    console.log("retrieving the now-issued certificate...");
    const retrieve = runCaptured("certreq", ["-retrieve", "-config", caConfig, requestId, cerPath]);
    console.log("certreq -retrieve stdout:", retrieve.stdout);
    console.log("certreq -retrieve stderr:", retrieve.stderr);
  }

  if (!fs.existsSync(cerPath)) {
    throw new Error("cerPath still missing after submit/resubmit/retrieve -- cannot proceed");
  }
  const certificatePem = fs.readFileSync(cerPath, "utf8");
  console.log("issued certificate PEM length:", certificatePem.length);

  console.log("");
  console.log(`=== step 3: acceptCertificateViaCng with store="${targetStore}" ===`);
  const acceptResult = await acceptCertificateViaCng({ certificatePem, workDir, store: targetStore });
  if (acceptResult.ok === false) {
    console.log("FAIL: acceptCertificateViaCng returned ok:false ->", JSON.stringify(acceptResult, null, 2));
    process.exitCode = 1;
    return;
  }
  console.log("acceptCertificateViaCng ok:true, thumbprint =", acceptResult.thumbprint, "store =", acceptResult.store);
  if (
    !markIssuedContainerAccepted({
      stateDir,
      containerName: csrResult.containerName,
      acceptedThumbprint: acceptResult.thumbprint,
      store: targetStore,
    })
  ) {
    throw new Error("initial certificate acceptance provenance was not persisted");
  }
  const initialIssuanceRecord = readIssuedContainerRecord({
    stateDir,
    containerName: csrResult.containerName,
  });
  if (
    initialIssuanceRecord?.status !== "enrolled_by_agent" ||
    initialIssuanceRecord.acceptedThumbprint !== acceptResult.thumbprint.toUpperCase()
  ) {
    throw new Error("initial issued-container record does not match the accepted certificate");
  }
  fs.writeFileSync(path.join(workDir, "nondefault-store-verify-thumbprint.txt"), acceptResult.thumbprint, { encoding: "utf8" });

  console.log("");
  console.log(`=== step 4: independent verification -- certutil -store ${targetStore} <thumbprint> ===`);
  const targetStoreQuery = runCaptured("certutil", ["-store", targetStore, acceptResult.thumbprint]);
  fs.writeFileSync(path.join(workDir, "nondefault-store-verify-certutil-target-store.txt"), targetStoreQuery.stdout, { encoding: "utf8" });
  console.log(targetStoreQuery.stdout);
  const normalizedTarget = targetStoreQuery.stdout.replace(/[^0-9A-Fa-f]/g, "").toUpperCase();
  const foundInTarget = normalizedTarget.includes(acceptResult.thumbprint);
  const hasPrivateKeyInTarget =
    /Key Container\s*=/i.test(targetStoreQuery.stdout) || /Provider\s*=/i.test(targetStoreQuery.stdout);
  console.log("thumbprint found verbatim in target-store certutil output:", foundInTarget);
  console.log("Key Container/Provider line present in target-store output (private key survived the move):", hasPrivateKeyInTarget);
  if (!foundInTarget) {
    console.log("FAIL: expected thumbprint in target store output");
    process.exitCode = 1;
  }
  if (!hasPrivateKeyInTarget) {
    console.log("FAIL: expected the CNG private-key association to have followed the certificate into", targetStore);
    process.exitCode = 1;
  }

  console.log("");
  console.log("=== step 5: confirm My no longer holds this thumbprint (delstore actually ran) ===");
  const myQuery = runCaptured("certutil", ["-store", "My", acceptResult.thumbprint]);
  const myStillHasIt = myQuery.exitCode === 0 && myQuery.stdout.replace(/[^0-9A-Fa-f]/g, "").toUpperCase().includes(acceptResult.thumbprint);
  fs.writeFileSync(path.join(workDir, "nondefault-store-verify-certutil-my-store-after.txt"), `exitCode=${myQuery.exitCode}\n${myQuery.stdout}\n${myQuery.stderr}`, {
    encoding: "utf8",
  });
  console.log("certutil -store My <thumbprint> exitCode:", myQuery.exitCode);
  console.log("My still has this thumbprint after mirror+delstore:", myStillHasIt);
  if (myStillHasIt) {
    console.log("FAIL: certificate should have been removed from My after being mirrored to", targetStore);
    process.exitCode = 1;
  } else {
    console.log("OK: certificate is live in", targetStore, "only, not duplicated in My");
  }

  console.log("");
  console.log("=== step 6: ownership-aware retention check (isAgentOwnedContainerName) ===");
  const ownCheck = isAgentOwnedContainerName(csrResult.containerName);
  const foreignCheck = isAgentOwnedContainerName("IIS-installed-abc123-not-ours");
  const emptyCheck = isAgentOwnedContainerName(undefined);
  console.log("our own container name", JSON.stringify(csrResult.containerName), "-> isAgentOwnedContainerName:", ownCheck);
  console.log("a plausible non-agent container name -> isAgentOwnedContainerName:", foreignCheck);
  console.log("undefined -> isAgentOwnedContainerName:", emptyCheck);
  if (!ownCheck) {
    console.log("FAIL: our own container name should be recognized as agent-owned");
    process.exitCode = 1;
  }
  if (foreignCheck) {
    console.log("FAIL: a non-agent-prefixed container name must NOT be recognized as agent-owned");
    process.exitCode = 1;
  }
  if (emptyCheck) {
    console.log("FAIL: undefined must not be recognized as agent-owned");
    process.exitCode = 1;
  }
  if (process.exitCode === 1) {
    throw new Error("non-default-store preconditions failed; refusing to start retention cleanup");
  }

  console.log("");
  console.log("=== step 7: enroll a distinct replacement through the same production CNG path ===");
  const replacement = await enrollTestCertificate({
    workDir,
    stateDir,
    caConfig,
    targetStore,
    stem: "nondefault-store-retention-replacement",
    commonName,
  });
  console.log("replacement thumbprint:", replacement.thumbprint);

  console.log("");
  console.log("=== step 8: durable retention ledger and all eligibility gates ===");
  const ledgerDir = path.join(stateDir, "windows-retention");
  await recordSupersededWindowsCertificate({
    jobId: "nondefault-store-real-host",
    stateDir,
    store: targetStore,
    oldThumbprint: acceptResult.thumbprint,
    replacementThumbprint: replacement.thumbprint,
    log: console.log,
  });
  const recordedRow = retention.readLedgerRow(ledgerDir, acceptResult.thumbprint);
  if (
    recordedRow?.ownershipProvenance !== "tokentimer_installed" ||
    recordedRow.cngKeyContainerId !== csrResult.containerName ||
    recordedRow.replacementThumbprint !== replacement.thumbprint.toUpperCase()
  ) {
    throw new Error("production supersession recorder did not prove predecessor ownership");
  }
  const row = retention.writeLedgerRow(ledgerDir, {
    ...recordedRow,
    jobOrRollbackJournalRefs: [
      { ref: "nondefault-store-real-host", active: true },
    ],
  });
  const deadline = retention.computeCleanupDeadline({
    verifiedCutoverAt: row.verifiedCutoverAt,
    oldNotAfter: row.oldNotAfter,
    retentionHours: 24,
  });
  const baseContext = {
    retentionHours: 24,
    bindingStillReferencesOldThumbprint: false,
    keyContainerSharedWithSurvivor: false,
    replacementPassesHandshakeNow: true,
  };
  const expectDeferred = (label, candidateRow, context, reason, instant) => {
    const outcome = retention.evaluateEligibility(candidateRow, {
      ...baseContext,
      ...context,
      now: () => instant,
    });
    console.log(label, "->", JSON.stringify(outcome));
    if (outcome.eligible !== false || outcome.reason !== reason) {
      throw new Error(`${label}: expected ${reason}`);
    }
  };
  const afterDeadline = new Date(deadline.getTime() + 1);
  expectDeferred("active journal reference", row, {}, "active_reference_present", afterDeadline);
  const closedRow = retention.closeJournalReference(
    ledgerDir,
    row.oldThumbprint,
    "nondefault-store-real-host",
  );
  expectDeferred(
    "active binding",
    closedRow,
    { bindingStillReferencesOldThumbprint: true },
    "binding_still_present",
    afterDeadline,
  );
  expectDeferred(
    "shared key container",
    closedRow,
    { keyContainerSharedWithSurvivor: true },
    "shared_key_container",
    afterDeadline,
  );
  expectDeferred(
    "non-owned material",
    { ...closedRow, ownershipProvenance: "preexisting" },
    {},
    "ownership_unrecorded",
    afterDeadline,
  );
  expectDeferred(
    "one millisecond before deadline",
    closedRow,
    {},
    "deadline_not_reached",
    new Date(deadline.getTime() - 1),
  );
  expectDeferred(
    "exact deadline boundary",
    closedRow,
    {},
    "deadline_not_reached",
    new Date(deadline.getTime()),
  );

  console.log("");
  console.log("=== step 9: restart persistence in a fresh node.exe process ===");
  const restartProbe = [
    "const r=require(process.argv[1]);",
    "const row=r.readLedgerRow(process.argv[2],process.argv[3]);",
    "if(!row||row.oldThumbprint!==process.argv[3])process.exit(2);",
    "process.stdout.write(row.lifecycleState);",
  ].join("");
  const restartState = execFileSync(
    process.execPath,
    ["-e", restartProbe, "C:\\TokenTimerAgentTest\\src\\windows-retention\\index.js", ledgerDir, row.oldThumbprint],
    { encoding: "utf8" },
  );
  console.log("fresh process re-read lifecycle state:", restartState);

  console.log("");
  console.log("=== step 10: strict post-deadline production sweep removes real cert and CNG key ===");
  const sweep = await retention.sweepLedger({
    ledgerDir,
    retentionHours: 24,
    gatherContext: () => ({
      bindingStillReferencesOldThumbprint: false,
      keyContainerSharedWithSurvivor: false,
      replacementPassesHandshakeNow: true,
    }),
    performCleanup: async (ledgerRow) => {
      const storeLock = acquireStoreLock(stateDir, ledgerRow.store);
      try {
        const removed = await removeCertificateAndKeyContainer({
          thumbprint: ledgerRow.oldThumbprint,
          store: ledgerRow.store,
          containerName: ledgerRow.cngKeyContainerId,
        });
        if (!removed.ok) throw new Error(`cleanup failed at ${removed.stage}`);
        removeIssuedContainerRecord({
          stateDir,
          containerName: ledgerRow.cngKeyContainerId,
        });
      } finally {
        storeLock.release();
      }
    },
    now: () => afterDeadline,
  });
  console.log("sweepLedger ->", JSON.stringify(sweep));
  if (!sweep.removed.includes(acceptResult.thumbprint)) {
    throw new Error("production sweep did not mark the real predecessor removed");
  }
  const removedLedgerRow = retention.readLedgerRow(
    ledgerDir,
    acceptResult.thumbprint,
  );
  if (removedLedgerRow?.lifecycleState !== "removed") {
    throw new Error("retention ledger did not persist the removed lifecycle state");
  }
  const oldStoreProbe = runCaptured("certutil", ["-store", targetStore, acceptResult.thumbprint]);
  const normalizedOldStoreOutput = oldStoreProbe.stdout
    .replace(/[^0-9A-Fa-f]/g, "")
    .toUpperCase();
  if (
    oldStoreProbe.exitCode === 0 &&
    normalizedOldStoreOutput.includes(acceptResult.thumbprint.toUpperCase())
  ) {
    throw new Error("old certificate still exists after production cleanup");
  }
  const oldKeyProbe = runCaptured("certutil", [
    "-csp",
    "Microsoft Software Key Storage Provider",
    "-key",
    csrResult.containerName,
  ]);
  if (oldKeyProbe.exitCode === 0 && oldKeyProbe.stdout.includes(csrResult.containerName)) {
    throw new Error("old CNG key container still exists after production cleanup");
  }
  const replacementStoreProbe = runCaptured("certutil", [
    "-store",
    targetStore,
    replacement.thumbprint,
  ]);
  const normalizedReplacementOutput = replacementStoreProbe.stdout
    .replace(/[^0-9A-Fa-f]/g, "")
    .toUpperCase();
  if (
    replacementStoreProbe.exitCode !== 0 ||
    !normalizedReplacementOutput.includes(replacement.thumbprint.toUpperCase())
  ) {
    throw new Error("replacement certificate was removed or is absent from the target store");
  }
  const replacementKeyProbe = runCaptured("certutil", [
    "-csp",
    "Microsoft Software Key Storage Provider",
    "-key",
    replacement.containerName,
  ]);
  if (
    replacementKeyProbe.exitCode !== 0 ||
    !replacementKeyProbe.stdout
      .toUpperCase()
      .includes(replacement.containerName.toUpperCase())
  ) {
    throw new Error("replacement CNG key container was removed or is unavailable");
  }
  console.log(
    "OK: old certificate and agent-owned CNG key container are absent; replacement certificate and key remain installed",
  );

  console.log("");
  console.log("driver complete.", process.exitCode === 1 ? "FAILURES ABOVE." : "ALL CHECKS PASSED.");
}

main().catch((err) => {
  console.error("UNCAUGHT ERROR:", err);
  process.exitCode = 1;
});
