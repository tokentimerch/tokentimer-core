"use strict";

// Real-host repro for interrupted-cleanup recovery: simulates a process
// crash between removeCertificateAndKeyContainer's two sequential certutil
// calls (-delstore succeeds, then the process dies before -delkey runs), then
// calls removeCertificateAndKeyContainer again exactly as a retried sweep
// would, to observe whether recovery is genuinely idempotent or whether the
// retry's own -delstore call (against a certificate already gone from the
// store) fails and leaves the CNG key container permanently orphaned.
//
// Usage: node windows-retention-interrupted-cleanup.js <caConfig> <workDir>

const path = require("node:path");
const fs = require("node:fs");
const { execFileSync } = require("node:child_process");

const modRoot = "C:\\TokenTimerAgentTest\\src";
const certStore = require(path.join(modRoot, "windows-cert-store", "index.js"));
const { generateCsrViaCng, acceptCertificateViaCng, removeCertificateAndKeyContainer } = certStore;

function runCaptured(cmd, args) {
  try {
    const stdout = execFileSync(cmd, args, { encoding: "utf8", timeout: 60000, killSignal: "SIGKILL" });
    return { stdout, stderr: "", exitCode: 0 };
  } catch (err) {
    return {
      stdout: err.stdout ? err.stdout.toString() : "",
      stderr: err.stderr ? err.stderr.toString() : String(err.message || err),
      exitCode: typeof err.status === "number" ? err.status : null,
    };
  }
}

async function main() {
  const [caConfig, workDirArg] = process.argv.slice(2);
  const workDir = workDirArg || "C:\\TokenTimerAgentTest\\work-iis10";
  fs.mkdirSync(workDir, { recursive: true });

  console.log("=== step 1: real CNG enrollment (throwaway cert to interrupt cleanup on) ===");
  const csr = await generateCsrViaCng({
    commonName: "iis10-interrupted.tokentimer-verify.local",
    altNames: ["iis10-interrupted.tokentimer-verify.local"],
    jobId: "iis10-interrupted",
    workDir,
  });
  if (!csr.ok) throw new Error(`generateCsrViaCng failed: ${JSON.stringify(csr)}`);
  const csrPath = path.join(workDir, "iis10.csr.pem");
  fs.writeFileSync(csrPath, csr.csrPem, "utf8");
  const cerPath = path.join(workDir, "iis10.cer");
  const rspPath = path.join(workDir, "iis10.rsp");
  for (const p of [cerPath, rspPath]) { try { fs.unlinkSync(p); } catch { /* fine */ } }

  const submit = runCaptured("certreq", ["-f", "-submit", "-config", caConfig, csrPath, cerPath]);
  let requestId = null;
  const idMatch = `${submit.stdout}\n${submit.stderr}`.match(/RequestId:\s*(\d+)/i);
  if (idMatch) requestId = idMatch[1];
  if (!fs.existsSync(cerPath)) {
    if (!requestId) throw new Error(`no cerPath and no RequestId: ${JSON.stringify(submit)}`);
    runCaptured("certutil", ["-resubmit", requestId]);
    runCaptured("certreq", ["-f", "-retrieve", "-config", caConfig, requestId, cerPath]);
  }
  const certPem = fs.readFileSync(cerPath, "utf8");
  const accept = await acceptCertificateViaCng({ certificatePem: certPem, workDir, store: "My" });
  if (!accept.ok) throw new Error(`acceptCertificateViaCng failed: ${JSON.stringify(accept)}`);
  console.log("OK: real cert enrolled, thumbprint =", accept.thumbprint, "container =", csr.containerName);

  console.log("");
  console.log("=== step 2: confirm cert+key both present before any cleanup ===");
  const beforeStore = runCaptured("certutil", ["-store", "My", accept.thumbprint]).stdout;
  const beforeKey = runCaptured("certutil", ["-key", "-csp", "Microsoft Software Key Storage Provider"]).stdout;
  console.log("cert present before cleanup:", beforeStore.toLowerCase().includes(accept.thumbprint.toLowerCase()));
  console.log("key container present before cleanup:", beforeKey.includes(csr.containerName));

  console.log("");
  console.log("=== step 3: SIMULATE THE CRASH -- run only the -delstore half by hand, never -delkey ===");
  const manualDelstore = runCaptured("certutil", ["-delstore", "My", accept.thumbprint]);
  console.log("manual -delstore exitCode:", manualDelstore.exitCode);
  console.log("manual -delstore stdout:", manualDelstore.stdout);
  const afterCrashStore = runCaptured("certutil", ["-store", "My", accept.thumbprint]).stdout;
  const afterCrashKey = runCaptured("certutil", ["-key", "-csp", "Microsoft Software Key Storage Provider"]).stdout;
  const certGoneAfterCrash = !afterCrashStore.toLowerCase().includes(accept.thumbprint.toLowerCase());
  const keyStillThereAfterCrash = afterCrashKey.includes(csr.containerName);
  console.log("REAL STATE after simulated crash: cert gone from store =", certGoneAfterCrash, "; key container still present (orphaned) =", keyStillThereAfterCrash);

  console.log("");
  console.log("=== step 4: RETRY -- call the real removeCertificateAndKeyContainer exactly as a retried sweep would ===");
  const retryResult = await removeCertificateAndKeyContainer({
    thumbprint: accept.thumbprint,
    store: "My",
    containerName: csr.containerName,
  });
  console.log("retry removeCertificateAndKeyContainer result:", JSON.stringify(retryResult, null, 2));

  console.log("");
  console.log("=== step 5: final real state, independently confirmed ===");
  const finalStore = runCaptured("certutil", ["-store", "My", accept.thumbprint]).stdout;
  const finalKey = runCaptured("certutil", ["-key", "-csp", "Microsoft Software Key Storage Provider"]).stdout;
  const finalCertGone = !finalStore.toLowerCase().includes(accept.thumbprint.toLowerCase());
  const finalKeyGone = !finalKey.includes(csr.containerName);
  console.log("FINAL: cert gone =", finalCertGone, "; key container gone =", finalKeyGone);

  const verdict = {
    retryReportedOk: retryResult.ok === true,
    retryFailureStage: retryResult.ok === true ? null : retryResult.stage,
    keyContainerOrphanedForever: !finalKeyGone,
  };
  console.log("");
  console.log("VERDICT:", JSON.stringify(verdict, null, 2));

  // Cleanup regardless of outcome, so this driver never leaves real
  // leftover state behind on the VM.
  if (!finalKeyGone) {
    runCaptured("certutil", ["-csp", "Microsoft Software Key Storage Provider", "-delkey", csr.containerName]);
    console.log("cleanup: force-removed the orphaned key container this repro may have left behind");
  }

  console.log("");
  console.log("=== SCENARIO B: crash AFTER performCleanup fully succeeds, but BEFORE the ledger row is marked removed ===");
  console.log("(this is the second, later interruption point along the same code path; a fresh cert/key is enrolled below)");
  const csr2 = await generateCsrViaCng({
    commonName: "iis10-scenariob.tokentimer-verify.local",
    altNames: ["iis10-scenariob.tokentimer-verify.local"],
    jobId: "iis10-scenariob",
    workDir,
  });
  if (!csr2.ok) throw new Error(`generateCsrViaCng (scenario B) failed: ${JSON.stringify(csr2)}`);
  const csrPath2 = path.join(workDir, "iis10b.csr.pem");
  fs.writeFileSync(csrPath2, csr2.csrPem, "utf8");
  const cerPath2 = path.join(workDir, "iis10b.cer");
  const rspPath2 = path.join(workDir, "iis10b.rsp");
  for (const p of [cerPath2, rspPath2]) { try { fs.unlinkSync(p); } catch { /* fine */ } }
  const submit2 = runCaptured("certreq", ["-f", "-submit", "-config", caConfig, csrPath2, cerPath2]);
  let requestId2 = null;
  const idMatch2 = `${submit2.stdout}\n${submit2.stderr}`.match(/RequestId:\s*(\d+)/i);
  if (idMatch2) requestId2 = idMatch2[1];
  if (!fs.existsSync(cerPath2)) {
    if (!requestId2) throw new Error(`no cerPath2 and no RequestId: ${JSON.stringify(submit2)}`);
    runCaptured("certutil", ["-resubmit", requestId2]);
    runCaptured("certreq", ["-f", "-retrieve", "-config", caConfig, requestId2, cerPath2]);
  }
  const certPem2 = fs.readFileSync(cerPath2, "utf8");
  const accept2 = await acceptCertificateViaCng({ certificatePem: certPem2, workDir, store: "My" });
  if (!accept2.ok) throw new Error(`acceptCertificateViaCng (scenario B) failed: ${JSON.stringify(accept2)}`);
  console.log("OK: real cert #2 enrolled, thumbprint =", accept2.thumbprint, "container =", csr2.containerName);

  console.log("simulating the FULL performCleanup body completing (both -delstore and -delkey), matching a crash that happens only after both succeed but before the ledger row write:");
  const firstCleanup = await removeCertificateAndKeyContainer({
    thumbprint: accept2.thumbprint,
    store: "My",
    containerName: csr2.containerName,
  });
  console.log("first (real, complete) removeCertificateAndKeyContainer result:", JSON.stringify(firstCleanup));

  console.log("RETRY: sweepLedger would call performCleanup again here because the ledger row was never marked removed. Calling removeCertificateAndKeyContainer a second time with the identical thumbprint/containerName, exactly as that retry would:");
  const secondCleanup = await removeCertificateAndKeyContainer({
    thumbprint: accept2.thumbprint,
    store: "My",
    containerName: csr2.containerName,
  });
  console.log("second (retry) removeCertificateAndKeyContainer result:", JSON.stringify(secondCleanup, null, 2));

  const scenarioBVerdict = {
    firstCleanupOk: firstCleanup.ok === true,
    secondCleanupOk: secondCleanup.ok === true,
    secondCleanupFailureStage: secondCleanup.ok === true ? null : secondCleanup.stage,
    bugConfirmed:
      firstCleanup.ok === true && secondCleanup.ok !== true && secondCleanup.stage === "delkey",
  };
  console.log("");
  console.log("SCENARIO B VERDICT:", JSON.stringify(scenarioBVerdict, null, 2));
}

main().catch((err) => {
  console.error("UNCAUGHT ERROR:", err);
  process.exitCode = 1;
});
