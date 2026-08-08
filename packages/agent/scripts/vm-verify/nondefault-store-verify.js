"use strict";

// Real-host verification for non-default certificate-store targeting via
// acceptCertificateViaCng's mirrorAcceptedCertificateToStore path, plus the
// ownership-aware retention fix, isAgentOwnedContainerName.
// Usage: node nondefault-store-verify.js <workDir> <caConfig> [targetStore]
//   caConfig example: "tt-win2019\\TokenTimer Test Root CA"

const path = require("node:path");
const fs = require("node:fs");
const { execFileSync } = require("node:child_process");

const modRoot = "C:\\TokenTimerAgentTest\\src\\windows-cert-store";
const { generateCsrViaCng, acceptCertificateViaCng, isAgentOwnedContainerName } = require(
  path.join(modRoot, "index.js"),
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

async function main() {
  const workDir = process.argv[2] || "C:\\TokenTimerAgentTest\\work";
  const caConfig = process.argv[3];
  const targetStore = process.argv[4] || "WebHosting";
  if (!caConfig) {
    throw new Error("caConfig is required, e.g. \"tt-win2019\\TokenTimer Test Root CA\"");
  }

  console.log("=== step 1: generate a fresh real CNG CSR ===");
  const csrResult = await generateCsrViaCng({
    commonName: "nondefaultstore.tokentimer-verify.local",
    jobId: "nondefault-store-verify",
    workDir,
  });
  if (csrResult.ok === false) {
    console.log("FAIL: generateCsrViaCng ->", JSON.stringify(csrResult, null, 2));
    process.exitCode = 1;
    return;
  }
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
    const resubmit = runCaptured("certutil", ["-resubmit", requestId]);
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

  console.log("");
  console.log("driver complete.", process.exitCode === 1 ? "FAILURES ABOVE." : "ALL CHECKS PASSED.");
}

main().catch((err) => {
  console.error("UNCAUGHT ERROR:", err);
  process.exitCode = 1;
});
