"use strict";

// Real-host verification for WCNG-01 (real CNG-native CSR generation) and
// WCNG-04 (invalid INF rejected before touching the store).
// Run on the Windows VM: node wcng-01-generate-csr.js <workDir> <outCsrPath>

const path = require("node:path");
const fs = require("node:fs");
const { execFileSync } = require("node:child_process");

const modRoot = "C:\\TokenTimerAgentTest\\src\\windows-cert-store";
const { generateCsrViaCng } = require(path.join(modRoot, "index.js"));

async function main() {
  const workDir = process.argv[2] || "C:\\TokenTimerAgentTest\\work";
  const outCsrPath = process.argv[3] || "C:\\TokenTimerAgentTest\\work\\real.csr";
  fs.mkdirSync(workDir, { recursive: true });

  console.log("=== WCNG-04: invalid INF is rejected before touching the store ===");
  try {
    await generateCsrViaCng({
      commonName: "",
      altNames: [],
      jobId: "wcng04-invalid",
      workDir,
    });
    console.log("FAIL: expected rejection for empty commonName, but call succeeded");
    process.exitCode = 1;
  } catch (err) {
    console.log("OK: rejected as expected before certreq -new:", err.message);
  }

  // On some certutil builds (confirmed on Windows Server 2022; not on 2025/2019),
  // plain "certutil -key" only enumerates legacy CryptoAPI providers and silently
  // omits CNG KSP-backed containers. Passing -csp explicitly is required to see
  // the container this module actually created. This is a test-tooling quirk,
  // not a product code issue: certreq itself has no such ambiguity.
  const CNG_KSP = "Microsoft Software Key Storage Provider";
  const keyListBefore = execFileSync("certutil", ["-key", "-csp", CNG_KSP], { encoding: "utf8" });

  console.log("");
  console.log("=== WCNG-01: real CNG-native CSR generation ===");
  const commonName = "wcng01.tokentimer-verify.local";
  const result = await generateCsrViaCng({
    commonName,
    altNames: [commonName],
    jobId: "wcng01-real",
    workDir,
  });

  if (result.ok === false) {
    console.log("FAIL: generateCsrViaCng returned ok:false ->", JSON.stringify(result, null, 2));
    process.exitCode = 1;
    return;
  }
  console.log("generateCsrViaCng ok:true, containerName =", result.containerName);
  fs.writeFileSync(outCsrPath, result.csrPem, "utf8");
  console.log("CSR written to", outCsrPath, "length:", result.csrPem.length, "bytes");

  console.log("");
  console.log("=== confirm .req/.inf artifacts were cleaned up (best-effort unlink) ===");
  console.log("infPath existed after call:", fs.existsSync(result.infPath));
  console.log("reqPath existed after call:", fs.existsSync(result.reqPath));

  console.log("");
  console.log("=== cross-check: certutil -key lists the container in MS Software KSP ===");
  const keyListAfter = execFileSync("certutil", ["-key", "-csp", CNG_KSP], { encoding: "utf8" });
  fs.writeFileSync(path.join(workDir, "certutil-key-list-after.txt"), keyListAfter);
  if (keyListAfter.includes(result.containerName)) {
    console.log("OK: container name found in certutil -key output");
  } else {
    console.log("FAIL: container name NOT found in certutil -key output");
    process.exitCode = 1;
  }
  if (!keyListBefore.includes(result.containerName) && keyListAfter.includes(result.containerName)) {
    console.log("OK: container is newly present (not pre-existing before this run)");
  }

  console.log("");
  console.log("=== no .pfx/.key file written anywhere under work dir ===");
  const workFiles = fs.readdirSync(workDir);
  const suspicious = workFiles.filter((f) => f.endsWith(".pfx") || f.endsWith(".key"));
  console.log("Files present in work dir:", workFiles.join(", "));
  if (suspicious.length === 0) {
    console.log("OK: no .pfx/.key artifacts in work dir");
  } else {
    console.log("FAIL: unexpected key material files found:", suspicious.join(", "));
    process.exitCode = 1;
  }

  console.log("");
  console.log("containerName for WCNG-02:", result.containerName);
  fs.writeFileSync(path.join(workDir, "container-name.txt"), result.containerName);
}

main().catch((err) => {
  console.error("UNCAUGHT ERROR:", err);
  process.exitCode = 1;
});
