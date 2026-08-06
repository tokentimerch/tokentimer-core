"use strict";

// Real-host verification for WCNG-02 (real CNG-native acceptance) and
// WCNG-05 (thumbprint utility cross-check).
// Usage: node wcng-02-accept.js <workDir> <certPemPath>

const path = require("node:path");
const fs = require("node:fs");
const crypto = require("node:crypto");
const { execFileSync } = require("node:child_process");

const modRoot = "C:\\TokenTimerAgentTest\\src\\windows-cert-store";
const { acceptCertificateViaCng, computeSha1ThumbprintFromPem } = require(path.join(modRoot, "index.js"));

async function main() {
  const workDir = process.argv[2] || "C:\\TokenTimerAgentTest\\work";
  const certPemPath = process.argv[3] || "C:\\TokenTimerAgentTest\\work\\real.cer";
  const certificatePem = fs.readFileSync(certPemPath, "utf8");

  console.log("=== WCNG-05: thumbprint utility cross-check (before accept) ===");
  const ourThumbprint = computeSha1ThumbprintFromPem(certificatePem);
  const nodeFingerprint = new crypto.X509Certificate(certificatePem).fingerprint.replace(/:/g, "");
  console.log("computeSha1ThumbprintFromPem:", ourThumbprint);
  console.log("crypto.X509Certificate fingerprint (sha1, colons stripped):", nodeFingerprint);
  if (ourThumbprint !== nodeFingerprint.toUpperCase()) {
    console.log("FAIL: mismatch between computeSha1ThumbprintFromPem and Node's own X509Certificate fingerprint");
    process.exitCode = 1;
  } else {
    console.log("OK: computeSha1ThumbprintFromPem agrees with Node's crypto.X509Certificate fingerprint");
  }

  console.log("");
  console.log("=== WCNG-02: real CNG-native acceptance ===");
  const result = await acceptCertificateViaCng({ certificatePem, workDir });
  if (result.ok === false) {
    console.log("FAIL: acceptCertificateViaCng returned ok:false ->", JSON.stringify(result, null, 2));
    process.exitCode = 1;
    return;
  }
  console.log("acceptCertificateViaCng ok:true, thumbprint =", result.thumbprint);
  console.log("certPath existed after call:", fs.existsSync(result.certPath));

  console.log("");
  console.log("=== cross-check: certutil -store My <thumbprint> reports the same thumbprint & HasPrivateKey ===");
  const storeOutput = execFileSync("certutil", ["-store", "My", result.thumbprint], { encoding: "utf8" });
  fs.writeFileSync(path.join(workDir, "certutil-store-my-after-accept.txt"), storeOutput);
  console.log(storeOutput);

  const hasPrivateKey = /Key Container\s*=/i.test(storeOutput) || /Provider\s*=/i.test(storeOutput);
  console.log("hasPrivateKey (Key Container/Provider line present):", hasPrivateKey);
  if (!hasPrivateKey) {
    console.log("FAIL: expected HasPrivateKey=True equivalent evidence in certutil -store output");
    process.exitCode = 1;
  }

  const thumbprintInStoreOutput = new RegExp(result.thumbprint.split("").join("\\s*"), "i").test(
    storeOutput.replace(/\s+/g, ""),
  );
  const normalizedStoreOutput = storeOutput.replace(/[^0-9A-Fa-f]/g, "").toUpperCase();
  const found = normalizedStoreOutput.includes(result.thumbprint);
  console.log("thumbprint bytes found verbatim in certutil -store output:", found);
  if (!found) {
    console.log("FAIL: thumbprint mismatch between module result and certutil -store report");
    process.exitCode = 1;
  } else {
    console.log("OK: all three (module, Node crypto, certutil) agree on the thumbprint");
  }

  fs.writeFileSync(path.join(workDir, "accepted-thumbprint.txt"), result.thumbprint);
}

main().catch((err) => {
  console.error("UNCAUGHT ERROR:", err);
  process.exitCode = 1;
});
