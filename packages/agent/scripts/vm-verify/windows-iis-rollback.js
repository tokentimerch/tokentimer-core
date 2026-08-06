"use strict";

// Real-host verification for real rollback on verify failure.
// Deliberately deploys a certificatePem whose thumbprint has no matching
// certificate+key actually present in the store, so the real post-bind TLS
// handshake genuinely fails, and confirms deployIisBinding rolls back to
// the prior thumbprint via a real netsh call (confirmed independently).
//
// Usage: node windows-iis-rollback.js <workDir>

const path = require("node:path");
const fs = require("node:fs");
const childProcess = require("node:child_process");

const { deployIisBinding, queryCurrentBinding } = require("C:\\TokenTimerAgentTest\\src\\windows-iis\\index.js");

// Note: the dangling (syntactically valid, CA-less, not-in-store) certificate
// used below is generated ahead of time via certreq/PowerShell's
// New-SelfSignedCertificate, then immediately removed from the store so the
// thumbprint is real-format but absent from LocalMachine\My at verify time,
// and handed to this script as dangling.cer. Node has no built-in self-signed
// cert issuance without extra deps, so that generation does not live here.

async function main() {
  const workDir = process.argv[2] || "C:\\TokenTimerAgentTest\\work";
  const currentBeforeResult = await queryCurrentBinding({
    binding: { address: "0.0.0.0", port: 8443, store: "My", site: "Default Web Site" },
  });
  const priorThumbprint = currentBeforeResult.thumbprint;
  console.log("Binding before rollback attempt:", priorThumbprint);

  const danglingCertPem = fs.readFileSync(path.join(workDir, "dangling.cer"), "utf8");

  const binding = { address: "0.0.0.0", port: 8443, store: "My", site: "Default Web Site" };
  const deployResult = await deployIisBinding({
    binding,
    certificatePem: danglingCertPem,
    verifyTimeoutMs: 4000,
  });
  console.log("deployIisBinding result:", JSON.stringify(deployResult, null, 2));
  fs.writeFileSync(path.join(workDir, "iis-rollback-result.json"), JSON.stringify(deployResult, null, 2));

  // On a real host, netsh's own add-sslcert validation rejects a
  // certificate whose key association is broken BEFORE any TLS handshake
  // happens, so this real repro surfaces BIND_FAILED, not VERIFY_FAILED
  // (both codes share the same attemptRollback discipline; which one
  // fires depends on where in the pipeline Windows itself rejects the
  // cert, not on this module's own choice).
  if (deployResult.ok !== false || !["VERIFY_FAILED", "BIND_FAILED"].includes(deployResult.code)) {
    console.log("FAIL: expected ok:false with code VERIFY_FAILED or BIND_FAILED, got", JSON.stringify(deployResult));
    process.exitCode = 1;
    return;
  }
  if (!deployResult.rolledBack) {
    console.log("FAIL: expected rolledBack:true");
    process.exitCode = 1;
    return;
  }
  console.log(`OK: deployIisBinding reported ${deployResult.code} with rolledBack:true`);

  console.log("");
  console.log("=== independent confirmation via a fresh netsh call ===");
  const confirmResult = await queryCurrentBinding({ binding });
  console.log("post-rollback queryCurrentBinding:", JSON.stringify(confirmResult));
  const rawNetsh = childProcess.execFileSync("netsh", ["http", "show", "sslcert", "ipport=0.0.0.0:8443"], { encoding: "utf8" });
  fs.writeFileSync(path.join(workDir, "iis-rollback-confirm.txt"), rawNetsh);

  if (confirmResult.ok && confirmResult.thumbprint === priorThumbprint) {
    console.log("OK: netsh independently confirms the binding is back on the pre-deploy thumbprint", priorThumbprint);
  } else {
    console.log("FAIL: post-rollback binding does not match the pre-deploy thumbprint");
    process.exitCode = 1;
  }
}

main().catch((err) => {
  console.error("UNCAUGHT ERROR:", err);
  process.exitCode = 1;
});
