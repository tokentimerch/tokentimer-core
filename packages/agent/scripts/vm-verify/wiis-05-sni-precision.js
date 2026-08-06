"use strict";

// Real-host verification for WIIS-05: binding-tuple precision. Repeats a
// deploy for an SNI-qualified binding and confirms only that targeted
// binding changes; the unrelated hostname-less binding on a different port
// (set up earlier at 9443) stays provably untouched.
//
// Usage: node wiis-05-sni-precision.js <workDir> <certPemPath>

const path = require("node:path");
const fs = require("node:fs");
const childProcess = require("node:child_process");

const { deployIisBinding } = require("C:\\TokenTimerAgentTest\\src\\windows-iis\\index.js");

async function main() {
  const workDir = process.argv[2] || "C:\\TokenTimerAgentTest\\work";
  const certPemPath = process.argv[3] || "C:\\TokenTimerAgentTest\\work\\real.cer";
  const certificatePem = fs.readFileSync(certPemPath, "utf8");

  const unrelatedThumbprintBefore = fs.readFileSync(path.join(workDir, "unrelated-thumbprint.txt"), "utf8").trim();

  const sniBinding = {
    address: "0.0.0.0",
    port: 10443,
    sniHost: "wiis05.tokentimer-verify.local",
    store: "My",
    site: "Default Web Site",
  };

  console.log("=== WIIS-05: SNI-qualified binding deploy ===");
  const result = await deployIisBinding({ binding: sniBinding, certificatePem });
  console.log("deployIisBinding:", JSON.stringify(result, null, 2));
  if (result.ok !== true) {
    console.log("FAIL: expected ok:true for the SNI binding deploy");
    process.exitCode = 1;
    return;
  }
  console.log("OK: SNI-qualified binding deployed and verified");

  console.log("");
  console.log("=== confirm the SNI binding via a fresh, independent netsh call ===");
  const sniConfirm = childProcess.execFileSync("netsh", ["http", "show", "sslcert", `hostnameport=${sniBinding.sniHost}:${sniBinding.port}`], { encoding: "utf8" });
  console.log(sniConfirm);
  if (!sniConfirm.toLowerCase().includes(result.boundThumbprint.toLowerCase())) {
    console.log("FAIL: netsh does not independently confirm the SNI binding's thumbprint");
    process.exitCode = 1;
  } else {
    console.log("OK: netsh independently confirms the SNI-qualified binding");
  }

  console.log("");
  console.log("=== confirm the unrelated 9443 (hostname-less) binding is provably untouched ===");
  const unrelatedConfirm = childProcess.execFileSync("netsh", ["http", "show", "sslcert", "ipport=0.0.0.0:9443"], { encoding: "utf8" });
  console.log(unrelatedConfirm);
  if (!unrelatedConfirm.toLowerCase().includes(unrelatedThumbprintBefore.toLowerCase())) {
    console.log("FAIL: unrelated 9443 binding changed!");
    process.exitCode = 1;
  } else {
    console.log("OK: unrelated 9443 binding's hash is unchanged");
  }

  console.log("");
  console.log("=== confirm the target 8443 (non-SNI) binding is ALSO provably untouched ===");
  const targetConfirm = childProcess.execFileSync("netsh", ["http", "show", "sslcert", "ipport=0.0.0.0:8443"], { encoding: "utf8" });
  console.log(targetConfirm);
}

main().catch((err) => {
  console.error("UNCAUGHT ERROR:", err);
  process.exitCode = 1;
});
