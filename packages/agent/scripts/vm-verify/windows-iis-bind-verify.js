"use strict";

// Real-host verification for a real binding query, real bind/rebind, full
// deploy orchestration with real TLS verification, and no blanket reset
// (via a command-audit wrapper).
//
// Usage: node windows-iis-bind-verify.js <workDir> <newCertPemPath>

const path = require("node:path");
const fs = require("node:fs");
const childProcess = require("node:child_process");

const iisMod = require("C:\\TokenTimerAgentTest\\src\\windows-iis\\index.js");
const { queryCurrentBinding, deployIisBinding } = iisMod;

const commandAudit = [];
function auditedExecFile(file, args, opts, cb) {
  commandAudit.push([file, ...args].join(" "));
  return childProcess.execFile(file, args, opts, cb);
}

async function main() {
  const workDir = process.argv[2] || "C:\\TokenTimerAgentTest\\work";
  const newCertPemPath = process.argv[3] || "C:\\TokenTimerAgentTest\\work\\real.cer";
  const certificatePem = fs.readFileSync(newCertPemPath, "utf8");
  const oldThumbprint = fs.readFileSync(path.join(workDir, "old-thumbprint.txt"), "utf8").trim();

  const binding = {
    address: "0.0.0.0",
    port: 8443,
    store: "My",
    site: "Default Web Site",
  };

  console.log("=== real binding query against hand-created netsh entry ===");
  const queryResult = await queryCurrentBinding({ binding, execFileImpl: auditedExecFile });
  console.log("queryCurrentBinding:", JSON.stringify(queryResult));
  if (!queryResult.ok || queryResult.thumbprint !== oldThumbprint.toUpperCase()) {
    console.log(`FAIL: expected thumbprint ${oldThumbprint.toUpperCase()}, got`, queryResult);
    process.exitCode = 1;
    return;
  }
  console.log("OK: queryCurrentBinding matches the hand-created netsh entry");

  console.log("");
  console.log("=== real deploy orchestration (query -> bind -> real TLS verify) ===");
  const deployResult = await deployIisBinding({
    binding,
    certificatePem,
    execFileImpl: auditedExecFile,
  });
  console.log("deployIisBinding:", JSON.stringify(deployResult, null, 2));
  fs.writeFileSync(path.join(workDir, "iis-bind-verify-result.json"), JSON.stringify(deployResult, null, 2));

  if (deployResult.ok !== true) {
    console.log("FAIL: deployIisBinding did not report ok:true");
    process.exitCode = 1;
    return;
  }
  if (deployResult.outgoingThumbprint !== oldThumbprint.toUpperCase()) {
    console.log("FAIL: outgoingThumbprint did not match the pre-existing binding");
    process.exitCode = 1;
  } else {
    console.log("OK: outgoingThumbprint correctly reports the old thumbprint");
  }
  console.log("verifiedAt (real TLS handshake target):", JSON.stringify(deployResult.verifiedAt));

  console.log("");
  console.log("=== independent confirmation via a fresh netsh call (not the module's own report) ===");
  const confirm = childProcess.execFileSync("netsh", ["http", "show", "sslcert", "ipport=0.0.0.0:8443"], { encoding: "utf8" });
  fs.writeFileSync(path.join(workDir, "wiis-confirm-after-deploy.txt"), confirm);
  console.log(confirm.includes(deployResult.boundThumbprint.toLowerCase()) ? "OK: netsh independently confirms the new binding" : "FAIL: netsh does not show the expected new thumbprint");

  console.log("");
  console.log("=== command/process audit -- no iisreset or blanket reload ===");
  console.log(commandAudit.join("\n"));
  fs.writeFileSync(path.join(workDir, "wiis-command-audit.txt"), commandAudit.join("\n"));
  const hasIisReset = commandAudit.some((c) => /iisreset/i.test(c));
  if (hasIisReset) {
    console.log("FAIL: an iisreset (or similarly named) command was issued");
    process.exitCode = 1;
  } else {
    console.log("OK: no iisreset/blanket-reload command appears anywhere in the executed command list");
  }
}

main().catch((err) => {
  console.error("UNCAUGHT ERROR:", err);
  process.exitCode = 1;
});
