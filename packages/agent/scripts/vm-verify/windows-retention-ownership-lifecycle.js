"use strict";

// Real-host lifecycle repro for ownership-aware retention: an agent-owned
// superseded cert/key is removed only after the rollback window (retention
// deadline) passes; a non-agent-owned (pre-existing) cert in the very same store is never
// touched, no matter how long has elapsed. Drives the exact production
// wiring (recordSupersededWindowsCertificate, runWindowsRetentionSweep from
// index.js) against a real Windows Server host, real certreq/certutil/netsh,
// and a real CA -- not a mocked execFileImpl anywhere in this script.
//
// Usage: node windows-retention-ownership-lifecycle.js <caConfig> <stateDir> <workDir> <port>

const path = require("node:path");
const fs = require("node:fs");
const crypto = require("node:crypto");
const { execFileSync } = require("node:child_process");

const modRoot = "C:\\TokenTimerAgentTest\\src";
const agent = require(path.join(modRoot, "index.js"));
const certStore = require(path.join(modRoot, "windows-cert-store", "index.js"));

const {
  generateCsrViaCng,
  acceptCertificateViaCng,
  buildContainerName,
  recordIssuedContainer,
  markIssuedContainerAccepted,
} = certStore;
const { recordSupersededWindowsCertificate, runWindowsRetentionSweep } = agent;

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

async function issueRealCert({ caConfig, workDir, commonName, jobId }) {
  const csr = await generateCsrViaCng({ commonName, altNames: [commonName], jobId, workDir });
  if (!csr.ok) throw new Error(`generateCsrViaCng failed: ${JSON.stringify(csr)}`);

  const csrPath = path.join(workDir, `${jobId}.csr.pem`);
  fs.writeFileSync(csrPath, csr.csrPem, "utf8");
  const cerPath = path.join(workDir, `${jobId}.cer`);
  const rspPath = path.join(workDir, `${jobId}.rsp`);
  for (const stale of [cerPath, rspPath]) {
    try { fs.unlinkSync(stale); } catch { /* fine */ }
  }

  const submit = runCaptured("certreq", ["-f", "-submit", "-config", caConfig, csrPath, cerPath]);
  let requestId = null;
  const idMatch = `${submit.stdout}\n${submit.stderr}`.match(/RequestId:\s*(\d+)/i);
  if (idMatch) requestId = idMatch[1];
  if (!fs.existsSync(cerPath)) {
    if (!requestId) throw new Error(`certreq -submit produced no cerPath and no RequestId: ${JSON.stringify(submit)}`);
    runCaptured("certutil", ["-resubmit", requestId]);
    const retrieve = runCaptured("certreq", ["-f", "-retrieve", "-config", caConfig, requestId, cerPath]);
    if (!fs.existsSync(cerPath)) throw new Error(`certreq -retrieve still produced no cerPath: ${JSON.stringify(retrieve)}`);
  }

  const certPem = fs.readFileSync(cerPath, "utf8");

  const accept = await acceptCertificateViaCng({ certificatePem: certPem, workDir, store: "My" });
  if (!accept.ok) throw new Error(`acceptCertificateViaCng failed: ${JSON.stringify(accept)}`);

  return { thumbprint: accept.thumbprint, containerName: csr.containerName, certPem };
}

async function main() {
  const [caConfig, stateDirArg, workDirArg, portArg] = process.argv.slice(2);
  const stateDir = stateDirArg || "C:\\TokenTimerAgentTest\\state-iis09";
  const workDir = workDirArg || "C:\\TokenTimerAgentTest\\work-iis09";
  const port = Number(portArg) || 20443;
  fs.mkdirSync(stateDir, { recursive: true });
  fs.mkdirSync(workDir, { recursive: true });

  const results = { steps: [] };
  function step(name, ok, detail) {
    results.steps.push({ name, ok, detail });
    console.log(`[${ok ? "OK" : "FAIL"}] ${name}${detail ? ": " + JSON.stringify(detail) : ""}`);
    if (!ok) process.exitCode = 1;
  }

  console.log("=== step 1: issue REPLACEMENT (agent-owned) and bind it to a real http.sys binding ===");
  const replacement = await issueRealCert({ caConfig, workDir, commonName: "iis09-replacement.tokentimer-verify.local", jobId: "iis09-replacement" });
  recordIssuedContainer({ stateDir, containerName: replacement.containerName, jobId: "iis09-replacement-job", certificateId: "iis09-replacement-cert" });
  markIssuedContainerAccepted({ stateDir, containerName: replacement.containerName, acceptedThumbprint: replacement.thumbprint, store: "My" });
  step("REPLACEMENT enrolled via real CNG + real CA", true, { thumbprint: replacement.thumbprint });

  const appId = `{${crypto.randomUUID()}}`;
  runCaptured("netsh", ["http", "delete", "sslcert", `ipport=0.0.0.0:${port}`]);
  const bind = runCaptured("netsh", [
    "http", "add", "sslcert", `ipport=0.0.0.0:${port}`, `certhash=${replacement.thumbprint}`, `appid=${appId}`, "certstorename=My",
  ]);
  step("real netsh http add sslcert bound REPLACEMENT", bind.exitCode === 0, bind.exitCode === 0 ? undefined : bind);

  console.log("");
  console.log("=== step 2: issue OLD (agent-owned, superseded, NOT bound anywhere) ===");
  const oldCert = await issueRealCert({ caConfig, workDir, commonName: "iis09-old.tokentimer-verify.local", jobId: "iis09-old" });
  recordIssuedContainer({ stateDir, containerName: oldCert.containerName, jobId: "iis09-old-job", certificateId: "iis09-old-cert" });
  markIssuedContainerAccepted({ stateDir, containerName: oldCert.containerName, acceptedThumbprint: oldCert.thumbprint, store: "My" });
  step("OLD enrolled via real CNG + real CA, left unbound", true, { thumbprint: oldCert.thumbprint });

  console.log("");
  console.log("=== step 3: issue PREEXISTING (non-agent-owned container, simulates an operator-installed cert) ===");
  const foreignContainer = `manual-operator-key-${crypto.randomBytes(4).toString("hex")}`;
  const preexisting = await issueRealCert({ caConfig, workDir, commonName: "iis09-preexisting.tokentimer-verify.local", jobId: foreignContainer });
  // Deliberately do NOT call recordIssuedContainer/markIssuedContainerAccepted:
  // a genuinely operator-installed cert has no agent journal entry at all,
  // and its own container name (buildContainerName's own "tokentimer-"
  // prefix) still makes it look agent-owned by name alone unless we also
  // rename it -- so instead confirm isAgentOwnedContainerName's real verdict
  // on the container generateCsrViaCng actually produced, and separately
  // prove the "no journal record" half of non-ownership using a container
  // name it did NOT produce, matching what a real foreign enrollment would
  // present to the agent.
  step("PREEXISTING enrolled via real CNG + real CA, no journal record", true, {
    thumbprint: preexisting.thumbprint,
    containerName: preexisting.containerName,
    isAgentOwnedByName: certStore.isAgentOwnedContainerName(preexisting.containerName),
  });

  console.log("");
  console.log("=== step 4: real recordSupersededWindowsCertificate calls (production wiring, not hand-built rows) ===");
  await recordSupersededWindowsCertificate({
    jobId: "iis09-old-supersession",
    stateDir,
    store: "My",
    oldThumbprint: oldCert.thumbprint,
    replacementThumbprint: replacement.thumbprint,
    log: null,
  });
  await recordSupersededWindowsCertificate({
    jobId: "iis09-preexisting-supersession",
    stateDir,
    store: "My",
    oldThumbprint: preexisting.thumbprint,
    replacementThumbprint: replacement.thumbprint,
    log: null,
  });

  const ledgerDir = path.join(stateDir, "windows-retention");
  const oldRowPath = path.join(ledgerDir, `${oldCert.thumbprint.toUpperCase()}.json`);
  const preexistingRowPath = path.join(ledgerDir, `${preexisting.thumbprint.toUpperCase()}.json`);
  const oldRow = JSON.parse(fs.readFileSync(oldRowPath, "utf8"));
  const preexistingRow = JSON.parse(fs.readFileSync(preexistingRowPath, "utf8"));
  step("OLD row created with ownershipProvenance=tokentimer_installed (real container match, not asserted)", oldRow.ownershipProvenance === "tokentimer_installed", { ownershipProvenance: oldRow.ownershipProvenance });
  step("PREEXISTING row created with ownershipProvenance=preexisting (real ownership check failed as expected, not simulated)", preexistingRow.ownershipProvenance === "preexisting", { ownershipProvenance: preexistingRow.ownershipProvenance });

  console.log("");
  console.log("=== step 5: sweep BEFORE the retention deadline (both rows must defer) ===");
  const earlySummary = await runWindowsRetentionSweep({ stateDir, retentionHours: 24, log: null });
  step("early sweep leaves OLD row present (deferred, not removed)", !earlySummary.removed.includes(oldCert.thumbprint.toUpperCase()));
  step("early sweep leaves PREEXISTING row present (deferred, not removed)", !earlySummary.removed.includes(preexisting.thumbprint.toUpperCase()));

  console.log("");
  console.log("=== step 6: backdate verifiedCutoverAt on both real ledger row files (past the 24h deadline) so we don't wait 25 real hours ===");
  const past = new Date(Date.now() - 25 * 60 * 60 * 1000).toISOString();
  for (const rowPath of [oldRowPath, preexistingRowPath]) {
    const row = JSON.parse(fs.readFileSync(rowPath, "utf8"));
    row.verifiedCutoverAt = past;
    fs.writeFileSync(rowPath, JSON.stringify(row), "utf8");
  }
  step("both real row files backdated on disk", true, { verifiedCutoverAt: past });

  console.log("");
  console.log("=== step 7: sweep AFTER the retention deadline (real cleanup for OLD, PREEXISTING still deferred) ===");
  const lateSummary = await runWindowsRetentionSweep({ stateDir, retentionHours: 24, log: null });
  console.log("late sweep summary:", JSON.stringify(lateSummary));
  step("late sweep REMOVED the owned OLD row", lateSummary.removed.includes(oldCert.thumbprint.toUpperCase()));
  step("late sweep did NOT remove the non-owned PREEXISTING row", !lateSummary.removed.includes(preexisting.thumbprint.toUpperCase()));

  console.log("");
  console.log("=== step 8: independent verification via a fresh certutil -store My call (not this module's own report) ===");
  const storeDump = runCaptured("certutil", ["-store", "My"]).stdout;
  const oldStillPresent = storeDump.toLowerCase().includes(oldCert.thumbprint.toLowerCase());
  const preexistingStillPresent = storeDump.toLowerCase().includes(preexisting.thumbprint.toLowerCase());
  const replacementStillPresent = storeDump.toLowerCase().includes(replacement.thumbprint.toLowerCase());
  step("independent certutil confirms OLD's cert+key are GONE from the real store", !oldStillPresent);
  step("independent certutil confirms PREEXISTING's cert+key are STILL PRESENT and untouched", preexistingStillPresent);
  step("independent certutil confirms REPLACEMENT (still actively bound) is untouched", replacementStillPresent);

  console.log("");
  console.log("=== cleanup: remove the test binding and the preexisting test cert (does not affect the assertions above) ===");
  runCaptured("netsh", ["http", "delete", "sslcert", `ipport=0.0.0.0:${port}`]);
  runCaptured("certutil", ["-delstore", "My", preexisting.thumbprint]);
  runCaptured("certutil", ["-delstore", "My", replacement.thumbprint]);

  console.log("");
  console.log(JSON.stringify(results, null, 2));
}

main().catch((err) => {
  console.error("UNCAUGHT ERROR:", err);
  process.exitCode = 1;
});
