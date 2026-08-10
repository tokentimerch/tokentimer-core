"use strict";

// Real-host verification for two rebind/precedence fixes in
// windows-iis/index.js that the earlier real-host binding/rebind passes
// predate: (A) the newer per-connection sslcert flags (including the
// disableLegacyTls "Set"/"Not Set" vocabulary fix) are read back and
// reapplied across a real delete-then-add rebind, not just the eight
// classic settings; (B) checkSniPrecedenceConflict's concrete-IP shadowing
// detection, not only the two wildcard forms.
//
// Usage: node windows-iis-flag-preservation-and-sni-shadowing-verify.js
//   <workDir> <caConfig> <vmConcreteIp>
//   caConfig example: "ttwinverify\\TokenTimer Test Root CA 2"

const path = require("node:path");
const fs = require("node:fs");
const { execFileSync } = require("node:child_process");

const certStoreRoot = "C:\\TokenTimerAgentTest\\src\\windows-cert-store";
const iisRoot = "C:\\TokenTimerAgentTest\\src\\windows-iis";
const { generateCsrViaCng, acceptCertificateViaCng } = require(path.join(certStoreRoot, "index.js"));
const { deployIisBinding } = require(path.join(iisRoot, "index.js"));

const RUN_CAPTURED_TIMEOUT_MS = 60 * 1000;

function runCaptured(cmd, args) {
  try {
    const stdout = execFileSync(cmd, args, { encoding: "utf8", timeout: RUN_CAPTURED_TIMEOUT_MS, killSignal: "SIGKILL" });
    return { stdout, stderr: "", exitCode: 0 };
  } catch (err) {
    if (err.code === "ETIMEDOUT" || err.signal === "SIGKILL") {
      return { stdout: err.stdout ? err.stdout.toString() : "", stderr: `TIMED OUT after ${RUN_CAPTURED_TIMEOUT_MS}ms running ${cmd} ${args.join(" ")}`, exitCode: null, timedOut: true };
    }
    return { stdout: err.stdout ? err.stdout.toString() : "", stderr: err.stderr ? err.stderr.toString() : String(err.message || err), exitCode: typeof err.status === "number" ? err.status : null };
  }
}

async function issueRealCert({ workDir, caConfig, commonName, basename }) {
  const csrResult = await generateCsrViaCng({ commonName, jobId: basename, workDir });
  if (csrResult.ok === false) {
    throw new Error(`generateCsrViaCng failed for ${commonName}: ${JSON.stringify(csrResult)}`);
  }
  const csrPath = path.join(workDir, `${basename}.csr`);
  fs.writeFileSync(csrPath, csrResult.csrPem, { encoding: "utf8" });

  const cerPath = path.join(workDir, `${basename}.cer`);
  const rspPath = path.join(workDir, `${basename}.rsp`);
  for (const stale of [cerPath, rspPath]) {
    try {
      fs.unlinkSync(stale);
    } catch {
      // fine if absent
    }
  }

  let requestId = null;
  const submit = runCaptured("certreq", ["-f", "-submit", "-config", caConfig, csrPath, cerPath]);
  if (submit.timedOut) throw new Error(`certreq -submit for ${commonName} timed out`);
  const combined = `${submit.stdout}\n${submit.stderr}`;
  const idMatch = combined.match(/RequestId:\s*(\d+)/i);
  if (idMatch) requestId = idMatch[1];

  if (!fs.existsSync(cerPath)) {
    if (!requestId) throw new Error(`certreq -submit produced no cerPath and no RequestId for ${commonName}`);
    const resubmit = runCaptured("certutil", ["-resubmit", requestId]);
    if (resubmit.timedOut) throw new Error(`certutil -resubmit ${requestId} timed out`);
    const retrieve = runCaptured("certreq", ["-f", "-retrieve", "-config", caConfig, requestId, cerPath]);
    if (retrieve.timedOut) throw new Error(`certreq -retrieve ${requestId} timed out`);
  }
  if (!fs.existsSync(cerPath)) throw new Error(`cerPath still missing for ${commonName} after submit/resubmit/retrieve`);

  const certificatePem = fs.readFileSync(cerPath, "utf8");
  const acceptResult = await acceptCertificateViaCng({ certificatePem, workDir });
  if (acceptResult.ok === false) {
    throw new Error(`acceptCertificateViaCng failed for ${commonName}: ${JSON.stringify(acceptResult)}`);
  }
  return { thumbprint: acceptResult.thumbprint, certificatePem, containerName: csrResult.containerName };
}

async function main() {
  const workDir = process.argv[2] || "C:\\TokenTimerAgentTest\\work";
  const caConfig = process.argv[3];
  const vmConcreteIp = process.argv[4];
  if (!caConfig) throw new Error('caConfig is required, e.g. "ttwinverify\\TokenTimer Test Root CA 2"');
  if (!vmConcreteIp) throw new Error("vmConcreteIp is required (this VM's own real, non-loopback IPv4 address)");

  let anyFailure = false;
  const fail = (msg) => {
    console.log("FAIL:", msg);
    anyFailure = true;
  };

  console.log("=== Part A: rebind-parameter preservation for newer per-connection sslcert flags ===");
  const partAPort = 21443;
  const partABinding = { address: "0.0.0.0", port: partAPort, store: "My", site: "Default Web Site" };

  console.log("--- issuing OLD and NEW real CNG certs against the real test CA ---");
  const oldCert = await issueRealCert({ workDir, caConfig, commonName: "wiis07-old.tokentimer-verify.local", basename: "wiis07-old" });
  const newCert = await issueRealCert({ workDir, caConfig, commonName: "wiis07-new.tokentimer-verify.local", basename: "wiis07-new" });
  console.log("OLD thumbprint:", oldCert.thumbprint);
  console.log("NEW thumbprint:", newCert.thumbprint);

  console.log("");
  console.log(`--- binding OLD cert at ipport=0.0.0.0:${partAPort} with explicit newer per-connection flags set ---`);
  const explicitFlagArgs = [
    "http", "delete", "sslcert", `ipport=0.0.0.0:${partAPort}`,
  ];
  runCaptured("netsh", explicitFlagArgs); // best-effort cleanup of any stale prior binding
  const addArgs = [
    "http", "add", "sslcert", `ipport=0.0.0.0:${partAPort}`,
    `certhash=${oldCert.thumbprint}`, `appid={${require("node:crypto").randomUUID()}}`, "certstorename=My",
    "disablehttp2=enable", "disablequic=enable", "disablelegacytls=enable",
    "enabletokenbinding=enable", "logextendedevents=enable", "enablesessionticket=enable", "disablesessionid=enable",
  ];
  const addResult = runCaptured("netsh", addArgs);
  if (addResult.exitCode !== 0) {
    fail(`initial OLD-cert bind with explicit flags failed: ${addResult.stdout} ${addResult.stderr}`);
  } else {
    console.log("OK: OLD cert bound with explicit newer per-connection flags");
  }

  console.log("");
  console.log("--- independent netsh confirmation of the flags BEFORE rebind ---");
  const beforeShow = runCaptured("netsh", ["http", "show", "sslcert", `ipport=0.0.0.0:${partAPort}`]);
  console.log(beforeShow.stdout);
  fs.writeFileSync(path.join(workDir, "wiis07-before-rebind.txt"), beforeShow.stdout, { encoding: "utf8" });
  const beforeChecks = [
    ["Disable HTTP2", "Set"],
    ["Disable QUIC", "Set"],
    ["Disable Legacy TLS Versions", "Set"],
    ["Enable Token Binding", "Set"],
    ["Log Extended Events", "Set"],
    ["Enable Session Ticket", "Set"],
    ["Disable Session ID", "Set"],
  ];
  for (const [label, expected] of beforeChecks) {
    const re = new RegExp(`${label}\\s*:\\s*${expected}`, "i");
    if (!re.test(beforeShow.stdout)) {
      fail(`expected "${label}: ${expected}" in pre-rebind netsh output, not found`);
    }
  }
  console.log("pre-rebind flag checks done.");

  console.log("");
  console.log("--- real rebind via deployIisBinding (queries current binding, preserves params, delete+add to NEW cert) ---");
  const deployResult = await deployIisBinding({ binding: partABinding, certificatePem: newCert.certificatePem });
  console.log("deployIisBinding result:", JSON.stringify(deployResult, null, 2));
  if (deployResult.ok !== true) {
    fail(`deployIisBinding for Part A rebind did not return ok:true: ${JSON.stringify(deployResult)}`);
  } else if (deployResult.boundThumbprint.toUpperCase() !== newCert.thumbprint.toUpperCase()) {
    fail(`deployIisBinding bound the wrong thumbprint: expected ${newCert.thumbprint}, got ${deployResult.boundThumbprint}`);
  } else {
    console.log("OK: real rebind to NEW cert succeeded and TLS-verified");
  }

  console.log("");
  console.log("--- independent netsh confirmation of the flags AFTER rebind (the real-host proof this driver exists to produce) ---");
  const afterShow = runCaptured("netsh", ["http", "show", "sslcert", `ipport=0.0.0.0:${partAPort}`]);
  console.log(afterShow.stdout);
  fs.writeFileSync(path.join(workDir, "wiis07-after-rebind.txt"), afterShow.stdout, { encoding: "utf8" });
  if (!afterShow.stdout.toUpperCase().includes(newCert.thumbprint.toUpperCase())) {
    fail("after rebind, netsh does not report the NEW cert's thumbprint");
  }
  for (const [label, expected] of beforeChecks) {
    const re = new RegExp(`${label}\\s*:\\s*${expected}`, "i");
    if (!re.test(afterShow.stdout)) {
      fail(`after rebind, expected "${label}: ${expected}" to have survived, but it did not (silently reset to netsh default)`);
    } else {
      console.log(`OK: "${label}: ${expected}" survived the real rebind`);
    }
  }

  console.log("");
  console.log("=== Part B: concrete-IP SNI-precedence shadowing detection, against real netsh output ===");
  const partBPort = 21444;
  const sniHost = "wiis07-shadow-test.tokentimer-verify.local";

  console.log(`--- binding a NON-SNI cert at the concrete IP ipport=${vmConcreteIp}:${partBPort} ---`);
  runCaptured("netsh", ["http", "delete", "sslcert", `ipport=${vmConcreteIp}:${partBPort}`]);
  const concreteBindArgs = [
    "http", "add", "sslcert", `ipport=${vmConcreteIp}:${partBPort}`,
    `certhash=${oldCert.thumbprint}`, `appid={${require("node:crypto").randomUUID()}}`, "certstorename=My",
  ];
  const concreteBindResult = runCaptured("netsh", concreteBindArgs);
  if (concreteBindResult.exitCode !== 0) {
    fail(`could not bind concrete-IP shadow certificate: ${concreteBindResult.stdout} ${concreteBindResult.stderr}`);
  } else {
    console.log("OK: concrete-IP non-SNI binding created");
  }

  console.log("");
  console.log("--- independent netsh confirmation the concrete-IP binding is real, not assumed ---");
  const concreteShow = runCaptured("netsh", ["http", "show", "sslcert", `ipport=${vmConcreteIp}:${partBPort}`]);
  console.log(concreteShow.stdout);
  fs.writeFileSync(path.join(workDir, "wiis07-concrete-ip-binding.txt"), concreteShow.stdout, { encoding: "utf8" });
  if (!concreteShow.stdout.toUpperCase().includes(oldCert.thumbprint.toUpperCase())) {
    fail("independent netsh call does not confirm the concrete-IP binding actually exists");
  }

  console.log("");
  console.log(`--- deploying an SNI binding (hostnameport=${sniHost}:${partBPort}) on the SAME port via deployIisBinding ---`);
  const sniBinding = { address: "0.0.0.0", port: partBPort, sniHost, store: "My", site: "Default Web Site" };
  const sniDeployResult = await deployIisBinding({ binding: sniBinding, certificatePem: newCert.certificatePem });
  console.log("deployIisBinding (SNI) result:", JSON.stringify(sniDeployResult, null, 2));
  if (sniDeployResult.ok !== true) {
    fail(`SNI-binding deploy for Part B did not return ok:true: ${JSON.stringify(sniDeployResult)}`);
  } else if (typeof sniDeployResult.precedenceWarning !== "string" || !sniDeployResult.precedenceWarning.includes(vmConcreteIp)) {
    fail(`expected a precedenceWarning mentioning the real concrete IP ${vmConcreteIp}, got: ${JSON.stringify(sniDeployResult.precedenceWarning)}`);
  } else {
    console.log("OK: checkSniPrecedenceConflict correctly detected the real concrete-IP shadowing binding");
    console.log("precedenceWarning:", sniDeployResult.precedenceWarning);
  }

  console.log("");
  console.log("--- negative control: an unrelated port with no concrete-IP shadow should carry no precedenceWarning ---");
  const controlPort = 21445;
  const controlSniHost = "wiis07-no-shadow.tokentimer-verify.local";
  runCaptured("netsh", ["http", "delete", "sslcert", `hostnameport=${controlSniHost}:${controlPort}`]);
  const controlBinding = { address: "0.0.0.0", port: controlPort, sniHost: controlSniHost, store: "My", site: "Default Web Site" };
  const controlResult = await deployIisBinding({ binding: controlBinding, certificatePem: newCert.certificatePem });
  console.log("deployIisBinding (control) result:", JSON.stringify(controlResult, null, 2));
  if (controlResult.ok !== true) {
    fail(`control SNI-binding deploy did not return ok:true: ${JSON.stringify(controlResult)}`);
  } else if (controlResult.precedenceWarning !== undefined) {
    fail(`control binding (no concrete-IP shadow on this port) unexpectedly carries a precedenceWarning: ${controlResult.precedenceWarning}`);
  } else {
    console.log("OK: no false-positive precedenceWarning when there is genuinely no shadowing binding");
  }

  console.log("");
  console.log("--- cleanup: remove all test bindings created by this driver ---");
  runCaptured("netsh", ["http", "delete", "sslcert", `ipport=0.0.0.0:${partAPort}`]);
  runCaptured("netsh", ["http", "delete", "sslcert", `ipport=${vmConcreteIp}:${partBPort}`]);
  runCaptured("netsh", ["http", "delete", "sslcert", `hostnameport=${sniHost}:${partBPort}`]);
  runCaptured("netsh", ["http", "delete", "sslcert", `hostnameport=${controlSniHost}:${controlPort}`]);

  console.log("");
  console.log("driver complete.", anyFailure ? "FAILURES ABOVE." : "ALL CHECKS PASSED.");
  if (anyFailure) process.exitCode = 1;
}

main().catch((err) => {
  console.error("UNCAUGHT ERROR:", err);
  process.exitCode = 1;
});
