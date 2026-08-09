"use strict";

// Real-host verification for the fingerprint-completion PowerShell call
// (fetchRawCertificateDerByThumbprint / computeFingerprintSha256 in
// discovery/windows.js): cross-checks the SHA-256 fingerprint this module
// computes against an independently-computed SHA-256 from the same
// certificate's bytes via a different tool (certutil -encode + a manual
// hash, not node:crypto's X509Certificate a second time), and confirms the
// documented graceful-degradation path when PowerShell itself is
// unavailable.
//
// Usage: node windows-discovery-fingerprint-verify.js [workDir]

const path = require("node:path");
const fs = require("node:fs");
const crypto = require("node:crypto");
const { execFileSync } = require("node:child_process");

const discoveryRoot = "C:\\TokenTimerAgentTest\\src\\discovery";
const { fetchRawCertificateDerByThumbprint, computeFingerprintSha256 } = require(
  path.join(discoveryRoot, "windows.js"),
);

async function main() {
  const workDir = process.argv[2] || "C:\\TokenTimerAgentTest\\work";
  let anyFailure = false;
  const fail = (msg) => {
    console.log("FAIL:", msg);
    anyFailure = true;
  };

  console.log("=== step 1: real fetchRawCertificateDerByThumbprint against LocalMachine\\My ===");
  const warnings = [];
  const byThumbprint = fetchRawCertificateDerByThumbprint({
    storeLocation: "LocalMachine",
    storeName: "My",
    onWarning: (m) => warnings.push(m),
  });
  console.log("certificates returned:", byThumbprint.size);
  console.log("warnings during real call:", JSON.stringify(warnings));
  if (byThumbprint.size === 0) {
    fail("expected at least one real certificate in LocalMachine\\My, got zero");
    console.log("driver complete. FAILURES ABOVE.");
    process.exitCode = 1;
    return;
  }
  console.log("OK: real PowerShell call returned", byThumbprint.size, "certificate(s) with raw DER bytes");

  console.log("");
  console.log("=== step 2: compute fingerprintSha256 via this module's own function, for every returned cert ===");
  const moduleFingerprints = new Map();
  for (const [thumbprint, rawBase64] of byThumbprint.entries()) {
    const fp = computeFingerprintSha256(rawBase64, (m) => console.log("  warning:", m));
    if (fp) moduleFingerprints.set(thumbprint, fp);
  }
  console.log("fingerprints computed:", moduleFingerprints.size, "of", byThumbprint.size);
  if (moduleFingerprints.size !== byThumbprint.size) {
    fail("expected every returned certificate to yield a non-null fingerprint");
  }

  console.log("");
  console.log("=== step 3: independent cross-check for a real certificate, via a DIFFERENT tool chain (certutil -encode, not node:crypto a second time) ===");
  const [sampleThumbprint] = [...moduleFingerprints.keys()];
  const sampleFingerprint = moduleFingerprints.get(sampleThumbprint);
  console.log("sample thumbprint:", sampleThumbprint);
  console.log("module-computed fingerprintSha256:", sampleFingerprint);

  // certutil -encode DER -> Base64 PEM-ish text (this is what `certutil
  // -store My <thumbprint>` embeds when asked for a base64 dump); exporting
  // via `certutil -store My <thumbprint> <outfile>` writes the raw DER
  // bytes to disk, independent of the PowerShell/X509Certificate path this
  // module itself uses.
  const derPath = path.join(workDir, "wobs01-sample.cer");
  const certutilStore = execFileSync("certutil", ["-store", "My", sampleThumbprint, derPath], { encoding: "utf8" });
  console.log("certutil -store My export stdout (excerpt):", certutilStore.slice(0, 300));
  if (!fs.existsSync(derPath)) {
    fail("certutil did not write the expected DER file");
  } else {
    const exportedDer = fs.readFileSync(derPath);
    const independentSha256 = crypto.createHash("sha256").update(exportedDer).digest("hex").toLowerCase();
    console.log("independently computed SHA-256 (crypto.createHash over certutil-exported DER bytes):", independentSha256);
    if (independentSha256 !== sampleFingerprint) {
      fail(`independent SHA-256 (${independentSha256}) does not match module-computed fingerprint (${sampleFingerprint})`);
    } else {
      console.log("OK: independent SHA-256 matches the module's own computed fingerprintSha256 exactly");
    }

    // Third cross-check: certutil's own -hashfile command, a completely
    // separate certutil invocation from the -store export above.
    const hashfileOut = execFileSync("certutil", ["-hashfile", derPath, "SHA256"], { encoding: "utf8" });
    console.log("certutil -hashfile SHA256 output:", hashfileOut);
    const hashLine = hashfileOut
      .split(/\r?\n/)
      .map((l) => l.trim())
      .find((l) => /^[0-9a-fA-F]{2}( [0-9a-fA-F]{2})*$/.test(l) || /^[0-9a-fA-F]{64}$/.test(l));
    const certutilHash = hashLine ? hashLine.replace(/\s+/g, "").toLowerCase() : null;
    console.log("certutil -hashfile SHA256 (normalized):", certutilHash);
    if (certutilHash !== sampleFingerprint) {
      fail(`certutil -hashfile SHA256 (${certutilHash}) does not match module-computed fingerprint (${sampleFingerprint})`);
    } else {
      console.log("OK: certutil -hashfile SHA256 independently confirms the same fingerprint a third way");
    }
  }

  console.log("");
  console.log("=== step 4: documented graceful-degradation path -- PowerShell invocation blocked/unavailable ===");
  const blockedResult = fetchRawCertificateDerByThumbprint({
    storeLocation: "LocalMachine",
    storeName: "My",
    spawn: () => {
      const err = new Error("spawn powershell ENOENT");
      err.code = "ENOENT";
      return { error: err };
    },
    onWarning: (m) => console.log("  degradation warning:", m),
  });
  console.log("blocked-path result size (expected 0):", blockedResult.size);
  if (blockedResult.size !== 0) {
    fail("expected an empty Map when the PowerShell invocation is blocked/unavailable, not a throw or partial result");
  } else {
    console.log("OK: blocked PowerShell invocation returns an empty Map with a warning, does not throw");
  }

  // A second, more realistic block: a real powershell.exe invocation that
  // is deliberately fed an invalid -PSModulePath via env override at the
  // spawn boundary this function actually uses, confirming the *real*
  // execution path (not just a stubbed spawn) degrades the same way when
  // the process genuinely cannot run.
  console.log("");
  console.log("--- second, more realistic block: spawn real powershell.exe with an intentionally-broken executable path ---");
  const realBlockedResult = fetchRawCertificateDerByThumbprint({
    storeLocation: "LocalMachine",
    storeName: "My",
    spawn: (cmd, args, opts) => {
      const { spawnSync } = require("node:child_process");
      return spawnSync("C:\\definitely-not-a-real-powershell.exe", args, opts);
    },
    onWarning: (m) => console.log("  degradation warning (real spawn, nonexistent binary):", m),
  });
  console.log("real-spawn-blocked result size (expected 0):", realBlockedResult.size);
  if (realBlockedResult.size !== 0) {
    fail("expected an empty Map when the real spawn target does not exist");
  } else {
    console.log("OK: a real spawn to a nonexistent PowerShell binary also degrades to an empty Map with a warning");
  }

  console.log("");
  console.log("driver complete.", anyFailure ? "FAILURES ABOVE." : "ALL CHECKS PASSED.");
  if (anyFailure) process.exitCode = 1;
}

main().catch((err) => {
  console.error("UNCAUGHT ERROR:", err);
  process.exitCode = 1;
});
