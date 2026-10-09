"use strict";

// Real-host regression for the shared CNG key path: explicit -machine on
// certreq -new and -accept, Silent = TRUE, and KeyUsage chosen per algorithm,
// end to end against a real enterprise CA. Also checks enrollment-named
// containers and records what certreq does when asked for a second key under
// a container name that already exists.
//
// Run as LocalSystem (the service identity), never in an interactive session:
//   node windows-cng-key-path-verify.js <workDir> <caConfig> <rsaTemplate> [ecTemplate]
//   caConfig example: "ca01.example.internal\\Example Issuing CA"
// Templates must auto-issue to this computer account; ecTemplate must be a
// schema v3+ template that allows ECDSA_P256. Everything this run enrolls is
// removed again at the end.

const path = require("node:path");
const fs = require("node:fs");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");

const modRoot = "C:\\TokenTimerAgentTest\\src\\windows-cert-store";
const certStore = require(path.join(modRoot, "index.js"));

const KSP = "Microsoft Software Key Storage Provider";
const results = [];

function check(label, ok, detail = "") {
  results.push({ label, ok });
  console.log(`${ok ? "OK" : "FAIL"}: ${label}${!ok && detail ? ` -- ${detail}` : ""}`);
  if (!ok) process.exitCode = 1;
}

// Observations are recorded for later design work and never fail the run.
function observe(label, detail) {
  console.log(`OBSERVE: ${label}: ${detail}`);
}

function run(file, args) {
  const r = spawnSync(file, args, { encoding: "utf8", windowsHide: true, timeout: 120000 });
  return { status: r.status, stdout: r.stdout || "", stderr: r.stderr || "", error: r.error || null };
}

function excerpt(r) {
  return `exit ${r.status}: ${`${r.stdout}\n${r.stderr}`.trim().slice(0, 600)}`;
}

function kspContainerList() {
  return run("certutil.exe", ["-key", "-csp", KSP]).stdout;
}

// certutil labels are localized, the extension OID and the hex flags are not.
// The separator after the OID is often a non-breaking space that the console
// code page mangles, so find the OID then take the last (hh) before the next OID.
function csrKeyUsageHex(csrPath) {
  const dump = run("certutil.exe", ["-dump", csrPath]).stdout;
  const idx = dump.search(/2\.5\.29\.15/);
  if (idx < 0) return null;
  const window = dump.slice(idx, idx + 500);
  const nextOid = window.search(/\r?\n\s*2\.5\.29\./);
  const region = nextOid > 0 ? window.slice(0, nextOid) : window;
  const matches = [...region.matchAll(/\(([0-9a-f]{2})\)/gi)];
  return matches.length > 0 ? matches[matches.length - 1][1].toLowerCase() : null;
}

function inspectStoreKey(thumbprint) {
  if (!/^[0-9A-F]{40}$/.test(thumbprint)) throw new Error(`bad thumbprint ${thumbprint}`);
  const ps = [
    `$c = Get-Item "Cert:\\LocalMachine\\My\\${thumbprint}" -ErrorAction SilentlyContinue`,
    "$o = [ordered]@{ inStore = [bool]$c; hasPrivateKey = [bool]($c -and $c.HasPrivateKey) }",
    "if ($c) {",
    "  $k = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c)",
    "  if (-not $k) { $k = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($c) }",
    "  if ($k -is [System.Security.Cryptography.RSACng] -or $k -is [System.Security.Cryptography.ECDsaCng]) {",
    '    $o.keyName = $k.Key.KeyName; $o.algorithm = "$($k.Key.Algorithm)"; $o.provider = "$($k.Key.Provider)"',
    '    $o.exportPolicy = "$($k.Key.ExportPolicy)"; $o.machineKey = $k.Key.IsMachineKey',
    "  }",
    "}",
    "$o | ConvertTo-Json -Compress",
  ].join("\n");
  const r = run("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", ps]);
  try {
    return JSON.parse(r.stdout.trim());
  } catch {
    return { parseError: excerpt(r) };
  }
}

async function main() {
  const [workDirArg, caConfig, rsaTemplate, ecTemplate] = process.argv.slice(2);
  if (!workDirArg || !caConfig || !rsaTemplate) {
    console.error("usage: node windows-cng-key-path-verify.js <workDir> <caConfig> <rsaTemplate> [ecTemplate]");
    process.exitCode = 2;
    return;
  }
  const workDir = path.join(workDirArg, `key-path-${Date.now()}`);
  fs.mkdirSync(workDir, { recursive: true });
  const enrolled = [];
  const bareContainers = [];

  function submit(label, csrPem, template) {
    const csrPath = path.join(workDir, `${label}.csr`);
    const cerPath = path.join(workDir, `${label}.cer`);
    fs.writeFileSync(csrPath, csrPem);
    // All four paths, so certreq never derives a response file name itself.
    const r = run("certreq.exe", [
      "-q", "-submit", "-config", caConfig, "-attrib", `CertificateTemplate:${template}`,
      csrPath, cerPath, path.join(workDir, `${label}.p7b`), path.join(workDir, `${label}.rsp`),
    ]);
    return { r, csrPath, certPem: fs.existsSync(cerPath) ? fs.readFileSync(cerPath, "utf8") : null };
  }

  async function acceptAndInspect(label, certPem, containerName, expectAlgorithm) {
    const accept = await certStore.acceptCertificateViaCng({ certificatePem: certPem, workDir, store: "My" });
    check(`${label}: certreq -machine -accept succeeded`, accept.ok, JSON.stringify(accept));
    if (!accept.ok) return null;
    enrolled.push({ thumbprint: accept.thumbprint, containerName });
    const key = inspectStoreKey(accept.thumbprint);
    console.log(`${label}: store key ${JSON.stringify(key)}`);
    check(`${label}: LocalMachine\\My holds the certificate with its private key`, key.inStore && key.hasPrivateKey);
    check(`${label}: bound to the generated container`, key.keyName === containerName, key.keyName);
    check(`${label}: ${expectAlgorithm} key in the Software KSP`, key.provider === KSP && key.algorithm === expectAlgorithm);
    check(`${label}: machine key, export policy None`, key.machineKey === true && key.exportPolicy === "None");
    return accept;
  }

  async function enrollAndCheck({ label, algorithm, template, keyUsageHex, expectAlgorithm }) {
    console.log(`\n=== ${label}: ${algorithm} through template ${template} ===`);
    const commonName = `${label}-keypath.tokentimer-verify.local`;
    const csr = await certStore.generateCsrViaCng({
      commonName, altNames: [commonName], jobId: `keypath-${label}`, algorithm, workDir,
    });
    check(`${label}: certreq -machine -new succeeded under the service identity`, csr.ok, JSON.stringify(csr));
    if (!csr.ok) return;
    bareContainers.push(csr.containerName);
    check(`${label}: container ${csr.containerName} is in the Software KSP`, kspContainerList().includes(csr.containerName));
    const s = submit(label, csr.csrPem, template);
    check(`${label}: CSR asks for KeyUsage 0x${keyUsageHex}`, csrKeyUsageHex(s.csrPath) === keyUsageHex, csrKeyUsageHex(s.csrPath));
    check(`${label}: CA issued`, Boolean(s.certPem), excerpt(s.r));
    if (!s.certPem) return;
    const accepted = await acceptAndInspect(label, s.certPem, csr.containerName, expectAlgorithm);
    if (accepted) bareContainers.splice(bareContainers.indexOf(csr.containerName), 1);
  }

  async function enrollmentContainerCheck(template) {
    console.log("\n=== enrollment-named container ===");
    const enrollmentId = crypto.randomUUID();
    const expected = `tokentimer-enr-${enrollmentId}`;
    const commonName = "enr-keypath.tokentimer-verify.local";
    const first = await certStore.generateCsrViaCng({
      commonName, altNames: [commonName], jobId: "keypath-enr", enrollmentId, workDir,
    });
    check("enrollment: certreq -machine -new succeeded", first.ok, JSON.stringify(first));
    if (!first.ok) return;
    check(`enrollment: container is ${expected}`, first.containerName === expected, first.containerName);
    bareContainers.push(expected);
    check("enrollment: container is in the Software KSP", kspContainerList().includes(expected));

    const second = await certStore.generateCsrViaCng({
      commonName, altNames: [commonName], jobId: "keypath-enr", enrollmentId, workDir,
    });
    observe(
      "second certreq -new under the same container name",
      second.ok ? "succeeded (certreq did not refuse)" : `refused, exit ${second.exitCode}: ${second.stdoutExcerpt} ${second.stderrExcerpt}`.trim(),
    );
    if (second.ok) {
      observe("second CSR carries a different public key", String(second.csrPem !== first.csrPem));
    }

    const s = submit("enr", first.csrPem, template);
    check("enrollment: CA issued for the first CSR", Boolean(s.certPem), excerpt(s.r));
    if (!s.certPem) return;
    const accept = await certStore.acceptCertificateViaCng({ certificatePem: s.certPem, workDir, store: "My" });
    observe(
      "first key still accepts its certificate after the second -new",
      accept.ok ? "yes" : `no: ${JSON.stringify(accept)}`,
    );
    if (accept.ok) {
      enrolled.push({ thumbprint: accept.thumbprint, containerName: expected });
      bareContainers.splice(bareContainers.indexOf(expected), 1);
      const key = inspectStoreKey(accept.thumbprint);
      check("enrollment: accepted certificate is bound to the enrollment container", key.keyName === expected, key.keyName);
    }
  }

  try {
    await enrollAndCheck({ label: "rsa", algorithm: "rsa-2048", template: rsaTemplate, keyUsageHex: "a0", expectAlgorithm: "RSA" });
    if (ecTemplate) {
      await enrollAndCheck({ label: "ec", algorithm: "ec-p256", template: ecTemplate, keyUsageHex: "80", expectAlgorithm: "ECDSA_P256" });
    } else {
      console.log("\n(no ecTemplate given: EC enrollment skipped)");
    }
    await enrollmentContainerCheck(rsaTemplate);

    const leftovers = fs.readdirSync(workDir).filter((f) => /\.(pfx|p12|key)$/i.test(f));
    check("no private key file was written to the work directory", leftovers.length === 0, leftovers.join(", "));
  } finally {
    console.log("\n=== cleanup ===");
    for (const { thumbprint, containerName } of enrolled) {
      const r = await certStore.removeCertificateAndKeyContainer({ thumbprint, store: "My", containerName });
      console.log(`removed ${thumbprint} + ${containerName}: ${JSON.stringify(r.ok ?? r)}`);
    }
    for (const containerName of bareContainers) {
      const r = await certStore.removeAbandonedKeyContainer({ containerName });
      console.log(`removed bare container ${containerName}: ${JSON.stringify(r.ok ?? r)}`);
    }
    const remaining = kspContainerList();
    const stale = [...enrolled.map((e) => e.containerName), ...bareContainers].filter((n) => remaining.includes(n));
    check("cleanup left none of this run's containers behind", stale.length === 0, stale.join(", "));
  }

  const failed = results.filter((r) => !r.ok).length;
  console.log(`\nsummary: ${results.length - failed}/${results.length} checks passed`);
  console.log(`workdir: ${workDir}`);
}

main().catch((err) => {
  console.error("UNCAUGHT ERROR:", err);
  process.exitCode = 1;
});
