/*
 * Qualification notes: standalone-adcs-feasibility
 * Shared setup, dispatch and evidence rules: docs/certops/e2e-qualification.md.
 * Experimental certops-standalone-adcs-smoke.yml uses elevated fresh Server2022,refuses existing
 * CA/reboot requests. Require actual standalone pending request,officer resubmit/retrieve/accept using
 * nonexportable CNG,and unique IIS SNI trustedTLS with DNS SAN/serverAuth. No product AD CS capability
 * enablement. Cleanup only owned leaf/key/site/binding/unique CA certs/authority/new roles; preserve
 * preexisting IIS. Verifier requires candidate/current hashes/measured OS/SID/CA type,3 nonduplicate
 * named cases and cleanup,never qualified label. Stable-host promotion needs3 consecutive
 * same-candidate/image successes<=25min,no skips/reboot and repeat after image/tooling changes.
 * Excluded from release collector; not domain
 * Kerberos/templates/continuations/renewal/revocation/CA-key/localization matrix.
 */
"use strict";

// Windows host checks for the two release gaps that can run on a runner:
// product store and http.sys queries in a session that is actually in
// Constrained Language Mode, and a real certutil -delstore that kills the
// lock owner before -delkey. A customer WDAC or AppLocker policy is not
// applied here. __PSLockdownPolicy is ignored on current Windows unless a
// code-integrity policy is already active, so the session is switched at
// the first statement and a blocked Add-Type proves the switch took.

const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const POWERSHELL = path.join(
  process.env.SystemRoot || "C:\\Windows",
  "System32",
  "WindowsPowerShell",
  "v1.0",
  "powershell.exe",
);
const KSP = "Microsoft Software Key Storage Provider";
const CONTAINER = "tokentimer-win10gap01";

function powershell(script, env) {
  return spawnSync(
    POWERSHELL,
    ["-NoProfile", "-NonInteractive", "-Command", script],
    { encoding: "utf8", windowsHide: true, timeout: 60000, env: env || process.env },
  );
}

function runConstrained(script) {
  const command = [
    "$ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage'",
    "'mode=' + $ExecutionContext.SessionState.LanguageMode",
    "try { Add-Type -TypeDefinition 'public class TtClmProbe { public int X; }'; 'control=not-blocked' } catch { 'control=blocked' }",
    script,
  ].join("; ");
  return powershell(command);
}

function jsonLine(stdout) {
  const line = String(stdout)
    .split(/\r?\n/)
    .map((entry) => entry.trim())
    .filter((entry) => entry.startsWith("{"))
    .pop();
  if (!line) throw new Error(`no JSON in PowerShell output:\n${stdout}`);
  return JSON.parse(line);
}

function isAdmin() {
  const result = powershell(
    "if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { 'yes' } else { 'no' }",
  );
  return result.status === 0 && String(result.stdout).includes("yes");
}

function certutil(args) {
  return spawnSync("certutil.exe", args, {
    encoding: "utf8",
    windowsHide: true,
    timeout: 30000,
  });
}

function createMachineMaterial() {
  const script = `
$ErrorActionPreference = 'Stop'
$name = '${CONTAINER}'
$provider = [System.Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider
$open = [System.Security.Cryptography.CngKeyOpenOptions]::MachineKey
if ([System.Security.Cryptography.CngKey]::Exists($name, $provider, $open)) {
  $stale = [System.Security.Cryptography.CngKey]::Open($name, $provider, $open)
  $stale.Delete()
}
$params = New-Object System.Security.Cryptography.CngKeyCreationParameters
$params.Provider = $provider
$params.KeyCreationOptions = [System.Security.Cryptography.CngKeyCreationOptions]::MachineKey
$params.KeyUsage = [System.Security.Cryptography.CngKeyUsages]::AllUsages
$params.ExportPolicy = [System.Security.Cryptography.CngExportPolicies]::AllowPlaintextExport
$key = [System.Security.Cryptography.CngKey]::Create([System.Security.Cryptography.CngAlgorithm]::Rsa, $name, $params)
$rsa = New-Object System.Security.Cryptography.RSACng $key
$req = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest ('CN=tt-win10-gap', $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
$cert = $req.CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays(-1), [DateTimeOffset]::UtcNow.AddDays(2))
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store ('My', 'LocalMachine')
$store.Open('ReadWrite')
$store.Add($cert)
$store.Close()
$key.Dispose()
Write-Output $cert.Thumbprint
`;
  const result = powershell(script);
  if (result.status !== 0) {
    throw new Error(`could not create the machine certificate:\n${result.stderr || result.stdout}`);
  }
  const thumbprint = String(result.stdout).trim().split(/\r?\n/).pop().replace(/\s/g, "").toUpperCase();
  if (!/^[0-9A-F]{40}$/.test(thumbprint)) {
    throw new Error(`unexpected thumbprint output:\n${result.stdout}`);
  }
  return thumbprint;
}

function certificatePresent(thumbprint) {
  const result = certutil(["-store", "My", thumbprint]);
  return result.status === 0 && String(result.stdout).toUpperCase().includes(thumbprint);
}

function keyPresent() {
  const result = certutil(["-csp", KSP, "-key"]);
  return result.status === 0 && String(result.stdout).includes(CONTAINER);
}

function cleanupMaterial(thumbprint) {
  if (thumbprint) certutil(["-delstore", "My", thumbprint]);
  certutil(["-csp", KSP, "-delkey", CONTAINER]);
}

async function interruptChild() {
  const stateDir = process.argv[3];
  const { removeCertificateAndKeyContainer, acquireStoreLock } = require(
    "../packages/agent/src/windows-cert-store",
  );
  const thumbprint = createMachineMaterial();
  fs.writeFileSync(
    path.join(stateDir, "created.json"),
    JSON.stringify({ thumbprint, container: CONTAINER }),
  );
  const lock = acquireStoreLock(stateDir, "My");
  try {
    await lock.run(async (signal) => {
      await removeCertificateAndKeyContainer({
        thumbprint,
        store: "My",
        containerName: CONTAINER,
        signal,
        assertHeld: () => lock.assertHeld(),
        execFileImpl(file, args, options, callback) {
          return require("node:child_process").execFile(
            file,
            args,
            options,
            (error, stdout, stderr) => {
              const deletedStore =
                !error &&
                path.win32.basename(String(file)).toLowerCase() === "certutil.exe" &&
                args[0] === "-delstore" &&
                args[1] === "My" &&
                String(args[2]).toUpperCase() === thumbprint;
              if (deletedStore) {
                fs.writeFileSync(
                  path.join(stateDir, "fault.json"),
                  JSON.stringify({ fault: "after-delstore", pid: process.pid, thumbprint }),
                );
                process.exit(86);
              }
              callback(error, stdout, stderr);
            },
          );
        },
      });
    });
  } finally {
    try {
      lock.release();
    } catch {
      // The process is about to exit or the worker already died.
    }
  }
  throw new Error("certutil -delstore did not run");
}

if (process.argv[2] === "--interrupt-child") {
  interruptChild().catch((error) => {
    console.error(error && error.stack ? error.stack : error);
    process.exitCode = 1;
  });
} else {
  const { test } = require("node:test");
  const assert = require("node:assert/strict");
  const windows = process.platform === "win32";

  test("store and http.sys queries run in Constrained Language Mode", { skip: !windows }, () => {
    const {
      buildStoreQueryScript,
      buildHttpSysBindingQueryScript,
    } = require("../packages/agent/src/windows-discovery");
    for (const script of [buildStoreQueryScript("My"), buildHttpSysBindingQueryScript()]) {
      const result = runConstrained(script);
      assert.equal(result.status, 0, result.stderr || result.stdout);
      assert.match(result.stdout, /mode=ConstrainedLanguage/);
      assert.match(result.stdout, /control=blocked/);
      const parsed = jsonLine(result.stdout);
      assert.ok(Object.prototype.hasOwnProperty.call(parsed, "items"));
    }
  });

  test("killing the lock owner after certutil -delstore keeps the CNG key", { skip: !windows }, async () => {
    assert.equal(isAdmin(), true, "LocalMachine\\My deletion requires an elevated runner");
    const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "tt-win10-"));
    let thumbprint = null;
    try {
      const child = spawnSync(process.execPath, [__filename, "--interrupt-child", stateDir], {
        encoding: "utf8",
        timeout: 90000,
        windowsHide: true,
      });
      const createdPath = path.join(stateDir, "created.json");
      if (fs.existsSync(createdPath)) {
        thumbprint = JSON.parse(fs.readFileSync(createdPath, "utf8")).thumbprint;
      }
      assert.equal(
        child.status,
        86,
        `interruption child exited ${child.status}\n${child.stdout}\n${child.stderr}`,
      );
      assert.equal(fs.existsSync(path.join(stateDir, "fault.json")), true);
      assert.equal(certificatePresent(thumbprint), false);
      assert.equal(keyPresent(), true);
      const { removeCertificateAndKeyContainer, acquireStoreLock } = require(
        "../packages/agent/src/windows-cert-store",
      );
      const lock = acquireStoreLock(stateDir, "My");
      try {
        const resumed = await lock.run((signal) =>
          removeCertificateAndKeyContainer({
            thumbprint,
            store: "My",
            containerName: CONTAINER,
            signal,
            assertHeld: () => lock.assertHeld(),
          }),
        );
        assert.equal(resumed.ok, true, JSON.stringify(resumed));
      } finally {
        lock.release();
      }
      assert.equal(keyPresent(), false);
    } finally {
      cleanupMaterial(thumbprint);
      fs.rmSync(stateDir, { recursive: true, force: true });
    }
  });
}
