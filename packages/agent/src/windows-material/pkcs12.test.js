"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { makePkcs12 } = require("./pkcs12");
const { writeProtectedFile } = require("../material-store");

test(
  "Windows CryptoAPI parses encrypted PKCS#12 and proves private-key association without persisting a key",
  // skip-reason: no-host — non-persisting native PKCS#12 parsing needs Windows.
  { skip: process.platform !== "win32" },
  (t) => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "tt-pkcs12-"));
    t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
    const bundle = {
      certificatePem: fs.readFileSync(
        path.join(__dirname, "../verify/fixtures/leaf.crt.pem"),
        "utf8",
      ),
      privateKeyPem: fs.readFileSync(
        path.join(__dirname, "../verify/fixtures/leaf.key.pem"),
        "utf8",
      ),
    };
    const pfx = makePkcs12(bundle, "synthetic-isolated-test-password");
    const file = path.join(directory, "material.pfx");
    writeProtectedFile(file, pfx);
    pfx.fill(0);
    const aclChecks =
      "$mask=[TokenTimer.MaterialImport].GetMethod('EffectiveMask',[Reflection.BindingFlags]'NonPublic,Static');$full=$mask.Invoke($null,@([Convert]::ToInt32('D01F01FF',16)));if($full -ne $mask.Invoke($null,@([int]0x10000000))){exit 5};$read=$mask.Invoke($null,@([Convert]::ToInt32('80000000',16)));if($read -ne $mask.Invoke($null,@([Convert]::ToInt32('80120089',16)))){exit 6};if($read -eq $mask.Invoke($null,@([Convert]::ToInt32('80000002',16)))){exit 7};'acl-verified'";
    const script =
      "$ErrorActionPreference='Stop';Add-Type -Path $env:TT_TEST_IMPORT_CS;$cert=[System.Security.Cryptography.X509Certificates.X509Certificate2]::new([IO.File]::ReadAllBytes($env:TT_TEST_PFX),'synthetic-isolated-test-password',[System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet);if(-not $cert.HasPrivateKey){exit 2};$method=[TokenTimer.MaterialImport].GetMethod('Key',[Reflection.BindingFlags]'NonPublic,Static');$copy=$method.Invoke($null,@($cert));if($copy.Algorithm.Algorithm -ne 'RSA'){exit 4};$copy.Dispose();$rsa=[System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert);$signature=$rsa.SignData([byte[]](1,2,3),[System.Security.Cryptography.HashAlgorithmName]::SHA256,[System.Security.Cryptography.RSASignaturePadding]::Pkcs1);if(-not $rsa.VerifyData([byte[]](1,2,3),$signature,[System.Security.Cryptography.HashAlgorithmName]::SHA256,[System.Security.Cryptography.RSASignaturePadding]::Pkcs1)){exit 3};$rsa.Dispose();$cert.Dispose();'verified'";
    const result = spawnSync(
      path.join(
        process.env.SystemRoot,
        "System32/WindowsPowerShell/v1.0/powershell.exe",
      ),
      [
        "-NoProfile",
        "-NonInteractive",
        "-EncodedCommand",
        Buffer.from(script + ";" + aclChecks, "utf16le").toString("base64"),
      ],
      {
        encoding: "utf8",
        env: {
          ...process.env,
          TT_TEST_PFX: file,
          TT_TEST_IMPORT_CS: path.join(__dirname, "MaterialImport.cs"),
        },
        windowsHide: true,
        timeout: 30000,
      },
    );
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /verified/);
    assert.match(result.stdout, /acl-verified/);
  },
);
