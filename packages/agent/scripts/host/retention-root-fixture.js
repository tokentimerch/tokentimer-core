"use strict";
// Temporary public root for the disposable host's real certreq acceptance.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

async function withOwnedRetentionRoot({ powershell, run, workDir, execute }) {
  const file = path.join(workDir, "ca.pem");
  const root = new crypto.X509Certificate(fs.readFileSync(file));
  assert.equal(root.ca, true);
  const thumbprint = root.fingerprint.replace(/:/g, "");
  assert.match(thumbprint, /^[A-F0-9]{40}$/);
  const digest = crypto.createHash("sha256").update(root.raw).digest("hex");
  const rootPath = `Cert:\\LocalMachine\\Root\\${thumbprint}`;
  const present = () => {
    const result = powershell(`[bool](Test-Path -LiteralPath '${rootPath}')`);
    assert.ok(result === "True" || result === "False", "Cannot determine retention root presence");
    return result === "True";
  };
  const verify = () => {
    const observed = JSON.parse(powershell(`$c=Get-Item -LiteralPath '${rootPath}'; try {@{raw=[Convert]::ToBase64String($c.RawData);hasPrivateKey=$c.HasPrivateKey}|ConvertTo-Json -Compress} finally {$c.Dispose()}`));
    assert.equal(observed.hasPrivateKey, false, "Preserve root with unexpected private key");
    assert.equal(crypto.createHash("sha256").update(Buffer.from(observed.raw, "base64")).digest("hex"), digest, "Preserve a replaced root");
  };
  assert.equal(present(), false, "Refuse existing retention signing root");
  try {
    run("certutil.exe", ["-addstore", "Root", file]);
    verify();
    return await execute();
  } finally {
    if (present()) {
      verify();
      powershell(`Remove-Item -LiteralPath '${rootPath}'; if (Test-Path -LiteralPath '${rootPath}') { throw 'Owned retention signing root remains' }`);
    }
    assert.equal(present(), false, "Owned retention signing root remains");
  }
}
module.exports = { withOwnedRetentionRoot };
