"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { listMachineStoreCertificates, listHttpSysBindings } = require("../../src/windows-discovery");
async function qualifyUserStoreBoundary({ powershell, workDir }) {
  const receipt = path.join(workDir, "current-user-certificate.receipt");
  const escapedReceipt = receipt.replace(/'/g, "''");
  const subject = `certops-user-${crypto.randomUUID()}.invalid`;
  let thumbprint;
  let primaryError;
  try {
    thumbprint = powershell(`$c=New-SelfSignedCertificate -DnsName '${subject}' -CertStoreLocation Cert:\\CurrentUser\\My; [IO.File]::WriteAllText('${escapedReceipt}', $c.Thumbprint); $c.Thumbprint`);
    assert.match(thumbprint, /^[A-F0-9]{40}$/);
    assert.equal(powershell(`[bool](Test-Path 'Cert:\\CurrentUser\\My\\${thumbprint}')`), "True");
    assert.equal(powershell(`[bool](Test-Path 'Cert:\\LocalMachine\\My\\${thumbprint}')`), "False");
    const machine = await listMachineStoreCertificates({ store: "My" });
    assert.equal(machine.ok, true, "native machine-store discovery must succeed");
    assert.equal(machine.certificates.some((certificate) => certificate.thumbprint?.toUpperCase() === thumbprint), false,
      "machine discovery must not cross into the caller's CurrentUser store");
    // Exercise actual process-launch failures, without inventing a native
    // query response or pretending unreadable stores/bindings are empty.
    const missingTool = path.join(workDir, `missing-${crypto.randomUUID()}.exe`);
    assert.equal(fs.existsSync(missingTool), false);
    for (const powershellPath of [missingTool, process.execPath]) {
      const storeFailure = await listMachineStoreCertificates({ store: "My", powershellPath });
      const bindingFailure = await listHttpSysBindings({ powershellPath });
      assert.equal(storeFailure.ok, false, "missing/wrong native runtime must fail store discovery");
      assert.equal(bindingFailure.ok, false, "missing/wrong native runtime must fail binding discovery");
      assert.equal(storeFailure.certificates, undefined);
      assert.equal(bindingFailure.bindings, undefined);
    }
  } catch (error) { primaryError = error; throw error; }
  finally {
    if (!/^[A-F0-9]{40}$/.test(thumbprint || "") && fs.existsSync(receipt)) thumbprint = fs.readFileSync(receipt, "utf8").trim();
    if (thumbprint) {
      assert.match(thumbprint, /^[A-F0-9]{40}$/);
      try {
        powershell(`$p='Cert:\\CurrentUser\\My\\${thumbprint}'; if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -DeleteKey }; if (Test-Path -LiteralPath $p) { throw 'Owned CurrentUser certificate remains' }`);
      } catch (error) { throw new AggregateError(primaryError ? [primaryError, error] : [error], "Owned CurrentUser fixture cleanup failed", { cause: primaryError }); }
    }
  }
}
module.exports = { qualifyUserStoreBoundary };
