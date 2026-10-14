"use strict";
/* Child-only native contention participant. Parent validates this owned Node
 * process before sending go. The real enrollment lock surrounds genuine CNG
 * CSR generation; the native-call observer delegates unchanged to execFile.
 * No CA or certificate acceptance occurs. Public bounded IPC is the only output.
 */
const assert = require("node:assert/strict"),
  cp = require("node:child_process"),
  fs = require("node:fs"),
  path = require("node:path");
const {
  acquireEnrollmentLock,
  generateCsrViaCng,
} = require("../../src/windows-cert-store");
// generateCsrViaCng removes its temporary INF/REQ before returning. Persist
// only an explicitly fixture-owned copy of the returned public CSR.
function persistPublicCsr(result, workDir) {
  assert.equal(result.ok, true);
  assert.equal(typeof result.csrPem, "string");
  assert.ok(Buffer.byteLength(result.csrPem) < 65536);
  assert.equal(
    fs.existsSync(result.reqPath),
    false,
    "Product request temporary must already be removed",
  );
  assert.equal(fs.existsSync(result.infPath), false);
  const file = path.join(workDir, "fixture-public.csr");
  fs.writeFileSync(file, result.csrPem, {
    encoding: "utf8",
    flag: "wx",
    mode: 0o600,
  });
  return file;
}
async function main() {
  assert.equal(process.platform, "win32");
  assert.equal(process.env.CERTOPS_HOST_TESTS, "1");
  assert.ok(process.send);
  const [mode, stateDir, enrollmentId, workDir] = process.argv.slice(2);
  assert.ok(["hold", "attempt"].includes(mode));
  assert.match(enrollmentId, /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
  let lock,
    nativeCalls = 0,
    certreqCalls = 0,
    nativeActive = 0;
  const send = (value) =>
    new Promise((resolve, reject) =>
      process.send(value, (error) => (error ? reject(error) : resolve())),
    );
  const event = (name) =>
    new Promise((resolve) => {
      const handler = (message) => {
        if (message?.event === name) {
          process.off("message", handler);
          resolve();
        }
      };
      process.on("message", handler);
    });
  const go = event("go");
  await send({ event: "ready", pid: process.pid });
  await go;
  try {
    try {
      lock = acquireEnrollmentLock(stateDir, enrollmentId);
    } catch (error) {
      assert.equal(error.code, "ENROLLMENT_LOCKED");
      await send({
        event: "locked",
        code: error.code,
        nativeCalls,
        certreqCalls,
      });
      return;
    }
    lock.assertHeld();
    const result = await lock.run((signal) =>
      generateCsrViaCng({
        signal,
        enrollmentId,
        commonName: "certops-lock.invalid",
        altNames: ["certops-lock.invalid"],
        algorithm: "rsa-2048",
        workDir,
        execFileImpl: (file, args, options, callback) => {
          nativeCalls++;
          if (/certreq(?:\.exe)?$/i.test(file)) certreqCalls++;
          nativeActive++;
          return cp.execFile(file, args, options, (...values) => {
            nativeActive--;
            callback(...values);
          });
        },
      }),
    );
    lock.assertHeld();
    if (mode === "hold") {
      assert.equal(result.ok, true);
      const publicCsrPath = persistPublicCsr(result, workDir);
      const release = event("release");
      await send({
        event: "generated",
        csrPem: result.csrPem,
        publicCsrPath,
        removedReqPath: result.reqPath,
        containerName: result.containerName,
        nativeCalls,
        certreqCalls,
      });
      await release;
    } else {
      assert.equal(result.ok, false);
      assert.equal(result.reason, "enrollment_container_exists");
      await send({
        event: "collision",
        reason: result.reason,
        nativeCalls,
        certreqCalls,
      });
    }
  } finally {
    if (lock) lock.release();
    assert.equal(nativeActive, 0);
    await send({ event: "released", nativeActive });
    process.disconnect();
  }
}
if (require.main === module)
  main().catch(() => {
    process.exitCode = 1;
    if (process.connected) process.disconnect();
  });

module.exports = { persistPublicCsr };
