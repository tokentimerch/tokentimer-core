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
// Publish complete public protocol bytes atomically; observers never read a partial JSON write.
function publishOwnedProtocol(directory, name, bytes) {
  assert.match(name, /^(?:event-[a-z]+\.json|command-(?:go|release))$/);
  assert.equal(fs.lstatSync(directory).isSymbolicLink(), false);
  assert.equal(
    fs.realpathSync(directory).toLowerCase(),
    path.resolve(directory).toLowerCase(),
  );
  const data = Buffer.from(bytes);
  assert.ok(data.length > 0 && data.length <= 131072);
  const temporary = path.join(
    directory,
    `.publish-${require("node:crypto").randomUUID()}`,
  );
  fs.writeFileSync(temporary, data, { flag: "wx" });
  try {
    fs.linkSync(temporary, path.join(directory, name));
  } finally {
    fs.unlinkSync(temporary);
  }
}
async function main() {
  assert.equal(process.platform, "win32");
  assert.equal(process.env.CERTOPS_HOST_TESTS, "1");

  const [mode, stateDir, enrollmentId, workDir, protocol] =
    process.argv.slice(2);
  const fileProtocol = typeof protocol === "string";
  assert.ok(fileProtocol || process.send);
  if (fileProtocol) {
    assert.equal(path.dirname(protocol), path.resolve(workDir));
    assert.equal(fs.lstatSync(protocol).isSymbolicLink(), false);
  }
  assert.ok(["hold", "attempt"].includes(mode));
  assert.match(enrollmentId, /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
  let lock,
    nativeCalls = 0,
    certreqCalls = 0,
    nativeActive = 0;
  const send = (value) =>
    fileProtocol
      ? Promise.resolve().then(() => {
          assert.match(value.event, /^[a-z]+$/);
          publishOwnedProtocol(
            protocol,
            `event-${value.event}.json`,
            JSON.stringify(value),
          );
        })
      : new Promise((resolve, reject) =>
          process.send(value, (error) => (error ? reject(error) : resolve())),
        );
  const event = (name) =>
    fileProtocol
      ? new Promise((resolve, reject) => {
          const deadline = Date.now() + 120000;
          const poll = () => {
            const file = path.join(protocol, `command-${name}`);
            if (fs.existsSync(file)) {
              const stat = fs.lstatSync(file);
              if (
                !stat.isFile() ||
                stat.isSymbolicLink() ||
                fs.readFileSync(file, "utf8") !== "1"
              )
                return reject(new Error("Owned command refused"));
              return resolve();
            }
            if (Date.now() >= deadline)
              return reject(new Error("Owned command timeout"));
            setTimeout(poll, 25);
          };
          poll();
        })
      : new Promise((resolve) => {
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
    if (process.connected) process.disconnect();
  }
}
if (require.main === module)
  main().catch(() => {
    process.exitCode = 1;
    if (process.connected) process.disconnect();
  });

module.exports = { persistPublicCsr, publishOwnedProtocol };
