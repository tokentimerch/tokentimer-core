"use strict";
/* Supporting disposable Windows CNG enrollment contention fixture. Starts
 * exact owned Node children, proves a real lock loser makes zero native calls,
 * and verifies winner CSR/key custody with independent OpenSSL public SPKI and
 * native signing. Retry uses the same lock and genuine existing-container check.
 * No CA, IIS, accepted certificate or fabricated raw-CSR atomicity is involved.
 */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto");
const contained = require("../../../../tests/e2e/helpers/certops-windows-contained-process");
const active = new Set(),
  guardName = ".preserve-enrollment-contention.json";
function assertCleanupSafe(workDir) {
  assert.equal(
    active.has(path.resolve(workDir)),
    false,
    "Enrollment contention ownership unresolved",
  );
  assert.equal(
    fs.existsSync(path.join(workDir, guardName)),
    false,
    "Preserve unresolved contention receipt",
  );
  contained.assertCleanupSafe(workDir);
}
const {
  buildEnrollmentContainerName,
} = require("../../src/windows-cert-store");
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
function verifyContentionFacts(facts) {
  for (const field of [
    "winnerGeneratedRealCsr",
    "loserLockedBeforeNativeExecution",
    "retryAcquiredEnrollmentLock",
    "retryExistingContainerRefused",
    "sameCsrAndSpki",
    "sameNonExportableKey",
    "winnerSignatureVerified",
    "ownedChildrenStopped",
    "ownedKeyRemoved",
  ])
    assert.equal(facts[field], true, field);
  assert.equal(facts.loserNativeCalls, 0);
  assert.equal(facts.loserCertreqCalls, 0);
  assert.equal(facts.retryCertreqCalls, 0);
  assert.equal(facts.winnerCertreqCalls, 1);
  assert.ok(
    Number.isInteger(facts.retryNativeCalls) &&
      facts.retryNativeCalls > 0 &&
      facts.retryNativeCalls <= 32,
  );
  return true;
}
async function qualifyEnrollmentContention({ powershell, run, workDir }) {
  assert.equal(process.platform, "win32");
  assert.equal(process.env.CERTOPS_HOST_TESTS, "1");
  const enrollmentId = crypto.randomUUID(),
    containerName = buildEnrollmentContainerName(enrollmentId),
    directory = path.join(workDir, `enrollment-contention-${enrollmentId}`),
    stateDir = path.join(directory, "state"),
    entry = path.join(__dirname, "enrollment-lock-child.js"),
    children = [],
    errors = [];
  let primary,
    facts,
    keyOwned = false;
  active.add(path.resolve(workDir));
  const guard = path.join(workDir, guardName);
  fs.writeFileSync(guard, JSON.stringify({ enrollmentId, directory }), {
    flag: "wx",
  });
  const guardStat = fs.lstatSync(guard, { bigint: true }),
    guardBytes = fs.readFileSync(guard);
  assert.ok(guardStat.ino > 0n);
  fs.mkdirSync(directory);
  fs.mkdirSync(stateDir);
  for (const name of ["winner", "loser", "retry"])
    fs.mkdirSync(path.join(directory, name));
  const snapshot = () =>
    JSON.parse(
      powershell(
        `$k=[Security.Cryptography.CngKey]::Open('${containerName}',[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider,[Security.Cryptography.CngKeyOpenOptions]::MachineKey);$r=$null;try{$r=[Security.Cryptography.RSACng]::new($k);@{name=$k.KeyName;unique=$k.UniqueName;provider=$k.Provider.Provider;machine=$k.IsMachineKey;policy=[int]$k.ExportPolicy;bits=$r.KeySize}|ConvertTo-Json -Compress}finally{if($r){$r.Dispose()};$k.Dispose()}`,
      ),
    );
  const start = async (mode) => {
    const folder =
      mode === "hold" ? "winner" : children.length === 1 ? "loser" : "retry";
    const protocol = path.join(directory, folder, "protocol");
    fs.mkdirSync(protocol);
    const owned = {
      protocol,
      resource: null,
      closed: false,
      nativeDrained: false,
    };
    children.push(owned);
    await contained.startContainedNativeProcess({
      executable: process.execPath,
      args: [
        entry,
        mode,
        stateDir,
        enrollmentId,
        path.join(directory, folder),
        protocol,
      ],
      environment: {
        ...Object.fromEntries(
          [
            "SystemRoot",
            "WINDIR",
            "ComSpec",
            "PATH",
            "PATHEXT",
            "TEMP",
            "TMP",
            "SystemDrive",
            "ProgramFiles",
            "ProgramData",
            "USERPROFILE",
          ]
            .filter((name) => process.env[name] !== undefined)
            .map((name) => [name, process.env[name]]),
        ),
        CERTOPS_HOST_TESTS: "1",
      },
      workDir,
      maxLifetimeMs: 180000,
      onCreated(resource) {
        owned.resource = resource;
        owned.exit = new Promise((resolve) => {
          resource.wrapper.once("close", (code) => {
            owned.closed = true;
            resolve(code);
          });
        });
      },
    });
    return owned;
  };
  const message = async (owned, event) => {
    const deadline = Date.now() + 90000,
      file = path.join(owned.protocol, `event-${event}.json`);
    while (Date.now() < deadline) {
      if (fs.existsSync(file)) {
        const stat = fs.lstatSync(file);
        assert.equal(stat.isSymbolicLink(), false);
        assert.ok(stat.isFile() && stat.size <= 131072);
        const value = JSON.parse(fs.readFileSync(file, "utf8"));
        assert.equal(value.event, event);
        return value;
      }
      assert.equal(
        owned.closed,
        false,
        `Owned contained child exited before ${event}`,
      );
      await delay(30);
    }
    throw new Error(`Owned contained child timed out before ${event}`);
  };
  const signal = (owned, event) =>
    require("./enrollment-lock-child").publishOwnedProtocol(
      owned.protocol,
      `command-${event}`,
      "1",
    );
  const begin = async (owned) => {
    await message(owned, "ready");
    signal(owned, "go");
  };
  const close = async (owned) => {
    const released = await message(owned, "released");
    assert.equal(released.nativeActive, 0);
    let timer;
    let code;
    try {
      code = await Promise.race([
        owned.exit,
        new Promise((_, reject) => {
          timer = setTimeout(
            () => reject(new Error("Contained participant did not close")),
            10000,
          );
        }),
      ]);
    } finally {
      clearTimeout(timer);
    }
    assert.equal(code, 0);
    const proof = await owned.resource.stopAndDrain();
    assert.equal(proof.rootExitCode, 0);
    assert.equal(proof.activeNativeProcesses, 0);
    owned.nativeDrained = true;
  };
  try {
    assert.equal(
      powershell(
        `[Security.Cryptography.CngKey]::Exists('${containerName}',[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider,[Security.Cryptography.CngKeyOpenOptions]::MachineKey)`,
      ),
      "False",
    );
    keyOwned = true;
    const winner = await start("hold");
    await begin(winner);
    const generated = await message(winner, "generated");
    assert.equal(generated.containerName, containerName);
    assert.ok(generated.csrPem.length < 65536);
    assert.ok(generated.certreqCalls > 0);
    const relative = path.relative(
      path.join(directory, "winner"),
      generated.publicCsrPath,
    );
    assert.ok(
      relative && !relative.startsWith("..") && !path.isAbsolute(relative),
    );
    assert.equal(
      fs.existsSync(generated.removedReqPath),
      false,
      "Product temporary request must not be treated as durable CSR state",
    );
    const csrBytes = fs.readFileSync(generated.publicCsrPath),
      csrFile = path.join(directory, "winner.csr");
    fs.writeFileSync(csrFile, generated.csrPem);
    const publicKey = crypto.createPublicKey(
        run("openssl", ["req", "-in", csrFile, "-pubkey", "-noout"]),
      ),
      spki = publicKey.export({ type: "spki", format: "der" }),
      before = snapshot();
    assert.equal(before.name, containerName);
    assert.equal(before.provider, "Microsoft Software Key Storage Provider");
    assert.equal(before.policy, 0);
    assert.equal(before.machine, true);
    assert.equal(before.bits, 2048);
    const sign = () => {
      const nonce = crypto.randomBytes(32),
        signature = powershell(
          `$k=[Security.Cryptography.CngKey]::Open('${containerName}',[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider,[Security.Cryptography.CngKeyOpenOptions]::MachineKey);$r=$null;try{$r=[Security.Cryptography.RSACng]::new($k);[Convert]::ToBase64String($r.SignData([Convert]::FromBase64String('${nonce.toString("base64")}'),[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1))}finally{if($r){$r.Dispose()};$k.Dispose()}`,
        );
      assert.equal(
        crypto.verify(
          "sha256",
          nonce,
          publicKey,
          Buffer.from(signature, "base64"),
        ),
        true,
      );
    };
    sign();
    const loser = await start("attempt");
    await begin(loser);
    const denied = await message(loser, "locked");
    assert.equal(denied.code, "ENROLLMENT_LOCKED");
    assert.equal(denied.nativeCalls, 0);
    assert.equal(denied.certreqCalls, 0);
    await close(loser);
    assert.deepEqual(snapshot(), before);
    assert.deepEqual(fs.readFileSync(generated.publicCsrPath), csrBytes);
    sign();
    signal(winner, "release");
    await close(winner);
    const retry = await start("attempt");
    await begin(retry);
    const refused = await message(retry, "collision");
    assert.equal(refused.reason, "enrollment_container_exists");
    assert.equal(refused.certreqCalls, 0);
    assert.ok(refused.nativeCalls > 0);
    await close(retry);
    assert.deepEqual(snapshot(), before);
    assert.deepEqual(fs.readFileSync(generated.publicCsrPath), csrBytes);
    assert.deepEqual(
      crypto
        .createPublicKey(
          run("openssl", ["req", "-in", csrFile, "-pubkey", "-noout"]),
        )
        .export({ type: "spki", format: "der" }),
      spki,
    );
    sign();
    facts = {
      winnerGeneratedRealCsr: true,
      loserLockedBeforeNativeExecution: true,
      retryAcquiredEnrollmentLock: true,
      retryExistingContainerRefused: true,
      sameCsrAndSpki: true,
      sameNonExportableKey: true,
      winnerSignatureVerified: true,
      loserNativeCalls: denied.nativeCalls,
      loserCertreqCalls: denied.certreqCalls,
      retryCertreqCalls: refused.certreqCalls,
      winnerCertreqCalls: generated.certreqCalls,
      retryNativeCalls: refused.nativeCalls,
    };
  } catch (error) {
    primary = error;
  } finally {
    for (const owned of children) {
      try {
        assert.ok(
          owned.resource,
          "Contained resource must register before launch",
        );
        const proof = await owned.resource.stopAndDrain();
        assert.equal(proof.activeNativeProcesses, 0);
        owned.nativeDrained = true;
      } catch (error) {
        errors.push(error);
      }
    }
    if (keyOwned && children.some((owned) => !owned.nativeDrained))
      errors.push(
        new Error(
          "Retain owned key after unverified native process-tree drain",
        ),
      );
    if (keyOwned && children.every((owned) => owned.nativeDrained))
      try {
        powershell(
          `$p=[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider;$o=[Security.Cryptography.CngKeyOpenOptions]::MachineKey;if([Security.Cryptography.CngKey]::Exists('${containerName}',$p,$o)){$k=[Security.Cryptography.CngKey]::Open('${containerName}',$p,$o);try{$k.Delete()}finally{$k.Dispose()}};if([Security.Cryptography.CngKey]::Exists('${containerName}',$p,$o)){throw 'Owned enrollment key remains'}`,
        );
      } catch (error) {
        errors.push(error);
      }
  }
  if (primary || errors.length)
    throw new AggregateError(
      [...(primary ? [primary] : []), ...errors],
      "Enrollment contention or owned cleanup failed",
    );
  contained.assertCleanupSafe(workDir);
  assert.equal(fs.lstatSync(guard, { bigint: true }).ino, guardStat.ino);
  assert.ok(fs.readFileSync(guard).equals(guardBytes));
  fs.unlinkSync(guard);
  active.delete(path.resolve(workDir));
  facts.ownedChildrenStopped = true;
  facts.ownedKeyRemoved = true;
  verifyContentionFacts(facts);
  return facts;
}
module.exports = {
  qualifyEnrollmentContention,
  verifyContentionFacts,
  assertCleanupSafe,
};
