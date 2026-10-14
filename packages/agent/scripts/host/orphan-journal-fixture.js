"use strict";
/** Supporting native CNG orphan safety controls. Prepared and unresolved journal
 * entries are explicit local prerequisites, not claimed CA requests or installed
 * agent outcomes. Every crypto/store command is real; failed ownership or drain
 * checks retain the private receipt and root for disposable-host teardown. */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto"),
  { isDeepStrictEqual } = require("node:util");
const store = require("../../src/windows-cert-store"),
  journal = require("../../src/issuers/adcs-enrollment-journal"),
  jobs = require("../../src/job-journal");
const { reconcileOrphanedWindowsCngContainers } = require("../../src/index");
const platform = require("../../src/platform");
const scenarios = Object.freeze([
  "windows-native-orphan-open-enrollment-protected",
  "windows-native-orphan-corrupt-journal-protected",
  "windows-native-orphan-closed-journal-and-untracked-key",
]);
const fields = Object.freeze([
  "actualPreparedCngCsr",
  "actualUnresolvedJobPrerequisites",
  "unprotectedNativeOrphanRemoved",
  "openJournalKeyPreserved",
  "corruptJournalFailsClosed",
  "exactJournalBytesRestored",
  "untrackedNativeKeyPreserved",
  "independentPrivateKeyPossession",
  "actualGlobalStoreInventory",
  "terminalFixtureClosureAllowsCleanup",
  "ownedNativeKeysAndStateRemoved",
]);
const scope = "native-cng-supporting-prepared-journal-orphan-protection";
const preserveGuardName = ".preserve-native-orphan-journal.json";
const requiredSources = Object.freeze([
  "packages/agent/scripts/host/orphan-journal-fixture.js",
  "packages/agent/src/index.js",
  "packages/agent/src/job-journal/index.js",
  "packages/agent/src/issuers/adcs-enrollment-journal.js",
  "packages/agent/src/windows-cert-store/index.js",
  "packages/agent/src/windows-key-survivors/index.js",
  "packages/agent/src/platform/index.js",
  "packages/agent/src/config/index.js",
  "packages/agent/vendor/log-scrub/secret-material.js",
]);
function verifyProof(value) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value));
  assert.deepEqual(
    Object.keys(value).sort(),
    [
      "scope",
      "installedServiceQualified",
      "caEnrollmentQualified",
      "orphanAgePolicyQualified",
      ...fields,
    ].sort(),
  );
  assert.equal(value.scope, scope);
  for (const key of [
    "installedServiceQualified",
    "caEnrollmentQualified",
    "orphanAgePolicyQualified",
  ])
    assert.equal(value[key], false);
  for (const key of fields) assert.equal(value[key], true, key);
  return true;
}
function validateFileId(value) {
  assert.ok(
    typeof value === "bigint" && value > 0n,
    "A positive native filesystem identity is required; preserve fixture",
  );
  return String(value);
}
function identity(file) {
  const s = fs.lstatSync(file, { bigint: true });
  assert.equal(s.isSymbolicLink(), false);
  assert.equal(
    fs.realpathSync(file).toLowerCase(),
    path.resolve(file).toLowerCase(),
  );
  return validateFileId(s.ino);
}
function assertFixtureTreeRegular(directory) {
  identity(directory);
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const child = path.join(directory, entry.name);
    identity(child);
    if (entry.isDirectory()) assertFixtureTreeRegular(child);
    else
      assert.equal(
        entry.isFile(),
        true,
        "Only regular owned fixture entries may be removed",
      );
  }
}
function assertCleanupSafe(workDir) {
  assert.equal(
    fs.existsSync(path.join(workDir, preserveGuardName)),
    false,
    "Preserve native orphan keys and fixture ownership receipt",
  );
}
function keyScript(container, nonce, { create = false } = {}) {
  assert.match(container, /^[A-Za-z0-9_-]{1,128}$/);
  assert.match(nonce, /^[a-f0-9]{32}$/);
  return `$ErrorActionPreference='Stop';$name='${container}';$provider=[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider;$options=[Security.Cryptography.CngKeyOpenOptions]::MachineKey;${create ? "if([Security.Cryptography.CngKey]::Exists($name,$provider,$options)){throw 'Untracked control key already exists'};$parameters=[Security.Cryptography.CngKeyCreationParameters]::new();$parameters.Provider=$provider;$parameters.KeyCreationOptions=[Security.Cryptography.CngKeyCreationOptions]::MachineKey;$parameters.ExportPolicy=[Security.Cryptography.CngExportPolicies]::None;$parameters.Parameters.Add([Security.Cryptography.CngProperty]::new('Length',[BitConverter]::GetBytes(2048),[Security.Cryptography.CngPropertyOptions]::None));$created=[Security.Cryptography.CngKey]::Create([Security.Cryptography.CngAlgorithm]::Rsa,$name,$parameters);$created.Dispose();" : ""}$key=[Security.Cryptography.CngKey]::Open($name,$provider,$options);$rsa=$null;try{$rsa=[Security.Cryptography.RSACng]::new($key);$public=$rsa.ExportParameters($false);$bytes=[Text.Encoding]::UTF8.GetBytes('${nonce}');$signature=$rsa.SignData($bytes,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1);$sha=[Security.Cryptography.SHA256]::Create();try{$unique=[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($key.UniqueName))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()};@{uniqueSha256=$unique;machine=$key.IsMachineKey;provider=$key.Provider.Provider;exportPolicy=[int]$key.ExportPolicy;bits=$rsa.KeySize;modulus=[Convert]::ToBase64String($public.Modulus);exponent=[Convert]::ToBase64String($public.Exponent);signature=[Convert]::ToBase64String($signature)}|ConvertTo-Json -Compress}finally{if($rsa){$rsa.Dispose()};$key.Dispose()}`;
}
function verifyObservation(value, nonce) {
  assert.match(nonce, /^[a-f0-9]{32}$/);
  assert.deepEqual(
    Object.keys(value).sort(),
    [
      "uniqueSha256",
      "machine",
      "provider",
      "exportPolicy",
      "bits",
      "modulus",
      "exponent",
      "signature",
    ].sort(),
  );
  assert.equal(value.machine, true);
  assert.equal(value.provider, "Microsoft Software Key Storage Provider");
  assert.equal(value.exportPolicy, 0);
  assert.equal(value.bits, 2048);
  assert.match(value.uniqueSha256, /^[a-f0-9]{64}$/);
  for (const key of ["modulus", "exponent", "signature"])
    assert.ok(typeof value[key] === "string" && value[key].length <= 1024);
  const publicKey = crypto.createPublicKey({
    format: "jwk",
    key: {
      kty: "RSA",
      n: Buffer.from(value.modulus, "base64").toString("base64url"),
      e: Buffer.from(value.exponent, "base64").toString("base64url"),
    },
  });
  assert.equal(
    crypto.verify(
      "sha256",
      Buffer.from(nonce),
      publicKey,
      Buffer.from(value.signature, "base64"),
    ),
    true,
    "Actual native private-key possession required",
  );
  return {
    uniqueSha256: value.uniqueSha256,
    spkiSha256: crypto
      .createHash("sha256")
      .update(publicKey.export({ type: "spki", format: "der" }))
      .digest("hex"),
  };
}
function parseNativeExists(value) {
  assert.ok(
    value === "True" || value === "False",
    "Exact native key-existence boolean required",
  );
  return value === "True";
}
function fixtureContainerNames(protectedId, orphanId, foreignId) {
  const names = {
    protectedContainer: store.buildEnrollmentContainerName(protectedId),
    orphanContainer: store.buildEnrollmentContainerName(orphanId),
    foreignContainer: store.buildEnrollmentContainerName(foreignId),
  };
  assert.equal(
    new Set(Object.values(names)).size,
    3,
    "Distinct deterministic fixture keys required",
  );
  for (const name of Object.values(names))
    assert.equal(store.isAgentOwnedContainerName(name), true);
  return names;
}
async function qualifyOrphanJournals({ gate, powershell, run, workDir }) {
  // Native command diagnostics can contain container identities; expose only a
  // bounded failure while the protected ownership receipt remains local.
  const ps = (script) => {
    try {
      return powershell(script);
    } catch {
      throw new Error(
        "Owned native CNG observation refused; preserve private ownership state",
      );
    }
  };
  assert.equal(process.platform, "win32");
  assertCleanupSafe(workDir);
  assert.equal(typeof powershell, "function");
  assert.equal(typeof run, "function");
  const parentId = identity(workDir),
    directory = fs.mkdtempSync(path.join(workDir, "native-orphan-journal-")),
    directoryId = identity(directory),
    nonce = crypto.randomBytes(16).toString("hex"),
    protectedId = crypto.randomUUID(),
    orphanId = crypto.randomUUID(),
    foreignId = crypto.randomUUID(),
    { protectedContainer, orphanContainer, foreignContainer } =
      fixtureContainerNames(protectedId, orphanId, foreignId),
    guard = path.join(workDir, preserveGuardName);
  platform.applyRestrictivePermissions(directory, { kind: "directory" });
  const receipt = {
    nonce,
    directory,
    keys: [protectedContainer, orphanContainer, foreignContainer],
  };
  fs.writeFileSync(guard, JSON.stringify(receipt), { flag: "wx" });
  platform.applyRestrictivePermissions(guard, { kind: "file" });
  const guardId = identity(guard),
    guardHash = crypto
      .createHash("sha256")
      .update(fs.readFileSync(guard))
      .digest("hex");
  const owned = () => {
    assert.equal(identity(workDir), parentId);
    assert.equal(identity(directory), directoryId);
    assert.equal(identity(guard), guardId);
    assert.equal(
      crypto.createHash("sha256").update(fs.readFileSync(guard)).digest("hex"),
      guardHash,
    );
  };
  const observe = (container) =>
    verifyObservation(JSON.parse(ps(keyScript(container, nonce))), nonce);
  const exists = (container) =>
    parseNativeExists(
      ps(
        `[Security.Cryptography.CngKey]::Exists('${container}',[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider,[Security.Cryptography.CngKeyOpenOptions]::MachineKey)`,
      ),
    );
  const seed = (jobId, containerName) => {
    jobs.markSideEffectReached({
      stateDir: directory,
      jobId,
      attemptId: nonce,
      stage: "keygen",
    });
    jobs.recordWindowsCngContainer({
      stateDir: directory,
      jobId,
      attemptId: nonce,
      containerName,
      store: "My",
    });
    store.recordIssuedContainer({
      stateDir: directory,
      jobId,
      containerName,
      certificateId: crypto.randomUUID(),
    });
  };
  const sweep = () =>
    reconcileOrphanedWindowsCngContainers({ stateDir: directory });
  const proof = {
    scope,
    installedServiceQualified: false,
    caEnrollmentQualified: false,
    orphanAgePolicyQualified: false,
  };
  let journalFile, journalBytes, journalId;
  try {
    require("../../src/config").ensureConfigDir(directory);
    for (const [id, container, enrollment] of [
      [protectedId, protectedContainer, true],
      [orphanId, orphanContainer, false],
    ]) {
      owned();
      assert.equal(exists(container), false, "Refuse existing fixture key");
      const nativeDir = path.join(directory, id);
      fs.mkdirSync(nativeDir);
      const result = await store.generateCsrViaCng({
        commonName: "orphan-journal.example.test",
        altNames: ["orphan-journal.example.test"],
        algorithm: "rsa-2048",
        enrollmentId: id,
        workDir: nativeDir,
      });
      assert.equal(result.ok, true, "Actual CNG CSR generation required");
      assert.equal(result.containerName, container);
      const csrFile = path.join(nativeDir, "public.csr");
      fs.writeFileSync(csrFile, result.csrPem, { flag: "wx" });
      const publicKey = crypto.createPublicKey(
        run("openssl", ["req", "-in", csrFile, "-pubkey", "-noout"]),
      );
      const spki = crypto
        .createHash("sha256")
        .update(publicKey.export({ type: "spki", format: "der" }))
        .digest("hex");
      assert.equal(observe(container).spkiSha256, spki);
      seed(id, container);
      if (enrollment) {
        const { csrSha256 } = await journal.writeCsrArtifact({
          stateDir: directory,
          enrollmentId: id,
          csrPem: result.csrPem,
        });
        await journal.writeEnrollmentJournal(directory, id, {
          state: "prepared",
          attempt: 1,
          containerName: container,
          snapshotSha256: crypto
            .createHash("sha256")
            .update(nonce)
            .digest("hex"),
          csrSha256,
          csrSpkiSha256: spki,
          templateOid: "1.3.6.1.4.1.311.21.8.1",
          jobId: id,
        });
      }
    }
    assert.equal(exists(foreignContainer), false);
    const foreign = verifyObservation(
        JSON.parse(ps(keyScript(foreignContainer, nonce, { create: true }))),
        nonce,
      ),
      protectedKey = observe(protectedContainer);
    journalFile = journal.journalV2Path(directory, protectedId);
    journalBytes = fs.readFileSync(journalFile);
    journalId = identity(journalFile);
    await gate.scenario(
      scenarios[0],
      async () => {
        const result = await sweep();
        assert.deepEqual(result.freed, [orphanContainer]);
        assert.ok(
          result.skipped.some(
            (row) =>
              row.containerName === protectedContainer &&
              /open AD CS enrollment journal/.test(row.reason),
          ),
        );
        assert.equal(exists(orphanContainer), false);
        assert.ok(
          isDeepStrictEqual(observe(protectedContainer), protectedKey),
          "Exact protected native key custody changed",
        );
        assert.ok(
          isDeepStrictEqual(observe(foreignContainer), foreign),
          "Exact untracked native key custody changed",
        );
        assert.equal(
          store.readIssuedContainerRecord({
            stateDir: directory,
            containerName: protectedContainer,
          }).status,
          "generated",
        );
        Object.assign(proof, {
          actualPreparedCngCsr: true,
          actualUnresolvedJobPrerequisites: true,
          unprotectedNativeOrphanRemoved: true,
          openJournalKeyPreserved: true,
          independentPrivateKeyPossession: true,
          actualGlobalStoreInventory: true,
        });
      },
      {
        evidenceLevel: "real-host",
        oracle:
          "Real CNG CSR and explicit prepared/unresolved local prerequisites protect one key while actual production native reconciler deletes a separate unaccepted orphan; no CA/installed-agent outcome is synthesized",
      },
    );
    await gate.scenario(
      scenarios[1],
      async () => {
        owned();
        fs.writeFileSync(journalFile, '{"schemaVersion":999}');
        const result = await sweep();
        assert.deepEqual(result.freed, []);
        assert.ok(
          result.skipped.some(
            (row) =>
              row.containerName === protectedContainer &&
              /journal scan failed/.test(row.reason),
          ),
        );
        assert.ok(
          isDeepStrictEqual(observe(protectedContainer), protectedKey),
          "Exact protected native key custody changed",
        );
        assert.ok(
          isDeepStrictEqual(observe(foreignContainer), foreign),
          "Exact untracked native key custody changed",
        );
        assert.equal(identity(journalFile), journalId);
        fs.writeFileSync(journalFile, journalBytes);
        assert.equal(identity(journalFile), journalId);
        assert.equal(fs.readFileSync(journalFile).equals(journalBytes), true);
        assert.equal(
          journal.readEnrollmentJournal(directory, protectedId).kind,
          "valid",
        );
        Object.assign(proof, {
          corruptJournalFailsClosed: true,
          exactJournalBytesRestored: true,
        });
      },
      {
        evidenceLevel: "real-host",
        oracle:
          "Actual malformed owned journal causes fail-closed production orphan reconciliation; exact native key possession and unrelated untracked key remain, then exact original journal bytes and file identity recover",
      },
    );
    await gate.scenario(
      scenarios[2],
      async () => {
        owned();
        const prior = journal.readEnrollmentJournal(directory, protectedId);
        assert.equal(prior.kind, "valid");
        await journal.writeEnrollmentJournal(directory, protectedId, {
          ...prior.journal,
          state: "abandoned",
        });
        const result = await sweep();
        assert.deepEqual(result.freed, [protectedContainer]);
        assert.equal(exists(protectedContainer), false);
        assert.ok(
          isDeepStrictEqual(observe(foreignContainer), foreign),
          "Exact untracked native key custody changed",
        );
        const removed = await store.removeAbandonedKeyContainer({
          containerName: foreignContainer,
        });
        assert.equal(
          removed.ok,
          true,
          "Exact owned untracked fixture key cleanup required",
        );
        assert.equal(exists(foreignContainer), false);
        assert.equal(
          (
            await store.removeAbandonedKeyContainer({
              containerName: foreignContainer,
              requireAlreadyAbsent: true,
            })
          ).ok,
          true,
        );
        Object.assign(proof, {
          untrackedNativeKeyPreserved: true,
          terminalFixtureClosureAllowsCleanup: true,
        });
      },
      {
        evidenceLevel: "real-host",
        oracle:
          "Explicit supporting fixture closure releases only its exact orphan, while the untracked native key survives every sweep and is independently identity-verified before owned cleanup; no orphan-age policy is claimed",
      },
    );
    owned();
    for (const container of receipt.keys)
      assert.equal(
        exists(container),
        false,
        "Every exact owned native key must be absent before removing fixture state",
      );
    assertFixtureTreeRegular(directory);
    fs.rmSync(directory, { recursive: true });
    assert.equal(fs.existsSync(directory), false);
    assert.equal(identity(workDir), parentId);
    assert.equal(identity(guard), guardId);
    assert.equal(
      crypto.createHash("sha256").update(fs.readFileSync(guard)).digest("hex"),
      guardHash,
    );
    fs.unlinkSync(guard);
    proof.ownedNativeKeysAndStateRemoved = true;
    verifyProof(proof);
    return proof;
  } catch (error) {
    throw new AggregateError(
      [error],
      "Native orphan journal qualification failed; preserve guard, journals and exact owned keys for disposable-host teardown",
    );
  }
}
module.exports = {
  qualifyOrphanJournals,
  fixtureContainerNames,
  parseNativeExists,
  validateFileId,
  verifyProof,
  verifyObservation,
  keyScript,
  assertCleanupSafe,
  assertFixtureTreeRegular,
  preserveGuardName,
  requiredSources,
  scenarios,
  fields,
  scope,
};
