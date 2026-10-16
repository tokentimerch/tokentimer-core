"use strict";
/** Supporting native Windows file-access refusals on run-owned temporary state.
 * Real ReadData deny ACEs exercise production readers with successful before/
 * restored-after controls. No service, registry, CNG, certificate or network
 * operation runs; this is not installed-service startup qualification. */
const assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), crypto = require("node:crypto");
const config = require("../../src/config");
const scenarios = ["windows-state-config-read-denied", "windows-state-credential-read-denied", "windows-state-signing-pin-read-denied"];
const fields = ["threeReadablePositiveControls", "threeActualNativeReadDenials", "productionReadersRefused", "exactFileIdentityAndBytesPreserved", "exactAclRestored", "allReadersRecovered", "ownedTemporaryStateRemoved"];
const requiredSources = ["packages/agent/scripts/host/state-read-refusal-fixture.js", "packages/agent/src/config/index.js", "packages/agent/src/platform/index.js"];
const preserveGuardName = ".preserve-state-read-refusal.json";
function assertCleanupSafe(directory) { assert.equal(fs.existsSync(path.join(directory, preserveGuardName)), false, "Preserve owned state because exact ACL restoration was not proven"); }
function verifyProof(proof) {
  assert.deepEqual(Object.keys(proof).sort(), [...fields, "scope", "installedServiceStartupQualified"].sort());
  assert.equal(proof.scope, "native-temporary-state-read-denials-production-readers"); assert.equal(proof.installedServiceStartupQualified, false);
  for (const field of fields) assert.equal(proof[field], true, field);
}
async function qualifyStateReadRefusals({ gate, powershell: ps, workDir }) {
  assert.equal(process.platform, "win32"); assert.ok(gate && typeof gate.scenario === "function");
  assertCleanupSafe(workDir);
  const directory = fs.mkdtempSync(path.join(workDir, "state-read-refusal-")), identity = fs.statSync(directory, { bigint: true }).ino;
  const quote = value => value.replace(/'/g, "''");
  const assertDirectory = () => { assert.equal(fs.lstatSync(directory).isSymbolicLink(), false); assert.equal(fs.statSync(directory, { bigint: true }).ino, identity); assert.equal(path.resolve(fs.realpathSync(directory)).toLowerCase(), path.resolve(directory).toLowerCase()); };
  const digest = file => crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
  let primary, preserve = false; const cleanupErrors = [];
  try {
    config.ensureConfigDir(directory); fs.writeFileSync(path.join(directory, "config.json"), JSON.stringify({ serverUrl: "https://state-refusal.example.test", execution: { enabled: false, dryRun: true } }));
    const credential = "ttagent_owned-fixture_" + crypto.randomBytes(32).toString("base64url"); config.writeCredential(directory, credential);
    const publicKeyPem = crypto.generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" });
    config.writeSigningKeyPin(directory, { signingKeyId: "owned-state-refusal", signingPublicKeyPem: publicKeyPem });
    const cases = [
      { file: "config.json", read: () => config.loadAgentConfig({ configDir: directory }), validate: value => { assert.equal(value.serverUrl, "https://state-refusal.example.test"); assert.equal(value.execution.enabled, false); assert.equal(value.execution.dryRun, true); } },
      { file: "credential", read: () => config.readCredential(directory), validate: value => assert.equal(value === credential, true, "Owned credential identity must match without exposing contents") },
      { file: "signing-key-pin.json", read: () => config.readSigningKeyPin(directory), validate: value => { assert.equal(value?.signingKeyId, "owned-state-refusal"); assert.equal(value?.publicKeyPem === publicKeyPem, true, "Owned signing public key must match"); } },
    ];
    for (const [index, item] of cases.entries()) await gate.scenario(scenarios[index], async () => {
      assertDirectory(); item.validate(item.read()); const file = path.join(directory, item.file), before = digest(file), fileId = fs.statSync(file, { bigint: true }).ino;
      const sddl = ps(`(Get-Acl -LiteralPath '${quote(file)}').GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All)`);
      assert.ok(sddl && !sddl.includes("'")); let attempted = false, guardFileId;
      const guardFile = path.join(workDir, preserveGuardName), guardBytes = JSON.stringify({ reason: "exact-acl-restoration-unproven", directory, directoryFileId: String(identity), token: crypto.randomUUID() });
      const assertFile = () => { assertDirectory(); assert.equal(fs.lstatSync(file).isSymbolicLink(), false); assert.equal(fs.statSync(file, { bigint: true }).ino, fileId); };
      try {
        assertFile(); fs.writeFileSync(guardFile, guardBytes, { flag: "wx" }); guardFileId = fs.statSync(guardFile, { bigint: true }).ino; attempted = true;
        ps(`$p='${quote(file)}';$a=[Security.AccessControl.FileSecurity]::new();$a.SetSecurityDescriptorSddlForm('${sddl}',[Security.AccessControl.AccessControlSections]::Access);$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User;$r=[Security.AccessControl.FileSystemAccessRule]::new($sid,[Security.AccessControl.FileSystemRights]::ReadData,[Security.AccessControl.AccessControlType]::Deny);$a.AddAccessRule($r);[IO.File]::SetAccessControl($p,$a)`);
        assert.throws(() => fs.readFileSync(file), error => ["EACCES", "EPERM"].includes(error.code), "Actual OS read denial required before production refusal can count");
        assert.throws(item.read, "Production state reader must refuse actual unreadable state");
      } finally {
        if (attempted) {
          try {
            assertFile(); ps(`$a=[Security.AccessControl.FileSecurity]::new();$a.SetSecurityDescriptorSddlForm('${sddl}',[Security.AccessControl.AccessControlSections]::Access);[IO.File]::SetAccessControl('${quote(file)}',$a)`);
            assert.equal(ps(`(Get-Acl -LiteralPath '${quote(file)}').GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All)`) === sddl, true, "Exact native ACL was not restored");
            assert.equal(fs.lstatSync(guardFile).isSymbolicLink(), false); assert.equal(fs.statSync(guardFile, { bigint: true }).ino, guardFileId); assert.equal(fs.readFileSync(guardFile, "utf8") === guardBytes, true, "Owned ACL guard identity changed"); fs.unlinkSync(guardFile);
          } catch (error) { preserve = true; throw error; }
        }
      }
      assertFile(); assert.equal(digest(file) === before, true, "Owned state bytes changed");
      item.validate(item.read());
    }, { evidenceLevel: "real-host", oracle: "Actual native ReadData denial independently observed before production reader refusal; exact temporary-file identity, bytes and original ACL restored with successful recovery read; no SCM startup claim" });
  } catch (error) { primary = error; }
  finally {
    try { assertCleanupSafe(workDir); assert.equal(preserve, false); assertDirectory(); const parent = path.resolve(workDir), target = path.resolve(directory); assert.ok(target.startsWith(parent + path.sep) && path.basename(target).startsWith("state-read-refusal-")); fs.rmSync(target, { recursive: true }); assert.equal(fs.existsSync(target), false); } catch (error) { cleanupErrors.push(error); }
  }
  if (primary || cleanupErrors.length) throw new AggregateError([...(primary ? [primary] : []), ...cleanupErrors], "Owned state read-refusal qualification failed");
  const proof = { scope: "native-temporary-state-read-denials-production-readers", installedServiceStartupQualified: false, ...Object.fromEntries(fields.map(field => [field, true])) }; verifyProof(proof); return proof;
}
module.exports = { scenarios, fields, requiredSources, verifyProof, qualifyStateReadRefusals, assertCleanupSafe, preserveGuardName };
