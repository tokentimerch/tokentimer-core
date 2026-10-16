"use strict";
/** Replacement prerequisite for the isolated WebHosting expiry journey.
 * One owned CNG leaf lives in My; an owned WebHosting CERTIFICATE-ONLY mirror
 * shares that key. The mirror is removed without DeleteKey, then My custody is
 * independently re-proved before the original fixture certificate/key cleanup.
 * Failure preserves the durable owner and public/private fixture files.
 */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto"),
  { isDeepStrictEqual } = require("node:util");
const cng = require("../../src/windows-cert-store"),
  discovery = require("../../src/windows-discovery"),
  platform = require("../../src/platform");
const GUARD = ".preserve-webhosting-replacement.json",
  active = new Set();
const REQUIRED_SOURCES = Object.freeze([
  "packages/agent/scripts/host/retention-webhosting-replacement.js",
  "packages/agent/src/windows-cert-store/index.js",
  "packages/agent/src/windows-key-survivors/index.js",
  "packages/agent/src/windows-discovery/index.js",
  "packages/agent/src/platform/index.js",
]);
const owner = (root) => path.resolve(root).toLowerCase();
function assertCleanupSafe(root) {
  assert.ok(
    !active.has(owner(root)) && !fs.existsSync(path.join(root, GUARD)),
    "Preserve unresolved borrowed replacement certificate/key ownership",
  );
}
function custodyScript(store, thumb) {
  assert.ok(["My", "WebHosting"].includes(store));
  assert.match(thumb, /^[A-F0-9]{40}$/);
  return `$c=Get-Item -LiteralPath 'Cert:\\LocalMachine\\${store}\\${thumb}' -ErrorAction Stop;$k=$null;try{$k=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c);if(!$k -or $k -isnot [Security.Cryptography.RSACng]){throw 'Owned replacement RSA CNG key required'};@{der=[Convert]::ToBase64String($c.RawData);name=$k.Key.KeyName;unique=$k.Key.UniqueName;provider=$k.Key.Provider.Provider;machine=$k.Key.IsMachineKey;exportPolicy=[string]$k.Key.ExportPolicy}|ConvertTo-Json -Compress}finally{if($k){$k.Dispose()};$c.Dispose()}`;
}
function sameCustody(a, b) {
  assert.ok(
    isDeepStrictEqual(a, b),
    "Original replacement native custody changed",
  );
}
function removalScript(store, thumb, expected) {
  assert.ok(["My", "WebHosting", "Root"].includes(store));
  assert.match(thumb, /^[A-F0-9]{40}$/);
  assert.match(expected, /^[a-f0-9]{64}$/);
  return `$p='Cert:\\LocalMachine\\${store}\\${thumb}';$c=Get-Item -LiteralPath $p -ErrorAction Stop;$h=[Security.Cryptography.SHA256]::Create();try{$d=([BitConverter]::ToString($h.ComputeHash($c.RawData))).Replace('-','').ToLowerInvariant();if($d -cne '${expected}'){throw 'Owned replacement DER changed'}}finally{$h.Dispose();$c.Dispose()};Remove-Item -LiteralPath $p -ErrorAction Stop;if(Test-Path -LiteralPath $p){throw 'Owned certificate remains'}`;
}
async function prepareReplacement({ workDir, powershell, run }) {
  assert.equal(process.platform, "win32");
  assert.equal(process.env.CERTOPS_HOST_TESTS, "1");
  assertCleanupSafe(workDir);
  const stat = fs.lstatSync(workDir, { bigint: true });
  assert.ok(stat.isDirectory() && !stat.isSymbolicLink() && stat.ino > 0n);
  const assertRoot = () => {
    const now = fs.lstatSync(workDir, { bigint: true });
    assert.ok(
      now.isDirectory() &&
        !now.isSymbolicLink() &&
        now.dev === stat.dev &&
        now.ino === stat.ino,
    );
    assert.equal(
      fs.realpathSync(workDir).toLowerCase(),
      path.resolve(workDir).toLowerCase(),
    );
  };
  const guard = path.join(workDir, GUARD),
    guardBytes = Buffer.from(
      JSON.stringify({ schemaVersion: 1, nonce: crypto.randomUUID() }),
    );
  active.add(owner(workDir));
  fs.writeFileSync(guard, guardBytes, { flag: "wx", mode: 0o600 });
  platform.applyRestrictivePermissions(guard, { kind: "file" });
  const guardId = fs.lstatSync(guard, { bigint: true });
  const caKey = path.join(workDir, "ca.key"),
    caCert = path.join(workDir, "ca.pem");
  run("openssl", [
    "req",
    "-x509",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-keyout",
    caKey,
    "-out",
    caCert,
    "-days",
    "2",
    "-subj",
    "/CN=CertOps Disposable WebHosting Expiry CA",
    "-addext",
    "basicConstraints=critical,CA:TRUE",
    "-addext",
    "keyUsage=critical,keyCertSign,cRLSign",
  ]);
  platform.applyRestrictivePermissions(caKey, { kind: "file" });
  const rootCertificate = new crypto.X509Certificate(fs.readFileSync(caCert)),
    rootThumb = rootCertificate.fingerprint.replace(/:/g, ""),
    rootDer = crypto
      .createHash("sha256")
      .update(rootCertificate.raw)
      .digest("hex");
  assert.equal(
    powershell(
      `[string](Test-Path -LiteralPath 'Cert:\\LocalMachine\\Root\\${rootThumb}')`,
    ),
    "False",
  );
  run("certutil.exe", ["-addstore", "Root", caCert]);
  const inventory = async () => {
    const value = await discovery.listMachineStoreCertificates({ store: "My" });
    assert.equal(value.ok, true);
    return value.certificates.sort((a, b) =>
      a.thumbprint.localeCompare(b.thumbprint),
    );
  };
  const pristineMy = await inventory();
  const enrollmentId = crypto.randomUUID(),
    container = cng.buildEnrollmentContainerName(enrollmentId);
  const exists = () =>
    powershell(
      `[string][Security.Cryptography.CngKey]::Exists('${container}',[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider,[Security.Cryptography.CngKeyOpenOptions]::MachineKey)`,
    );
  assert.equal(exists(), "False");
  const csr = await cng.generateCsrViaCng({
    commonName: "certops-host.invalid",
    altNames: ["certops-host.invalid"],
    algorithm: "rsa-2048",
    enrollmentId,
    workDir,
  });
  assert.equal(csr.ok, true);
  const csrPath = path.join(workDir, "replacement.csr"),
    pemPath = path.join(workDir, "replacement.pem");
  fs.writeFileSync(csrPath, csr.csrPem, { flag: "wx" });
  run("openssl", [
    "x509",
    "-req",
    "-in",
    csrPath,
    "-CA",
    caCert,
    "-CAkey",
    caKey,
    "-CAcreateserial",
    "-out",
    pemPath,
    "-days",
    "1",
    "-copy_extensions",
    "copy",
    "-sha256",
  ]);
  const pem = fs.readFileSync(pemPath, "utf8"),
    certificate = new crypto.X509Certificate(pem),
    thumb = certificate.fingerprint.replace(/:/g, ""),
    derHash = crypto.createHash("sha256").update(certificate.raw).digest("hex");
  assert.equal(certificate.verify(rootCertificate.publicKey), true);
  assert.equal(
    certificate.checkHost("certops-host.invalid"),
    "certops-host.invalid",
  );
  for (const store of ["My", "WebHosting"])
    assert.equal(
      powershell(
        `[string](Test-Path -LiteralPath 'Cert:\\LocalMachine\\${store}\\${thumb}')`,
      ),
      "False",
    );
  assert.equal(
    (
      await cng.acceptCertificateViaCng({
        certificatePem: pem,
        workDir,
        store: "My",
      })
    ).ok,
    true,
  );
  const capture = (store) =>
      JSON.parse(powershell(custodyScript(store, thumb))),
    original = capture("My");
  assert.ok(
    original.name === container,
    "Original owned container association required",
  );
  assert.equal(original.provider, "Microsoft Software Key Storage Provider");
  assert.equal(original.machine, true);
  assert.equal(original.exportPolicy, "None");
  assert.ok(Buffer.from(original.der, "base64").equals(certificate.raw));
  const beforeMy = await inventory();
  const possession = () => {
    const nonce = crypto.randomBytes(32),
      signature = powershell(
        `$c=Get-Item -LiteralPath 'Cert:\\LocalMachine\\My\\${thumb}';$k=$null;try{$k=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c);[Convert]::ToBase64String($k.SignData([Convert]::FromBase64String('${nonce.toString("base64")}'),[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1))}finally{if($k){$k.Dispose()};$c.Dispose()}`,
      );
    assert.equal(
      crypto.verify(
        "sha256",
        nonce,
        certificate.publicKey,
        Buffer.from(signature, "base64"),
      ),
      true,
    );
  };
  possession();
  // This prerequisite intentionally mirrors without the product's final My
  // deletion. It does not claim a second key enrollment or a second key owner.
  run("certutil.exe", ["-addstore", "WebHosting", pemPath]);
  run("certutil.exe", ["-repairstore", "WebHosting", thumb]);
  sameCustody(capture("WebHosting"), original);
  sameCustody(capture("My"), original);
  const verifyBorrowed = async () => {
    assertRoot();
    sameCustody(capture("My"), original);
    sameCustody(capture("WebHosting"), original);
    assert.ok(
      isDeepStrictEqual(await inventory(), beforeMy),
      "Unrelated/original My inventory changed",
    );
    possession();
  };
  await verifyBorrowed();
  let completed = false;
  return {
    replacementPem: pem,
    replacementThumbprint: thumb,
    verifyBorrowed,
    async cleanupAfterSuccessfulCase() {
      assert.equal(completed, false);
      await verifyBorrowed();
      const bindings = await discovery.listHttpSysBindings();
      assert.equal(bindings.ok, true);
      assert.ok(
        !bindings.bindings.some((entry) => entry.thumbprint === thumb),
        "Borrowed replacement remains bound",
      );
      const survivor =
        await require("../../src/windows-key-survivors").inspectMachineKeySurvivors(
          { containerName: container, store: "WebHosting", thumbprint: thumb },
        );
      assert.equal(survivor.ok, true);
      assert.equal(
        survivor.shared,
        true,
        "Original My certificate must protect the shared replacement key",
      );
      powershell(removalScript("WebHosting", thumb, derHash));
      sameCustody(capture("My"), original);
      assert.ok(
        isDeepStrictEqual(await inventory(), beforeMy),
        "Removing mirror changed original My inventory",
      );
      possession();
      assert.equal(exists(), "True");
      powershell(removalScript("My", thumb, derHash));
      assert.equal(
        (
          await cng.removeAbandonedKeyContainer({
            containerName: container,
            allowAlreadyAbsent: false,
          })
        ).ok,
        true,
      );
      assert.equal(exists(), "False");
      assert.ok(
        isDeepStrictEqual(await inventory(), pristineMy),
        "Owned replacement cleanup changed preexisting My inventory",
      );
      powershell(removalScript("Root", rootThumb, rootDer));
      assertRoot();
      const end = fs.lstatSync(guard, { bigint: true });
      assert.ok(
        end.isFile() &&
          !end.isSymbolicLink() &&
          end.dev === guardId.dev &&
          end.ino === guardId.ino &&
          fs.readFileSync(guard).equals(guardBytes),
      );
      fs.unlinkSync(guard);
      active.delete(owner(workDir));
      completed = true;
      return {
        sameOriginalMyCustodyAndInventory: true,
        sameOriginalMyPrivateKeyPossession: true,
        mirrorRemovedWithoutDeletingSharedKey: true,
        originalFixtureCertificateAndKeyRemoved: true,
      };
    },
  };
}
module.exports = {
  GUARD,
  REQUIRED_SOURCES,
  assertCleanupSafe,
  custodyScript,
  removalScript,
  sameCustody,
  prepareReplacement,
};
