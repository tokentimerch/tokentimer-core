"use strict";
// Proves fixture parsing, revoked OCSP response shape, and separation from
// signed-good availability. Native lab execution is still pending. No
// Microsoft responder, CA request, service, certificate store, or native verdict.
const test = require("node:test"),
  assert = require("node:assert/strict"),
  crypto = require("node:crypto");
const subject = require("../tests/e2e/helpers/certops-adcs-ocsp-revoked");
const fs = require("node:fs"),
  path = require("node:path"),
  { spawnSync } = require("node:child_process");
function der(tag, ...parts) {
  const bytes = Buffer.concat(parts);
  let size = Buffer.from([bytes.length]);
  if (bytes.length >= 128) {
    let hex = bytes.length.toString(16);
    if (hex.length % 2) hex = "0" + hex;
    const length = Buffer.from(hex, "hex");
    size = Buffer.concat([Buffer.from([128 + length.length]), length]);
  }
  return Buffer.concat([Buffer.from([tag]), size, bytes]);
}
const seq = (...parts) => der(0x30, ...parts),
  algorithm = Buffer.from("300d06092a864886f70d01010b0500", "hex");
const keys = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const name = (text) =>
  seq(
    der(
      0x31,
      seq(Buffer.from("0603550403", "hex"), der(0x0c, Buffer.from(text))),
    ),
  );
const caName = name("PUBLIC software revocation CA");
const time = (ms) =>
  der(
    0x18,
    Buffer.from(
      new Date(ms)
        .toISOString()
        .replace(/[-:T]/g, "")
        .replace(/\.\d{3}Z$/, "Z"),
    ),
  );
function signed(body) {
  return seq(
    body,
    algorithm,
    der(0x03, Buffer.from([0]), crypto.sign("sha256", body, keys.privateKey)),
  );
}
function certificate(serial, ca = false) {
  return signed(
    seq(
      Buffer.from("a003020102", "hex"),
      der(2, Buffer.from([serial])),
      algorithm,
      caName,
      seq(time(Date.now() - 86400000), time(Date.now() + 7 * 86400000)),
      ca ? caName : name("PUBLIC software leaf " + serial),
      keys.publicKey.export({ format: "der", type: "spki" }),
      der(
        0xa3,
        seq(
          seq(
            Buffer.from("0603551d130101ff", "hex"),
            der(4, ca ? seq(Buffer.from([1, 1, 255])) : seq()),
          ),
        ),
      ),
    ),
  );
}
const issuerDer = certificate(1, true),
  historicalDer = certificate(2),
  currentDer = certificate(3);
const issuerKeySha256 = crypto
  .createHash("sha256")
  .update(keys.publicKey.export({ format: "der", type: "spki" }))
  .digest("hex");
function crl(number, serials = []) {
  return signed(
    seq(
      Buffer.from([2, 1, 1]),
      algorithm,
      caName,
      time(Date.now() - 60000),
      time(Date.now() + 2 * 86400000),
      ...(serials.length
        ? [
            seq(
              ...serials.map((serial) =>
                seq(der(2, Buffer.from([serial])), time(Date.now() - 30000)),
              ),
            ),
          ]
        : []),
      der(
        0xa0,
        seq(
          seq(
            Buffer.from("0603551d14", "hex"),
            der(4, der(2, Buffer.from([number]))),
          ),
        ),
      ),
    ),
  );
}
function publication(originalCrl = crl(0), revokedCrl = crl(1, [2])) {
  return {
    originalCrl,
    revokedCrl,
    issuerDer,
    issuerKeySha256,
    historicalDer,
    currentDer,
  };
}
test("actual signed CRL transition binds only the historical issued leaf and advances native CRL number", () => {
  const result = subject.verifyRevokedPublication(publication());
  assert.equal(result.originalCrlNumber, "0");
  assert.equal(result.revokedCrlNumber, "1");
  assert.equal(result.historicalSerial, "2");
  assert.notEqual(result.originalCrlSha256, result.revokedCrlSha256);
  for (const input of [
    publication(crl(0), crl(1)),
    publication(crl(0), crl(1, [2, 3])),
    publication(crl(1), crl(1, [2])),
    publication(crl(0, [2]), crl(1, [2])),
    publication(crl(0), crl(1, [2, 2])),
  ])
    assert.throws(() => subject.verifyRevokedPublication(input));
  const tampered = publication();
  tampered.revokedCrl = Buffer.from(tampered.revokedCrl);
  tampered.revokedCrl[tampered.revokedCrl.length - 1] ^= 1;
  assert.throws(() => subject.verifyRevokedPublication(tampered));
  assert.throws(() =>
    subject.verifyRevokedPublication({
      ...publication(),
      issuerKeySha256: "0".repeat(64),
    }),
  );
});
test("both complete native inventories must exclude historical A and contain current B", () => {
  const a = "A".repeat(40),
    b = "B".repeat(40),
    row = { thumbprint: b };
  assert.equal(subject.verifyUnservedInventory(a, b, [row], [row]), true);
  for (const [iis, http] of [
    [[row, { thumbprint: a }], [row]],
    [[row], [{ thumbprint: a }]],
    [[row], []],
    [[row], [{ thumbprint: null }]],
    [[{ thumbprint: b.toLowerCase() }], [row]],
  ])
    assert.throws(() => subject.verifyUnservedInventory(a, b, iis, http));
});
test("revoked proof is closed and cross-bound to the exact installed predecessor/successor pair", () => {
  const fixture = require("./fixtures/certops-adcs-ocsp-revoked.cjs").proof,
    base = require("./fixtures/certops-adcs-ocsp.cjs").proof(),
    signedGood = require("../tests/e2e/helpers/certops-adcs-ocsp-proof");
  assert.ok(subject.verifyCrossProof(fixture(), base));
  assert.equal(base.authoritativeRevokedStatusQualified, false);
  assert.equal(fixture().authoritativeRevokedStatusQualified, true);
  assert.notEqual(base.scope, subject.SCOPE);
  assert.equal(base.nativeVerdicts.join(","), "valid,revocation_unknown,valid");
  assert.throws(() => subject.verifyProof(base));
  assert.throws(() => signedGood.verifyProof(fixture()));
  for (const key of subject.FIELDS) {
    const value = fixture();
    delete value[key];
    assert.throws(() => subject.verifyProof(value));
  }
  for (const flag of subject.FLAGS)
    for (const bad of [false, 1])
      assert.throws(() => subject.verifyProof({ ...fixture(), [flag]: bad }));
  for (const patch of [
    { caRequestCounts: [42, 43] },
    { revokedCrlNumber: "0" },
    { historicalRequestId: 42 },
    { installedAgentRevokedLeafRefusalQualified: true },
    { authoritativeUnknownStatusQualified: true },
    { privateContainer: "sentinel" },
  ])
    assert.throws(() =>
      subject.verifyCrossProof({ ...fixture(), ...patch }, base),
    );
  for (const patch of [
    { historicalRequestId: 43 },
    { currentFingerprint: "e".repeat(64) },
    { originalCrlSha256: "0".repeat(64) },
  ])
    assert.throws(() =>
      subject.verifyCrossProof({ ...fixture(), ...patch }, base),
    );
});
test("delegated revoked response shape requires an independent revoked verdict", () => {
  const response = require("../tests/e2e/helpers/certops-adcs-ocsp-response");
  const signerKeys = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const leafKeys = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const extension = (oidHex, content) =>
    seq(Buffer.from(oidHex, "hex"), der(0x04, content));
  function certificateFor(serial, publicKey, role) {
    const extensions = [
      seq(
        Buffer.from("0603551d130101ff", "hex"),
        der(4, role === "ca" ? seq(Buffer.from([1, 1, 255])) : seq()),
      ),
    ];
    if (role !== "ca")
      extensions.push(extension("0603551d0f", Buffer.from([3, 2, 7, 128])));
    if (role === "signer") {
      extensions.push(
        extension(
          "0603551d25",
          seq(Buffer.from("06082b06010505070309", "hex")),
        ),
      );
      extensions.push(
        extension("06092b0601050507300105", Buffer.from([5, 0])),
      );
    }
    return signed(
      seq(
        Buffer.from("a003020102", "hex"),
        der(2, Buffer.from([serial])),
        algorithm,
        caName,
        seq(time(Date.now() - 86400000), time(Date.now() + 7 * 86400000)),
        role === "ca"
          ? caName
          : name(
              role === "signer"
                ? "PUBLIC delegated signer"
                : "PUBLIC historical leaf",
            ),
        publicKey.export({ format: "der", type: "spki" }),
        der(0xa3, seq(...extensions)),
      ),
    );
  }
  const issuerBytes = certificateFor(1, keys.publicKey, "ca"),
    signerBytes = certificateFor(4, signerKeys.publicKey, "signer"),
    leafBytes = certificateFor(3, leafKeys.publicKey, "leaf");
  const options = {
    issuerBytes,
    signerBytes,
    leafBytes,
    expectedCaKeySha256: issuerKeySha256,
  };
  const issuer = new crypto.X509Certificate(issuerBytes),
    signer = new crypto.X509Certificate(signerBytes),
    issuerParts = response.certificateParts(issuer),
    signerBits = response.certificateParts(signer).publicBits;
  function ocsp(status, reason) {
    const now = Date.now();
    const id = seq(
      Buffer.from("300906052b0e03021a0500", "hex"),
      der(4, crypto.createHash("sha1").update(issuerParts.subject).digest()),
      der(
        4,
        crypto.createHash("sha1").update(issuerParts.publicBits).digest(),
      ),
      der(2, Buffer.from([3])),
    );
    const state =
      status === "revoked"
        ? der(
            0xa1,
            time(now - 60000),
            ...(reason === undefined
              ? []
              : [der(0xa0, der(0x0a, Buffer.from([reason])))]),
          )
        : der(status === "good" ? 0x80 : 0x82);
    const data = seq(
      der(0xa2, der(4, crypto.createHash("sha1").update(signerBits).digest())),
      time(now - 1000),
      seq(
        seq(id, state, time(now - 30000), der(0xa0, time(now + 3600000))),
      ),
    );
    const basic = seq(
      data,
      algorithm,
      der(
        3,
        Buffer.from([0]),
        crypto.sign("sha256", data, signerKeys.privateKey),
      ),
      der(0xa0, seq(signerBytes)),
    );
    return seq(
      Buffer.from([0x0a, 1, 0]),
      der(
        0xa0,
        seq(Buffer.from("06092b0601050507300101", "hex"), der(4, basic)),
      ),
    );
  }
  const admitted = subject.verifyRevokedResponse(
    ocsp("revoked"),
    options,
    "revoked",
  );
  assert.equal(admitted.status, "revoked");
  assert.equal(admitted.serialNumber, "3");
  assert.match(admitted.revocationTime, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/);
  assert.equal(
    subject.verifyRevokedResponse(ocsp("revoked", 1), options, "revoked").status,
    "revoked",
  );
  assert.throws(() =>
    subject.verifyRevokedResponse(ocsp("revoked", 7), options, "revoked"),
  );
  for (const status of ["good", "unknown"])
    assert.throws(() =>
      subject.verifyRevokedResponse(ocsp(status), options, "revoked"),
    );
  assert.throws(() =>
    subject.verifyRevokedResponse(ocsp("revoked"), options, "valid"),
  );
});
test("revoked fixture source parses without the disposable lab", () => {
  const root = path.resolve(__dirname, ".."),
    revoked = fs.readFileSync(
      path.join(root, "infra/certops-adcs/ocsp-revoked-fixture.ps1"),
      "utf8",
    ),
    broker = fs.readFileSync(
      path.join(root, "infra/certops-adcs/ocsp-member-operation.ps1"),
      "utf8",
    );
  for (const name of [
    "Get-OwnedOcspHistoricalRequest",
    "Assert-OwnedOcspOriginalService",
    "Invoke-OwnedOcspHistoricalRevocation",
    "Get-OwnedOcspProviderFingerprint",
    "Set-OwnedOcspRevokedProvider",
  ])
    assert.equal(revoked.split(`function ${name}`).length, 2, name);
  assert.match(broker, /'RevokeHistorical','RefreshHistoricalRevocation'/);
  assert.match(broker, /ocsp-revoked-fixture\.ps1/);
  assert.doesNotMatch(revoked, /New-PSSession|Install-WindowsFeature/);
});
test("historical revocation fails closed when the disposable lab is absent", async () => {
  const saved = process.env.CERTOPS_ADCS_DISPOSABLE_LAB;
  delete process.env.CERTOPS_ADCS_DISPOSABLE_LAB;
  try {
    await assert.rejects(() => subject.qualifyHistoricalRevoked({}));
  } finally {
    if (saved === undefined) delete process.env.CERTOPS_ADCS_DISPOSABLE_LAB;
    else process.env.CERTOPS_ADCS_DISPOSABLE_LAB = saved;
  }
});
test("actual managed native-provider fingerprint preserves ordering, variant types and unchanged fields", () => {
  const root = path.resolve(__dirname, ".."),
    file = path.join(root, "infra/certops-adcs/ocsp-revoked-fixture.ps1");
  const source = fs.readFileSync(file, "utf8");
  assert.ok(source.includes("$after=$before.Clone()"));
  assert.ok(source.includes("$entry.ProviderProperties=$after"));
  const script = `$ErrorActionPreference='Stop';$file='${file.replace(/'/g, "''")}';$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($file,[ref]$tokens,[ref]$errors);if($errors.Count){throw 'Invalid managed policy source'};$functions=@($ast.FindAll({param($n) $n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-ceq'Get-OwnedOcspProviderFingerprint'},$true));if($functions.Count-ne 1){throw 'Exact managed policy required'};. ([scriptblock]::Create($functions[0].Extent.Text));$p=[Array]::CreateInstance([object],3,2);$p[0,0]='BaseCrl';$p[0,1]=[byte[]]@(1,2,3);$p[1,0]='RevocationErrorCode';$p[1,1]=[int]0;$p[2,0]='BaseCrlUrls';$p[2,1]=[string[]]@('http://PUBLIC.invalid/owned');$a=Get-OwnedOcspProviderFingerprint $p;$copy=$p.Clone();$copy[0,1]=[byte[]]@(4,5,6);$b=Get-OwnedOcspProviderFingerprint $copy;if($a-eq$b-or$a-cne(Get-OwnedOcspProviderFingerprint $p)){throw 'Actual clone did not preserve original snapshot'};$copy=$p.Clone();$copy[1,1]=[uint32]0;if($a-ceq(Get-OwnedOcspProviderFingerprint $copy)){throw 'Native variant kind was lost'};$copy=$p.Clone();$copy[2,1]=[string[]]@('http://PUBLIC.invalid/foreign');if($a-ceq(Get-OwnedOcspProviderFingerprint $copy)){throw 'Native unrelated URL was lost'};'passed'`;
  const result = spawnSync(
    process.platform === "win32" ? "powershell.exe" : "pwsh",
    ["-NoProfile", "-NonInteractive", "-Command", script],
    { encoding: "utf8", timeout: 10000 },
  );
  assert.equal(result.error, undefined, result.error && result.error.message);
  assert.equal(
    result.status,
    0,
    "Managed provider policy must execute without native constructors",
  );
  assert.equal(result.stdout.trim(), "passed");
});
