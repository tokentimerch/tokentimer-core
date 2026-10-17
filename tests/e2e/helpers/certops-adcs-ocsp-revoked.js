"use strict";

// Proves the closed shape of one historical unserved leaf becoming revoked.
// Native lab execution is still pending. Importing or testing this module
// does not revoke a certificate or configure a responder.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const der = require("./certops-adcs-http-leaf-crl-der");
const response = require("./certops-adcs-ocsp-response");
const discovery = require("../../../packages/agent/src/windows-discovery");
const digest = (bytes) =>
  crypto.createHash("sha256").update(bytes).digest("hex");
const SCENARIO = "adcs-real-ocsp-authoritative-historical-revoked-status";
const SCOPE =
  "native-microsoft-ocsp-historical-unserved-leaf-authoritative-revoked";
const FLAGS = Object.freeze([
  "historicalLeafUnservedBeforeAndAfter",
  "currentReplacementCustodyAndTlsPreserved",
  "exactOwnedNativeCaRequestRevoked",
  "freshSignedCrlAddsHistoricalLeaf",
  "sameOwnedProviderRefreshed",
  "independentDelegatedRevokedResponse",
  "actualCryptoApiRevoked",
  "noNewCaRequest",
  "originalPublicationAndCacheRestored",
  "activeResponderResourcesDrained",
  "ownedCleanupReleased",
  "authoritativeRevokedStatusQualified",
]);
const FALSE_FLAGS = Object.freeze([
  "installedAgentRevokedLeafRefusalQualified",
  "authoritativeUnknownStatusQualified",
]);
const FIELDS = Object.freeze([
  "scope",
  "historicalEnrollmentId",
  "currentEnrollmentId",
  "historicalRequestId",
  "currentRequestId",
  "originalCrlSha256",
  "revokedCrlSha256",
  "originalCrlNumber",
  "revokedCrlNumber",
  "historicalFingerprint",
  "currentFingerprint",
  "historicalSerial",
  "revocationTime",
  "responseSha256",
  "signerFingerprint",
  "issuerKeySha256",
  "nativeVerdict",
  "caRequestCounts",
  ...FLAGS,
  ...FALSE_FLAGS,
]);
function verifyProof(value) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value));
  assert.deepEqual(Object.keys(value).sort(), [...FIELDS].sort());
  assert.equal(value.scope, SCOPE);
  const uuid = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i;
  for (const key of ["historicalEnrollmentId", "currentEnrollmentId"])
    assert.match(value[key], uuid);
  assert.notEqual(
    value.historicalEnrollmentId.toLowerCase(),
    value.currentEnrollmentId.toLowerCase(),
  );
  for (const key of ["historicalRequestId", "currentRequestId"])
    assert.ok(
      Number.isInteger(value[key]) &&
        value[key] >= 1 &&
        value[key] <= 0xffffffff,
    );
  assert.notEqual(value.historicalRequestId, value.currentRequestId);
  for (const key of [
    "originalCrlSha256",
    "revokedCrlSha256",
    "historicalFingerprint",
    "currentFingerprint",
    "responseSha256",
    "signerFingerprint",
    "issuerKeySha256",
  ])
    assert.match(value[key], /^[a-f0-9]{64}$/);
  assert.notEqual(value.originalCrlSha256, value.revokedCrlSha256);
  assert.notEqual(value.historicalFingerprint, value.currentFingerprint);
  for (const key of ["originalCrlNumber", "revokedCrlNumber"])
    assert.match(value[key], /^(0|[1-9][0-9]{0,48})$/);
  assert.ok(BigInt(value.revokedCrlNumber) > BigInt(value.originalCrlNumber));
  assert.match(value.historicalSerial, /^[1-9A-F][A-F0-9]{0,39}$/);
  assert.match(
    value.revocationTime,
    /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/,
  );
  assert.equal(
    new Date(value.revocationTime).toISOString(),
    value.revocationTime,
  );
  assert.equal(value.nativeVerdict, "revoked");
  assert.ok(
    Array.isArray(value.caRequestCounts) &&
      value.caRequestCounts.length === 2 &&
      value.caRequestCounts.every(
        (v) => Number.isInteger(v) && v >= 0 && v <= 2048,
      ),
  );
  assert.equal(value.caRequestCounts[0], value.caRequestCounts[1]);
  for (const flag of FLAGS) assert.equal(value[flag], true);
  for (const flag of FALSE_FLAGS) assert.equal(value[flag], false);
  return value;
}
function verifyCrossProof(value, base) {
  verifyProof(value);
  require("./certops-adcs-ocsp-proof").verifyProof(base);
  assert.equal(value.historicalEnrollmentId, base.enrollmentIds[0]);
  assert.equal(value.currentEnrollmentId, base.enrollmentIds[1]);
  assert.equal(value.historicalRequestId, base.requestIds[0]);
  assert.equal(value.currentRequestId, base.requestIds[1]);
  assert.equal(value.historicalFingerprint, base.leafFingerprints[0]);
  assert.equal(value.currentFingerprint, base.leafFingerprints[1]);
  assert.equal(value.originalCrlSha256, base.publicCrlSha256);
  assert.equal(value.signerFingerprint, base.signerFingerprint);
  assert.equal(value.issuerKeySha256, base.issuerKeySha256);
  assert.equal(value.caRequestCounts[0], base.caRequestCounts.at(-1));
  return value;
}
function positiveInteger(node, allowZero = false) {
  assert.equal(node.tag, 0x02);
  const bytes = node.value;
  assert.ok(
    bytes.length >= 1 && bytes.length <= 21 && (bytes[0] & 0x80) === 0,
    "Bounded positive native CRL integer required",
  );
  if (bytes.length > 1 && bytes[0] === 0)
    assert.ok(bytes[1] & 0x80, "Nonminimal native CRL integer refused");
  const value = BigInt("0x" + bytes.toString("hex"));
  assert.ok(allowZero ? value >= 0n : value > 0n);
  return value;
}
function parseRevocationList(bytes) {
  const outer = der.item(bytes);
  assert.equal(outer.end, bytes.length);
  const certificateList = der.children(outer);
  assert.equal(certificateList.length, 3);
  const fields = der.children(certificateList[0]);
  let offset = fields[0].tag === 0x02 ? 1 : 0;
  offset += 4; // signature, issuer, thisUpdate, nextUpdate (verified separately).
  const revoked = new Map();
  if (fields[offset]?.tag === 0x30) {
    for (const entry of der.children(fields[offset++])) {
      const parts = der.children(entry);
      assert.ok(parts.length === 2 || parts.length === 3);
      const serial = positiveInteger(parts[0]).toString(16).toUpperCase();
      assert.ok(!revoked.has(serial), "Duplicate signed CRL serial refused");
      const at = der.timestamp(parts[1]);
      assert.ok(at <= Date.now(), "Future native revocation date refused");
      if (parts[2]) {
        assert.equal(parts[2].tag, 0x30);
        assert.ok(der.children(parts[2]).length <= 8);
      }
      revoked.set(serial, at);
    }
  }
  assert.equal(
    fields.length,
    offset + 1,
    "Exactly one native CRL extension envelope required",
  );
  assert.equal(fields[offset].tag, 0xa0);
  const extensionSequence = der.item(fields[offset].value);
  assert.equal(extensionSequence.end, fields[offset].value.length);
  const extensions = der.children(extensionSequence);
  assert.ok(extensions.length >= 1 && extensions.length <= 32);
  const seen = new Set();
  let number;
  for (const extension of extensions) {
    const fields = der.children(extension);
    assert.ok(fields.length === 2 || fields.length === 3);
    assert.equal(fields[0].tag, 0x06);
    const oid = fields[0].value.toString("hex");
    assert.ok(
      !["551d1b", "551d1c"].includes(oid),
      "Delta or partitioned CRLs cannot prove this complete base-CRL transition",
    );
    assert.ok(!seen.has(oid), "Duplicate native CRL extension refused");
    seen.add(oid);
    const value = fields.at(-1);
    assert.equal(value.tag, 0x04);
    if (fields.length === 3)
      assert.ok(
        fields[1].raw.equals(Buffer.from([1, 1, 255])),
        "Noncanonical critical extension bit refused",
      );
    if (oid === "551d14") {
      assert.equal(
        fields.length,
        2,
        "Qualification CRL number must be noncritical",
      );
      const integer = der.item(value.value);
      assert.equal(integer.end, value.value.length);
      number = positiveInteger(integer, true);
    }
  }
  assert.ok(
    number !== undefined,
    "Actual signed native CRL number is required",
  );
  return { number, revoked };
}
function originalLeaf(bytes, ca) {
  assert.ok(
    Buffer.isBuffer(bytes) && bytes.length >= 100 && bytes.length <= 65536,
  );
  const leaf = new crypto.X509Certificate(bytes);
  assert.ok(leaf.raw.equals(bytes), "Exact native DER leaf bytes required");
  assert.ok(
    leaf.checkIssued(ca) && leaf.verify(ca.publicKey),
    "Historical leaf must be issued by the exact original CA",
  );
  return leaf;
}
function verifyRevokedPublication({
  originalCrl,
  revokedCrl,
  issuerDer,
  issuerKeySha256,
  historicalDer,
  currentDer,
}) {
  const original = der.verifyCrl(originalCrl, issuerDer, issuerKeySha256);
  const published = der.verifyCrl(revokedCrl, issuerDer, issuerKeySha256);
  assert.notEqual(published.sha256, original.sha256);
  const ca = new crypto.X509Certificate(issuerDer);
  const historical = originalLeaf(historicalDer, ca),
    current = originalLeaf(currentDer, ca);
  assert.ok(!historical.raw.equals(current.raw));
  const before = parseRevocationList(originalCrl),
    after = parseRevocationList(revokedCrl);
  assert.ok(after.number > before.number, "Actual CA CRL number must advance");
  assert.ok(
    Date.parse(published.thisUpdate) >= Date.parse(original.thisUpdate),
  );
  const oldSerial = BigInt("0x" + historical.serialNumber)
    .toString(16)
    .toUpperCase();
  const currentSerial = BigInt("0x" + current.serialNumber)
    .toString(16)
    .toUpperCase();
  assert.ok(
    !before.revoked.has(oldSerial) && after.revoked.has(oldSerial),
    "Historical issued leaf must become newly revoked in the actual signed CRL",
  );
  assert.ok(
    !before.revoked.has(currentSerial) && !after.revoked.has(currentSerial),
    "Current served successor must remain unrevoked",
  );
  return {
    originalCrlSha256: original.sha256,
    revokedCrlSha256: published.sha256,
    originalCrlNumber: before.number.toString(),
    revokedCrlNumber: after.number.toString(),
    historicalFingerprint: digest(historical.raw),
    currentFingerprint: digest(current.raw),
    historicalSerial: oldSerial,
    revocationTime: new Date(after.revoked.get(oldSerial)).toISOString(),
  };
}
function verifyUnservedInventory(
  historicalThumbprint,
  currentThumbprint,
  iisBindings,
  httpBindings,
) {
  for (const thumb of [historicalThumbprint, currentThumbprint])
    assert.match(thumb, /^[A-F0-9]{40}$/);
  assert.notEqual(historicalThumbprint, currentThumbprint);
  for (const rows of [iisBindings, httpBindings]) {
    assert.ok(Array.isArray(rows) && rows.length >= 1 && rows.length <= 2048);
    for (const row of rows)
      assert.ok(
        row &&
          typeof row === "object" &&
          typeof row.thumbprint === "string" &&
          /^[A-F0-9]{40}$/.test(row.thumbprint),
        "Complete native certificate binding inventory required",
      );
    assert.ok(
      rows.every((row) => row.thumbprint !== historicalThumbprint),
      "Historical leaf is still serving; revocation refused",
    );
    assert.ok(
      rows.some((row) => row.thumbprint === currentThumbprint),
      "Actual served successor must be independently present",
    );
  }
  return true;
}
function iisInventoryScript() {
  return `Import-Module WebAdministration;$rows=@();foreach($site in @(Get-Website)){foreach($b in @(Get-WebBinding -Name $site.Name -Protocol https)){if(([int]$b.sslFlags -band 2)-ne 0){throw 'Unresolved central-certificate IIS binding refused'};$hash=$b.certificateHash;if($hash-is[byte[]]){$hash=[BitConverter]::ToString($hash).Replace('-','')};$hash=([string]$hash).ToUpperInvariant();if($hash-cnotmatch'^[A-F0-9]{40}$'-or$b.certificateStoreName-notin @('My','WebHosting')){throw 'Incomplete IIS certificate inventory refused'};$rows+=,@{siteId=[int]$site.Id;site=[string]$site.Name;coordinates=[string]$b.bindingInformation;flags=[int]$b.sslFlags;store=[string]$b.certificateStoreName;thumbprint=$hash};if($rows.Count-gt 2048){throw 'Bounded IIS inventory required'}}};ConvertTo-Json -InputObject @($rows) -Depth 5 -Compress`;
}
async function observeHistoricalUnserved({ historicalDer, currentDer, ps }) {
  assert.equal(process.platform, "win32");
  assert.equal(typeof ps, "function");
  const historical = new crypto.X509Certificate(historicalDer),
    current = new crypto.X509Certificate(currentDer);
  const iis = JSON.parse(ps(iisInventoryScript()));
  const native = await discovery.listHttpSysBindings({});
  assert.equal(native.ok, true, "Complete native HTTP.sys inventory required");
  const http = native.bindings.map((row) => ({
    ...row,
    thumbprint: String(row.thumbprint || "").toUpperCase(),
  }));
  verifyUnservedInventory(
    historical.fingerprint.replace(/:/g, "").toUpperCase(),
    current.fingerprint.replace(/:/g, "").toUpperCase(),
    iis,
    http,
  );
  return { iis, http }; // Private bounded native observations, never a public report.
}
function verifyRevokedResponse(bytes, options, nativeVerdict) {
  const verified = response.verifyResponse(bytes, options);
  assert.equal(
    verified.status,
    "revoked",
    "Actual delegated signed OCSP revoked status required",
  );
  assert.equal(
    nativeVerdict,
    "revoked",
    "Actual CryptoAPI chain must independently report revoked",
  );
  return verified;
}
async function qualifyHistoricalRevoked(c) {
  assert.equal(process.platform, "win32");
  assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB, "1");
  const {
    historical,
    current,
    issuerDer,
    signerDer,
    issuerKeySha256,
    originalCrl,
    ps,
    operation,
    assertCurrent,
    checkpoint,
    fetchRevoked,
    probeRevoked,
  } = c;
  for (const fn of [
    ps,
    operation,
    assertCurrent,
    checkpoint,
    fetchRevoked,
    probeRevoked,
  ])
    assert.equal(typeof fn, "function");
  const ca = new crypto.X509Certificate(issuerDer);
  originalLeaf(historical.leaf.raw, ca);
  originalLeaf(current.leaf.raw, ca);
  assert.notEqual(historical.enrollmentId, current.enrollmentId);
  assert.notEqual(historical.requestId, current.requestId);
  const observe = () =>
    observeHistoricalUnserved({
      historicalDer: historical.leaf.raw,
      currentDer: current.leaf.raw,
      ps,
    });
  await assertCurrent();
  await observe();
  const before = checkpoint();
  const revoked = await operation("RevokeHistorical", {
    historicalRequestId: historical.requestId,
    currentRequestId: current.requestId,
    historicalDerBase64: historical.leaf.raw.toString("base64"),
    currentDerBase64: current.leaf.raw.toString("base64"),
    caDerBase64: issuerDer.toString("base64"),
    signerDerBase64: signerDer.toString("base64"),
    crlDerBase64: originalCrl.toString("base64"),
  });
  assert.equal(revoked.historicalRequestId, historical.requestId);
  assert.equal(revoked.currentRequestId, current.requestId);
  assert.equal(revoked.nativeDisposition, 21);
  assert.ok(
    typeof revoked.crlDerBase64 === "string" &&
      revoked.crlDerBase64.length <= 32768,
  );
  const revokedCrl = Buffer.from(revoked.crlDerBase64, "base64");
  const publication = verifyRevokedPublication({
    originalCrl,
    revokedCrl,
    issuerDer,
    issuerKeySha256,
    historicalDer: historical.leaf.raw,
    currentDer: current.leaf.raw,
  });
  await assertCurrent();
  await observe();
  const refreshed = await operation("RefreshHistoricalRevocation", {
    caDerBase64: issuerDer.toString("base64"),
    signerDerBase64: signerDer.toString("base64"),
    originalCrlDerBase64: originalCrl.toString("base64"),
    crlDerBase64: revokedCrl.toString("base64"),
  });
  assert.equal(refreshed.signedCrlSha256, publication.revokedCrlSha256);
  assert.equal(refreshed.caDerSha256, digest(issuerDer));
  assert.equal(refreshed.signerDerSha256, digest(signerDer));
  // Native responders can have a real response cache. A bounded miss fails;
  // no cache entry, status response or clock is manufactured to pass the case.
  const signed = await fetchRevoked(revokedCrl);
  assert.equal(signed.status, "revoked");
  assert.equal(signed.serialNumber, publication.historicalSerial);
  assert.equal(signed.revocationTime, publication.revocationTime);
  assert.equal(signed.signerFingerprint, digest(signerDer));
  assert.equal(signed.issuerKeySha256, issuerKeySha256);
  const native = await probeRevoked(historical.leaf);
  assert.equal(native.verdict, "revoked");
  await assertCurrent();
  await observe();
  const after = checkpoint();
  assert.equal(
    after,
    before,
    "Revocation/provider refresh must not submit another CA request",
  );
  return {
    revokedCrl,
    facts: {
      scope: SCOPE,
      historicalEnrollmentId: historical.enrollmentId,
      currentEnrollmentId: current.enrollmentId,
      historicalRequestId: historical.requestId,
      currentRequestId: current.requestId,
      ...publication,
      responseSha256: signed.responseSha256,
      signerFingerprint: signed.signerFingerprint,
      issuerKeySha256,
      nativeVerdict: native.verdict,
      caRequestCounts: [before, after],
    },
  };
}
module.exports = {
  SCENARIO,
  SCOPE,
  FLAGS,
  FALSE_FLAGS,
  FIELDS,
  verifyProof,
  verifyCrossProof,
  qualifyHistoricalRevoked,
  parseRevocationList,
  verifyRevokedPublication,
  verifyUnservedInventory,
  iisInventoryScript,
  observeHistoricalUnserved,
  verifyRevokedResponse,
};
