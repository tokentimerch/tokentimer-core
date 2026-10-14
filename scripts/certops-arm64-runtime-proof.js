"use strict";
/** Bounded desktop ARM64 proof contract. These checks consume measured facts;
 * cross-compiled PE headers alone never establish native runtime qualification. */
const assert = require("node:assert/strict");
const suite = "windows-arm64-cng-runtime";
const requiredScenarios = Object.freeze([
  "windows-arm64-native-runtime", "windows-arm64-fresh-helper",
  "windows-arm64-cng-csr-signature-and-public-leaf", "windows-arm64-acceptance-and-export-refusal",
  "windows-arm64-native-chain-and-key-survivors", "windows-arm64-owned-cleanup",
]);
const profiles = Object.freeze(["rsa-2048", "ec-p256"]);
const requiredCapabilities = Object.freeze(["native-arm64-desktop", "native-powershell", "native-go", "native-certreq-certutil", "administrator"]);
const caseFlags = Object.freeze(["csrSignatureVerified", "csrPublicKeyMatchesLeaf", "dnsSanVerified", "keyUsageVerified", "publicLeafSignatureVerified", "nativeAssociationVerified", "nativeSignatureVerified", "protectedExportDenied", "exportableControlSucceeded", "privateBuffersZeroed", "custodyUnchanged", "machineStoreReferenceFound", "exactReferenceExcluded", "ownedArtifactsAbsent"]);
function peMachine(bytes) {
  assert.ok(Buffer.isBuffer(bytes) && bytes.length >= 64, "PE header unavailable");
  assert.equal(bytes.readUInt16LE(0), 0x5a4d, "DOS header missing");
  const offset = bytes.readUInt32LE(0x3c);
  assert.ok(offset <= bytes.length - 6, "Truncated PE header");
  assert.equal(bytes.readUInt32LE(offset), 0x4550, "PE signature missing");
  return bytes.readUInt16LE(offset + 4);
}
function verifyArchitecture(value) {
  assert.deepEqual(Object.keys(value).sort(), ["productType", "build", "cpuArchitectures", "platform", "nodeArchitecture", "powershellArchitecture", "goHostArchitecture", "goHostOs", "nodePeMachine", "powershellPeMachine", "goPeMachine", "certreqPeMachine", "certutilPeMachine", "administrator"].sort());
  assert.equal(value.productType, 1); assert.match(value.build, /^\d{5,6}$/);
  assert.ok(Number(value.build) >= 22000, "Windows 11 desktop required");
  assert.ok(value.cpuArchitectures.length > 0 && value.cpuArchitectures.length <= 64 && value.cpuArchitectures.every(item => item === 12));
  for (const field of ["nodeArchitecture", "powershellArchitecture", "goHostArchitecture"]) assert.equal(value[field], "arm64", field);
  assert.equal(value.goHostOs, "windows"); assert.equal(value.platform, "win32");
  // ARM64EC and ARM64X are reported distinctly and deliberately not accepted as
  // proof of a wholly native inbox executable in this narrow initial lane.
  for (const field of ["nodePeMachine", "powershellPeMachine", "goPeMachine", "certreqPeMachine", "certutilPeMachine"]) assert.equal(value[field], 0xaa64, field);
  assert.equal(value.administrator, true);
  return true;
}
function verifyProof(value) {
  assert.deepEqual(Object.keys(value).sort(), ["scope", "architecture", "helperPeMachine", "helperSha256", "helperExecuted", "serverQualified", "iisQualified", "domainAdcsQualified", "privateCaKeyPersisted", "cleanupCompleted", "cases"].sort());
  assert.equal(value.scope, "native-windows11-arm64-cng-public-fixture");
  verifyArchitecture(value.architecture);
  assert.equal(value.helperPeMachine, 0xaa64); assert.match(value.helperSha256, /^[a-f0-9]{64}$/);
  assert.equal(value.helperExecuted, true); assert.equal(value.serverQualified, false);
  assert.equal(value.iisQualified, false); assert.equal(value.domainAdcsQualified, false);
  assert.equal(value.privateCaKeyPersisted, false); assert.equal(value.cleanupCompleted, true);
  assert.equal(value.cases.length, profiles.length);
  assert.deepEqual(value.cases.map(item => item.profile).sort(), [...profiles].sort());
  for (const item of value.cases) {
    assert.deepEqual(Object.keys(item).sort(), [...caseFlags, "profile", "chainVerdict", "wrongPinVerdict", "malformedVerdict", "storesScanned", "privateExportHResult"].sort());
    for (const field of caseFlags) assert.equal(item[field], true, `${item.profile}/${field}`);
    assert.equal(item.chainVerdict, "revocation_unknown"); assert.equal(item.wrongPinVerdict, "ca_key_changed");
    assert.equal(item.malformedVerdict, "invalid");
    assert.ok(Number.isInteger(item.storesScanned) && item.storesScanned >= 1 && item.storesScanned <= 512);
    assert.ok(Number.isInteger(item.privateExportHResult) && item.privateExportHResult < 0 && item.privateExportHResult >= -2147483648);
  }
  return true;
}
function verifyRuntimeReport(report) {
  assert.equal(report.platform, "win32"); assert.equal(report.architecture, "arm64");
  verifyProof(report.nativeArm64CngRuntime);
  assert.deepEqual(report.nativeArchitectureProbe, report.nativeArm64CngRuntime.architecture);
  assert.deepEqual(report.qualificationEnvironment, { osFamily: "windows", osVersion: `desktop-${report.nativeArm64CngRuntime.architecture.build}`, productType: 1, measurement: "native", architecture: "arm64" });
  return true;
}
module.exports = { suite, requiredScenarios, requiredCapabilities, profiles, peMachine, verifyArchitecture, verifyProof, verifyRuntimeReport };
