/**
 * Regression coverage: contradictory or duplicate DWORD representations are unreadable without hiding other unsafe flags.
 * Local fixtures verify this contract; measured native/environment execution
 * is tracked separately in the qualification suites and their reports.
 */
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { parseTemplateDump, parseCaCheck, runCertutilPreflight } = require("./adcs-preflight");
test("contradictory or duplicate DWORD representations are unreadable without hiding other unsafe flags", () => {
  for (const malformed of ["InterfaceFlags REG_DWORD = 0x200 (0)", "InterfaceFlags REG_DWORD = 0x200 (512) trailing", "InterfaceFlags REG_DWORD = 0x200 (512)\nInterfaceFlags REG_DWORD = 0x200 (512)"]) {
    const result = parseCaCheck("EditFlags REG_DWORD = 0x40000 (262144)", malformed, true);
    assert.equal(result.verdict, "unsafe"); assert.equal(result.operatorAttested, false);
    assert.ok(result.reasons.includes("flags_unreadable")); assert.ok(result.reasons.includes("subject_alt_name_attribute_enabled"));
  }
});
const safe = ["cn = SafeWeb", "msPKI-Template-Schema-Version = 2", "pKIExtendedKeyUsage = 1.3.6.1.5.5.7.3.1",
  "msPKI-Certificate-Application-Policy = 1.3.6.1.5.5.7.3.1", "msPKI-Minimal-Key-Size = 2048",
  "msPKI-Certificate-Name-Flag = 1", "msPKI-Cert-Template-OID = 1.3.6.1.4.1.311.21.8.2"].join("\n");
for (const field of ["msPKI-Minimal-Key-Size", "msPKI-Certificate-Name-Flag", "msPKI-Cert-Template-OID", "msPKI-Template-Schema-Version"]) {
  test(`missing ${field} cannot produce a safe template`, () => {
    const result = parseTemplateDump(safe.split("\n").filter((line) => !line.startsWith(field)).join("\n"), "SafeWeb");
    assert.equal(result.verdict, "unreadable"); assert.ok(result.reasons.includes("template_unreadable"));
  });
}
test("missing application policy is unsafe and malformed OID tokens are never ignored", () => {
  assert.equal(parseTemplateDump(safe.replace(/^msPKI-Certificate-Application-Policy.*\n/m, ""), "SafeWeb").verdict, "unsafe");
  assert.equal(parseTemplateDump(safe.replace("pKIExtendedKeyUsage = 1.3.6.1.5.5.7.3.1", "pKIExtendedKeyUsage = 1.3.6.1.5.5.7.3.1 not-an-oid"), "SafeWeb").verdict, "unsafe");
});
test("schema2 RSA may legitimately omit its asymmetric algorithm", () => {
  const result = parseTemplateDump(safe, "SafeWeb"); assert.equal(result.verdict, "safe"); assert.equal(result.asymmetricAlgorithm, null);
});
test("template numeric hex/decimal pairs must agree exactly", () => {
  assert.equal(parseTemplateDump(safe.replace("Key-Size = 2048","Key-Size = 800 (2048)"),"SafeWeb").verdict,"safe");
  assert.equal(parseTemplateDump(safe.replace("Key-Size = 2048","Key-Size = 0x800 (2048)"),"SafeWeb").verdict,"safe");
  for(const value of ["800 (1024)","0x800 (2048) trailing","0x100000000 (4294967296)"]){
    assert.equal(parseTemplateDump(safe.replace("Key-Size = 2048",`Key-Size = ${value}`),"SafeWeb").verdict,"unreadable");
  }
});
test("schema3 requires an unambiguous asymmetric algorithm", () => {
  const schema3 = safe.replace("Schema-Version = 2", "Schema-Version = 3");
  assert.equal(parseTemplateDump(schema3, "SafeWeb").verdict, "unreadable");
  assert.equal(parseTemplateDump(schema3 + "\nmsPKI-Asymmetric-Algorithm = RSA", "SafeWeb").verdict, "safe");
});
test("schema4 algorithm is read from genuine typed RA policy tuple shape", () => {
  const schema4 = safe.replace("Schema-Version = 2", "Schema-Version = 4").replace("Key-Size = 2048", "Key-Size = 256");
  const tuple = "\nmsPKI-RA-Application-Policies = msPKI-Asymmetric-Algorithm`PZPWSTR`ECDSA_P256`msPKI-Hash-Algorithm`PZPWSTR`SHA256";
  const result = parseTemplateDump(schema4 + tuple, "SafeWeb");
  assert.equal(result.verdict, "safe"); assert.equal(result.asymmetricAlgorithm, "ECDSA_P256");
  assert.equal(parseTemplateDump(schema4 + tuple + "`", "SafeWeb").verdict, "safe");
  assert.equal(parseTemplateDump(schema4 + tuple + "``", "SafeWeb").verdict, "unreadable");
  assert.equal(parseTemplateDump(schema4 + tuple + "\nmsPKI-Asymmetric-Algorithm = ECDSA_P256", "SafeWeb").verdict, "safe");
  for (const text of [schema4 + tuple + "\nmsPKI-Asymmetric-Algorithm = RSA", schema4 + tuple + tuple,
    schema4 + tuple.replace("Algorithm`PZPWSTR", "Algorithm`DWORD"), schema4 + tuple + "`dangling"]) {
    assert.equal(parseTemplateDump(text, "SafeWeb").verdict, "unreadable");
  }
});
test("duplicate required attributes and invalid numeric values are unreadable", () => {
  for (const text of [safe + "\nmsPKI-Minimal-Key-Size = 2048", safe.replace("Key-Size = 2048", "Key-Size = nope"),
    safe.replace("Name-Flag = 1", "Name-Flag = -1"), safe.replace("Key-Size = 2048", "Key-Size = 0")]) {
    assert.equal(parseTemplateDump(text, "SafeWeb").verdict, "unreadable");
  }
});
test("known unsafe EKU/schema remains explicit when another required attribute is unreadable", () => {
  const result = parseTemplateDump(safe.replace("Schema-Version = 2", "Schema-Version = 1").replace("Key-Size = 2048", "Key-Size = nope"), "SafeWeb");
  assert.equal(result.verdict, "unsafe"); assert.ok(result.reasons.includes("schema_version_1")); assert.ok(result.reasons.includes("template_unreadable"));
});
test("one unreadable CA flag does not suppress another known unsafe flag or certificate query", async () => {
  const calls = [];
  const result = await runCertutilPreflight({ caConfig: "ca.example.com\\Example CA", template: "SafeWeb", operatorAttested: true,
    execFileImpl(_file, args) {
      calls.push(args);
      if (args.includes("-dstemplate")) return { stdout: safe };
      if (args.includes("policy\\EditFlags")) return { stdout: "EditFlags REG_DWORD = 0x40000" };
      if (args.includes("CA\\InterfaceFlags")) throw new Error("access denied");
      if (args.includes("certcount")) return { stdout: "Cert count: 0" };
      throw new Error("unexpected native argv");
    } });
  assert.equal(result.preflightResult.caCheck.verdict, "unsafe");
  assert.equal(result.preflightResult.caCheck.operatorAttested, false);
  assert.ok(calls.some((args) => args.includes("certcount")));
});
