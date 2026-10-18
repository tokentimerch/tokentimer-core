/**
 * Regression coverage: known unsafe SAN flag wins over unreadable interface and operator attestation.
 * Local fixtures verify this contract; measured native/environment execution
 * is tracked separately in the qualification suites and their reports.
 */
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { parseCaCheck } = require("./adcs-preflight");
const safeEdit = "EditFlags REG_DWORD = 0x10000 (65536)";
const unsafeEdit = "EditFlags REG_DWORD = 0x40000 (262144)";
const safeInterface = "InterfaceFlags REG_DWORD = 0x200 (512)";
const unsafeInterface = "InterfaceFlags REG_DWORD = 0x0 (0)";

test("known unsafe SAN flag wins over unreadable interface and operator attestation", () => {
  for (const attested of [false, true]) {
    const result = parseCaCheck(unsafeEdit, "", attested);
    assert.equal(result.verdict, "unsafe"); assert.equal(result.operatorAttested, false);
    assert.deepEqual(result.reasons, ["subject_alt_name_attribute_enabled", "flags_unreadable"]);
  }
});
test("known unencrypted requests win over unreadable EditFlags and operator attestation", () => {
  for (const attested of [false, true]) {
    const result = parseCaCheck("", unsafeInterface, attested);
    assert.equal(result.verdict, "unsafe"); assert.equal(result.operatorAttested, false);
    assert.deepEqual(result.reasons, ["encrypted_requests_not_enforced", "flags_unreadable"]);
  }
});
test("both known unsafe flags cannot be overridden by an attestation", () => {
  assert.deepEqual(parseCaCheck(unsafeEdit, unsafeInterface, true), { verdict: "unsafe", reasons: ["subject_alt_name_attribute_enabled", "encrypted_requests_not_enforced"], operatorAttested: false });
});
test("partially unreadable otherwise safe CA retains explicit local attestation semantics", () => {
  for (const pair of [[safeEdit, ""], ["", safeInterface], ["", ""]]) {
    for (const attested of [false, true]) assert.deepEqual(parseCaCheck(...pair, attested), { verdict: "unreadable", reasons: ["flags_unreadable"], operatorAttested: attested });
  }
});
test("fully readable safe flags never claim operator attestation", () => {
  assert.deepEqual(parseCaCheck(safeEdit, safeInterface, true), { verdict: "safe", reasons: [], operatorAttested: false });
});
