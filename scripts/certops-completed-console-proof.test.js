"use strict";

/** Offline adversarial report checks, not browser execution evidence. */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { FIELDS, verifyProof } = require("./certops-completed-console-proof");

test("completed console proof requires actual finality, mounted access withdrawal and truthful execution scope", () => {
  const proof = Object.fromEntries(FIELDS.map(field => [field, true]));
  assert.equal(verifyProof(proof), true);
  for (const field of FIELDS) {
    const omitted = { ...proof };
    delete omitted[field];
    assert.throws(() => verifyProof(omitted));
    for (const value of [false, 1, "true", null]) {
      assert.throws(() => verifyProof({ ...proof, [field]: value }));
    }
  }
});

test("empty, unbounded and private completed-console evidence is refused", () => {
  const proof = Object.fromEntries(FIELDS.map(field => [field, true]));
  for (const invalid of [null, [], {}, { ...proof, consoleText: "private text must not enter evidence" }, { ...proof, browserCookies: [] }]) {
    assert.throws(() => verifyProof(invalid));
  }
});
