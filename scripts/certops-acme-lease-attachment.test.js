"use strict";
/** Closed observer-protocol controls only; no native process is attached. */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const {
  validateRecord,
} = require("../tests/e2e/helpers/certops-acme-lease-attachment");
const expected = { token: "a".repeat(36), pid: 123, startTicks: "2345678" };
function attached() {
  return {
    kind: "lease-pidfd-attached",
    ...expected,
    pidfdPinned: true,
    initialGroupRootOnly: true,
  };
}
function closed() {
  return {
    kind: "lease-pidfd-closed",
    ...expected,
    rootExited: true,
    groupEmpty: true,
    pidfdClosed: true,
    pidfdSignalUsed: false,
  };
}
test("lease observer accepts exact retained attachment and natural-exit receipts", () => {
  validateRecord(attached(), expected, "lease-pidfd-attached");
  validateRecord(closed(), expected, "lease-pidfd-closed");
  validateRecord(
    { ...closed(), pidfdSignalUsed: true },
    expected,
    "lease-pidfd-closed",
  );
});
test("lease observer rejects missing or false native ownership observations", () => {
  for (const make of [attached, closed]) {
    const original = make();
    for (const key of Object.keys(original)) {
      const missing = { ...original };
      delete missing[key];
      assert.throws(() => validateRecord(missing, expected, original.kind));
    }
    for (const key of Object.keys(original).filter(
      (key) => original[key] === true,
    ))
      assert.throws(() =>
        validateRecord({ ...original, [key]: false }, expected, original.kind),
      );
  }
});
test("lease observer refuses spliced identity, private extras and nonboolean signal facts", () => {
  for (const make of [attached, closed]) {
    const original = make();
    for (const replacement of [
      { pid: 124 },
      { startTicks: "2345679" },
      { token: "b".repeat(36) },
      { privateState: "must-not-persist" },
    ])
      assert.throws(() =>
        validateRecord(
          { ...original, ...replacement },
          expected,
          original.kind,
        ),
      );
  }
  for (const value of [0, 1, null, "false"])
    assert.throws(() =>
      validateRecord(
        { ...closed(), pidfdSignalUsed: value },
        expected,
        "lease-pidfd-closed",
      ),
    );
});
