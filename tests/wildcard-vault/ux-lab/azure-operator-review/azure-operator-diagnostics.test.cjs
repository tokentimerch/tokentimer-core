"use strict";
const assert = require("node:assert/strict");
const { test } = require("node:test");
const { OperatorStageError, requireCleanup, diagnostics } = require("./azure-operator-diagnostics.cjs");

test("the original broker error and independent cleanup failures remain visible without private output", () => {
  const cause = Object.assign(new Error("AZURE_BROKER_CERTIFICATE_ISOLATION_REFUSED"),
    { stack: "at /protected/paths/azure-role-token-broker.cjs:15:40" });
  const observation = new OperatorStageError("broker-admission", new Error("private assertion text", { cause }));
  try {
    requireCleanup([
      ["broker-stop", { status: "fulfilled" }],
      ["provider-cleanup", { status: "rejected",
        reason: Object.assign(new Error("private Entra response"), { code: "AZURE_OPERATOR_ENTRA_RETIREMENT_TIMEOUT" }) }],
      ["local-cleanup", { status: "rejected", reason: Object.assign(new Error("private Docker stderr"), { status: 1 }) }],
    ]);
    assert.fail("cleanup failure expected");
  } catch (cleanup) {
    assert.deepEqual(diagnostics(new AggregateError([observation, cleanup])), [
      "AZURE_OPERATOR_FAILED broker-admission AZURE_BROKER_CERTIFICATE_ISOLATION_REFUSED azure-role-token-broker.cjs:15:40",
      "AZURE_OPERATOR_FAILED provider-cleanup AZURE_OPERATOR_ENTRA_RETIREMENT_TIMEOUT",
      "AZURE_OPERATOR_FAILED local-cleanup native-exit",
    ]);
  }
});

test("diagnostic output is bounded and omits unfamiliar codes and raw exception text", () => {
  const reason = Object.assign(new Error("private response"), { code: "AZURE_UNKNOWN_PRIVATE_VALUE", stack: "foreign.cjs:10:20" });
  const failure = new OperatorStageError("public-journey", reason);
  const rows = diagnostics(new AggregateError(Array(32).fill(failure)));
  assert.deepEqual(rows, Array(8).fill("AZURE_OPERATOR_FAILED public-journey error"));
});
