"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

const { formatExecutionFinishLine } = require("./index.js");

describe("formatExecutionFinishLine", () => {
  it("keeps a successful finish to the status", () => {
    assert.equal(
      formatExecutionFinishLine("job-1", { status: "succeeded" }),
      "job job-1: execution finished with status succeeded",
    );
  });

  it("puts the rejection, enrollment state, and error in the message", () => {
    const line = formatExecutionFinishLine("job-2", {
      status: "rejected",
      rejectionReason: "issuer_not_allowlisted",
      errorMessage: "no local enrollment rule names this CA",
      enrollmentResult: { state: "refused", requestId: 18, caHresult: "0x80094014" },
    });
    assert.match(line, /status rejected reason=issuer_not_allowlisted/);
    assert.match(line, /enrollment=refused requestId=18 hresult=0x80094014/);
    assert.match(line, /no local enrollment rule names this CA/);
  });

  it("adds preflight verdicts without an error on success", () => {
    const line = formatExecutionFinishLine("job-3", {
      status: "succeeded",
      preflightResult: {
        templateCheck: { verdict: "safe" },
        caCheck: { verdict: "unsafe" },
      },
    });
    assert.equal(
      line,
      "job job-3: execution finished with status succeeded template=safe ca=unsafe",
    );
  });
});
