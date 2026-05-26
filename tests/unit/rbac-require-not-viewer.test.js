"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert");
const { requireNotViewer } = require("../../apps/api/services/rbac");

function mockRes() {
  return {
    statusCode: null,
    body: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(payload) {
      this.body = payload;
      return this;
    },
  };
}

describe("requireNotViewer", () => {
  it("allows internal worker calls without workspace membership", async () => {
    let called = false;
    const req = {
      isWorkerCall: true,
      user: { id: null, role: "admin", email: "worker@internal" },
      query: {},
      body: {},
    };
    const res = mockRes();

    await requireNotViewer(req, res, () => {
      called = true;
    });

    assert.strictEqual(called, true);
    assert.strictEqual(res.statusCode, null);
  });
});
