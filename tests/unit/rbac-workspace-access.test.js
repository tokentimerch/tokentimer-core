"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert");
const {
  requireWorkspaceManager,
  requireIntegrationQuota,
  requireNotViewer,
} = require("../../apps/api/services/rbac");

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

describe("requireWorkspaceManager", () => {
  it("allows admin and workspace_manager", () => {
    for (const role of ["admin", "workspace_manager"]) {
      let called = false;
      const res = mockRes();
      requireWorkspaceManager(
        { authz: { workspaceRole: role } },
        res,
        () => {
          called = true;
        },
      );
      assert.strictEqual(called, true, `expected ${role} to pass`);
      assert.strictEqual(res.statusCode, null);
    }
  });

  it("rejects viewers and missing membership", () => {
    const cases = [
      { authz: { workspaceRole: "viewer" } },
      { authz: {} },
      {},
    ];
    for (const req of cases) {
      let called = false;
      const res = mockRes();
      requireWorkspaceManager(req, res, () => {
        called = true;
      });
      assert.strictEqual(called, false);
      assert.strictEqual(res.statusCode, 403);
      assert.strictEqual(res.body.error, "Forbidden: insufficient role");
      assert.strictEqual(res.body.code, "INSUFFICIENT_ROLE");
    }
  });
});

describe("requireIntegrationQuota", () => {
  it("is a pass-through and does not authorize", () => {
    let called = false;
    const res = mockRes();
    requireIntegrationQuota({ user: { id: "anyone" }, query: {}, body: {} }, res, () => {
      called = true;
    });
    assert.strictEqual(called, true);
    assert.strictEqual(res.statusCode, null);
  });
});

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
