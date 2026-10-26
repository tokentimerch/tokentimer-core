"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { authorize, can } = require("../../apps/api/services/rbac");

describe("certificate setup authorization", () => {
  for (const action of [
    "certops.issuer.manage",
    "certops.renewal_profile.manage",
  ]) {
    it(`${action} allows managers and owners, and denies viewers or missing membership`, () => {
      for (const role of ["workspace_manager", "admin", "viewer", null]) {
        let allowed = false;
        let status;
        const res = {
          status(code) {
            status = code;
            return this;
          },
          json() {},
        };
        authorize(action)(
          { authz: { workspaceRole: role }, user: { isAdmin: true } },
          res,
          () => {
            allowed = true;
          },
        );
        assert.equal(
          allowed,
          role === "admin" || role === "workspace_manager",
          `${action}: ${role}`,
        );
        if (!allowed) assert.equal(status, 403);
      }
    });
  }

  it("preserves owner-only controls outside certificate operations", () => {
    for (const action of [
      "workspace.delete",
      "certops.kill_switch.manage",
      "certops.trust_anchor.manage",
      "certops.agents.diagnose",
    ]) {
      assert.equal(can("workspace_manager", action), false, action);
      assert.equal(can("admin", action), true, action);
    }
  });
});
