"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const workspacesRouter = require(
  path.resolve(__dirname, "../../apps/api/routes/workspaces.js"),
);

const { manualInvitesDisabled, requireManualInvitesEnabled } =
  workspacesRouter._test;

function responseRecorder() {
  return {
    statusCode: null,
    body: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(body) {
      this.body = body;
      return this;
    },
  };
}

describe("manualInvitesDisabled", () => {
  it("is disabled only when the env var is exactly 'true'", () => {
    assert.equal(manualInvitesDisabled({ DISABLE_MANUAL_INVITES: "true" }), true);
  });

  it("stays enabled (returns false) for any other value, including unset", () => {
    for (const env of [
      {},
      { DISABLE_MANUAL_INVITES: "false" },
      { DISABLE_MANUAL_INVITES: "1" },
      { DISABLE_MANUAL_INVITES: "TRUE" },
      { DISABLE_MANUAL_INVITES: "" },
    ]) {
      assert.equal(
        manualInvitesDisabled(env),
        false,
        `expected false for ${JSON.stringify(env)}`,
      );
    }
  });
});

describe("requireManualInvitesEnabled middleware", () => {
  it("passes through to the handler (and no DB writes) when the flag is unset", () => {
    delete process.env.DISABLE_MANUAL_INVITES;
    const res = responseRecorder();
    let nextCalled = false;

    requireManualInvitesEnabled({}, res, () => {
      nextCalled = true;
    });

    assert.equal(nextCalled, true);
    assert.equal(res.statusCode, null);
  });

  it("returns 403 with the documented error shape before the handler runs when enabled", () => {
    process.env.DISABLE_MANUAL_INVITES = "true";
    try {
      const res = responseRecorder();
      let nextCalled = false;

      requireManualInvitesEnabled({}, res, () => {
        nextCalled = true;
      });

      assert.equal(nextCalled, false);
      assert.equal(res.statusCode, 403);
      assert.equal(res.body.code, "MANUAL_INVITES_DISABLED");
      assert.equal(typeof res.body.error, "string");
    } finally {
      delete process.env.DISABLE_MANUAL_INVITES;
    }
  });

  it("re-enables invites the moment the flag is turned back off", () => {
    process.env.DISABLE_MANUAL_INVITES = "true";
    const disabledRes = responseRecorder();
    requireManualInvitesEnabled({}, disabledRes, () => {});
    assert.equal(disabledRes.statusCode, 403);

    delete process.env.DISABLE_MANUAL_INVITES;
    const enabledRes = responseRecorder();
    let nextCalled = false;
    requireManualInvitesEnabled({}, enabledRes, () => {
      nextCalled = true;
    });
    assert.equal(nextCalled, true);
    assert.equal(enabledRes.statusCode, null);
  });
});
