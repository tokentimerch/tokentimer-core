"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const certOpsRouter = require(
  path.resolve(__dirname, "../../apps/api/routes/certops.js"),
);

const { createAgentJobLogReadHandler } = certOpsRouter._test;

const JOB_ID = "aaaaaaaa-0000-4000-8000-000000000001";

function fakeRes() {
  return {
    statusCode: 200,
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

function request(workspaceRole, query = {}) {
  return {
    params: { id: "ws-1", jobId: JOB_ID },
    query,
    workspace: { id: "ws-1" },
    authz: { workspaceRole },
  };
}

// A reader that ignores includeText, so the handler is the only guard under test.
function leakyReader(calls) {
  return async (options) => {
    calls.push(options);
    return {
      items: [{ seq: 1, level: "info", message: "secret-ish output" }],
      nextCursor: "abc",
      hasMore: false,
      logsComplete: true,
      streams: [{ attempt: 1, status: "final" }],
      storageEnabled: true,
    };
  };
}

describe("CertOps agent job log read route", () => {
  it("never returns line text to a viewer, even if the reader does", async () => {
    const calls = [];
    const handler = createAgentJobLogReadHandler({ agentJobLogReader: leakyReader(calls) });
    const res = fakeRes();

    await handler(request("viewer", { cursor: "xyz" }), res);

    assert.equal(res.statusCode, 200);
    assert.equal(calls[0].includeText, false);
    assert.deepEqual(res.body.items, []);
    assert.equal(res.body.nextCursor, null);
    assert.equal(res.body.linesVisible, false);
    assert.equal(res.body.logsComplete, true);
    assert.equal(res.body.streams.length, 1);
  });

  it("returns lines to a workspace manager", async () => {
    const calls = [];
    const handler = createAgentJobLogReadHandler({ agentJobLogReader: leakyReader(calls) });
    const res = fakeRes();

    await handler(request("workspace_manager", { cursor: "xyz", limit: "50" }), res);

    assert.equal(calls[0].includeText, true);
    assert.equal(calls[0].cursor, "xyz");
    assert.equal(calls[0].limit, "50");
    assert.equal(res.body.items.length, 1);
    assert.equal(res.body.nextCursor, "abc");
    assert.equal(res.body.linesVisible, true);
  });

  it("rejects a malformed job id before reading", async () => {
    const calls = [];
    const handler = createAgentJobLogReadHandler({ agentJobLogReader: leakyReader(calls) });
    const res = fakeRes();
    const req = request("admin");
    req.params.jobId = "not-a-uuid";

    await handler(req, res);

    assert.equal(res.statusCode, 400);
    assert.equal(calls.length, 0);
  });
});
