"use strict";

const { it } = require("node:test");
const assert = require("node:assert/strict");
const { _test: { createObservationHistoryHandler } } = require("../../apps/api/routes/certops");

function response() {
  return { statusCode: 200, status(code) { this.statusCode = code; return this; }, json(body) { this.body = body; return this; } };
}

it("rejects viewer topology sorts without reading evidence and removes topology from visible results", async () => {
  const calls = [];
  const handler = createObservationHistoryHandler({
    certificateReader: async () => ({ fingerprintSha256: "abc" }),
    evidenceReader: async (options) => {
      calls.push(options);
      return { items: [{ id: "one", metadata: { source: "secret", targetHost: "secret", observedRevocationVerdict: "good" } }], pagination: {} };
    },
  });
  const req = { params: { certId: "aaaaaaaa-0000-4000-8000-000000000001" }, workspace: { id: "ws" }, authz: { workspaceRole: "viewer" } };
  for (const sortBy of ["source", "location"]) {
    const res = response();
    await handler({ ...req, query: { sortBy, sortDirection: "asc" } }, res);
    assert.equal(res.statusCode, 403);
    assert.equal(calls.length, 0);
  }
  const res = response();
  await handler({ ...req, query: { sortBy: "observedAt", sortDirection: "desc" } }, res);
  assert.equal(calls[0].sortBy, "observedAt");
  assert.deepEqual(res.body.items[0].metadata, { observedRevocationVerdict: "good" });
  const manager = response();
  await handler({ ...req, authz: { workspaceRole: "workspace_manager" }, query: { sortBy: "source", sortDirection: "asc" } }, manager);
  assert.equal(calls[1].sortBy, "source");
  assert.equal(manager.body.items[0].metadata.targetHost, "secret");
});
