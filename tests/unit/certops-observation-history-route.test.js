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


it("validates filters and denies viewer location queries before reading evidence", async () => {
  const calls = [];
  const handler = createObservationHistoryHandler({
    certificateReader: async () => ({ fingerprintSha256: "abc" }),
    evidenceReader: async (options) => { calls.push(options); return { items: [], pagination: {} }; },
  });
  const req = { params: { certId: "aaaaaaaa-0000-4000-8000-000000000001" }, workspace: { id: "ws" }, authz: { workspaceRole: "workspace_manager" } };
  for (const query of [{ revocationStatus: "other" }, { location: " " }, { since: "2026-02-30T00:00:00Z" }, { since: "2026-01-01" }, { since: "2026-02-01T00:00:00Z", until: "2026-01-01T00:00:00Z" }, { revocationStatus: ["good"] }]) {
    const res = response(); await handler({ ...req, query }, res); assert.equal(res.statusCode, 400, JSON.stringify(query));
  }
  const denied = response();
  await handler({ ...req, authz: { workspaceRole: "viewer" }, query: { location: "host" } }, denied);
  assert.equal(denied.statusCode, 403); assert.equal(calls.length, 0);
  const accepted = response();
  await handler({ ...req, query: { revocationStatus: "disabled", location: " host ", since: "2026-01-01T01:00:00+01:00", until: "2026-01-02T00:00:00Z" } }, accepted);
  assert.equal(accepted.statusCode, 200); assert.equal(calls[0].location, "host"); assert.equal(calls[0].revocationStatus, "disabled");
});


it("passes legacy pagination values through to the evidence reader", async () => {
  const calls = [];
  const handler = createObservationHistoryHandler({
    certificateReader: async () => ({ fingerprintSha256: "abc" }),
    evidenceReader: async (options) => { calls.push(options); return { items: [], pagination: {} }; },
  });
  const req = { params: { certId: "aaaaaaaa-0000-4000-8000-000000000001" }, workspace: { id: "ws" }, authz: { workspaceRole: "viewer" } };
  for (const query of [{ limit: "101", offset: "-1" }, { limit: "1x", offset: "invalid" }]) {
    const res = response();
    await handler({ ...req, query }, res);
    assert.equal(res.statusCode, 200);
    assert.equal(calls.at(-1).limit, query.limit);
    assert.equal(calls.at(-1).offset, query.offset);
  }
});
