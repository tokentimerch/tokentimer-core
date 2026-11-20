"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const Module = require("node:module");

test("audit CSV preserves user IDs and quotes untrusted display text safely", async () => {
  const file = path.resolve(__dirname, "../../apps/api/routes/usage.js");
  const routeModule = { exports: {} };
  const row = {
    id: 19,
    occurred_at: "2026-11-20T07:00:00Z",
    actor_user_id: 7,
    actor_display_name: 'Alex "Ops"',
    subject_user_id: 42,
    action: "CERTOPS_ISSUER_CREATED",
    target_type: "certops_issuer",
    target_id: null,
    channel: null,
    workspace_id: "workspace-id",
    workspace_name: "  +Operations",
    metadata: { issuerId: "issuer-id" },
  };
  let handler;
  const actual = Module.createRequire(file);
  const mocks = {
    express: { Router: () => ({
      get(route, ...callbacks) {
        if (route === "/api/account/export-audit") handler = callbacks.at(-1);
      },
      post() {},
    }) },
    "../db/database": { pool: {
      async query(sql, params) {
        assert.match(sql, /FROM audit_events ae/);
        assert.deepEqual(params, ["CERTOPS_ISSUER_CREATED", 10000]);
        return { rows: [row, { ...row, actor_display_name: "\tOperations", actor_user_id: null }] };
      },
    } },
    "../utils/logger": { logger: { error: assert.fail } },
    "../middleware/auth": {},
    "../middleware/rateLimit": { getApiLimiter() {} },
    "../services/rbac": {},
    "../config/constants": {},
    "../services/planLimits": {},
    "../services/alertQueue": {},
    "../db/models/User": {},
    "../db/models/Token": {},
    "../src/shared/contactGroups": {},
  };
  vm.runInThisContext(Module.wrap(fs.readFileSync(file, "utf8")), { filename: file })(
    routeModule.exports,
    (name) => Object.hasOwn(mocks, name) ? mocks[name] : actual(name),
    routeModule,
    file,
    path.dirname(file),
  );
  const responseHeaders = new Map();
  let body;
  assert.ok(handler);
  await handler(
    {
      user: { id: 1, is_admin: true },
      query: {
        scope: "organization",
        format: "csv",
        action: "certops.issuer.created",
      },
      headers: {},
    },
    {
      setHeader(name, value) { responseHeaders.set(name, value); },
      send(value) { body = value; },
    },
  );
  assert.equal(responseHeaders.get("Content-Type"), "text/csv; charset=utf-8");
  const [header, first, second] = body.split("\n");
  assert.equal(
    header,
    "id,occurred_at,actor_display_name,action,target_type,target_id,channel,workspace_id,workspace_name,metadata,actor_user_id,subject_user_id",
  );
  assert.equal(
    first,
    String.raw`"19","2026-11-20T07:00:00Z","Alex ""Ops""","CERTOPS_ISSUER_CREATED","certops_issuer","","","workspace-id","'  +Operations","{""issuerId"":""issuer-id""}","7","42"`,
  );
  assert.ok(second.includes("\"'\tOperations\""));
  assert.ok(second.endsWith(',"","42"'));
});
