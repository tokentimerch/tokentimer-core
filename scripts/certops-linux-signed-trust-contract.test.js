"use strict";
/** Route authorization and creator selection only. Manual workflow_dispatch only. No live stack. */
const test = require("node:test");
const assert = require("node:assert/strict");
const { createManualCertificateJobHandler } =
  require("../apps/api/routes/certops")._test;
const trust = require("../packages/agent/src/trust-store");
function response() {
  return {
    status(code) {
      this.code = code;
      return this;
    },
    json(body) {
      this.body = body;
      return this;
    },
  };
}
function request(operation, workspaceRole) {
  return {
    body: {
      operation,
      subjectType: "trust_anchor",
      subjectId: "anchor",
      agentId: "registered-agent",
      owner: "qualification",
      idempotencyKey: "owned-intent",
    },
    authz: { workspaceRole },
    workspace: { id: "workspace" },
    user: { id: "administrator" },
  };
}
test("actual manual route refuses manager trust mutations before admission", async () => {
  for (const operation of ["distribute-trust", "revoke-trust"]) {
    let calls = 0;
    const handler = createManualCertificateJobHandler({
      manualJobCreator: () => {
        calls++;
      },
    });
    const result = response();
    await handler(request(operation, "workspace_manager"), result);
    assert.equal(result.code, 403);
    assert.equal(calls, 0);
  }
});
test("actual admin route selects dedicated trust admission without invoking native work", async () => {
  for (const operation of ["distribute-trust", "revoke-trust"]) {
    let observed;
    const handler = createManualCertificateJobHandler({
      manualJobCreator: (options) => {
        observed = options;
        return {
          skippedOsMutation: true,
          installation: { id: "controlled-response" },
        };
      },
    });
    const result = response();
    await handler(request(operation, "admin"), result);
    assert.equal(typeof observed.jobCreator, "function");
    assert.equal(observed.operation, operation);
    assert.equal(observed.subjectType, "trust_anchor");
    assert.equal(observed.subjectId, "anchor");
    assert.equal(observed.source, "api");
    assert.equal(result.code, 200);
  }
});
test("Debian install and derived-link pruning remain distinct explicit production profiles", () => {
  assert.equal(
    trust.trustStoreCommandRefForFamily("debian"),
    "trust-store:update-ca-certificates",
  );
  assert.equal(
    trust.TRUST_STORE_COMMAND_REFS.DEBIAN_UPDATE_CA_CERTIFICATES_FRESH,
    "trust-store:update-ca-certificates-fresh",
  );
  assert.notEqual(
    trust.TRUST_STORE_COMMAND_REFS.DEBIAN_UPDATE_CA_CERTIFICATES_FRESH,
    trust.trustStoreCommandRefForFamily("debian"),
  );
});
