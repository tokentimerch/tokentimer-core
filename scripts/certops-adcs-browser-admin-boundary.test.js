"use strict";
/** Proof/authorization-observation contract only. No public request, browser,
 * role mutation, native certificate operation or hosted resource is executed. */
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  h = require("../tests/e2e/helpers/certops-adcs-browser-admin-boundary");
const id = "11111111-1111-1111-1111-111111111111";
function proof() {
  return {
    scope: h.SCOPE,
    enrollmentId: id,
    forbiddenMutations: 4,
    roleChanges: 2,
    adminDemotions: 0,
    mountedAdminWithdrawalQualified: false,
    ...Object.fromEntries(h.FLAGS.map((flag) => [flag, true])),
  };
}
function observations() {
  return {
    roles: ["workspace_manager", "viewer", "workspace_manager"],
    forbiddenStatuses: [403, 403, 403, 403],
    adminDemotionStatus: 403,
    ownerRole: "admin",
    actorGlobalAdmin: false,
    controllerGlobalAdmin: false,
  };
}
test("role boundary cannot claim public admin withdrawal or omit measured refusal facts", () => {
  assert.equal(h.verifyProof(proof()), true);
  for (const key of Object.keys(proof())) {
    const missing = proof();
    delete missing[key];
    assert.throws(() => h.verifyProof(missing), key);
  }
  for (const mutate of [
    (p) => (p.mountedAdminWithdrawalQualified = true),
    (p) => (p.adminDemotions = 1),
    (p) => (p.forbiddenMutations = 3),
    (p) => (p.roleChanges = 1),
    (p) => (p.scope = "mounted-admin-withdrawal"),
    (p) => (p.rawCredential = "private"),
  ]) {
    const value = proof();
    mutate(value);
    assert.throws(() => h.verifyProof(value));
  }
  for (const flag of h.FLAGS) {
    const value = proof();
    value[flag] = false;
    assert.throws(() => h.verifyProof(value));
  }
});
test("actual role observations require non-global-admin principals and all four403s", () => {
  assert.equal(h.verifyRoleObservations(observations()), true);
  for (const mutate of [
    (o) => (o.roles = ["admin", "viewer", "admin"]),
    (o) => (o.actorGlobalAdmin = true),
    (o) => (o.controllerGlobalAdmin = true),
    (o) => (o.ownerRole = "viewer"),
    (o) => (o.adminDemotionStatus = 200),
    (o) => (o.forbiddenStatuses[0] = 204),
    (o) => o.forbiddenStatuses.pop(),
  ]) {
    const value = observations();
    mutate(value);
    assert.throws(() => h.verifyRoleObservations(value));
  }
});
test("critical sources expose actual supported role and enrollment boundaries", () => {
  for (const file of h.REQUIRED_SOURCES)
    assert.ok(fs.statSync(path.resolve(__dirname, "..", file)).isFile());
  assert.equal(new Set(h.REQUIRED_SOURCES).size, h.REQUIRED_SOURCES.length);
  const routes = fs.readFileSync(
    path.resolve(__dirname, "../apps/api/routes/workspaces.js"),
    "utf8",
  );
  assert.ok(routes.includes("Workspace admin role cannot be changed here"));
  assert.ok(routes.includes("Forbidden: cannot remove admin"));
  const rbac = fs.readFileSync(
    path.resolve(__dirname, "../apps/api/services/rbac.js"),
    "utf8",
  );
  assert.ok(rbac.includes('"certops.issuer.manage": "admin"'));
  assert.equal(h.REQUIRED_SCENARIOS.length, 2);
});
