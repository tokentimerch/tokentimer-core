"use strict";
/** Pure refusal tests for native path proof, without filesystem mutations. */
const { test } = require("node:test"), assert = require("node:assert/strict"), fixture = require("./certops-installer-path-support");
test("installer path proof requires every literal/junction/control count and owned cleanup", () => {
  const proof = { scope: "actual-production-copy-activation-temporary-filesystem", positivePathShapes: 3, copyJunctionRefusals: 6, activationJunctionRefusals: 4, serviceOrCertificateExecutionQualified: false, ...Object.fromEntries(fixture.fields.map(field => [field, true])) };
  fixture.verifyProof(proof);
  for (const field of fixture.fields) { const missing = { ...proof }; delete missing[field]; assert.throws(() => fixture.verifyProof(missing)); for (const value of [false, null, 1, "true"]) assert.throws(() => fixture.verifyProof({ ...proof, [field]: value })); }
  for (const changes of [{ positivePathShapes: 2 }, { copyJunctionRefusals: 5 }, { activationJunctionRefusals: 3 }, { serviceOrCertificateExecutionQualified: true }, { scope: "full-installer" }, { rawPaths: [] }]) assert.throws(() => fixture.verifyProof({ ...proof, ...changes }));
});
