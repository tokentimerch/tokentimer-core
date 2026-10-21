/*
 * Qualification notes: installer-pe-preflight
 * Shared setup, dispatch and evidence rules: docs/certops/e2e-qualification.md.
 * Separate native PE preflight reads selected host and store-survivor helper before installed changes
 * and rereads staged copies before renames. Both architectures require bounded DOS/COFF/PE32+
 * executable non-DLL headers,sections/alignment/nonoverlap,file-backed code entry;
 * caps64MiB/96sections. Read handles exclude write/delete/reparse; structural checks are not
 * Authenticode/loader/runtime attestation. Refuse preexisting stage, bind new stage native file
 * identity via trusted system Node fs with NODE_OPTIONS/NODE_PATH temporarily removed/restored;
 * preload sentinel verifies isolation. Cleanup preserves replaced/linked stage and original validation
 * error. scripts/certops-installer-pe.test.ps1 extracts actual AST only:4 compiled-image positives,44
 * malformed/missing/architecture negatives plus staged corruption/cleanup branches. Installed RSA2048
 * lane separately requires6 real host/helper refusals preserving live
 * service/config/credential/pin/unused bootstrap/no swaps. Structurally valid genuine chain helper in
 * host slot exercises distinct SCM health rollback. No candidate execution in PE checks; ARM64 byte
 * inspection is not ARM64 execution.
 */
"use strict";
/** Pure refusal tests for native path proof, without filesystem mutations. */
const { test } = require("node:test"), assert = require("node:assert/strict"), fixture = require("./certops-installer-path-support");
test("installer path proof requires every literal/junction/control count and owned cleanup", () => {
  const proof = { scope: "actual-production-copy-activation-temporary-filesystem", positivePathShapes: 3, copyJunctionRefusals: 6, activationJunctionRefusals: 4, serviceOrCertificateExecutionQualified: false, ...Object.fromEntries(fixture.fields.map(field => [field, true])) };
  fixture.verifyProof(proof);
  for (const field of fixture.fields) { const missing = { ...proof }; delete missing[field]; assert.throws(() => fixture.verifyProof(missing)); for (const value of [false, null, 1, "true"]) assert.throws(() => fixture.verifyProof({ ...proof, [field]: value })); }
  for (const changes of [{ positivePathShapes: 2 }, { copyJunctionRefusals: 5 }, { activationJunctionRefusals: 3 }, { serviceOrCertificateExecutionQualified: true }, { scope: "full-installer" }, { rawPaths: [] }]) assert.throws(() => fixture.verifyProof({ ...proof, ...changes }));
});
