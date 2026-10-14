"use strict";
/** Pure descriptor/parser/proof controls, never native LDAP or CA evidence. */
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path");
const h = require("../tests/e2e/helpers/certops-adcs-template-required-attributes"),
  descriptor = require("../infra/certops-adcs/template-required-attribute-cases.json");
const uuid = (n) => `${String(n).padStart(8, "0")}-1111-1111-1111-111111111111`;
function proof() {
  return {
    scope: h.SCOPE,
    predecessorFingerprint: "a".repeat(64),
    templateOid: "1.3.6.1.4.1.311.21.8.2",
    cases: descriptor.cases.map((item, index) => ({
      caseId: item.id,
      preflightVerdict: "unreadable",
      reason: "template_unreadable",
      observedField: item.observedField,
      observedValue: item.observedValue,
      enrollmentId: uuid(index * 2 + 1),
      jobId: uuid(index * 2 + 2),
      ...Object.fromEntries(h.FLAGS.map((flag) => [flag, true])),
    })),
  };
}
test("zero minimum and missing name flag reach distinct actual production parser predicates", () => {
  const {
    parseTemplateDump,
  } = require("../packages/agent/src/issuers/adcs-preflight");
  const safe = [
    "cn = SafeWeb",
    "msPKI-Template-Schema-Version = 2",
    "pKIExtendedKeyUsage = 1.3.6.1.5.5.7.3.1",
    "msPKI-Certificate-Application-Policy = 1.3.6.1.5.5.7.3.1",
    "msPKI-Minimal-Key-Size = 2048",
    "msPKI-Certificate-Name-Flag = 1",
    "msPKI-Cert-Template-OID = 1.3.6.1.4.1.311.21.8.2",
  ].join("\n");
  assert.equal(parseTemplateDump(safe, "SafeWeb").verdict, "safe");
  for (const selected of descriptor.cases) {
    const changed =
        selected.operation === "set-zero"
          ? safe.replace(
              `${selected.attribute} = 2048`,
              `${selected.attribute} = 0`,
            )
          : safe
              .split("\n")
              .filter((line) => !line.startsWith(selected.attribute + " = "))
              .join("\n"),
      actual = parseTemplateDump(changed, "SafeWeb");
    assert.equal(actual.verdict, "unreadable");
    assert.deepEqual(actual.reasons, ["template_unreadable"]);
    assert.equal(actual[selected.observedField], selected.observedValue);
    assert.equal(
      actual.templateOid,
      parseTemplateDump(safe, "SafeWeb").templateOid,
    );
  }
});
test("required-attribute proof refuses missing restoration, skipped native conditions and reused jobs", () => {
  assert.equal(h.verifyProof(proof()), true);
  for (const flag of h.FLAGS) {
    const bad = proof();
    bad.cases[0][flag] = false;
    assert.throws(() => h.verifyProof(bad));
  }
  for (const mutate of [
    (v) => v.cases.reverse(),
    (v) => v.cases.pop(),
    (v) => (v.cases[0].observedValue = null),
    (v) => (v.cases[1].observedValue = false),
    (v) => (v.cases[1].jobId = v.cases[0].jobId),
    (v) => (v.cases[0].preflightVerdict = "unsafe"),
    (v) => (v.privateReceipt = "sentinel"),
  ]) {
    const bad = proof();
    mutate(bad);
    assert.throws(() => h.verifyProof(bad));
  }
});
test("unknown or unresolved LDAP receipt cannot authorize native or public cleanup", () => {
  h.assertCleanupSafe([]);
  for (const values of [
    [{ restored: false }],
    [{ restored: true }],
    [{}],
    null,
  ])
    assert.throws(() => h.assertCleanupSafe(values));
});
test("native source registers restoration before mutation and measures a fresh safe control after exact restore", () => {
  const source = fs.readFileSync(
      path.resolve(
        __dirname,
        "../tests/e2e/helpers/certops-adcs-template-required-attributes.js",
      ),
      "utf8",
    ),
    compact = source.replace(/\s/g, "");
  assert.ok(
    compact.indexOf("ownedTemplateAttributeRestorations.push(receipt)") <
      compact.indexOf('mutate("apply")'),
  );
  assert.ok(
    compact.indexOf('mutate("restore")') <
      compact.lastIndexOf("preflightCohorts.preflight("),
  );
  assert.ok(compact.includes("restored.exactPublicAttributesVerified,true"));
  assert.ok(compact.includes("receipt.restored=true"));
  assert.ok(compact.includes('path.join(configDir,"credential")'));
  assert.doesNotMatch(
    source,
    /UPDATE\s|DELETE\s|INSERT\s|writeEnrollmentJournal|Set-Date|utimes/,
  );
});
