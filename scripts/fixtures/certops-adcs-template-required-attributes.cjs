"use strict";
/** Synthetic closed report factory; never actual LDAP/restoration evidence. */
const helper = require("../../tests/e2e/helpers/certops-adcs-template-required-attributes");
const descriptor = require("../../infra/certops-adcs/template-required-attribute-cases.json");
function proof() {
  return {
    scope: helper.SCOPE,
    predecessorFingerprint: "a".repeat(64),
    templateOid: "1.3.6.1.4.1.311.21.8.2",
    cases: descriptor.cases.map((item, index) => ({
      caseId: item.id,
      preflightVerdict: "unreadable",
      reason: "template_unreadable",
      observedField: item.observedField,
      observedValue: item.observedValue,
      enrollmentId: `${String(index * 2 + 1).padStart(8, "0")}-1111-1111-1111-111111111111`,
      jobId: `${String(index * 2 + 2).padStart(8, "0")}-1111-1111-1111-111111111111`,
      ...Object.fromEntries(helper.FLAGS.map(flag => [flag, true])),
    })),
  };
}
module.exports = { proof };
