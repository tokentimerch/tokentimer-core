"use strict";
/** Select evidence only: profiles never dispatch tests, hide a missing selected
 * report, or convert a partial hosted verdict into full release qualification. */
const assert = require("node:assert/strict");
const DOMAIN = Object.freeze([
  "enterprise-adcs-real",
  "enterprise-adcs-hierarchy-real",
  "native-adcs-issuer-reassignment",
  "adcs-browser-enrollment",
  "adcs-install-interruption",
  "adcs-lost-submit",
  "adcs-uncertain-abandon",
  "adcs-cmc-renewal",
  "adcs-safety-variants",
  "adcs-crash-experiments",
]);
const EXTENDED = Object.freeze([
  "enterprise-adcs-elapsed-pending-real",
  "windows-domain-adcs-retention24h",
  "windows-domain-adcs-default-ttl24h",
  "windows-domain-installed-retention-default-timer",
]);
// Native collection deliberately excludes contract-only diagnostics; omitted slot
// IDs remain in every verdict and cannot imply complete AD CS qualification.
const ADCS_NATIVE = Object.freeze(["enterprise-adcs-real"]);
const PROFILES = Object.freeze({
  full: ["hosted", "domain-adcs", "extended-domain-adcs"],
  "standard-hosted": ["hosted"],
  adcs: ["domain-adcs"],
  "adcs-native": ["domain-adcs"],
  "extended-adcs": ["extended-domain-adcs"],
});
function classify(slot) {
  if (DOMAIN.includes(slot.suite)) return "domain-adcs";
  if (EXTENDED.includes(slot.suite)) return "extended-domain-adcs";
  const caps =
    require("../docs/certops/qualification-suites.json").requiredCapabilities[
      slot.suite
    ] || [];
  assert.ok(
    !caps.includes("domain"),
    "Unclassified domain suite cannot enter hosted qualification",
  );
  return "hosted";
}
function selectProfile(matrix, profile = "full") {
  assert.ok(Object.hasOwn(PROFILES, profile), "Unknown qualification profile");
  assert.ok(
    Array.isArray(matrix?.slots) &&
      matrix.slots.length > 0 &&
      matrix.slots.length <= 512,
  );
  const ids = matrix.slots.map((slot) => slot.id);
  assert.ok(
    ids.every((id) => typeof id === "string" && id.length > 0) &&
      new Set(ids).size === ids.length,
    "Unique committed slot IDs required",
  );
  const selected = matrix.slots.filter((slot) =>
    PROFILES[profile].includes(classify(slot)) &&
    (profile !== "adcs-native" || ADCS_NATIVE.includes(slot.suite)),
  );
  assert.ok(
    selected.length > 0,
    "Qualification profile selects no environments",
  );
  const selectedSlotIds = selected.map((slot) => slot.id);
  return {
    profile,
    selectedSlotIds,
    omittedSlotIds: [...ids.filter((id) => !selectedSlotIds.includes(id)), ...(matrix.deferredSlots || []).map(slot => slot.id)],
    specification: { ...matrix, slots: selected },
  };
}
function summaryFields(selection, qualified = false) {
  return {
    qualificationProfile: selection.profile,
    qualificationScope:
      selection.profile === "full"
        ? "committed-mandatory-matrix"
        : "declared-profile",
    selectedSlotIds: [...selection.selectedSlotIds],
    omittedSlotIds: [...selection.omittedSlotIds],
    fullMatrixQualified: qualified === true && selection.profile === "full" && selection.omittedSlotIds.length === 0,
  };
}
function validateProfileSummary(summary, matrix) {
  const selected = selectProfile(matrix, summary?.qualificationProfile);
  assert.deepEqual(
    Object.fromEntries(
      Object.keys(summaryFields(selected)).map((key) => [key, summary[key]]),
    ),
    summaryFields(selected, summary.status === "passed"),
  );
  assert.equal(summary.mandatoryEnvironments, selected.selectedSlotIds.length);
  assert.equal(summary.allFeaturesQualified, false);
  return selected;
}
function parseArguments(args) {
  let profile = "full",
    rest = [...args];
  if (rest[0] === "--profile") {
    assert.ok(rest.length >= 2, "Explicit qualification profile required");
    profile = rest[1];
    rest = rest.slice(2);
  }
  assert.ok(Object.hasOwn(PROFILES, profile), "Unknown qualification profile");
  assert.ok(
    !rest.some((value) => value.startsWith("--")),
    "Unknown qualification argument",
  );
  return { profile, rest };
}
module.exports = {
  DOMAIN,
  ADCS_NATIVE,
  EXTENDED,
  PROFILES,
  classify,
  selectProfile,
  summaryFields,
  validateProfileSummary,
  parseArguments,
};
