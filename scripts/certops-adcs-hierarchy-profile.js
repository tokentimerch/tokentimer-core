"use strict";
/* Explicit single-campaign hierarchy selectors. Each manual run provisions one
 * owned lab; all nine measured member environments remain independently needed
 * by release qualification. This does not dispatch or provision anything. */
const assert = require("node:assert/strict");
const VERSIONS = Object.freeze(["2019", "2022", "2025"]);
const LANGUAGES = Object.freeze(["en-US", "de-DE", "fr-FR"]);
const REQUIRED_SOURCES = Object.freeze([
  "scripts/certops-adcs-hierarchy-profile.js",
  ".github/workflows/certops-enterprise-adcs-hierarchy-qualification.yml",
]);
function profile(version, language) {
  assert.ok(
    VERSIONS.includes(version),
    "Supported hierarchy member Windows Server required",
  );
  assert.ok(
    LANGUAGES.includes(language),
    "Supported actual hierarchy UI language required",
  );
  return {
    osFamily: "windows",
    osVersion: version,
    nativeLanguage: language,
    identity: "LocalSystem",
  };
}
function environments() {
  return VERSIONS.flatMap((version) =>
    LANGUAGES.map((language) => profile(version, language)),
  );
}
module.exports = {
  VERSIONS,
  LANGUAGES,
  REQUIRED_SOURCES,
  profile,
  environments,
};
if (require.main === module) {
  const selected = profile(
    process.env.WINDOWS_VERSION,
    process.env.WINDOWS_LANGUAGE,
  );
  process.stdout.write(JSON.stringify(selected) + "\n");
}
