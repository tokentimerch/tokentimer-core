"use strict";

/**
 * Build-time qualified-capabilities manifest gate (ADR-0012 decision 14,
 * corrected 2026-08-02 from a runtime-environment-variable mechanism to a
 * build-time manifest).
 *
 * Some capability strings depend on real-host evidence (real IIS
 * renewal/rollback, real Windows-store and Linux trust-store
 * install/removal) that release planning treats as a hard tag gate: the
 * code path may exist and be fully unit-tested, but the string must not be
 * ADVERTISED to the control plane until a real-host test run against the
 * exact build artifact has proven it. "The code ships with the capability
 * undeclared until that evidence exists" is a release policy; without a
 * mechanism, it is a policy any agent build can violate by simply having
 * the underlying code and declaring the string anyway.
 *
 * The manifest (qualified-capabilities.json, sibling to this file) is
 * committed to the release branch and embedded into the agent at build
 * time, the same way a version string is embedded: it is not read from an
 * environment variable, a config file, or any other operator-configurable
 * source, because whoever configures the agent's runtime environment is
 * exactly the actor this gate exists to take the decision away from. A
 * capability absent from the embedded manifest is never advertised and
 * therefore never claimed, regardless of whether the code that could serve
 * it exists in this build; CI builds its own manifest locally (typically
 * naming every gated capability, so the underlying code stays exercised in
 * CI) and is not bound by the release manifest.
 *
 * This module does not decide WHICH capabilities are gate-controlled; that
 * is GATED_CAPABILITIES below, mirroring ADR-0012 decision 14's three
 * strings. A capability not in GATED_CAPABILITIES is unaffected by this
 * gate entirely (always advertisable, e.g. evidence-claim-binding-v1).
 */

const fs = require("node:fs");
const path = require("node:path");

const MANIFEST_PATH = path.join(__dirname, "qualified-capabilities.json");

// The three capability strings ADR-0012 decision 14 marks as depending on
// real-host evidence, gated at ADVERTISEMENT time, not only at claim time.
// windows-cert-store-v1 and iis-binding-v1 are Wave 2b execution work (not
// implemented yet in this change); trust-anchor-deploy-v1 is Wave 3. All
// three are listed here now, in this shared contract-foundation change, so
// the gate and the capability constants land together rather than the gate
// being invented ad hoc whenever the first gated capability is implemented.
const GATED_CAPABILITIES = Object.freeze([
  "windows-cert-store-v1",
  "iis-binding-v1",
  "trust-anchor-deploy-v1",
]);
const GATED_CAPABILITY_SET = new Set(GATED_CAPABILITIES);

/**
 * Loads and validates the embedded manifest. Cached after the first call
 * (the manifest is a build-time artifact, not something that changes while
 * the process runs).
 *
 * @returns {{ qualified: readonly string[] }}
 */
let cachedManifest = null;
function loadQualifiedCapabilitiesManifest() {
  if (cachedManifest) return cachedManifest;

  let raw;
  try {
    raw = fs.readFileSync(MANIFEST_PATH, "utf8");
  } catch (err) {
    throw new Error(
      `qualified-capabilities manifest is missing at ${MANIFEST_PATH}: ${err?.message || err}`,
    );
  }

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(
      `qualified-capabilities manifest at ${MANIFEST_PATH} is not valid JSON: ${err?.message || err}`,
    );
  }

  const qualified = Array.isArray(parsed?.qualified) ? parsed.qualified : null;
  if (!qualified) {
    throw new Error(
      `qualified-capabilities manifest at ${MANIFEST_PATH} must have a "qualified" array`,
    );
  }

  // An unrecognized string in the manifest is rejected at build/load time
  // rather than silently ignored (ADR-0012 decision 14 acceptance
  // criteria): a typo or a stale entry for a retired capability string
  // must fail loudly, not quietly advertise nothing for it.
  for (const entry of qualified) {
    if (typeof entry !== "string" || !GATED_CAPABILITY_SET.has(entry)) {
      throw new Error(
        `qualified-capabilities manifest at ${MANIFEST_PATH} names unrecognized ` +
          `capability ${JSON.stringify(entry)}; must be one of ${GATED_CAPABILITIES.join(", ")}`,
      );
    }
  }

  cachedManifest = Object.freeze({ qualified: Object.freeze([...qualified]) });
  return cachedManifest;
}

/**
 * Filters a list of candidate capability strings down to the ones this
 * build is actually allowed to advertise: every ungated capability passes
 * through unchanged, and every gated capability (GATED_CAPABILITIES) passes
 * through only when the embedded manifest names it.
 *
 * This is a MATCHING/ADVERTISEMENT filter, not a security boundary (ADR-0012
 * decision 14): it controls what the agent tells the control plane it can
 * do, not what the underlying code is capable of. The gate exists so a
 * release process can promote the exact tested build artifact unchanged,
 * never a rebuild with a manifest edit.
 *
 * @param {readonly string[]} candidateCapabilities
 * @returns {readonly string[]}
 */
function filterQualifiedCapabilities(candidateCapabilities) {
  const manifest = loadQualifiedCapabilitiesManifest();
  const qualifiedSet = new Set(manifest.qualified);
  return Object.freeze(
    (Array.isArray(candidateCapabilities) ? candidateCapabilities : []).filter(
      (capability) =>
        !GATED_CAPABILITY_SET.has(capability) || qualifiedSet.has(capability),
    ),
  );
}

/**
 * Test-only: clears the cached manifest so a test can point MANIFEST_PATH
 * overrides or reload after mutating the on-disk fixture. Production code
 * never calls this; the manifest is immutable for the lifetime of the
 * process.
 */
function _resetQualifiedCapabilitiesCacheForTests() {
  cachedManifest = null;
}

module.exports = {
  GATED_CAPABILITIES,
  MANIFEST_PATH,
  loadQualifiedCapabilitiesManifest,
  filterQualifiedCapabilities,
  _resetQualifiedCapabilitiesCacheForTests,
};
