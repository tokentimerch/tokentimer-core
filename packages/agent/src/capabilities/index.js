"use strict";

/**
 * Build-time qualified-capabilities manifest gate (ADR-0012 decision 14,
 * corrected 2026-08-02 from a runtime-environment-variable mechanism to a
 * build-time manifest, and corrected again 2026-08-03 from a
 * runtime-readable JSON file to a build-time-generated, code-embedded
 * module).
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
 * The manifest is embedded into the agent AT BUILD TIME as ordinary,
 * frozen JavaScript (./qualified-capabilities.generated.js), the same way
 * a version string is embedded: it is not read from an environment
 * variable, a config file, or any other operator-configurable source at
 * runtime, because whoever can edit a file next to the running agent and
 * restart it is exactly the actor this gate exists to take the decision
 * away from. qualified-capabilities.json (sibling to this file) is the
 * build INPUT only -- scripts/build-qualified-capabilities.js compiles it
 * into the generated module below, and nothing in this package reads that
 * JSON file at runtime. A capability absent from the generated module is
 * never advertised and therefore never claimed, regardless of whether the
 * code that could serve it exists in this build; CI builds its own
 * manifest locally (typically naming every gated capability, so the
 * underlying code stays exercised in CI) and is not bound by the release
 * manifest.
 *
 * This module does not decide WHICH capabilities are gate-controlled; that
 * is GATED_CAPABILITIES (./gated-capabilities.js), mirroring ADR-0012
 * decision 14's three strings. A capability not in GATED_CAPABILITIES is
 * unaffected by this gate entirely (always advertisable, e.g.
 * evidence-claim-binding-v1).
 */

const path = require("node:path");

const { GATED_CAPABILITIES } = require("./gated-capabilities.js");

const GATED_CAPABILITY_SET = new Set(GATED_CAPABILITIES);

const DEFAULT_MANIFEST_MODULE_PATH = path.join(
  __dirname,
  "qualified-capabilities.generated.js",
);

// Test-only override seam: lets a test point the loader at a fixture module
// (to simulate a missing, malformed, or unrecognized-entry manifest) without
// touching the real build artifact. Production code never calls the setter,
// so this always resolves to DEFAULT_MANIFEST_MODULE_PATH outside tests.
let manifestModulePath = DEFAULT_MANIFEST_MODULE_PATH;

/**
 * Loads and validates the embedded manifest. Cached after the first call
 * (the manifest is a build-time artifact, not something that changes while
 * the process runs).
 *
 * The generated module is already validated by
 * scripts/build-qualified-capabilities.js at build time; this re-validates
 * its shape and contents at load time too (defense in depth against a
 * generated file that was hand-edited or corrupted after the fact, bypassing
 * the build step). Any failure here throws, which is a startup rejection:
 * this module is required from the agent's main entrypoint
 * (packages/agent/src/index.js) before the agent does anything else, so a
 * bad manifest stops the process rather than silently advertising nothing
 * (or, worse, something unqualified).
 *
 * @returns {{ qualified: readonly string[] }}
 */
let cachedManifest = null;
function loadQualifiedCapabilitiesManifest() {
  if (cachedManifest) return cachedManifest;

  let loaded;
  try {
    // eslint-disable-next-line global-require -- lazy, path is dynamic (test seam)
    loaded = require(manifestModulePath);
  } catch (err) {
    throw new Error(
      `qualified-capabilities manifest module is missing or failed to load ` +
        `at ${manifestModulePath}: ${err?.message || err}. Run ` +
        `"node packages/agent/scripts/build-qualified-capabilities.js" to ` +
        `(re)generate it from qualified-capabilities.json.`,
    );
  }

  const qualified = Array.isArray(loaded?.qualified) ? loaded.qualified : null;
  if (!qualified) {
    throw new Error(
      `qualified-capabilities manifest module at ${manifestModulePath} must ` +
        `export a "qualified" array`,
    );
  }

  // An unrecognized string in the manifest is rejected at load time rather
  // than silently ignored (ADR-0012 decision 14 acceptance criteria): a
  // typo or a stale entry for a retired capability string must fail loudly,
  // not quietly advertise nothing for it.
  for (const entry of qualified) {
    if (typeof entry !== "string" || !GATED_CAPABILITY_SET.has(entry)) {
      throw new Error(
        `qualified-capabilities manifest module at ${manifestModulePath} names ` +
          `unrecognized capability ${JSON.stringify(entry)}; must be one of ` +
          `${GATED_CAPABILITIES.join(", ")}`,
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
 * Test-only: points the loader at a different manifest module (a fixture
 * simulating a missing/malformed/unrecognized-entry manifest) and clears the
 * cache so the next load re-reads it. This is the real injectable path the
 * previous version of this module's docblock described but did not actually
 * provide (MANIFEST_PATH was a hardcoded module-level const with no seam).
 * Also clears the module's own require cache entry so a test can reuse the
 * same fixture path across cases with different contents.
 *
 * @param {string|null} overridePath null resets to the real generated module.
 */
function _setManifestModulePathForTests(overridePath) {
  if (overridePath) {
    try {
      delete require.cache[require.resolve(overridePath)];
    } catch {
      // Not yet resolvable (e.g. simulating a missing file) -- nothing to evict.
    }
  }
  manifestModulePath = overridePath || DEFAULT_MANIFEST_MODULE_PATH;
  cachedManifest = null;
}

/**
 * Test-only: clears the cached manifest and resets the loader back to the
 * real generated module. Production code never calls this; the manifest is
 * immutable for the lifetime of the process.
 */
function _resetQualifiedCapabilitiesCacheForTests() {
  cachedManifest = null;
  manifestModulePath = DEFAULT_MANIFEST_MODULE_PATH;
}

module.exports = {
  GATED_CAPABILITIES,
  DEFAULT_MANIFEST_MODULE_PATH,
  loadQualifiedCapabilitiesManifest,
  filterQualifiedCapabilities,
  _setManifestModulePathForTests,
  _resetQualifiedCapabilitiesCacheForTests,
};
