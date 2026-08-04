"use strict";

/**
 * The three capability strings ADR-0012 decision 14 marks as depending on
 * real-host evidence, gated at ADVERTISEMENT time, not only at claim time:
 * windows-cert-store-v1 and iis-binding-v1 depend on the real Windows
 * store/site/binding execution path, and trust-anchor-deploy-v1 depends on
 * the real trust-store install/removal execution path. None of those
 * executors exist yet in this build.
 *
 * Split into its own module (no other dependencies) so that both the
 * runtime gate (./index.js) and the build-time manifest generator
 * (../../scripts/build-qualified-capabilities.js) can require it without
 * either one having to require the other: the generator needs this list to
 * validate qualified-capabilities.json BEFORE the generated module it
 * produces (./qualified-capabilities.generated.js) exists, so it cannot
 * depend on anything that itself requires that generated file.
 */
const GATED_CAPABILITIES = Object.freeze([
  "windows-cert-store-v1",
  "iis-binding-v1",
  "trust-anchor-deploy-v1",
]);

module.exports = { GATED_CAPABILITIES };
