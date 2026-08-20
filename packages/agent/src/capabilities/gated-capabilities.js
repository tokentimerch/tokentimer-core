"use strict";

/**
 * The three capability strings ADR-0012 decision 14 marks as depending on
 * real-host evidence, gated at ADVERTISEMENT time, not only at claim time:
 * windows-cert-store-v1 and iis-binding-v1 depend on the real Windows
 * store/site/binding execution path, and trust-anchor-deploy-v1 depends on
 * the real trust-store install/removal execution path.
 *
 * windows-cert-store-v1 and iis-binding-v1's executors exist and have been
 * real-host verified (Windows Server 2019/2022/2025; see
 * docs/certops/agent.md and the real-host verification runbook), so
 * ./qualified-capabilities.json now names both. trust-anchor-deploy-v1 has
 * no executor at all yet (targets 0.14.0) and stays unqualified.
 * This list itself never changes based on evidence -- it is the fixed set
 * of strings the build-time manifest is allowed to name at all; whether a
 * given build's manifest actually qualifies one is a release decision made
 * per-tag, described in ./qualified-capabilities.json's own history and the
 * release process's exit-criteria documentation, not here.
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
