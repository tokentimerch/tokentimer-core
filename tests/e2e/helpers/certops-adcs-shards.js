"use strict";
/*
 * Diagnostic sharding for the native AD CS qualification.
 *
 * One lab can run the whole journey ("all", the only mode that can produce release evidence) or one shard.
 * Shards exist to shorten feedback: independent labs run in parallel and one cascading failure can no longer
 * exhaust the failure budget and hide the remaining scenarios. A shard report is always experimental and
 * not-qualified, so the release collector can never count it as evidence for a native slot.
 *
 * Phases follow the execution order of tests/e2e/certops-adcs-real-e2e.test.js. A phase is only ever run
 * together with every phase it reads state from:
 *  - capacity -> ca: the pending CA renewal proof reads gate.report.nativeAdcsCapacity and the capacity store receipts.
 *  - pending  -> ca: pending CA key change and renewal reuse pendingRecoveryFixtures.
 *  - ca keeps its own order (same-key renewal, key change, revalidation, validation expiry, CRL outage, stopped site)
 *    because they chain renewalFixture.observed / currentEnrollmentId.
 *  - renewals is one chain: manual -> profile -> scheduler -> two -> background -> live ACL -> HTTP CRL -> OCSP -> outbox
 *    (profileId, ownedBackgroundStoreCertificates and renewalFixture.observed are produced step by step).
 */

const PHASES = Object.freeze(["core", "capacity", "renewals", "pending", "templates", "ca", "uncertain"]);

const SHARDS = Object.freeze({
  issuance: Object.freeze(["core"]),
  renewals: Object.freeze(["renewals"]),
  "pending-and-ca": Object.freeze(["capacity", "pending", "ca"]),
  "templates-and-uncertain": Object.freeze(["templates", "uncertain"]),
});

const SHARD_NAMES = Object.freeze(["all", ...Object.keys(SHARDS)]);

// Scenarios every shard owns because every shard performs the same setup and cleanup.
const EVERY_SHARD = Object.freeze(["setup", "cleanup"]);

const CAPACITY_BROWSER = /^adcs-real-browser-(?:requested-renewal-cancel|cancel-native-custody-and-capacity|job-approval-.+)$/;
const CORE_TEMPLATE_KEY = /^adcs-real-template-key-(?:rsa2048-below-template3072|rsa3072-below-template4096|ec256-on-p384-schema-three|ec256-on-p384-schema-four)-refused$/;

// First match wins. Every required scenario must resolve to exactly one phase (unit-tested and re-asserted at run start).
const RULES = Object.freeze([
  [/^adcs-real-(?:installed-native-language|agent-registration-system)$/, "setup"],
  [/^adcs-real-owned-cleanup$/, "cleanup"],
  [CAPACITY_BROWSER, "capacity"],
  [/^adcs-real-capacity-/, "capacity"],
  [/^adcs-real-browser-/, "uncertain"],
  [/^adcs-real-[a-z0-9]+-(?:issued|renewed)-cng-iis$/, "core"],
  [/^adcs-real-localized-/, "core"],
  [CORE_TEMPLATE_KEY, "core"],
  [/^adcs-real-webhosting-/, "core"],
  [/^adcs-real-native-(?:reconcile|retrieve)-/, "core"],
  [/^adcs-real-(?:late-approved-older-leaf-refused|minimum-remaining-validity-refused|cancel-ca-issued-unaccepted-key)$/, "core"],
  [/^adcs-real-local-rule-/, "core"],
  [/^adcs-real-pending-key-survivor-preserves-retrieval-and-installed-custody$/, "core"],
  [/^adcs-real-(?:manual-renewal-replaces-iis-certificate|profile-automatic-service-renewal|scheduler-selects-short-lived-observed-certificate)$/, "renewals"],
  [/^adcs-real-(?:two-|background-|live-|http-|ocsp-|native-ocsp-|native-success-result-outbox)/, "renewals"],
  [/^adcs-hierarchy-/, "renewals"],
  [/^adcs-real-(?:pending-request-refuses-new-ca-key|pending-issuer-reconfirmation-fresh-request-recovers)$/, "ca"],
  [/^adcs-real-ca-(?:renewal|same-key|revocation|key-change|revalidation)-/, "ca"],
  [/^adcs-real-(?:elapsed-validation-deadline-frees-unaccepted-key|crl-outage-defers-then-recovers-owned-key|stopped-site-tls-failure-restores-outgoing-binding)$/, "ca"],
  [/^adcs-real-ca-flags-/, "templates"],
  [/^adcs-real-(?:template-key-|template-.+-denied$|unsafe-|mutated-template-|required-template-)/, "templates"],
  [/^adcs-real-(?:pending-|late-approval-|cancelled-late-approval-|same-certificate-|deleted-request-|installation-failure-|native-cmc-|initial-certreq-|issued-)/, "pending"],
  [/^adcs-real-service-restart-preserves-registration$/, "uncertain"],
  [/^adcs-real-(?:uncertain-|public-reconcile-)/, "uncertain"],
]);

function phaseOf(id) {
  for (const [pattern, phase] of RULES) if (pattern.test(id)) return phase;
  return null;
}

function normalizeShard(value) {
  const shard = value === undefined || value === null || value === "" ? "all" : String(value);
  if (!SHARD_NAMES.includes(shard)) throw new Error(`Unknown AD CS qualification shard: ${shard}`);
  return shard;
}

function createShard(value) {
  const name = normalizeShard(value);
  const phases = name === "all" ? new Set(PHASES) : new Set(SHARDS[name]);
  const sharded = name !== "all";
  function runs(phase) {
    if (!PHASES.includes(phase)) throw new Error(`Unknown AD CS qualification phase: ${phase}`);
    return phases.has(phase);
  }
  function owns(id) {
    const phase = phaseOf(id);
    if (!phase) throw new Error(`Scenario is not assigned to a qualification shard: ${id}`);
    return EVERY_SHARD.includes(phase) || phases.has(phase);
  }
  // Fails closed for shards: a required scenario without an owner would silently disappear from every shard.
  // The "all" mode is deliberately untouched so the release path never depends on this mapping.
  function select(requiredScenarios) {
    if (!sharded) return requiredScenarios;
    for (const id of requiredScenarios) if (!phaseOf(id)) throw new Error(`Scenario is not assigned to a qualification shard: ${id}`);
    return requiredScenarios.filter(owns);
  }
  return Object.freeze({ name, sharded, phases: Object.freeze([...phases]), runs, owns, select });
}

module.exports = { PHASES, SHARDS, SHARD_NAMES, RULES, phaseOf, createShard, normalizeShard };
