/**
 * Fail-closed AD CS template and CA safety checks shared by preflight and enrollment.
 * Native helper evidence, requested key constraints and explicit operator attestation
 * have distinct roles; attestation cannot override an observed unsafe native setting. */
"use strict";

const { executeAdcsPreflight, cachePreflightLocally, matchEnrollmentRule } = require("./adcs-preflight");
const { PREFLIGHT_CACHE_TTL_MS, mapSnapshotKeyAlgorithm } = require("./adcs-enrollment");
const SAFETY_REUSE_MS = Math.min(PREFLIGHT_CACHE_TTL_MS, 5 * 60 * 1000);
const MAX_CACHE_PAIRS = 32;

function refusal(errorCode, detail) { return { ok: false, errorCode, detail }; }

function evaluateEnrollmentSafety({ preflightResult, snapshot, operatorAttested = false }) {
  if (!preflightResult || preflightResult.caConfig !== snapshot.caConfig || preflightResult.template !== snapshot.template) {
    return refusal("ADCS_TEMPLATE_UNSAFE", "Current preflight is not bound to the signed CA and template");
  }
  const template = preflightResult.templateCheck;
  const schema = template?.schemaVersion;
  if (template?.verdict !== "safe" || !Array.isArray(template.reasons) || template.reasons.length ||
      !Number.isInteger(schema) || schema < 2 || schema > 16 ||
      !Number.isInteger(template.minimalKeySize) || template.minimalKeySize < 1 ||
      typeof template.enrolleeSuppliesSubject !== "boolean" ||
      typeof template.templateOid !== "string" || !/^[0-2](\.(0|[1-9][0-9]{0,9})){1,63}$/.test(template.templateOid)) {
    return refusal("ADCS_TEMPLATE_UNSAFE", "Current template safety attributes are unsafe or unreadable");
  }
  const expectedAlgorithm = snapshot.keyAlgorithm === "rsa" ? "RSA" :
    snapshot.keyAlgorithm === "ecdsa" && snapshot.keySize === 256 ? "ECDSA_P256" :
      snapshot.keyAlgorithm === "ecdsa" && snapshot.keySize === 384 ? "ECDSA_P384" : null;
  if (mapSnapshotKeyAlgorithm(snapshot).error || !expectedAlgorithm || !Number.isInteger(snapshot.keySize) || snapshot.keySize < template.minimalKeySize ||
      (schema === 2 && snapshot.keyAlgorithm !== "rsa") ||
      (schema >= 3 && template.asymmetricAlgorithm !== expectedAlgorithm)) {
    return refusal("ADCS_TEMPLATE_UNSAFE", "Requested key size or algorithm is incompatible with the current template");
  }
  const ca = preflightResult.caCheck;
  const attestationAccepted = ca?.verdict === "unreadable" && operatorAttested === true &&
    Array.isArray(ca.reasons) && ca.reasons.length === 1 && ca.reasons[0] === "flags_unreadable";
  if (!(ca?.verdict === "safe" && Array.isArray(ca.reasons) && ca.reasons.length === 0) && !attestationAccepted) {
    return refusal("ADCS_CA_CONFIG_UNSAFE", "Current CA security flags are unsafe or unreadable without explicit local attestation");
  }
  const certificates = Array.isArray(preflightResult.caCertificates) ? preflightResult.caCertificates : [];
  const matchingCertificates = certificates.filter((certificate) => certificate?.keySha256 === snapshot.caKeySha256);
  if (!matchingCertificates.length) return refusal("ADCS_CA_KEY_UNPINNED", "Current CA certificates do not carry the signed pinned issuer key");
  return { ok: true, templateOid: template.templateOid, matchingCertificates,
    operatorAttested: ca.verdict === "unreadable" && operatorAttested === true };
}

/** New enrollment entries refresh native facts; only an immediately following
 * submit within the same execution context may reuse the bounded positive read.
 * Already-submitted retrieval and terminal cleanup never enter this guard. */
function createEnrollmentSafetyGuard({ now = Date.now } = {}) {
  const contexts = new WeakMap();
  return async function check({ snapshot, executionContext, stateDir, forceRefresh = true, info }) {
    const rule = matchEnrollmentRule(executionContext.adcsEnrollmentRules, snapshot.caConfig, snapshot.template, snapshot);
    if (!rule) return refusal("ADCS_CA_CONFIG_UNSAFE", "No whole local enrollment rule permits the signed CA, template, DNS names and key algorithm");
    let entries = contexts.get(executionContext);
    if (!entries) { entries = new Map(); contexts.set(executionContext, entries); }
    const key = JSON.stringify([stateDir, snapshot.caConfig, snapshot.template]);
    let entry = entries.get(key);
    let refreshed = false;
    const age = entry ? now() - entry.observedAt : Infinity;
    if (forceRefresh || !entry || age < 0 || age > SAFETY_REUSE_MS) {
      const result = await executeAdcsPreflight({ job: { mode: "real", transport: snapshot.transport,
        caConfig: snapshot.caConfig, template: snapshot.template }, rules: executionContext.adcsEnrollmentRules,
      probe: executionContext.adcsPreflightImpl, execFileImpl: executionContext.adcsPreflightExecFileImpl,
      info });
      if (result.status !== "succeeded") return refusal("ADCS_CA_CONFIG_UNSAFE", "Current native issuer preflight could not complete");
      entry = { observedAt: now(), preflightResult: result.preflightResult };
      refreshed = true;
    }
    const safety = evaluateEnrollmentSafety({ preflightResult: entry.preflightResult, snapshot, operatorAttested: rule.operatorAttested === true });
    if (!safety.ok) { entries.delete(key); return { ...safety, preflightResult: entry.preflightResult }; }
    if (refreshed) {
      const cached = await cachePreflightLocally({ stateDir, caConfig: snapshot.caConfig, template: snapshot.template,
        preflightResult: { ...entry.preflightResult, caCertificates: safety.matchingCertificates } });
      if (cached.errors.length || cached.pinned !== safety.matchingCertificates.length || cached.templateOid !== safety.templateOid) {
        entries.delete(key);
        return refusal("ADCS_CA_KEY_UNPINNED", "Verified current CA certificate or template facts could not be safely cached");
      }
    }
    if (entries.size >= MAX_CACHE_PAIRS && !entries.has(key)) entries.delete(entries.keys().next().value);
    entries.set(key, entry);
    return { ...safety, preflightResult: entry.preflightResult };
  };
}
module.exports = { evaluateEnrollmentSafety, createEnrollmentSafetyGuard, SAFETY_REUSE_MS };
