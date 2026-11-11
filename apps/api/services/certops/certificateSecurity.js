"use strict";

// Security observations are not management lifecycle transitions. In
// particular, reporting a revocation must not close management periods or
// suppress alerts needed to replace a certificate that is still deployed.
function classifyCertificateSecurity({ observedRevocation, lifecycleStatus, now = Date.now() } = {}) {
  if (lifecycleStatus === "revoked") {
    return { state: "revoked", source: "lifecycle", freshness: "asserted" };
  }
  const result = observedRevocation;
  if (!result || typeof result !== "object" || Array.isArray(result)) {
    return { state: "unknown", source: null, freshness: "unchecked" };
  }
  const checked = Date.parse(result.checkedAt);
  const until = Date.parse(result.validUntil);
  const credible = Number.isFinite(checked) && Number.isFinite(until) &&
    checked <= now && until > checked && result.chainStatus === "valid";
  const fresh = credible && now < until;
  const adverse = (value) => value === "revoked" || value === "issuer_revoked";
  const previous = result.lastVerified;

  if (adverse(result.verdict) && credible) {
    return { state: fresh ? result.verdict : `last_known_${result.verdict}`,
      source: "observation", freshness: fresh ? "fresh" : "stale" };
  }
  const previousChecked = Date.parse(previous?.checkedAt);
  const previousUntil = Date.parse(previous?.validUntil);
  const previousCredible = previous?.chainStatus === "valid" && Number.isFinite(previousChecked) &&
    Number.isFinite(previousUntil) && previousChecked <= now && previousUntil > previousChecked;
  // An unknown result can carry a validity interval; it still cannot clear a
  // previous positive revocation finding. Only a fresh, valid good result can.
  if (!(result.verdict === "good" && fresh) && adverse(previous?.verdict) && previousCredible) {
    return { state: `last_known_${previous.verdict}`, source: "observation", freshness: "unavailable" };
  }
  if (result.chainStatus === "invalid") {
    return { state: "chain_untrusted", source: "observation", freshness: "unknown" };
  }
  if (result.verdict === "good" && fresh) {
    return { state: "revocation_good", source: "observation", freshness: "fresh" };
  }
  return { state: "unknown", source: "observation", freshness: result.verdict === "good" ? "stale" : "unavailable" };
}

// The caller supplies an internal SQL expression, never operator input.
// Use the same precedence for identity and managed-certificate projections.
function observedRevocationCredibleSql(result) {
  // Agent timestamps are normalized to UTC ISO milliseconds on ingestion.
  // String comparison avoids casting legacy malformed metadata in list queries.
  const now = `to_char(CURRENT_TIMESTAMP AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')`;
  return `(${result}->>'chainStatus' = 'valid'
    AND ${result}->>'checkedAt' ~ '^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z$'
    AND ${result}->>'validUntil' ~ '^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z$'
    AND ${result}->>'checkedAt' <= ${now}
    AND ${result}->>'validUntil' > ${result}->>'checkedAt') IS TRUE`;
}

function observedRevocationFreshGoodSql(result) {
  const now = `to_char(CURRENT_TIMESTAMP AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')`;
  return `(${observedRevocationCredibleSql(result)} AND ${result}->>'verdict' = 'good' AND ${result}->>'validUntil' > ${now}) IS TRUE`;
}

function observedRevocationKnownSql(result, verdict) {
  const previous = `${result}->'lastVerified'`;
  return `((${result}->>'verdict' = '${verdict}' AND ${observedRevocationCredibleSql(result)}) OR
    (NOT (${observedRevocationFreshGoodSql(result)}) AND ${previous}->>'verdict' = '${verdict}' AND ${observedRevocationCredibleSql(previous)}))`;
}

// A chain check identifies the exact intermediate certificate, independently
// of its name or public key. Re-express that proof as a direct revocation of
// the intermediate when projecting that fingerprint's inventory record.
function issuerEvidenceSql(result, fingerprint) {
  return `CASE
    WHEN ${result}->>'verdict' = 'issuer_revoked' AND ${result}->>'revokedIssuerFingerprintSha256' = ${fingerprint}
      THEN jsonb_set(${result}, '{verdict}', '"revoked"'::jsonb) || jsonb_build_object('derivedFromIssuerChain', true)
    WHEN ${result}->'lastVerified'->>'verdict' = 'issuer_revoked'
      AND ${result}->'lastVerified'->>'revokedIssuerFingerprintSha256' = ${fingerprint}
      THEN jsonb_set(jsonb_set(${result}, '{verdict}', '"unknown"'::jsonb), '{lastVerified,verdict}', '"revoked"'::jsonb) || jsonb_build_object('derivedFromIssuerChain', true)
    ELSE NULL END`;
}

function observedRevocationPrioritySql(result) {
  // Ranking is only a conservative preselection; the full credibility check
  // is applied to the selected result. Keep it compact to avoid expensive
  // repeated expressions in the correlated inventory query.
  const previousApplies = `(${result}->>'verdict' IS DISTINCT FROM 'good' OR ${result}->>'validUntil' <= to_char(CURRENT_TIMESTAMP AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'))`;
  const credible = (r) => `(${r}->>'chainStatus' = 'valid' AND ${r}->>'checkedAt' <= to_char(CURRENT_TIMESTAMP AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AND ${r}->>'validUntil' > ${r}->>'checkedAt')`;
  return `CASE
    WHEN (${result}->>'verdict' = 'revoked' AND ${credible(result)}) OR
      (${previousApplies} AND ${result}->'lastVerified'->>'verdict' = 'revoked' AND ${credible(`${result}->'lastVerified'`)}) THEN 0
    WHEN (${result}->>'verdict' = 'issuer_revoked' AND ${credible(result)}) OR
      (${previousApplies} AND ${result}->'lastVerified'->>'verdict' = 'issuer_revoked' AND ${credible(`${result}->'lastVerified'`)}) THEN 1
    WHEN ${result}->>'chainStatus' = 'invalid' THEN 2
    WHEN COALESCE(${result}->>'verdict', 'unknown') <> 'good' THEN 3 ELSE 4 END`;
}

async function isObservedCertificateCompromised(client, workspaceId, fingerprintSha256) {
  const observations = await client.query(`SELECT observed.public_metadata->'observedRevocation' AS result
    FROM certificate_instances observed
    WHERE observed.workspace_id=$1 AND certops_normalize_fingerprint(observed.observed_fingerprint_sha256)=$2
      AND observed.source IN ('agent_filesystem','agent_windows')
      AND observed.presence_state IS DISTINCT FROM 'confirmed_absent'
    UNION ALL
    SELECT observed.observed_revocation FROM certops_slot_observations observed
    WHERE observed.workspace_id=$1 AND observed.fingerprint_sha256=$2
      AND observed.source IN ('agent_filesystem','agent_windows')
      AND NOT EXISTS (SELECT 1 FROM certificate_instances instance
        WHERE instance.workspace_id=observed.workspace_id AND instance.target_id=observed.target_id
          AND instance.source=observed.source AND instance.source_ref=observed.source_ref
          AND certops_normalize_fingerprint(instance.observed_fingerprint_sha256)=observed.fingerprint_sha256
          AND instance.presence_state IS DISTINCT FROM 'confirmed_absent')
    UNION ALL
    SELECT ${issuerEvidenceSql("observed.public_metadata->'observedRevocation'", "$2::text")}
      FROM certificate_instances observed
     WHERE observed.workspace_id=$1 AND observed.source IN ('agent_filesystem','agent_windows')
       AND observed.presence_state IS DISTINCT FROM 'confirmed_absent'
       AND (observed.public_metadata->'observedRevocation'->>'revokedIssuerFingerprintSha256'=$2
         OR observed.public_metadata->'observedRevocation'->'lastVerified'->>'revokedIssuerFingerprintSha256'=$2)
    UNION ALL
    SELECT ${issuerEvidenceSql("observed.observed_revocation", "$2::text")}
      FROM certops_slot_observations observed
     WHERE observed.workspace_id=$1 AND observed.source IN ('agent_filesystem','agent_windows')
       AND (observed.observed_revocation->>'revokedIssuerFingerprintSha256'=$2
         OR observed.observed_revocation->'lastVerified'->>'revokedIssuerFingerprintSha256'=$2)
       AND NOT EXISTS (SELECT 1 FROM certificate_instances instance
         WHERE instance.workspace_id=observed.workspace_id AND instance.target_id=observed.target_id
           AND instance.source=observed.source AND instance.source_ref=observed.source_ref
           AND certops_normalize_fingerprint(instance.observed_fingerprint_sha256)=observed.fingerprint_sha256
           AND instance.presence_state IS DISTINCT FROM 'confirmed_absent')`,
  [workspaceId, fingerprintSha256]);
  return observations.rows.some(({ result }) => ["revoked", "issuer_revoked", "last_known_revoked", "last_known_issuer_revoked"].includes(
    classifyCertificateSecurity({ observedRevocation: result }).state,
  ));
}

module.exports = { classifyCertificateSecurity, observedRevocationKnownSql, observedRevocationPrioritySql, issuerEvidenceSql, isObservedCertificateCompromised };
