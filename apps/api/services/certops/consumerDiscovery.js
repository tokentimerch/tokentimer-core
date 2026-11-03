"use strict";
const { hashIntent } = require("./materialDistribution");
function serviceKey(observation) {
  if (
    !["iis_binding", "http_sys", "filesystem"].includes(
      observation.locationKind,
    )
  )
    return null;
  return hashIntent({
    agentId: observation.agentRowId,
    targetHost: observation.targetHost?.toLowerCase() || null,
    kind: observation.locationKind,
    slot:
      observation.locationKind === "filesystem"
        ? observation.filePath
        : observation.locationSlot?.toLowerCase(),
  });
}
async function recordConsumerObservation(
  client,
  observation,
  managedCertificate,
) {
  const key = serviceKey(observation);
  if (!key) return null;
  const observed = Date.parse(observation.observedAt);
  const received = Date.parse(observation.observedAtServer || new Date().toISOString());
  if (!Number.isFinite(observed) || !Number.isFinite(received) || observed > received + 30000) return null;
  const identity =
    (
      await client.query(
        `SELECT id FROM certops_certificate_identities WHERE workspace_id=$1 AND fingerprint_sha256=$2`,
        [observation.workspaceId, observation.fingerprintSha256],
      )
    ).rows[0]?.id || null;
  const fields = observation.windowsFields || {};
  const location =
    observation.locationKind === "filesystem"
      ? observation.filePath
      : `winstore://${fields.storeLocation || "LocalMachine"}/${fields.storeName || "My"}`;
  return (
    (
      await client.query(
        `INSERT INTO certops_discovered_consumers(workspace_id,agent_id,service_key,service_identity,source_kind,target_host,
    listener_target,material_location,observed_fingerprint_sha256,certificate_identity_id,managed_certificate_id,last_observed_at,relationship_state)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
    ON CONFLICT(workspace_id,agent_id,service_key) DO UPDATE SET
      listener_target=CASE WHEN certops_discovered_consumers.last_observed_at=EXCLUDED.last_observed_at THEN certops_discovered_consumers.listener_target ELSE EXCLUDED.listener_target END,
      material_location=CASE WHEN certops_discovered_consumers.last_observed_at=EXCLUDED.last_observed_at THEN certops_discovered_consumers.material_location ELSE EXCLUDED.material_location END,
      observed_fingerprint_sha256=CASE WHEN certops_discovered_consumers.last_observed_at=EXCLUDED.last_observed_at THEN certops_discovered_consumers.observed_fingerprint_sha256 ELSE EXCLUDED.observed_fingerprint_sha256 END,
      certificate_identity_id=CASE WHEN certops_discovered_consumers.last_observed_at=EXCLUDED.last_observed_at THEN certops_discovered_consumers.certificate_identity_id ELSE EXCLUDED.certificate_identity_id END,
      managed_certificate_id=CASE WHEN certops_discovered_consumers.last_observed_at=EXCLUDED.last_observed_at THEN certops_discovered_consumers.managed_certificate_id ELSE EXCLUDED.managed_certificate_id END,
      coverage=CASE WHEN certops_discovered_consumers.last_observed_at=EXCLUDED.last_observed_at AND
        (certops_discovered_consumers.coverage='unknown' OR certops_discovered_consumers.observed_fingerprint_sha256<>EXCLUDED.observed_fingerprint_sha256)
        THEN 'unknown' ELSE 'partial' END,
      last_observed_at=EXCLUDED.last_observed_at,relationship_state=EXCLUDED.relationship_state
    WHERE certops_discovered_consumers.last_observed_at<=EXCLUDED.last_observed_at RETURNING id`,
        [
          observation.workspaceId,
          observation.agentRowId,
          key,
          observation.locationKind === "filesystem"
            ? observation.filePath
            : observation.locationSlot,
          observation.locationKind,
          observation.targetHost,
          observation.locationRef,
          location,
          observation.fingerprintSha256,
          identity,
          managedCertificate.id,
          observation.observedAt,
          observation.locationKind === "filesystem"
            ? "configured_not_observed"
            : "confirmed_relationship",
        ],
      )
    ).rows[0]?.id || null
  );
}
module.exports = { serviceKey, recordConsumerObservation };
