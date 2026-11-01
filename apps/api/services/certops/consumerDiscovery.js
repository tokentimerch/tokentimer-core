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
    targetHost: observation.targetHost || null,
    kind: observation.locationKind,
    slot:
      observation.locationKind === "filesystem"
        ? observation.filePath
        : observation.locationSlot,
  });
}
async function recordConsumerObservation(
  client,
  observation,
  managedCertificate,
) {
  const key = serviceKey(observation);
  if (!key) return null;
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
    ON CONFLICT(workspace_id,agent_id,service_key) DO UPDATE SET listener_target=EXCLUDED.listener_target,material_location=EXCLUDED.material_location,
      observed_fingerprint_sha256=EXCLUDED.observed_fingerprint_sha256,certificate_identity_id=EXCLUDED.certificate_identity_id,
      managed_certificate_id=EXCLUDED.managed_certificate_id,last_observed_at=EXCLUDED.last_observed_at,relationship_state=EXCLUDED.relationship_state
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
