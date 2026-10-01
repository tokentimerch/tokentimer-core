"use strict";

const { pool } = require("../../db/database");
const { suppressPendingRetiredCertificateAlerts } = require("./inventory");

const FINGERPRINT_PATTERN = /^[a-f0-9]{64}$/;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const FRESHNESS_SQL = `GREATEST(INTERVAL '15 minutes',
  COALESCE(ci.scan_interval_seconds * INTERVAL '2 seconds', INTERVAL '24 hours'))`;

function fail(code, message) {
  const error = new Error(message);
  error.code = code;
  throw error;
}

function normalizeFingerprint(value) {
  const fingerprint = String(value || "").replace(/:/g, "").trim().toLowerCase();
  return FINGERPRINT_PATTERN.test(fingerprint) ? fingerprint : null;
}

function reasonFor(value) {
  const reason = typeof value === "string" ? value.trim() : "";
  if (!reason || reason.length > 512 || /[\x00-\x1f\x7f]/.test(reason)) {
    fail("CERTOPS_CERTIFICATE_RETIRE_REASON_INVALID", "A reason of 1–512 characters is required");
  }
  return reason;
}

async function inTransaction(db, callback) {
  if (db && typeof db.connect !== "function") return callback(db);
  const client = await (db || pool).connect();
  try {
    await client.query("BEGIN");
    const result = await callback(client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

function identityRecord(row) {
  if (!row) return null;
  return {
    id: row.open_period_id ? row.managed_id : row.id,
    identityId: row.id,
    workspaceId: row.workspace_id,
    fingerprintSha256: row.fingerprint_sha256,
    status: row.lifecycle_status === "active"
      ? (["revoked", "decommissioned"].includes(row.managed_status)
        ? "discovered" : (row.managed_status || "discovered"))
      : row.lifecycle_status,
    lifecycleStatus: row.lifecycle_status,
    lifecycleReason: row.lifecycle_reason,
    commonName: row.common_name || row.managed_name,
    name: row.common_name || row.managed_name,
    issuer: row.issuer,
    notAfter: row.not_after,
    tokenId: row.open_period_id ? row.token_id || null : null,
    source: row.open_period_id ? row.source || null : null,
    profileId: row.open_period_id ? row.profile_id || null : null,
    keyMode: row.open_period_id ? row.key_mode || null : null,
    keyReference: row.open_period_id ? row.key_reference || null : null,
    managed: Boolean(row.open_period_id),
    managedCertificateId: row.open_period_id ? row.managed_id : null,
    sources: row.sources || [],
    locations: row.locations || [],
    sourceCount: Number(row.source_count || 0),
    locationCount: Number(row.location_count || 0),
    stillObserved: Boolean(row.still_observed),
    visibilityUnknown: Boolean(row.visibility_unknown),
    lifecycleDisplay: row.lifecycle_status === "active"
      ? null
      : `${row.lifecycle_status === "revoked" ? "Revoked" : "Decommissioned"}${row.still_observed ? " · Still observed" : ""}`,
  };
}

async function listCertificateIdentities({
  workspaceId, limit = 50, offset = 0, status, source, excludeRetired = false,
  unmanaged, identityId, sort = "expiry", direction = "asc", client = pool,
}) {
  const pageSize = Math.max(1, Math.min(100, Number.parseInt(limit, 10) || 50));
  const pageOffset = Math.max(0, Number.parseInt(offset, 10) || 0);
  const params = [workspaceId];
  const conditions = ["ci.workspace_id = $1"];
  if (identityId) {
    if (!UUID_PATTERN.test(String(identityId))) fail("CERTOPS_CERTIFICATE_NOT_FOUND", "Certificate not found");
    params.push(identityId);
    conditions.push(`ci.id = $${params.length}`);
  }
  if (status) {
    if (!["active", "discovered", "provisioning", "renewing", "expiring", "expired", "revoked", "decommissioned"].includes(status)) {
      fail("CERTOPS_CERTIFICATE_STATUS_INVALID", "Invalid certificate status filter");
    }
    params.push(status);
    conditions.push(status === "revoked" || status === "decommissioned" || status === "active"
      ? `ci.lifecycle_status = $${params.length}`
      : `ci.lifecycle_status = 'active' AND EXISTS (
          SELECT 1 FROM managed_certificates mc WHERE mc.workspace_id = ci.workspace_id
            AND lower(replace(mc.fingerprint_sha256, ':', '')) = ci.fingerprint_sha256
            AND mc.status = $${params.length})`);
  } else if (excludeRetired) {
    conditions.push(`(ci.lifecycle_status = 'active' OR EXISTS (
      SELECT 1 FROM certificate_instances observed
      WHERE observed.workspace_id = ci.workspace_id
        AND observed.observed_fingerprint_sha256 = ci.fingerprint_sha256
        AND observed.presence_state = 'confirmed_present'
        AND observed.captured_at >= NOW() - GREATEST(INTERVAL '15 minutes',
          COALESCE(observed.scan_interval_seconds * INTERVAL '2 seconds', INTERVAL '24 hours')))
      OR EXISTS (SELECT 1 FROM certops_slot_observations observed
        WHERE observed.workspace_id = ci.workspace_id
          AND observed.fingerprint_sha256 = ci.fingerprint_sha256
          AND observed.captured_at >= NOW() - INTERVAL '24 hours')
      OR EXISTS (SELECT 1 FROM certops_unmanaged_observations observed
        WHERE observed.workspace_id = ci.workspace_id
          AND observed.fingerprint_sha256 = ci.fingerprint_sha256
          AND observed.domain_monitor_id IS NOT NULL
          AND observed.captured_at >= NOW() - INTERVAL '24 hours'))`);
  }
  if (source) {
    params.push(source);
    conditions.push(`EXISTS (
      SELECT 1 FROM certops_management_associations a
      JOIN certops_management_periods p ON p.id = a.period_id
      JOIN managed_certificates mc ON mc.id = p.managed_certificate_id
      WHERE a.identity_id = ci.id AND mc.source = $${params.length})`);
  }
  if (unmanaged === true || unmanaged === "true") {
    conditions.push(`NOT EXISTS (SELECT 1 FROM certops_management_periods p
      WHERE p.current_identity_id = ci.id AND p.ended_at IS NULL)`);
  }
  const where = conditions.join(" AND ");
  const total = await client.query(`SELECT COUNT(*)::int AS total FROM certops_certificate_identities ci WHERE ${where}`, params);
  const sortColumns = {
    expiry: "ci.not_after", name: "ci.common_name",
    certificate: "ci.common_name", status: "ci.lifecycle_status",
    source: "rep.source", keyLocality: "rep.key_mode",
    created: "ci.created_at",
  };
  const order = sortColumns[sort] || sortColumns.expiry;
  const dir = String(direction).toLowerCase() === "desc" ? "DESC" : "ASC";
  const page = await client.query(
    `SELECT ci.*, rep.id AS managed_id, rep.name AS managed_name,
            rep.status AS managed_status, rep.source, rep.token_id, rep.profile_id,
            rep.key_mode, rep.key_reference, rep.open_period_id,
            EXISTS (SELECT 1 FROM certificate_instances observed
              WHERE observed.workspace_id = ci.workspace_id
                AND observed.observed_fingerprint_sha256 = ci.fingerprint_sha256
                AND observed.presence_state = 'confirmed_present'
                AND observed.captured_at >= NOW() - GREATEST(INTERVAL '15 minutes',
                  COALESCE(observed.scan_interval_seconds * INTERVAL '2 seconds', INTERVAL '24 hours'))
                AND (observed.source NOT IN ('endpoint_monitor', 'domain_checker')
                  OR observed.domain_monitor_id IS NOT NULL))
              OR EXISTS (SELECT 1 FROM certops_slot_observations observed
                WHERE observed.workspace_id = ci.workspace_id
                  AND observed.fingerprint_sha256 = ci.fingerprint_sha256
                  AND observed.captured_at >= NOW() - INTERVAL '24 hours')
              OR EXISTS (SELECT 1 FROM certops_unmanaged_observations observed
                WHERE observed.workspace_id = ci.workspace_id
                  AND observed.fingerprint_sha256 = ci.fingerprint_sha256
                  AND observed.domain_monitor_id IS NOT NULL
                  AND observed.captured_at >= NOW() - INTERVAL '24 hours') AS still_observed,
            EXISTS (SELECT 1 FROM certificate_instances observed
              WHERE observed.workspace_id = ci.workspace_id
                AND observed.observed_fingerprint_sha256 = ci.fingerprint_sha256
                AND (observed.presence_state = 'unknown'
                  OR observed.captured_at IS NULL
                  OR observed.captured_at < NOW() - GREATEST(INTERVAL '15 minutes',
                    COALESCE(observed.scan_interval_seconds * INTERVAL '2 seconds', INTERVAL '24 hours'))))
              OR EXISTS (SELECT 1 FROM certops_slot_observations observed
                WHERE observed.workspace_id = ci.workspace_id
                  AND observed.fingerprint_sha256 = ci.fingerprint_sha256
                  AND observed.captured_at < NOW() - INTERVAL '24 hours')
              OR EXISTS (SELECT 1 FROM certops_unmanaged_observations observed
                WHERE observed.workspace_id = ci.workspace_id
                  AND observed.fingerprint_sha256 = ci.fingerprint_sha256
                  AND (observed.domain_monitor_id IS NULL
                    OR observed.captured_at < NOW() - INTERVAL '24 hours')) AS visibility_unknown
       FROM certops_certificate_identities ci
       LEFT JOIN LATERAL (
         SELECT mc.*, CASE WHEN p.ended_at IS NULL AND p.current_identity_id = ci.id
           THEN p.id ELSE NULL END AS open_period_id
           FROM certops_management_associations a
           JOIN certops_management_periods p ON p.id = a.period_id
           JOIN managed_certificates mc ON mc.id = p.managed_certificate_id
          WHERE a.identity_id = ci.id
          ORDER BY (p.ended_at IS NULL AND p.current_identity_id = ci.id) DESC,
                   a.associated_at DESC, mc.id
          LIMIT 1
       ) rep ON TRUE
      WHERE ${where}
      ORDER BY ${order} ${dir} NULLS LAST, ci.id ASC
      LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
    [...params, pageSize, pageOffset],
  );
  const rows = page.rows;
  if (rows.length) {
    const ids = rows.map((row) => row.id);
    const sources = await client.query(
      `SELECT * FROM (SELECT a.identity_id, p.id AS period_id,
              p.managed_certificate_id, p.ended_at AS period_ended_at,
              p.ended_reason,
              p.current_identity_id, p.renewal_profile_id,
              a.associated_at AS started_at,
              COALESCE(a.superseded_at, p.ended_at) AS ended_at,
              mc.source, mc.source_ref,
              COUNT(*) OVER (PARTITION BY a.identity_id)::int AS total,
              ROW_NUMBER() OVER (PARTITION BY a.identity_id
                ORDER BY a.associated_at DESC, a.id DESC) AS rn
         FROM certops_management_associations a
         JOIN certops_management_periods p ON p.id = a.period_id
         JOIN managed_certificates mc ON mc.id = p.managed_certificate_id
        WHERE a.identity_id = ANY($1::uuid[])) ranked
        WHERE rn <= 20 ORDER BY started_at DESC`, [ids],
    );
    const sourceMap = new Map();
    for (const sourceRow of sources.rows) {
      const group = sourceMap.get(sourceRow.identity_id) || [];
      group.push({ periodId: sourceRow.period_id, managedCertificateId: sourceRow.managed_certificate_id,
        source: sourceRow.source, sourceRef: sourceRow.source_ref,
        startedAt: sourceRow.started_at, endedAt: sourceRow.ended_at,
        periodEndedAt: sourceRow.period_ended_at,
        endedReason: sourceRow.ended_reason,
        currentIdentityId: sourceRow.current_identity_id,
        renewalProfileId: sourceRow.renewal_profile_id });
      sourceMap.set(sourceRow.identity_id, group);
    }
    const locations = await client.query(
      `SELECT * FROM (
         SELECT all_locations.*,
                COUNT(*) OVER (PARTITION BY identity_id)::int AS total,
                ROW_NUMBER() OVER (PARTITION BY identity_id
                  ORDER BY captured_at DESC NULLS LAST, id) AS rn
         FROM (
         SELECT identity.id AS identity_id, observed.id, observed.source,
                observed.source_ref, observed.location_kind, observed.deployment_reference,
                CASE WHEN (observed.source IN ('endpoint_monitor', 'domain_checker')
                             AND observed.domain_monitor_id IS NULL)
                           OR observed.captured_at IS NULL
                           OR observed.captured_at < NOW() - GREATEST(INTERVAL '15 minutes',
                             COALESCE(observed.scan_interval_seconds * INTERVAL '2 seconds',
                               INTERVAL '24 hours'))
                     THEN 'unknown' ELSE observed.presence_state END AS presence_state,
                observed.evidence_kind, observed.captured_at
           FROM certops_certificate_identities identity
           JOIN certificate_instances observed
             ON observed.workspace_id = identity.workspace_id
            AND observed.observed_fingerprint_sha256 = identity.fingerprint_sha256
          WHERE identity.id = ANY($1::uuid[])
            AND observed.source <> 'agent_filesystem'
         UNION ALL
         SELECT identity.id, observed.id, 'endpoint_monitor',
                observed.source_ref, 'tls_endpoint', NULL,
                CASE WHEN observed.domain_monitor_id IS NOT NULL
                       AND observed.captured_at >= NOW() - INTERVAL '24 hours'
                     THEN 'confirmed_present' ELSE 'unknown' END,
                'service_binding', observed.captured_at
           FROM certops_certificate_identities identity
           JOIN certops_unmanaged_observations observed
             ON observed.workspace_id = identity.workspace_id
            AND observed.fingerprint_sha256 = identity.fingerprint_sha256
          WHERE identity.id = ANY($1::uuid[])
         UNION ALL
         SELECT identity.id, observed.id, observed.source,
                observed.source_ref, observed.location_kind, observed.location_ref,
                CASE WHEN observed.captured_at >= NOW() - INTERVAL '24 hours'
                     THEN 'confirmed_present' ELSE 'unknown' END,
                CASE WHEN observed.location_kind IN ('iis_binding', 'http_sys')
                     THEN 'service_binding' ELSE 'stored_copy' END,
                observed.captured_at
           FROM certops_certificate_identities identity
           JOIN certops_slot_observations observed
             ON observed.workspace_id = identity.workspace_id
            AND observed.fingerprint_sha256 = identity.fingerprint_sha256
          WHERE identity.id = ANY($1::uuid[])
         ) all_locations
        ) ranked WHERE rn <= 20`, [ids],
    );
    const locationMap = new Map();
    for (const location of locations.rows) {
      const group = locationMap.get(location.identity_id) || [];
      group.push({ id: location.id, source: location.source,
        sourceRef: location.source_ref, locationKind: location.location_kind,
        deploymentReference: location.deployment_reference, presenceState: location.presence_state,
        evidenceKind: location.evidence_kind, capturedAt: location.captured_at });
      locationMap.set(location.identity_id, group);
    }
    for (const row of rows) {
      row.sources = sourceMap.get(row.id) || [];
      row.source_count = Number(sources.rows.find((sourceRow) => sourceRow.identity_id === row.id)?.total || 0);
      row.locations = locationMap.get(row.id) || [];
      row.location_count = Number(locations.rows.find((location) => location.identity_id === row.id)?.total || 0);
    }
  }
  const items = rows.map(identityRecord);
  let provisionalTotal = 0;
  if (!identityId && status !== "revoked" && status !== "decommissioned") {
    const provisionalParams = [workspaceId];
    const provisionalWhere = ["mc.workspace_id = $1",
      "(mc.fingerprint_sha256 IS NULL OR lower(replace(mc.fingerprint_sha256, ':', '')) !~ '^[a-f0-9]{64}$')"];
    if (status) {
      provisionalParams.push(status);
      provisionalWhere.push(`mc.status = $${provisionalParams.length}`);
    }
    if (source) {
      provisionalParams.push(source);
      provisionalWhere.push(`mc.source = $${provisionalParams.length}`);
    }
    if (unmanaged === true || unmanaged === "true") {
      provisionalWhere.push(`NOT EXISTS (SELECT 1 FROM certops_management_periods p
        WHERE p.workspace_id = mc.workspace_id AND p.managed_certificate_id = mc.id
          AND p.ended_at IS NULL)`);
    }
    const provisionalFilter = provisionalWhere.join(" AND ");
    const count = await client.query(`SELECT COUNT(*)::int AS total
      FROM managed_certificates mc WHERE ${provisionalFilter}`, provisionalParams);
    provisionalTotal = Number(count.rows[0]?.total || 0);
    const remaining = pageSize - items.length;
    if (remaining > 0) {
      const identityTotal = Number(total.rows[0]?.total || 0);
      const provisionalOffset = Math.max(0, pageOffset - identityTotal);
      const provisional = await client.query(
        `SELECT mc.*, p.id AS period_id, p.ended_at AS period_ended_at,
                p.ended_reason
           FROM managed_certificates mc
           LEFT JOIN LATERAL (
             SELECT * FROM certops_management_periods period
              WHERE period.workspace_id = mc.workspace_id
                AND period.managed_certificate_id = mc.id
              ORDER BY period.started_at DESC LIMIT 1
           ) p ON TRUE
          WHERE ${provisionalFilter}
          ORDER BY mc.created_at DESC, mc.id ASC
          LIMIT $${provisionalParams.length + 1} OFFSET $${provisionalParams.length + 2}`,
        [...provisionalParams, remaining, provisionalOffset],
      );
      for (const mc of provisional.rows) {
        items.push({ id: mc.id, identityId: null, workspaceId: mc.workspace_id,
          fingerprintSha256: null, status: mc.status, lifecycleStatus: null,
          commonName: mc.common_name || mc.name, notAfter: mc.not_after,
          tokenId: mc.token_id, source: mc.source, profileId: mc.profile_id,
          keyMode: mc.key_mode, keyReference: mc.key_reference,
          managed: Boolean(mc.period_id && !mc.period_ended_at),
          managedCertificateId: mc.id, sourceCount: 1, locationCount: 0,
          locations: [], sources: mc.period_id ? [{ periodId: mc.period_id,
            managedCertificateId: mc.id, source: mc.source, sourceRef: mc.source_ref,
            startedAt: mc.created_at, endedAt: mc.period_ended_at,
            periodEndedAt: mc.period_ended_at, endedReason: mc.ended_reason,
            currentIdentityId: null }] : [],
        });
      }
    }
  }
  return { items, pagination: {
    limit: pageSize, offset: pageOffset,
    total: Number(total.rows[0]?.total || 0) + provisionalTotal,
  } };
}

async function retireCertificateIdentity({ workspaceId, identityId, expectedFingerprintSha256,
  status, reason, acknowledgeUncertainty = false, actorUserId = null, client = pool }) {
  const fingerprint = normalizeFingerprint(expectedFingerprintSha256);
  if (!fingerprint) fail("CERTOPS_IDENTITY_PRECONDITION_REQUIRED", "The certificate fingerprint is required");
  if (!UUID_PATTERN.test(String(identityId || ""))) fail("CERTOPS_CERTIFICATE_NOT_FOUND", "Certificate not found");
  if (!["revoked", "decommissioned"].includes(status)) {
    fail("CERTOPS_CERTIFICATE_RETIRE_STATUS_INVALID", "Invalid lifecycle status");
  }
  const normalizedReason = reasonFor(reason);
  return inTransaction(client, async (tx) => {
    const locked = await tx.query(
      `SELECT * FROM certops_certificate_identities
        WHERE workspace_id = $1 AND id = $2 FOR UPDATE`, [workspaceId, identityId],
    );
    const identity = locked.rows[0];
    if (!identity) fail("CERTOPS_CERTIFICATE_NOT_FOUND", "Certificate not found");
    if (identity.fingerprint_sha256 !== fingerprint) {
      fail("CERTOPS_IDENTITY_PRECONDITION_FAILED", "Certificate fingerprint changed; refresh and retry");
    }
    if (identity.lifecycle_status === "revoked" && status === "decommissioned") {
      fail("CERTOPS_LIFECYCLE_DOWNGRADE", "A revoked certificate cannot be decommissioned");
    }
    if (identity.lifecycle_status === status) return identityRecord(identity);

    if (status === "decommissioned") {
      const observations = await tx.query(
        `SELECT ci.id, ci.source_ref, ci.evidence_kind, ci.source,
                CASE WHEN ci.source IN ('endpoint_monitor', 'domain_checker')
                            AND ci.domain_monitor_id IS NULL
                     THEN 'unknown' ELSE ci.presence_state END AS presence_state,
                ci.captured_at,
                ci.captured_at >= NOW() - ${FRESHNESS_SQL}
                  AND (ci.source NOT IN ('endpoint_monitor', 'domain_checker')
                    OR ci.domain_monitor_id IS NOT NULL) AS fresh
           FROM certificate_instances ci
          WHERE ci.workspace_id = $1 AND ci.observed_fingerprint_sha256 = $2
            AND ci.source <> 'agent_filesystem'
         UNION ALL
         SELECT observed.id, observed.source_ref, 'service_binding',
                'endpoint_monitor',
                CASE WHEN observed.domain_monitor_id IS NULL THEN 'unknown'
                     ELSE 'confirmed_present' END,
                observed.captured_at,
                observed.domain_monitor_id IS NOT NULL
                  AND observed.captured_at >= NOW() - INTERVAL '24 hours'
           FROM certops_unmanaged_observations observed
          WHERE observed.workspace_id = $1 AND observed.fingerprint_sha256 = $2
         UNION ALL
         SELECT observed.id, observed.source_ref,
                CASE WHEN observed.location_kind IN ('iis_binding', 'http_sys')
                     THEN 'service_binding' ELSE 'stored_copy' END,
                observed.source,
                CASE WHEN observed.captured_at >= NOW() - INTERVAL '24 hours'
                     THEN 'confirmed_present' ELSE 'unknown' END,
                observed.captured_at,
                observed.captured_at >= NOW() - INTERVAL '24 hours'
           FROM certops_slot_observations observed
          WHERE observed.workspace_id = $1 AND observed.fingerprint_sha256 = $2`,
        [workspaceId, fingerprint],
      );
      const present = observations.rows.filter((row) => row.presence_state === "confirmed_present" && row.fresh);
      const serving = present.filter((row) => row.evidence_kind === "service_binding");
      const locationSummary = (rows) => rows.slice(0, 5)
        .map((row) => String(row.source_ref || row.id).slice(0, 160)).join(", ");
      if (serving.length) {
        fail("CERTOPS_CERTIFICATE_STILL_SERVING",
          `Certificate is still serving at ${serving.length} location(s): ${locationSummary(serving)}`);
      }
      if ((!observations.rows.length || observations.rows.length !== present.length || present.length)
        && acknowledgeUncertainty !== true) {
        fail("CERTOPS_VISIBILITY_ACK_REQUIRED",
          `Stored copies or uncertain locations require acknowledgment: ${locationSummary(observations.rows) || "no recent observation"}`);
      }
      const running = await tx.query(
        `SELECT cj.id FROM certificate_jobs cj
          JOIN certops_management_periods p
            ON cj.subject_type = 'managed_certificate'
           AND cj.subject_id = p.managed_certificate_id::text
          JOIN certops_management_associations a ON a.period_id = p.id
         WHERE cj.workspace_id = $1 AND a.identity_id = $2
           AND (cj.certificate_identity_id = $2
             OR (cj.certificate_identity_id IS NULL AND a.identity_id = $2))
           AND cj.status IN ('claimed', 'running')
           AND cj.operation IN ('renew', 'deploy', 'reload')
           AND NOT (cj.payload->>'targetFingerprintSha256' IS NOT NULL
             AND lower(cj.payload->>'targetFingerprintSha256') <> $3
             AND cj.payload->>'canRestoreOriginal' = 'false')
         LIMIT 1`, [workspaceId, identityId, fingerprint],
      );
      if (running.rows.length) {
        fail("CERTOPS_MUTATION_RUNNING", `Operation ${running.rows[0].id} may install this certificate`);
      }
    }
    const changed = await tx.query(
      `UPDATE certops_certificate_identities SET lifecycle_status = $3,
              lifecycle_reason = $4, retired_at = NOW(), updated_at = NOW()
        WHERE workspace_id = $1 AND id = $2 RETURNING *`,
      [workspaceId, identityId, status, normalizedReason],
    );
    await tx.query(
      `UPDATE managed_certificates SET status = $3, updated_at = NOW()
        WHERE workspace_id = $1 AND lower(replace(fingerprint_sha256, ':', '')) = $2`,
      [workspaceId, fingerprint, status],
    );
    const cancelled = await tx.query(
      `UPDATE certificate_jobs cj SET status = 'cancelled', canceled_at = NOW(), updated_at = NOW()
        FROM certops_management_periods p
        JOIN certops_management_associations a ON a.period_id = p.id
       WHERE cj.workspace_id = $1 AND a.identity_id = $2
         AND (cj.certificate_identity_id = $2
           OR (cj.certificate_identity_id IS NULL AND a.identity_id = $2))
         AND cj.subject_type = 'managed_certificate'
         AND cj.subject_id = p.managed_certificate_id::text
         AND cj.status IN ('pending_approval', 'approved', 'pending')
         AND cj.operation IN ('renew', 'deploy', 'reload')
         AND NOT (cj.payload->>'targetFingerprintSha256' IS NOT NULL
           AND lower(cj.payload->>'targetFingerprintSha256') <> $3
           AND cj.payload->>'canRestoreOriginal' = 'false')`,
      [workspaceId, identityId, fingerprint],
    );
    const tokens = await tx.query(
      `SELECT DISTINCT token_id FROM managed_certificates
        WHERE workspace_id = $1 AND lower(replace(fingerprint_sha256, ':', '')) = $2
          AND token_id IS NOT NULL`, [workspaceId, fingerprint],
    );
    for (const { token_id: tokenId } of tokens.rows) {
      const sibling = await tx.query(
        `SELECT 1 FROM managed_certificates mc
          JOIN certops_certificate_identities identity
            ON identity.workspace_id = mc.workspace_id
           AND identity.fingerprint_sha256 = lower(replace(mc.fingerprint_sha256, ':', ''))
         WHERE mc.workspace_id = $1 AND mc.token_id = $2
           AND identity.id <> $3 AND identity.lifecycle_status = 'active' LIMIT 1`,
        [workspaceId, tokenId, identityId],
      );
      if (!sibling.rowCount) {
        await tx.query(`UPDATE tokens SET cert_lifecycle_status = $3, updated_at = NOW()
          WHERE workspace_id = $1 AND id = $2`, [workspaceId, tokenId, status]);
      }
      const affected = await tx.query(`SELECT id FROM managed_certificates
        WHERE workspace_id = $1 AND token_id = $2
          AND lower(replace(fingerprint_sha256, ':', '')) = $3`,
      [workspaceId, tokenId, fingerprint]);
      for (const mc of affected.rows) {
        await suppressPendingRetiredCertificateAlerts(tx, { workspaceId,
          certificateId: mc.id, tokenId, suppressTokenExpiry: !sibling.rowCount });
      }
    }
    await tx.query(
      `INSERT INTO audit_events(actor_user_id, subject_user_id, action, target_type,
         target_id, channel, metadata, workspace_id)
       VALUES ($1, $1, 'CERTOPS_CERTIFICATE_RETIRED', 'managed_certificate', NULL, NULL,
         $2::jsonb, $3)`,
      [actorUserId, JSON.stringify({ identityId, fingerprintSha256: fingerprint,
        status, reason: normalizedReason, cancelledJobs: cancelled.rowCount }), workspaceId],
    );
    return identityRecord(changed.rows[0]);
  });
}

async function stopManagingSource({ workspaceId, periodId, actorUserId = null, client = pool }) {
  return inTransaction(client, async (tx) => {
    const result = await tx.query(
      `SELECT p.*, mc.source, mc.source_ref
         FROM certops_management_periods p
         JOIN managed_certificates mc ON mc.id = p.managed_certificate_id
        WHERE p.workspace_id = $1 AND p.id = $2 FOR UPDATE OF p`,
      [workspaceId, periodId],
    );
    const period = result.rows[0];
    if (!period) fail("CERTOPS_MANAGEMENT_PERIOD_NOT_FOUND", "Management period not found");
    if (period.ended_at) return { periodId, endedAt: period.ended_at, runningJobs: 0 };
    await tx.query(`UPDATE certops_management_periods
      SET ended_at = NOW(), ended_reason = 'stopped_by_operator'
      WHERE id = $1`, [periodId]);
    await tx.query(`UPDATE certops_management_associations
      SET superseded_at = NOW() WHERE period_id = $1 AND superseded_at IS NULL`, [periodId]);
    await tx.query(`UPDATE certificate_jobs SET status = 'cancelled', canceled_at = NOW(),
      updated_at = NOW() WHERE workspace_id = $1 AND management_period_id = $2
      AND status IN ('pending_approval', 'approved', 'pending')`, [workspaceId, periodId]);
    const running = await tx.query(`SELECT COUNT(*)::int AS c FROM certificate_jobs
      WHERE workspace_id = $1 AND management_period_id = $2
        AND status IN ('claimed', 'running')`, [workspaceId, periodId]);
    await tx.query(`INSERT INTO audit_events(actor_user_id, subject_user_id, action,
      target_type, target_id, channel, metadata, workspace_id)
      VALUES ($1, $1, 'CERTOPS_MANAGEMENT_STOPPED', 'managed_certificate', NULL, NULL,
        $2::jsonb, $3)`, [actorUserId,
        JSON.stringify({ periodId, managedCertificateId: period.managed_certificate_id }), workspaceId]);
    return { periodId, endedAt: new Date().toISOString(),
      runningJobs: Number(running.rows[0]?.c || 0) };
  });
}

async function readdManagingSource({ workspaceId, managedCertificateId,
  renewalProfileId, automationEnabled, actorUserId = null,
  admitManagement = null, client = pool }) {
  if (typeof automationEnabled !== "boolean" || renewalProfileId === undefined) {
    fail("CERTOPS_MANAGEMENT_CONFIG_REQUIRED", "Select renewal configuration explicitly");
  }
  return inTransaction(client, async (tx) => {
    const mc = await tx.query(`SELECT * FROM managed_certificates
      WHERE workspace_id = $1 AND id = $2 FOR UPDATE`, [workspaceId, managedCertificateId]);
    if (!mc.rows.length) fail("CERTOPS_CERTIFICATE_NOT_FOUND", "Certificate source not found");
    if (mc.rows[0].source === "endpoint_monitor") {
      const monitor = await tx.query(`SELECT 1 FROM domain_monitors
        WHERE workspace_id = $1 AND id::text = $2`,
      [workspaceId, mc.rows[0].source_ref]);
      if (!monitor.rowCount) fail("CERTOPS_MANAGEMENT_SOURCE_UNAVAILABLE", "Endpoint no longer exists");
    }
    if (automationEnabled && !renewalProfileId) {
      fail("CERTOPS_MANAGEMENT_CONFIG_REQUIRED", "Select a renewal profile for automation");
    }
    if (!automationEnabled && renewalProfileId) {
      fail("CERTOPS_MANAGEMENT_CONFIG_INVALID", "Disable automation with no renewal profile selected");
    }
    const open = await tx.query(`SELECT 1 FROM certops_management_periods
      WHERE workspace_id = $1 AND managed_certificate_id = $2 AND ended_at IS NULL`,
    [workspaceId, managedCertificateId]);
    if (open.rowCount) fail("CERTOPS_MANAGEMENT_ALREADY_OPEN", "Source is already managed");
    if (renewalProfileId) {
      const profile = await tx.query(`SELECT 1 FROM certificate_profiles
        WHERE workspace_id = $1 AND id = $2`, [workspaceId, renewalProfileId]);
      if (!profile.rowCount) fail("CERTOPS_MANAGEMENT_CONFIG_INVALID", "Renewal profile not found");
    }
    const identity = await tx.query(`SELECT id FROM certops_certificate_identities
      WHERE workspace_id = $1 AND fingerprint_sha256 = $2`,
    [workspaceId, normalizeFingerprint(mc.rows[0].fingerprint_sha256)]);
    if (admitManagement) {
      await admitManagement(tx, {
        workspaceId, fingerprintSha256: normalizeFingerprint(mc.rows[0].fingerprint_sha256),
        identityId: identity.rows[0]?.id || null,
      });
    }
    const inserted = await tx.query(`INSERT INTO certops_management_periods(
      workspace_id, managed_certificate_id, current_identity_id, renewal_profile_id,
      automation_enabled, created_by) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
    [workspaceId, managedCertificateId, identity.rows[0]?.id || null,
      renewalProfileId || null, automationEnabled, actorUserId]);
    if (identity.rows.length) await tx.query(`INSERT INTO certops_management_associations(
      workspace_id, period_id, identity_id) VALUES ($1, $2, $3)`,
    [workspaceId, inserted.rows[0].id, identity.rows[0].id]);
    await tx.query(`UPDATE managed_certificates SET profile_id = $3, updated_at = NOW()
      WHERE workspace_id = $1 AND id = $2`, [workspaceId, managedCertificateId, renewalProfileId || null]);
    await tx.query(`INSERT INTO audit_events(actor_user_id, subject_user_id, action,
      target_type, target_id, channel, metadata, workspace_id)
      VALUES ($1, $1, 'CERTOPS_MANAGEMENT_STARTED', 'managed_certificate', NULL, NULL,
        $2::jsonb, $3)`, [actorUserId,
        JSON.stringify({ periodId: inserted.rows[0].id, managedCertificateId }), workspaceId]);
    return { periodId: inserted.rows[0].id, managedCertificateId,
      startedAt: inserted.rows[0].started_at };
  });
}

module.exports = { normalizeFingerprint, listCertificateIdentities,
  retireCertificateIdentity, stopManagingSource, readdManagingSource };
