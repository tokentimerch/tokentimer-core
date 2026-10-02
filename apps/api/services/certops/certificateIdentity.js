"use strict";

const { pool } = require("../../db/database");
const { Client } = require("pg");
const {
  suppressPendingRetiredCertificateAlerts,
  acquireManagedCertificateImportLock,
  normalizeCertificateStatusFilter,
  normalizeCertificateSourceFilter,
  normalizeCertificateFlagFilter,
} = require("./inventory");

const { resolveListSort } = require("./listSorting");

const FINGERPRINT_PATTERN = /^[a-f0-9]{64}$/;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const FRESHNESS_SQL = `GREATEST(INTERVAL '15 minutes',
  COALESCE(ci.scan_interval_seconds * INTERVAL '2 seconds', INTERVAL '24 hours'))`;

function fail(code, message) {
  const error = new Error(message);
  error.code = code;
  throw error;
}

function normalizeFingerprint(value) {
  const fingerprint = String(value || "")
    .replace(/:/g, "")
    .trim()
    .toLowerCase();
  return FINGERPRINT_PATTERN.test(fingerprint) ? fingerprint : null;
}

function reasonFor(value) {
  const reason = typeof value === "string" ? value.trim() : "";
  if (!reason || reason.length > 512 || /[\x00-\x1f\x7f]/.test(reason)) {
    fail(
      "CERTOPS_CERTIFICATE_RETIRE_REASON_INVALID",
      "A reason of 1–512 characters is required",
    );
  }
  return reason;
}

async function inTransaction(db, callback) {
  if (db && (db instanceof Client || typeof db.connect !== "function"))
    return callback(db);
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
    status:
      row.lifecycle_status === "active"
        ? ["revoked", "decommissioned"].includes(row.managed_status)
          ? "discovered"
          : row.managed_status || "discovered"
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
    activeSourceCount: Number(row.active_source_count || 0),
    locationCount: Number(row.location_count || 0),
    stillObserved: Boolean(row.still_observed),
    visibilityUnknown:
      row.visibility_unknown === undefined
        ? !row.still_observed ||
          (row.locations || []).some(
            (location) => location.presenceState === "unknown",
          )
        : Boolean(row.visibility_unknown),
    lifecycleDisplay:
      row.lifecycle_status === "active"
        ? null
        : `${row.lifecycle_status === "revoked" ? "Revoked" : "Decommissioned"}${row.still_observed ? " · Still observed" : ""}`,
  };
}

async function listCertificateIdentities({
  workspaceId,
  limit = 50,
  offset = 0,
  status,
  source,
  excludeRetired = false,
  unmanaged,
  identityId,
  sort,
  direction,
  client = pool,
}) {
  const pageSize = Math.max(1, Math.min(100, Number.parseInt(limit, 10) || 50));
  const pageOffset = Math.max(0, Number.parseInt(offset, 10) || 0);
  const normalizedStatus = normalizeCertificateStatusFilter(status);
  const normalizedSource = normalizeCertificateSourceFilter(source);
  const unmanagedOnly = normalizeCertificateFlagFilter(unmanaged, "unmanaged");
  const params = [workspaceId];
  const conditions = ["TRUE"];
  if (identityId) {
    if (!UUID_PATTERN.test(String(identityId)))
      fail("CERTOPS_CERTIFICATE_NOT_FOUND", "Certificate not found");
    params.push(identityId);
    conditions.push(`kind = 'identity' AND id = $${params.length}`);
  }
  if (normalizedStatus) {
    params.push(normalizedStatus);
    conditions.push(
      normalizedStatus === "active"
        ? `(lifecycle_status = $${params.length} OR (kind = 'provisional' AND managed_status = $${params.length}))`
        : `display_status = $${params.length}`,
    );
  } else if (excludeRetired) {
    conditions.push(
      "(display_status NOT IN ('revoked', 'decommissioned') OR still_observed)",
    );
  }
  if (normalizedSource) {
    params.push(normalizedSource);
    conditions.push(`(source = $${params.length} OR (kind = 'identity' AND EXISTS (
      SELECT 1 FROM certops_management_associations a
      JOIN certops_management_periods p ON p.id = a.period_id
      WHERE a.identity_id = candidates.id AND a.workspace_id = $1 AND p.source = $${params.length})))`);
  }
  if (unmanagedOnly !== null)
    conditions.push(
      unmanagedOnly ? "open_period_id IS NULL" : "open_period_id IS NOT NULL",
    );
  const orderBy = resolveListSort({
    sort,
    direction,
    allowlist: {
      expiry: "not_after",
      name: "display_name",
      certificate: "display_name",
      status: "display_status",
      source: "source",
      keyLocality: "key_mode",
      created: "created_at",
    },
    defaultOrderBy: "not_after ASC NULLS LAST, kind ASC, id ASC",
    tieBreaker: "kind ASC, id ASC",
  });
  const presence = `SELECT certops_normalize_fingerprint(observed.observed_fingerprint_sha256) AS fingerprint
    FROM certificate_instances observed WHERE observed.workspace_id = $1
      AND observed.presence_state = 'confirmed_present'
      AND observed.captured_at >= NOW() - GREATEST(INTERVAL '15 minutes',
        COALESCE(observed.scan_interval_seconds * INTERVAL '2 seconds', INTERVAL '24 hours'))
      AND (observed.source NOT IN ('endpoint_monitor', 'domain_checker') OR observed.domain_monitor_id IS NOT NULL)
    UNION SELECT o.fingerprint_sha256 FROM certops_slot_observations o WHERE o.workspace_id = $1
      AND o.captured_at >= NOW() - INTERVAL '24 hours'
    UNION SELECT o.fingerprint_sha256 FROM certops_unmanaged_observations o WHERE o.workspace_id = $1
      AND o.domain_monitor_id IS NOT NULL AND o.captured_at >= NOW() - INTERVAL '24 hours'`;
  // Count and page share one PostgreSQL snapshot, including provisional sources.
  const page = await client.query(
    `WITH representatives AS (
    SELECT DISTINCT ON (a.identity_id) a.identity_id, mc.*,
      CASE WHEN p.ended_at IS NULL AND p.current_identity_id = a.identity_id THEN p.id ELSE NULL END AS open_period_id
    FROM certops_management_associations a JOIN certops_management_periods p ON p.id = a.period_id
    JOIN managed_certificates mc ON mc.id = p.managed_certificate_id AND mc.workspace_id = p.workspace_id
    WHERE a.workspace_id = $1 ${identityId ? "AND a.identity_id = $2" : ""}
    ORDER BY a.identity_id, (p.ended_at IS NULL AND p.current_identity_id = a.identity_id) DESC,
      a.associated_at DESC, a.id DESC
  ), present_fingerprints AS (${presence}), candidates AS (
    SELECT ci.id, ci.workspace_id, ci.fingerprint_sha256, ci.lifecycle_status, ci.lifecycle_reason,
      ci.common_name, ci.issuer, ci.not_after, ci.created_at, 'identity'::text AS kind,
      rep.id AS managed_id, rep.name AS managed_name, rep.status AS managed_status,
      rep.source, rep.token_id, rep.profile_id, rep.key_mode, rep.key_reference, rep.open_period_id,
      NULL::uuid AS period_id, NULL::timestamptz AS period_started_at, NULL::timestamptz AS period_ended_at, NULL::text AS ended_reason,
      NULL::text AS source_ref, COALESCE(ci.common_name, rep.name) AS display_name,
      CASE WHEN ci.lifecycle_status <> 'active' THEN ci.lifecycle_status
        WHEN rep.status IN ('revoked', 'decommissioned') THEN 'discovered'
        ELSE COALESCE(rep.status, 'discovered') END AS display_status,
      present.fingerprint IS NOT NULL AS still_observed
    FROM certops_certificate_identities ci
    LEFT JOIN representatives rep ON rep.identity_id = ci.id
    LEFT JOIN present_fingerprints present ON present.fingerprint = ci.fingerprint_sha256
    WHERE ci.workspace_id = $1 ${identityId ? "AND ci.id = $2" : ""}
    UNION ALL
    SELECT mc.id, mc.workspace_id, NULL::text, NULL::text, NULL::text,
      mc.common_name, mc.issuer, mc.not_after, mc.created_at, 'provisional',
      mc.id, mc.name, mc.status, mc.source, mc.token_id, mc.profile_id, mc.key_mode, mc.key_reference,
      CASE WHEN p.ended_at IS NULL THEN p.id ELSE NULL END, p.id, p.started_at, p.ended_at, p.ended_reason,
      mc.source_ref, COALESCE(mc.common_name, mc.name), mc.status, FALSE
    FROM managed_certificates mc LEFT JOIN LATERAL (
      SELECT * FROM certops_management_periods period
      WHERE period.workspace_id = mc.workspace_id AND period.managed_certificate_id = mc.id
      ORDER BY period.started_at DESC, period.id DESC LIMIT 1
    ) p ON TRUE WHERE mc.workspace_id = $1 AND certops_normalize_fingerprint(mc.fingerprint_sha256) IS NULL
  ), filtered AS (SELECT * FROM candidates WHERE ${conditions.join(" AND ")}),
  page AS (SELECT * FROM filtered ORDER BY ${orderBy} LIMIT $${params.length + 1} OFFSET $${params.length + 2})
  SELECT (SELECT COUNT(*)::int FROM filtered) AS total,
    COALESCE((SELECT jsonb_agg(page ORDER BY ${orderBy}) FROM page), '[]'::jsonb) AS items`,
    [...params, pageSize, pageOffset],
  );
  const rows = page.rows[0]?.items || [];
  if (rows.some((row) => row.kind === "identity")) {
    const ids = rows
      .filter((row) => row.kind === "identity")
      .map((row) => row.id);
    const sources = await client.query(
      `SELECT * FROM (SELECT a.identity_id, p.id AS period_id,
              p.managed_certificate_id, p.ended_at AS period_ended_at,
              p.ended_reason,
              p.current_identity_id, p.renewal_profile_id,
              a.associated_at AS started_at,
              COALESCE(a.superseded_at, p.ended_at) AS ended_at,
              p.source, p.source_ref,
              COUNT(*) OVER (PARTITION BY a.identity_id)::int AS total,
              COUNT(*) FILTER (WHERE p.ended_at IS NULL
                AND p.current_identity_id = a.identity_id
                AND a.superseded_at IS NULL)
                OVER (PARTITION BY a.identity_id)::int AS active_total,
              ROW_NUMBER() OVER (PARTITION BY a.identity_id
                ORDER BY a.associated_at DESC, a.id DESC) AS rn
         FROM certops_management_associations a
         JOIN certops_management_periods p ON p.id = a.period_id
        WHERE a.identity_id = ANY($1::uuid[])) ranked
        WHERE ${identityId ? "TRUE" : "rn <= 20"} ORDER BY started_at DESC`,
      [ids],
    );
    const sourceMap = new Map();
    for (const sourceRow of sources.rows) {
      const group = sourceMap.get(sourceRow.identity_id) || [];
      group.push({
        periodId: sourceRow.period_id,
        managedCertificateId: sourceRow.managed_certificate_id,
        source: sourceRow.source,
        sourceRef: sourceRow.source_ref,
        startedAt: sourceRow.started_at,
        endedAt: sourceRow.ended_at,
        periodEndedAt: sourceRow.period_ended_at,
        endedReason: sourceRow.ended_reason,
        currentIdentityId: sourceRow.current_identity_id,
        renewalProfileId: sourceRow.renewal_profile_id,
      });
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
            AND certops_normalize_fingerprint(observed.observed_fingerprint_sha256) = identity.fingerprint_sha256
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
        ) ranked WHERE rn <= 20`,
      [ids],
    );
    const locationMap = new Map();
    for (const location of locations.rows) {
      const group = locationMap.get(location.identity_id) || [];
      group.push({
        id: location.id,
        source: location.source,
        sourceRef: location.source_ref,
        locationKind: location.location_kind,
        deploymentReference: location.deployment_reference,
        presenceState: location.presence_state,
        evidenceKind: location.evidence_kind,
        capturedAt: location.captured_at,
      });
      locationMap.set(location.identity_id, group);
    }
    for (const row of rows) {
      row.sources = sourceMap.get(row.id) || [];
      row.source_count = Number(
        sources.rows.find((sourceRow) => sourceRow.identity_id === row.id)
          ?.total || 0,
      );
      row.active_source_count = Number(
        sources.rows.find((sourceRow) => sourceRow.identity_id === row.id)
          ?.active_total || 0,
      );
      row.locations = locationMap.get(row.id) || [];
      row.location_count = Number(
        locations.rows.find((location) => location.identity_id === row.id)
          ?.total || 0,
      );
    }
  }
  const items = rows.map((row) =>
    row.kind === "identity"
      ? identityRecord(row)
      : {
          id: row.id,
          identityId: null,
          workspaceId: row.workspace_id,
          fingerprintSha256: null,
          status: row.managed_status,
          lifecycleStatus: null,
          commonName: row.display_name,
          name: row.display_name,
          notAfter: row.not_after,
          tokenId: row.token_id,
          source: row.source,
          profileId: row.profile_id,
          keyMode: row.key_mode,
          keyReference: row.key_reference,
          managed: Boolean(row.open_period_id),
          managedCertificateId: row.id,
          sourceCount: row.period_id ? 1 : 0,
          activeSourceCount: row.open_period_id ? 1 : 0,
          locationCount: 0,
          locations: [],
          sources: row.period_id
            ? [
                {
                  periodId: row.period_id,
                  managedCertificateId: row.id,
                  source: row.source,
                  sourceRef: row.source_ref,
                  startedAt: row.period_started_at,
                  endedAt: row.period_ended_at,
                  periodEndedAt: row.period_ended_at,
                  endedReason: row.ended_reason,
                  currentIdentityId: null,
                },
              ]
            : [],
        },
  );
  return {
    items,
    pagination: {
      limit: pageSize,
      offset: pageOffset,
      total: Number(page.rows[0]?.total || 0),
    },
  };
}

async function retireCertificateIdentity({
  workspaceId,
  identityId,
  expectedFingerprintSha256,
  status,
  reason,
  acknowledgeUncertainty = false,
  actorUserId = null,
  client = pool,
}) {
  const fingerprint = normalizeFingerprint(expectedFingerprintSha256);
  if (!fingerprint)
    fail(
      "CERTOPS_IDENTITY_PRECONDITION_REQUIRED",
      "The certificate fingerprint is required",
    );
  if (!UUID_PATTERN.test(String(identityId || "")))
    fail("CERTOPS_CERTIFICATE_NOT_FOUND", "Certificate not found");
  if (!["revoked", "decommissioned"].includes(status)) {
    fail(
      "CERTOPS_CERTIFICATE_RETIRE_STATUS_INVALID",
      "Invalid certificate retire status",
    );
  }
  const normalizedReason = reasonFor(reason);
  return inTransaction(client, async (tx) => {
    await acquireManagedCertificateImportLock(tx, workspaceId);
    const locked = await tx.query(
      `SELECT * FROM certops_certificate_identities
        WHERE workspace_id = $1 AND id = $2 FOR UPDATE`,
      [workspaceId, identityId],
    );
    const identity = locked.rows[0];
    if (!identity)
      fail("CERTOPS_CERTIFICATE_NOT_FOUND", "Certificate not found");
    if (identity.fingerprint_sha256 !== fingerprint) {
      fail(
        "CERTOPS_IDENTITY_PRECONDITION_FAILED",
        "Certificate fingerprint changed; refresh and retry",
      );
    }
    if (
      identity.lifecycle_status === "revoked" &&
      status === "decommissioned"
    ) {
      fail(
        "CERTOPS_LIFECYCLE_DOWNGRADE",
        "A revoked certificate cannot be decommissioned",
      );
    }
    const recordWithManagement = async (row) => {
      const representative = await tx.query(
        `SELECT p.id AS open_period_id, mc.id AS managed_id,
        mc.name AS managed_name, mc.status AS managed_status, mc.token_id, mc.source,
        mc.profile_id, mc.key_mode, mc.key_reference FROM certops_management_periods p
        JOIN managed_certificates mc ON mc.id = p.managed_certificate_id
        WHERE p.workspace_id = $1 AND p.current_identity_id = $2 AND p.ended_at IS NULL
        ORDER BY p.started_at DESC, p.id DESC LIMIT 1`,
        [workspaceId, identityId],
      );
      return identityRecord({ ...row, ...representative.rows[0] });
    };
    if (identity.lifecycle_status === status)
      return recordWithManagement(identity);

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
      const present = observations.rows.filter(
        (row) => row.presence_state === "confirmed_present" && row.fresh,
      );
      const serving = present.filter(
        (row) => row.evidence_kind === "service_binding",
      );
      const locationSummary = (rows) =>
        rows
          .slice(0, 5)
          .map((row) => String(row.source_ref || row.id).slice(0, 160))
          .join(", ");
      if (serving.length) {
        fail(
          "CERTOPS_CERTIFICATE_STILL_SERVING",
          `Certificate is still serving at ${serving.length} location(s): ${locationSummary(serving)}`,
        );
      }
      const uncertain =
        !observations.rows.length ||
        observations.rows.some(
          (row) => !row.fresh || row.presence_state === "unknown",
        );
      const storedCopies = present.some(
        (row) => row.evidence_kind !== "service_binding",
      );
      if ((uncertain || storedCopies) && acknowledgeUncertainty !== true) {
        fail(
          "CERTOPS_VISIBILITY_ACK_REQUIRED",
          `Stored copies or uncertain locations require acknowledgment: ${locationSummary(observations.rows) || "no recent observation"}`,
        );
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
         LIMIT 1`,
        [workspaceId, identityId, fingerprint],
      );
      if (running.rows.length) {
        fail(
          "CERTOPS_MUTATION_RUNNING",
          `Operation ${running.rows[0].id} may install this certificate`,
        );
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
        WHERE workspace_id = $1 AND certops_normalize_fingerprint(fingerprint_sha256) = $2`,
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
        AND cj.id IN (SELECT id FROM certificate_jobs WHERE workspace_id = $1 FOR UPDATE SKIP LOCKED)
         AND cj.operation IN ('renew', 'deploy', 'reload')
         AND NOT (cj.payload->>'targetFingerprintSha256' IS NOT NULL
           AND lower(cj.payload->>'targetFingerprintSha256') <> $3
           AND cj.payload->>'canRestoreOriginal' = 'false')`,
      [workspaceId, identityId, fingerprint],
    );
    const tokens = await tx.query(
      `SELECT DISTINCT token_id FROM managed_certificates
        WHERE workspace_id = $1 AND certops_normalize_fingerprint(fingerprint_sha256) = $2
          AND token_id IS NOT NULL`,
      [workspaceId, fingerprint],
    );
    for (const { token_id: tokenId } of tokens.rows) {
      const sibling = await tx.query(
        `SELECT 1 FROM managed_certificates mc
          JOIN certops_certificate_identities identity
            ON identity.workspace_id = mc.workspace_id
           AND identity.fingerprint_sha256 = certops_normalize_fingerprint(mc.fingerprint_sha256)
         WHERE mc.workspace_id = $1 AND mc.token_id = $2
           AND identity.id <> $3 AND identity.lifecycle_status = 'active' LIMIT 1`,
        [workspaceId, tokenId, identityId],
      );
      const affected = await tx.query(
        `SELECT id FROM managed_certificates
        WHERE workspace_id = $1 AND token_id = $2
          AND certops_normalize_fingerprint(fingerprint_sha256) = $3`,
        [workspaceId, tokenId, fingerprint],
      );
      for (const mc of affected.rows) {
        await suppressPendingRetiredCertificateAlerts(tx, {
          workspaceId,
          certificateId: mc.id,
          tokenId,
          suppressTokenExpiry: !sibling.rowCount,
        });
      }
    }
    await tx.query(
      `INSERT INTO audit_events(actor_user_id, subject_user_id, action, target_type,
         target_id, channel, metadata, workspace_id)
       VALUES ($1, $1, 'CERTOPS_CERTIFICATE_RETIRED', 'managed_certificate', NULL, NULL,
         $2::jsonb, $3)`,
      [
        actorUserId,
        JSON.stringify({
          identityId,
          fingerprintSha256: fingerprint,
          status,
          reason: normalizedReason,
          cancelledJobs: cancelled.rowCount,
        }),
        workspaceId,
      ],
    );
    return recordWithManagement(changed.rows[0]);
  });
}

async function stopManagingSource({
  workspaceId,
  periodId,
  actorUserId = null,
  client = pool,
}) {
  if (!UUID_PATTERN.test(String(periodId || "")))
    fail("CERTOPS_MANAGEMENT_PERIOD_NOT_FOUND", "Management period not found");
  return inTransaction(client, async (tx) => {
    await acquireManagedCertificateImportLock(tx, workspaceId);
    const result = await tx.query(
      `SELECT p.*, mc.source, mc.source_ref
         FROM certops_management_periods p
         JOIN managed_certificates mc ON mc.id = p.managed_certificate_id
        WHERE p.workspace_id = $1 AND p.id = $2 FOR UPDATE OF p`,
      [workspaceId, periodId],
    );
    const period = result.rows[0];
    if (!period)
      fail(
        "CERTOPS_MANAGEMENT_PERIOD_NOT_FOUND",
        "Management period not found",
      );
    const closed =
      !period.ended_at &&
      (await tx.query(
        `UPDATE certops_management_periods
      SET ended_at = GREATEST(NOW(), started_at), ended_reason = 'stopped_by_operator'
      WHERE id = $1 RETURNING ended_at`,
        [periodId],
      ));
    const running = await tx.query(
      `SELECT COUNT(*)::int AS c FROM certificate_jobs
      WHERE workspace_id = $1 AND management_period_id = $2
        AND status IN ('claimed', 'running')`,
      [workspaceId, periodId],
    );
    if (period.ended_at)
      return {
        periodId,
        endedAt: period.ended_at,
        runningJobs: Number(running.rows[0]?.c || 0),
      };
    await tx.query(
      `INSERT INTO audit_events(actor_user_id, subject_user_id, action,
      target_type, target_id, channel, metadata, workspace_id)
      VALUES ($1, $1, 'CERTOPS_MANAGEMENT_STOPPED', 'managed_certificate', NULL, NULL,
        $2::jsonb, $3)`,
      [
        actorUserId,
        JSON.stringify({
          periodId,
          managedCertificateId: period.managed_certificate_id,
        }),
        workspaceId,
      ],
    );
    return {
      periodId,
      endedAt: closed.rows[0].ended_at,
      runningJobs: Number(running.rows[0]?.c || 0),
    };
  });
}

async function readdManagingSource({
  workspaceId,
  managedCertificateId,
  renewalProfileId,
  automationEnabled,
  actorUserId = null,
  client = pool,
}) {
  if (!UUID_PATTERN.test(String(managedCertificateId || "")))
    fail("CERTOPS_CERTIFICATE_NOT_FOUND", "Certificate source not found");
  if (
    typeof automationEnabled !== "boolean" ||
    renewalProfileId === undefined
  ) {
    fail(
      "CERTOPS_MANAGEMENT_CONFIG_REQUIRED",
      "Select renewal configuration explicitly",
    );
  }
  if (
    renewalProfileId !== null &&
    !UUID_PATTERN.test(String(renewalProfileId))
  ) {
    fail("CERTOPS_MANAGEMENT_CONFIG_INVALID", "Renewal profile not found");
  }
  return inTransaction(client, async (tx) => {
    await acquireManagedCertificateImportLock(tx, workspaceId);
    const mc = await tx.query(
      `SELECT * FROM managed_certificates
      WHERE workspace_id = $1 AND id = $2 FOR UPDATE`,
      [workspaceId, managedCertificateId],
    );
    if (!mc.rows.length)
      fail("CERTOPS_CERTIFICATE_NOT_FOUND", "Certificate source not found");
    if (mc.rows[0].source === "endpoint_monitor") {
      const monitor = await tx.query(
        `SELECT 1 FROM domain_monitors
        WHERE workspace_id = $1 AND id::text = $2`,
        [workspaceId, mc.rows[0].source_ref],
      );
      if (!monitor.rowCount)
        fail(
          "CERTOPS_MANAGEMENT_SOURCE_UNAVAILABLE",
          "Endpoint no longer exists",
        );
    }
    if (automationEnabled && !renewalProfileId) {
      fail(
        "CERTOPS_MANAGEMENT_CONFIG_REQUIRED",
        "Select a renewal profile for automation",
      );
    }
    if (!automationEnabled && renewalProfileId) {
      fail(
        "CERTOPS_MANAGEMENT_CONFIG_INVALID",
        "Disable automation with no renewal profile selected",
      );
    }
    const open = await tx.query(
      `SELECT 1 FROM certops_management_periods
      WHERE workspace_id = $1 AND managed_certificate_id = $2 AND ended_at IS NULL`,
      [workspaceId, managedCertificateId],
    );
    if (open.rowCount)
      fail("CERTOPS_MANAGEMENT_ALREADY_OPEN", "Source is already managed");
    if (renewalProfileId) {
      const profile = await tx.query(
        `SELECT 1 FROM certificate_profiles
        WHERE workspace_id = $1 AND id = $2`,
        [workspaceId, renewalProfileId],
      );
      if (!profile.rowCount)
        fail("CERTOPS_MANAGEMENT_CONFIG_INVALID", "Renewal profile not found");
    }
    const identity = await tx.query(
      `SELECT id FROM certops_certificate_identities
      WHERE workspace_id = $1 AND fingerprint_sha256 = $2`,
      [workspaceId, normalizeFingerprint(mc.rows[0].fingerprint_sha256)],
    );
    await tx.query("SELECT certops_admit_management($1::uuid, $2::uuid)", [
      workspaceId,
      identity.rows[0]?.id || null,
    ]);
    const inserted = await tx.query(
      `INSERT INTO certops_management_periods(
      workspace_id, managed_certificate_id, current_identity_id, renewal_profile_id,
      automation_enabled, created_by) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [
        workspaceId,
        managedCertificateId,
        identity.rows[0]?.id || null,
        renewalProfileId || null,
        automationEnabled,
        actorUserId,
      ],
    );
    await tx.query(
      `UPDATE managed_certificates SET profile_id = $3, updated_at = NOW()
      WHERE workspace_id = $1 AND id = $2`,
      [workspaceId, managedCertificateId, renewalProfileId || null],
    );
    await tx.query(
      `INSERT INTO audit_events(actor_user_id, subject_user_id, action,
      target_type, target_id, channel, metadata, workspace_id)
      VALUES ($1, $1, 'CERTOPS_MANAGEMENT_STARTED', 'managed_certificate', NULL, NULL,
        $2::jsonb, $3)`,
      [
        actorUserId,
        JSON.stringify({ periodId: inserted.rows[0].id, managedCertificateId }),
        workspaceId,
      ],
    );
    return {
      periodId: inserted.rows[0].id,
      managedCertificateId,
      startedAt: inserted.rows[0].started_at,
    };
  });
}

module.exports = {
  normalizeFingerprint,
  listCertificateIdentities,
  retireCertificateIdentity,
  stopManagingSource,
  readdManagingSource,
};
