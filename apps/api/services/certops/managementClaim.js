"use strict";

// A claim already owns its job row. Retirement owns the identity before
// closing its periods, and enrollment cancellation owns the enrollment before
// touching its job. Never wait for those rows in the reverse order: leave busy
// work queued for the next poll instead of aborting either transaction.
async function lockManagedJobForClaim({ client, job, workspaceId }) {
  if (job.subject_type !== "managed_certificate") return true;

  if (job.operation === "adcs-installation-proof") {
    const binding = await require("./adcsProofRecovery").loadAdcsProofJobBindingTx({ client, workspaceId, jobId: job.id, agentId: job.assigned_agent_id });
    return Boolean(binding);
  }

  if (job.operation === "continue-enrollment" && job.acme_store_bound === true) {
    const enrollment = await client.query(
      `SELECT id FROM certops_acme_store_enrollments
        WHERE workspace_id = $1 AND certificate_id::text = lower($2)
          AND agent_id = $3 AND current_job_id = $4
        FOR SHARE SKIP LOCKED`,
      [workspaceId, job.subject_id, job.assigned_agent_id, job.id],
    );
    if (!enrollment.rows[0]) return false;
  } else if (job.enrollment_id || job.operation === "continue-enrollment") {
    const enrollment = await client.query(
      `SELECT state FROM certificate_enrollments
        WHERE workspace_id = $1 AND id = $2
          AND certificate_id::text = lower($3)
          AND agent_id = $4 AND current_job_id = $5
        FOR SHARE SKIP LOCKED`,
      [workspaceId, job.enrollment_id, job.subject_id, job.assigned_agent_id, job.id],
    );
    if (!enrollment.rows[0]) return false;
    if (["cancelled", "expired", "abandoned"].includes(enrollment.rows[0].state)) {
      // Only the current continuation of its bound terminal enrollment can
      // clean up a retained key after management ends. This lock also keeps
      // the signed dispatch directive consistent with the admission decision.
      return job.operation === "continue-enrollment";
    }
  }

  if (!job.management_period_id) return true;
  const ownership = await client.query(
    `SELECT current_identity_id FROM certops_management_periods
      WHERE id = $1 AND workspace_id = $2 AND ended_at IS NULL
      FOR SHARE SKIP LOCKED`,
    [job.management_period_id, workspaceId],
  );
  if (!ownership.rows[0]) return false;

  const identityId = job.certificate_identity_id || ownership.rows[0].current_identity_id;
  if (!identityId) return true; // Initial provisioning has no identity yet.
  const identity = await client.query(
    `SELECT id FROM certops_certificate_identities
      WHERE workspace_id = $1 AND id = $2
      FOR SHARE SKIP LOCKED`,
    [workspaceId, identityId],
  );
  return Boolean(identity.rows[0]);
}

// A never-started automatic enrollment must still reflect the operator's
// current management policy. Retried claims and continuations may already
// have effects and must retain their existing recovery path.
async function lockAutomaticAdcsRenewalForClaim({ client, job, workspaceId }) {
  if (job.status !== "pending" || job.source !== "automation" || job.operation !== "renew" ||
      !job.enrollment_id || Number(job.attempt_count) !== 0 || job.subject_type !== "managed_certificate") return true;
  const locked = await client.query(
    `SELECT period.automation_enabled, period.renewal_profile_id, period.current_identity_id, mc.profile_id,
            mc.fingerprint_sha256, mc.deployed_agent_id, identity.fingerprint_sha256 AS identity_fingerprint,
            (mc.not_after IS NOT NULL AND (cp.renew_before_days IS NULL OR
              mc.not_after <= NOW() + (cp.renew_before_days || ' days')::interval)) AS currently_due,
            cp.status AS profile_status, cp.issuer_id, cp.public_metadata,
            issuer.current_version, issuer.revalidation_required, enrollment.issuer_id AS enrolled_issuer_id, enrollment.agent_id AS enrolled_agent_id,
            enrollment.issuer_version, enrollment.snapshot_bytes, enrollment.deploy_target
       FROM certificate_enrollments enrollment
       JOIN managed_certificates mc ON mc.workspace_id=enrollment.workspace_id AND mc.id=enrollment.certificate_id
       JOIN certops_management_periods period ON period.workspace_id=mc.workspace_id AND period.managed_certificate_id=mc.id
       LEFT JOIN certops_certificate_identities identity ON identity.workspace_id=period.workspace_id AND identity.id=period.current_identity_id
       JOIN certificate_profiles cp ON cp.workspace_id=mc.workspace_id AND cp.id=mc.profile_id
       JOIN certificate_issuers issuer ON issuer.workspace_id=enrollment.workspace_id AND issuer.id=enrollment.issuer_id
      WHERE enrollment.workspace_id=$1 AND enrollment.id=$2 AND enrollment.current_job_id=$3
        AND mc.id::text=lower($4) AND period.ended_at IS NULL
        AND ($5::uuid IS NULL OR period.id=$5::uuid)
      FOR SHARE OF period, mc, cp, issuer SKIP LOCKED`,
    [workspaceId, job.enrollment_id, job.id, job.subject_id, job.management_period_id || null],
  );
  const row = locked.rows[0];
  if (!row || !row.automation_enabled || !row.currently_due || ["disabled", "archived"].includes(row.profile_status)) return false;
  if (!row.current_identity_id || !row.identity_fingerprint || !row.fingerprint_sha256) return false;
  if (!job.certificate_identity_id) return "supersede";
  if (String(job.certificate_identity_id) !== String(row.current_identity_id) ||
      String(row.fingerprint_sha256).replace(/:/g, "").toLowerCase() !== String(row.identity_fingerprint).toLowerCase() ||
      String(job.assigned_agent_id) !== String(row.enrolled_agent_id)) return "supersede";
  const address = row.deploy_target?.binding?.address;
  const ownerRequired = row.deploy_target?.type === "windows-cert-store" ||
    (row.deploy_target?.type === "windows-iis" && address != null && address !== "*" && address !== "0.0.0.0");
  if (ownerRequired && !row.deployed_agent_id) return false;
  if (ownerRequired && String(row.deployed_agent_id) !== String(job.assigned_agent_id)) return "supersede";
  if (row.renewal_profile_id !== row.profile_id || row.issuer_id !== row.enrolled_issuer_id ||
      Number(row.current_version) !== Number(row.issuer_version)) return "supersede";
  if (row.revalidation_required === true) return false;
  try {
    const profile = require("./adcsRenewalRules").validateAdcsRenewalProfile(row.public_metadata?.renewalProfile);
    const snapshot = JSON.parse(Buffer.from(row.snapshot_bytes).toString("utf8"));
    const equal = require("node:util").isDeepStrictEqual;
    return equal(profile.target, row.deploy_target) && equal(profile.sanPolicy.sans, snapshot.authorizedDnsNames) &&
      profile.keyAlgorithm === snapshot.keyAlgorithm && profile.keySize === snapshot.keySize ? true : "supersede";
  } catch {
    return false;
  }
}

module.exports = { lockManagedJobForClaim, lockAutomaticAdcsRenewalForClaim };
