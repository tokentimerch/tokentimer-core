"use strict";

// A claim already owns its job row. Retirement owns the identity before
// closing its periods, and enrollment cancellation owns the enrollment before
// touching its job. Never wait for those rows in the reverse order: leave busy
// work queued for the next poll instead of aborting either transaction.
async function lockManagedJobForClaim({ client, job, workspaceId }) {
  if (job.subject_type !== "managed_certificate") return true;

  if (job.enrollment_id || job.operation === "continue-enrollment") {
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

module.exports = { lockManagedJobForClaim };
