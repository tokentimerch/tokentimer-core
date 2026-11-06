-- Issuance jobs begin without a certificate fingerprint. Preserve the
-- first verified identity separately from the job's immutable admission identity.
CREATE TABLE IF NOT EXISTS certops_issuance_job_identities (
  workspace_id UUID NOT NULL,
  job_id UUID NOT NULL PRIMARY KEY,
  identity_id UUID NOT NULL,
  FOREIGN KEY (workspace_id, job_id) REFERENCES certificate_jobs(workspace_id, id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, identity_id) REFERENCES certops_certificate_identities(workspace_id, id)
);

CREATE OR REPLACE FUNCTION certops_guard_issuance_job_identity()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW IS DISTINCT FROM OLD THEN
    RAISE EXCEPTION 'Issuance job identity is immutable' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS trg_certops_guard_issuance_job_identity ON certops_issuance_job_identities;
CREATE TRIGGER trg_certops_guard_issuance_job_identity BEFORE UPDATE ON certops_issuance_job_identities
  FOR EACH ROW EXECUTE FUNCTION certops_guard_issuance_job_identity();

-- Earlier completed jobs are attributable only when the successful claim's
-- latest verification names an identity associated with that job's own period.
INSERT INTO certops_issuance_job_identities(workspace_id, job_id, identity_id)
SELECT j.workspace_id, j.id, i.id
  FROM certificate_jobs j
  CROSS JOIN LATERAL (
    SELECT e.metadata, COUNT(*) OVER (PARTITION BY e.created_at) AS timestamp_count FROM certificate_evidence e
     WHERE e.workspace_id = j.workspace_id AND e.job_id = j.id
       AND e.claim_id = j.claim_id AND e.evidence_type = 'validation.passed'
       AND e.metadata->>'step' = 'verify' AND e.created_at <= j.completed_at
     ORDER BY e.created_at DESC, e.id DESC LIMIT 1
  ) evidence
  JOIN certops_certificate_identities i
    ON i.workspace_id = j.workspace_id
   AND i.fingerprint_sha256 = certops_normalize_fingerprint(evidence.metadata->>'fingerprintSha256')
  JOIN certops_management_associations a
    ON a.workspace_id = j.workspace_id AND a.period_id = j.management_period_id
   AND a.identity_id = i.id
 WHERE j.operation = 'issue' AND j.status = 'succeeded'
   AND j.certificate_identity_id IS NULL AND j.claim_id IS NOT NULL
   AND evidence.timestamp_count = 1
   AND NULLIF(evidence.metadata->>'validTo', '') IS NOT NULL
   AND EXISTS (
     SELECT 1 FROM audit_events audit
      WHERE audit.workspace_id = j.workspace_id AND audit.action = 'CERTOPS_CERTIFICATE_ISSUED'
        AND audit.metadata->>'jobId' = j.id::text
        AND certops_normalize_fingerprint(audit.metadata->>'fingerprintSha256') = i.fingerprint_sha256
   )
ON CONFLICT (job_id) DO NOTHING;
