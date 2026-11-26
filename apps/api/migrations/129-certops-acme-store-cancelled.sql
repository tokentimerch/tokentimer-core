ALTER TABLE certops_acme_store_enrollments
  DROP CONSTRAINT certops_acme_store_enrollments_state_check,
  ADD CONSTRAINT certops_acme_store_enrollments_state_check
    CHECK (state IN ('keygen_intent', 'prepared', 'submitting', 'issued', 'installing', 'installed', 'uncertain', 'cancelled_no_effect'));

-- A terminal decision alone is insufficient evidence that no order exists.
-- Reconcile only rows belonging to the original job with no claim history.
UPDATE certops_acme_store_enrollments e
SET state='cancelled_no_effect', updated_at=NOW()
FROM certificate_jobs j
WHERE (j.workspace_id,j.id)=(e.workspace_id,e.original_job_id)
  AND e.current_job_id=e.original_job_id AND e.state='keygen_intent'
  AND j.operation IN ('issue','renew') AND j.enrollment_id IS NULL AND j.mode='real'
  AND j.payload->'target'->>'type'='windows-cert-store'
  AND j.subject_type='managed_certificate' AND j.subject_id=e.certificate_id::text
  AND j.assigned_agent_id=e.agent_id AND j.status IN ('cancelled','rejected')
  AND j.attempt_count=0 AND j.claim_id IS NULL AND j.claimed_by_agent_id IS NULL
  AND j.lease_expires_at IS NULL AND j.lease_renewed_at IS NULL
  AND j.needs_operator_reconciliation IS NOT TRUE
  AND NOT EXISTS (SELECT 1 FROM certops_consumed_nonces n
    WHERE (n.workspace_id,n.job_id)=(j.workspace_id,j.id))
  AND e.csr_sha256 IS NULL AND e.csr_spki_sha256 IS NULL
  AND e.fingerprint_sha256 IS NULL AND e.order_reference_sha256 IS NULL
  AND NOT EXISTS (SELECT 1 FROM certificate_evidence ev
    WHERE (ev.workspace_id,ev.job_id)=(j.workspace_id,j.id))
  AND NOT EXISTS (SELECT 1 FROM certops_acme_store_receipts r
    WHERE (r.workspace_id,r.enrollment_id)=(e.workspace_id,e.id));

DROP INDEX uq_certops_acme_store_open_certificate;
CREATE UNIQUE INDEX uq_certops_acme_store_open_certificate
  ON certops_acme_store_enrollments (workspace_id, certificate_id)
  WHERE state NOT IN ('installed', 'cancelled_no_effect');
