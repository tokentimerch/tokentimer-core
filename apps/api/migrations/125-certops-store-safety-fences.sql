-- Drain existing job writers before the backfill snapshot, and prevent new
-- writers until the cancellation trigger becomes visible at commit.
LOCK TABLE certificate_jobs IN SHARE ROW EXCLUSIVE MODE;

-- A receipt is usable only after another transaction has observed its commit
-- while its original claim is still live. Existing receipts remain unverified.
ALTER TABLE certops_adcs_expected_identity_receipts
  ADD COLUMN IF NOT EXISTS committed_seen_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS origin_xid BIGINT;

ALTER TABLE certops_acme_store_enrollments
  DROP CONSTRAINT IF EXISTS certops_acme_store_enrollments_state_check;
ALTER TABLE certops_acme_store_enrollments
  ADD CONSTRAINT certops_acme_store_enrollments_state_check CHECK
    (state IN ('keygen_intent','prepared','submitting','issued','installing','installed','uncertain','cancelled_no_effect'));
DROP INDEX IF EXISTS uq_certops_acme_store_open_certificate;
CREATE UNIQUE INDEX uq_certops_acme_store_open_certificate
  ON certops_acme_store_enrollments(workspace_id, certificate_id)
  WHERE state NOT IN ('installed','cancelled_no_effect');

-- Release only preview rows whose durable state proves no external effect.
UPDATE certops_acme_store_enrollments e
   SET state='cancelled_no_effect'
  FROM certificate_jobs j
 WHERE j.workspace_id=e.workspace_id AND j.id=e.original_job_id
   AND e.current_job_id=e.original_job_id AND e.state='keygen_intent'
   AND j.status IN ('cancelled','rejected') AND j.attempt_count=0
   AND j.claim_id IS NULL AND j.claimed_by_agent_id IS NULL
   AND NOT EXISTS (SELECT 1 FROM certificate_evidence ev WHERE ev.workspace_id=j.workspace_id AND ev.job_id=j.id)
   AND e.csr_sha256 IS NULL AND e.csr_spki_sha256 IS NULL
   AND e.fingerprint_sha256 IS NULL AND e.order_reference_sha256 IS NULL
   AND NOT EXISTS (SELECT 1 FROM certops_acme_store_receipts r
                    WHERE r.workspace_id=e.workspace_id AND r.enrollment_id=e.id);
-- The job transition and no-effect cancellation commit together. Attempts
-- that were ever claimed, submitted, or received evidence remain fenced.
CREATE OR REPLACE FUNCTION certops_cancel_unclaimed_acme_store() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.status IN ('pending','pending_approval')
     AND NEW.status IN ('cancelled','rejected')
     AND OLD.attempt_count=0 AND NEW.attempt_count=0
     AND OLD.claim_id IS NULL AND NEW.claim_id IS NULL
     AND OLD.claimed_by_agent_id IS NULL AND NEW.claimed_by_agent_id IS NULL THEN
    UPDATE certops_acme_store_enrollments e
       SET state='cancelled_no_effect', updated_at=clock_timestamp()
     WHERE e.workspace_id=NEW.workspace_id AND e.original_job_id=NEW.id
       AND e.current_job_id=NEW.id AND e.state='keygen_intent'
       AND e.csr_sha256 IS NULL AND e.csr_spki_sha256 IS NULL
       AND e.fingerprint_sha256 IS NULL AND e.order_reference_sha256 IS NULL
       AND NOT EXISTS (SELECT 1 FROM certificate_evidence ev WHERE ev.workspace_id=NEW.workspace_id AND ev.job_id=NEW.id)
       AND NOT EXISTS (SELECT 1 FROM certops_acme_store_receipts r
                        WHERE r.workspace_id=e.workspace_id AND r.enrollment_id=e.id);
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS certops_cancel_unclaimed_acme_store ON certificate_jobs;
CREATE TRIGGER certops_cancel_unclaimed_acme_store
AFTER UPDATE OF status ON certificate_jobs FOR EACH ROW
EXECUTE FUNCTION certops_cancel_unclaimed_acme_store();
