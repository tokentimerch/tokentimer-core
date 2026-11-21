ALTER TABLE certops_adcs_expected_identity_receipts
  ADD COLUMN IF NOT EXISTS origin_xid BIGINT,
  ADD COLUMN IF NOT EXISTS committed_seen_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS receipt_claim_expires_at TIMESTAMPTZ;

-- Preserve the identity, but never reconstruct old authority from a newer lease.
UPDATE certops_adcs_expected_identity_receipts
   SET committed_seen_at=NULL
 WHERE receipt_claim_expires_at IS NULL;

ALTER TABLE certops_adcs_expected_identity_receipts
  DROP CONSTRAINT IF EXISTS certops_adcs_receipt_deadline_check;
ALTER TABLE certops_adcs_expected_identity_receipts
  ADD CONSTRAINT certops_adcs_receipt_deadline_check CHECK (
    committed_seen_at IS NULL OR (
      origin_xid IS NOT NULL AND receipt_claim_expires_at IS NOT NULL
      AND committed_seen_at < receipt_claim_expires_at
    )
  );
