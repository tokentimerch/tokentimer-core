CREATE TABLE IF NOT EXISTS certops_adcs_expected_identity_receipts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL,
  enrollment_id UUID NOT NULL,
  agent_id UUID NOT NULL,
  original_job_id UUID NOT NULL,
  original_claim_id UUID NOT NULL,
  original_attempt INTEGER NOT NULL CHECK (original_attempt > 0),
  evidence_id UUID NOT NULL,
  snapshot_sha256 TEXT NOT NULL CHECK (snapshot_sha256 ~ '^[a-f0-9]{64}$'),
  destination_sha256 TEXT NOT NULL CHECK (destination_sha256 ~ '^[a-f0-9]{64}$'),
  fingerprint_sha256 TEXT NOT NULL CHECK (fingerprint_sha256 ~ '^[a-f0-9]{64}$'),
  csr_spki_sha256 TEXT NOT NULL CHECK (csr_spki_sha256 ~ '^[a-f0-9]{64}$'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
  UNIQUE (workspace_id, id),
  UNIQUE (workspace_id, enrollment_id, original_job_id, original_claim_id, original_attempt),
  FOREIGN KEY (workspace_id, enrollment_id) REFERENCES certificate_enrollments(workspace_id, id),
  FOREIGN KEY (workspace_id, original_job_id) REFERENCES certificate_jobs(workspace_id, id),
  FOREIGN KEY (workspace_id, evidence_id) REFERENCES certificate_evidence(workspace_id, id),
  FOREIGN KEY (workspace_id, agent_id) REFERENCES certops_agents(workspace_id, id)
);

ALTER TABLE certificate_jobs DROP CONSTRAINT certificate_jobs_operation_check;
ALTER TABLE certificate_jobs ADD CONSTRAINT certificate_jobs_operation_check CHECK (operation IN
  ('issue','renew','deploy','deploy-from-store','reload','revoke','noop','protocol_smoke','distribute-trust','revoke-trust','continue-enrollment','adcs-preflight','adcs-installation-proof'));

CREATE TABLE IF NOT EXISTS certops_adcs_proof_recovery_intents (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL,
  enrollment_id UUID NOT NULL,
  receipt_id UUID NOT NULL,
  agent_id UUID NOT NULL,
  state TEXT NOT NULL DEFAULT 'transport_unavailable' CHECK (state IN ('transport_unavailable', 'queued')),
  proof_job_id UUID NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
  UNIQUE (workspace_id, receipt_id),
  FOREIGN KEY (workspace_id, enrollment_id) REFERENCES certificate_enrollments(workspace_id, id),
  FOREIGN KEY (workspace_id, receipt_id) REFERENCES certops_adcs_expected_identity_receipts(workspace_id, id),
  FOREIGN KEY (workspace_id, agent_id) REFERENCES certops_agents(workspace_id, id),
  FOREIGN KEY (workspace_id, proof_job_id) REFERENCES certificate_jobs(workspace_id, id)
);
