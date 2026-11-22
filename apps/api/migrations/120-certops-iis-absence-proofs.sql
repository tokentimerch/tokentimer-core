-- Short-lived, authenticated agent proofs.  A unique client id prevents a
-- transport retry from renewing a proof's server receipt timestamp.
-- Keep the provenance on the registration, including across management
-- period changes, so an operator-editable profile cannot remove the guard.
ALTER TABLE managed_certificates ADD COLUMN IF NOT EXISTS iis_reassociation_requires_absence BOOLEAN NOT NULL DEFAULT FALSE;
CREATE TABLE IF NOT EXISTS certops_iis_absence_proofs (
  workspace_id UUID NOT NULL,
  agent_id UUID NOT NULL,
  evidence_id TEXT NOT NULL CHECK (evidence_id ~ '^[A-Za-z0-9_.:-]{1,128}$'),
  target_host TEXT NOT NULL CHECK (char_length(target_host) BETWEEN 1 AND 255),
  site TEXT NOT NULL CHECK (char_length(site) BETWEEN 1 AND 128),
  port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
  address INET NOT NULL,
  fingerprint_sha256 TEXT NOT NULL CHECK (fingerprint_sha256 ~ '^[a-f0-9]{64}$'),
  thumbprint TEXT NOT NULL CHECK (thumbprint ~ '^[a-f0-9]{40}$'),
  observed_at TIMESTAMPTZ NOT NULL,
  received_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  agent_sequence BIGINT NOT NULL CHECK (agent_sequence > 0),
  PRIMARY KEY (workspace_id, agent_id, evidence_id),
  FOREIGN KEY (workspace_id, agent_id) REFERENCES certops_agents(workspace_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_certops_iis_absence_proofs_lookup
  ON certops_iis_absence_proofs(workspace_id, agent_id, site, port, address, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_certops_iis_absence_proofs_expiry
  ON certops_iis_absence_proofs(received_at);
