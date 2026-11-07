CREATE TABLE IF NOT EXISTS certops_agent_credential_rotations (
  agent_id UUID PRIMARY KEY REFERENCES certops_agents(id) ON DELETE CASCADE,
  operation_id TEXT NOT NULL UNIQUE CHECK (operation_id ~ '^[a-f0-9]{32}$'),
  prior_hash TEXT NOT NULL CHECK (prior_hash ~ '^[a-f0-9]{64}$'),
  candidate_prefix TEXT NOT NULL CHECK (candidate_prefix ~ '^ttagent_[a-f0-9]{16}$'),
  candidate_hash TEXT NOT NULL CHECK (candidate_hash ~ '^[a-f0-9]{64}$'),
  state TEXT NOT NULL CHECK (state IN ('pending', 'committed')),
  expires_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
