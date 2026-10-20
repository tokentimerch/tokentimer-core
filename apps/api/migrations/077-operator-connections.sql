-- Operator connections (ADR-0015): a delegated principal for MCP clients.
--
-- One connection represents one user in one workspace. The credential that
-- authenticates it is stored only as a hash and can be rotated without
-- changing the connection. The role ceiling is fixed when the connection is
-- created; promotion of the user never widens it. Authority is evaluated per
-- request against the user's current membership, so nothing here caches a role.
--
-- Deliberately separate from api_tokens, certops_agents and the bootstrap
-- tables: those authenticate machines, this authenticates a person's delegate.

CREATE TABLE IF NOT EXISTS operator_connections (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL
    CHECK (char_length(btrim(name)) BETWEEN 1 AND 128),
  scopes TEXT[] NOT NULL
    CHECK (cardinality(scopes) BETWEEN 1 AND 16),
  role_ceiling TEXT NOT NULL
    CHECK (role_ceiling IN ('viewer', 'workspace_manager', 'admin')),
  credential_prefix TEXT NOT NULL
    CHECK (credential_prefix ~ '^ttopc_[a-f0-9]{16}$'),
  credential_hash TEXT NOT NULL
    CHECK (credential_hash ~ '^[a-f0-9]{64}$'),
  credential_rotated_at TIMESTAMPTZ NULL,
  status TEXT NOT NULL DEFAULT 'active'
    CHECK (status IN ('active', 'revoked')),
  expires_at TIMESTAMPTZ NOT NULL,
  last_used_at TIMESTAMPTZ NULL,
  revoked_at TIMESTAMPTZ NULL,
  revoked_by INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
  created_by INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_operator_connections_workspace_id UNIQUE (workspace_id, id),
  CONSTRAINT uq_operator_connections_credential_prefix UNIQUE (credential_prefix),
  CONSTRAINT uq_operator_connections_credential_hash UNIQUE (credential_hash),
  CONSTRAINT operator_connections_revoked_consistency_check CHECK (
    (status = 'revoked') = (revoked_at IS NOT NULL)
  ),
  -- A connection is bounded: no open-ended delegation. The service also caps
  -- the lifetime at creation; this keeps a manual insert from bypassing it.
  CONSTRAINT operator_connections_expiry_after_creation_check CHECK (
    expires_at > created_at
  ),
  CONSTRAINT operator_connections_expiry_cap_check CHECK (
    expires_at <= created_at + INTERVAL '90 days'
  )
);

CREATE INDEX IF NOT EXISTS idx_operator_connections_workspace
  ON operator_connections(workspace_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_operator_connections_user
  ON operator_connections(user_id, workspace_id)
  WHERE status = 'active';
