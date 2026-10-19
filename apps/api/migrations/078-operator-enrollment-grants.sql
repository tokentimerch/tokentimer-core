-- Operator enrollment grants (ADR-0015 section 12).
--
-- A grant is the one-time secret a signed-in person creates to connect an
-- assistant. It fixes the user, workspace, scopes, role ceiling and connection
-- name when it is created, and redeeming it can change none of them. Only a
-- hash is stored. There is no stored copy of the credential it produces: if the
-- response to a redemption is lost, the connection is revoked and a new grant
-- is issued.
--
-- Separate from agent bootstrap tokens on purpose: different prefix, different
-- table, different routes, so older code against this schema can never accept
-- one as the other.

CREATE TABLE IF NOT EXISTS operator_enrollment_grants (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL
    CHECK (char_length(btrim(name)) BETWEEN 1 AND 128),
  scopes TEXT[] NOT NULL
    CHECK (cardinality(scopes) BETWEEN 1 AND 16),
  role_ceiling TEXT NOT NULL
    CHECK (role_ceiling IN ('viewer', 'workspace_manager', 'admin')),
  -- How long the connection lives once redeemed. Fixed here so the person
  -- redeeming cannot ask for more than the person who authorized it.
  connection_lifetime_days SMALLINT NOT NULL
    CHECK (connection_lifetime_days BETWEEN 1 AND 90),
  grant_prefix TEXT NOT NULL
    CHECK (grant_prefix ~ '^ttopg_[a-f0-9]{16}$'),
  grant_hash TEXT NOT NULL
    CHECK (grant_hash ~ '^[a-f0-9]{64}$'),
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'redeemed', 'revoked')),
  expires_at TIMESTAMPTZ NOT NULL,
  redeemed_at TIMESTAMPTZ NULL,
  -- SET NULL, not CASCADE: deleting a connection must not erase the record
  -- that a grant was spent.
  redeemed_connection_id UUID NULL
    REFERENCES operator_connections(id) ON DELETE SET NULL,
  revoked_at TIMESTAMPTZ NULL,
  revoked_by INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
  created_by INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_operator_enrollment_grants_prefix UNIQUE (grant_prefix),
  CONSTRAINT uq_operator_enrollment_grants_hash UNIQUE (grant_hash),
  -- Short by construction: a manual insert cannot create a long-lived grant.
  CONSTRAINT operator_enrollment_grants_expiry_check CHECK (
    expires_at > created_at AND expires_at <= created_at + INTERVAL '15 minutes'
  ),
  -- The state fields move together, so a row can never claim to be redeemed
  -- without a time, or revoked and redeemed at once.
  CONSTRAINT operator_enrollment_grants_state_check CHECK (
    (status = 'pending' AND redeemed_at IS NULL AND revoked_at IS NULL)
    OR (status = 'redeemed' AND redeemed_at IS NOT NULL AND revoked_at IS NULL)
    OR (status = 'revoked' AND revoked_at IS NOT NULL AND redeemed_at IS NULL)
  )
);

CREATE INDEX IF NOT EXISTS idx_operator_enrollment_grants_workspace
  ON operator_enrollment_grants(workspace_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_operator_enrollment_grants_user
  ON operator_enrollment_grants(user_id, workspace_id, created_at DESC);
