-- Operator renew requests (ADR-0015 sections 6, 8 and 10).
--
-- A preview is an immutable, short-lived record of exactly what a renewal would
-- do, bound to the connection that asked. A request is one deliberate
-- submission of a preview. Both are separate from the job: the job is the
-- existing CertOps unit of work and keeps its own approval ledger, and the
-- request only remembers who asked and ties retries together.

-- Which connection asked for a job. Null for every job created by a person,
-- the scheduler or an agent. SET NULL, not CASCADE: deleting a connection must
-- not delete the record of work it caused, and the job keeps requested_by_user_id.
ALTER TABLE certificate_jobs
  ADD COLUMN IF NOT EXISTS requested_by_connection_id UUID NULL
    REFERENCES operator_connections(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_certificate_jobs_requested_by_connection
  ON certificate_jobs(requested_by_connection_id)
  WHERE requested_by_connection_id IS NOT NULL;

-- Second of the three write gates (instance flag, this setting, the scope).
-- Off by default in every workspace; an admin turns it on from a session.
ALTER TABLE workspaces
  ADD COLUMN IF NOT EXISTS operator_writes_enabled BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS operator_action_plans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  connection_id UUID NOT NULL REFERENCES operator_connections(id) ON DELETE CASCADE,
  operation TEXT NOT NULL CHECK (operation IN ('renew')),
  -- The handle the caller used (a certificate identity), and the managed
  -- certificate it resolved to when the plan was made.
  identity_id UUID NOT NULL,
  -- The managed certificate the plan is about, and the facts it was computed
  -- from. A submission re-reads these; a change means the plan is stale.
  subject_id UUID NOT NULL,
  bound_fingerprint_sha256 TEXT NULL
    CHECK (bound_fingerprint_sha256 IS NULL OR bound_fingerprint_sha256 ~ '^[a-f0-9]{64}$'),
  bound_profile_id UUID NULL,
  -- Hash of the canonical effect shown to the person. The submission must
  -- present it back, so what is approved is what was previewed.
  plan_hash TEXT NOT NULL CHECK (plan_hash ~ '^[a-f0-9]{64}$'),
  effect JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  CONSTRAINT operator_action_plans_expiry_check CHECK (
    expires_at > created_at AND expires_at <= created_at + INTERVAL '15 minutes'
  ),
  CONSTRAINT uq_operator_action_plans_workspace_id UNIQUE (workspace_id, id)
);

CREATE INDEX IF NOT EXISTS idx_operator_action_plans_connection
  ON operator_action_plans(connection_id, created_at DESC);

CREATE TABLE IF NOT EXISTS operator_action_requests (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  connection_id UUID NOT NULL REFERENCES operator_connections(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  -- Client-generated, reused across retries of one deliberate submission.
  request_id UUID NOT NULL,
  plan_id UUID NOT NULL,
  plan_hash TEXT NOT NULL CHECK (plan_hash ~ '^[a-f0-9]{64}$'),
  operation TEXT NOT NULL CHECK (operation IN ('renew')),
  identity_id UUID NOT NULL,
  subject_id UUID NOT NULL,
  job_id UUID NULL,
  -- Only the states the job cannot express. Everything else is read from the job.
  state_override TEXT NULL CHECK (state_override IN ('cancelled', 'expired', 'stale')),
  state_reason TEXT NULL CHECK (state_reason IS NULL OR state_reason ~ '^[a-z][a-z0-9_]{1,63}$'),
  approval_expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  -- Replay is scoped to the originating connection.
  CONSTRAINT uq_operator_action_requests_connection_request UNIQUE (connection_id, request_id),
  -- A preview is spent by its first submission, so one preview cannot become
  -- several orders at the certificate authority.
  CONSTRAINT uq_operator_action_requests_plan UNIQUE (plan_id),
  CONSTRAINT operator_action_requests_plan_fk
    FOREIGN KEY (workspace_id, plan_id) REFERENCES operator_action_plans(workspace_id, id)
);

CREATE INDEX IF NOT EXISTS idx_operator_action_requests_connection
  ON operator_action_requests(connection_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_operator_action_requests_job
  ON operator_action_requests(job_id) WHERE job_id IS NOT NULL;
