-- Curated agent execution-console storage.
-- job_state owns the per-job ingest_order counter. It is never derived from
-- MAX(ingest_order): retention deletes log rows, and a cursor that was already
-- returned must stay behind every later committed line.

CREATE TABLE IF NOT EXISTS certops_agent_log_job_state (
  workspace_id UUID NOT NULL,
  job_id UUID NOT NULL,
  next_ingest_order BIGINT NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (workspace_id, job_id),
  CONSTRAINT fk_certops_agent_log_job_state_job
    FOREIGN KEY (workspace_id, job_id)
    REFERENCES certificate_jobs (workspace_id, id)
    ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS certops_agent_log_stream (
  workspace_id UUID NOT NULL,
  job_id UUID NOT NULL,
  claim_id UUID NOT NULL,
  agent_id UUID NOT NULL,
  attempt_number INTEGER NOT NULL CHECK (attempt_number >= 0),
  streaming_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'streaming', 'final', 'abandoned', 'disabled')),
  issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  closed_at TIMESTAMPTZ NULL,
  accept_until TIMESTAMPTZ NULL,
  resolved_through_seq BIGINT NOT NULL DEFAULT 0,
  accepted_lines INTEGER NOT NULL DEFAULT 0,
  accepted_bytes BIGINT NOT NULL DEFAULT 0,
  server_dropped_lines INTEGER NOT NULL DEFAULT 0,
  agent_gap_lines INTEGER NOT NULL DEFAULT 0,
  rejected_batches INTEGER NOT NULL DEFAULT 0,
  conflict_count INTEGER NOT NULL DEFAULT 0,
  conflicts JSONB NOT NULL DEFAULT '{}'::jsonb,
  last_batch_key TEXT NULL,
  last_ack JSONB NULL,
  last_http_status INTEGER NULL,
  first_received_at TIMESTAMPTZ NULL,
  last_received_at TIMESTAMPTZ NULL,
  finalized_at TIMESTAMPTZ NULL,
  PRIMARY KEY (workspace_id, job_id, claim_id),
  CONSTRAINT fk_certops_agent_log_stream_job
    FOREIGN KEY (workspace_id, job_id)
    REFERENCES certificate_jobs (workspace_id, id)
    ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_certops_agent_log_stream_abandon
  ON certops_agent_log_stream (accept_until)
  WHERE status IN ('pending', 'streaming') AND accept_until IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_certops_agent_log_stream_closed
  ON certops_agent_log_stream (closed_at)
  WHERE closed_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_certops_agent_log_stream_open
  ON certops_agent_log_stream (issued_at)
  WHERE closed_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_certops_agent_log_stream_agent
  ON certops_agent_log_stream (workspace_id, agent_id, issued_at DESC);

CREATE TABLE IF NOT EXISTS certops_agent_log_daily_quota (
  workspace_id UUID NOT NULL,
  quota_day DATE NOT NULL,
  used_bytes BIGINT NOT NULL DEFAULT 0,
  used_lines INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (workspace_id, quota_day)
);

CREATE TABLE IF NOT EXISTS certops_agent_job_log (
  id BIGSERIAL PRIMARY KEY,
  workspace_id UUID NOT NULL,
  job_id UUID NOT NULL,
  claim_id UUID NOT NULL,
  seq BIGINT NOT NULL,
  ts TIMESTAMPTZ NOT NULL,
  received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  level TEXT NOT NULL CHECK (level IN ('info', 'warn', 'error')),
  step TEXT NOT NULL,
  message TEXT NOT NULL,
  fields JSONB NULL,
  redaction_count INTEGER NOT NULL DEFAULT 0,
  content_hash TEXT NOT NULL,
  ingest_order BIGINT NOT NULL,
  CONSTRAINT uq_certops_agent_job_log_seq
    UNIQUE (workspace_id, job_id, claim_id, seq),
  CONSTRAINT fk_certops_agent_job_log_stream
    FOREIGN KEY (workspace_id, job_id, claim_id)
    REFERENCES certops_agent_log_stream (workspace_id, job_id, claim_id)
    ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_certops_agent_job_log_cursor
  ON certops_agent_job_log (workspace_id, job_id, ingest_order);

CREATE INDEX IF NOT EXISTS idx_certops_agent_job_log_received
  ON certops_agent_job_log (received_at);
