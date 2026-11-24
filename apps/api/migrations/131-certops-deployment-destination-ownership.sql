-- Retain the one owner of a canonical mutation domain even after the job,
-- lease or agent disappears. Result delivery does not release this fence.
CREATE TABLE certops_deployment_destination_operations (
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  mutation_domain_sha256 text NOT NULL CHECK (mutation_domain_sha256 ~ '^[a-f0-9]{64}$'),
  operation_id text NOT NULL CHECK (operation_id ~ '^[a-f0-9]{64}$'),
  owner_job_id uuid NOT NULL UNIQUE,
  owner_claim_id uuid NOT NULL UNIQUE,
  owner_agent_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (workspace_id, mutation_domain_sha256),
  UNIQUE (workspace_id, operation_id)
);
