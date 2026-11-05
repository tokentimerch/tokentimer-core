CREATE TABLE IF NOT EXISTS operator_inventory_plans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  connection_id UUID NOT NULL REFERENCES operator_connections(id) ON DELETE CASCADE,
  plan_hash TEXT NOT NULL CHECK (plan_hash ~ '^[a-f0-9]{64}$'),
  decisions JSONB NOT NULL CHECK (jsonb_typeof(decisions) = 'array' AND jsonb_array_length(decisions) BETWEEN 1 AND 100),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '15 minutes'),
  imported_at TIMESTAMPTZ NULL,
  UNIQUE (workspace_id, id),
  CHECK (expires_at > created_at AND expires_at <= created_at + INTERVAL '15 minutes')
);
CREATE INDEX IF NOT EXISTS operator_inventory_plans_connection ON operator_inventory_plans(connection_id, expires_at);
CREATE TABLE IF NOT EXISTS operator_inventory_requests (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  connection_id UUID NOT NULL REFERENCES operator_connections(id) ON DELETE CASCADE,
  request_id UUID NOT NULL,
  plan_id UUID NOT NULL,
  plan_hash TEXT NOT NULL CHECK (plan_hash ~ '^[a-f0-9]{64}$'),
  result JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (connection_id, request_id),
  UNIQUE (plan_id),
  FOREIGN KEY (workspace_id, plan_id) REFERENCES operator_inventory_plans(workspace_id, id)
);
