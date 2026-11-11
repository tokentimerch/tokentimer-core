-- Explicit authorization is separate from certificate observation.
CREATE TABLE certops_windows_store_renewal_owners (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  managed_certificate_id UUID NOT NULL,
  management_period_id UUID NOT NULL,
  agent_id UUID NOT NULL,
  store_name TEXT NOT NULL CHECK (store_name = 'My'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (workspace_id, id, agent_id),
  UNIQUE (workspace_id, managed_certificate_id, management_period_id),
  FOREIGN KEY (workspace_id, managed_certificate_id, management_period_id)
    REFERENCES certops_management_periods(workspace_id, managed_certificate_id, id),
  FOREIGN KEY (workspace_id, agent_id) REFERENCES certops_agents(workspace_id, id)
);

CREATE TABLE certops_windows_iis_renewal_consumers (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL,
  owner_id UUID NOT NULL,
  agent_id UUID NOT NULL,
  target_id UUID NOT NULL,
  selector_key TEXT NOT NULL CHECK (length(selector_key) BETWEEN 1 AND 300),
  automatic_update BOOLEAN NOT NULL DEFAULT FALSE,
  authorization_revision BIGINT NOT NULL DEFAULT 1 CHECK (authorization_revision BETWEEN 1 AND 9007199254740991),
  authorized_by INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
  authorized_at TIMESTAMPTZ NULL,
  removed_at TIMESTAMPTZ NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY (workspace_id, owner_id, agent_id)
    REFERENCES certops_windows_store_renewal_owners(workspace_id, id, agent_id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, target_id) REFERENCES certificate_targets(workspace_id, id) ON DELETE CASCADE,
  CHECK (NOT automatic_update OR authorized_at IS NOT NULL)
);
CREATE UNIQUE INDEX uq_windows_renewal_consumer_live_selector
  ON certops_windows_iis_renewal_consumers(workspace_id, agent_id, selector_key)
  WHERE removed_at IS NULL;
