-- Binding observations are stable across certificate rotation. A store-only
-- inventory observation never becomes an actively consuming service.
CREATE TABLE certops_discovered_consumers (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL,
  agent_id UUID NOT NULL,
  service_key TEXT NOT NULL CHECK(service_key ~ '^[a-f0-9]{64}$'),
  service_identity TEXT NOT NULL,
  source_kind TEXT NOT NULL CHECK(source_kind IN ('iis_binding','http_sys','filesystem')),
  target_host TEXT NULL,
  listener_target TEXT NULL,
  material_location TEXT NULL,
  observed_fingerprint_sha256 TEXT NOT NULL CHECK(observed_fingerprint_sha256 ~ '^[a-f0-9]{64}$'),
  certificate_identity_id UUID NULL,
  managed_certificate_id UUID NULL,
  last_observed_at TIMESTAMPTZ NOT NULL,
  relationship_state TEXT NOT NULL CHECK(relationship_state IN ('confirmed_relationship','configured_not_observed')),
  coverage TEXT NOT NULL DEFAULT 'partial' CHECK(coverage IN ('partial','unknown')),
  UNIQUE(workspace_id,agent_id,service_key),
  FOREIGN KEY(workspace_id,agent_id) REFERENCES certops_agents(workspace_id,id),
  FOREIGN KEY(workspace_id,certificate_identity_id) REFERENCES certops_certificate_identities(workspace_id,id)
);
CREATE INDEX idx_certops_discovered_consumer_material ON certops_discovered_consumers(workspace_id,observed_fingerprint_sha256);
