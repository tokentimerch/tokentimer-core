-- A directory remap or workspace deletion cannot release a physical writer.
-- Duplicate preexisting holds require explicit reconciliation before upgrade.
ALTER TABLE certops_deployment_destination_operations
  ADD CONSTRAINT certops_destination_mutation_domain_unique UNIQUE (mutation_domain_sha256),
  DROP CONSTRAINT certops_deployment_destination_operations_workspace_id_fkey;
