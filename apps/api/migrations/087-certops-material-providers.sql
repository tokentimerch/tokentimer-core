-- Additive public references only. Preserve KV v2's integer column and wire
-- type; Azure versions are opaque identifiers, never coerced to a revision.
ALTER TABLE certops_distribution_groups ADD COLUMN material_store_provider TEXT NOT NULL
  DEFAULT 'vault-kv2' CHECK (material_store_provider IN ('vault-kv2','openbao-kv2','azure-key-vault'));
ALTER TABLE certops_material_versions ADD COLUMN provider_version_ref TEXT
  CHECK (provider_version_ref ~ '^[a-f0-9]{32}$');
ALTER TABLE certops_material_versions DROP CONSTRAINT certops_material_versions_check;
ALTER TABLE certops_material_versions ADD CONSTRAINT certops_material_published_reference CHECK (
  state <> 'published' OR (certificate_identity_id IS NOT NULL AND
    (provider_version IS NOT NULL OR provider_version_ref IS NOT NULL) AND
    fingerprint_sha256 IS NOT NULL AND valid_to IS NOT NULL AND
    publishing_claim_id IS NOT NULL AND published_at IS NOT NULL));
ALTER TABLE certops_material_versions ADD CONSTRAINT certops_material_single_version_type
  CHECK (provider_version IS NULL OR provider_version_ref IS NULL);

CREATE FUNCTION certops_material_provider_version_guard() RETURNS trigger AS $$
DECLARE provider TEXT;
BEGIN
  SELECT material_store_provider INTO provider FROM certops_distribution_groups
    WHERE workspace_id=NEW.workspace_id AND id=NEW.group_id;
  IF (NEW.provider_version_ref IS NOT NULL AND provider <> 'azure-key-vault') OR
     (NEW.provider_version IS NOT NULL AND provider = 'azure-key-vault') THEN
    RAISE EXCEPTION 'Material provider version type mismatch';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER trg_certops_material_provider_version_guard BEFORE INSERT OR UPDATE ON certops_material_versions
  FOR EACH ROW EXECUTE FUNCTION certops_material_provider_version_guard();
