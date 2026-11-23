"use strict";

const MIGRATION_V1_SQL = `
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE sso_providers (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  slug TEXT NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9_-]{0,62}$'),
  type TEXT NOT NULL CHECK (type IN ('oidc','saml')),
  display_name TEXT NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  sort_order INT NOT NULL DEFAULT 100 CHECK (sort_order BETWEEN 1 AND 1000),
  config JSONB NOT NULL DEFAULT '{}'::jsonb,
  claim_mapping JSONB NOT NULL DEFAULT '{}'::jsonb,
  security JSONB NOT NULL DEFAULT '{}'::jsonb,
  locked_fields JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ
);
CREATE INDEX idx_sso_providers_enabled_sort ON sso_providers (enabled, sort_order, display_name);

CREATE TABLE sso_provider_secrets (
  provider_id UUID NOT NULL REFERENCES sso_providers(id) ON DELETE CASCADE,
  secret_name TEXT NOT NULL,
  encrypted_value JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ,
  updated_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  PRIMARY KEY (provider_id, secret_name)
);
CREATE INDEX idx_sso_provider_secrets_provider ON sso_provider_secrets (provider_id);

CREATE TABLE external_identities (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider_slug TEXT NOT NULL REFERENCES sso_providers(slug) ON DELETE CASCADE,
  protocol TEXT NOT NULL CHECK (protocol IN ('oidc','saml')),
  subject_id TEXT NOT NULL,
  email_at_link TEXT, display_name_at_link TEXT,
  linked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at TIMESTAMPTZ,
  UNIQUE (provider_slug, subject_id)
);
CREATE INDEX idx_external_identities_user ON external_identities (user_id);
CREATE INDEX idx_external_identities_provider ON external_identities (provider_slug);

CREATE TABLE sso_group_role_mappings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  provider_slug TEXT NOT NULL REFERENCES sso_providers(slug) ON DELETE CASCADE,
  idp_group TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin','workspace_manager','viewer')),
  workspace_id UUID REFERENCES workspaces(id) ON DELETE CASCADE,
  priority INT NOT NULL DEFAULT 100 CHECK (priority BETWEEN 1 AND 1000),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  updated_at TIMESTAMPTZ,
  CHECK (role <> 'admin' OR workspace_id IS NULL)
);

CREATE UNIQUE INDEX uniq_sso_group_mapping ON sso_group_role_mappings (
  provider_slug,
  lower(idp_group),
  role,
  COALESCE(workspace_id, '00000000-0000-0000-0000-000000000000'::uuid)
);
CREATE INDEX idx_sso_group_mappings_provider_priority ON sso_group_role_mappings (provider_slug, priority);

CREATE TABLE saml_request_cache (
  provider_slug TEXT NOT NULL,
  cache_key TEXT NOT NULL,
  cache_value TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (provider_slug, cache_key)
);
CREATE INDEX idx_saml_request_cache_created ON saml_request_cache (created_at);

CREATE TABLE sso_deleted_external_identities_archive (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  provider_slug TEXT NOT NULL,
  provider_id UUID,
  original_identity_id UUID,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  subject_id TEXT NOT NULL,
  protocol TEXT NOT NULL CHECK (protocol IN ('oidc','saml')),
  email_at_link TEXT,
  display_name_at_link TEXT,
  linked_at TIMESTAMPTZ,
  deleted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  deleted_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  delete_reason TEXT NOT NULL DEFAULT 'provider_force_delete'
);
CREATE INDEX idx_sso_deleted_identities_provider ON sso_deleted_external_identities_archive (provider_slug, deleted_at);

ALTER TABLE workspace_memberships
  ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'manual'
    CHECK (source IN ('manual', 'sso')),
  ADD COLUMN IF NOT EXISTS source_provider_slug TEXT
    REFERENCES sso_providers(slug) ON DELETE RESTRICT;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'workspace_memberships_source_provider_check'
       AND conrelid = 'workspace_memberships'::regclass
  ) THEN
    ALTER TABLE workspace_memberships
      ADD CONSTRAINT workspace_memberships_source_provider_check
      CHECK (
        (source = 'manual' AND source_provider_slug IS NULL)
        OR
        (source = 'sso' AND source_provider_slug IS NOT NULL)
      );
  END IF;
END$$;

CREATE INDEX IF NOT EXISTS idx_workspace_memberships_sso_source
  ON workspace_memberships (source, source_provider_slug);

ALTER TABLE system_settings ADD COLUMN IF NOT EXISTS sso_config_version BIGINT NOT NULL DEFAULT 1;

CREATE OR REPLACE FUNCTION prevent_sso_provider_immutable_update() RETURNS trigger AS $$
BEGIN
  IF NEW.slug <> OLD.slug THEN
    RAISE EXCEPTION 'sso_providers.slug is immutable';
  END IF;
  IF NEW.type <> OLD.type THEN
    RAISE EXCEPTION 'sso_providers.type is immutable';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_prevent_sso_provider_immutable_update ON sso_providers;
CREATE TRIGGER trg_prevent_sso_provider_immutable_update
  BEFORE UPDATE ON sso_providers
  FOR EACH ROW EXECUTE FUNCTION prevent_sso_provider_immutable_update();

CREATE OR REPLACE FUNCTION enforce_external_identity_protocol() RETURNS trigger AS $$
DECLARE expected TEXT;
BEGIN
  SELECT type INTO expected FROM sso_providers WHERE slug = NEW.provider_slug;
  IF expected IS NULL THEN
    RAISE EXCEPTION 'unknown provider_slug % in external_identities', NEW.provider_slug;
  END IF;
  IF NEW.protocol <> expected THEN
    RAISE EXCEPTION 'external_identities.protocol (%) must match sso_providers.type (%)', NEW.protocol, expected;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_enforce_external_identity_protocol ON external_identities;
CREATE TRIGGER trg_enforce_external_identity_protocol
  BEFORE INSERT OR UPDATE ON external_identities
  FOR EACH ROW EXECUTE FUNCTION enforce_external_identity_protocol();

-- SSO-created users need auth_method in ('saml','oidc','sso') with SSO_NO_PASSWORD sentinel.
-- Drop pre-enterprise users.auth_method CHECK constraints (name discovered dynamically; not SSO columns).
DO $$
DECLARE
  legacy_check_name TEXT;
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'check_auth_requirements'
       AND conrelid = 'users'::regclass
  ) THEN
    ALTER TABLE users DROP CONSTRAINT check_auth_requirements;
  END IF;

  SELECT c.conname
    INTO legacy_check_name
    FROM pg_constraint c
    JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY(c.conkey)
   WHERE c.conrelid = 'users'::regclass
     AND a.attname = 'auth_method'
     AND c.contype = 'c'
     AND pg_get_constraintdef(c.oid) ILIKE '%auth_method%local%'
     AND pg_get_constraintdef(c.oid) NOT ILIKE '%saml%'
   LIMIT 1;
  IF legacy_check_name IS NOT NULL THEN
    EXECUTE 'ALTER TABLE users DROP CONSTRAINT ' || quote_ident(legacy_check_name);
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'users_auth_method_enterprise_check'
       AND conrelid = 'users'::regclass
  ) THEN
    ALTER TABLE users
      ADD CONSTRAINT users_auth_method_enterprise_check
      CHECK (auth_method IN ('local','saml','oidc','sso'));
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'users_auth_requirements_enterprise'
       AND conrelid = 'users'::regclass
  ) THEN
    ALTER TABLE users
      ADD CONSTRAINT users_auth_requirements_enterprise
      CHECK (
        (auth_method = 'local' AND password_hash IS NOT NULL)
        OR (auth_method IN ('saml','oidc','sso'))
      );
  END IF;
END$$;
`;

const MIGRATION_V2_SQL = `
CREATE TABLE IF NOT EXISTS sso_system_admin_grants (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider_slug TEXT NOT NULL REFERENCES sso_providers(slug) ON DELETE CASCADE,
  granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (user_id, provider_slug)
);

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS is_admin_manual BOOLEAN NOT NULL DEFAULT FALSE;

-- Local/bootstrap admins stay manual-only and are never auto-demoted by SSO sync.
UPDATE users
   SET is_admin_manual = TRUE
 WHERE is_admin = TRUE
   AND auth_method = 'local';

-- Seed provider grants for existing SSO admins so demotion tracks per provider.
INSERT INTO sso_system_admin_grants (user_id, provider_slug)
SELECT u.id, ei.provider_slug
  FROM users u
  JOIN external_identities ei ON ei.user_id = u.id
 WHERE u.is_admin = TRUE
   AND u.auth_method IN ('sso', 'oidc', 'saml')
ON CONFLICT (user_id, provider_slug) DO NOTHING;

-- Remaining SSO admins without linked identities stay manual until next login.
UPDATE users
   SET is_admin_manual = TRUE
 WHERE is_admin = TRUE
   AND is_admin_manual = FALSE
   AND auth_method IN ('sso', 'oidc', 'saml')
   AND NOT EXISTS (
     SELECT 1 FROM sso_system_admin_grants g WHERE g.user_id = users.id
   );
`;

const MIGRATION_V3_SQL = `
ALTER TABLE system_settings
  ADD COLUMN IF NOT EXISTS sso_global_settings JSONB NOT NULL DEFAULT '{}'::jsonb;
`;

const SHARED_SSO_MIGRATION_NAME = "shared_sso_schema";

// Reject unrecognized ledger identities even when some objects happen to match.
const LEGACY_LEDGER_CHECK_SQL = `
DO $sso_history$
DECLARE versions integer[];
BEGIN
  IF to_regclass('enterprise_migrations') IS NULL THEN RETURN; END IF;
  SELECT array_agg(version ORDER BY version) INTO versions FROM enterprise_migrations WHERE version <= 3;
  IF EXISTS (SELECT 1 FROM enterprise_migrations WHERE
       version < 1
       OR (version = 1 AND name <> 'multi_provider_sso_v1')
       OR (version = 2 AND name <> 'sso_system_admin_grants_v2')
       OR (version = 3 AND name <> 'sso_global_settings_v3'))
     OR (versions IS NOT NULL AND versions NOT IN (ARRAY[1], ARRAY[1,2], ARRAY[1,2,3]))
     OR (versions IS DISTINCT FROM ARRAY[1,2,3] AND EXISTS (SELECT 1 FROM enterprise_migrations WHERE version > 3))
  THEN
    RAISE EXCEPTION 'Unsupported Enterprise SSO migration history';
  END IF;
  IF 2 = ANY(versions) AND (
    to_regclass('sso_system_admin_grants') IS NULL OR NOT EXISTS (
      SELECT 1 FROM pg_attribute WHERE attrelid = 'users'::regclass
        AND attname = 'is_admin_manual' AND NOT attisdropped
    )
  ) THEN
    RAISE EXCEPTION 'Recorded Enterprise SSO administrator provenance is missing. Restore the database before adoption.';
  END IF;
END
$sso_history$;
`;

// A known partial installation can be completed by adding absent objects.
// Check essential columns and integrity objects before either ledger is stamped.
const VALIDATE_SHARED_SSO_SCHEMA_SQL = `
DO $sso_validate$
BEGIN
  PERFORM id, slug, type, display_name, enabled, sort_order, config, claim_mapping, security, locked_fields, created_at, updated_at FROM sso_providers LIMIT 0;
  PERFORM provider_id, secret_name, encrypted_value, created_at, updated_at, updated_by FROM sso_provider_secrets LIMIT 0;
  PERFORM id, user_id, provider_slug, protocol, subject_id, email_at_link, display_name_at_link, linked_at, last_seen_at FROM external_identities LIMIT 0;
  PERFORM id, provider_slug, idp_group, role, workspace_id, priority, created_at, created_by, updated_at FROM sso_group_role_mappings LIMIT 0;
  PERFORM provider_slug, cache_key, cache_value, created_at FROM saml_request_cache LIMIT 0;
  PERFORM id, provider_slug, provider_id, original_identity_id, user_id, subject_id, protocol, email_at_link, display_name_at_link, linked_at, deleted_at, deleted_by, delete_reason FROM sso_deleted_external_identities_archive LIMIT 0;
  PERFORM user_id, provider_slug, granted_at FROM sso_system_admin_grants LIMIT 0;
  PERFORM source, source_provider_slug FROM workspace_memberships LIMIT 0;
  PERFORM sso_config_version, sso_global_settings FROM system_settings LIMIT 0;
  PERFORM is_admin_manual FROM users LIMIT 0;
  IF EXISTS (
    SELECT 1 FROM (VALUES
      ('sso_providers'::regclass, ARRAY[
        'sso_providers_pkey',
        'sso_providers_slug_key',
        'sso_providers_slug_check',
        'sso_providers_type_check',
        'sso_providers_sort_order_check'
      ]),
      ('sso_provider_secrets'::regclass, ARRAY[
        'sso_provider_secrets_pkey',
        'sso_provider_secrets_provider_id_fkey',
        'sso_provider_secrets_updated_by_fkey'
      ]),
      ('external_identities'::regclass, ARRAY[
        'external_identities_pkey',
        'external_identities_provider_slug_fkey',
        'external_identities_user_id_fkey',
        'external_identities_protocol_check',
        'external_identities_provider_slug_subject_id_key'
      ]),
      ('sso_group_role_mappings'::regclass, ARRAY[
        'sso_group_role_mappings_pkey',
        'sso_group_role_mappings_provider_slug_fkey',
        'sso_group_role_mappings_workspace_id_fkey',
        'sso_group_role_mappings_created_by_fkey',
        'sso_group_role_mappings_role_check',
        'sso_group_role_mappings_priority_check',
        'sso_group_role_mappings_check'
      ]),
      ('saml_request_cache'::regclass, ARRAY[
        'saml_request_cache_pkey'
      ]),
      ('sso_deleted_external_identities_archive'::regclass, ARRAY[
        'sso_deleted_external_identities_archive_pkey',
        'sso_deleted_external_identities_archive_protocol_check',
        'sso_deleted_external_identities_archive_user_id_fkey',
        'sso_deleted_external_identities_archive_deleted_by_fkey'
      ]),
      ('sso_system_admin_grants'::regclass, ARRAY[
        'sso_system_admin_grants_pkey',
        'sso_system_admin_grants_provider_slug_fkey',
        'sso_system_admin_grants_user_id_fkey'
      ]),
      ('workspace_memberships'::regclass, ARRAY[
        'workspace_memberships_source_check',
        'workspace_memberships_source_provider_check',
        'workspace_memberships_source_provider_slug_fkey'
      ]),
      ('users'::regclass, ARRAY[
        'users_auth_method_enterprise_check',
        'users_auth_requirements_enterprise'
      ])
    ) AS expected(relation, names)
    CROSS JOIN LATERAL unnest(expected.names) AS required(name)
    WHERE NOT EXISTS (
      SELECT 1 FROM pg_constraint WHERE conrelid = expected.relation
        AND conname = required.name AND convalidated
    )
  )
  OR NOT EXISTS (SELECT 1 FROM pg_index WHERE indexrelid = 'uniq_sso_group_mapping'::regclass
      AND indisunique AND indisvalid)
  OR NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid = 'sso_providers'::regclass
      AND tgname = 'trg_prevent_sso_provider_immutable_update' AND tgenabled IN ('O','A'))
  OR NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid = 'external_identities'::regclass
      AND tgname = 'trg_enforce_external_identity_protocol' AND tgenabled IN ('O','A'))
  OR NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = 'external_identities'::regclass
      AND contype = 'u' AND pg_get_constraintdef(oid) = 'UNIQUE (provider_slug, subject_id)')
  THEN
    RAISE EXCEPTION 'Incomplete or incompatible shared SSO schema';
  END IF;
END
$sso_validate$;
`;

const sharedV1Sql = MIGRATION_V1_SQL
  .replace(/^CREATE TABLE /gm, "CREATE TABLE IF NOT EXISTS ")
  .replace(/^CREATE (UNIQUE )?INDEX (?!IF NOT EXISTS )/gm, "CREATE $1INDEX IF NOT EXISTS ")
  .replace(
    /^DROP TRIGGER IF EXISTS (\w+) ON (\w+);\n(CREATE TRIGGER [^;]+;)/gm,
    (_statement, name, table, create) => `
DO $sso_trigger$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid = '${table}'::regclass AND tgname = '${name}') THEN
    ${create}
  END IF;
END
$sso_trigger$;
`,
  );
const v2SeedStart = MIGRATION_V2_SQL.indexOf("-- Local/bootstrap admins");

// Preserve the original v2 grant and manual-admin decisions on adopted databases.
// The shared migration adds missing structural objects without reseeding v2 data.
const SHARED_SSO_SCHEMA_SQL = `
${LEGACY_LEDGER_CHECK_SQL}
${sharedV1Sql}
${MIGRATION_V2_SQL.slice(0, v2SeedStart)}
DO $sso_seed$
BEGIN
  IF to_regclass('enterprise_migrations') IS NOT NULL THEN
    IF EXISTS (SELECT 1 FROM enterprise_migrations WHERE version = 2) THEN RETURN; END IF;
  END IF;
${MIGRATION_V2_SQL.slice(v2SeedStart)}
END
$sso_seed$;
${MIGRATION_V3_SQL}
${VALIDATE_SHARED_SSO_SCHEMA_SQL}
`;

module.exports = {
  MIGRATION_V1_SQL,
  MIGRATION_V2_SQL,
  MIGRATION_V3_SQL,
  SHARED_SSO_MIGRATION_NAME,
  SHARED_SSO_SCHEMA_SQL,
  VALIDATE_SHARED_SSO_SCHEMA_SQL,
};
