const { Pool } = require("pg");
const fs = require("fs");
const { logger } = require("../utils/logger");

const caPath = process.env.PGSSLROOTCERT;
const sslMode = process.env.DB_SSL;
const hasCA = !!caPath;
const isProduction = process.env.NODE_ENV === "production";

// SSL semantics mirrored from apps/api/db/database.js so migrations don't
// silently skip server-identity verification when the main API enforces it.
const sslConfig =
  sslMode === "verify" || hasCA
    ? {
        ca: hasCA ? fs.readFileSync(caPath, "utf8") : undefined,
        rejectUnauthorized: true,
        minVersion: "TLSv1.3",
      }
    : sslMode === "require"
      ? { rejectUnauthorized: isProduction, minVersion: "TLSv1.3" }
      : sslMode === "require-no-verify"
        ? { rejectUnauthorized: false, minVersion: "TLSv1.3" }
        : false;

// Reusable pool for migrations
const migrationPool = new Pool({
  host: process.env.DB_HOST || "localhost",
  database: process.env.DB_NAME || "tokentimer",
  user: process.env.DB_USER || "tokentimer",
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT || 5432,
  ssl: sslConfig,
  max: 5,
  idleTimeoutMillis: 30000,
});

// Wait for database to be ready
async function waitForDatabase(maxRetries = 30, delay = 2000) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      logger.info(`Database connection attempt ${i + 1}/${maxRetries}`);
      const client = await migrationPool.connect();
      await client.query("SELECT 1");
      client.release();
      logger.info("Database is ready!");
      return true;
    } catch (_error) {
      if (i < maxRetries - 1) {
        logger.info(`Database not ready, retrying in ${delay}ms...`);
        await new Promise((resolve) => setTimeout(resolve, delay));
      }
    }
  }
  return false;
}

// Consolidated migrations for tokentimer-core (squashed from 37 incremental migrations)
const migrations = [
  {
    version: 1,
    name: "core_schema",
    sql: `
      -- USERS
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        email_original TEXT,
        display_name VARCHAR(255) NOT NULL,
        password_hash TEXT,
        auth_method VARCHAR(20) NOT NULL DEFAULT 'local' CHECK (auth_method IN ('local')),
        photo TEXT,
        access_token TEXT,
        refresh_token TEXT,
        token_expiry BIGINT,
        email_verified BOOLEAN DEFAULT FALSE,
        verification_token VARCHAR(255),
        verification_token_expires TIMESTAMP,
        reset_token VARCHAR(255),
        reset_token_expires TIMESTAMP,
        first_name VARCHAR(100) NULL,
        last_name VARCHAR(100) NULL,
        two_factor_enabled BOOLEAN NOT NULL DEFAULT FALSE,
        two_factor_secret TEXT NULL,
        is_admin BOOLEAN NOT NULL DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW(),
        CONSTRAINT check_auth_requirements CHECK (
          auth_method = 'local' AND password_hash IS NOT NULL
        )
      );

      CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
      CREATE INDEX IF NOT EXISTS idx_users_verification_token ON users(verification_token);
      CREATE INDEX IF NOT EXISTS idx_users_reset_token ON users(reset_token);
      CREATE INDEX IF NOT EXISTS idx_users_first_name ON users(first_name);
      CREATE INDEX IF NOT EXISTS idx_users_last_name ON users(last_name);

      -- TOKENS
      CREATE TABLE IF NOT EXISTS tokens (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        workspace_id UUID NOT NULL,
        created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
        name VARCHAR(100) NOT NULL CHECK (length(name) >= 3),
        expiration DATE NOT NULL,
        type VARCHAR(50) NOT NULL CHECK (type IN (
          'ssl_cert','tls_cert','code_signing','client_cert','api_key','secret','password','encryption_key','ssh_key','software_license','service_subscription','domain_registration','other','document','membership'
        )),
        category VARCHAR(50) NOT NULL DEFAULT 'general' CHECK (category IN ('cert','key_secret','license','general')),
        domains TEXT[],
        location VARCHAR(500),
        used_by VARCHAR(500),
        issuer VARCHAR(255),
        serial_number VARCHAR(255),
        subject TEXT,
        key_size INTEGER CHECK (key_size IS NULL OR key_size > 0),
        algorithm VARCHAR(100),
        license_type VARCHAR(100),
        vendor VARCHAR(255),
        cost DECIMAL(15,2) CHECK (cost IS NULL OR (cost >= 0 AND cost < 1000000000000)),
        renewal_url VARCHAR(500),
        renewal_date DATE,
        contacts VARCHAR(500),
        description TEXT,
        notes TEXT,
        section TEXT[],
        contact_group_id TEXT NULL,
        privileges TEXT NULL,
        imported_at TIMESTAMP NULL,
        last_used TIMESTAMP NULL,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );

      CREATE INDEX IF NOT EXISTS idx_tokens_user_id ON tokens(user_id);
      CREATE INDEX IF NOT EXISTS idx_tokens_workspace_id ON tokens(workspace_id);
      CREATE INDEX IF NOT EXISTS idx_tokens_expiration ON tokens(expiration);
      CREATE INDEX IF NOT EXISTS idx_tokens_category ON tokens(category);
      CREATE INDEX IF NOT EXISTS idx_tokens_domains ON tokens USING GIN(domains);
      CREATE INDEX IF NOT EXISTS idx_tokens_location ON tokens(location);
      CREATE INDEX IF NOT EXISTS idx_tokens_used_by ON tokens(used_by);
      CREATE INDEX IF NOT EXISTS idx_tokens_issuer ON tokens(issuer);
      CREATE INDEX IF NOT EXISTS idx_tokens_subject ON tokens USING GIN(to_tsvector('english', description));
      CREATE INDEX IF NOT EXISTS idx_tokens_vendor ON tokens(vendor);
      CREATE INDEX IF NOT EXISTS idx_tokens_renewal_date ON tokens(renewal_date);
      CREATE INDEX IF NOT EXISTS idx_tokens_contacts ON tokens(contacts);
      CREATE INDEX IF NOT EXISTS idx_tokens_user_expiration ON tokens(user_id, expiration);
      CREATE INDEX IF NOT EXISTS idx_tokens_user_created_at ON tokens(user_id, created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_tokens_user_lower_name ON tokens(user_id, LOWER(name));
      CREATE INDEX IF NOT EXISTS idx_tokens_workspace_section ON tokens(workspace_id, section);
      CREATE INDEX IF NOT EXISTS idx_tokens_contact_group_id ON tokens(contact_group_id);
      CREATE INDEX IF NOT EXISTS idx_tokens_last_used ON tokens(last_used);
      CREATE INDEX IF NOT EXISTS idx_tokens_imported_at ON tokens(imported_at);
      CREATE INDEX IF NOT EXISTS idx_tokens_section_gin ON tokens USING GIN(section);

      -- SESSION
      CREATE TABLE IF NOT EXISTS session (
        sid VARCHAR NOT NULL COLLATE "default",
        sess JSON NOT NULL,
        expire TIMESTAMP(6) NOT NULL
      );
      DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1
          FROM pg_constraint
          WHERE conrelid = 'session'::regclass
            AND contype = 'p'
        ) THEN
          ALTER TABLE session ADD CONSTRAINT session_pkey PRIMARY KEY (sid);
        END IF;
      END
      $$;
      CREATE INDEX IF NOT EXISTS IDX_session_expire ON session(expire);
    `,
  },
  {
    version: 2,
    name: "workspaces_and_rbac",
    sql: `
      -- WORKSPACES
      CREATE TABLE IF NOT EXISTS workspaces (
        id UUID PRIMARY KEY,
        name TEXT NOT NULL,
        plan TEXT NOT NULL DEFAULT 'oss',
        created_by INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
        is_personal_default BOOLEAN NOT NULL DEFAULT FALSE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE INDEX IF NOT EXISTS idx_workspaces_is_personal_default ON workspaces(is_personal_default);

      -- MEMBERSHIPS & ROLES
      CREATE TABLE IF NOT EXISTS workspace_memberships (
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
        role TEXT NOT NULL CHECK (role IN ('admin','workspace_manager','viewer')),
        invited_by INTEGER,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        PRIMARY KEY (user_id, workspace_id)
      );

      CREATE UNIQUE INDEX IF NOT EXISTS uq_one_admin_per_workspace
        ON workspace_memberships (workspace_id)
        WHERE role = 'admin';

      -- WORKSPACE INVITATIONS
      CREATE TABLE IF NOT EXISTS workspace_invitations (
        id UUID PRIMARY KEY,
        workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
        email TEXT NOT NULL,
        role TEXT NOT NULL CHECK (role IN ('admin','workspace_manager','viewer')),
        invited_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
        token TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        accepted_at TIMESTAMPTZ NULL,
        UNIQUE (workspace_id, email)
      );
      CREATE INDEX IF NOT EXISTS idx_workspace_invitations_email ON workspace_invitations(LOWER(email));
      CREATE INDEX IF NOT EXISTS idx_workspace_invitations_ws ON workspace_invitations(workspace_id);

      -- WORKSPACE SETTINGS
      CREATE TABLE IF NOT EXISTS workspace_settings (
        workspace_id UUID PRIMARY KEY REFERENCES workspaces(id) ON DELETE CASCADE,
        alert_thresholds JSONB DEFAULT '[30,14,7,1,0]'::jsonb,
        webhook_urls JSONB DEFAULT '[]'::jsonb,
        email_alerts_enabled BOOLEAN NOT NULL DEFAULT TRUE,
        slack_alerts_enabled BOOLEAN NOT NULL DEFAULT FALSE,
        webhooks_alerts_enabled BOOLEAN NOT NULL DEFAULT FALSE,
        whatsapp_alerts_enabled BOOLEAN NOT NULL DEFAULT FALSE,
        contact_groups JSONB NOT NULL DEFAULT '[]'::jsonb,
        default_contact_group_id TEXT NULL,
        delivery_window_start TEXT NULL,
        delivery_window_end TEXT NULL,
        delivery_window_tz TEXT NULL,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_by INTEGER NULL REFERENCES users(id) ON DELETE SET NULL
      );

      CREATE INDEX IF NOT EXISTS idx_ws_delivery_window ON workspace_settings(delivery_window_start, delivery_window_end);

      -- Add workspace FK to tokens (idempotent)
      DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1
          FROM pg_constraint
          WHERE conname = 'tokens_workspace_id_fkey'
        ) THEN
          ALTER TABLE tokens ADD CONSTRAINT tokens_workspace_id_fkey
            FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE;
        END IF;
      END
      $$;
    `,
  },
  {
    version: 3,
    name: "audit_schema",
    sql: `
      CREATE TABLE IF NOT EXISTS audit_events (
        id SERIAL PRIMARY KEY,
        occurred_at TIMESTAMP NOT NULL DEFAULT NOW(),
        actor_user_id INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
        subject_user_id INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
        action VARCHAR(64) NOT NULL,
        target_type VARCHAR(64),
        target_id INTEGER,
        channel VARCHAR(16),
        workspace_id UUID NULL REFERENCES workspaces(id) ON DELETE SET NULL,
        metadata JSONB NOT NULL DEFAULT '{}'::jsonb
      );
      CREATE INDEX IF NOT EXISTS idx_audit_events_subject_time ON audit_events(subject_user_id, occurred_at DESC);
      CREATE INDEX IF NOT EXISTS idx_audit_events_action ON audit_events(action);
      CREATE INDEX IF NOT EXISTS idx_audit_events_workspace_time ON audit_events(workspace_id, occurred_at DESC);

      -- Audit immutability guard
      CREATE OR REPLACE FUNCTION audit_events_update_guard() RETURNS trigger AS $$
      BEGIN
        IF (
          (NEW.actor_user_id IS NULL AND OLD.actor_user_id IS NOT NULL)
          OR (NEW.subject_user_id IS NULL AND OLD.subject_user_id IS NOT NULL)
          OR (NEW.workspace_id IS NULL AND OLD.workspace_id IS NOT NULL)
        )
        AND NEW.subject_user_id IS NOT DISTINCT FROM OLD.subject_user_id
        AND NEW.action IS NOT DISTINCT FROM OLD.action
        AND NEW.target_type IS NOT DISTINCT FROM OLD.target_type
        AND NEW.target_id IS NOT DISTINCT FROM OLD.target_id
        AND NEW.channel IS NOT DISTINCT FROM OLD.channel
        AND NEW.metadata IS NOT DISTINCT FROM OLD.metadata
        AND NEW.occurred_at IS NOT DISTINCT FROM OLD.occurred_at THEN
          RETURN NEW;
        END IF;
        RAISE EXCEPTION 'audit_events are immutable (update denied)';
      END;
      $$ LANGUAGE plpgsql;

      CREATE TRIGGER audit_events_immutable_update
      BEFORE UPDATE ON audit_events
      FOR EACH ROW
      EXECUTE FUNCTION audit_events_update_guard();
    `,
  },
  {
    version: 4,
    name: "alerting_schema",
    sql: `
      CREATE TABLE IF NOT EXISTS alert_queue (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token_id INTEGER NOT NULL REFERENCES tokens(id) ON DELETE CASCADE,
        alert_key TEXT NOT NULL,
        threshold_days INTEGER NOT NULL,
        due_date DATE NOT NULL,
        channels JSONB NOT NULL DEFAULT '[]'::jsonb,
        status VARCHAR(20) NOT NULL DEFAULT 'pending'
          CHECK (status IN ('pending', 'sent', 'failed', 'blocked', 'limit_exceeded', 'partial')),
        attempts INTEGER NOT NULL DEFAULT 0,
        attempts_email INTEGER NOT NULL DEFAULT 0,
        attempts_webhooks INTEGER NOT NULL DEFAULT 0,
        attempts_whatsapp INTEGER NOT NULL DEFAULT 0,
        last_attempt TIMESTAMP NULL,
        next_attempt_at TIMESTAMP NULL,
        delivery_claim_id UUID NULL,
        last_error_class TEXT NULL,
        last_error_message TEXT NULL,
        error_message TEXT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMP NOT NULL DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_alert_queue_due ON alert_queue(due_date, status);
      CREATE INDEX IF NOT EXISTS idx_alert_queue_user_status ON alert_queue(user_id, status);
      CREATE INDEX IF NOT EXISTS idx_alert_queue_next_attempt ON alert_queue(next_attempt_at);
      CREATE UNIQUE INDEX IF NOT EXISTS uq_alert_queue_key ON alert_queue(alert_key);

      CREATE TABLE IF NOT EXISTS alert_delivery_log (
        id SERIAL PRIMARY KEY,
        alert_queue_id INTEGER REFERENCES alert_queue(id) ON DELETE SET NULL,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token_id INTEGER REFERENCES tokens(id) ON DELETE SET NULL,
        channel VARCHAR(16) NOT NULL,
        status VARCHAR(20) NOT NULL CHECK (status IN ('success', 'failed', 'blocked', 'deferred')),
        workspace_id UUID NULL,
        sent_at TIMESTAMP NOT NULL DEFAULT NOW(),
        error_message TEXT NULL,
        metadata JSONB DEFAULT '{}'::jsonb
      );
      CREATE INDEX IF NOT EXISTS idx_delivery_log_user_month ON alert_delivery_log(user_id, date_trunc('month', sent_at));
      CREATE INDEX IF NOT EXISTS idx_delivery_log_user_sent_at ON alert_delivery_log(user_id, sent_at);
      CREATE INDEX IF NOT EXISTS idx_delivery_log_queue ON alert_delivery_log(alert_queue_id);
      CREATE INDEX IF NOT EXISTS idx_delivery_log_channel_status_time ON alert_delivery_log(channel, status, sent_at DESC);
      CREATE INDEX IF NOT EXISTS idx_delivery_log_workspace_month ON alert_delivery_log(workspace_id, date_trunc('month', sent_at));
    `,
  },
  {
    version: 5,
    name: "contacts_and_optin",
    sql: `
      -- Workspace contacts
      CREATE TABLE IF NOT EXISTS workspace_contacts (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
        first_name VARCHAR(100) NOT NULL,
        last_name VARCHAR(100) NOT NULL,
        phone_e164 TEXT,
        details JSONB DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_by INTEGER NULL REFERENCES users(id) ON DELETE SET NULL
      );
      CREATE INDEX IF NOT EXISTS idx_workspace_contacts_ws ON workspace_contacts(workspace_id);
      CREATE INDEX IF NOT EXISTS idx_workspace_contacts_phone ON workspace_contacts(phone_e164);
      CREATE UNIQUE INDEX IF NOT EXISTS uq_workspace_contacts_phone
        ON workspace_contacts(workspace_id, phone_e164)
        WHERE phone_e164 IS NOT NULL;
    `,
  },
  {
    version: 6,
    name: "weekly_digest_and_integration_usage",
    sql: `
      -- Weekly digest tracking
      CREATE TABLE IF NOT EXISTS weekly_digest_log (
        id SERIAL PRIMARY KEY,
        workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
        contact_group_id TEXT NOT NULL,
        week_start_date DATE NOT NULL,
        sent_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        tokens_count INTEGER NOT NULL DEFAULT 0,
        channels JSONB NOT NULL DEFAULT '[]'::jsonb,
        metadata JSONB DEFAULT '{}'::jsonb
      );
      CREATE INDEX IF NOT EXISTS idx_weekly_digest_log_workspace ON weekly_digest_log(workspace_id);
      CREATE INDEX IF NOT EXISTS idx_weekly_digest_log_week ON weekly_digest_log(week_start_date);
      CREATE UNIQUE INDEX IF NOT EXISTS uq_weekly_digest_workspace_group_week
        ON weekly_digest_log(workspace_id, contact_group_id, week_start_date);

      -- Integration scan usage per workspace
      CREATE TABLE IF NOT EXISTS workspace_integration_usage (
        workspace_id UUID PRIMARY KEY REFERENCES workspaces(id) ON DELETE CASCADE,
        scans_this_month INTEGER NOT NULL DEFAULT 0 CHECK (scans_this_month >= 0),
        month_start DATE NOT NULL DEFAULT date_trunc('month', NOW())::date,
        updated_at TIMESTAMP NOT NULL DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_workspace_integration_usage_month
        ON workspace_integration_usage(month_start);

      -- Function to atomically check and increment usage
      CREATE OR REPLACE FUNCTION check_and_increment_integration_usage(
        p_workspace_id UUID,
        p_limit INTEGER
      ) RETURNS INTEGER AS $$
      DECLARE
        v_current_month DATE := date_trunc('month', NOW())::date;
        v_current_count INTEGER;
      BEGIN
        PERFORM pg_advisory_xact_lock(hashtext('integration_usage_' || p_workspace_id::text));
        INSERT INTO workspace_integration_usage (workspace_id, scans_this_month, month_start, updated_at)
        VALUES (p_workspace_id, 0, v_current_month, NOW())
        ON CONFLICT (workspace_id) DO UPDATE
        SET
          scans_this_month = CASE
            WHEN workspace_integration_usage.month_start < v_current_month THEN 0
            ELSE workspace_integration_usage.scans_this_month
          END,
          month_start = v_current_month,
          updated_at = NOW();

        UPDATE workspace_integration_usage
        SET scans_this_month = scans_this_month + 1, updated_at = NOW()
        WHERE workspace_id = p_workspace_id;

        SELECT scans_this_month INTO v_current_count
        FROM workspace_integration_usage
        WHERE workspace_id = p_workspace_id;

        IF p_limit IS NOT NULL AND p_limit > 0 AND v_current_count > p_limit THEN
          UPDATE workspace_integration_usage
          SET scans_this_month = scans_this_month - 1, updated_at = NOW()
          WHERE workspace_id = p_workspace_id;
          RETURN 1;
        END IF;
        RETURN 0;
      EXCEPTION
        WHEN OTHERS THEN RETURN -1;
      END;
      $$ LANGUAGE plpgsql;

      CREATE OR REPLACE FUNCTION get_integration_usage(p_workspace_id UUID)
      RETURNS TABLE(used INTEGER, month_start DATE) AS $$
      DECLARE
        v_current_month DATE := date_trunc('month', NOW())::date;
      BEGIN
        RETURN QUERY
        SELECT
          CASE
            WHEN wiu.month_start < v_current_month THEN 0
            ELSE wiu.scans_this_month
          END AS used,
          v_current_month AS month_start
        FROM workspace_integration_usage wiu
        WHERE wiu.workspace_id = p_workspace_id;
        IF NOT FOUND THEN
          RETURN QUERY SELECT 0 AS used, v_current_month AS month_start;
        END IF;
      END;
      $$ LANGUAGE plpgsql;
    `,
  },
  {
    version: 7,
    name: "system_settings",
    sql: `
      -- Global system settings (single row) for admin-configurable SMTP and Twilio
      CREATE TABLE IF NOT EXISTS system_settings (
        id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
        -- SMTP
        smtp_host TEXT,
        smtp_port TEXT,
        smtp_user TEXT,
        smtp_pass_encrypted TEXT,
        smtp_from_email TEXT,
        smtp_from_name TEXT,
        smtp_secure TEXT,
        smtp_require_tls TEXT,
        -- Twilio WhatsApp
        twilio_account_sid TEXT,
        twilio_auth_token_encrypted TEXT,
        twilio_whatsapp_from TEXT,
        twilio_whatsapp_test_content_sid TEXT,
        twilio_whatsapp_alert_content_sid_expires TEXT,
        twilio_whatsapp_alert_content_sid_expired TEXT,
        twilio_whatsapp_alert_content_sid_endpoint_down TEXT,
        twilio_whatsapp_alert_content_sid_endpoint_recovered TEXT,
        twilio_whatsapp_weekly_digest_content_sid TEXT,
        -- Metadata
        updated_at TIMESTAMPTZ DEFAULT NOW(),
        updated_by INTEGER REFERENCES users(id)
      );
      INSERT INTO system_settings (id) VALUES (1) ON CONFLICT DO NOTHING;
    `,
  },
  {
    version: 8,
    name: "auto_sync_and_domain_monitors",
    sql: `
      -- Auto-sync configurations (scheduled integration scans)
      CREATE TABLE IF NOT EXISTS auto_sync_configs (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
        provider TEXT NOT NULL CHECK (provider IN ('github','gitlab','aws','azure','azure-ad','gcp','vault')),
        credentials_encrypted TEXT NOT NULL,
        scan_params JSONB DEFAULT '{}'::jsonb,
        frequency TEXT NOT NULL DEFAULT 'daily' CHECK (frequency IN ('daily','weekly','monthly')),
        schedule_time TEXT DEFAULT '09:00',
        schedule_tz TEXT DEFAULT 'UTC',
        enabled BOOLEAN NOT NULL DEFAULT TRUE,
        last_sync_at TIMESTAMPTZ NULL,
        last_sync_status TEXT NULL CHECK (last_sync_status IN ('success','failed','partial')),
        last_sync_error TEXT NULL,
        last_sync_items_count INTEGER NULL,
        next_sync_at TIMESTAMPTZ NULL,
        created_by INTEGER NOT NULL REFERENCES users(id),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (workspace_id, provider)
      );
      CREATE INDEX IF NOT EXISTS idx_auto_sync_next ON auto_sync_configs(next_sync_at) WHERE enabled = TRUE;
      CREATE INDEX IF NOT EXISTS idx_auto_sync_workspace ON auto_sync_configs(workspace_id);

      -- Endpoint monitors (SSL cert tracking + health checks)
      CREATE TABLE IF NOT EXISTS domain_monitors (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
        url TEXT NOT NULL,
        validated BOOLEAN NOT NULL DEFAULT FALSE,
        validation_token TEXT NULL,
        validated_at TIMESTAMPTZ NULL,
        ssl_issuer TEXT NULL,
        ssl_subject TEXT NULL,
        ssl_valid_from TIMESTAMPTZ NULL,
        ssl_valid_to TIMESTAMPTZ NULL,
        ssl_serial TEXT NULL,
        ssl_fingerprint TEXT NULL,
        token_id INTEGER NULL REFERENCES tokens(id) ON DELETE SET NULL,
        health_check_enabled BOOLEAN NOT NULL DEFAULT TRUE,
        last_health_check_at TIMESTAMPTZ NULL,
        check_claimed_until TIMESTAMPTZ NULL,
        check_claim_id UUID NULL,
        last_health_status TEXT NULL CHECK (last_health_status IN ('healthy','unhealthy','error','pending')),
        last_health_status_code INTEGER NULL,
        last_health_error TEXT NULL,
        last_health_response_ms INTEGER NULL,
        previous_health_status TEXT NULL,
        consecutive_failures INTEGER NOT NULL DEFAULT 0,
        alert_after_failures INTEGER NOT NULL DEFAULT 2,
        check_interval TEXT NOT NULL DEFAULT 'hourly' CHECK (check_interval IN ('1min','5min','30min','hourly','daily')),
        created_by INTEGER NOT NULL REFERENCES users(id),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_domain_monitors_workspace ON domain_monitors(workspace_id);
      CREATE INDEX IF NOT EXISTS idx_domain_monitors_token ON domain_monitors(token_id);
    `,
  },
  {
    version: 9,
    name: "tokens_workspace_expiration_index",
    sql: `
      CREATE INDEX IF NOT EXISTS idx_tokens_workspace_expiration
        ON tokens(workspace_id, expiration);
    `,
  },
  {
    version: 10,
    name: "certops_inventory_schema",
    sql: `
      -- CertOps profiles contain public/non-secret policy metadata only.
      CREATE TABLE IF NOT EXISTS certificate_profiles (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        description TEXT NULL,
        status TEXT NOT NULL DEFAULT 'active'
          CHECK (status IN ('active', 'disabled', 'archived')),
        source TEXT NOT NULL DEFAULT 'manual'
          CHECK (source IN ('manual', 'api', 'import', 'domain_checker', 'endpoint_monitor', 'integration', 'auto_sync')),
        source_ref TEXT NULL,
        issuer TEXT NULL,
        subject_template TEXT NULL,
        san_templates TEXT[] NOT NULL DEFAULT '{}',
        validity_days INTEGER NULL CHECK (validity_days IS NULL OR validity_days > 0),
        renew_before_days INTEGER NULL CHECK (renew_before_days IS NULL OR renew_before_days >= 0),
        key_mode TEXT NULL CHECK (
          key_mode IS NULL OR key_mode IN (
            'agent-local',
            'proxy-agent-local',
            'cert-manager-managed',
            'appliance-managed',
            'hsm-managed',
            'vault-managed',
            'os-store-managed',
            'external-unknown'
          )
        ),
        key_reference TEXT NULL,
        public_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_by INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        CONSTRAINT uq_certificate_profiles_workspace_id UNIQUE (workspace_id, id)
      );
      CREATE INDEX IF NOT EXISTS idx_certificate_profiles_workspace
        ON certificate_profiles(workspace_id);
      CREATE INDEX IF NOT EXISTS idx_certificate_profiles_workspace_status
        ON certificate_profiles(workspace_id, status);
      CREATE UNIQUE INDEX IF NOT EXISTS uq_certificate_profiles_workspace_name
        ON certificate_profiles(workspace_id, LOWER(name));

      -- Managed certificates are inventory identities. They store public
      -- certificate material and metadata only; never customer private keys.
      CREATE TABLE IF NOT EXISTS managed_certificates (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
        token_id INTEGER NULL REFERENCES tokens(id) ON DELETE SET NULL,
        profile_id UUID NULL,
        status TEXT NOT NULL DEFAULT 'discovered'
          CHECK (status IN ('discovered', 'active', 'renewing', 'expiring', 'expired', 'revoked', 'decommissioned')),
        source TEXT NOT NULL DEFAULT 'manual'
          CHECK (source IN ('manual', 'api', 'import', 'domain_checker', 'endpoint_monitor', 'integration', 'auto_sync')),
        source_ref TEXT NULL,
        name TEXT NULL,
        common_name TEXT NULL,
        subject_alt_names TEXT[] NOT NULL DEFAULT '{}',
        issuer TEXT NULL,
        subject TEXT NULL,
        serial_number TEXT NULL,
        certificate_pem TEXT NULL,
        fingerprint_sha256 TEXT NULL,
        spki_fingerprint_sha256 TEXT NULL,
        public_key_algorithm TEXT NULL,
        public_key_size INTEGER NULL CHECK (public_key_size IS NULL OR public_key_size > 0),
        signature_algorithm TEXT NULL,
        not_before TIMESTAMPTZ NULL,
        not_after TIMESTAMPTZ NULL,
        key_mode TEXT NULL CHECK (
          key_mode IS NULL OR key_mode IN (
            'agent-local',
            'proxy-agent-local',
            'cert-manager-managed',
            'appliance-managed',
            'hsm-managed',
            'vault-managed',
            'os-store-managed',
            'external-unknown'
          )
        ),
        key_reference TEXT NULL,
        public_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_by INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        CONSTRAINT fk_managed_certificates_profile
          FOREIGN KEY (workspace_id, profile_id)
          REFERENCES certificate_profiles(workspace_id, id)
          ON DELETE SET NULL (profile_id),
        CONSTRAINT uq_managed_certificates_workspace_id UNIQUE (workspace_id, id)
      );
      CREATE INDEX IF NOT EXISTS idx_managed_certificates_workspace
        ON managed_certificates(workspace_id);
      CREATE INDEX IF NOT EXISTS idx_managed_certificates_workspace_status
        ON managed_certificates(workspace_id, status);
      CREATE INDEX IF NOT EXISTS idx_managed_certificates_workspace_token
        ON managed_certificates(workspace_id, token_id)
        WHERE token_id IS NOT NULL;
      CREATE INDEX IF NOT EXISTS idx_managed_certificates_workspace_expiry
        ON managed_certificates(workspace_id, not_after);
      CREATE INDEX IF NOT EXISTS idx_managed_certificates_serial
        ON managed_certificates(workspace_id, serial_number)
        WHERE serial_number IS NOT NULL;
      -- Non-monitor rows (import/api/manual/...) dedupe by fingerprint.
      -- Monitor observations dedupe by (source, source_ref) so two monitors
      -- can share a fingerprint as separate inventory identities without
      -- stealing provenance.
      CREATE UNIQUE INDEX IF NOT EXISTS uq_managed_certificates_workspace_fingerprint_import
        ON managed_certificates(workspace_id, fingerprint_sha256)
        WHERE fingerprint_sha256 IS NOT NULL
          AND source NOT IN ('endpoint_monitor', 'domain_checker');
      CREATE UNIQUE INDEX IF NOT EXISTS uq_managed_certificates_workspace_source_ref
        ON managed_certificates(workspace_id, source, source_ref)
        WHERE source_ref IS NOT NULL
          AND source IN ('endpoint_monitor', 'domain_checker');
      CREATE INDEX IF NOT EXISTS idx_managed_certificates_workspace_san
        ON managed_certificates USING GIN(subject_alt_names);

      -- Certificate targets are a location abstraction (observation point or
      -- deployment destination). They may point at hosts, endpoints, appliances,
      -- or cluster references, but never hold key material.
      CREATE TABLE IF NOT EXISTS certificate_targets (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
        profile_id UUID NULL,
        domain_monitor_id UUID NULL REFERENCES domain_monitors(id) ON DELETE SET NULL,
        token_id INTEGER NULL REFERENCES tokens(id) ON DELETE SET NULL,
        name TEXT NOT NULL,
        target_type TEXT NOT NULL
          CHECK (target_type IN ('endpoint', 'domain', 'host', 'kubernetes-secret', 'load-balancer', 'cdn', 'appliance', 'hsm', 'vault', 'other')),
        status TEXT NOT NULL DEFAULT 'active'
          CHECK (status IN ('active', 'inactive', 'decommissioned', 'error')),
        source TEXT NOT NULL DEFAULT 'manual'
          CHECK (source IN ('manual', 'api', 'import', 'domain_checker', 'endpoint_monitor', 'integration', 'auto_sync')),
        source_ref TEXT NULL,
        hostname TEXT NULL,
        url TEXT NULL,
        deployment_reference TEXT NULL,
        environment TEXT NULL,
        public_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_by INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        CONSTRAINT fk_certificate_targets_profile
          FOREIGN KEY (workspace_id, profile_id)
          REFERENCES certificate_profiles(workspace_id, id)
          ON DELETE SET NULL (profile_id),
        CONSTRAINT uq_certificate_targets_workspace_id UNIQUE (workspace_id, id)
      );
      CREATE INDEX IF NOT EXISTS idx_certificate_targets_workspace
        ON certificate_targets(workspace_id);
      CREATE INDEX IF NOT EXISTS idx_certificate_targets_workspace_status
        ON certificate_targets(workspace_id, status);
      CREATE INDEX IF NOT EXISTS idx_certificate_targets_workspace_type
        ON certificate_targets(workspace_id, target_type);
      CREATE INDEX IF NOT EXISTS idx_certificate_targets_workspace_hostname
        ON certificate_targets(workspace_id, hostname)
        WHERE hostname IS NOT NULL;
      CREATE INDEX IF NOT EXISTS idx_certificate_targets_domain_monitor
        ON certificate_targets(workspace_id, domain_monitor_id)
        WHERE domain_monitor_id IS NOT NULL;

      -- Certificate instances are observed/deployed public certificate copies
      -- on a target.
      CREATE TABLE IF NOT EXISTS certificate_instances (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
        managed_certificate_id UUID NOT NULL,
        target_id UUID NOT NULL,
        domain_monitor_id UUID NULL REFERENCES domain_monitors(id) ON DELETE SET NULL,
        token_id INTEGER NULL REFERENCES tokens(id) ON DELETE SET NULL,
        status TEXT NOT NULL DEFAULT 'discovered'
          CHECK (status IN ('discovered', 'active', 'deployed', 'stale', 'drifted', 'expiring', 'expired', 'revoked', 'missing', 'decommissioned', 'error')),
        source TEXT NOT NULL DEFAULT 'manual'
          CHECK (source IN ('manual', 'api', 'import', 'domain_checker', 'endpoint_monitor', 'integration', 'auto_sync')),
        source_ref TEXT NULL,
        observed_fingerprint_sha256 TEXT NULL,
        observed_serial_number TEXT NULL,
        observed_subject TEXT NULL,
        observed_issuer TEXT NULL,
        observed_not_before TIMESTAMPTZ NULL,
        observed_not_after TIMESTAMPTZ NULL,
        deployment_reference TEXT NULL,
        observed_at TIMESTAMPTZ NULL,
        public_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_by INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        CONSTRAINT fk_certificate_instances_managed_certificate
          FOREIGN KEY (workspace_id, managed_certificate_id)
          REFERENCES managed_certificates(workspace_id, id)
          ON DELETE CASCADE,
        CONSTRAINT fk_certificate_instances_target
          FOREIGN KEY (workspace_id, target_id)
          REFERENCES certificate_targets(workspace_id, id)
          ON DELETE CASCADE
      );
      CREATE INDEX IF NOT EXISTS idx_certificate_instances_workspace
        ON certificate_instances(workspace_id);
      CREATE INDEX IF NOT EXISTS idx_certificate_instances_certificate
        ON certificate_instances(workspace_id, managed_certificate_id);
      CREATE INDEX IF NOT EXISTS idx_certificate_instances_target
        ON certificate_instances(workspace_id, target_id);
      CREATE INDEX IF NOT EXISTS idx_certificate_instances_domain_monitor
        ON certificate_instances(workspace_id, domain_monitor_id)
        WHERE domain_monitor_id IS NOT NULL;
      CREATE INDEX IF NOT EXISTS idx_certificate_instances_workspace_status
        ON certificate_instances(workspace_id, status);
      CREATE INDEX IF NOT EXISTS idx_certificate_instances_workspace_fingerprint
        ON certificate_instances(workspace_id, observed_fingerprint_sha256)
        WHERE observed_fingerprint_sha256 IS NOT NULL;
      -- A monitor keeps one managed_certificate row (stable identity by source +
      -- source_ref). Rotations are recorded as additional certificate_instances rows
      -- per distinct served fingerprint: re-observing the same fingerprint at the same
      -- target refreshes the existing row (last-seen), while a new fingerprint appends a
      -- new row (rotation history). Uniqueness therefore includes the observed fingerprint.
      CREATE UNIQUE INDEX IF NOT EXISTS uq_certificate_instances_target_cert_fingerprint
        ON certificate_instances(
          workspace_id,
          target_id,
          managed_certificate_id,
          observed_fingerprint_sha256
        );
    `,
  },
  {
    version: 11,
    name: "certops_token_lifecycle_status",
    sql: `
      ALTER TABLE tokens
        ADD COLUMN IF NOT EXISTS cert_lifecycle_status TEXT NULL;

      DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1
            FROM pg_constraint c
            JOIN pg_class t ON t.oid = c.conrelid
            JOIN pg_namespace n ON n.oid = t.relnamespace
           WHERE c.conname = 'tokens_cert_lifecycle_status_check'
             AND t.relname = 'tokens'
             AND n.nspname = current_schema()
        ) THEN
          ALTER TABLE tokens
            ADD CONSTRAINT tokens_cert_lifecycle_status_check
            CHECK (
              cert_lifecycle_status IS NULL OR
              cert_lifecycle_status IN (
                'discovered',
                'active',
                'renewing',
                'expiring',
                'expired',
                'revoked',
                'decommissioned'
              )
            );
        END IF;
      END $$;

      CREATE INDEX IF NOT EXISTS idx_tokens_workspace_cert_lifecycle_status
        ON tokens(workspace_id, cert_lifecycle_status)
        WHERE cert_lifecycle_status IS NOT NULL;
    `,
  },
  {
    version: 12,
    name: "certops_api_tokens_schema",
    sql: `
      -- CertOps API tokens store lookup metadata only. The raw plaintext token
      -- is returned once by the service and is never persisted.
      CREATE TABLE IF NOT EXISTS api_tokens (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
        name TEXT NOT NULL CHECK (char_length(btrim(name)) BETWEEN 1 AND 128),
        token_prefix TEXT NOT NULL
          CHECK (token_prefix ~ '^ttx_[a-f0-9]{16}$'),
        token_hash TEXT NOT NULL CHECK (token_hash ~ '^[a-f0-9]{64}$'),
        scopes TEXT[] NOT NULL DEFAULT '{}',
        CONSTRAINT api_tokens_scopes_check CHECK (
            COALESCE(array_length(scopes, 1), 0) BETWEEN 1 AND 8 AND
            scopes <@ ARRAY[
              'certops:read',
              'certops:events:write',
              'certops:jobs:read',
              'certops:evidence:write'
            ]::text[]
        ),
        status TEXT NOT NULL DEFAULT 'active'
          CHECK (status IN ('active', 'revoked')),
        expires_at TIMESTAMPTZ NULL,
        last_used_at TIMESTAMPTZ NULL,
        revoked_at TIMESTAMPTZ NULL,
        revoked_by INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
        created_by INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        CONSTRAINT uq_api_tokens_workspace_id UNIQUE (workspace_id, id)
      );

      CREATE UNIQUE INDEX IF NOT EXISTS uq_api_tokens_token_prefix
        ON api_tokens(token_prefix);
      CREATE UNIQUE INDEX IF NOT EXISTS uq_api_tokens_token_hash
        ON api_tokens(token_hash);
      CREATE INDEX IF NOT EXISTS idx_api_tokens_workspace
        ON api_tokens(workspace_id);
      CREATE INDEX IF NOT EXISTS idx_api_tokens_workspace_status
        ON api_tokens(workspace_id, status);
      CREATE INDEX IF NOT EXISTS idx_api_tokens_status_expires
        ON api_tokens(status, expires_at)
        WHERE status = 'active';
      CREATE INDEX IF NOT EXISTS idx_api_tokens_created_by
        ON api_tokens(workspace_id, created_by)
        WHERE created_by IS NOT NULL;
    `,
  },
  {
    version: 13,
    name: "certops_jobs_evidence_schema",
    sql: `
      -- CertOps jobs persist public lifecycle intent and status only. Payloads
      -- and metadata are sanitized by services before persistence; no private
      -- key material, credentials, PEM blobs, PFX/JKS bundles, or passwords are
      -- accepted into these tables.
      CREATE TABLE IF NOT EXISTS certificate_jobs (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
        operation TEXT NOT NULL
          CHECK (operation IN ('renew', 'deploy', 'reload', 'revoke', 'noop')),
        status TEXT NOT NULL DEFAULT 'pending'
          CHECK (status IN ('pending_approval', 'approved', 'rejected', 'pending', 'claimed', 'running', 'succeeded', 'failed', 'blocked', 'cancelled')),
        source TEXT NOT NULL DEFAULT 'api'
          CHECK (source IN ('api', 'executor', 'system', 'automation', 'domain-monitor', 'endpoint-monitor', 'control-plane', 'external')),
        requested_by_user_id INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
        requested_by_api_token_id UUID NULL,
        idempotency_key TEXT NULL
          CHECK (idempotency_key IS NULL OR char_length(btrim(idempotency_key)) BETWEEN 1 AND 128),
        subject_type TEXT NULL
          CHECK (subject_type IS NULL OR subject_type IN ('managed_certificate', 'certificate_instance', 'certificate_target', 'token', 'domain', 'endpoint', 'external')),
        subject_id TEXT NULL
          CHECK (subject_id IS NULL OR char_length(btrim(subject_id)) BETWEEN 1 AND 128),
        payload JSONB NOT NULL DEFAULT '{}'::jsonb,
        result_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
        error_code TEXT NULL
          CHECK (error_code IS NULL OR char_length(btrim(error_code)) BETWEEN 1 AND 128),
        error_message TEXT NULL
          CHECK (error_message IS NULL OR char_length(error_message) <= 1024),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        queued_at TIMESTAMPTZ NULL,
        started_at TIMESTAMPTZ NULL,
        completed_at TIMESTAMPTZ NULL,
        canceled_at TIMESTAMPTZ NULL,
        CONSTRAINT uq_certificate_jobs_workspace_id UNIQUE (workspace_id, id),
        CONSTRAINT fk_certificate_jobs_api_token
          FOREIGN KEY (workspace_id, requested_by_api_token_id)
          REFERENCES api_tokens(workspace_id, id)
          ON DELETE SET NULL (requested_by_api_token_id)
      );

      CREATE INDEX IF NOT EXISTS idx_certificate_jobs_workspace_created
        ON certificate_jobs(workspace_id, created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_certificate_jobs_workspace_status_created
        ON certificate_jobs(workspace_id, status, created_at DESC);
      CREATE UNIQUE INDEX IF NOT EXISTS uq_certificate_jobs_workspace_idempotency_key
        ON certificate_jobs(workspace_id, idempotency_key)
        WHERE idempotency_key IS NOT NULL;
      CREATE INDEX IF NOT EXISTS idx_certificate_jobs_workspace_subject
        ON certificate_jobs(workspace_id, subject_type, subject_id, created_at DESC)
        WHERE subject_type IS NOT NULL AND subject_id IS NOT NULL;

      -- CertOps job log stores bounded lifecycle events and sanitized metadata.
      CREATE TABLE IF NOT EXISTS certificate_job_log (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
        job_id UUID NOT NULL,
        event_type TEXT NOT NULL
          CHECK (event_type IN ('job.created', 'job.accepted', 'job.started', 'job.progress', 'job.completed', 'job.failed', 'job.rejected', 'job.cancelled', 'job.status_updated', 'evidence.attached')),
        status TEXT NULL
          CHECK (status IS NULL OR status IN ('pending_approval', 'approved', 'rejected', 'pending', 'claimed', 'running', 'succeeded', 'failed', 'blocked', 'cancelled')),
        message TEXT NULL
          CHECK (message IS NULL OR char_length(message) <= 1024),
        metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_by_user_id INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
        created_by_api_token_id UUID NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        CONSTRAINT fk_certificate_job_log_job
          FOREIGN KEY (workspace_id, job_id)
          REFERENCES certificate_jobs(workspace_id, id)
          ON DELETE CASCADE,
        CONSTRAINT fk_certificate_job_log_api_token
          FOREIGN KEY (workspace_id, created_by_api_token_id)
          REFERENCES api_tokens(workspace_id, id)
          ON DELETE SET NULL (created_by_api_token_id)
      );

      CREATE INDEX IF NOT EXISTS idx_certificate_job_log_workspace_job_created
        ON certificate_job_log(workspace_id, job_id, created_at DESC);

      -- CertOps evidence is public, sanitized lifecycle metadata only. Job
      -- deletion detaches evidence from the job while preserving workspace
      -- ownership for later audit/reporting until the workspace is removed.
      CREATE TABLE IF NOT EXISTS certificate_evidence (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
        job_id UUID NULL,
        evidence_type TEXT NOT NULL
          CHECK (evidence_type IN ('certificate.observed', 'deployment.checked', 'deployment.updated', 'validation.passed', 'validation.failed', 'policy.checked')),
        subject_type TEXT NULL
          CHECK (subject_type IS NULL OR subject_type IN ('managed_certificate', 'certificate_instance', 'certificate_target', 'token', 'domain', 'endpoint', 'external')),
        subject_id TEXT NULL
          CHECK (subject_id IS NULL OR char_length(btrim(subject_id)) BETWEEN 1 AND 128),
        metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
        redacted_output TEXT NULL
          CHECK (redacted_output IS NULL OR octet_length(redacted_output) <= 65536),
        output_truncated BOOLEAN NOT NULL DEFAULT FALSE,
        output_sha256 TEXT NULL
          CHECK (output_sha256 IS NULL OR output_sha256 ~ '^[a-f0-9]{64}$'),
        output_size_bytes INTEGER NULL
          CHECK (output_size_bytes IS NULL OR output_size_bytes BETWEEN 0 AND 65536),
        observed_at TIMESTAMPTZ NULL,
        created_by_user_id INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
        created_by_api_token_id UUID NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        CONSTRAINT uq_certificate_evidence_workspace_id UNIQUE (workspace_id, id),
        CONSTRAINT fk_certificate_evidence_job
          FOREIGN KEY (workspace_id, job_id)
          REFERENCES certificate_jobs(workspace_id, id)
          ON DELETE SET NULL (job_id),
        CONSTRAINT fk_certificate_evidence_api_token
          FOREIGN KEY (workspace_id, created_by_api_token_id)
          REFERENCES api_tokens(workspace_id, id)
          ON DELETE SET NULL (created_by_api_token_id),
        CONSTRAINT certificate_evidence_output_consistency_check CHECK (
          (redacted_output IS NULL AND output_sha256 IS NULL AND output_size_bytes IS NULL) OR
          (redacted_output IS NOT NULL AND output_sha256 IS NOT NULL AND
            output_size_bytes = octet_length(redacted_output))
        )
      );

      CREATE INDEX IF NOT EXISTS idx_certificate_evidence_workspace_job_created
        ON certificate_evidence(workspace_id, job_id, created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_certificate_evidence_workspace_subject_created
        ON certificate_evidence(workspace_id, subject_type, subject_id, created_at DESC)
        WHERE subject_type IS NOT NULL AND subject_id IS NOT NULL;
    `,
  },
  {
    version: 14,
    name: "certops_executor_event_idempotency",
    sql: `
      -- Executor event records hold only a hash of the normalized public
      -- envelope and a safe accepted response. They never retain request
      -- bodies, bearer tokens, credentials, or private-key material.
      CREATE TABLE IF NOT EXISTS certificate_executor_events (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
        job_id UUID NOT NULL,
        executor_event_id TEXT NOT NULL
          CHECK (char_length(btrim(executor_event_id)) BETWEEN 1 AND 128),
        request_hash TEXT NOT NULL
          CHECK (request_hash ~ '^[a-f0-9]{64}$'),
        response JSONB NOT NULL DEFAULT '{}'::jsonb,
        status TEXT NOT NULL DEFAULT 'accepted'
          CHECK (status IN ('accepted', 'claimed', 'running', 'succeeded', 'failed', 'rejected', 'blocked', 'cancelled')),
        created_by_api_token_id UUID NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        CONSTRAINT uq_certificate_executor_events_workspace_job_event
          UNIQUE (workspace_id, job_id, executor_event_id),
        CONSTRAINT fk_certificate_executor_events_job
          FOREIGN KEY (workspace_id, job_id)
          REFERENCES certificate_jobs(workspace_id, id)
          ON DELETE CASCADE,
        CONSTRAINT fk_certificate_executor_events_api_token
          FOREIGN KEY (workspace_id, created_by_api_token_id)
          REFERENCES api_tokens(workspace_id, id)
          ON DELETE SET NULL (created_by_api_token_id)
      );

      CREATE INDEX IF NOT EXISTS idx_certificate_executor_events_workspace_job_created
        ON certificate_executor_events(workspace_id, job_id, created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_certificate_executor_events_workspace_event
        ON certificate_executor_events(workspace_id, executor_event_id);
      CREATE INDEX IF NOT EXISTS idx_certificate_executor_events_api_token
        ON certificate_executor_events(workspace_id, created_by_api_token_id)
        WHERE created_by_api_token_id IS NOT NULL;
    `,
  },
  {
    version: 15,
    name: "certops_managed_certificate_monitor_identity",
    sql: `
      -- Stop merging distinct monitor observations on shared fingerprints.
      -- Non-monitor rows (import/api/manual/...) keep fingerprint dedupe.
      -- Monitor identity is (workspace_id, source, source_ref).
      -- certificate_targets is a location abstraction (observation point or
      -- deployment destination), not only a deployment reference.
      DROP INDEX IF EXISTS uq_managed_certificates_workspace_fingerprint;
      DROP INDEX IF EXISTS uq_managed_certificates_workspace_fingerprint_import;
      DROP INDEX IF EXISTS uq_managed_certificates_workspace_source_ref;

      -- Pre-v15 databases could hold duplicate monitor identities
      -- (workspace_id, source, source_ref): the old SELECT-then-INSERT
      -- monitor bridge raced (TOCTOU) and NULL-fingerprint rows bypassed
      -- the old fingerprint unique index. Deduplicate deterministically
      -- before creating the monitor identity unique index: keep the newest
      -- row per identity (updated_at DESC, created_at DESC, id DESC), the
      -- same resolution the old bridge converged on (latest observation).
      -- certificate_instances children of losing rows are re-pointed to the
      -- keeper so rotation history survives; only instances that would
      -- collide with an equivalent keeper instance under
      -- uq_certificate_instances_target_cert_fingerprint are deleted
      -- (they describe the same observation). certificate_jobs and
      -- certificate_evidence history that references losing rows through the
      -- FK-less text pair (subject_type='managed_certificate', subject_id)
      -- is re-pointed to the keeper too, and a terminal lifecycle status on
      -- any losing row ('revoked'/'decommissioned', retire-first) is
      -- carried onto the keeper before losers are deleted. No dedup is
      -- needed for
      -- uq_managed_certificates_workspace_fingerprint_import: the pre-v15
      -- index uq_managed_certificates_workspace_fingerprint was unique over
      -- ALL rows with fingerprint_sha256 IS NOT NULL, a superset of the new
      -- import predicate's row set.
      WITH monitor_identity_keepers AS (
        SELECT DISTINCT ON (workspace_id, source, source_ref)
               workspace_id, source, source_ref, id AS keeper_id
          FROM managed_certificates
         WHERE source_ref IS NOT NULL
           AND source IN ('endpoint_monitor', 'domain_checker')
         ORDER BY workspace_id, source, source_ref,
                  updated_at DESC, created_at DESC, id DESC
      ),
      colliding_instances AS (
        SELECT ci.id,
               ROW_NUMBER() OVER (
                 PARTITION BY ci.workspace_id, ci.target_id, k.keeper_id,
                              ci.observed_fingerprint_sha256
                 ORDER BY (ci.managed_certificate_id = k.keeper_id) DESC,
                          ci.updated_at DESC, ci.created_at DESC, ci.id DESC
               ) AS rn
          FROM certificate_instances ci
          JOIN managed_certificates mc
            ON mc.workspace_id = ci.workspace_id
           AND mc.id = ci.managed_certificate_id
          JOIN monitor_identity_keepers k
            ON k.workspace_id = mc.workspace_id
           AND k.source = mc.source
           AND k.source_ref = mc.source_ref
         WHERE ci.observed_fingerprint_sha256 IS NOT NULL
      )
      DELETE FROM certificate_instances
       WHERE id IN (SELECT id FROM colliding_instances WHERE rn > 1);

      WITH monitor_identity_keepers AS (
        SELECT DISTINCT ON (workspace_id, source, source_ref)
               workspace_id, source, source_ref, id AS keeper_id
          FROM managed_certificates
         WHERE source_ref IS NOT NULL
           AND source IN ('endpoint_monitor', 'domain_checker')
         ORDER BY workspace_id, source, source_ref,
                  updated_at DESC, created_at DESC, id DESC
      )
      UPDATE certificate_instances ci
         SET managed_certificate_id = k.keeper_id
        FROM managed_certificates mc
        JOIN monitor_identity_keepers k
          ON k.workspace_id = mc.workspace_id
         AND k.source = mc.source
         AND k.source_ref = mc.source_ref
       WHERE ci.workspace_id = mc.workspace_id
         AND ci.managed_certificate_id = mc.id
         AND mc.id <> k.keeper_id;

      -- certificate_jobs and certificate_evidence reference managed
      -- certificates through the FK-less text pair
      -- (subject_type = 'managed_certificate', subject_id = mc.id::text).
      -- Re-point that history from each losing row to its keeper so job and
      -- evidence trails survive the dedup. audit_events rows that mention
      -- loser ids inside their metadata are historical records of what
      -- happened at the time and are intentionally left untouched.
      WITH monitor_identity_keepers AS (
        SELECT DISTINCT ON (workspace_id, source, source_ref)
               workspace_id, source, source_ref, id AS keeper_id
          FROM managed_certificates
         WHERE source_ref IS NOT NULL
           AND source IN ('endpoint_monitor', 'domain_checker')
         ORDER BY workspace_id, source, source_ref,
                  updated_at DESC, created_at DESC, id DESC
      ),
      monitor_identity_losers AS (
        SELECT mc.workspace_id, mc.id AS loser_id, k.keeper_id
          FROM managed_certificates mc
          JOIN monitor_identity_keepers k
            ON k.workspace_id = mc.workspace_id
           AND k.source = mc.source
           AND k.source_ref = mc.source_ref
         WHERE mc.id <> k.keeper_id
      )
      UPDATE certificate_jobs cj
         SET subject_id = l.keeper_id::text
        FROM monitor_identity_losers l
       WHERE cj.workspace_id = l.workspace_id
         AND cj.subject_type = 'managed_certificate'
         AND cj.subject_id = l.loser_id::text;

      WITH monitor_identity_keepers AS (
        SELECT DISTINCT ON (workspace_id, source, source_ref)
               workspace_id, source, source_ref, id AS keeper_id
          FROM managed_certificates
         WHERE source_ref IS NOT NULL
           AND source IN ('endpoint_monitor', 'domain_checker')
         ORDER BY workspace_id, source, source_ref,
                  updated_at DESC, created_at DESC, id DESC
      ),
      monitor_identity_losers AS (
        SELECT mc.workspace_id, mc.id AS loser_id, k.keeper_id
          FROM managed_certificates mc
          JOIN monitor_identity_keepers k
            ON k.workspace_id = mc.workspace_id
           AND k.source = mc.source
           AND k.source_ref = mc.source_ref
         WHERE mc.id <> k.keeper_id
      )
      UPDATE certificate_evidence ce
         SET subject_id = l.keeper_id::text
        FROM monitor_identity_losers l
       WHERE ce.workspace_id = l.workspace_id
         AND ce.subject_type = 'managed_certificate'
         AND ce.subject_id = l.loser_id::text;

      -- Retire-first: a terminal lifecycle status ('revoked' or
      -- 'decommissioned') must not be discarded just because a different
      -- duplicate has a newer updated_at. The keeper row is still selected
      -- by recency (identity and relationships), but if any losing row in
      -- the group is terminal and the keeper is not, the keeper inherits the
      -- terminal status. Deterministic choice: the most recently updated
      -- terminal loser wins (updated_at DESC, created_at DESC, id DESC).
      -- managed_certificates has no retired_at/decommissioned_at columns;
      -- status is the only lifecycle column. updated_at is left as-is: the
      -- keeper already carries the newest updated_at in its group by
      -- construction.
      WITH monitor_identity_keepers AS (
        SELECT DISTINCT ON (workspace_id, source, source_ref)
               workspace_id, source, source_ref, id AS keeper_id
          FROM managed_certificates
         WHERE source_ref IS NOT NULL
           AND source IN ('endpoint_monitor', 'domain_checker')
         ORDER BY workspace_id, source, source_ref,
                  updated_at DESC, created_at DESC, id DESC
      ),
      terminal_losers AS (
        SELECT DISTINCT ON (k.workspace_id, k.keeper_id)
               k.workspace_id, k.keeper_id,
               mc.status AS terminal_status
          FROM managed_certificates mc
          JOIN monitor_identity_keepers k
            ON k.workspace_id = mc.workspace_id
           AND k.source = mc.source
           AND k.source_ref = mc.source_ref
         WHERE mc.id <> k.keeper_id
           AND mc.status IN ('revoked', 'decommissioned')
         ORDER BY k.workspace_id, k.keeper_id,
                  mc.updated_at DESC, mc.created_at DESC, mc.id DESC
      )
      UPDATE managed_certificates mc
         SET status = t.terminal_status
        FROM terminal_losers t
       WHERE mc.workspace_id = t.workspace_id
         AND mc.id = t.keeper_id
         AND mc.status NOT IN ('revoked', 'decommissioned');

      WITH monitor_identity_keepers AS (
        SELECT DISTINCT ON (workspace_id, source, source_ref)
               workspace_id, source, source_ref, id AS keeper_id
          FROM managed_certificates
         WHERE source_ref IS NOT NULL
           AND source IN ('endpoint_monitor', 'domain_checker')
         ORDER BY workspace_id, source, source_ref,
                  updated_at DESC, created_at DESC, id DESC
      )
      DELETE FROM managed_certificates mc
       USING monitor_identity_keepers k
       WHERE mc.workspace_id = k.workspace_id
         AND mc.source = k.source
         AND mc.source_ref = k.source_ref
         AND mc.id <> k.keeper_id;

      CREATE UNIQUE INDEX IF NOT EXISTS uq_managed_certificates_workspace_fingerprint_import
        ON managed_certificates(workspace_id, fingerprint_sha256)
        WHERE fingerprint_sha256 IS NOT NULL
          AND source NOT IN ('endpoint_monitor', 'domain_checker');

      CREATE UNIQUE INDEX IF NOT EXISTS uq_managed_certificates_workspace_source_ref
        ON managed_certificates(workspace_id, source, source_ref)
        WHERE source_ref IS NOT NULL
          AND source IN ('endpoint_monitor', 'domain_checker');
    `,
  },
  {
    version: 16,
    name: "endpoint_monitor_check_claim_lease",
    sql: `
      -- Dedicated concurrency lease for the endpoint check worker so
      -- last_health_check_at stays pure scheduling state. A claimed monitor
      -- has check_claimed_until in the future; crash recovery is natural
      -- lease expiry. Mirrors the auto-sync worker's claimed-until idiom.
      ALTER TABLE domain_monitors
        ADD COLUMN IF NOT EXISTS check_claimed_until TIMESTAMPTZ NULL;
    `,
  },
  {
    version: 17,
    name: "worker_owner_scoped_claim_ids",
    sql: `
      -- Owner identity for the claim-then-commit workers. A time-based marker
      -- (next_attempt_at / check_claimed_until) alone cannot distinguish two
      -- workers racing on the same row after a lease expires: both renewals
      -- match a status-only predicate and both perform external side effects.
      -- Each worker run generates one claim UUID; renewals, terminal writes,
      -- and lease releases are conditional on still owning that claim id, so
      -- a superseded worker's writes no-op instead of double-sending or
      -- clearing another worker's lease.
      ALTER TABLE alert_queue
        ADD COLUMN IF NOT EXISTS delivery_claim_id UUID NULL;
      ALTER TABLE domain_monitors
        ADD COLUMN IF NOT EXISTS check_claim_id UUID NULL;
    `,
  },
  {
    version: 18,
    name: "tokens_certops_api_token_link",
    sql: `
      -- Links a TokenTimer monitoring token to the CertOps machine token it
      -- was created to track (opt-in checkbox on "store this token now").
      -- Revoking the CertOps token must delete this row explicitly (revoke
      -- is an UPDATE, not a DELETE, so ON DELETE CASCADE alone never fires
      -- on the common path); the FK is a defense-in-depth backstop only.
      ALTER TABLE tokens
        ADD COLUMN IF NOT EXISTS certops_api_token_id UUID NULL
          REFERENCES api_tokens(id) ON DELETE CASCADE;

      CREATE UNIQUE INDEX IF NOT EXISTS uq_tokens_certops_api_token_id
        ON tokens(certops_api_token_id)
        WHERE certops_api_token_id IS NOT NULL;
    `,
  },
  {
    version: 19,
    name: "certops_workspace_kill_switch",
    sql: `
      -- Workspace-scoped CertOps incident control. This is deliberately
      -- separate from system_settings.certops_settings.enabled: the latter is
      -- the deployment-wide rollout flag, while this column stops new work for
      -- exactly one workspace. Existing rows receive the safe unpaused default.
      ALTER TABLE workspaces
        ADD COLUMN IF NOT EXISTS certops_paused BOOLEAN NOT NULL DEFAULT FALSE;
    `,
  },
  {
    version: 20,
    name: "certops_job_creation_request_fingerprint",
    sql: `
      -- A new job stores a SHA-256 fingerprint of its normalized original
      -- creation request. It is immutable so idempotent replays can be
      -- distinguished from changed original requests even after lifecycle
      -- status, result metadata, errors, or generated timestamps change.
      -- Existing rows remain NULL: their complete original request cannot be
      -- reconstructed safely from mutable lifecycle state.
      ALTER TABLE certificate_jobs
        ADD COLUMN IF NOT EXISTS creation_request_hash CHAR(64) NULL
          CHECK (
            creation_request_hash IS NULL OR
            creation_request_hash ~ '^[a-f0-9]{64}$'
          );
    `,
  },
  {
    version: 21,
    name: "certops_controller_observation_reporting",
    sql: `
      -- Binds the narrow controller-observation scope to one immutable
      -- workspace-local cluster label. Existing executor tokens remain valid with
      -- a NULL binding; the binding is only meaningful for this new write scope.
      ALTER TABLE api_tokens
        ADD COLUMN IF NOT EXISTS controller_cluster_id TEXT NULL;
      ALTER TABLE api_tokens
        DROP CONSTRAINT IF EXISTS api_tokens_scopes_check;
      ALTER TABLE api_tokens
        ADD CONSTRAINT api_tokens_scopes_check CHECK (
          COALESCE(array_length(scopes, 1), 0) BETWEEN 1 AND 8 AND
          scopes <@ ARRAY[
            'certops:read',
            'certops:events:write',
            'certops:jobs:read',
            'certops:evidence:write',
            'certops:observations:write'
          ]::text[] AND
          ((scopes @> ARRAY['certops:observations:write']::text[]) =
            (controller_cluster_id IS NOT NULL)) AND
          (controller_cluster_id IS NULL OR
            controller_cluster_id ~ '^[a-z0-9]([-a-z0-9]*[a-z0-9])?$') AND
          (controller_cluster_id IS NULL OR char_length(controller_cluster_id) BETWEEN 1 AND 63)
        );

      -- Stable controller identity is source based, not fingerprint based. A
      -- cert-manager observation must never merge a different cluster or
      -- namespace merely because it reports the same public certificate.
      ALTER TABLE managed_certificates
        DROP CONSTRAINT IF EXISTS managed_certificates_source_check;
      ALTER TABLE managed_certificates
        ADD CONSTRAINT managed_certificates_source_check CHECK (
          source IN ('manual', 'api', 'import', 'domain_checker', 'endpoint_monitor', 'integration', 'auto_sync', 'cert_manager')
        );
      ALTER TABLE certificate_targets
        DROP CONSTRAINT IF EXISTS certificate_targets_source_check;
      ALTER TABLE certificate_targets
        ADD CONSTRAINT certificate_targets_source_check CHECK (
          source IN ('manual', 'api', 'import', 'domain_checker', 'endpoint_monitor', 'integration', 'auto_sync', 'cert_manager')
        );
      ALTER TABLE certificate_targets
        DROP CONSTRAINT IF EXISTS certificate_targets_cert_manager_observation_check;
      ALTER TABLE certificate_targets
        ADD CONSTRAINT certificate_targets_cert_manager_observation_check CHECK (
          source <> 'cert_manager' OR
          (target_type = 'kubernetes-secret' AND source_ref IS NOT NULL)
        );
      ALTER TABLE certificate_instances
        DROP CONSTRAINT IF EXISTS certificate_instances_source_check;
      ALTER TABLE certificate_instances
        ADD CONSTRAINT certificate_instances_source_check CHECK (
          source IN ('manual', 'api', 'import', 'domain_checker', 'endpoint_monitor', 'integration', 'auto_sync', 'cert_manager')
        );

      DROP INDEX IF EXISTS uq_managed_certificates_workspace_fingerprint_import;
      CREATE UNIQUE INDEX IF NOT EXISTS uq_managed_certificates_workspace_fingerprint_import
        ON managed_certificates(workspace_id, fingerprint_sha256)
        WHERE fingerprint_sha256 IS NOT NULL
          AND source NOT IN ('endpoint_monitor', 'domain_checker', 'cert_manager');
      DROP INDEX IF EXISTS uq_managed_certificates_workspace_source_ref;
      CREATE UNIQUE INDEX IF NOT EXISTS uq_managed_certificates_workspace_source_ref
        ON managed_certificates(workspace_id, source, source_ref)
        WHERE source_ref IS NOT NULL
          AND source IN ('endpoint_monitor', 'domain_checker', 'cert_manager');
      CREATE UNIQUE INDEX IF NOT EXISTS uq_certificate_targets_workspace_cert_manager_source_ref
        ON certificate_targets(workspace_id, source, source_ref)
        WHERE source = 'cert_manager' AND source_ref IS NOT NULL;

      -- Controller observation idempotency never stores a raw request,
      -- authorization header, public PEM, Kubernetes object, or token. The
      -- semantic request hash excludes retry diagnostics at the service layer.
      CREATE TABLE IF NOT EXISTS certificate_controller_observations (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
        controller_cluster_id TEXT NOT NULL
          CHECK (controller_cluster_id ~ '^[a-z0-9]([-a-z0-9]*[a-z0-9])?$')
          CHECK (char_length(controller_cluster_id) BETWEEN 1 AND 63),
        idempotency_key CHAR(64) NOT NULL
          CHECK (idempotency_key ~ '^[a-f0-9]{64}$'),
        request_hash CHAR(64) NOT NULL
          CHECK (request_hash ~ '^[a-f0-9]{64}$'),
        managed_certificate_id UUID NULL,
        target_id UUID NULL,
        certificate_instance_id UUID NULL,
        status TEXT NOT NULL CHECK (status IN ('accepted', 'redacted')),
        created_by_api_token_id UUID NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        CONSTRAINT uq_certificate_controller_observations_workspace_cluster_key
          UNIQUE (workspace_id, controller_cluster_id, idempotency_key),
        CONSTRAINT fk_certificate_controller_observations_managed_certificate
          FOREIGN KEY (workspace_id, managed_certificate_id)
          REFERENCES managed_certificates(workspace_id, id)
          ON DELETE SET NULL (managed_certificate_id),
        CONSTRAINT fk_certificate_controller_observations_target
          FOREIGN KEY (workspace_id, target_id)
          REFERENCES certificate_targets(workspace_id, id)
          ON DELETE SET NULL (target_id),
        CONSTRAINT fk_certificate_controller_observations_instance
          FOREIGN KEY (certificate_instance_id)
          REFERENCES certificate_instances(id)
          ON DELETE SET NULL,
        CONSTRAINT fk_certificate_controller_observations_api_token
          FOREIGN KEY (workspace_id, created_by_api_token_id)
          REFERENCES api_tokens(workspace_id, id)
          ON DELETE SET NULL (created_by_api_token_id)
      );
      CREATE INDEX IF NOT EXISTS idx_certificate_controller_observations_workspace_created
        ON certificate_controller_observations(workspace_id, created_at DESC);
    `,
  },
  {
    version: 22,
    name: "certops_controller_provisioning",
    sql: `
      -- Adds a second narrow controller scope. A cluster binding is
      -- required exactly for either controller-owned scope; legacy executor
      -- tokens remain valid with no binding.
      ALTER TABLE api_tokens
        DROP CONSTRAINT IF EXISTS api_tokens_scopes_check;
      ALTER TABLE api_tokens
        ADD CONSTRAINT api_tokens_scopes_check CHECK (
          COALESCE(array_length(scopes, 1), 0) BETWEEN 1 AND 8 AND
          scopes <@ ARRAY[
            'certops:read',
            'certops:events:write',
            'certops:jobs:read',
            'certops:evidence:write',
            'certops:observations:write',
            'certops:provision:execute'
          ]::text[] AND
          ((scopes && ARRAY[
              'certops:observations:write',
              'certops:provision:execute'
            ]::text[]) = (controller_cluster_id IS NOT NULL)) AND
          (controller_cluster_id IS NULL OR
            controller_cluster_id ~ '^[a-z0-9]([-a-z0-9]*[a-z0-9])?$') AND
          (controller_cluster_id IS NULL OR char_length(controller_cluster_id) BETWEEN 1 AND 63)
        );

      -- This is intentionally only a bounded redelivery throttle for the
      -- narrow controller command endpoint. It has no agent identity,
      -- attempt, lease, heartbeat, or general job-claim semantics.
      CREATE TABLE IF NOT EXISTS certificate_controller_provision_deliveries (
        job_id UUID PRIMARY KEY REFERENCES certificate_jobs(id) ON DELETE CASCADE,
        workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
        controller_cluster_id TEXT NOT NULL
          CHECK (controller_cluster_id ~ '^[a-z0-9]([-a-z0-9]*[a-z0-9])?$')
          CHECK (char_length(controller_cluster_id) BETWEEN 1 AND 63),
        delivered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_certificate_controller_provision_deliveries_lookup
        ON certificate_controller_provision_deliveries(workspace_id, controller_cluster_id, delivered_at);
    `,
  },
  {
    version: 23,
    name: "certops_controller_provisioning_event_timestamps",
    sql: `
      -- First accepted controller-event times make deterministic event
      -- retries truthful without adding agent attempts, claims, or leases.
      ALTER TABLE certificate_jobs
        DROP CONSTRAINT IF EXISTS certificate_jobs_source_check;
      ALTER TABLE certificate_jobs
        ADD CONSTRAINT certificate_jobs_source_check CHECK (
          source IN (
            'api', 'executor', 'system', 'automation', 'domain-monitor',
            'endpoint-monitor', 'control-plane', 'external',
            'controller_provisioning'
          )
        );
      ALTER TABLE certificate_controller_provision_deliveries
        ADD COLUMN IF NOT EXISTS started_at TIMESTAMPTZ NULL;
      ALTER TABLE certificate_controller_provision_deliveries
        ADD COLUMN IF NOT EXISTS completed_at TIMESTAMPTZ NULL;
      ALTER TABLE certificate_controller_provision_deliveries
        ADD COLUMN IF NOT EXISTS failed_at TIMESTAMPTZ NULL;
    `,
  },
  {
    version: 24,
    name: "certops_agent_protocol_schema",
    sql: `
      -- Agent control plane (ADR-0002/0003). Zero private-key
      -- custody for certificates is preserved: agents keep certificate keys
      -- locally and only hashed credentials are stored here. The one deliberate
      -- exception below is the control-plane-owned Ed25519 JOB-SIGNING key
      -- (never a certificate key), stored encrypted at rest following the
      -- system_settings *_encrypted envelope pattern.

      -- 7.2 agent identity lifecycle. credential_hash is sha256 hex of the
      -- ttagent_ per-agent credential; the raw credential is returned once at
      -- registration and never persisted.
      CREATE TABLE IF NOT EXISTS certops_agents (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
        agent_id TEXT NOT NULL
          CHECK (agent_id ~ '^[A-Za-z0-9_.:-]{1,128}$'),
        name TEXT NULL
          CHECK (name IS NULL OR char_length(btrim(name)) BETWEEN 1 AND 128),
        hostname TEXT NULL
          CHECK (hostname IS NULL OR char_length(hostname) <= 255),
        platform TEXT NULL
          CHECK (platform IS NULL OR platform IN ('linux', 'darwin', 'win32')),
        node_version TEXT NULL
          CHECK (node_version IS NULL OR char_length(node_version) <= 32),
        agent_version TEXT NOT NULL
          CHECK (char_length(btrim(agent_version)) BETWEEN 1 AND 32),
        protocol_version TEXT NOT NULL
          CHECK (protocol_version ~ '^[0-9]+\\.[0-9]+\\.[0-9]+$'),
        credential_prefix TEXT NOT NULL
          CHECK (credential_prefix ~ '^ttagent_[a-f0-9]{16}$'),
        credential_hash TEXT NOT NULL
          CHECK (credential_hash ~ '^[a-f0-9]{64}$'),
        declared_target_selectors JSONB NOT NULL DEFAULT '[]'::jsonb,
        declared_command_profile_names JSONB NOT NULL DEFAULT '[]'::jsonb,
        status TEXT NOT NULL DEFAULT 'active'
          CHECK (status IN ('active', 'offline', 'retired')),
        last_seen_at TIMESTAMPTZ NULL,
        clock_offset_ms BIGINT NULL,
        ntp_synced BOOLEAN NULL,
        uptime_seconds BIGINT NULL
          CHECK (uptime_seconds IS NULL OR uptime_seconds >= 0),
        pinned_signing_key_id TEXT NULL
          CHECK (pinned_signing_key_id IS NULL OR pinned_signing_key_id ~ '^[A-Za-z0-9_.:-]{1,128}$'),
        last_sequence BIGINT NOT NULL DEFAULT 0
          CHECK (last_sequence >= 0),
        bootstrap_token_id UUID NULL,
        retired_at TIMESTAMPTZ NULL,
        retired_by_user_id INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
        retire_reason TEXT NULL
          CHECK (retire_reason IS NULL OR char_length(retire_reason) <= 1024),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        CONSTRAINT uq_certops_agents_workspace_id UNIQUE (workspace_id, id),
        CONSTRAINT certops_agents_retired_consistency_check CHECK (
          (status = 'retired' AND retired_at IS NOT NULL) OR
          (status <> 'retired' AND retired_at IS NULL)
        )
      );

      CREATE UNIQUE INDEX IF NOT EXISTS uq_certops_agents_agent_id
        ON certops_agents(agent_id);
      CREATE UNIQUE INDEX IF NOT EXISTS uq_certops_agents_credential_prefix
        ON certops_agents(credential_prefix);
      CREATE UNIQUE INDEX IF NOT EXISTS uq_certops_agents_credential_hash
        ON certops_agents(credential_hash);
      CREATE INDEX IF NOT EXISTS idx_certops_agents_workspace_status
        ON certops_agents(workspace_id, status);
      CREATE INDEX IF NOT EXISTS idx_certops_agents_status_last_seen
        ON certops_agents(status, last_seen_at)
        WHERE status = 'active';

      -- 7.2 single-use hashed expiring bootstrap tokens. The raw ttboot_
      -- token is shown once at creation and never persisted.
      CREATE TABLE IF NOT EXISTS certops_agent_bootstrap_tokens (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
        name TEXT NOT NULL
          CHECK (char_length(btrim(name)) BETWEEN 1 AND 128),
        token_prefix TEXT NOT NULL
          CHECK (token_prefix ~ '^ttboot_[a-f0-9]{16}$'),
        token_hash TEXT NOT NULL
          CHECK (token_hash ~ '^[a-f0-9]{64}$'),
        status TEXT NOT NULL DEFAULT 'active'
          CHECK (status IN ('active', 'used', 'revoked', 'expired')),
        expires_at TIMESTAMPTZ NOT NULL,
        used_at TIMESTAMPTZ NULL,
        used_by_agent_id UUID NULL REFERENCES certops_agents(id) ON DELETE SET NULL,
        revoked_at TIMESTAMPTZ NULL,
        revoked_by INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
        created_by INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        CONSTRAINT uq_certops_agent_bootstrap_tokens_workspace_id UNIQUE (workspace_id, id),
        CONSTRAINT certops_agent_bootstrap_tokens_used_consistency_check CHECK (
          (status = 'used' AND used_at IS NOT NULL) OR
          (status <> 'used' AND used_at IS NULL)
        )
      );

      CREATE UNIQUE INDEX IF NOT EXISTS uq_certops_agent_bootstrap_tokens_prefix
        ON certops_agent_bootstrap_tokens(token_prefix);
      CREATE UNIQUE INDEX IF NOT EXISTS uq_certops_agent_bootstrap_tokens_hash
        ON certops_agent_bootstrap_tokens(token_hash);
      CREATE INDEX IF NOT EXISTS idx_certops_agent_bootstrap_tokens_workspace_status
        ON certops_agent_bootstrap_tokens(workspace_id, status);
      CREATE INDEX IF NOT EXISTS idx_certops_agent_bootstrap_tokens_status_expires
        ON certops_agent_bootstrap_tokens(status, expires_at)
        WHERE status = 'active';

      ALTER TABLE certops_agents
        DROP CONSTRAINT IF EXISTS fk_certops_agents_bootstrap_token;
      ALTER TABLE certops_agents
        ADD CONSTRAINT fk_certops_agents_bootstrap_token
        FOREIGN KEY (bootstrap_token_id)
        REFERENCES certops_agent_bootstrap_tokens(id)
        ON DELETE SET NULL;

      -- ADR-0003 Ed25519 JOB-SIGNING keys (control-plane owned; NOT certificate
      -- keys, so the zero-custody invariant for certificates is untouched).
      -- private_key_encrypted is a versioned AES-256-GCM envelope; the service
      -- fails closed when the wrap key is unset while dispatch is enabled.
      CREATE TABLE IF NOT EXISTS certops_signing_keys (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        signing_key_id TEXT NOT NULL
          CHECK (signing_key_id ~ '^[A-Za-z0-9_.:-]{1,128}$'),
        public_key_pem TEXT NOT NULL
          CHECK (public_key_pem LIKE '-----BEGIN PUBLIC KEY-----%'),
        private_key_encrypted TEXT NOT NULL,
        encryption_version SMALLINT NOT NULL DEFAULT 1
          CHECK (encryption_version >= 1),
        status TEXT NOT NULL DEFAULT 'active'
          CHECK (status IN ('active', 'retiring', 'retired')),
        retired_at TIMESTAMPTZ NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE UNIQUE INDEX IF NOT EXISTS uq_certops_signing_keys_signing_key_id
        ON certops_signing_keys(signing_key_id);
      CREATE UNIQUE INDEX IF NOT EXISTS uq_certops_signing_keys_single_active
        ON certops_signing_keys(status)
        WHERE status = 'active';

      -- ADR-0003 server-side replay ledger: nonces issued at dispatch are
      -- recorded here; a nonce is single-use per job and swept after expiry.
      CREATE TABLE IF NOT EXISTS certops_consumed_nonces (
        nonce TEXT NOT NULL
          CHECK (nonce ~ '^[A-Za-z0-9_-]{16,128}$'),
        job_id UUID NOT NULL,
        workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
        issued_to_agent_id UUID NULL REFERENCES certops_agents(id) ON DELETE SET NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        consumed_at TIMESTAMPTZ NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        PRIMARY KEY (nonce, job_id)
      );

      CREATE INDEX IF NOT EXISTS idx_certops_consumed_nonces_expires
        ON certops_consumed_nonces(expires_at);
      CREATE INDEX IF NOT EXISTS idx_certops_consumed_nonces_workspace_job
        ON certops_consumed_nonces(workspace_id, job_id);

      -- 7.3 claim/lease execution columns on certificate_jobs (additive).
      ALTER TABLE certificate_jobs
        ADD COLUMN IF NOT EXISTS claimed_by_agent_id UUID NULL;
      ALTER TABLE certificate_jobs
        ADD COLUMN IF NOT EXISTS claim_id UUID NULL;
      ALTER TABLE certificate_jobs
        ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ NULL;
      ALTER TABLE certificate_jobs
        ADD COLUMN IF NOT EXISTS attempt_count INTEGER NOT NULL DEFAULT 0
          CHECK (attempt_count >= 0);
      ALTER TABLE certificate_jobs
        ADD COLUMN IF NOT EXISTS max_attempts INTEGER NOT NULL DEFAULT 3
          CHECK (max_attempts BETWEEN 1 AND 10);
      ALTER TABLE certificate_jobs
        ADD COLUMN IF NOT EXISTS next_attempt_at TIMESTAMPTZ NULL;
      ALTER TABLE certificate_jobs
        ADD COLUMN IF NOT EXISTS scheduled_for TIMESTAMPTZ NULL;
      ALTER TABLE certificate_jobs
        ADD COLUMN IF NOT EXISTS approved_by_user_id INTEGER NULL REFERENCES users(id) ON DELETE SET NULL;
      ALTER TABLE certificate_jobs
        ADD COLUMN IF NOT EXISTS approved_at TIMESTAMPTZ NULL;
      ALTER TABLE certificate_jobs
        ADD COLUMN IF NOT EXISTS approved_payload_hash CHAR(64) NULL
          CHECK (approved_payload_hash IS NULL OR approved_payload_hash ~ '^[a-f0-9]{64}$');

      ALTER TABLE certificate_jobs
        DROP CONSTRAINT IF EXISTS fk_certificate_jobs_claimed_by_agent;
      ALTER TABLE certificate_jobs
        ADD CONSTRAINT fk_certificate_jobs_claimed_by_agent
        FOREIGN KEY (claimed_by_agent_id)
        REFERENCES certops_agents(id)
        ON DELETE SET NULL;

      CREATE INDEX IF NOT EXISTS idx_certificate_jobs_claimable
        ON certificate_jobs(workspace_id, status, next_attempt_at, scheduled_for)
        WHERE status = 'pending';
      CREATE INDEX IF NOT EXISTS idx_certificate_jobs_lease_expiry
        ON certificate_jobs(lease_expires_at)
        WHERE status IN ('claimed', 'running') AND lease_expires_at IS NOT NULL;
      CREATE INDEX IF NOT EXISTS idx_certificate_jobs_claimed_by_agent
        ON certificate_jobs(claimed_by_agent_id)
        WHERE claimed_by_agent_id IS NOT NULL;
    `,
  },
  {
    version: 25,
    name: "certops_job_approvals",
    sql: `
      -- Approval gates (control-plane orchestration). A job created
      -- with requiresApproval starts at pending_approval and may only reach
      -- 'pending' (claimable) through a human approval. The approval is bound
      -- to a SHA256 hash of the canonical job payload (the same
      -- packages/contracts/certops/canonical-json.cjs serialization the job
      -- signer uses), so any later payload edit voids it and the claim path
      -- flips the job back to pending_approval. No key material is involved:
      -- only hashes, user ids, decisions, and bounded public reasons.

      -- Dedicated append-only decision ledger for auditability. The current
      -- binding also lives on certificate_jobs (approved_by_user_id,
      -- approved_at, approved_payload_hash from migration 24); this table
      -- keeps the full decision history including invalidations.
      CREATE TABLE IF NOT EXISTS certops_job_approvals (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
        job_id UUID NOT NULL,
        decision TEXT NOT NULL
          CHECK (decision IN ('approved', 'rejected', 'invalidated')),
        approved_by_user_id INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
        payload_hash CHAR(64) NULL
          CHECK (payload_hash IS NULL OR payload_hash ~ '^[a-f0-9]{64}$'),
        reason TEXT NULL
          CHECK (reason IS NULL OR char_length(reason) <= 1024),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        CONSTRAINT fk_certops_job_approvals_job
          FOREIGN KEY (workspace_id, job_id)
          REFERENCES certificate_jobs(workspace_id, id)
          ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_certops_job_approvals_workspace_job_created
        ON certops_job_approvals(workspace_id, job_id, created_at DESC);

      -- Approval lifecycle events join the bounded job-log event vocabulary
      -- (kept in sync with JOB_LOG_EVENT_TYPES in services/certops/jobs.js).
      ALTER TABLE certificate_job_log
        DROP CONSTRAINT IF EXISTS certificate_job_log_event_type_check;
      ALTER TABLE certificate_job_log
        ADD CONSTRAINT certificate_job_log_event_type_check CHECK (
          event_type IN (
            'job.created', 'job.accepted', 'job.started', 'job.progress',
            'job.completed', 'job.failed', 'job.rejected', 'job.cancelled',
            'job.status_updated', 'evidence.attached',
            'approval.granted', 'approval.rejected', 'approval.invalidated'
          )
        );
    `,
  },
  {
    version: 26,
    name: "certops_job_mode_and_dry_run_complete",
    sql: `
      -- B4: first-class immutable job mode (real | dry_run) plus a distinct
      -- terminal status for dry-run completion. Dry-run must never be reported
      -- as succeeded. Mode is set at creation and never updated afterwards.
      -- See COORDINATION-B4.md.

      ALTER TABLE certificate_jobs
        ADD COLUMN IF NOT EXISTS mode TEXT NOT NULL DEFAULT 'real';

      ALTER TABLE certificate_jobs
        DROP CONSTRAINT IF EXISTS certificate_jobs_mode_check;
      ALTER TABLE certificate_jobs
        ADD CONSTRAINT certificate_jobs_mode_check
          CHECK (mode IN ('real', 'dry_run'));

      ALTER TABLE certificate_jobs
        DROP CONSTRAINT IF EXISTS certificate_jobs_status_check;
      ALTER TABLE certificate_jobs
        ADD CONSTRAINT certificate_jobs_status_check CHECK (
          status IN (
            'pending_approval', 'approved', 'rejected', 'pending', 'claimed',
            'running', 'succeeded', 'failed', 'blocked', 'cancelled',
            'dry_run_complete'
          )
        );

      ALTER TABLE certificate_job_log
        DROP CONSTRAINT IF EXISTS certificate_job_log_status_check;
      ALTER TABLE certificate_job_log
        ADD CONSTRAINT certificate_job_log_status_check CHECK (
          status IS NULL OR status IN (
            'pending_approval', 'approved', 'rejected', 'pending', 'claimed',
            'running', 'succeeded', 'failed', 'blocked', 'cancelled',
            'dry_run_complete'
          )
        );

      CREATE INDEX IF NOT EXISTS idx_certificate_jobs_workspace_mode_status
        ON certificate_jobs(workspace_id, mode, status);
    `,
  },
  {
    version: 27,
    name: "certops_dispatch_executor_lanes_and_routing",
    sql: `
      -- B2: immutable executor lane separating agent jobs from controller
      -- provisioning jobs so an agent that supports 'deploy' can never claim
      -- a controller_provisioning command (and vice versa).
      ALTER TABLE certificate_jobs
        ADD COLUMN IF NOT EXISTS executor_kind TEXT NOT NULL DEFAULT 'agent';
      ALTER TABLE certificate_jobs
        DROP CONSTRAINT IF EXISTS certificate_jobs_executor_kind_check;
      ALTER TABLE certificate_jobs
        ADD CONSTRAINT certificate_jobs_executor_kind_check
          CHECK (executor_kind IN ('agent', 'controller'));

      -- Existing controller_provisioning rows must be lane-locked; the
      -- column is otherwise immutable after insert (enforced in services).
      UPDATE certificate_jobs
         SET executor_kind = 'controller'
       WHERE source = 'controller_provisioning'
         AND executor_kind <> 'controller';

      -- Controller claim binding: which authenticated cluster holds the
      -- lease (distinct from claimed_by_agent_id on the agent lane).
      ALTER TABLE certificate_jobs
        ADD COLUMN IF NOT EXISTS claimed_by_controller_cluster_id TEXT NULL
          CHECK (
            claimed_by_controller_cluster_id IS NULL OR
            (
              char_length(claimed_by_controller_cluster_id) BETWEEN 1 AND 63 AND
              claimed_by_controller_cluster_id ~ '^[a-z0-9]([-a-z0-9]*[a-z0-9])?$'
            )
          );

      -- B6: first successful lease renew stamps this; the reaper treats a
      -- NULL value as "no side effects proven" (safe requeue) and a non-NULL
      -- value as effects-unknown (manual reconciliation, no silent retry).
      ALTER TABLE certificate_jobs
        ADD COLUMN IF NOT EXISTS lease_renewed_at TIMESTAMPTZ NULL;

      -- B5: job routing selectors set at creation time. NULL means "any
      -- capable agent in the workspace may claim this job".
      ALTER TABLE certificate_jobs
        ADD COLUMN IF NOT EXISTS assigned_agent_id UUID NULL;
      ALTER TABLE certificate_jobs
        ADD COLUMN IF NOT EXISTS required_target_selector TEXT NULL
          CHECK (
            required_target_selector IS NULL OR
            char_length(required_target_selector) BETWEEN 1 AND 512
          );
      ALTER TABLE certificate_jobs
        ADD COLUMN IF NOT EXISTS required_dns_provider TEXT NULL
          CHECK (
            required_dns_provider IS NULL OR
            required_dns_provider ~ '^[A-Za-z0-9_.:-]{1,64}$'
          );
      ALTER TABLE certificate_jobs
        ADD COLUMN IF NOT EXISTS required_command_profile TEXT NULL
          CHECK (
            required_command_profile IS NULL OR
            required_command_profile ~ '^[A-Za-z0-9_.:-]{1,128}$'
          );

      ALTER TABLE certificate_jobs
        DROP CONSTRAINT IF EXISTS fk_certificate_jobs_assigned_agent;
      ALTER TABLE certificate_jobs
        ADD CONSTRAINT fk_certificate_jobs_assigned_agent
        FOREIGN KEY (assigned_agent_id)
        REFERENCES certops_agents(id)
        ON DELETE SET NULL;

      CREATE INDEX IF NOT EXISTS idx_certificate_jobs_claimable_agent_lane
        ON certificate_jobs(workspace_id, status, executor_kind, next_attempt_at, scheduled_for)
        WHERE status = 'pending' AND executor_kind = 'agent';
      CREATE INDEX IF NOT EXISTS idx_certificate_jobs_claimable_controller_lane
        ON certificate_jobs(workspace_id, status, executor_kind, created_at)
        WHERE status = 'pending' AND executor_kind = 'controller';

      -- B5: persisted agent capabilities used by the claim matcher.
      -- declared_target_selectors / declared_command_profile_names already
      -- exist from migration 24; these two cover operations + DNS providers
      -- refreshed on heartbeat/claim.
      ALTER TABLE certops_agents
        ADD COLUMN IF NOT EXISTS supported_operations JSONB NOT NULL DEFAULT '[]'::jsonb;
      ALTER TABLE certops_agents
        ADD COLUMN IF NOT EXISTS supported_dns_providers JSONB NOT NULL DEFAULT '[]'::jsonb;
    `,
  },
  {
    version: 28,
    name: "certops_agent_inventory_evidence_integrity",
    sql: `
      -- B17: agent filesystem discovery becomes inventory-visible.
      -- Mirror cert_manager observer identity: source + source_ref uniqueness.
      ALTER TABLE managed_certificates
        DROP CONSTRAINT IF EXISTS managed_certificates_source_check;
      ALTER TABLE managed_certificates
        ADD CONSTRAINT managed_certificates_source_check CHECK (
          source IN (
            'manual', 'api', 'import', 'domain_checker', 'endpoint_monitor',
            'integration', 'auto_sync', 'cert_manager', 'agent_filesystem'
          )
        );
      ALTER TABLE certificate_targets
        DROP CONSTRAINT IF EXISTS certificate_targets_source_check;
      ALTER TABLE certificate_targets
        ADD CONSTRAINT certificate_targets_source_check CHECK (
          source IN (
            'manual', 'api', 'import', 'domain_checker', 'endpoint_monitor',
            'integration', 'auto_sync', 'cert_manager', 'agent_filesystem'
          )
        );
      ALTER TABLE certificate_instances
        DROP CONSTRAINT IF EXISTS certificate_instances_source_check;
      ALTER TABLE certificate_instances
        ADD CONSTRAINT certificate_instances_source_check CHECK (
          source IN (
            'manual', 'api', 'import', 'domain_checker', 'endpoint_monitor',
            'integration', 'auto_sync', 'cert_manager', 'agent_filesystem'
          )
        );

      DROP INDEX IF EXISTS uq_managed_certificates_workspace_fingerprint_import;
      CREATE UNIQUE INDEX IF NOT EXISTS uq_managed_certificates_workspace_fingerprint_import
        ON managed_certificates(workspace_id, fingerprint_sha256)
        WHERE fingerprint_sha256 IS NOT NULL
          AND source NOT IN (
            'endpoint_monitor', 'domain_checker', 'cert_manager', 'agent_filesystem'
          );
      DROP INDEX IF EXISTS uq_managed_certificates_workspace_source_ref;
      CREATE UNIQUE INDEX IF NOT EXISTS uq_managed_certificates_workspace_source_ref
        ON managed_certificates(workspace_id, source, source_ref)
        WHERE source_ref IS NOT NULL
          AND source IN (
            'endpoint_monitor', 'domain_checker', 'cert_manager', 'agent_filesystem'
          );
      CREATE UNIQUE INDEX IF NOT EXISTS uq_certificate_targets_workspace_agent_filesystem_source_ref
        ON certificate_targets(workspace_id, source, source_ref)
        WHERE source = 'agent_filesystem' AND source_ref IS NOT NULL;

      -- B18: server-owned agent attribution + client evidence idempotency keys.
      ALTER TABLE certificate_evidence
        ADD COLUMN IF NOT EXISTS created_by_agent_id UUID NULL;
      ALTER TABLE certificate_evidence
        ADD COLUMN IF NOT EXISTS client_evidence_id TEXT NULL
          CHECK (
            client_evidence_id IS NULL OR
            (
              char_length(btrim(client_evidence_id)) BETWEEN 1 AND 128 AND
              client_evidence_id ~ '^[A-Za-z0-9_.:-]+$'
            )
          );
      ALTER TABLE certificate_evidence
        DROP CONSTRAINT IF EXISTS fk_certificate_evidence_created_by_agent;
      ALTER TABLE certificate_evidence
        ADD CONSTRAINT fk_certificate_evidence_created_by_agent
        FOREIGN KEY (created_by_agent_id)
        REFERENCES certops_agents(id)
        ON DELETE SET NULL;
      CREATE UNIQUE INDEX IF NOT EXISTS uq_certificate_evidence_agent_client_evidence_id
        ON certificate_evidence(workspace_id, created_by_agent_id, client_evidence_id)
        WHERE created_by_agent_id IS NOT NULL AND client_evidence_id IS NOT NULL;

      -- H2: bind approvals to a canonical execution intent hash (operation +
      -- subject + target + profile snapshot + payload), not only mutable payload.
      ALTER TABLE certificate_jobs
        ADD COLUMN IF NOT EXISTS approved_canonical_intent_hash CHAR(64) NULL
          CHECK (
            approved_canonical_intent_hash IS NULL OR
            approved_canonical_intent_hash ~ '^[a-f0-9]{64}$'
          );
      ALTER TABLE certops_job_approvals
        ADD COLUMN IF NOT EXISTS canonical_intent_hash CHAR(64) NULL
          CHECK (
            canonical_intent_hash IS NULL OR
            canonical_intent_hash ~ '^[a-f0-9]{64}$'
          );

      -- H3: overlapping signing-key rotation acknowledgement tracking.
      -- Existing certops_signing_keys statuses already include retiring for
      -- the previous active key; agents acknowledge the new active key via
      -- heartbeat pinned_signing_key_id.
      CREATE TABLE IF NOT EXISTS certops_signing_key_acks (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
        agent_id UUID NOT NULL REFERENCES certops_agents(id) ON DELETE CASCADE,
        signing_key_id TEXT NOT NULL
          CHECK (signing_key_id ~ '^[A-Za-z0-9_.:-]{1,128}$'),
        acknowledged_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        CONSTRAINT uq_certops_signing_key_acks_agent_key
          UNIQUE (agent_id, signing_key_id)
      );
      CREATE INDEX IF NOT EXISTS idx_certops_signing_key_acks_workspace_key
        ON certops_signing_key_acks(workspace_id, signing_key_id);

      ALTER TABLE certops_signing_keys
        ADD COLUMN IF NOT EXISTS supersedes_signing_key_id TEXT NULL
          CHECK (
            supersedes_signing_key_id IS NULL OR
            supersedes_signing_key_id ~ '^[A-Za-z0-9_.:-]{1,128}$'
          );
      ALTER TABLE certops_signing_keys
        ADD COLUMN IF NOT EXISTS rotation_started_at TIMESTAMPTZ NULL;
      ALTER TABLE certops_signing_keys
        ADD COLUMN IF NOT EXISTS rotation_forced_at TIMESTAMPTZ NULL;
      ALTER TABLE certops_signing_keys
        ADD COLUMN IF NOT EXISTS rotation_force_reason TEXT NULL
          CHECK (
            rotation_force_reason IS NULL OR
            char_length(rotation_force_reason) <= 1024
          );

      -- H12: forced retirement fences in-flight work for operator reconciliation.
      -- The status CHECK is redeclared cumulatively here (migration 26 already
      -- added dry_run_complete) so this ALTER does not silently drop it.
      ALTER TABLE certificate_jobs
        DROP CONSTRAINT IF EXISTS certificate_jobs_status_check;
      ALTER TABLE certificate_jobs
        ADD CONSTRAINT certificate_jobs_status_check CHECK (
          status IN (
            'pending_approval', 'approved', 'rejected', 'pending', 'claimed',
            'running', 'succeeded', 'failed', 'blocked', 'cancelled',
            'dry_run_complete', 'orphaned_unknown_effect'
          )
        );
      ALTER TABLE certificate_job_log
        DROP CONSTRAINT IF EXISTS certificate_job_log_status_check;
      ALTER TABLE certificate_job_log
        ADD CONSTRAINT certificate_job_log_status_check CHECK (
          status IS NULL OR status IN (
            'pending_approval', 'approved', 'rejected', 'pending', 'claimed',
            'running', 'succeeded', 'failed', 'blocked', 'cancelled',
            'dry_run_complete', 'orphaned_unknown_effect'
          )
        );
      ALTER TABLE certificate_jobs
        ADD COLUMN IF NOT EXISTS needs_operator_reconciliation BOOLEAN NOT NULL DEFAULT FALSE;
      ALTER TABLE certificate_jobs
        ADD COLUMN IF NOT EXISTS reconciliation_reason TEXT NULL
          CHECK (
            reconciliation_reason IS NULL OR
            char_length(reconciliation_reason) <= 1024
          );
      CREATE INDEX IF NOT EXISTS idx_certificate_jobs_needs_reconciliation
        ON certificate_jobs(workspace_id, needs_operator_reconciliation)
        WHERE needs_operator_reconciliation = TRUE;
    `,
  },
  {
    version: 29,
    name: "certops_agent_registration_idempotency",
    sql: `
      -- H1: durable registrationId → credential replay map so a crash after
      -- bootstrap-token consumption can still recover the issued credential.
      -- Retained for a short crash-retry window (default 7 days); expired rows
      -- are ignored by lookup and may be deleted by ops cleanup.
      CREATE TABLE IF NOT EXISTS certops_agent_registration_replays (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
        bootstrap_token_id UUID NOT NULL
          REFERENCES certops_agent_bootstrap_tokens(id) ON DELETE CASCADE,
        registration_id TEXT NOT NULL
          CHECK (registration_id ~ '^[A-Za-z0-9_.:-]{1,128}$'),
        agent_id TEXT NOT NULL
          CHECK (agent_id ~ '^[A-Za-z0-9_.:-]{1,128}$'),
        -- Plaintext credential retained ONLY for the idempotent replay window.
        -- Agents receive it once at register; this column exists so a lost
        -- response can be replayed. Rows expire via expires_at.
        credential TEXT NOT NULL
          CHECK (char_length(credential) BETWEEN 1 AND 256),
        protocol_version TEXT NOT NULL
          CHECK (protocol_version ~ '^[0-9]+\\.[0-9]+\\.[0-9]+$'),
        signing_key_id TEXT NULL
          CHECK (
            signing_key_id IS NULL OR
            signing_key_id ~ '^[A-Za-z0-9_.:-]{1,128}$'
          ),
        signing_public_key_pem TEXT NULL
          CHECK (
            signing_public_key_pem IS NULL OR
            char_length(signing_public_key_pem) <= 8192
          ),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        expires_at TIMESTAMPTZ NOT NULL,
        CONSTRAINT uq_certops_agent_registration_replays_token_registration
          UNIQUE (bootstrap_token_id, registration_id)
      );

      CREATE INDEX IF NOT EXISTS idx_certops_agent_registration_replays_expires
        ON certops_agent_registration_replays(expires_at);
      CREATE INDEX IF NOT EXISTS idx_certops_agent_registration_replays_workspace
        ON certops_agent_registration_replays(workspace_id, created_at DESC);
    `,
  },
  {
    version: 30,
    name: "certops_registration_replay_credential_encryption",
    sql: `
      -- Encrypt H1 registration-replay credentials at rest. Pre-existing
      -- plaintext rows are wiped (short-lived crash-retry window only); a
      -- retry after wipe uses a fresh bootstrap token / registration.
      ALTER TABLE certops_agent_registration_replays
        ADD COLUMN IF NOT EXISTS credential_ciphertext TEXT NULL
          CHECK (
            credential_ciphertext IS NULL OR
            (
              char_length(credential_ciphertext) BETWEEN 1 AND 2048 AND
              credential_ciphertext ~ '^[a-f0-9]+:[a-f0-9]+:[a-f0-9]+$'
            )
          );
      ALTER TABLE certops_agent_registration_replays
        ADD COLUMN IF NOT EXISTS encryption_version INTEGER NOT NULL DEFAULT 1
          CHECK (encryption_version >= 1);

      DELETE FROM certops_agent_registration_replays;

      ALTER TABLE certops_agent_registration_replays
        DROP COLUMN IF EXISTS credential;

      ALTER TABLE certops_agent_registration_replays
        ALTER COLUMN credential_ciphertext SET NOT NULL;
    `,
  },
  {
    version: 31,
    name: "certops_agents_agent_id_scoped_to_workspace",
    sql: `
      -- agent_id was globally unique across all workspaces, so two unrelated
      -- tenants who both pick a common id (e.g. "prod-web-01") could not
      -- both register: the second registration hard-fails with
      -- CERTOPS_AGENT_REGISTRATION_CONFLICT, and one workspace's bootstrap
      -- token holder could inadvertently (or deliberately) block agent
      -- registration for another workspace. Every other certops query
      -- scopes strictly by workspace_id; agent_id uniqueness now matches
      -- that pattern instead of being a global namespace.
      DROP INDEX IF EXISTS uq_certops_agents_agent_id;
      CREATE UNIQUE INDEX IF NOT EXISTS uq_certops_agents_workspace_agent_id
        ON certops_agents(workspace_id, agent_id);
    `,
  },
  {
    version: 32,
    name: "certificate_targets_target_type_agent_host",
    sql: `
      -- Migration 28 (B17) taught certificate_targets/_instances/managed_
      -- certificates about the 'agent_filesystem' source, but never widened
      -- certificate_targets_target_type_check: upsertAgentFilesystemTarget
      -- (services/certops/inventory.js) always inserts target_type =
      -- 'agent-host', which the check constraint rejected outright. Every
      -- agent filesystem-discovery evidence report has been failing with an
      -- HTTP 500 (23514 check-constraint violation) since #91/#92 shipped.
      -- Found manually re-running the real agent against a live backend.
      ALTER TABLE certificate_targets
        DROP CONSTRAINT IF EXISTS certificate_targets_target_type_check;
      ALTER TABLE certificate_targets
        ADD CONSTRAINT certificate_targets_target_type_check CHECK (
          target_type IN (
            'endpoint', 'domain', 'host', 'kubernetes-secret', 'load-balancer',
            'cdn', 'appliance', 'hsm', 'vault', 'other', 'agent-host'
          )
        );
    `,
  },
  {
    version: 33,
    name: "managed_certificates_provisioning_issuance",
    sql: `
      -- The "issue" job operation (ADR-0008) creates the managed certificate
      -- row up front, before any certificate exists, so the operator sees the
      -- pending identity in the dashboard immediately and the job has a real
      -- subject to bind to. That needs two new vocabulary values:
      --
      --   status 'provisioning' - requested, not yet issued. Non-terminal, so
      --     it counts as active for quota (active counting is
      --     status NOT IN ('revoked','decommissioned')) and it is retireable
      --     like any other live row. On a successful agent result it is
      --     reconciled to 'active' with real x509 metadata; on failure it
      --     stays 'provisioning' with the failed job and evidence attached,
      --     for the operator to retry or retire. There is no auto-cleanup.
      --   source 'agent_issuance' - this identity originated from a TokenTimer
      --     issuance request executed by an agent, as opposed to being
      --     discovered on a host ('agent_filesystem') or observed remotely.
      --
      -- Without 'provisioning', a successful agent issuance was invisible in
      -- the product: a bare manual renew job really did issue and deploy a
      -- certificate, but nothing was ever written to managed_certificates, so
      -- the operator had no certificate, no expiry tracking, and no renewal.
      -- Found during live end-to-end testing against Let's Encrypt staging.
      ALTER TABLE managed_certificates
        DROP CONSTRAINT IF EXISTS managed_certificates_status_check;
      ALTER TABLE managed_certificates
        ADD CONSTRAINT managed_certificates_status_check CHECK (
          status IN (
            'discovered', 'provisioning', 'active', 'renewing', 'expiring',
            'expired', 'revoked', 'decommissioned'
          )
        );

      ALTER TABLE managed_certificates
        DROP CONSTRAINT IF EXISTS managed_certificates_source_check;
      ALTER TABLE managed_certificates
        ADD CONSTRAINT managed_certificates_source_check CHECK (
          source IN (
            'manual', 'api', 'import', 'domain_checker', 'endpoint_monitor',
            'integration', 'auto_sync', 'cert_manager', 'agent_filesystem',
            'agent_issuance'
          )
        );

      -- Identity uniqueness for the new source. agent_issuance rows are keyed
      -- by their creating request's idempotency key, not by fingerprint: the
      -- fingerprint is unknown until the certificate actually exists, and
      -- NULL fingerprints must not collide. Mirrors the source_ref treatment
      -- migrations 28/29 gave cert_manager and agent_filesystem.
      DROP INDEX IF EXISTS uq_managed_certificates_workspace_fingerprint_import;
      CREATE UNIQUE INDEX IF NOT EXISTS uq_managed_certificates_workspace_fingerprint_import
        ON managed_certificates(workspace_id, fingerprint_sha256)
        WHERE fingerprint_sha256 IS NOT NULL
          AND source NOT IN (
            'endpoint_monitor', 'domain_checker', 'cert_manager',
            'agent_filesystem', 'agent_issuance'
          );
      DROP INDEX IF EXISTS uq_managed_certificates_workspace_source_ref;
      CREATE UNIQUE INDEX IF NOT EXISTS uq_managed_certificates_workspace_source_ref
        ON managed_certificates(workspace_id, source, source_ref)
        WHERE source_ref IS NOT NULL
          AND source IN (
            'endpoint_monitor', 'domain_checker', 'cert_manager',
            'agent_filesystem', 'agent_issuance'
          );
    `,
  },
  {
    version: 34,
    name: "certificate_jobs_issue_operation",
    sql: `
      -- Companion to migration 33. Migration 33 taught managed_certificates
      -- about the "issue" operation's row (status 'provisioning', source
      -- 'agent_issuance') but left the certificate_jobs vocabulary alone, so
      -- the job that creates that row could never be inserted: every issue
      -- request failed at COMMIT with
      -- "violates check constraint certificate_jobs_operation_check", surfacing
      -- as an opaque HTTP 500. Found by live end-to-end testing against a
      -- running stack, which is exactly the class of gap the service-layer unit
      -- tests cannot see because they stub the database.
      --
      -- "issue" is control-plane vocabulary only: signed dispatch translates it
      -- to the wire action "renew", so no agent needs to know about it and this
      -- constraint is the only schema change it requires.
      ALTER TABLE certificate_jobs
        DROP CONSTRAINT IF EXISTS certificate_jobs_operation_check;
      ALTER TABLE certificate_jobs
        ADD CONSTRAINT certificate_jobs_operation_check CHECK (
          operation IN ('issue', 'renew', 'deploy', 'reload', 'revoke', 'noop')
        );
    `,
  },
  {
    version: 35,
    name: "certops_outbox",
    sql: `
      -- Transactional outbox for CertOps side effects that must survive the
      -- transaction that decided them.
      --
      -- Before this table, a terminal renew failure resolved contacts and
      -- inserted into alert_queue inline, wrapped in a savepoint so an alert
      -- failure could never abort result ingestion. That made the two
      -- guarantees mutually exclusive: ingestion never failed, but the intent
      -- to alert was silently lost on any error (a lone log.warn, no retry, no
      -- record). Operators saw a failed job and no notification.
      --
      -- Now the deciding transaction records the intent here and nothing else:
      -- contact resolution and delivery move to a drain sweep in the certops
      -- maintenance worker. The insert is cheap and local, so it can be part of
      -- the terminal transaction proper rather than a best-effort savepoint. If
      -- it fails, the terminal transaction fails, which is the honest outcome.
      --
      -- Deliberately generic and typed rather than alert-specific: profile
      -- derivation after a successful issuance needs the same
      -- decided-here-executed-later property, and a second bespoke table would
      -- duplicate the claim/lease/backoff logic.
      CREATE TABLE IF NOT EXISTS certops_outbox (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
        event_type TEXT NOT NULL
          CHECK (event_type IN (
            'renewal_alert_requested', 'profile_derivation_requested'
          )),
        -- Caller-supplied natural key for the intent (a job id, a certificate
        -- id). Combined with event_type it makes the insert idempotent, so a
        -- retried transaction cannot enqueue the same side effect twice.
        dedupe_key TEXT NOT NULL
          CHECK (char_length(btrim(dedupe_key)) BETWEEN 1 AND 256),
        -- Ids and frozen codes only. Never payload contents, never credentials:
        -- validated per event_type and run through the key-material detector
        -- before persistence, same as every other CertOps public_metadata sink.
        payload JSONB NOT NULL DEFAULT '{}'::jsonb,
        status TEXT NOT NULL DEFAULT 'pending'
          CHECK (status IN ('pending', 'succeeded', 'skipped', 'failed')),
        -- Terminal skip/failure explanation for the operator, e.g. the
        -- no_linked_token / no_channels reasons the alert resolver returns.
        outcome_reason TEXT NULL
          CHECK (outcome_reason IS NULL OR char_length(outcome_reason) <= 256),
        attempt_count INTEGER NOT NULL DEFAULT 0
          CHECK (attempt_count >= 0),
        max_attempts INTEGER NOT NULL DEFAULT 5
          CHECK (max_attempts > 0),
        next_retry_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        last_error TEXT NULL
          CHECK (last_error IS NULL OR char_length(last_error) <= 2048),
        -- Owner-scoped lease, mirroring the worker-fleet convention
        -- (alert_queue.delivery_claim_id, migration 17): every terminal write
        -- in the drain sweep is conditional on its own claim id, so a second
        -- worker taking over an expired lease turns the first one's late
        -- writes into no-ops.
        claim_id UUID NULL,
        claimed_until TIMESTAMPTZ NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        CONSTRAINT uq_certops_outbox_workspace_id UNIQUE (workspace_id, id)
      );
      CREATE UNIQUE INDEX IF NOT EXISTS uq_certops_outbox_event_dedupe
        ON certops_outbox(workspace_id, event_type, dedupe_key);
      -- Drain-sweep scan path: due pending rows, oldest first.
      CREATE INDEX IF NOT EXISTS idx_certops_outbox_due
        ON certops_outbox(next_retry_at)
        WHERE status = 'pending';
    `,
  },
  {
    version: 36,
    name: "certops_evidence_claim_binding",
    sql: `
      -- Bind verify evidence to the exact claim that produced it.
      --
      -- Reconciliation promotes a 'provisioning' certificate to 'active' using
      -- the newest validation.passed evidence for the job. Without a claim
      -- binding that is unsafe in a way that matters: a job can be attempted
      -- more than once (requeue after a lease expiry, an operator retry), and
      -- evidence from attempt 1 outlives attempt 1. Attempt 2 could then be
      -- reconciled against a fingerprint and expiry that describe a
      -- certificate a previous attempt deployed, so the control plane would
      -- record facts that are not true of the file currently on the host.
      --
      -- claim_id is the agent's proof that it owns the current attempt: it is
      -- issued at dispatch, already travels in the result envelope, and is
      -- re-proven on ingestion. attempt_count is the server's own counter and
      -- is recorded alongside so an operator can see which attempt produced a
      -- given piece of evidence without joining back through the job history.
      ALTER TABLE certificate_evidence
        ADD COLUMN IF NOT EXISTS claim_id UUID NULL;
      ALTER TABLE certificate_evidence
        ADD COLUMN IF NOT EXISTS attempt_count INTEGER NULL
          CHECK (attempt_count IS NULL OR attempt_count >= 0);
      -- Reconciliation's lookup path: newest bound evidence for one claim.
      CREATE INDEX IF NOT EXISTS idx_certificate_evidence_job_claim
        ON certificate_evidence(workspace_id, job_id, claim_id, created_at DESC)
        WHERE claim_id IS NOT NULL;

      -- Why a provisioning certificate was NOT promoted. Reconciliation is no
      -- longer allowed to activate a row on incomplete evidence, so the
      -- operator needs the reason recorded somewhere durable rather than
      -- inferring it from an absence.
      ALTER TABLE managed_certificates
        ADD COLUMN IF NOT EXISTS reconciliation_reason TEXT NULL
          CHECK (
            reconciliation_reason IS NULL OR
            char_length(reconciliation_reason) <= 256
          );

      -- Discovery correlation. An agent that issues a certificate to a path
      -- will later scan that same path and report it as an ordinary
      -- 'agent_filesystem' find. The partial unique indexes from migration 33
      -- key the two sources differently (issuance by source_ref, filesystem by
      -- its own source_ref), so nothing stopped the same physical file from
      -- acquiring two managed_certificate identities: one 'agent_issuance' row
      -- the operator requested, and one 'agent_filesystem' row that appears
      -- later as a duplicate.
      --
      -- The deployed path plus the agent that owns it is the stable correlation
      -- key, since it is known at request time and unchanged by renewal, unlike
      -- the fingerprint. Issuance records it here, and the partial unique index
      -- below reserves the pair.
      --
      -- Recording it is only the prerequisite. The discovery ingest upsert
      -- (inventory.js) still conflicts on (workspace_id, source, source_ref) and
      -- does not read these columns, so a later 'agent_filesystem' scan of an
      -- 'agent_issuance' path still inserts a parallel row. Closing that needs a
      -- resolve-by-(agent, path) lookup ahead of the upsert; until then these
      -- columns are the recorded identity, not an enforced deduplication.
      ALTER TABLE managed_certificates
        ADD COLUMN IF NOT EXISTS deployed_cert_path TEXT NULL
          CHECK (
            deployed_cert_path IS NULL OR
            char_length(btrim(deployed_cert_path)) BETWEEN 1 AND 1024
          );
      ALTER TABLE managed_certificates
        ADD COLUMN IF NOT EXISTS deployed_agent_id UUID NULL;
      -- One identity per (agent, path). Scoped to the two agent-owned sources
      -- so remote observations, imports and cert-manager rows are unaffected.
      CREATE UNIQUE INDEX IF NOT EXISTS uq_managed_certificates_agent_deployed_path
        ON managed_certificates(workspace_id, deployed_agent_id, deployed_cert_path)
        WHERE deployed_cert_path IS NOT NULL
          AND deployed_agent_id IS NOT NULL
          AND source IN ('agent_issuance', 'agent_filesystem');

      -- Declared agent capabilities, advertised at registration alongside the
      -- existing declared_* scopes.
      --
      -- Issuance reconciliation now REQUIRES claim-bound verify evidence, and an
      -- agent that does not send claimId cannot produce it. Such an agent would
      -- run an issuance to completion and leave the certificate stuck in
      -- 'provisioning' forever, which is worse than never dispatching it. So
      -- claimability is gated on the capability rather than attempted and
      -- abandoned: an older agent keeps doing ordinary work on already-active
      -- certificates and is simply never offered issuance.
      ALTER TABLE certops_agents
        ADD COLUMN IF NOT EXISTS declared_capabilities JSONB NOT NULL
          DEFAULT '[]'::jsonb;
    `,
  },
  {
    version: 37,
    name: "domain_monitors_workspace_url_dedup",
    sql: `
      -- Duplicate endpoint monitors for the same URL (POST .../domains had no
      -- existing-URL lookup before its own insert) each earn their own
      -- distinct id, so managed_certificates' (workspace_id, source,
      -- source_ref) unique index (migration 15,
      -- certops_managed_certificate_monitor_identity) never sees a conflict
      -- between them - source_ref is the monitor's own id, and two
      -- different monitor rows for one URL both look "valid" to it. The
      -- real gap is one level up: domain_monitors itself has never had a
      -- uniqueness check on (workspace_id, url). Deduplicate existing
      -- monitor rows first (keep the newest per URL, same
      -- updated_at/created_at/id DESC convergence, plus a token-linked
      -- preference so an existing token stays attached), carrying over each
      -- loser's certificate lifecycle state (D7 retire-first, same rule
      -- migration 15 used) and job/evidence history onto the keeper's own
      -- managed_certificates row before the loser rows are dropped, then add
      -- the unique index that makes this class of duplicate impossible
      -- again.
      WITH url_keepers AS (
        SELECT DISTINCT ON (workspace_id, url)
               workspace_id, url, id AS keeper_id
          FROM domain_monitors
         ORDER BY workspace_id, url,
                  (token_id IS NOT NULL) DESC, updated_at DESC, created_at DESC, id DESC
      ),
      url_losers AS (
        SELECT dm.workspace_id, dm.id AS loser_id, k.keeper_id
          FROM domain_monitors dm
          JOIN url_keepers k
            ON k.workspace_id = dm.workspace_id AND k.url = dm.url
         WHERE dm.id <> k.keeper_id
      )
      -- Backfill a token link onto the keeper if it has none but a loser
      -- does (should not happen given the ordering above, but cheap
      -- insurance against losing a real token link either way).
      UPDATE domain_monitors k
         SET token_id = l.token_id, updated_at = NOW()
        FROM url_losers ul
        JOIN domain_monitors l ON l.id = ul.loser_id
       WHERE k.id = ul.keeper_id
         AND k.token_id IS NULL
         AND l.token_id IS NOT NULL;

      -- D7 retire-first: a terminal lifecycle status ('revoked' or
      -- 'decommissioned') on a losing monitor's certificate must not be
      -- discarded just because the keeper's own certificate row is not
      -- terminal. source_ref has no FK (polymorphic text/uuid identity
      -- column), so this join is by value, not constraint.
      WITH url_keepers AS (
        SELECT DISTINCT ON (workspace_id, url)
               workspace_id, url, id AS keeper_id
          FROM domain_monitors
         ORDER BY workspace_id, url,
                  (token_id IS NOT NULL) DESC, updated_at DESC, created_at DESC, id DESC
      ),
      url_losers AS (
        SELECT dm.workspace_id, dm.id AS loser_id, k.keeper_id
          FROM domain_monitors dm
          JOIN url_keepers k
            ON k.workspace_id = dm.workspace_id AND k.url = dm.url
         WHERE dm.id <> k.keeper_id
      ),
      terminal_losers AS (
        SELECT DISTINCT ON (ul.workspace_id, ul.keeper_id)
               ul.workspace_id, ul.keeper_id, mc.status AS terminal_status
          FROM managed_certificates mc
          JOIN url_losers ul
            ON ul.workspace_id = mc.workspace_id
           AND ul.loser_id::text = mc.source_ref
         WHERE mc.source IN ('endpoint_monitor', 'domain_checker')
           AND mc.status IN ('revoked', 'decommissioned')
         ORDER BY ul.workspace_id, ul.keeper_id,
                  mc.updated_at DESC, mc.created_at DESC, mc.id DESC
      )
      UPDATE managed_certificates mc
         SET status = t.terminal_status
        FROM terminal_losers t
       WHERE mc.workspace_id = t.workspace_id
         AND mc.source IN ('endpoint_monitor', 'domain_checker')
         AND mc.source_ref = t.keeper_id::text
         AND mc.status NOT IN ('revoked', 'decommissioned');

      -- Re-point certificate_jobs/certificate_evidence history (FK-less text
      -- pair, subject_type = 'managed_certificate') from a loser monitor's
      -- certificate row onto the keeper's, mirroring migration 15's own
      -- re-pointing precedent - covers the unlikely case that a job or
      -- evidence row was ever created against a monitor-sourced (never
      -- agent-deployable) certificate.
      WITH url_keepers AS (
        SELECT DISTINCT ON (workspace_id, url)
               workspace_id, url, id AS keeper_id
          FROM domain_monitors
         ORDER BY workspace_id, url,
                  (token_id IS NOT NULL) DESC, updated_at DESC, created_at DESC, id DESC
      ),
      url_losers AS (
        SELECT dm.workspace_id, dm.id AS loser_id, k.keeper_id
          FROM domain_monitors dm
          JOIN url_keepers k
            ON k.workspace_id = dm.workspace_id AND k.url = dm.url
         WHERE dm.id <> k.keeper_id
      ),
      cert_pairs AS (
        SELECT loser_mc.workspace_id, loser_mc.id AS loser_mc_id, keeper_mc.id AS keeper_mc_id
          FROM url_losers ul
          JOIN managed_certificates loser_mc
            ON loser_mc.workspace_id = ul.workspace_id
           AND loser_mc.source_ref = ul.loser_id::text
           AND loser_mc.source IN ('endpoint_monitor', 'domain_checker')
          JOIN managed_certificates keeper_mc
            ON keeper_mc.workspace_id = ul.workspace_id
           AND keeper_mc.source_ref = ul.keeper_id::text
           AND keeper_mc.source IN ('endpoint_monitor', 'domain_checker')
      )
      UPDATE certificate_jobs cj
         SET subject_id = cp.keeper_mc_id::text
        FROM cert_pairs cp
       WHERE cj.workspace_id = cp.workspace_id
         AND cj.subject_type = 'managed_certificate'
         AND cj.subject_id = cp.loser_mc_id::text;

      WITH url_keepers AS (
        SELECT DISTINCT ON (workspace_id, url)
               workspace_id, url, id AS keeper_id
          FROM domain_monitors
         ORDER BY workspace_id, url,
                  (token_id IS NOT NULL) DESC, updated_at DESC, created_at DESC, id DESC
      ),
      url_losers AS (
        SELECT dm.workspace_id, dm.id AS loser_id, k.keeper_id
          FROM domain_monitors dm
          JOIN url_keepers k
            ON k.workspace_id = dm.workspace_id AND k.url = dm.url
         WHERE dm.id <> k.keeper_id
      ),
      cert_pairs AS (
        SELECT loser_mc.workspace_id, loser_mc.id AS loser_mc_id, keeper_mc.id AS keeper_mc_id
          FROM url_losers ul
          JOIN managed_certificates loser_mc
            ON loser_mc.workspace_id = ul.workspace_id
           AND loser_mc.source_ref = ul.loser_id::text
           AND loser_mc.source IN ('endpoint_monitor', 'domain_checker')
          JOIN managed_certificates keeper_mc
            ON keeper_mc.workspace_id = ul.workspace_id
           AND keeper_mc.source_ref = ul.keeper_id::text
           AND keeper_mc.source IN ('endpoint_monitor', 'domain_checker')
      )
      UPDATE certificate_evidence ce
         SET subject_id = cp.keeper_mc_id::text
        FROM cert_pairs cp
       WHERE ce.workspace_id = cp.workspace_id
         AND ce.subject_type = 'managed_certificate'
         AND ce.subject_id = cp.loser_mc_id::text;

      -- Drop each loser monitor's own managed_certificates row - its
      -- lifecycle-relevant state, if any, was already carried onto the
      -- keeper's row above.
      WITH url_keepers AS (
        SELECT DISTINCT ON (workspace_id, url)
               workspace_id, url, id AS keeper_id
          FROM domain_monitors
         ORDER BY workspace_id, url,
                  (token_id IS NOT NULL) DESC, updated_at DESC, created_at DESC, id DESC
      ),
      url_losers AS (
        SELECT dm.workspace_id, dm.id AS loser_id, k.keeper_id
          FROM domain_monitors dm
          JOIN url_keepers k
            ON k.workspace_id = dm.workspace_id AND k.url = dm.url
         WHERE dm.id <> k.keeper_id
      )
      DELETE FROM managed_certificates mc
       USING url_losers ul
       WHERE mc.workspace_id = ul.workspace_id
         AND mc.source IN ('endpoint_monitor', 'domain_checker')
         AND mc.source_ref = ul.loser_id::text;

      -- Drop the loser monitor rows themselves.
      WITH url_keepers AS (
        SELECT DISTINCT ON (workspace_id, url)
               workspace_id, url, id AS keeper_id
          FROM domain_monitors
         ORDER BY workspace_id, url,
                  (token_id IS NOT NULL) DESC, updated_at DESC, created_at DESC, id DESC
      )
      DELETE FROM domain_monitors dm
       USING url_keepers k
       WHERE dm.workspace_id = k.workspace_id
         AND dm.url = k.url
         AND dm.id <> k.keeper_id;

      CREATE UNIQUE INDEX IF NOT EXISTS uq_domain_monitors_workspace_url
        ON domain_monitors(workspace_id, url);
    `,
  },
  {
    version: 38,
    name: "managed_certificates_cross_source_monitor_dedup",
    sql: `
      -- Domain Checker and Endpoint Monitor each mint their own
      -- managed_certificates row keyed by (source, source_ref) - "domain_checker"
      -- keys on the discovered certificate's own id/hostname, "endpoint_monitor"
      -- keys on the domain_monitors row id - so migration 15's
      -- (workspace_id, source, source_ref) unique index never sees these as the
      -- same identity even when they are the same real endpoint: Domain Checker
      -- discovers a hostname first (with "Also create endpoint monitors" off),
      -- then a user later manually adds that same hostname as an endpoint
      -- monitor (or the reverse order), and the certificate shows up twice in
      -- the Certificate operations list forever after. The application-level
      -- fix (this migration's companion change in monitorBridge.js) makes new
      -- observations reuse whatever managed_certificate a PRIOR observation -
      -- from any source - already created for the same domain_monitors row,
      -- found via certificate_instances.domain_monitor_id (a column
      -- managed_certificates itself does not have). This migration merges
      -- pre-existing duplicates the same way, keeping the newest row per
      -- (workspace_id, domain_monitor_id) group - the same
      -- updated_at/created_at/id DESC convergence used by every dedup migration
      -- in this file - and carrying over lifecycle state and history exactly as
      -- migration 15 did for its own (source, source_ref) merge.
      --
      -- Materialized once into a temp table: re-deriving the keeper/loser
      -- pairs from certificate_instances after the first UPDATE below
      -- re-points those very rows would make every loser look like it was
      -- already merged (no remaining instances pointing at it), silently
      -- orphaning loser managed_certificates rows instead of deleting them.
      CREATE TEMP TABLE tmp_monitor_cert_pairs AS
      WITH monitor_cert_links AS (
        SELECT DISTINCT ci.workspace_id, ci.domain_monitor_id, ci.managed_certificate_id AS mc_id
          FROM certificate_instances ci
         WHERE ci.domain_monitor_id IS NOT NULL
      ),
      monitor_cert_groups AS (
        SELECT l.workspace_id, l.domain_monitor_id, l.mc_id,
               mc.updated_at, mc.created_at
          FROM monitor_cert_links l
          JOIN managed_certificates mc
            ON mc.workspace_id = l.workspace_id AND mc.id = l.mc_id
      ),
      keepers AS (
        SELECT DISTINCT ON (workspace_id, domain_monitor_id)
               workspace_id, domain_monitor_id, mc_id AS keeper_mc_id
          FROM monitor_cert_groups
         ORDER BY workspace_id, domain_monitor_id,
                  updated_at DESC, created_at DESC, mc_id DESC
      )
      SELECT DISTINCT g.workspace_id, g.mc_id AS loser_mc_id, k.keeper_mc_id
        FROM monitor_cert_groups g
        JOIN keepers k
          ON k.workspace_id = g.workspace_id AND k.domain_monitor_id = g.domain_monitor_id
       WHERE g.mc_id <> k.keeper_mc_id;

      -- Collision detection must also include the KEEPER's own pre-existing
      -- instances, not just the losers': Domain Checker and Endpoint Monitor
      -- share one certificate_targets row per domain_monitor_id
      -- (findOrCreateTarget in monitorBridge.js keys the lookup on
      -- domain_monitor_id), so when both sources observed the same live
      -- certificate, the keeper's own instance and a loser's instance
      -- already agree on (target_id, observed_fingerprint_sha256) before
      -- this migration ever runs. Scanning losers alone missed that
      -- collision, so the UPDATE below - which re-points loser rows onto the
      -- keeper's managed_certificate_id - hit
      -- uq_certificate_instances_target_cert_fingerprint the moment a loser
      -- row collided with a keeper row nobody had checked against. Unioning
      -- keeper + loser instances into one partition lets the ORDER BY
      -- tiebreaker rank the keeper's own row first and drop the duplicate
      -- loser row up front instead of during the re-point.
      WITH combined_instances AS (
        SELECT DISTINCT ci.id, ci.workspace_id, ci.target_id,
               ci.observed_fingerprint_sha256, ci.managed_certificate_id,
               ci.updated_at, ci.created_at, cp.keeper_mc_id
          FROM certificate_instances ci
          JOIN tmp_monitor_cert_pairs cp
            ON cp.workspace_id = ci.workspace_id
           AND ci.managed_certificate_id IN (cp.loser_mc_id, cp.keeper_mc_id)
         WHERE ci.observed_fingerprint_sha256 IS NOT NULL
      ),
      colliding_instances AS (
        SELECT id,
               ROW_NUMBER() OVER (
                 PARTITION BY workspace_id, target_id, keeper_mc_id,
                              observed_fingerprint_sha256
                 ORDER BY (managed_certificate_id = keeper_mc_id) DESC,
                          updated_at DESC, created_at DESC, id DESC
               ) AS rn
          FROM combined_instances
      )
      DELETE FROM certificate_instances
       WHERE id IN (SELECT id FROM colliding_instances WHERE rn > 1);

      UPDATE certificate_instances ci
         SET managed_certificate_id = cp.keeper_mc_id
        FROM tmp_monitor_cert_pairs cp
       WHERE ci.workspace_id = cp.workspace_id
         AND ci.managed_certificate_id = cp.loser_mc_id;

      -- D7 retire-first: a terminal lifecycle status on a losing row must not
      -- be discarded just because the keeper is not terminal.
      WITH terminal_losers AS (
        SELECT DISTINCT ON (cp.workspace_id, cp.keeper_mc_id)
               cp.workspace_id, cp.keeper_mc_id, mc.status AS terminal_status
          FROM managed_certificates mc
          JOIN tmp_monitor_cert_pairs cp
            ON cp.workspace_id = mc.workspace_id AND cp.loser_mc_id = mc.id
         WHERE mc.status IN ('revoked', 'decommissioned')
         ORDER BY cp.workspace_id, cp.keeper_mc_id,
                  mc.updated_at DESC, mc.created_at DESC, mc.id DESC
      )
      UPDATE managed_certificates mc
         SET status = t.terminal_status
        FROM terminal_losers t
       WHERE mc.workspace_id = t.workspace_id
         AND mc.id = t.keeper_mc_id
         AND mc.status NOT IN ('revoked', 'decommissioned');

      -- Re-point certificate_jobs/certificate_evidence history (FK-less text
      -- pair, subject_type = 'managed_certificate') from a loser row to the
      -- keeper's, mirroring migration 15's own re-pointing precedent.
      UPDATE certificate_jobs cj
         SET subject_id = cp.keeper_mc_id::text
        FROM tmp_monitor_cert_pairs cp
       WHERE cj.workspace_id = cp.workspace_id
         AND cj.subject_type = 'managed_certificate'
         AND cj.subject_id = cp.loser_mc_id::text;

      UPDATE certificate_evidence ce
         SET subject_id = cp.keeper_mc_id::text
        FROM tmp_monitor_cert_pairs cp
       WHERE ce.workspace_id = cp.workspace_id
         AND ce.subject_type = 'managed_certificate'
         AND ce.subject_id = cp.loser_mc_id::text;

      -- Drop the now-fully-merged loser managed_certificates rows.
      DELETE FROM managed_certificates mc
       USING tmp_monitor_cert_pairs cp
       WHERE mc.workspace_id = cp.workspace_id
         AND mc.id = cp.loser_mc_id;

      DROP TABLE tmp_monitor_cert_pairs;
    `,
  },
  {
    version: 39,
    name: "certops_agents_capabilities_freshness_epoch",
    sql: `
      -- ADR-0012 decision 17: certops_agents.declared_capabilities had no
      -- epoch and no freshness check at claim time. An agent downgraded to a
      -- build that stops sending a capability (or never re-sends one) could
      -- keep matching capability-gated jobs on an assertion of unbounded
      -- age, because heartbeat's own three-valued semantics (absent
      -- preserves, explicit [] clears, non-empty replaces - unchanged by
      -- this migration) have no notion of "how long ago was this last
      -- asserted".
      --
      -- capabilities_updated_at is written by INSERT at registration
      -- (always, since registration always sends a declared_capabilities
      -- value, defaulting to an empty array) and by the heartbeat UPDATE on
      -- every write that touches declared_capabilities, including a no-op
      -- replace where the new value equals the old one - because the write
      -- is itself a fresh assertion "this is still my current set as of
      -- right now", independent of whether the set changed.
      --
      -- Deliberately NOT backfilled here. A migration cannot know when an
      -- already-existing row's currently-stored capability set was actually
      -- asserted, so stamping NOW() at migration time would manufacture a
      -- false freshness signal for a set that could in truth be arbitrarily
      -- stale - precisely the failure this column exists to close,
      -- reintroduced at its own birth. Existing rows migrate with
      -- capabilities_updated_at IS NULL, and the claim-time freshness
      -- predicate (CERTOPS_CAPABILITY_FRESHNESS_MS, agentDispatch.js) treats
      -- NULL as maximally stale: such a row is offered no capability-gated
      -- job until its next heartbeat that reports capabilities sets this
      -- column for the first time. This is the only DDL for existing rows;
      -- no migration-time UPDATE touches this column's value.
      ALTER TABLE certops_agents
        ADD COLUMN IF NOT EXISTS capabilities_updated_at TIMESTAMPTZ NULL;
    `,
  },
  {
    version: 40,
    name: "certops_diagnostic_agent_isolation",
    sql: `
      -- Diagnostic-agent isolation surface (ADR-0012 decisions 2 and 7).
      --
      -- protocol_smoke is a dedicated wire action used only to test agent
      -- protocol connectivity (claim/verify/report) without performing any
      -- certificate work: no keygen, no ACME order, no filesystem write. It
      -- is always dispatched with mode = 'dry_run' and, per the existing
      -- mode/status guard above (certops_job_mode_and_dry_run_complete),
      -- can therefore never terminate as 'succeeded' -- only
      -- 'dry_run_complete' or 'rejected'.
      ALTER TABLE certificate_jobs
        DROP CONSTRAINT IF EXISTS certificate_jobs_operation_check;
      ALTER TABLE certificate_jobs
        ADD CONSTRAINT certificate_jobs_operation_check CHECK (
          operation IN (
            'issue', 'renew', 'deploy', 'reload', 'revoke', 'noop',
            'protocol_smoke'
          )
        );

      -- agent_kind is server-assigned exactly once, at row creation, and is
      -- never updated afterward: there is deliberately no UPDATE path that
      -- changes it for an existing agent. This makes it a trustworthy trust
      -- boundary in a way declared_capabilities (client-supplied on every
      -- register/heartbeat) can never be: dispatch keys the protocol_smoke
      -- gate on this column, not on anything the agent itself asserts, so
      -- a normal agent cannot make itself eligible for a diagnostic job (or
      -- vice versa) by lying about what it supports.
      ALTER TABLE certops_agents
        ADD COLUMN IF NOT EXISTS agent_kind TEXT NOT NULL DEFAULT 'normal';
      ALTER TABLE certops_agents
        DROP CONSTRAINT IF EXISTS certops_agents_agent_kind_check;
      ALTER TABLE certops_agents
        ADD CONSTRAINT certops_agents_agent_kind_check CHECK (
          agent_kind IN ('normal', 'diagnostic')
        );
      CREATE INDEX IF NOT EXISTS idx_certops_agents_workspace_agent_kind
        ON certops_agents(workspace_id, agent_kind, status);
    `,
  },
  {
    version: 41,
    name: "certops_diagnostic_bootstrap_requests",
    sql: `
      -- Single-use, non-replayable record for the session-authenticated
      -- diagnostic-bootstrap endpoint (POST .../certops/agents/diagnostic-bootstrap).
      --
      -- Unlike certops_agent_registration_replays (which deliberately DOES
      -- replay a lost response for a machine-credential register call),
      -- a diagnostic bootstrap must never silently reissue
      -- {agentId, credential, job}: a retried request with the same
      -- request_id has to fail with diagnostic_bootstrap_already_consumed.
      -- The UNIQUE(workspace_id, request_id) index below is what makes that
      -- true: the row is inserted and the agent + smoke job are created in
      -- the same transaction, so a second attempt with the same request_id
      -- hits the unique constraint before anything else happens, and can
      -- never observe (or create) a half-finished bootstrap.
      --
      -- expires_at is retained as a documented 15-minute request window and
      -- as a future janitor-cleanup boundary for this audit trail; it is
      -- not a re-arm mechanism, because a consumed row is never deleted and
      -- the UNIQUE index makes single-use permanent, which is a strictly
      -- stronger guarantee than "usable again after 15 minutes".
      CREATE TABLE IF NOT EXISTS certops_diagnostic_bootstrap_requests (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
        request_id TEXT NOT NULL
          CHECK (char_length(btrim(request_id)) BETWEEN 1 AND 128),
        requested_by_user_id INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
        agent_row_id UUID NULL,
        job_id UUID NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        CONSTRAINT fk_certops_diagnostic_bootstrap_agent
          FOREIGN KEY (workspace_id, agent_row_id)
          REFERENCES certops_agents(workspace_id, id)
          ON DELETE SET NULL (agent_row_id),
        CONSTRAINT fk_certops_diagnostic_bootstrap_job
          FOREIGN KEY (workspace_id, job_id)
          REFERENCES certificate_jobs(workspace_id, id)
          ON DELETE SET NULL (job_id)
      );
      CREATE UNIQUE INDEX IF NOT EXISTS uq_certops_diagnostic_bootstrap_workspace_request
        ON certops_diagnostic_bootstrap_requests(workspace_id, request_id);
      CREATE INDEX IF NOT EXISTS idx_certops_diagnostic_bootstrap_expires
        ON certops_diagnostic_bootstrap_requests(expires_at);
    `,
  },
  {
    version: 42,
    name: "certops_windows_iis_target_descriptors",
    sql: `
      -- Windows execution surface (ADR-0012 decisions 1, 9, 10): an IIS
      -- deploy destination is a machine certificate store plus a site
      -- binding (site, port, optional SNI host), keyed on thumbprint rather
      -- than a filesystem path. certificate_targets is where every other
      -- target-type-specific descriptor already lives (hostname, url,
      -- deployment_reference), so these columns join that set rather than
      -- starting a parallel table: a windows-iis row is still one
      -- certificate_targets row, just with a different subset of columns
      -- populated, the same shape every other target_type already uses.
      --
      -- All four columns are nullable and unconstrained against target_type
      -- at the database layer: enforcing "populated only for windows-iis" as
      -- a CHECK would need a multi-column conditional CHECK that duplicates
      -- the validation validateTargetConfig (packages/agent/src/deploy) and
      -- renewalProfile.js's validateTarget already own, and having both
      -- enforce it invites them to drift. The database stores; the service
      -- layer validates.
      --
      -- windows_site's bound is expressed as an unbounded character-class
      -- match plus a separate char_length() check rather than a single
      -- '{1,256}' interval: PostgreSQL's regex engine rejects a bounded
      -- repetition count above 255 outright ("invalid regular expression:
      -- invalid repetition count(s)"), so a single-interval '{1,256}' CHECK
      -- would fail to compile on every single non-null insert or update,
      -- never actually evaluating true or false. Verified directly against
      -- a real Postgres 17 instance. windows_store's 1-64 bound and
      -- windows_sni_host's 0-61 bounds are both well under the limit and
      -- compile fine; only a 256 bound is affected. This is the same split
      -- certops_trust_anchors.name (below) already uses for its own 1-255
      -- bound.
      ALTER TABLE certificate_targets
        ADD COLUMN IF NOT EXISTS windows_store TEXT NULL
          CHECK (windows_store IS NULL OR windows_store ~ '^[A-Za-z0-9 _.-]{1,64}$'),
        ADD COLUMN IF NOT EXISTS windows_site TEXT NULL
          CHECK (
            windows_site IS NULL
            OR (
              windows_site ~ '^[A-Za-z0-9 _.:-]+$'
              AND char_length(windows_site) BETWEEN 1 AND 256
            )
          ),
        ADD COLUMN IF NOT EXISTS windows_port INTEGER NULL
          CHECK (windows_port IS NULL OR windows_port BETWEEN 1 AND 65535),
        ADD COLUMN IF NOT EXISTS windows_sni_host TEXT NULL
          CHECK (
            windows_sni_host IS NULL
            OR windows_sni_host ~ '^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$'
          );

      -- "windows-iis" joins the target_type vocabulary the same way every
      -- earlier target type did (see the certificate_targets_source_check
      -- pattern above): widen the enum additively, never CREATE TYPE.
      ALTER TABLE certificate_targets
        DROP CONSTRAINT IF EXISTS certificate_targets_target_type_check;
      ALTER TABLE certificate_targets
        ADD CONSTRAINT certificate_targets_target_type_check CHECK (
          target_type IN (
            'endpoint', 'domain', 'host', 'kubernetes-secret',
            'load-balancer', 'cdn', 'appliance', 'hsm', 'vault', 'other',
            'agent-host', 'windows-iis'
          )
        );
    `,
  },
  {
    version: 43,
    name: "certops_trust_anchors",
    sql: `
      -- Trust-anchor persistence shape (ADR-0012 decisions 4-6), groundwork
      -- for trust distribution execution (a later change). Two tables,
      -- matching the ADR's split between what a trust anchor IS and where
      -- it has been installed:
      --
      -- certops_trust_anchors: one row per distinct root/intermediate CA
      -- certificate a workspace has approved for distribution, identified by
      -- its SHA-256 fingerprint. This is the approved-material record, not a
      -- per-host installation record: it carries no host/store columns of
      -- its own (those belong on certops_trust_anchor_installations below),
      -- because the same anchor is meant to be distributed to many hosts,
      -- and pinning it to one host/store here would force a duplicate anchor
      -- row per destination for the same CA certificate.
      --
      -- certops_trust_anchor_installations: one row per (host, store,
      -- fingerprint, owner) tuple, tracking whether that specific anchor is
      -- actually present in that specific machine trust store on that
      -- specific host, who put it there, and its current transition state.
      -- A single trust anchor can be distributed to many hosts, and a single
      -- host can receive many anchors, so this is the join, not a foreign key
      -- on certops_trust_anchors.
      --
      -- Both tables are additive and carry no execution logic: nothing in
      -- this migration creates jobs, dispatches to agents, or runs
      -- netsh/WebAdministration/IISAdministration calls (ADR-0012's "these
      -- are implementation choices, not contract" rule applies here too).
      CREATE TABLE IF NOT EXISTS certops_trust_anchors (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
        name TEXT NOT NULL
          CHECK (char_length(btrim(name)) BETWEEN 1 AND 255),
        -- The approved CA certificate itself (ADR-0012 decision 6). Read
        -- back only at signed-dispatch time to attach to a distribute-trust
        -- job's payload -- never through the general job-creation
        -- persistence boundary, which rejects any "pem"-named field in a
        -- job's stored payload/metadata (jobs.js's
        -- FORBIDDEN_KEY_BEARING_FIELD_FRAGMENTS) the same way it already
        -- does for a certificate deploy's certificatePem.
        pem TEXT NOT NULL
          CHECK (pem ~ '^-----BEGIN CERTIFICATE-----'),
        anchor_type TEXT NOT NULL
          CHECK (anchor_type IN ('root', 'intermediate')),
        fingerprint_sha256 TEXT NOT NULL
          CHECK (fingerprint_sha256 ~ '^[a-f0-9]{64}$'),
        subject_common_name TEXT NULL
          CHECK (subject_common_name IS NULL OR char_length(btrim(subject_common_name)) BETWEEN 1 AND 255),
        status TEXT NOT NULL DEFAULT 'active'
          CHECK (status IN ('active', 'revoked')),
        source TEXT NOT NULL DEFAULT 'api'
          CHECK (source IN ('api', 'system')),
        public_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_by INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        revoked_at TIMESTAMPTZ NULL,
        CONSTRAINT uq_certops_trust_anchors_workspace_id UNIQUE (workspace_id, id)
      );
      CREATE INDEX IF NOT EXISTS idx_certops_trust_anchors_workspace
        ON certops_trust_anchors(workspace_id);
      -- One approved-material row per distinct CA certificate per workspace:
      -- re-approving the same fingerprint updates the existing row rather
      -- than creating a duplicate "same CA, second row" record.
      CREATE UNIQUE INDEX IF NOT EXISTS uq_certops_trust_anchors_workspace_fingerprint
        ON certops_trust_anchors(workspace_id, fingerprint_sha256);

      CREATE TABLE IF NOT EXISTS certops_trust_anchor_installations (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
        trust_anchor_id UUID NOT NULL,
        host TEXT NOT NULL
          CHECK (char_length(btrim(host)) BETWEEN 1 AND 255),
        store TEXT NOT NULL
          CHECK (store ~ '^[A-Za-z0-9 _.-]{1,64}$'),
        fingerprint_sha256 TEXT NOT NULL
          CHECK (fingerprint_sha256 ~ '^[a-f0-9]{64}$'),
        owner TEXT NOT NULL
          CHECK (char_length(btrim(owner)) BETWEEN 1 AND 128),
        -- Durable transition-state: an install/remove is dispatched to an
        -- agent and only reaches its terminal state (installed/removed) once
        -- the agent reports success, mirroring how certificate_jobs never
        -- assumes an in-flight operation succeeded.
        transition_state TEXT NOT NULL DEFAULT 'pending_install'
          CHECK (transition_state IN ('pending_install', 'installed', 'pending_remove', 'removed')),
        -- Provenance: was this anchor already present in the store before
        -- TokenTimer touched it (discovered, not installed by us) or did
        -- TokenTimer put it there. A 'removed' installation must never
        -- delete a 'preexisting' anchor a different owner relies on; this
        -- column is how a revoke path would tell the two apart.
        provenance TEXT NOT NULL
          CHECK (provenance IN ('preexisting', 'tokentimer_installed')),
        public_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        CONSTRAINT fk_certops_trust_anchor_installations_anchor
          FOREIGN KEY (workspace_id, trust_anchor_id)
          REFERENCES certops_trust_anchors(workspace_id, id)
          ON DELETE CASCADE
      );
      CREATE INDEX IF NOT EXISTS idx_certops_trust_anchor_installations_workspace
        ON certops_trust_anchor_installations(workspace_id);
      CREATE INDEX IF NOT EXISTS idx_certops_trust_anchor_installations_anchor
        ON certops_trust_anchor_installations(workspace_id, trust_anchor_id);
      -- One ownership row per (host, store, fingerprint, owner) tuple, per
      -- the ADR's persistence shape: the same anchor installed by two
      -- different owners on the same host/store is two rows, each tracking
      -- its own transition state and provenance independently.
      CREATE UNIQUE INDEX IF NOT EXISTS uq_certops_trust_anchor_installations_identity
        ON certops_trust_anchor_installations(workspace_id, host, store, fingerprint_sha256, owner);
    `,
  },
  {
    version: 44,
    name: "certops_trust_anchor_jobs",
    sql: `
      -- Trust-anchor operations (ADR-0012 decisions 4-6 and 14): a job that
      -- installs (distribute-trust) or removes (revoke-trust) a CA
      -- certificate from a machine trust store. A trust anchor has no
      -- private key and no renewal, so this is a distinct operation family
      -- from every certificate operation already in this CHECK, and
      -- 'trust_anchor' is a distinct subject_type from every certificate
      -- subject already in that CHECK, referencing a
      -- certops_trust_anchors.id (cast to text) rather than a
      -- managed_certificates.id.
      -- This re-adds certificate_jobs_operation_check with the union of
      -- every operation any migration has ever named, not just this one's:
      -- migration 40 added 'protocol_smoke' to the same constraint, and a
      -- DROP/ADD here that only listed this migration's own two new values
      -- would silently regress that support the moment this migration runs
      -- after it.
      ALTER TABLE certificate_jobs
        DROP CONSTRAINT IF EXISTS certificate_jobs_operation_check;
      ALTER TABLE certificate_jobs
        ADD CONSTRAINT certificate_jobs_operation_check CHECK (
          operation IN (
            'issue', 'renew', 'deploy', 'reload', 'revoke', 'noop',
            'protocol_smoke', 'distribute-trust', 'revoke-trust'
          )
        );
      ALTER TABLE certificate_jobs
        DROP CONSTRAINT IF EXISTS certificate_jobs_subject_type_check;
      ALTER TABLE certificate_jobs
        ADD CONSTRAINT certificate_jobs_subject_type_check CHECK (
          subject_type IS NULL OR subject_type IN (
            'managed_certificate', 'certificate_instance', 'certificate_target',
            'token', 'domain', 'endpoint', 'external', 'trust_anchor'
          )
        );

      -- certificate_evidence (ADR-0012 decision 15) has its own separate
      -- subject_type CHECK, defined on the column itself back in migration
      -- 13 (certops_jobs_evidence_schema), so widening certificate_jobs's
      -- constraint above does nothing for it: without this ALTER, the
      -- first piece of evidence written against a trust_anchor subject
      -- (or a trust.distributed/trust.revoked event) would violate this
      -- table's own CHECK at runtime, not certificate_jobs's. Both column
      -- CHECKs were auto-named table_column_check since neither was given
      -- an explicit CONSTRAINT name at CREATE TABLE time.
      ALTER TABLE certificate_evidence
        DROP CONSTRAINT IF EXISTS certificate_evidence_subject_type_check;
      ALTER TABLE certificate_evidence
        ADD CONSTRAINT certificate_evidence_subject_type_check CHECK (
          subject_type IS NULL OR subject_type IN (
            'managed_certificate', 'certificate_instance', 'certificate_target',
            'token', 'domain', 'endpoint', 'external', 'trust_anchor'
          )
        );
      ALTER TABLE certificate_evidence
        DROP CONSTRAINT IF EXISTS certificate_evidence_evidence_type_check;
      ALTER TABLE certificate_evidence
        ADD CONSTRAINT certificate_evidence_evidence_type_check CHECK (
          evidence_type IN (
            'certificate.observed', 'deployment.checked', 'deployment.updated',
            'validation.passed', 'validation.failed', 'policy.checked',
            'trust.distributed', 'trust.revoked'
          )
        );
    `,
  },
  {
    version: 45,
    name: "certops_agent_observation_locality_and_downtime_alerts",
    sql: `
      -- Generalized observation locality for Windows/OS-store certificates and
      -- persistent observed locations. agent_filesystem stays
      -- exactly as it was (filePath-oriented); a new distinct source,
      -- agent_windows, carries non-filesystem locations (Windows machine
      -- certificate store, IIS bindings, http.sys SSL bindings) through the
      -- SAME managed_certificate -> certificate_target -> certificate_instance
      -- pipeline rather than a parallel model. location_kind is the
      -- fine-grained discriminator the UI/API need to render "Type" (Location
      -- kind) distinctly from target_type/source; it is nullable so every
      -- pre-existing row (endpoint/domain/import/etc., and pre-migration
      -- agent_filesystem rows) resolves safely to null/unknown rather than
      -- requiring a backfill.
      ALTER TABLE certificate_targets
        ADD COLUMN IF NOT EXISTS location_kind TEXT NULL
          CHECK (
            location_kind IS NULL OR location_kind IN (
              'filesystem', 'windows_store', 'iis_binding', 'http_sys'
            )
          );
      ALTER TABLE certificate_instances
        ADD COLUMN IF NOT EXISTS location_kind TEXT NULL
          CHECK (
            location_kind IS NULL OR location_kind IN (
              'filesystem', 'windows_store', 'iis_binding', 'http_sys'
            )
          );

      ALTER TABLE managed_certificates
        DROP CONSTRAINT IF EXISTS managed_certificates_source_check;
      ALTER TABLE managed_certificates
        ADD CONSTRAINT managed_certificates_source_check CHECK (
          source IN (
            'manual', 'api', 'import', 'domain_checker', 'endpoint_monitor',
            'integration', 'auto_sync', 'cert_manager', 'agent_filesystem',
            'agent_issuance', 'agent_windows'
          )
        );
      ALTER TABLE certificate_targets
        DROP CONSTRAINT IF EXISTS certificate_targets_source_check;
      ALTER TABLE certificate_targets
        ADD CONSTRAINT certificate_targets_source_check CHECK (
          source IN (
            'manual', 'api', 'import', 'domain_checker', 'endpoint_monitor',
            'integration', 'auto_sync', 'cert_manager', 'agent_filesystem',
            'agent_windows'
          )
        );
      ALTER TABLE certificate_instances
        DROP CONSTRAINT IF EXISTS certificate_instances_source_check;
      ALTER TABLE certificate_instances
        ADD CONSTRAINT certificate_instances_source_check CHECK (
          source IN (
            'manual', 'api', 'import', 'domain_checker', 'endpoint_monitor',
            'integration', 'auto_sync', 'cert_manager', 'agent_filesystem',
            'agent_windows'
          )
        );

      DROP INDEX IF EXISTS uq_managed_certificates_workspace_source_ref;
      CREATE UNIQUE INDEX IF NOT EXISTS uq_managed_certificates_workspace_source_ref
        ON managed_certificates(workspace_id, source, source_ref)
        WHERE source_ref IS NOT NULL
          AND source IN (
            'endpoint_monitor', 'domain_checker', 'cert_manager',
            'agent_filesystem', 'agent_issuance', 'agent_windows'
          );
      -- Same widening for the companion fingerprint-identity index: without
      -- this, two agent_windows rows sharing one fingerprint (the same
      -- certificate bound to two IIS sites, observed via two distinct
      -- source_refs) would collide on this OTHER unique index even though
      -- their (source, source_ref) identity above is perfectly distinct.
      DROP INDEX IF EXISTS uq_managed_certificates_workspace_fingerprint_import;
      CREATE UNIQUE INDEX IF NOT EXISTS uq_managed_certificates_workspace_fingerprint_import
        ON managed_certificates(workspace_id, fingerprint_sha256)
        WHERE fingerprint_sha256 IS NOT NULL
          AND source NOT IN (
            'endpoint_monitor', 'domain_checker', 'cert_manager',
            'agent_filesystem', 'agent_issuance', 'agent_windows'
          );
      CREATE UNIQUE INDEX IF NOT EXISTS uq_certificate_targets_workspace_agent_windows_source_ref
        ON certificate_targets(workspace_id, source, source_ref)
        WHERE source = 'agent_windows' AND source_ref IS NOT NULL;

      -- Windows-observed deployments are real deployment locations for
      -- renewal-path purposes, same as agent_filesystem/cert_manager.
      -- renewalAdoption.js's countCertificateDeploymentLocations reads this
      -- set at query time (no stored list to keep in sync).

      -- Per-agent downtime alert settings.
      -- alertsEnabled defaults to true (consistent with the endpoint-health
      -- alerting default of "on unless explicitly turned off");
      -- contact_group_id is workspace-scoped free reference, resolved the
      -- same way endpoint/domain alerts resolve contact_group_id (fallback to
      -- the workspace default contact group at send time, not stored here).
      --
      -- Delivery settings live on the agent. Outage incident state is kept in
      -- the dedicated durable incident table introduced by the forward
      -- migration that follows the alert-queue anchor migration.
      ALTER TABLE certops_agents
        ADD COLUMN IF NOT EXISTS downtime_alerts_enabled BOOLEAN NOT NULL DEFAULT TRUE;
      ALTER TABLE certops_agents
        ADD COLUMN IF NOT EXISTS contact_group_id TEXT NULL;

      -- Bootstrap tokens carry the requested alert settings so they can be
      -- copied onto the agent row at registration time (the agent row does
      -- not exist yet when the Deploy Agent modal creates the token).
      -- Nullable: a token created before this migration has both columns
      -- NULL, and registration treats NULL alertsEnabled as "use the
      -- system default (enabled)" -- see agentDispatch.js registerAgent.
      ALTER TABLE certops_agent_bootstrap_tokens
        ADD COLUMN IF NOT EXISTS downtime_alerts_enabled BOOLEAN NULL;
      ALTER TABLE certops_agent_bootstrap_tokens
        ADD COLUMN IF NOT EXISTS contact_group_id TEXT NULL;
    `,
  },
  {
    version: 46,
    name: "alert_queue_agent_health_anchor",
    sql: `
      -- Agent-down/recovery notifications use the same alert_queue and
      -- delivery-worker pipeline as endpoint_health and cert_renewal_failed.
      -- Those two existing alert types both anchor on
      -- alert_queue.token_id (a tokens row), because every existing alert is
      -- ultimately "about" a certificate/token. An agent is not about a
      -- certificate, so forcing it through a synthetic/hidden tokens row would
      -- either pollute the Certificates UI or require new hidden-category
      -- filtering everywhere that lists tokens -- worse than the alternative:
      -- loosen the NOT NULL and add a second, parallel anchor column.
      -- token_id remains the anchor for every alert type that has one; this
      -- only widens the CHECK to also accept certops_agent_id as an anchor, so
      -- every pre-existing row (which always has token_id) is untouched.
      ALTER TABLE alert_queue
        ALTER COLUMN token_id DROP NOT NULL;
      ALTER TABLE alert_queue
        ADD COLUMN IF NOT EXISTS certops_agent_id UUID NULL
          REFERENCES certops_agents(id) ON DELETE CASCADE;
      ALTER TABLE alert_queue
        DROP CONSTRAINT IF EXISTS alert_queue_anchor_check;
      ALTER TABLE alert_queue
        ADD CONSTRAINT alert_queue_anchor_check
          CHECK (token_id IS NOT NULL OR certops_agent_id IS NOT NULL);
      CREATE INDEX IF NOT EXISTS idx_alert_queue_certops_agent_id
        ON alert_queue(certops_agent_id);

      -- Agent-health alerts have no linked tokens/domain_monitors row to
      -- render from (unlike endpoint_health/cert_renewal_failed, which read
      -- name/location/issuer straight off the joined token). metadata carries
      -- everything the delivery-worker content builders need (agent identity,
      -- last-seen, impacted auto-renew certificates) frozen at the moment the
      -- transition was detected, so delivery never has to re-join
      -- certops_agents for rendering. Generic (not agent-specific) and
      -- defaulted to '{}' so it is safe for every pre-existing alert type to
      -- leave unset.
      ALTER TABLE alert_queue
        ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::jsonb;
    `,
  },
  {
    version: 47,
    name: "agent_health_incidents_and_alert_anchor_xor",
    sql: `
      -- Refuse to hide pre-existing ambiguous anchors. All normal alert
      -- producers use token_id and agent-health alerts use certops_agent_id.
      DO $$
      BEGIN
        IF EXISTS (
          SELECT 1
            FROM alert_queue
           WHERE (token_id IS NULL) = (certops_agent_id IS NULL)
        ) THEN
          RAISE EXCEPTION
            'alert_queue contains rows that do not have exactly one anchor';
        END IF;
      END
      $$;

      ALTER TABLE alert_queue
        DROP CONSTRAINT IF EXISTS alert_queue_anchor_check;
      ALTER TABLE alert_queue
        ADD CONSTRAINT alert_queue_anchor_check CHECK (
          (token_id IS NOT NULL) <> (certops_agent_id IS NOT NULL)
        );

      -- An open row is durable recovery intent. It is created in the same
      -- transaction that flips an agent offline and removed only after the
      -- recovery transition has been queued or deliberately suppressed.
      CREATE TABLE IF NOT EXISTS certops_agent_health_incidents (
        agent_id UUID PRIMARY KEY
          REFERENCES certops_agents(id) ON DELETE CASCADE,
        workspace_id UUID NOT NULL
          REFERENCES workspaces(id) ON DELETE CASCADE,
        opened_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        last_seen_at TIMESTAMPTZ NULL,
        down_alert_key TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        CONSTRAINT fk_certops_agent_health_incidents_workspace_agent
          FOREIGN KEY (workspace_id, agent_id)
          REFERENCES certops_agents(workspace_id, id) ON DELETE CASCADE
      );
      CREATE INDEX IF NOT EXISTS idx_certops_agent_health_incidents_workspace
        ON certops_agent_health_incidents(workspace_id, opened_at);

      -- Preserve recovery intent for outages opened before this table
      -- existed. Only the canonical per-agent DOWN key represents an open
      -- incident; unrelated agent-anchored alerts are not backfilled.
      INSERT INTO certops_agent_health_incidents (
        agent_id, workspace_id, opened_at, last_seen_at, down_alert_key
      )
      SELECT a.id,
             a.workspace_id,
             aq.created_at,
             a.last_seen_at,
             aq.alert_key
        FROM alert_queue aq
        JOIN certops_agents a ON a.id = aq.certops_agent_id
       WHERE aq.alert_key = 'agent_health:' || a.id::text || ':down'
      ON CONFLICT (agent_id) DO NOTHING;
    `,
  },
  {
    version: 48,
    name: "certops_trust_anchor_installation_agent_linkage",
    sql: `
      -- ADR-0012 decision 20: migration 43's installation row identified
      -- itself by free-text (host, store, fingerprint, owner) alone, with
      -- no link to the certops_agents row that holds it or the job that
      -- last dispatched a transition against it. That can't distinguish a
      -- legitimate concurrent transition from a crashed one, and gives a
      -- reconciliation sweep no fleet row to dispatch against.
      --
      -- Precondition: this table has no write path anywhere in the
      -- codebase yet, so it must be empty in any real deployment. Asserted
      -- rather than assumed (matching migration 47's guard style): a NOT
      -- NULL FK added onto a populated table would otherwise silently
      -- backfill every row under a fabricated agent_id/provenance value.
      DO $$
      BEGIN
        IF EXISTS (SELECT 1 FROM certops_trust_anchor_installations) THEN
          RAISE EXCEPTION
            'certops_trust_anchor_installations must be empty before agent_id can be added NOT NULL: found existing rows';
        END IF;
      END
      $$;

      -- agent_id replaces host as the installation's join key. host stays
      -- as a display/audit snapshot only, and drops out of the uniqueness
      -- tuple below. Added nullable, then tightened to NOT NULL in the
      -- same migration (gated by the emptiness check above).
      ALTER TABLE certops_trust_anchor_installations
        ADD COLUMN IF NOT EXISTS agent_id UUID NULL;
      ALTER TABLE certops_trust_anchor_installations
        ALTER COLUMN agent_id SET NOT NULL;
      ALTER TABLE certops_trust_anchor_installations
        DROP CONSTRAINT IF EXISTS fk_certops_trust_anchor_installations_agent;
      ALTER TABLE certops_trust_anchor_installations
        ADD CONSTRAINT fk_certops_trust_anchor_installations_agent
        FOREIGN KEY (workspace_id, agent_id)
        REFERENCES certops_agents(workspace_id, id)
        ON DELETE CASCADE;
      -- Immutable after insert: enforced in services (migration 27's
      -- executor_kind precedent), not by a DB trigger. Reassigning
      -- ownership to a different agent is a new row, never an UPDATE here.

      -- One unique row per (agent, store, fingerprint, owner), replacing
      -- migration 43's (host, store, fingerprint, owner) tuple.
      DROP INDEX IF EXISTS uq_certops_trust_anchor_installations_identity;
      CREATE UNIQUE INDEX IF NOT EXISTS uq_certops_trust_anchor_installations_identity
        ON certops_trust_anchor_installations(workspace_id, agent_id, store, fingerprint_sha256, owner);

      -- Linkage to the certops job that last touched this row. Nullable: a
      -- row can exist before any job has ever been dispatched against it.
      ALTER TABLE certops_trust_anchor_installations
        ADD COLUMN IF NOT EXISTS last_job_id UUID NULL;
      ALTER TABLE certops_trust_anchor_installations
        DROP CONSTRAINT IF EXISTS fk_certops_trust_anchor_installations_last_job;
      ALTER TABLE certops_trust_anchor_installations
        ADD CONSTRAINT fk_certops_trust_anchor_installations_last_job
        FOREIGN KEY (workspace_id, last_job_id)
        REFERENCES certificate_jobs(workspace_id, id)
        ON DELETE SET NULL (last_job_id);

      -- Idempotency and stale-result rejection (decision 20c/20e): each
      -- dispatched transition is stamped with the generation it was
      -- created for; a job result may only advance that same generation.
      -- DEFAULT 1 means "row created, nothing dispatched yet";
      -- runCreateTrustJob bumps this on every job it creates, so a row's
      -- first dispatched transition actually carries generation 2.
      ALTER TABLE certops_trust_anchor_installations
        ADD COLUMN IF NOT EXISTS transition_generation INTEGER NOT NULL DEFAULT 1
          CHECK (transition_generation >= 1);

      ALTER TABLE certops_trust_anchor_installations
        ADD COLUMN IF NOT EXISTS last_attempt_at TIMESTAMPTZ NULL;

      -- Sanitized failure category only, never raw exception text or a
      -- stack trace: diagnostic metadata, not an error log.
      ALTER TABLE certops_trust_anchor_installations
        ADD COLUMN IF NOT EXISTS last_error TEXT NULL
          CHECK (last_error IS NULL OR char_length(last_error) <= 128);

      -- Reconciliation-sweep scheduling (decision 20f/20h): when a pending
      -- row is next due for revalidation. NULL means not currently scheduled.
      ALTER TABLE certops_trust_anchor_installations
        ADD COLUMN IF NOT EXISTS next_reconcile_at TIMESTAMPTZ NULL;

      CREATE INDEX IF NOT EXISTS idx_certops_trust_anchor_installations_agent
        ON certops_trust_anchor_installations(workspace_id, agent_id);
      CREATE INDEX IF NOT EXISTS idx_certops_trust_anchor_installations_last_job
        ON certops_trust_anchor_installations(workspace_id, last_job_id)
        WHERE last_job_id IS NOT NULL;
      CREATE INDEX IF NOT EXISTS idx_certops_trust_anchor_installations_next_reconcile
        ON certops_trust_anchor_installations(next_reconcile_at)
        WHERE next_reconcile_at IS NOT NULL;
    `,
  },
  {
    version: 49,
    name: "certops_trust_reference_release_idempotency",
    sql: `
      -- runCreateTrustJob's two "no real job" revoke-trust branches
      -- (otherLiveReferences > 0, and provenance = 'preexisting') mutate the
      -- installation row and write an audit event, then return before
      -- createCertificateJob ever runs - so the idempotency machinery on
      -- certificate_jobs (idempotency_key + creation_request_hash, migration
      -- 20/37) never sees these calls at all. Without a durable record of
      -- our own, a caller retrying the exact same idempotencyKey re-bumps
      -- transition_generation and re-writes the audit event on every retry,
      -- and a late-enough retry can even fall through into a different
      -- branch entirely once the state it originally observed has changed.
      --
      -- This table is a small, purpose-built idempotency ledger for those
      -- two branches only: one row per (workspace, idempotencyKey), storing
      -- the installation snapshot the ORIGINAL call returned so a replay can
      -- return the identical response without touching the installation row
      -- or writing another audit event. See
      -- recordTrustReferenceReleaseIdempotency /
      -- findTrustReferenceReleaseIdempotencyRecord in trustAnchors.js.
      CREATE TABLE IF NOT EXISTS certops_trust_reference_release_idempotency (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
        trust_anchor_id UUID NOT NULL,
        agent_id UUID NOT NULL,
        store TEXT NOT NULL
          CHECK (store ~ '^[A-Za-z0-9 _.-]{1,64}$'),
        owner TEXT NOT NULL
          CHECK (char_length(btrim(owner)) BETWEEN 1 AND 128),
        -- Reserved for future no-job branches; only 'revoke-trust' is
        -- written today.
        operation TEXT NOT NULL
          CHECK (operation IN ('distribute-trust', 'revoke-trust')),
        idempotency_key TEXT NOT NULL
          CHECK (char_length(idempotency_key) BETWEEN 1 AND 255),
        installation_snapshot JSONB NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
      -- One outcome per (workspace, idempotencyKey): a replay looks itself
      -- up by key alone, then verifies the tuple below still matches before
      -- trusting the cached snapshot.
      CREATE UNIQUE INDEX IF NOT EXISTS uq_certops_trust_reference_release_idempotency_key
        ON certops_trust_reference_release_idempotency(workspace_id, idempotency_key);
      CREATE INDEX IF NOT EXISTS idx_certops_trust_reference_release_idempotency_tuple
        ON certops_trust_reference_release_idempotency(workspace_id, trust_anchor_id, agent_id, store, owner);
    `,
  },
  {
    version: 50,
    name: "import_cleanup_scan_provenance",
    sql: `
      -- Per-instance/owner provenance for imported tokens. NULL on every
      -- pre-existing row (legacy tokens cannot be safely backfilled from the
      -- old free-text "location" column alone) and populated going forward
      -- by the source identity resolver on every import/auto-sync path.
      -- source_owner_key is an immutable principal id (e.g. a numeric
      -- GitHub/GitLab user or repo id, an AWS/GCP/Azure account or project
      -- id) -- never a mutable display name -- so cleanup matching never
      -- depends on something a user can rename. source_owner_display is
      -- kept separately for UI only.
      --
      -- source_owner_key is NOT NULL DEFAULT '' rather than nullable:
      -- Postgres treats NULL as distinct in unique indexes, which would
      -- silently defeat uq_tokens_source_identity below for every provider
      -- using the '' ownership sentinel (Vault/AWS/Azure/Azure AD/GCP).
      ALTER TABLE tokens
        ADD COLUMN IF NOT EXISTS source_provider TEXT NULL,
        ADD COLUMN IF NOT EXISTS source_instance TEXT NULL,
        ADD COLUMN IF NOT EXISTS source_owner_key TEXT NOT NULL DEFAULT '',
        ADD COLUMN IF NOT EXISTS source_owner_display TEXT NULL,
        ADD COLUMN IF NOT EXISTS source_kind TEXT NULL,
        ADD COLUMN IF NOT EXISTS source_dimensions JSONB NULL,
        ADD COLUMN IF NOT EXISTS source_object_id TEXT NULL,
        ADD COLUMN IF NOT EXISTS source_observed_at TIMESTAMPTZ NULL;

      -- Upsert identity for provenance-aware imports: one row per distinct
      -- upstream object per workspace/provider/instance/owner/kind. Legacy
      -- rows (source_object_id IS NULL) are intentionally excluded rather
      -- than backfilled -- see integration_scans below.
      CREATE UNIQUE INDEX IF NOT EXISTS uq_tokens_source_identity
        ON tokens (workspace_id, source_provider, source_instance, source_owner_key, source_kind, source_object_id)
        WHERE source_object_id IS NOT NULL;

      -- Cleanup candidate-selection scope (provider+instance+owner+kind),
      -- used by the anti-join in importCleanup.js.
      CREATE INDEX IF NOT EXISTS idx_tokens_source_scope
        ON tokens (workspace_id, source_provider, source_instance, source_owner_key, source_kind);

      -- One row per completed (or attempted) scan. cleanup_scope records,
      -- per source kind/dimension actually scanned, whether that sub-scope
      -- was fully enumerated ("complete") or degraded (truncated/errored) --
      -- the authoritative contract cleanup checks before deleting anything.
      -- cleanup_consumed_at is the single-use claim: a scan can drive at
      -- most one destructive cleanup.
      CREATE TABLE IF NOT EXISTS integration_scans (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
        provider TEXT NOT NULL,
        source_instance TEXT NOT NULL,
        source_owner_key TEXT NOT NULL,
        started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        completed_at TIMESTAMPTZ NULL,
        cleanup_scope JSONB NOT NULL DEFAULT '{}'::jsonb,
        cleanup_consumed_at TIMESTAMPTZ NULL,
        created_by INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_integration_scans_scope
        ON integration_scans(workspace_id, provider, source_instance, source_owner_key);

      -- Metadata-only record of every item a scan actually rediscovered
      -- (never secret material). Import binds client-submitted items to a
      -- real row here by (scan_id, source_kind, source_object_id) instead of
      -- trusting whatever provenance the client claims, and cleanup's
      -- anti-join uses this table to find tokens NOT rediscovered.
      CREATE TABLE IF NOT EXISTS integration_scan_items (
        id BIGSERIAL PRIMARY KEY,
        scan_id UUID NOT NULL REFERENCES integration_scans(id) ON DELETE CASCADE,
        source_kind TEXT NOT NULL,
        source_object_id TEXT NOT NULL,
        source_dimensions JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
      CREATE UNIQUE INDEX IF NOT EXISTS uq_integration_scan_items_identity
        ON integration_scan_items(scan_id, source_kind, source_object_id);
      CREATE INDEX IF NOT EXISTS idx_integration_scan_items_scan
        ON integration_scan_items(scan_id);

      -- connection_key lets a future multi-config-per-provider workspace
      -- distinguish auto-sync configs pointing at different instances of
      -- the same provider. cleanup_obsolete makes scheduled-sync cleanup an
      -- explicit per-config opt-in, matching manual import's opt-in cleanup
      -- checkbox rather than being implied by scan_params.
      ALTER TABLE auto_sync_configs
        ADD COLUMN IF NOT EXISTS connection_key TEXT NULL,
        ADD COLUMN IF NOT EXISTS cleanup_obsolete BOOLEAN NOT NULL DEFAULT FALSE;
    `,
  },
];

async function runMigrations() {
  logger.info("Starting database migrations...");

  const dbReady = await waitForDatabase();
  if (!dbReady) {
    logger.error(
      "Database is not available. Please ensure PostgreSQL is running.",
    );
    process.exit(1);
  }

  const client = await migrationPool.connect();
  try {
    logger.info("Creating migrations table if it doesn't exist...");

    await client.query(`
      CREATE TABLE IF NOT EXISTS migrations (
        version INTEGER PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        executed_at TIMESTAMP DEFAULT NOW()
      );
    `);

    const result = await client.query(
      "SELECT version FROM migrations ORDER BY version",
    );
    const executedVersions = result.rows.map((row) => row.version);
    logger.info(`Found ${executedVersions.length} executed migrations`, {
      versions: executedVersions,
    });

    let migrationsRun = 0;
    for (const migration of migrations) {
      if (!executedVersions.includes(migration.version)) {
        logger.info(
          `Running migration ${migration.version}: ${migration.name}`,
        );
        await client.query("BEGIN");
        try {
          await client.query(migration.sql);
          await client.query(
            "INSERT INTO migrations (version, name) VALUES ($1, $2)",
            [migration.version, migration.name],
          );
          await client.query("COMMIT");
          logger.info(`Migration ${migration.version} completed successfully`);
          migrationsRun++;
        } catch (error) {
          await client.query("ROLLBACK");
          logger.error(`Migration ${migration.version} failed:`, error.message);
          throw error;
        }
      } else {
        logger.info(`Migration ${migration.version} already executed`);
      }
    }

    if (migrationsRun > 0)
      logger.info(`${migrationsRun} new migrations completed successfully`);
    else logger.info("All migrations are up to date");
  } catch (error) {
    logger.error("Migration process failed:", error);
    process.exit(1);
  } finally {
    client.release();
  }
}

if (require.main === module) {
  runMigrations().finally(() => migrationPool.end());
}

module.exports = { runMigrations, migrations };
