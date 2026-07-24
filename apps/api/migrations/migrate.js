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
