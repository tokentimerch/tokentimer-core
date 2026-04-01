const { Pool } = require("pg");
const fs = require("fs");
const { logger } = require("../utils/logger");

const caPath = process.env.PGSSLROOTCERT;
const sslMode = process.env.DB_SSL;
const hasCA = !!caPath;
const sslConfig =
  sslMode === "verify" || hasCA
    ? {
        ca: hasCA ? fs.readFileSync(caPath, "utf8") : undefined,
        rejectUnauthorized: true,
        minVersion: "TLSv1.3",
      }
    : sslMode === "require"
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
