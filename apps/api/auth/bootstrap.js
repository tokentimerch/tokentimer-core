/**
 * Admin Bootstrap - Initialize first admin user on startup
 *
 * On-premise deployments need a secure way to create the initial admin.
 * This runs on startup and creates the admin if no users exist.
 */

const bcrypt = require("bcryptjs");
const { v4: uuidv4 } = require("uuid");
const { canonicalizeEmail } = require("../db/models/User");

function normalizeEnvCredential(value) {
  if (typeof value !== "string") return "";
  const trimmed = value.trim();
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'"))
  ) {
    return trimmed.slice(1, -1).trim();
  }
  return trimmed;
}

/**
 * Bootstrap initial admin user if none exists
 * @param {Pool} pool - Database pool
 * @returns {Promise<{created: boolean, admin: object|null}>}
 */
async function bootstrapAdmin(pool) {
  try {
    // Check if any users exist
    const usersResult = await pool.query(
      "SELECT COUNT(*)::int as count FROM users",
    );
    const userCount = usersResult.rows[0].count;

    if (userCount > 0) {
      console.log("Users already exist, skipping admin bootstrap");
      return { created: false, admin: null };
    }

    // Get admin credentials from environment
    const rawAdminEmail = process.env.ADMIN_EMAIL;
    const rawAdminPassword = process.env.ADMIN_PASSWORD;
    const rawAdminName = process.env.ADMIN_NAME;
    const adminEmail = normalizeEnvCredential(rawAdminEmail);
    const adminPassword = normalizeEnvCredential(rawAdminPassword);
    const adminName = normalizeEnvCredential(rawAdminName) || "Administrator";

    if (!adminEmail || !adminPassword) {
      console.error(
        "CRITICAL: No users exist and ADMIN_EMAIL/ADMIN_PASSWORD not set!",
      );
      console.error(
        "Set ADMIN_EMAIL and ADMIN_PASSWORD environment variables to create the initial admin.",
      );
      throw new Error("Admin credentials required for initial setup");
    }

    // Validate password strength
    if (adminPassword.length < 8) {
      throw new Error("ADMIN_PASSWORD must be at least 8 characters");
    }

    if (rawAdminEmail && rawAdminEmail !== adminEmail) {
      console.warn("ADMIN_EMAIL normalized from environment value");
    }
    if (rawAdminPassword && rawAdminPassword !== adminPassword) {
      console.warn("ADMIN_PASSWORD normalized from environment value");
    }

    console.log("Creating initial admin user...");

    // Hash password
    const passwordHash = await bcrypt.hash(adminPassword, 12);

    const canonicalEmail = canonicalizeEmail(adminEmail);

    // Create admin user
    const userResult = await pool.query(
      `INSERT INTO users (email, email_original, password_hash, display_name, auth_method, email_verified, is_admin)
       VALUES ($1, $2, $3, $4, 'local', TRUE, TRUE)
       RETURNING id, email, display_name`,
      [canonicalEmail, adminEmail, passwordHash, adminName],
    );

    const admin = userResult.rows[0];

    // Create admin workspace
    const workspaceId = uuidv4();
    await pool.query(
      `INSERT INTO workspaces (id, name, plan, created_by)
       VALUES ($1, $2, 'oss', $3)`,
      [workspaceId, `${adminName}'s Workspace`, admin.id],
    );

    // Add admin as workspace admin
    await pool.query(
      `INSERT INTO workspace_memberships (user_id, workspace_id, role)
       VALUES ($1, $2, 'admin')`,
      [admin.id, workspaceId],
    );

    // Create workspace settings
    await pool.query(
      `INSERT INTO workspace_settings (workspace_id, delivery_window_start, delivery_window_end, delivery_window_tz)
       VALUES ($1, '00:00', '23:59', 'UTC')`,
      [workspaceId],
    );

    console.log("Initial admin user created successfully");
    console.log(`   Email: ${adminEmail}`);
    console.log(
      `   Login at: ${process.env.APP_URL || "http://localhost:5173"}/login`,
    );
    console.log("");
    console.log(
      "IMPORTANT: Remove ADMIN_PASSWORD from environment after first login!",
    );
    console.log("   The admin can invite other users from the dashboard.");

    return { created: true, admin };
  } catch (error) {
    console.error("Failed to bootstrap admin:", error.message);
    throw error;
  }
}

module.exports = { bootstrapAdmin };
