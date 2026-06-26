"use strict";

const CERTOPS_DISABLED = "CERTOPS_DISABLED";

function defaultPool() {
  return require("../../db/database").pool;
}

function parseBoolean(value) {
  if (typeof value === "boolean") return value;
  if (typeof value !== "string") return null;
  const normalized = value.trim().toLowerCase();
  if (["1", "true", "yes", "on", "enabled"].includes(normalized)) return true;
  if (["0", "false", "no", "off", "disabled"].includes(normalized)) return false;
  return null;
}

function envCertOpsEnabled(env = process.env) {
  return parseBoolean(env.CERTOPS_ENABLED);
}

async function dbCertOpsEnabled(dbPool = defaultPool()) {
  try {
    const { rows } = await dbPool.query(
      "SELECT certops_settings FROM system_settings WHERE id = 1",
    );
    const settings = rows[0]?.certops_settings;
    if (!settings || typeof settings !== "object") return null;
    return parseBoolean(settings.enabled);
  } catch (err) {
    if (err?.code === "42P01" || err?.code === "42703") return null;
    throw err;
  }
}

async function isCertOpsEnabled({ dbPool = defaultPool(), env = process.env } = {}) {
  const envValue = envCertOpsEnabled(env);
  if (envValue !== null) return envValue;

  const dbValue = await dbCertOpsEnabled(dbPool);
  if (dbValue !== null) return dbValue;

  return false;
}

module.exports = {
  CERTOPS_DISABLED,
  dbCertOpsEnabled,
  envCertOpsEnabled,
  isCertOpsEnabled,
  parseBoolean,
};
