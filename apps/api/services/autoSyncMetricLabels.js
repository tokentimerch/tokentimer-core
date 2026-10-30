"use strict";

const { createHash } = require("node:crypto");

const OPTIONAL_LABELS = ["configuration_name", "monitoring_group", "kind", "asset_name", "project", "group"];
const systemSettings = require("./systemSettings");
systemSettings.registerJsonColumn("auto_sync_metrics", { envMap: { enabled: "AUTO_SYNC_METRICS_ENABLED", labels: null }, validate: metricSettingsError });
const DEFAULT_SYSTEM_LABELS = ["configuration_name", "monitoring_group", "kind"];
const HIGH_CARDINALITY_LABELS = ["asset_name", "project", "group"];
function permittedExtraLabels(env = process.env, storedPolicy) {
  const raw = String(env.AUTO_SYNC_METRICS_EXTRA_LABELS || "").trim();
  const requested = raw ? raw.split(",").map(label => label.trim()) : (storedPolicy?.labels || []);
  if (!Array.isArray(requested) || requested.includes("none")) return [];
  return HIGH_CARDINALITY_LABELS.filter(label => requested.includes(label));
}
function deploymentMetricLabelOptions(env = process.env) {
  return { extra_labels: String(env.AUTO_SYNC_METRICS_EXTRA_LABELS || "").trim() ? permittedExtraLabels(env) : [...HIGH_CARDINALITY_LABELS],
    extra_labels_locked: Boolean(String(env.AUTO_SYNC_METRICS_EXTRA_LABELS || "").trim()) };
}

const KNOWN_KINDS = new Set([
  "aws-acm", "aws-iam-key", "aws-secrets-manager", "azure-ad-certificate", "azure-ad-client-secret",
  "azure-ad-sp-certificate", "azure-ad-sp-secret", "azure-key-vault-certificate", "azure-key-vault-key",
  "azure-key-vault-secret", "gcp-certificate-manager-cert", "gcp-compute-ssl-cert", "gcp-secret-manager",
  "github-deploy-key", "github-secret", "github-ssh-key", "gitlab-deploy-token", "gitlab-group-token",
  "gitlab-pat", "gitlab-project-token", "gitlab-ssh-key", "gitlab-trigger-token", "vault-kv", "vault-pki",
]);

function metricSettingsError(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return "Invalid metric settings";
  if (Object.keys(value).some(key => !["enabled", "labels", "monitoring_group", "inherit_system"].includes(key))) return "Unknown metric setting";
  if (value.inherit_system !== undefined && typeof value.inherit_system !== "boolean") return "Invalid inheritance flag";
  if (value.enabled !== undefined && typeof value.enabled !== "boolean") return "Invalid metric exposure flag";
  if (value.labels !== undefined && (!Array.isArray(value.labels) || value.labels.length > OPTIONAL_LABELS.length ||
      new Set(value.labels).size !== value.labels.length || value.labels.some(label => !OPTIONAL_LABELS.includes(label)))) return "Invalid metric labels";
  if (value.monitoring_group !== undefined && (typeof value.monitoring_group !== "string" ||
      value.monitoring_group.length > 64 || /[\x00-\x1f\x7f]/u.test(value.monitoring_group))) return "Monitoring group must contain at most 64 characters without control characters";
  return null;
}
function normalizeMetricSettings(value = {}) {
  const error = metricSettingsError(value);
  if (error) throw new Error(error);
  return { enabled: value.enabled === true, labels: [...(value.labels || [])].sort(),
    monitoring_group: (value.monitoring_group || "").trim(),
    ...(value.inherit_system !== undefined ? { inherit_system: value.inherit_system } : {}) };
}
function systemMetricPolicy(stored = {}, env = process.env) {
  const raw = typeof env.AUTO_SYNC_METRICS_ENABLED === "string" ? env.AUTO_SYNC_METRICS_ENABLED.trim() : "";
  const enabled = raw ? raw.toLowerCase() === "true" : typeof stored?.enabled === "boolean" ? stored.enabled : null;
  const configured = Array.isArray(stored?.labels) ? OPTIONAL_LABELS.filter(label => stored.labels.includes(label)) : DEFAULT_SYSTEM_LABELS;
  const permitted = permittedExtraLabels(env, stored);
  const labels = String(env.AUTO_SYNC_METRICS_EXTRA_LABELS || "").trim()
    ? [...configured.filter(label => !HIGH_CARDINALITY_LABELS.includes(label)), ...permitted] : configured;
  return { enabled, labels: labels.filter(label => !HIGH_CARDINALITY_LABELS.includes(label) || permitted.includes(label)),
    locked: Boolean(raw), source: raw ? "env" : typeof stored?.enabled === "boolean" ? "database" : null };
}
async function readSystemMetricPolicy(db) {
  const { rows } = await db.query("SELECT auto_sync_metrics FROM system_settings WHERE id = 1");
  return systemMetricPolicy(rows[0]?.auto_sync_metrics);
}
function effectiveMetricSettings(value, env = process.env, storedPolicy) {
  const settings = normalizeMetricSettings(value);
  const policy = systemMetricPolicy(storedPolicy, env);
  const inherits = settings.inherit_system === true || (settings.inherit_system !== false && !settings.enabled);
  settings.enabled = policy.enabled === false ? false : inherits ? policy.enabled === true : settings.enabled;
  if (inherits) settings.labels = policy.labels;
  else if (policy.enabled !== null) settings.labels = settings.labels.filter(label => policy.labels.includes(label));
  const permitted = permittedExtraLabels(env, storedPolicy);
  settings.labels = settings.labels.filter(label => !HIGH_CARDINALITY_LABELS.includes(label) || permitted.includes(label));
  return settings;
}
function metadata(value) { return typeof value === "string" && value.length <= 512 ? value : ""; }
function metricSourceDimensions(item) {
  return { project: metadata(item.project_path || item.project_name || item.repository || item.projectId),
    group: metadata(item.group_path || item.group_name) };
}
function creationDimensions(payload, settings, env = process.env, policy) {
  const selected = effectiveMetricSettings(settings, env, policy);
  const exposes = label => selected.enabled && selected.labels.includes(label);
  return { kind: KNOWN_KINDS.has(payload.source_kind) ? payload.source_kind : "other",
    asset_name: exposes("asset_name") ? metadata(payload.name) : "",
    project: exposes("project") ? metadata(payload.source_dimensions?.project) : "",
    group: exposes("group") ? metadata(payload.source_dimensions?.group) : "" };
}
async function recordCreationMetrics(client, context, payload, settings, policy) {
  const dimensions = creationDimensions(payload, settings, process.env, policy);
  await client.query(`INSERT INTO auto_sync_kind_stats (provider, kind, items_created_total)
    VALUES ($1, $2, 1) ON CONFLICT (provider, kind) DO UPDATE
    SET items_created_total = auto_sync_kind_stats.items_created_total + 1`, [context.provider, dimensions.kind]);
  await client.query(`INSERT INTO auto_sync_creation_stats
    (config_id, kind, asset_name, project, group_name, dimension_key, items_created_total, last_created_at)
    VALUES ($1, $2, $3, $4, $5, $6, 1, NOW())
    ON CONFLICT (config_id, dimension_key) DO UPDATE
    SET items_created_total = auto_sync_creation_stats.items_created_total + 1, last_created_at = NOW()`,
  [context.configId, dimensions.kind, dimensions.asset_name, dimensions.project, dimensions.group,
    createHash("sha256").update(JSON.stringify(dimensions)).digest("hex")]);
}
module.exports = { deploymentMetricLabelOptions, systemMetricPolicy, readSystemMetricPolicy, DEFAULT_SYSTEM_LABELS, permittedExtraLabels, HIGH_CARDINALITY_LABELS, effectiveMetricSettings, KNOWN_KINDS, OPTIONAL_LABELS, metricSettingsError, normalizeMetricSettings, metricSourceDimensions, creationDimensions, recordCreationMetrics };
