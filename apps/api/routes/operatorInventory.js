"use strict";

const router = require("express").Router();
const { pool } = require("../db/database");
const { logger } = require("../utils/logger");
const { getApiLimiter } = require("../middleware/rateLimit");
const { rejectKeyMaterial } = require("../middleware/reject-key-material");
const { requireOperatorInterfaceEnabled } = require("../middleware/require-operator-interface");
const { requireOperatorConnection } = require("../middleware/operator-connection-auth");
const inventory = require("../services/operator/tokenInventory");
const imports = require("../services/operator/inventoryImports");
const updates = require("../services/operator/inventoryUpdates");
const contacts = require("../services/operator/contactCreates");
const webhooks = require("../services/operator/webhookCreates");
const groups = require("../services/operator/contactGroupCreates");
const invites = require("../services/operator/memberInvites");
const issuance = require("../services/operator/issuanceRequests");
const { requireCertOpsEnabled } = require("../middleware/require-certops-enabled");
function guard(scope, minRole) { return [getApiLimiter(), requireOperatorInterfaceEnabled, requireOperatorConnection({ scope, minRole })]; }
function errorReply(res, error) {
  const messages = {
    CERTOPS_CERTIFICATE_PATH_IN_USE: "The selected destination is already in use on this agent.",
    CERTOPS_RENEWAL_PER_CA_CAP_EXCEEDED: "The certificate authority has too many certificate jobs in progress. Try again later.",
    CERTOPS_MANAGED_CERT_LIMIT: "The workspace has reached its managed certificate limit.",
  };
  const code = error.code === "P0001" && error.detail === "CERTOPS_MANAGED_CERT_LIMIT" ? error.detail : error.code;
  const statuses = { OPERATOR_VALIDATION_ERROR: 400, OPERATOR_CURSOR_INVALID: 400, OPERATOR_UNSAFE_METADATA: 422,
    OPERATOR_CONNECTION_UNAUTHORIZED: 401, OPERATOR_CONNECTION_SCOPE_DENIED: 403, OPERATOR_WRITES_DISABLED: 403,
    NOT_FOUND: 404, OPERATOR_PLAN_EXPIRED: 410, OPERATOR_PLAN_USED: 409, OPERATOR_PLAN_MISMATCH: 409,
    OPERATOR_IDEMPOTENCY_CONFLICT: 409, OPERATOR_INTENT_STALE: 409, OPERATOR_UPDATE_UNSUPPORTED: 409, OPERATOR_PENDING_LIMIT: 429,
    WORKSPACE_FROZEN: 403, PLAN_FEATURE_REQUIRED: 402, PLAN_TOKEN_LIMIT: 402, PLAN_CONTACT_GROUP_LIMIT: 402,
    PLAN_MEMBER_LIMIT: 402, MANUAL_INVITES_DISABLED: 403, PERSONAL_DEFAULT: 403,
    CERTOPS_WORKSPACE_PAUSED: 409, CERTOPS_DISABLED: 404, CERTOPS_CERTIFICATE_PATH_IN_USE: 409,
    CERTOPS_RENEWAL_PER_CA_CAP_EXCEEDED: 409, CERTOPS_MANAGED_CERT_LIMIT: 402 };
  if (Object.hasOwn(statuses, code)) return res.status(statuses[code]).json({
    error: Object.hasOwn(messages, code) ? messages[code] : error.message, code,
  });
  logger.error("Operator inventory request failed", { code: error.code || null });
  return res.status(500).json({ error: "Inventory request failed", code: "INTERNAL_ERROR" });
}
async function transaction(work) {
  const client = await pool.connect();
  try { await client.query("BEGIN"); const result = await work(client); await client.query("COMMIT"); return result; }
  catch (error) { await client.query("ROLLBACK"); throw error; }
  finally { client.release(); }
}
function exactBody(body, keys) {
  if (!body || typeof body !== "object" || Array.isArray(body) || Object.keys(body).length !== keys.length || Object.keys(body).some((key) => !keys.includes(key))) throw inventory.invalid();
  return body;
}
router.get("/api/v1/operator/tokens", ...guard("mcp:tokens:read"), async (req, res) => {
  try { return res.json(await inventory.listTokens({ workspaceId: req.operator.workspaceId, query: req.query })); }
  catch (error) { return errorReply(res, error); }
});
router.get("/api/v1/operator/sections", ...guard("mcp:tokens:read"), async (req, res) => {
  try { return res.json(await inventory.listSections({ workspaceId: req.operator.workspaceId, query: req.query })); }
  catch (error) { return errorReply(res, error); }
});
router.get("/api/v1/operator/tokens/:tokenId", ...guard("mcp:tokens:read"), async (req, res) => {
  try {
    if (Object.keys(req.query).length) throw inventory.invalid();
    const record = await inventory.getToken({ workspaceId: req.operator.workspaceId, tokenId: req.params.tokenId });
    return record ? res.json(record) : res.status(404).json({ error: "Not found", code: "NOT_FOUND" });
  } catch (error) { return errorReply(res, error); }
});
router.get("/api/v1/operator/tokens/:tokenId/similar", ...guard("mcp:tokens:read"), async (req, res) => {
  try {
    const result = await inventory.similarTokens({ workspaceId: req.operator.workspaceId, tokenId: req.params.tokenId, query: req.query });
    return result ? res.json(result) : res.status(404).json({ error: "Not found", code: "NOT_FOUND" });
  } catch (error) { return errorReply(res, error); }
});
router.post("/api/v1/operator/inventory/preview", ...guard("mcp:inventory:import", "workspace_manager"), rejectKeyMaterial, async (req, res) => {
  try { const body = exactBody(req.body, ["records"]); return res.json(await transaction((client) => imports.previewImport({ client, operator: req.operator, records: body.records }))); }
  catch (error) { return errorReply(res, error); }
});
router.post("/api/v1/operator/inventory/import", ...guard("mcp:inventory:import", "workspace_manager"), rejectKeyMaterial, async (req, res) => {
  try { const body = exactBody(req.body, ["planId", "planHash", "requestId"]); return res.json(await transaction((client) => imports.importInventory({ client, operator: req.operator, ...body }))); }
  catch (error) { return errorReply(res, error); }
});
router.post("/api/v1/operator/inventory/update/preview", ...guard("mcp:inventory:update", "workspace_manager"), rejectKeyMaterial, async (req, res) => {
  try { const body = exactBody(req.body, ["tokenId", "changes"]); return res.json(await transaction((client) => updates.previewUpdate({ client, operator: req.operator, ...body }))); }
  catch (error) { return errorReply(res, error); }
});
router.post("/api/v1/operator/inventory/update", ...guard("mcp:inventory:update", "workspace_manager"), rejectKeyMaterial, async (req, res) => {
  try { const body = exactBody(req.body, ["planId", "planHash", "requestId"]); return res.json(await transaction((client) => updates.updateInventory({ client, operator: req.operator, ...body }))); }
  catch (error) { return errorReply(res, error); }
});
router.post("/api/v1/operator/contacts/preview", ...guard("mcp:contacts:create", "workspace_manager"), rejectKeyMaterial, async (req, res) => {
  try { const body = exactBody(req.body, ["contact"]); return res.json(await transaction((client) => contacts.previewContact({ client, operator: req.operator, ...body }))); }
  catch (error) { return errorReply(res, error); }
});
router.post("/api/v1/operator/contacts/create", ...guard("mcp:contacts:create", "workspace_manager"), rejectKeyMaterial, async (req, res) => {
  try { const body = exactBody(req.body, ["planId", "planHash", "requestId"]); return res.json(await transaction((client) => contacts.createContact({ client, operator: req.operator, ...body }))); }
  catch (error) { return errorReply(res, error); }
});
router.post("/api/v1/operator/webhooks/preview", ...guard("mcp:webhooks:create", "workspace_manager"), rejectKeyMaterial, async (req, res) => {
  try { const body = exactBody(req.body, ["webhook"]); return res.json(await transaction((client) => webhooks.previewWebhook({ client, operator: req.operator, ...body }))); }
  catch (error) { return errorReply(res, error); }
});
router.post("/api/v1/operator/webhooks/create", ...guard("mcp:webhooks:create", "workspace_manager"), rejectKeyMaterial, async (req, res) => {
  try {
    const keys = Object.hasOwn(req.body || {}, "routingKey") ? ["planId", "planHash", "requestId", "url", "routingKey"] : ["planId", "planHash", "requestId", "url"];
    const body = exactBody(req.body, keys);
    return res.json(await transaction((client) => webhooks.createWebhook({ client, operator: req.operator, ...body })));
  } catch (error) { return errorReply(res, error); }
});
router.get("/api/v1/operator/groups/sources", ...guard("mcp:groups:create", "workspace_manager"), async (req, res) => {
  try { return res.json(await groups.listGroupSources({ client: pool, operator: req.operator, query: req.query })); }
  catch (error) { return errorReply(res, error); }
});
router.post("/api/v1/operator/groups/preview", ...guard("mcp:groups:create", "workspace_manager"), rejectKeyMaterial, async (req, res) => {
  try { const body = exactBody(req.body, ["group"]); return res.json(await transaction((client) => groups.previewGroup({ client, operator: req.operator, ...body }))); }
  catch (error) { return errorReply(res, error); }
});
router.post("/api/v1/operator/groups/create", ...guard("mcp:groups:create", "workspace_manager"), rejectKeyMaterial, async (req, res) => {
  try { const body = exactBody(req.body, ["planId", "planHash", "requestId"]); return res.json(await transaction((client) => groups.createGroup({ client, operator: req.operator, ...body }))); }
  catch (error) { return errorReply(res, error); }
});
router.post("/api/v1/operator/members/preview", ...guard("mcp:members:invite", "workspace_manager"), rejectKeyMaterial, async (req, res) => {
  try { const body = exactBody(req.body, ["invite"]); return res.json(await transaction((client) => invites.previewInvite({ client, operator: req.operator, ...body }))); }
  catch (error) { return errorReply(res, error); }
});
router.post("/api/v1/operator/members/invite", ...guard("mcp:members:invite", "workspace_manager"), rejectKeyMaterial, async (req, res) => {
  try {
    const body = exactBody(req.body, ["planId", "planHash", "requestId"]);
    const result = await transaction((client) => invites.createInvite({ client, operator: req.operator, ...body }));
    const emailStatus = await invites.deliverInvite({ operator: req.operator, requestId: body.requestId });
    return res.json({ ...result, emailStatus });
  } catch (error) { return errorReply(res, error); }
});
router.post("/api/v1/operator/issuance/preview", ...guard("mcp:issue:request", "workspace_manager"), rejectKeyMaterial, requireCertOpsEnabled, async (req, res) => {
  try { const body = exactBody(req.body, ["issuance"]); return res.json(await transaction((client) => issuance.previewIssuance({ client, operator: req.operator, ...body }))); }
  catch (error) { return errorReply(res, error); }
});
router.post("/api/v1/operator/issuance/request", ...guard("mcp:issue:request", "workspace_manager"), rejectKeyMaterial, requireCertOpsEnabled, async (req, res) => {
  try { const body = exactBody(req.body, ["issuance", "planId", "planHash", "requestId"]); return res.json(await transaction((client) => issuance.requestIssuance({ client, operator: req.operator, ...body }))); }
  catch (error) { return errorReply(res, error); }
});
module.exports = router;
