"use strict";

const { normalizeIssuanceRequest } = require("../certops/issuance");
const { validateJobPayloadForOperation } = require("../certops/jobs");
const { invalid } = require("./tokenInventory");

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const KEYS = ["agentId", "commonName", "sans", "commandRef", "caEndpoint", "dnsZone", "dnsProvider", "certPath"];

// Accept a deliberately small file-based ACME request, not an arbitrary job
// payload. In particular the caller cannot provide key material or choose an
// unreviewed execution override. The execution destination is resubmitted with
// the request and is never persisted in the preview.
function normalizeIssuance(input) {
  if (!input || typeof input !== "object" || Array.isArray(input) ||
      Object.keys(input).some((key) => !KEYS.includes(key)) ||
      KEYS.some((key) => !Object.hasOwn(input, key)) ||
      !UUID.test(String(input.agentId || "")) ||
      !Array.isArray(input.sans)) throw invalid();
  const payload = {
    target: { type: "domain", reference: input.commonName },
    sans: input.sans, commandRef: input.commandRef, caEndpoint: input.caEndpoint,
    dnsZone: input.dnsZone, dnsProvider: input.dnsProvider, certPath: input.certPath,
  };
  let normalized;
  try {
    normalized = normalizeIssuanceRequest({ idempotencyKey: "mcp-preview", assignedAgentId: input.agentId, payload });
    validateJobPayloadForOperation(payload, "issue");
    const endpoint = new URL(input.caEndpoint);
    if (endpoint.username || endpoint.password || endpoint.hash) throw invalid();
  } catch (_error) { throw invalid(); }
  return {
    agentId: input.agentId.toLowerCase(),
    payload: { ...payload, target: { type: "domain", reference: normalized.commonName }, sans: normalized.sans, certPath: normalized.certPath },
  };
}

module.exports = { normalizeIssuance };
