"use strict";

const { assertOutboundUrl, OUTBOUND_POLICY_DENIED } = require("@tokentimer/config/network");
const { createPinnedGet } = require("@tokentimer/webhook-safety");
const {
  BLOCKED_CODE,
  shouldEnforceIntegrationAddressCheck,
} = require("../../utils/integrationAddressGuard");
const { pool } = require("../../db/database");
const { serviceError } = require("./enrollmentLifecycle");

const getDirectory = createPinnedGet(shouldEnforceIntegrationAddressCheck);

function parseHttpsUrl(value) {
  if (typeof value !== "string" || value.length > 2048 ||
      !/^https:\/\//i.test(value) || /[\u0000-\u0020\u007f\\#]/u.test(value)) {
    return null;
  }
  try {
    const url = new URL(value);
    return url.hostname && !url.username && !url.password && !url.hash ? url : null;
  } catch {
    return null;
  }
}

function readDirectory(body) {
  let directory;
  try {
    directory = JSON.parse(body);
  } catch {
    // HTML and malformed JSON are treated like any other invalid directory.
  }
  if (!["newNonce", "newAccount", "newOrder"].every(key => parseHttpsUrl(directory?.[key]))) {
    throw serviceError(
      "The CA response did not advertise HTTPS endpoints for ACME nonce, account and order operations.",
      "CERTOPS_ISSUER_DIRECTORY_INVALID",
    );
  }
  return {
    revocationAdvertised: Boolean(parseHttpsUrl(directory.revokeCert)),
    externalAccountRequired: directory.meta?.externalAccountRequired === true,
  };
}

async function validateAcmeIssuerDirectory({
  workspaceId, issuerId, caEndpoint, client = pool, request = getDirectory,
}) {
  const { rows } = await client.query(
    "SELECT kind FROM certificate_issuers WHERE workspace_id = $1 AND id = $2",
    [workspaceId, issuerId],
  );
  if (!rows[0]) {
    throw serviceError("issuer not found", "CERTOPS_ISSUER_NOT_FOUND");
  }
  if (rows[0].kind !== "acme") {
    throw serviceError("Directory validation requires an ACME issuer.", "CERTOPS_ISSUER_KIND_INVALID");
  }
  const url = parseHttpsUrl(caEndpoint);
  if (!url || caEndpoint.length > 512 || caEndpoint.includes("?")) {
    throw serviceError(
      "Provide an HTTPS ACME directory URL of at most 512 characters without credentials, a query or a fragment.",
      "CERTOPS_ISSUER_DIRECTORY_URL_INVALID",
    );
  }
  assertOutboundUrl(url);
  let response;
  try {
    response = await request(url.href, {
      headers: { Accept: "application/json" },
      timeoutMs: 5_000,
    });
  } catch (error) {
    if (error?.code === OUTBOUND_POLICY_DENIED) throw error;
    if (error?.code === "WEBHOOK_PRIVATE_IP_BLOCKED") {
      throw serviceError("The directory resolves to a private or reserved address.", BLOCKED_CODE);
    }
    if (error?.code === "WEBHOOK_TIMEOUT") {
      throw serviceError("The ACME directory did not respond within five seconds.", "CERTOPS_ISSUER_DIRECTORY_TIMEOUT");
    }
    if (error?.code === "WEBHOOK_REDIRECT_REFUSED") {
      throw serviceError("The ACME directory redirected the request. Provide its final HTTPS URL.", "CERTOPS_ISSUER_DIRECTORY_INVALID");
    }
    throw serviceError("The API could not connect directly to the ACME directory. Check DNS, connectivity and CA trust.", "CERTOPS_ISSUER_DIRECTORY_UNREACHABLE");
  }
  if (response.status !== 200) {
    throw serviceError("The ACME directory did not return HTTP 200.", "CERTOPS_ISSUER_DIRECTORY_UNREACHABLE");
  }
  return { issuerId, kind: "acme", ...readDirectory(response.bodyText) };
}

module.exports = { validateAcmeIssuerDirectory };
