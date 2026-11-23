"use strict";

const { safeFetch } = require("./safe-fetch");

function formatFetchReason(reason) {
  const code = String(reason || "fetch_failed");
  if (code.startsWith("http_")) {
    return `HTTP ${code.replace("http_", "")}`;
  }
  return code.replace(/_/g, " ");
}

/**
 * Fetch IdP SAML metadata XML via the safe-fetch module for the admin UI proxy.
 *
 * @param {string} url
 * @returns {Promise<string>}
 */
async function fetchIdpMetadataXml(url) {
  const target = String(url || "").trim();
  if (!target) {
    throw new Error("Metadata URL is required");
  }
  const result = await safeFetch(target);
  if (!result.ok) {
    throw new Error(formatFetchReason(result.reason));
  }
  const xml = String(result.body || "").trim();
  if (!xml) {
    throw new Error("Empty metadata response");
  }
  return xml;
}

module.exports = {
  fetchIdpMetadataXml,
  formatFetchReason,
};
