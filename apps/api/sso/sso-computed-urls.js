"use strict";

const {
  getOidcCallbackUrl,
  getSamlCallbackUrl,
  getSamlMetadataUrl,
} = require("./callback-urls.js");

/**
 * @param {{ slug: string, type: 'oidc'|'saml', config?: object }} provider
 * @returns {{ callback_url: string, metadata_url: string|null }}
 */
function buildComputedUrls(provider) {
  const slug = provider.slug;
  const cfg = provider.config || {};
  const callbackDefault =
    provider.type === "oidc"
      ? getOidcCallbackUrl(slug)
      : getSamlCallbackUrl(slug);
  const callback_url =
    typeof cfg.callback_url === "string" && cfg.callback_url.trim()
      ? cfg.callback_url.trim()
      : callbackDefault;
  const metadata_url =
    provider.type === "saml" ? getSamlMetadataUrl(slug) : null;
  return { callback_url, metadata_url };
}

/**
 * @param {string} manual
 * @param {string} computed
 * @returns {boolean}
 */
function isRedundantCallbackOverride(manual, computed) {
  return (
    typeof manual === "string" &&
    manual.trim().length > 0 &&
    manual.trim() === computed
  );
}

module.exports = {
  buildComputedUrls,
  isRedundantCallbackOverride,
  getOidcCallbackUrl,
  getSamlCallbackUrl,
  getSamlMetadataUrl,
};
