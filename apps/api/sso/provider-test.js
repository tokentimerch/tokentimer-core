"use strict";

const { validateProviderConfig } = require("./provider-config-schema.js");
const { safeFetch, validateOutboundUrl, outboundBlockHint } = require("./safe-fetch.js");
const { loadDecryptedSecret } = require("./provider-registry.js");
const { buildComputedUrls } = require("./sso-computed-urls.js");
const { recordLastTestChecks } = require("./sso-runtime-status.js");

function pushCheck(checks, name, ok, detail) {
  checks.push({ name, ok: !!ok, detail: detail || null });
}

function reasonWithHint(reason) {
  if (!reason) return reason;
  const hint = outboundBlockHint(reason);
  return hint ? `${reason}: ${hint}` : reason;
}

function isAllowedOidcUrl(url) {
  return (
    typeof url === "string" &&
    url.trim() !== "" &&
    (url.startsWith("https://") ||
      url.startsWith("http://127.0.0.1") ||
      url.startsWith("http://localhost"))
  );
}

async function checkManualOidcEndpoint(checks, name, url, { fetchGet = false } = {}) {
  const present = isAllowedOidcUrl(url);
  pushCheck(checks, name, present, url || "missing");
  if (!present) return;
  const outbound = await validateOutboundUrl(url);
  pushCheck(
    checks,
    `${name}_outbound_safe`,
    outbound.ok,
    outbound.ok ? null : reasonWithHint(outbound.reason),
  );
  if (!fetchGet || !outbound.ok) return;
  const probe = await safeFetch(url);
  pushCheck(
    checks,
    `${name}_reachable`,
    probe.ok,
    probe.ok ? `status ${probe.status}` : reasonWithHint(probe.reason),
  );
}

async function probeTokenEndpointPost(checks, tokenUrl, clientId, redirectUri) {
  if (!isAllowedOidcUrl(tokenUrl) || !clientId) {
    pushCheck(checks, "token_endpoint_post_reachable", false, "token_url or client_id missing");
    return;
  }
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: "connectivity-probe-invalid",
    client_id: String(clientId).trim(),
    redirect_uri: redirectUri || "https://example.invalid/callback",
  }).toString();
  const probe = await safeFetch(tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  const responded = typeof probe.status === "number" && probe.status > 0;
  pushCheck(
    checks,
    "token_endpoint_post_reachable",
    responded,
    responded ? `status ${probe.status}` : reasonWithHint(probe.reason) || "timeout",
  );
}

/**
 * @param {import('pg').Pool} pool
 * @param {object} provider rowToProvider shape or DB row
 */
async function runProviderTest(pool, provider) {
  const checks = [];
  const type = provider.type;
  const config = provider.config || {};
  const security = provider.security || {};

  const schema = validateProviderConfig(type, config);
  pushCheck(
    checks,
    "config_schema",
    schema.ok,
    schema.ok ? null : schema.errors.join(", "),
  );
  if (!schema.ok) {
    return { ok: false, checks, reason: "invalid_config" };
  }

  if (type === "oidc") {
    const issuer = config.issuer;
    const computed = buildComputedUrls(provider);
    let tokenEndpointUrl = config.token_url || null;
    if (!security.disable_discovery) {
      const wellKnown = `${String(issuer).replace(/\/+$/, "")}/.well-known/openid-configuration`;
      const disc = await safeFetch(wellKnown);
      pushCheck(
        checks,
        "discovery_reachable",
        disc.ok,
        disc.ok ? `status ${disc.status}` : reasonWithHint(disc.reason),
      );
      if (disc.ok && disc.body) {
        try {
          const doc = JSON.parse(disc.body);
          for (const endpoint of [
            "authorization_endpoint",
            "token_endpoint",
            "jwks_uri",
          ]) {
            const url = doc[endpoint];
            const httpsOk =
              typeof url === "string" &&
              (url.startsWith("https://") ||
                url.startsWith("http://127.0.0.1") ||
                url.startsWith("http://localhost"));
            pushCheck(checks, endpoint, httpsOk, url || "missing");
          }
          tokenEndpointUrl = doc.token_endpoint || tokenEndpointUrl;
          if (doc.jwks_uri) {
            const jwks = await safeFetch(doc.jwks_uri);
            pushCheck(
              checks,
              "jwks_reachable",
              jwks.ok,
              jwks.ok ? null : reasonWithHint(jwks.reason),
            );
          }
        } catch (e) {
          pushCheck(checks, "discovery_parse", false, e.message);
        }
      }
    } else {
      pushCheck(checks, "discovery_skipped", true, "disable_discovery=true");
      tokenEndpointUrl = config.token_url || tokenEndpointUrl;
      await checkManualOidcEndpoint(
        checks,
        "authorization_url",
        config.authorization_url,
      );
      await checkManualOidcEndpoint(checks, "token_url", config.token_url);
      await checkManualOidcEndpoint(checks, "jwks_uri", config.jwks_uri, {
        fetchGet: true,
      });
      const userinfo = config.userinfo_url;
      if (userinfo && String(userinfo).trim()) {
        await checkManualOidcEndpoint(checks, "userinfo_url", userinfo);
      }
    }
    await probeTokenEndpointPost(
      checks,
      tokenEndpointUrl,
      config.client_id,
      computed.callback_url,
    );
    try {
      const secret = await loadDecryptedSecret(
        pool,
        provider.slug,
        "client_secret",
      );
      pushCheck(checks, "client_secret_decryptable", !!secret, null);
    } catch (e) {
      pushCheck(checks, "client_secret_decryptable", false, e.message);
    }
  } else {
    const entry = config.entry_point;
    const httpsOk =
      typeof entry === "string" &&
      (entry.startsWith("https://") ||
        entry.startsWith("http://127.0.0.1") ||
        entry.startsWith("http://localhost"));
    pushCheck(checks, "entry_point_https", httpsOk, entry);
    if (config.cert) {
      const hasCertMarkers =
        String(config.cert).includes("BEGIN CERTIFICATE");
      pushCheck(checks, "idp_cert_parseable", hasCertMarkers, null);
    }
    if (config.decryption_key || security.decryption_key) {
      try {
        const key = await loadDecryptedSecret(
          pool,
          provider.slug,
          "decryption_key",
        );
        pushCheck(checks, "decryption_key_decryptable", !!key, null);
      } catch (e) {
        pushCheck(checks, "decryption_key_decryptable", false, e.message);
      }
    }
    try {
      await pool.query(
        `INSERT INTO saml_request_cache (provider_slug, cache_key, cache_value)
         VALUES ($1, $2, $3)
         ON CONFLICT (provider_slug, cache_key) DO UPDATE SET cache_value = EXCLUDED.cache_value`,
        [provider.slug, `test-${Date.now()}`, "probe"],
      );
      pushCheck(checks, "saml_cache_rw", true, null);
      await pool.query(
        `DELETE FROM saml_request_cache WHERE provider_slug = $1 AND cache_key LIKE 'test-%'`,
        [provider.slug],
      );
    } catch (e) {
      pushCheck(checks, "saml_cache_rw", false, e.message);
    }
  }

  const computedUrls = buildComputedUrls(provider);
  pushCheck(
    checks,
    "callback_url_derivable",
    !!computedUrls.callback_url,
    computedUrls.callback_url,
  );

  const ok = checks.every((c) => c.ok);
  recordLastTestChecks(provider.slug, checks);
  return { ok, checks, reason: ok ? undefined : "checks_failed" };
}

module.exports = {
  runProviderTest,
  probeTokenEndpointPost,
};
