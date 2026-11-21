/**
 * Multi-provider OIDC authentication for TokenTimer.
 *
 * Authorization Code + PKCE (S256) via openid-client. One runtime per provider
 * slug loaded from sso_providers (provider-registry.js).
 * Routes: GET /auth/oidc/:provider and GET /auth/oidc/:provider/callback only.
 */

"use strict";

const { isValidEmail } = require("../utils/emailAddress");
const { extractFirst, extractAll } = require("../sso/claim-extractor");
const { resolveUser } = require("../sso/identity-resolver");
const {
  resolveSsoBindings,
  applyResolution,
  hasAnyWorkspaceMembership,
} = require("../sso/group-resolver");
const {
  loadConfiguredAdminIdpGroups,
  buildSsoLoginSuccessMetadata,
} = require("../sso/login-audit-metadata.js");
const { createProviderStrategyConfig } = require("../sso/strategy-config");
const {
  setProviderRuntimeStatus,
  removeProviderRuntimeStatus,
  getAllProviderRuntimeStatuses,
} = require("../sso/sso-runtime-status.js");
const {
  createOidcClient,
  buildAuthorizationRequest,
  buildEndSessionUrl,
  exchangeAuthorizationCode,
  validateUserinfoSubject,
  buildPassportStyleProfiles,
  DEFAULT_OPENID_CLIENT,
  resolveIdpHttpTimeoutMs,
} = require("./oidc-flow");
const {
  publicOidcLoginErrorCode,
  buildLoginFailureRedirect,
  sanitizeNextPath,
} = require("../sso/login-redirect.js");
const { normalizeBaseUrl } = require("../sso/callback-urls.js");

/** @type {Map<string, object>} slug -> runtime */
const oidcRuntimes = new Map();

const MAX_PENDING_OIDC_TX =
  Number(process.env.MAX_PENDING_OIDC_TX) > 0
    ? Number(process.env.MAX_PENDING_OIDC_TX)
    : 5;
const OIDC_TX_TTL_SEC =
  Number(process.env.OIDC_TX_TTL_SEC) > 0
    ? Number(process.env.OIDC_TX_TTL_SEC)
    : 600;

let routeAuditWriter = null;
let routeAuditLogger = console;

const parseCsv = (raw) =>
  String(raw || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

function resolveOpenIdClient(deps) {
  if (deps?.openIdClient) return deps.openIdClient;
  return DEFAULT_OPENID_CLIENT();
}

function saveSession(req) {
  return new Promise((resolve, reject) => {
    req.session.save((err) => (err ? reject(err) : resolve()));
  });
}

async function safeAudit(writeAudit, logger, params) {
  if (!writeAudit) return;
  try {
    await writeAudit(params);
  } catch (err) {
    logger?.warn?.("OIDC audit write failed", { error: err?.message });
  }
}

function pruneOidcAuthSession(session) {
  if (!session?.oidcAuth || typeof session.oidcAuth !== "object") {
    session.oidcAuth = {};
    return;
  }
  const now = Date.now();
  const entries = Object.entries(session.oidcAuth);
  const fresh = entries.filter(([, tx]) => {
    const created = Number(tx?.createdAt) || 0;
    return now - created <= OIDC_TX_TTL_SEC * 1000;
  });
  fresh.sort((a, b) => (a[1].createdAt || 0) - (b[1].createdAt || 0));
  const kept =
    fresh.length > MAX_PENDING_OIDC_TX
      ? fresh.slice(fresh.length - MAX_PENDING_OIDC_TX)
      : fresh;
  session.oidcAuth = Object.fromEntries(kept);
}

function stashOidcTx(session, state, entry) {
  if (!session) return;
  if (!session.oidcAuth || typeof session.oidcAuth !== "object") {
    session.oidcAuth = {};
  }
  pruneOidcAuthSession(session);
  session.oidcAuth[state] = entry;
  const keys = Object.keys(session.oidcAuth);
  if (keys.length > MAX_PENDING_OIDC_TX) {
    keys
      .sort(
        (a, b) =>
          (session.oidcAuth[a].createdAt || 0) -
          (session.oidcAuth[b].createdAt || 0),
      )
      .slice(0, keys.length - MAX_PENDING_OIDC_TX)
      .forEach((k) => delete session.oidcAuth[k]);
  }
}

async function deleteOidcTxAndSave(req, state) {
  if (req.session?.oidcAuth && state) {
    delete req.session.oidcAuth[state];
    if (Object.keys(req.session.oidcAuth).length === 0) {
      delete req.session.oidcAuth;
    }
  }
  delete req.session?.ssoNext;
  await saveSession(req);
}

function getOidcRuntime(slug) {
  return oidcRuntimes.get(slug) || null;
}

function normalizeReturnedState(raw) {
  if (Array.isArray(raw)) return null;
  if (typeof raw !== "string" || raw.length === 0) return null;
  return raw;
}

async function completeOidcLogin({
  providerSlug,
  issuer,
  idClaims,
  userinfoClaims,
  trustedUserinfo,
  pool,
  claimConfig,
  securityConfig,
  bootstrapAdminGroups,
  canonicalizeEmail,
  ensureInitialWorkspaceForUser,
  writeAudit,
  logger,
}) {
  const useUserinfo =
    trustedUserinfo && idClaims.sub && userinfoClaims?.sub === idClaims.sub;
  const { profile } = buildPassportStyleProfiles(idClaims, userinfoClaims, useUserinfo);

  const rawEmail = extractFirst(profile, claimConfig.oidc.email) || "";
  const displayName =
    extractFirst(profile, claimConfig.oidc.displayName) ||
    `${profile.name?.givenName || ""} ${profile.name?.familyName || ""}`.trim() ||
    rawEmail;
  const idSub = idClaims.sub;
  const subjectId =
    idSub || extractFirst(profile, claimConfig.oidc.subject) || "";
  const idpGroups = extractAll(profile, claimConfig.oidc.groups);

  // Verification belongs to the email in its own claim set. UserInfo can
  // override the ID token's verification only for the same mailbox.
  const mailbox = rawEmail.trim().toLowerCase();
  const matchesMailbox = (claims) =>
    typeof claims?.email === "string" &&
    claims.email.trim().toLowerCase() === mailbox;
  const proofClaims =
    useUserinfo &&
    matchesMailbox(userinfoClaims) &&
    userinfoClaims.email_verified != null
      ? userinfoClaims
      : idClaims;
  const verifiedEmail =
    isValidEmail(mailbox) &&
    matchesMailbox(proofClaims) &&
    [true, "true", 1, "1"].includes(proofClaims.email_verified)
      ? mailbox
      : null;

  if (!rawEmail && !subjectId) {
    await safeAudit(writeAudit, logger, {
      actorUserId: null,
      subjectUserId: null,
      action: "LOGIN_FAILED",
      targetType: "user",
      targetId: null,
      channel: null,
      workspaceId: null,
      metadata: {
        method: "oidc",
        provider_slug: providerSlug,
        reason: "missing_email",
      },
    });
    throw new Error("OIDC profile did not include an email address");
  }

  const resolved = await resolveUser({
    pool,
    providerSlug,
    protocol: "oidc",
    issuer,
    subjectId,
    email: rawEmail,
    displayName,
    allowAutoLink: securityConfig.allowAutoLinkLocalAccounts,
    verifiedEmail,
    canonicalizeEmail,
  });

  if (!resolved.user) {
    await safeAudit(writeAudit, logger, {
      actorUserId: null,
      subjectUserId: null,
      action: "LOGIN_FAILED",
      targetType: "user",
      targetId: null,
      channel: null,
      workspaceId: null,
      metadata: {
        method: "oidc",
        provider_slug: providerSlug,
        reason: resolved.reason || "no_user",
        subject_id: subjectId || null,
        issuer,
        email_verified_by_idp: verifiedEmail !== null,
      },
    });
    const reasonMessage = (() => {
      switch (resolved.reason) {
        case "local_account_exists_auto_link_disabled":
          return "A local-password account exists for this email. Enable allow auto-link under System Settings → SSO policy (or override on this provider), or delete the local account first.";
        case "sso_account_exists_subject_mismatch":
          return "An existing account with this email is already linked to a different SSO identity. Ask an admin to merge or relink it.";
        case "cross_provider_auto_link_disabled":
          return "This email is already linked to another SSO provider. Enable allow auto-link under System Settings → SSO policy (or override on this provider), or sign in with the original provider.";
        case "email_not_verified_for_link":
          return "Refusing to link this SSO identity to an existing account because the IdP did not assert email_verified=true for the selected email address.";
        default:
          return "OIDC login could not resolve a user";
      }
    })();
    throw new Error(reasonMessage);
  }

  try {
    await pool.query(
      `UPDATE users
          SET auth_method = 'sso',
              email_verified = TRUE,
              updated_at = NOW()
        WHERE id = $1 AND auth_method <> 'local'`,
      [resolved.user.id],
    );
  } catch (_) {
    /* non-fatal */
  }

  const resolution = await resolveSsoBindings({
    pool,
    providerSlug,
    userId: resolved.user.id,
    idpGroups,
    strictSync: securityConfig.strictMembershipSync,
    bootstrapAdminGroups,
  });
  const applied = await applyResolution({
    pool,
    userId: resolved.user.id,
    providerSlug,
    resolution,
    matchedGroups: resolution.matchedGroups,
    writeAudit,
    logger,
  });

  const requiresExistingMembership =
    securityConfig.strictMembershipSync === true &&
    resolution.effectiveSystemAdmin !== true &&
    resolution.workspaceGrants.length === 0;
  if (
    requiresExistingMembership &&
    verifiedEmail &&
    typeof ensureInitialWorkspaceForUser === "function"
  ) {
    // A verified pending invitation can satisfy strict admission.
    await ensureInitialWorkspaceForUser(
      resolved.user.id,
      canonicalizeEmail(rawEmail),
      displayName,
      { sso: true, verifiedEmail, invitationsOnly: true },
    );
  }
  if (
    requiresExistingMembership &&
    !(await hasAnyWorkspaceMembership(pool, resolved.user.id))
  ) {
    await safeAudit(writeAudit, logger, {
      actorUserId: null,
      subjectUserId: resolved.user.id,
      action: "LOGIN_FAILED",
      targetType: "user",
      targetId: resolved.user.id,
      channel: null,
      workspaceId: null,
      metadata: {
        method: "oidc",
        provider_slug: providerSlug,
        reason: "no_group_mapping_matched",
        subject_id: subjectId || null,
        issuer,
      },
    });
    throw new Error(
      "No IdP group mapping matched this login and strict membership sync is enabled for this provider. Ask an admin to add a group mapping or grant workspace access.",
    );
  }

  if (typeof ensureInitialWorkspaceForUser === "function") {
    try {
      await ensureInitialWorkspaceForUser(
        resolved.user.id,
        canonicalizeEmail(rawEmail),
        displayName,
        { sso: true, verifiedEmail },
      );
    } catch (workspaceErr) {
      logger?.warn?.("OIDC: ensureInitialWorkspaceForUser failed", {
        error: workspaceErr?.message,
        userId: resolved.user.id,
      });
    }
  }

  const refreshed = await pool.query("SELECT * FROM users WHERE id = $1", [
    resolved.user.id,
  ]);
  const user = refreshed.rows[0] || resolved.user;

  let configuredAdminIdpGroups = [];
  try {
    configuredAdminIdpGroups = await loadConfiguredAdminIdpGroups(
      pool,
      providerSlug,
    );
  } catch (_) {
    /* non-fatal */
  }

  await safeAudit(writeAudit, logger, {
    actorUserId: user.id,
    subjectUserId: user.id,
    action: "LOGIN_SUCCESS",
    targetType: "user",
    targetId: user.id,
    channel: null,
    workspaceId: null,
    metadata: buildSsoLoginSuccessMetadata({
      method: "oidc",
      providerSlug,
      protocol: "oidc",
      issuer,
      resolved,
      resolution,
      applied,
      userAfterLogin: user,
      subjectId,
      idpGroups,
      configuredAdminIdpGroups,
    }),
  });

  return user;
}

function finishOidcSetup(result) {
  return result;
}

/**
 * Load all OIDC providers from the registry into oidcRuntimes.
 */
async function setupOidcStrategy(_passport, pool, _unusedStrategyCtor, deps = {}) {
  const logger = deps.logger || console;
  routeAuditWriter = deps.writeAudit || null;
  routeAuditLogger = logger;

  const { listProviders, loadDecryptedSecret } = require("../sso/provider-registry.js");
  const builders = createProviderStrategyConfig({
    logger,
    fetchImpl: deps.fetchImpl || null,
  });

  oidcRuntimes.clear();
  for (const [slug, status] of getAllProviderRuntimeStatuses()) {
    if (status.type === "oidc") {
      removeProviderRuntimeStatus(slug);
    }
  }

  let providers;
  try {
    const loadProviders = deps.loadProviders || listProviders;
    const all = await loadProviders(pool, { includeStatuses: false });
    providers = all.filter((p) => p.type === "oidc");
  } catch (err) {
    logger.error?.("OIDC provider list failed", { error: err?.message });
    return finishOidcSetup({ registered: false, reason: "registry_unavailable" });
  }

  const canonicalizeEmail =
    deps.canonicalizeEmail || ((e) => String(e || "").trim().toLowerCase());
  const ensureInitialWorkspaceForUser = deps.ensureInitialWorkspaceForUser || null;
  const writeAudit = deps.writeAudit || null;
  const openIdClientFactory = resolveOpenIdClient(deps);

  let loaded = 0;

  for (const provider of providers) {
    const slug = provider.slug;
    if (!provider.enabled) {
      setProviderRuntimeStatus(slug, {
        type: "oidc",
        registered: false,
        signInReady: false,
        reason: provider.disabledReason || "provider_disabled",
      });
      continue;
    }

    try {
      let clientSecret;
      try {
        clientSecret = await loadDecryptedSecret(pool, slug, "client_secret");
      } catch (secretErr) {
        const reason =
          secretErr?.code === "secret_keyring_missing" ||
          /secret_keyring_missing/i.test(String(secretErr?.message))
            ? "secret_keyring_missing"
            : "secret_decrypt_failed";
        setProviderRuntimeStatus(slug, {
          type: "oidc",
          registered: false,
          signInReady: false,
          reason,
        });
        continue;
      }
      if (!clientSecret) {
        setProviderRuntimeStatus(slug, {
          type: "oidc",
          registered: false,
          signInReady: false,
          reason: "client_secret_missing",
        });
        continue;
      }

      const strategyConfig = await builders.buildOidcStrategyConfigFromProvider(
        pool,
        provider,
        { client_secret: clientSecret },
      );
      if (!strategyConfig) {
        setProviderRuntimeStatus(slug, {
          type: "oidc",
          registered: false,
          signInReady: false,
          reason: "not_configured",
        });
        continue;
      }

      if (!strategyConfig.jwksURL) {
        const msg = "jwks_uri missing";
        if (process.env.NODE_ENV === "production") {
          setProviderRuntimeStatus(slug, {
            type: "oidc",
            registered: false,
            signInReady: false,
            reason: "jwks_uri_missing",
          });
          continue;
        }
        logger.warn?.(`OIDC provider ${slug}: ${msg}`);
      }

      const { client } = createOidcClient(strategyConfig, openIdClientFactory);
      const claimConfig = builders.buildClaimConfigFromProvider(provider);
      const securityConfig = builders.buildSecurityConfigFromProvider(provider);
      const bootstrapAdminGroups = parseCsv(
        provider.config?.bootstrap_admin_groups ||
          provider.config?.admin_groups ||
          "",
      );

      oidcRuntimes.set(slug, {
        providerSlug: slug,
        displayName: provider.displayName || slug,
        enabled: true,
        issuer: strategyConfig.issuer,
        strategyConfig,
        client,
        openIdClient: openIdClientFactory,
        pkceEnabled: securityConfig.pkce !== false,
        claimConfig,
        securityConfig,
        bootstrapAdminGroups,
        pool,
        deps: {
          canonicalizeEmail,
          ensureInitialWorkspaceForUser,
          writeAudit,
          logger,
        },
      });

      setProviderRuntimeStatus(slug, {
        type: "oidc",
        registered: true,
        signInReady: true,
      });
      loaded += 1;
      logger.info?.("OIDC provider runtime registered", {
        slug,
        issuer: strategyConfig.issuer,
        discoverySource: strategyConfig.discoverySource,
      });
    } catch (err) {
      const reason =
        err?.message === "discovery_required_or_manual_endpoints_missing"
          ? err.message
          : "config_build_failed";
      setProviderRuntimeStatus(slug, {
        type: "oidc",
        registered: false,
        signInReady: false,
        reason,
      });
      logger.warn?.("OIDC provider runtime build failed", {
        slug,
        error: err?.message,
      });
    }
  }

  const result = {
    registered: loaded > 0,
    loaded,
    reason: loaded > 0 ? undefined : "not_configured",
  };
  return finishOidcSetup(result);
}

function oidcRoutes(_passport, express) {
  const router = express.Router();
  const APP_URL = process.env.APP_URL || "http://localhost:5173";

  const safeAuditRoute = async (params) => {
    if (!routeAuditWriter) return;
    try {
      await routeAuditWriter(params);
    } catch (err) {
      routeAuditLogger?.warn?.("OIDC route audit write failed", {
        error: err?.message,
      });
    }
  };

  /**
   * Hands the caller the IdP end-session URL for its own session so the dashboard
   * can end the IdP session right after clearing the local one. Without this step
   * the IdP SSO cookie survives sign-out and the next login is granted with no
   * credential prompt.
   *
   * Mounted outside /auth/oidc/* so sign-out works even after a provider is disabled.
   */
  router.get("/api/sso/logout-url", (req, res) => {
    res.set("Cache-Control", "no-store");
    const sso = req.session?.sso || null;
    if (!sso || sso.protocol !== "oidc") {
      return res.json({ url: null });
    }
    if (process.env.SSO_DISABLE_SINGLE_LOGOUT === "true") {
      return res.json({ url: null });
    }
    const runtime = getOidcRuntime(String(sso.providerSlug || "").trim());
    if (!runtime?.strategyConfig) {
      return res.json({ url: null });
    }
    try {
      // post_logout_redirect_uri is opt-in: IdPs match it as an exact string
      // against a registered allowlist and reject anything else outright
      // (Keycloak answers 400 "Invalid redirect uri"). Defaulting it on would turn
      // every sign-out into an error page for deployments that have not registered
      // the URI yet, so it is only sent once an operator confirms registration.
      // Without it the IdP session still ends; the user just lands on the IdP's
      // own signed-out page instead of returning to /login.
      const wantsReturnRedirect =
        process.env.SSO_POST_LOGOUT_REDIRECT === "true";
      const url = buildEndSessionUrl(runtime.strategyConfig, {
        idToken: sso.idToken || null,
        // Normalised: a trailing slash on APP_URL would produce "host//login",
        // which is not the string registered at the IdP.
        postLogoutRedirectUri: wantsReturnRedirect
          ? `${normalizeBaseUrl(APP_URL) || APP_URL}/login`
          : null,
        client: runtime.client,
        openidClient: runtime.openIdClient,
      });
      return res.json({ url: url || null });
    } catch (err) {
      // Fail soft: the local session is still cleared, so a provider that cannot
      // produce an end-session URL degrades to a local-only sign-out.
      routeAuditLogger?.warn?.("OIDC end-session URL build failed", {
        providerSlug: sso.providerSlug,
        error: err?.message,
      });
      return res.json({ url: null });
    }
  });

  router.get("/auth/oidc/:provider", (req, res) => {
    const providerSlug = String(req.params.provider || "").trim();
    const runtime = getOidcRuntime(providerSlug);
    if (!runtime || !runtime.enabled) {
      return res.redirect(`${APP_URL}/login?error=oidc_not_ready`);
    }
    if (!req.session) {
      return res.redirect(`${APP_URL}/login?error=oidc_failed`);
    }

    const safeNext = sanitizeNextPath(req.query?.next);
    const { strategyConfig, client, openIdClient, pkceEnabled } = runtime;

    try {
      const auth = buildAuthorizationRequest(
        strategyConfig,
        client,
        openIdClient,
        { pkceEnabled },
      );
      stashOidcTx(req.session, auth.state, {
        providerSlug,
        issuer: strategyConfig.issuer,
        state: auth.state,
        nonce: auth.nonce,
        codeVerifier: auth.codeVerifier,
        next: safeNext,
        createdAt: Date.now(),
      });
      return req.session.save((saveErr) => {
        if (saveErr) {
          routeAuditLogger?.warn?.("OIDC session save failed", {
            error: saveErr?.message,
          });
          return res.redirect(`${APP_URL}/login?error=oidc_failed`);
        }
        return res.redirect(auth.authorizationUrl);
      });
    } catch (err) {
      routeAuditLogger?.error?.("OIDC authorization redirect failed", {
        providerSlug,
        error: err?.message,
      });
      return res.redirect(`${APP_URL}/login?error=oidc_failed`);
    }
  });

  router.get("/auth/oidc/:provider/callback", async (req, res) => {
    const providerSlug = String(req.params.provider || "").trim();
    const returnedState = normalizeReturnedState(req.query?.state);
    const tx = returnedState ? req.session?.oidcAuth?.[returnedState] : null;
    const stashed = tx?.next ?? req.session?.ssoNext ?? null;
    const landingPath = sanitizeNextPath(stashed) || "/dashboard";

    const failRedirect = async (reason, callbackPhase = null) => {
      if (returnedState && req.session) {
        try {
          await deleteOidcTxAndSave(req, returnedState);
        } catch (saveErr) {
          routeAuditLogger?.warn?.("OIDC session save after tx delete failed", {
            error: saveErr?.message,
          });
        }
      }
      await safeAuditRoute({
        actorUserId: null,
        subjectUserId: null,
        action: "LOGIN_FAILED",
        targetType: "auth",
        targetId: providerSlug,
        channel: "web",
        workspaceId: null,
        metadata: {
          method: "oidc",
          provider_slug: providerSlug,
          protocol: "oidc",
          reason,
          path: req.path,
          ...(callbackPhase ? { callback_phase: callbackPhase } : {}),
        },
      });
      const errorCode = publicOidcLoginErrorCode(reason);
      return res.redirect(
        buildLoginFailureRedirect(APP_URL, {
          error: errorCode,
          provider: providerSlug,
          reason,
        }),
      );
    };

    if (!returnedState || !tx) {
      return failRedirect("state_mismatch");
    }

    if (tx.providerSlug !== providerSlug) {
      return failRedirect("provider_mismatch");
    }

    const runtime = getOidcRuntime(providerSlug);
    if (!runtime || !runtime.enabled) {
      return failRedirect("provider_disabled");
    }

    const {
      strategyConfig,
      client,
      pkceEnabled,
      claimConfig,
      securityConfig,
      pool,
      deps,
      bootstrapAdminGroups,
    } = runtime;

    let callbackPhase = "token_exchange";

    try {
      if (securityConfig.pkce !== false && !tx.codeVerifier) {
        return failRedirect("pkce_verifier_missing");
      }

      routeAuditLogger?.info?.("OIDC callback: starting token exchange", {
        providerSlug,
        tokenUrl: strategyConfig.tokenURL || null,
        jwksUrl: strategyConfig.jwksURL || null,
        httpTimeoutMs: resolveIdpHttpTimeoutMs(),
      });
      const exchangeStarted = Date.now();
      const { tokenSet, idClaims } = await exchangeAuthorizationCode({
        client,
        strategyConfig,
        callbackParams: req.query,
        sessionAuth: tx,
        pkceEnabled: pkceEnabled && securityConfig.pkce !== false,
      });
      routeAuditLogger?.info?.("OIDC callback: token exchange complete", {
        providerSlug,
        ms: Date.now() - exchangeStarted,
      });

      if (idClaims.iss && tx.issuer && idClaims.iss !== tx.issuer) {
        return failRedirect("issuer_mismatch", callbackPhase);
      }

      let userinfoClaims = null;
      let trustedUserinfo = false;
      if (strategyConfig.userInfoURL && tokenSet?.access_token) {
        callbackPhase = "userinfo";
        routeAuditLogger?.info?.("OIDC callback: starting userinfo fetch", {
          providerSlug,
          userInfoUrl: strategyConfig.userInfoURL,
        });
        const userinfoStarted = Date.now();
        try {
          userinfoClaims = await client.userinfo(tokenSet.access_token);
          routeAuditLogger?.info?.("OIDC callback: userinfo fetch complete", {
            providerSlug,
            ms: Date.now() - userinfoStarted,
          });
        } catch {
          deps.logger?.warn?.("OIDC UserInfo fetch failed", {
            providerSlug,
            ms: Date.now() - userinfoStarted,
          });
        }
      }

      callbackPhase = "complete_login";

      const userinfoCheck = validateUserinfoSubject(idClaims.sub, userinfoClaims, {
        logger: deps.logger,
        issuer: strategyConfig.issuer,
      });

      if (userinfoCheck.reason === "userinfo_sub_mismatch") {
        await safeAuditRoute({
          actorUserId: null,
          subjectUserId: null,
          action: "LOGIN_FAILED",
          targetType: "user",
          targetId: null,
          channel: null,
          workspaceId: null,
          metadata: {
            method: "oidc",
            provider_slug: providerSlug,
            reason: "userinfo_sub_mismatch",
            issuer: strategyConfig.issuer,
            id_token_sub: userinfoCheck.id_token_sub,
            userinfo_sub: userinfoCheck.userinfo_sub,
          },
        });
        await deleteOidcTxAndSave(req, returnedState);
        return res.redirect(
          buildLoginFailureRedirect(APP_URL, {
            error: "oidc_failed",
            provider: providerSlug,
            reason: "userinfo_sub_mismatch",
          }),
        );
      }

      trustedUserinfo = userinfoCheck.trusted === true;

      const user = await completeOidcLogin({
        providerSlug,
        issuer: strategyConfig.issuer,
        idClaims,
        userinfoClaims: trustedUserinfo ? userinfoClaims : null,
        trustedUserinfo,
        pool,
        claimConfig,
        securityConfig,
        bootstrapAdminGroups,
        canonicalizeEmail: deps.canonicalizeEmail,
        ensureInitialWorkspaceForUser: deps.ensureInitialWorkspaceForUser,
        writeAudit: deps.writeAudit,
        logger: deps.logger,
      });

      await deleteOidcTxAndSave(req, returnedState);

      return req.logIn(user, async (loginErr) => {
        if (loginErr) {
          await safeAuditRoute({
            actorUserId: null,
            subjectUserId: user?.id || null,
            action: "LOGIN_FAILED",
            targetType: "auth",
            targetId: providerSlug,
            channel: "web",
            workspaceId: null,
            metadata: {
              method: "oidc",
              provider_slug: providerSlug,
              reason: "session_login_error",
            },
          });
          return failRedirect("session_login_error");
        }
        req.session.sso = {
          providerSlug,
          protocol: "oidc",
          loginAt: new Date().toISOString(),
          // Retained solely as id_token_hint for RP-initiated logout. Okta rejects
          // an end-session request without it; other IdPs fall back to client_id.
          idToken: tokenSet?.id_token || null,
        };
        await saveSession(req);
        return res.redirect(`${APP_URL}${landingPath}`);
      });
    } catch (err) {
      let mappedReason = "callback_error";
      const msg = String(err?.message || "");
      if (/auto-link|local-password account exists/i.test(msg)) {
        mappedReason = "auto_link_disabled";
      } else if (/email_verified/i.test(msg)) {
        mappedReason = "email_not_verified_for_link";
      } else if (/email address/i.test(msg)) {
        mappedReason = "missing_email";
      } else if (/strict membership sync is enabled/i.test(msg)) {
        mappedReason = "no_group_mapping_matched";
      } else if (/could not resolve a user/i.test(msg)) {
        mappedReason = "oidc_no_user";
      }
      routeAuditLogger?.warn?.("OIDC callback failed", {
        providerSlug,
        reason: mappedReason,
        callbackPhase,
      });
      return failRedirect(mappedReason, callbackPhase);
    }
  });

  return router;
}

function getConfigRequirements() {
  return {
    required: [],
    optional: [
      "OIDC_TX_TTL_SEC",
      "MAX_PENDING_OIDC_TX",
      "SSO_IDP_HTTP_TIMEOUT_MS",
      "SSO_SECRETS_KEYRING",
      "SSO_SECRETS_KEYRING_FILE",
    ],
  };
}

function _resetOidcRuntimeForTests() {
  oidcRuntimes.clear();
}

function _setOidcRuntimeForTests(slug, runtime) {
  oidcRuntimes.set(slug, runtime);
}

function isOidcRuntimeReady() {
  for (const [, st] of getAllProviderRuntimeStatuses()) {
    if (st.type === "oidc" && (st.signInReady || st.registered)) {
      return true;
    }
  }
  return oidcRuntimes.size > 0;
}

function getOidcRuntimes() {
  return oidcRuntimes;
}

const provider = {
  name: "oidc",
  _sanitizeNextPath: sanitizeNextPath,
  _pruneOidcAuthSession: pruneOidcAuthSession,
  _stashOidcTx: stashOidcTx,
  _deleteOidcTxAndSave: deleteOidcTxAndSave,
  setupStrategy: setupOidcStrategy,
  setupOidcStrategy,
  isOidcRuntimeReady,
  getOidcRuntime,
  getOidcRuntimes,
  routes: oidcRoutes,
  oidcRoutes,
  getConfigRequirements,
  completeOidcLogin,
  _resetOidcRuntimeForTests,
  _setOidcRuntimeForTests,
  MAX_PENDING_OIDC_TX,
  OIDC_TX_TTL_SEC,
};

module.exports = provider;
