/**
 * Multi-provider SAML authentication for TokenTimer.
 *
 * Single MultiSamlStrategy named `saml`; per-provider options from
 * sso_providers via provider-registry.js.
 * Routes: GET /auth/saml/:provider, POST /auth/saml/:provider/callback,
 * GET /auth/saml/:provider/metadata only.
 */

"use strict";

const { sanitizeNextPath } = require("../sso/login-redirect.js");

const { createHash, randomBytes } = require("node:crypto");
// Match the pinned node-saml POST form's onload handler.
const postSubmitHash = createHash("sha256").update("document.forms[0].submit()").digest("base64");
const { resolveSessionCookieOptions } = require("../session-cookie-options");
const { isValidEmail } = require("../utils/emailAddress");
const { extractFirst, extractAll } = require("../sso/claim-extractor");
const {
  ENTRA_GIVEN_NAME_PATHS,
  ENTRA_SURNAME_PATHS,
  isEntraGuestUpn,
  looksLikeEmail,
  normalizeEntraIdentityClaims,
} = require("../sso/entra-identity-normalize");
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
  bindSamlCacheToBrowser,
  startSamlCacheCleanupTimer,
} = require("../sso/saml-cache-provider.js");

/** @type {Map<string, object>} */
const samlRuntimes = new Map();

let routeAuditWriter = null;
let routeAuditLogger = console;
let routePool = null;
let multiSamlRegistered = false;

const parseCsv = (raw) =>
  String(raw || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

function finishSamlSetup(result) {
  return result;
}

function getSamlRuntime(slug) {
  return samlRuntimes.get(slug) || null;
}

function isSamlRuntimeReady(_passport) {
  for (const [, st] of getAllProviderRuntimeStatuses()) {
    if (st.type === "saml" && (st.signInReady || st.registered)) {
      return true;
    }
  }
  return multiSamlRegistered && samlRuntimes.size > 0;
}

async function handleSamlProfile(req, profile, done) {
  const providerSlug = String(req.params?.provider || "").trim();
  const runtime = getSamlRuntime(providerSlug);
  const logger = runtime?.deps?.logger || routeAuditLogger;
  const writeAudit = runtime?.deps?.writeAudit || routeAuditWriter;
  const pool = runtime?.pool || routePool;

  const safeAudit = async (params) => {
    if (!writeAudit) return false;
    try {
      await writeAudit(params);
      return true;
    } catch (err) {
      logger?.warn?.("SAML audit write failed", { error: err?.message });
      return false;
    }
  };

  if (!runtime || !runtime.enabled) {
    await safeAudit({
      actorUserId: null,
      subjectUserId: null,
      action: "LOGIN_FAILED",
      targetType: "auth",
      targetId: null,
      channel: "web",
      workspaceId: null,
      metadata: {
        method: "saml",
        provider_slug: providerSlug,
        reason: "provider_disabled",
      },
    });
    return done(new Error("provider_disabled"));
  }

  const { claimConfig, securityConfig, bootstrapAdminGroups, deps } = runtime;

  const rawEmail = extractFirst(profile, claimConfig.saml.email) || "";
  const rawDisplayName =
    extractFirst(profile, claimConfig.saml.displayName) ||
    `${profile.firstName || ""} ${profile.lastName || ""}`.trim();
  const subjectId = extractFirst(profile, claimConfig.saml.subject) || "";
  const normalized = normalizeEntraIdentityClaims({
    email: rawEmail,
    displayName: rawDisplayName,
    givenName: extractFirst(profile, ENTRA_GIVEN_NAME_PATHS),
    surname: extractFirst(profile, ENTRA_SURNAME_PATHS),
    subjectId,
  });
  const emailForLogin = normalized.email || rawEmail;
  const mailbox = emailForLogin.trim().toLowerCase();
  // The operator can trust the asserted mailbox for account linking. Only an
  // explicit verification attribute establishes mailbox ownership.
  const trustedSamlEmail =
    isValidEmail(rawEmail) && rawEmail.trim().toLowerCase() === mailbox
      ? mailbox
      : null;
  const assertedEmail = extractFirst(profile, "email");
  const verifiedEmail =
    trustedSamlEmail &&
    assertedEmail?.trim().toLowerCase() === mailbox &&
    extractFirst(profile, "email_verified") === "true"
      ? mailbox
      : null;
  const displayName =
    normalized.displayName ||
    (looksLikeEmail(emailForLogin)
      ? emailForLogin.split("@")[0]
      : emailForLogin);
  const idpGroups = extractAll(profile, claimConfig.saml.groups);

  try {
    if (!emailForLogin && !subjectId) {
      await safeAudit({
        actorUserId: null,
        subjectUserId: null,
        action: "LOGIN_FAILED",
        targetType: "user",
        targetId: null,
        channel: null,
        workspaceId: null,
        metadata: {
          method: "saml",
          provider_slug: providerSlug,
          reason: "missing_email",
        },
      });
      return done(new Error("SAML assertion did not include an email address"));
    }

    const resolved = await resolveUser({
      pool,
      providerSlug,
      protocol: "saml",
      subjectId,
      email: emailForLogin,
      displayName,
      allowAutoLink: securityConfig.allowAutoLinkLocalAccounts,
      verifiedEmail,
      trustedSamlEmail,
      canonicalizeEmail: deps.canonicalizeEmail,
    });

    if (!resolved.user) {
      await safeAudit({
        actorUserId: null,
        subjectUserId: null,
        action: "LOGIN_FAILED",
        targetType: "user",
        targetId: null,
        channel: null,
        workspaceId: null,
        metadata: {
          method: "saml",
          provider_slug: providerSlug,
          reason: resolved.reason || "no_user",
          subject_id: subjectId || null,
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
            return "SAML login requires a verified email address or an explicitly trusted SAML email claim to link an existing account.";
          default:
            return "SAML login could not resolve a user";
        }
      })();
      return done(new Error(reasonMessage));
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

    if (!resolved.isNewUser && resolved.user?.id) {
      try {
        const canonicalEmail = deps.canonicalizeEmail(emailForLogin);
        const currentEmail = String(resolved.user.email || "");
        const shouldFixEmail =
          resolved.user.auth_method !== "local" &&
          looksLikeEmail(emailForLogin) &&
          (isEntraGuestUpn(currentEmail) || currentEmail.includes("#EXT#"));
        // No-op mailbox assignments would revoke recipient proof.
        await pool.query(
          `UPDATE users
              SET display_name = CASE
                    WHEN $2 <> '' AND display_name LIKE '%#EXT#%' THEN $2
                    WHEN $2 <> '' AND display_name = email THEN $2
                    ELSE display_name
                  END,
                  ${shouldFixEmail ? "email = $3, email_original = $4," : ""}
                  updated_at = NOW()
            WHERE id = $1${shouldFixEmail ? " AND auth_method <> 'local'" : ""}`,
          [
            resolved.user.id,
            displayName,
            ...(shouldFixEmail ? [canonicalEmail, emailForLogin] : []),
          ],
        );
      } catch (profileErr) {
        logger?.warn?.("SAML: failed to refresh user profile from IdP claims", {
          error: profileErr?.message,
          userId: resolved.user.id,
        });
      }
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
      typeof deps.ensureInitialWorkspaceForUser === "function"
    ) {
      // A verified pending invitation can satisfy strict admission.
      await deps.ensureInitialWorkspaceForUser(
        resolved.user.id,
        deps.canonicalizeEmail(emailForLogin),
        displayName,
        { sso: true, verifiedEmail, invitationsOnly: true },
      );
    }
    if (
      requiresExistingMembership &&
      !(await hasAnyWorkspaceMembership(pool, resolved.user.id))
    ) {
      const loginAuditRecorded = await safeAudit({
        actorUserId: null,
        subjectUserId: resolved.user.id,
        action: "LOGIN_FAILED",
        targetType: "user",
        targetId: resolved.user.id,
        channel: null,
        workspaceId: null,
        metadata: {
          method: "saml",
          provider_slug: providerSlug,
          reason: "no_group_mapping_matched",
          subject_id: subjectId || null,
        },
      });
      return done(
        Object.assign(
          new Error(
            "No IdP group mapping matched this login and strict membership sync is enabled for this provider. Ask an admin to add a group mapping or grant workspace access.",
          ),
          { code: "no_group_mapping_matched", loginAuditRecorded },
        ),
      );
    }

    if (typeof deps.ensureInitialWorkspaceForUser === "function") {
      try {
        await deps.ensureInitialWorkspaceForUser(
          resolved.user.id,
          deps.canonicalizeEmail(emailForLogin),
          displayName,
          { sso: true, verifiedEmail },
        );
      } catch (workspaceErr) {
        logger?.warn?.("SAML: ensureInitialWorkspaceForUser failed", {
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

    await safeAudit({
      actorUserId: user.id,
      subjectUserId: user.id,
      action: "LOGIN_SUCCESS",
      targetType: "user",
      targetId: user.id,
      channel: null,
      workspaceId: null,
      metadata: buildSsoLoginSuccessMetadata({
        method: "saml",
        providerSlug,
        protocol: "saml",
        resolved,
        resolution,
        applied,
        userAfterLogin: user,
        subjectId,
        idpGroups,
        configuredAdminIdpGroups,
      }),
    });

    if (req.session) {
      req.session.sso = {
        providerSlug,
        protocol: "saml",
        loginAt: new Date().toISOString(),
      };
    }
    return done(null, user);
  } catch (err) {
    await safeAudit({
      actorUserId: null,
      subjectUserId: null,
      action: "LOGIN_FAILED",
      targetType: "user",
      targetId: null,
      channel: null,
      workspaceId: null,
      metadata: {
        method: "saml",
        provider_slug: providerSlug,
        reason: "exception",
      },
    });
    return done(err);
  }
}

function ensureMultiSamlStrategy(passport, MultiSamlStrategy) {
  if (multiSamlRegistered && passport._strategies?.saml) {
    return;
  }
  if (passport._strategies?.saml) {
    delete passport._strategies.saml;
  }

  passport.use(
    "saml",
    new MultiSamlStrategy(
      {
        passReqToCallback: true,
        getSamlOptions: async (req, done) => {
          try {
            const slug = String(req.params?.provider || "").trim();
            const runtime = getSamlRuntime(slug);
            if (!runtime || !runtime.enabled) {
              return done(new Error("unknown_or_disabled_saml_provider"));
            }
            return done(null, {
              ...runtime.strategyConfig,
              cacheProvider: req.samlBrowserCache || runtime.cacheProvider,
              ...(req.samlRelayState
                ? { additionalAuthorizeParams: { RelayState: req.samlRelayState } }
                : {}),
            });
          } catch (err) {
            return done(err);
          }
        },
      },
      (req, profile, done) => handleSamlProfile(req, profile, done),
      (req, profile, done) => done(null, profile),
    ),
  );
  multiSamlRegistered = true;
}

async function setupSamlStrategy(passport, pool, SamlStrategyModule, deps = {}) {
  const logger = deps.logger || console;
  routePool = pool;
  routeAuditWriter = deps.writeAudit || null;
  routeAuditLogger = logger;

  const MultiSamlStrategy =
    SamlStrategyModule?.MultiSamlStrategy || SamlStrategyModule;
  if (!MultiSamlStrategy) {
    return finishSamlSetup({ registered: false, reason: "saml_module_missing" });
  }

  const { listProviders, loadDecryptedSecret } = require("../sso/provider-registry.js");
  const builders = createProviderStrategyConfig({ logger });

  samlRuntimes.clear();
  for (const [slug, status] of getAllProviderRuntimeStatuses()) {
    if (status.type === "saml") {
      removeProviderRuntimeStatus(slug);
    }
  }

  let providers;
  try {
    const loadProviders = deps.loadProviders || listProviders;
    const all = await loadProviders(pool, { includeStatuses: false });
    providers = all.filter((p) => p.type === "saml");
  } catch (err) {
    logger.error?.("SAML provider list failed", { error: err?.message });
    return finishSamlSetup({ registered: false, reason: "registry_unavailable" });
  }

  const canonicalizeEmail =
    deps.canonicalizeEmail || ((e) => String(e || "").trim().toLowerCase());
  const ensureInitialWorkspaceForUser = deps.ensureInitialWorkspaceForUser || null;
  const writeAudit = deps.writeAudit || null;

  let loaded = 0;

  for (const provider of providers) {
    const slug = provider.slug;
    if (!provider.enabled) {
      setProviderRuntimeStatus(slug, {
        type: "saml",
        registered: false,
        signInReady: false,
        reason: provider.disabledReason || "provider_disabled",
      });
      continue;
    }

    try {
      const secrets = {};
      for (const name of ["decryption_key", "signing_key"]) {
        try {
          const value = await loadDecryptedSecret(pool, slug, name);
          if (value) secrets[name] = value;
        } catch (secretErr) {
          const reason =
            secretErr?.code === "secret_keyring_missing" ||
            /secret_keyring_missing/i.test(String(secretErr?.message))
              ? "secret_keyring_missing"
              : null;
          if (reason && name === "signing_key") {
            continue;
          }
          if (reason) {
            setProviderRuntimeStatus(slug, {
              type: "saml",
              registered: false,
              signInReady: false,
              reason,
            });
            throw secretErr;
          }
        }
      }

      const strategyConfig = await builders.buildSamlStrategyConfigFromProvider(
        pool,
        provider,
        secrets,
      );
      if (!strategyConfig) {
        setProviderRuntimeStatus(slug, {
          type: "saml",
          registered: false,
          signInReady: false,
          reason: "not_configured",
        });
        continue;
      }

      samlRuntimes.set(slug, {
        providerSlug: slug,
        displayName: provider.displayName || slug,
        enabled: true,
        strategyConfig,
        cacheProvider: strategyConfig.cacheProvider,
        claimConfig: builders.buildClaimConfigFromProvider(provider),
        securityConfig: builders.buildSecurityConfigFromProvider(provider),
        bootstrapAdminGroups: parseCsv(
          provider.config?.bootstrap_admin_groups ||
            provider.config?.admin_groups ||
            "",
        ),
        pool,
        deps: {
          canonicalizeEmail,
          ensureInitialWorkspaceForUser,
          writeAudit,
          logger,
        },
      });

      setProviderRuntimeStatus(slug, {
        type: "saml",
        registered: true,
        signInReady: true,
      });
      loaded += 1;
      logger.info?.("SAML provider runtime registered", { slug });
    } catch (err) {
      const msg = String(err?.message || "");
      const reason =
        err?.code === "signing_key_missing"
          ? "signing_key_missing"
          : /saml_request_cache|cacheProvider|InResponseTo cache/i.test(msg)
            ? "saml_cache_provider_unavailable"
            : "config_build_failed";
      setProviderRuntimeStatus(slug, {
        type: "saml",
        registered: false,
        signInReady: false,
        reason,
      });
      logger.warn?.("SAML provider runtime build failed", {
        slug,
        error: err?.message,
      });
    }
  }

  if (loaded > 0) {
    ensureMultiSamlStrategy(passport, MultiSamlStrategy);
    startSamlCacheCleanupTimer(pool, { logger });
  } else {
    multiSamlRegistered = false;
    if (passport._strategies?.saml) {
      delete passport._strategies.saml;
    }
  }

  return finishSamlSetup({
    registered: loaded > 0,
    loaded,
    reason: loaded > 0 ? undefined : "not_configured",
  });
}

function samlRoutes(passport, express) {
  const router = express.Router();
  const APP_URL = process.env.APP_URL || "http://localhost:5173";

  const safeAudit = async (params) => {
    if (!routeAuditWriter) return;
    try {
      await routeAuditWriter(params);
    } catch (err) {
      routeAuditLogger?.warn?.("SAML route audit write failed", {
        error: err?.message,
      });
    }
  };

  // The IdP POST can arrive without the ordinary SameSite=Lax session cookie.
  // Give only this short-lived, host-only correlation cookie cross-site scope.
  function bindBrowser(req, res, runtime, starting) {
    if (!runtime.cacheProvider) return;
    const secure = resolveSessionCookieOptions().secure ||
      runtime.strategyConfig.callbackUrl.startsWith("https://");
    const name = secure ? "__Host-tt-saml-browser" : "tt-saml-browser";
    const cookie = req.cookies?.[name];
    const browserId = typeof cookie === "string" && /^[a-f0-9]{64}$/.test(cookie)
      ? cookie : randomBytes(32).toString("hex");
    if (starting) {
      res.cookie(name, browserId, {
        secure, sameSite: secure ? "none" : "lax", httpOnly: true, path: "/",
        maxAge: runtime.cacheProvider.ttlMs,
      });
    }
    req.samlBrowserCache = bindSamlCacheToBrowser(runtime.cacheProvider, browserId);
  }

  router.get("/auth/saml/:provider", (req, res, next) => {
    const slug = String(req.params.provider || "").trim();
    const runtime = getSamlRuntime(slug);
    if (!runtime || !runtime.enabled || !isSamlRuntimeReady(passport)) {
      return res.redirect(`${APP_URL}/login?error=saml_failed`);
    }
    bindBrowser(req, res, runtime, true);
    if (runtime.strategyConfig.authnRequestBinding === "HTTP-POST") {
      const idpOrigin = new URL(runtime.strategyConfig.entryPoint).origin;
      res.setHeader("Content-Security-Policy",
        `default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action ${idpOrigin}; script-src 'unsafe-hashes' 'sha256-${postSubmitHash}'`);
    }
    // Passport skips per-call parameters when it sends an AuthnRequest by POST.
    req.samlRelayState = sanitizeNextPath(req.query?.next);
    passport.authenticate("saml")(req, res, next);
  });

  router.post(
    "/auth/saml/:provider/callback",
    express.urlencoded({ extended: false }),
    (req, res, next) => {
      const slug = String(req.params.provider || "").trim();
      const runtime = getSamlRuntime(slug);
      if (!runtime || !runtime.enabled || !isSamlRuntimeReady(passport)) {
        return res.redirect(`${APP_URL}/login?error=provider_disabled`);
      }
      bindBrowser(req, res, runtime, false);
      const relay = sanitizeNextPath(req.body?.RelayState);
      const landingPath = relay || "/dashboard";
      passport.authenticate("saml", async (err, user) => {
        if (err || !user) {
          const strictDenial = err?.code === "no_group_mapping_matched";
          let reason =
            err?.message === "provider_disabled" ||
            err?.message === "unknown_or_disabled_saml_provider"
              ? "provider_disabled"
              : err
                ? "callback_error"
                : "no_user";
          if (strictDenial) reason = "no_group_mapping_matched";
          if (!strictDenial || err.loginAuditRecorded !== true) {
            await safeAudit({
              actorUserId: null,
              subjectUserId: null,
              action: "LOGIN_FAILED",
              targetType: "auth",
              targetId: null,
              channel: "web",
              workspaceId: null,
              metadata: {
                method: "saml",
                provider_slug: slug,
                protocol: "saml",
                reason,
                path: req.path,
              },
            });
          }
          const errorCode =
            reason === "provider_disabled" ? "provider_disabled" : "saml_failed";
          return res.redirect(`${APP_URL}/login?error=${errorCode}`);
        }
        req.logIn(user, async (loginErr) => {
          if (loginErr) {
            await safeAudit({
              actorUserId: null,
              subjectUserId: user?.id || null,
              action: "LOGIN_FAILED",
              targetType: "auth",
              targetId: null,
              channel: "web",
              workspaceId: null,
              metadata: {
                method: "saml",
                provider_slug: slug,
                reason: "session_login_error",
              },
            });
            return res.redirect(`${APP_URL}/login?error=saml_failed`);
          }
          if (req.session && !req.session.sso) {
            req.session.sso = {
              providerSlug: slug,
              protocol: "saml",
              loginAt: new Date().toISOString(),
            };
          }
          return res.redirect(`${APP_URL}${landingPath}`);
        });
      })(req, res, next);
    },
  );

  router.get("/auth/saml/:provider/metadata", (req, res) => {
    const slug = String(req.params.provider || "").trim();
    const runtime = getSamlRuntime(slug);
    if (!runtime || !runtime.enabled) {
      return res
        .status(501)
        .json({ error: "SAML metadata generation not available" });
    }
    try {
      const strategy = passport._strategy("saml");
      if (
        strategy &&
        typeof strategy.generateServiceProviderMetadata === "function"
      ) {
        req.params.provider = slug;
        res.type("application/xml");
        return strategy.generateServiceProviderMetadata(req, null, null, (err, xml) => {
          if (err) {
            return res.status(500).json({ error: "Failed to generate SAML metadata" });
          }
          return res.send(xml);
        });
      }
      return res
        .status(501)
        .json({ error: "SAML metadata generation not available" });
    } catch (_err) {
      return res.status(500).json({ error: "Failed to generate SAML metadata" });
    }
  });

  return router;
}

function getConfigRequirements() {
  return {
    required: [],
    optional: [
      "SAML_CACHE_TTL_SEC",
      "SAML_CACHE_CLEANUP_INTERVAL_MS",
      "SSO_SECRETS_KEYRING",
      "SSO_SECRETS_KEYRING_FILE",
    ],
  };
}

function _resetSamlRuntimeForTests() {
  samlRuntimes.clear();
  multiSamlRegistered = false;
}

function _setSamlRuntimeForTests(slug, runtime) {
  samlRuntimes.set(slug, runtime);
}

function getSamlRuntimes() {
  return samlRuntimes;
}

const provider = {
  name: "saml",
  setupStrategy: setupSamlStrategy,
  setupSamlStrategy,
  isSamlRuntimeReady,
  getSamlRuntime,
  getSamlRuntimes,
  routes: samlRoutes,
  samlRoutes,
  getConfigRequirements,
  _sanitizeNextPath: sanitizeNextPath,
  _resetSamlRuntimeForTests,
  _setSamlRuntimeForTests,
  handleSamlProfile,
};

module.exports = provider;
