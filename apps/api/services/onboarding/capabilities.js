"use strict";

// Capability model for the onboarding wizard. Every fact is tri-state:
// true, false or "unknown". "unknown" means the source could not be read
// (for example a non-admin who cannot see a deployment setting) and must
// never be treated as "not available". Cloud and enterprise register
// overrides instead of forking the wizard.

const UNKNOWN = "unknown";
const ROLE_RANK = Object.freeze({ viewer: 1, workspace_manager: 2, admin: 3 });
const FACTS = Object.freeze([
  "supported",
  "entitled",
  "authorized",
  "qualified",
  "configured",
]);

// Features that stay candidates until their real-host release evidence
// exists. Flip a value only in the release that qualifies it.
const QUALIFIED_FEATURES = Object.freeze({
  // Qualified in 0.18.0 (agent qualified-capabilities manifest). Add an id here
  // with false for a feature that ships ahead of its real-host qualification.
});

const BASE_CAPABILITIES = Object.freeze([
  { id: "assets.manual", group: "assets", minRole: "workspace_manager" },
  { id: "assets.file_import", group: "assets", minRole: "workspace_manager" },
  { id: "monitoring.endpoint", group: "monitoring", minRole: "workspace_manager" },
  // Manual scan-and-import per provider. Scheduled auto-sync is deliberately
  // a separate capability: it has its own role, entitlement and edition rules.
  ...[
    "github",
    "gitlab",
    "vault",
    "aws",
    "azure",
    "azure-ad",
    "gcp",
  ].map((provider) => ({
    id: `integrations.${provider}`,
    group: "integrations",
    minRole: "workspace_manager",
  })),
  { id: "autosync.github", group: "integrations", minRole: "workspace_manager" },
  { id: "autosync.gitlab", group: "integrations", minRole: "workspace_manager" },
  { id: "alerts.contact_groups", group: "alerts", minRole: "workspace_manager" },
  { id: "alerts.email_delivery", group: "alerts", minRole: "workspace_manager", needs: "smtp" },
  { id: "certops.core", group: "certops", minRole: "workspace_manager", needs: "certops" },
  { id: "certops.adcs", group: "certops", minRole: "admin", needs: "certops" },
  { id: "certops.vault_distribution", group: "certops", minRole: "workspace_manager", needs: "certops" },
]);

const overrides = new Map();
// Capabilities an edition adds on top of BASE_CAPABILITIES.
const registered = new Map();
let docsBaseUrl = "https://tokentimer.ch/docs/self-hosted";

/** Overlay hook: Cloud and Enterprise point wizard doc links at their editions. */
function setDocsBaseUrl(url) {
  if (typeof url !== "string" || !/^https:\/\/[^\s]+$/.test(url)) {
    throw new Error("docs base URL must be an https URL");
  }
  docsBaseUrl = url.replace(/\/+$/, "");
}

function getDocsBaseUrl() {
  return docsBaseUrl;
}

/**
 * Overlay hook. `fn(ctx, capability)` may return a partial object with any of
 * the five facts, `blockers` (appended) or `availableActions`.
 */
function registerCapabilityOverride(id, fn) {
  if (typeof id !== "string" || !id) throw new Error("capability id required");
  if (typeof fn !== "function") throw new Error("override must be a function");
  const list = overrides.get(id) || [];
  list.push(fn);
  overrides.set(id, list);
}

function resetCapabilityOverrides() {
  overrides.clear();
}

const CAPABILITY_ID = /^[a-z][a-z0-9_]*(\.[a-z0-9_-]+)+$/;

/**
 * Edition hook: adds a capability id the base list does not know. `def` is
 * { id, group, minRole?, scope? } where `scope: "system_admin"` replaces the
 * workspace role check with the system administrator flag. `evaluate(ctx,
 * capability)` is optional, synchronous and returns the same partial object as
 * an override (facts, blockers, availableActions). A throwing evaluator leaves
 * the facts unknown instead of failing the whole list.
 */
function registerCapability(def, evaluate) {
  if (!def || typeof def !== "object") throw new Error("capability definition required");
  if (typeof def.id !== "string" || !CAPABILITY_ID.test(def.id)) {
    throw new Error("capability id must look like area.name");
  }
  if (BASE_CAPABILITIES.some((c) => c.id === def.id) || registered.has(def.id)) {
    throw new Error(`capability "${def.id}" is already registered`);
  }
  if (typeof def.group !== "string" || !def.group) {
    throw new Error("capability group required");
  }
  const minRole = def.minRole === undefined ? "viewer" : def.minRole;
  if (!ROLE_RANK[minRole]) throw new Error("capability minRole is not a known role");
  if (def.scope !== undefined && def.scope !== "system_admin") {
    throw new Error("capability scope must be system_admin");
  }
  if (evaluate !== undefined && typeof evaluate !== "function") {
    throw new Error("capability evaluator must be a function");
  }
  registered.set(def.id, {
    def: { id: def.id, group: def.group, minRole, scope: def.scope },
    evaluate,
  });
}

function resetRegisteredCapabilities() {
  registered.clear();
}

function toTriState(value) {
  if (value === true || value === false) return value;
  return UNKNOWN;
}

function authorize(ctx, def) {
  if (def.scope === "system_admin") {
    return typeof ctx.isSystemAdmin === "boolean" ? ctx.isSystemAdmin : UNKNOWN;
  }
  const rank = ROLE_RANK[ctx.workspaceRole];
  if (!rank) return UNKNOWN;
  return rank >= ROLE_RANK[def.minRole];
}

function baseCapability(def, ctx) {
  const blockers = [];
  const authorized = authorize(ctx, def);
  if (authorized === false) {
    blockers.push({
      code: "ROLE_REQUIRED",
      remediation:
        def.scope === "system_admin"
          ? "Ask a system administrator to complete this step."
          : def.minRole === "admin"
            ? "Ask a workspace administrator to complete this step."
            : "Ask a workspace manager or administrator to complete this step.",
    });
  }

  let configured = true;
  if (def.needs === "certops") configured = toTriState(ctx.certopsEnabled);
  if (def.needs === "smtp") configured = toTriState(ctx.smtpConfigured);
  if (configured === false) {
    blockers.push(
      def.needs === "smtp"
        ? {
            code: "SMTP_NOT_CONFIGURED",
            remediation: ctx.isSystemAdmin
              ? "Configure SMTP in System Settings."
              : "Ask a system administrator to configure SMTP.",
          }
        : {
            code: "CERTOPS_DISABLED",
            remediation:
              "Certificate management is disabled on this deployment. An operator must enable it.",
          },
    );
  }

  const qualified = Object.prototype.hasOwnProperty.call(
    QUALIFIED_FEATURES,
    def.id,
  )
    ? QUALIFIED_FEATURES[def.id]
    : true;
  if (qualified === false) {
    blockers.push({
      code: "FEATURE_NOT_QUALIFIED",
      remediation:
        "This feature is a candidate and is not production-qualified yet.",
    });
  }

  return {
    id: def.id,
    group: def.group,
    supported: true,
    entitled: true,
    authorized,
    qualified,
    configured,
    blockers,
  };
}

function applyPatch(current, patch) {
  const next = { ...current };
  const p = patch || {};
  for (const fact of FACTS) {
    if (p[fact] !== undefined) next[fact] = toTriState(p[fact]);
  }
  if (Array.isArray(p.blockers)) {
    next.blockers = [...current.blockers, ...p.blockers];
  }
  if (Array.isArray(p.availableActions)) {
    next.availableActions = p.availableActions;
  }
  return next;
}

function applyOverrides(capability, ctx) {
  let current = capability;
  for (const fn of overrides.get(capability.id) || []) {
    current = applyPatch(current, fn(ctx, current));
  }
  return current;
}

/**
 * Maps the facts to the single behavior the wizard shows. Order matters: a
 * missing edition feature hides the item before any permission question.
 */
function deriveState(capability) {
  if (capability.supported === false) return "hidden";
  if (capability.entitled === false) return "upgrade";
  if (capability.authorized === false) return "role_handoff";
  if (capability.qualified === false) return "candidate";
  if (capability.configured === false) return "runbook";
  if (FACTS.some((fact) => capability[fact] === UNKNOWN)) return "unknown";
  return "ready";
}

function finalize(capability) {
  const state = deriveState(capability);
  const availableActions =
    capability.availableActions !== undefined
      ? capability.availableActions
      : state === "ready" || state === "unknown"
        ? ["use"]
        : [];
  return { ...capability, state, availableActions };
}

function evaluateCapabilities(ctx = {}) {
  const items = BASE_CAPABILITIES.map((def) =>
    finalize(applyOverrides(baseCapability(def, ctx), ctx)),
  );
  for (const { def, evaluate } of registered.values()) {
    let capability = baseCapability(def, ctx);
    if (evaluate) {
      try {
        capability = applyPatch(capability, evaluate(ctx, capability));
      } catch {
        // A faulty edition evaluator must not break the list: facts it
        // would have set stay unknown.
        capability = { ...capability, configured: UNKNOWN };
      }
    }
    items.push(finalize(applyOverrides(capability, ctx)));
  }
  return items;
}

module.exports = {
  UNKNOWN,
  FACTS,
  QUALIFIED_FEATURES,
  registerCapability,
  registerCapabilityOverride,
  resetCapabilityOverrides,
  resetRegisteredCapabilities,
  setDocsBaseUrl,
  getDocsBaseUrl,
  deriveState,
  evaluateCapabilities,
};
