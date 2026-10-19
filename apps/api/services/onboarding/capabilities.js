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
  "certops.adcs": false,
  "certops.vault_distribution": false,
});

const BASE_CAPABILITIES = Object.freeze([
  { id: "assets.manual", group: "assets", minRole: "workspace_manager" },
  { id: "assets.file_import", group: "assets", minRole: "workspace_manager" },
  { id: "monitoring.endpoint", group: "monitoring", minRole: "workspace_manager" },
  { id: "alerts.contact_groups", group: "alerts", minRole: "workspace_manager" },
  { id: "alerts.email_delivery", group: "alerts", minRole: "workspace_manager", needs: "smtp" },
  { id: "certops.core", group: "certops", minRole: "workspace_manager", needs: "certops" },
  { id: "certops.adcs", group: "certops", minRole: "admin", needs: "certops" },
  { id: "certops.vault_distribution", group: "certops", minRole: "workspace_manager", needs: "certops" },
]);

const overrides = new Map();
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

function toTriState(value) {
  if (value === true || value === false) return value;
  return UNKNOWN;
}

function authorize(ctx, minRole) {
  const rank = ROLE_RANK[ctx.workspaceRole];
  if (!rank) return UNKNOWN;
  return rank >= ROLE_RANK[minRole];
}

function baseCapability(def, ctx) {
  const blockers = [];
  const authorized = authorize(ctx, def.minRole);
  if (authorized === false) {
    blockers.push({
      code: "ROLE_REQUIRED",
      remediation:
        def.minRole === "admin"
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

function applyOverrides(capability, ctx) {
  let current = capability;
  for (const fn of overrides.get(capability.id) || []) {
    const patch = fn(ctx, current) || {};
    const next = { ...current };
    for (const fact of FACTS) {
      if (patch[fact] !== undefined) next[fact] = toTriState(patch[fact]);
    }
    if (Array.isArray(patch.blockers)) {
      next.blockers = [...current.blockers, ...patch.blockers];
    }
    if (Array.isArray(patch.availableActions)) {
      next.availableActions = patch.availableActions;
    }
    current = next;
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
  return BASE_CAPABILITIES.map((def) =>
    finalize(applyOverrides(baseCapability(def, ctx), ctx)),
  );
}

module.exports = {
  UNKNOWN,
  FACTS,
  QUALIFIED_FEATURES,
  registerCapabilityOverride,
  resetCapabilityOverrides,
  setDocsBaseUrl,
  getDocsBaseUrl,
  deriveState,
  evaluateCapabilities,
};
