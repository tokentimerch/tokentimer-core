const { describe, it, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const {
  UNKNOWN,
  deriveState,
  evaluateCapabilities,
  registerCapabilityOverride,
  resetCapabilityOverrides,
} = require("../../apps/api/services/onboarding/capabilities");

function find(items, id) {
  return items.find((c) => c.id === id);
}

const manager = {
  workspaceRole: "workspace_manager",
  smtpConfigured: true,
  certopsEnabled: true,
};

describe("onboarding capabilities", () => {
  afterEach(() => resetCapabilityOverrides());

  it("is ready for a manager when prerequisites are in place", () => {
    const items = evaluateCapabilities(manager);
    const cap = find(items, "monitoring.endpoint");
    assert.equal(cap.state, "ready");
    assert.deepEqual(cap.availableActions, ["use"]);
    assert.deepEqual(cap.blockers, []);
  });

  it("separates role handoff from configuration", () => {
    const viewer = find(
      evaluateCapabilities({ ...manager, workspaceRole: "viewer" }),
      "assets.manual",
    );
    assert.equal(viewer.authorized, false);
    assert.equal(viewer.state, "role_handoff");
    assert.equal(viewer.blockers[0].code, "ROLE_REQUIRED");
    assert.deepEqual(viewer.availableActions, []);
  });

  it("reports SMTP as a runbook state with role-aware remediation", () => {
    const base = { ...manager, smtpConfigured: false };
    const admin = find(
      evaluateCapabilities({ ...base, isSystemAdmin: true }),
      "alerts.email_delivery",
    );
    assert.equal(admin.state, "runbook");
    assert.match(admin.blockers[0].remediation, /System Settings/);
    const other = find(evaluateCapabilities(base), "alerts.email_delivery");
    assert.match(other.blockers[0].remediation, /system administrator/);
  });

  it("never treats unreadable sources as unavailable", () => {
    const items = evaluateCapabilities({
      workspaceRole: "workspace_manager",
      smtpConfigured: UNKNOWN,
      certopsEnabled: UNKNOWN,
    });
    const smtp = find(items, "alerts.email_delivery");
    assert.equal(smtp.configured, UNKNOWN);
    assert.equal(smtp.state, "unknown");
    assert.deepEqual(smtp.availableActions, ["use"]);
    assert.equal(find(items, "certops.core").state, "unknown");
    const noRole = find(evaluateCapabilities({}), "assets.manual");
    assert.equal(noRole.authorized, UNKNOWN);
  });

  it("keeps gated features visibly gated", () => {
    const items = evaluateCapabilities({ ...manager, workspaceRole: "admin" });
    for (const id of ["certops.adcs", "certops.vault_distribution"]) {
      const cap = find(items, id);
      assert.equal(cap.qualified, false);
      assert.equal(cap.state, "candidate");
      assert.equal(cap.availableActions.length, 0);
      assert.ok(cap.blockers.some((b) => b.code === "FEATURE_NOT_QUALIFIED"));
    }
  });

  it("flags disabled CertOps as a configuration runbook, not unsupported", () => {
    const cap = find(
      evaluateCapabilities({ ...manager, certopsEnabled: false }),
      "certops.core",
    );
    assert.equal(cap.supported, true);
    assert.equal(cap.state, "runbook");
    assert.equal(cap.blockers[0].code, "CERTOPS_DISABLED");
  });

  it("lets overlays change facts without forking", () => {
    registerCapabilityOverride("assets.file_import", () => ({
      entitled: false,
      blockers: [{ code: "PLAN_UPGRADE_REQUIRED", remediation: "Upgrade the plan." }],
    }));
    registerCapabilityOverride("monitoring.endpoint", () => ({ supported: false }));
    const items = evaluateCapabilities(manager);
    assert.equal(find(items, "assets.file_import").state, "upgrade");
    assert.equal(find(items, "monitoring.endpoint").state, "hidden");
    assert.equal(find(items, "assets.manual").state, "ready");
  });

  it("derives hidden before upgrade before role before candidate", () => {
    const all = {
      supported: false,
      entitled: false,
      authorized: false,
      qualified: false,
      configured: false,
    };
    assert.equal(deriveState(all), "hidden");
    assert.equal(deriveState({ ...all, supported: true }), "upgrade");
    assert.equal(deriveState({ ...all, supported: true, entitled: true }), "role_handoff");
    assert.equal(
      deriveState({ ...all, supported: true, entitled: true, authorized: true }),
      "candidate",
    );
  });
});
