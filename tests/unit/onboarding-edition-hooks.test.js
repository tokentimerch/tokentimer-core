const { describe, it, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const {
  UNKNOWN,
  evaluateCapabilities,
  registerCapability,
  registerCapabilityOverride,
  resetCapabilityOverrides,
  resetRegisteredCapabilities,
} = require("../../apps/api/services/onboarding/capabilities");
const {
  buildSummary,
  hasSummaryProviders,
  registerSummaryProvider,
  resetSummaryProviders,
} = require("../../apps/api/services/onboarding/summary");
const {
  OnboardingValidationError,
  validateSessionWrite,
} = require("../../apps/api/services/onboarding/sessionSchema");

const find = (items, id) => items.find((c) => c.id === id);
const manager = { workspaceRole: "workspace_manager", smtpConfigured: true, certopsEnabled: true };

function emptyPool() {
  return {
    query: async (sql) => {
      if (sql.includes("COUNT(*)")) return { rows: [{ n: 0 }] };
      if (sql.includes("COUNT(DISTINCT")) return { rows: [{ n: 0 }] };
      return { rows: [] };
    },
  };
}

afterEach(() => {
  resetRegisteredCapabilities();
  resetCapabilityOverrides();
  resetSummaryProviders();
});

describe("registerCapability", () => {
  it("leaves the list unchanged when nothing is registered", () => {
    const ids = evaluateCapabilities(manager).map((c) => c.id);
    assert.equal(ids.includes("example.setup"), false);
    assert.equal(new Set(ids).size, ids.length);
  });

  it("adds a capability with its evaluator", () => {
    registerCapability({ id: "example.setup", group: "example" }, (ctx) => ({
      entitled: ctx.licensed === true,
      blockers: ctx.licensed ? [] : [{ code: "LICENSE", remediation: "Add a license." }],
    }));
    const base = evaluateCapabilities(manager);
    assert.equal(base.length, evaluateCapabilities({ ...manager, licensed: true }).length);
    assert.equal(find(base, "example.setup").state, "upgrade");
    assert.equal(find(base, "example.setup").blockers[0].code, "LICENSE");
    const ready = find(evaluateCapabilities({ ...manager, licensed: true }), "example.setup");
    assert.equal(ready.state, "ready");
    assert.equal(ready.group, "example");
    assert.deepEqual(ready.availableActions, ["use"]);
  });

  it("supports a system administrator scope", () => {
    registerCapability({ id: "example.admin", group: "example", scope: "system_admin" });
    const get = (ctx) => find(evaluateCapabilities({ ...manager, ...ctx }), "example.admin");
    assert.equal(get({ isSystemAdmin: true }).state, "ready");
    const other = get({ isSystemAdmin: false });
    assert.equal(other.state, "role_handoff");
    assert.match(other.blockers[0].remediation, /system administrator/);
    assert.equal(get({}).authorized, UNKNOWN);
  });

  it("still applies overrides to a registered capability", () => {
    registerCapability({ id: "example.setup", group: "example" });
    registerCapabilityOverride("example.setup", () => ({ supported: false }));
    assert.equal(find(evaluateCapabilities(manager), "example.setup").state, "hidden");
  });

  it("leaves the facts unknown when the evaluator throws", () => {
    registerCapability({ id: "example.setup", group: "example" }, () => {
      throw new Error("boom");
    });
    const items = evaluateCapabilities(manager);
    assert.equal(find(items, "example.setup").state, "unknown");
    assert.equal(find(items, "assets.manual").state, "ready");
  });

  it("rejects duplicates, base ids and malformed definitions", () => {
    registerCapability({ id: "example.setup", group: "example" });
    const bad = [
      [{ id: "example.setup", group: "example" }, /already registered/],
      [{ id: "assets.manual", group: "assets" }, /already registered/],
      [{ id: "NoDot", group: "x" }, /id must look like/],
      [{ id: "a.b", group: "" }, /group required/],
      [{ id: "a.b", group: "x", minRole: "root" }, /minRole/],
      [{ id: "a.b", group: "x", scope: "everyone" }, /scope/],
    ];
    for (const [def, message] of bad) {
      assert.throws(() => registerCapability(def), message);
    }
    assert.throws(() => registerCapability({ id: "a.b", group: "x" }, "nope"), /evaluator/);
    assert.throws(() => registerCapability(null), /definition required/);
  });
});

describe("registerSummaryProvider", () => {
  it("adds no edition block when nothing is registered", async () => {
    assert.equal(hasSummaryProviders(), false);
    const summary = await buildSummary(emptyPool(), { workspaceId: "w1", refs: {} });
    assert.equal("edition" in summary, false);
  });

  it("passes the workspace, database and caller to a provider", async () => {
    const pool = emptyPool();
    const seen = [];
    registerSummaryProvider("example", async (input) => {
      seen.push(input);
      return { configured: 1 };
    });
    const user = { id: 7, isSystemAdmin: true, workspaceRole: "admin" };
    const summary = await buildSummary(pool, { workspaceId: "w1", refs: {}, user });
    assert.deepEqual(summary.edition, { example: { configured: 1 } });
    assert.equal(seen[0].workspaceId, "w1");
    assert.equal(seen[0].db, pool);
    assert.deepEqual(seen[0].user, user);
    // The core keys are unaffected.
    assert.equal(summary.assets.total, 0);
  });

  it("reports unknown for a provider that fails or returns a non-object", async () => {
    registerSummaryProvider("throws", async () => {
      throw new Error("boom");
    });
    registerSummaryProvider("sync_throws", () => {
      throw new Error("boom");
    });
    registerSummaryProvider("list", async () => [1]);
    registerSummaryProvider("ok", async () => ({ n: 2 }));
    const summary = await buildSummary(emptyPool(), { workspaceId: "w1", refs: {} });
    assert.deepEqual(summary.edition, {
      throws: "unknown",
      sync_throws: "unknown",
      list: "unknown",
      ok: { n: 2 },
    });
  });

  it("rejects duplicate and malformed ids", () => {
    registerSummaryProvider("example", async () => ({}));
    assert.throws(() => registerSummaryProvider("example", async () => ({})), /already registered/);
    assert.throws(() => registerSummaryProvider("Bad Id", async () => ({})), /id must match/);
    assert.throws(() => registerSummaryProvider("fine", "nope"), /must be a function/);
  });
});

// Sessions store goal and step ids as free strings, so an edition needs no id
// registration. Only the generic key, size and credential rules apply.
describe("session ids for edition goals and steps", () => {
  it("accepts edition goal and step ids without registration", () => {
    const { patch } = validateSessionWrite({
      expectedRevision: 2,
      intent: { goal: "example_goal" },
      progress: { skipped: ["example_step"], example_step: { reviewed: true } },
    });
    assert.equal(patch.intent.goal, "example_goal");
    assert.deepEqual(patch.progress.skipped, ["example_step"]);
  });

  it("still rejects malformed ids and credential-like values", () => {
    const rejects = (body, code) =>
      assert.throws(
        () => validateSessionWrite(body),
        (e) => e instanceof OnboardingValidationError && e.code === code,
      );
    rejects({ expectedRevision: 1, intent: { goal: "x".repeat(513) } }, "VALUE_TOO_LONG");
    rejects({ expectedRevision: 1, progress: { "bad key": 1 } }, "INVALID_KEY");
    rejects({ expectedRevision: 1, progress: { example_secret: "x" } }, "SECRET_REJECTED");
    rejects({ expectedRevision: 1, intent: { goal: "ghp_abcdefghijklmnopqrstuvwxyz0123456789" } }, "SECRET_REJECTED");
  });
});
