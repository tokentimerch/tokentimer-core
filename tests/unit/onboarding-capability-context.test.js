"use strict";

const { test, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const {
  registerCapabilityContextProvider,
  resetCapabilityContextProviders,
  hasCapabilityContextProviders,
  readCapabilityContext,
  registerCapabilityOverride,
  resetCapabilityOverrides,
  evaluateCapabilities,
} = require("../../apps/api/services/onboarding/capabilities");

afterEach(() => {
  resetCapabilityContextProviders();
  resetCapabilityOverrides();
});

test("no edition provider means no added context or database work", async () => {
  assert.equal(hasCapabilityContextProviders(), false);
  const db = { query() { assert.fail("unexpected database query"); } };
  assert.deepEqual(await readCapabilityContext(db), {});
});

test("providers receive scoped caller facts once per request, without caching", async () => {
  const db = {};
  const seen = [];
  registerCapabilityContextProvider("license", async (input) => {
    seen.push(input);
    return { entitled: input.workspaceId === "workspace-a" };
  });
  assert.equal(hasCapabilityContextProviders(), true);
  const user = { id: 4, workspaceRole: "viewer", isSystemAdmin: false };
  const [a, b] = await Promise.all([
    readCapabilityContext(db, { user, workspaceId: "workspace-a" }),
    readCapabilityContext(db, { user, workspaceId: "workspace-b" }),
  ]);
  assert.deepEqual(a, { license: { entitled: true } });
  assert.deepEqual(b, { license: { entitled: false } });
  assert.equal(seen.length, 2);
  assert.equal(seen[0].db, db);
  assert.deepEqual(seen[0].user, user);
  assert.notEqual(seen[0].user, user);
  assert.ok(Object.isFrozen(seen[0].user));
});

test("failed or invalid context is null and cannot grant an entitlement", async () => {
  registerCapabilityContextProvider("failed", () => { throw new Error("license unavailable"); });
  registerCapabilityContextProvider("rejected", async () => { throw new Error("read failed"); });
  registerCapabilityContextProvider("invalid", async () => [true]);
  registerCapabilityContextProvider("date", async () => new Date());
  registerCapabilityContextProvider("good", async () => ({ entitled: false }));
  const edition = await readCapabilityContext({});
  assert.deepEqual(edition, {
    failed: null, rejected: null, invalid: null, date: null, good: { entitled: false },
  });
  registerCapabilityOverride("integrations.aws", (ctx) => ({
    entitled: ctx.edition.failed?.entitled ?? "unknown",
  }));
  const item = evaluateCapabilities({ workspaceRole: "admin", edition })
    .find((cap) => cap.id === "integrations.aws");
  assert.equal(item.entitled, "unknown");
  assert.equal(item.state, "unknown");
});

test("edition facts stay in their namespace and do not replace caller authority", async () => {
  registerCapabilityContextProvider("example", async () => ({
    workspaceRole: "admin", isSystemAdmin: true, certopsEnabled: true,
  }));
  const edition = await readCapabilityContext({}, {
    user: { workspaceRole: "viewer", isSystemAdmin: false }, workspaceId: "w1",
  });
  const items = evaluateCapabilities({
    workspaceRole: "viewer", isSystemAdmin: false, certopsEnabled: false, edition,
  });
  assert.equal(items.find((cap) => cap.id === "assets.manual").authorized, false);
  assert.equal(items.find((cap) => cap.id === "certops.core").configured, false);
});

test("duplicate and malformed providers are refused", () => {
  registerCapabilityContextProvider("example", async () => ({}));
  assert.throws(() => registerCapabilityContextProvider("example", () => ({})), /already registered/);
  for (const id of ["", "Bad Id", "x".repeat(41), "__proto__"]) {
    assert.throws(() => registerCapabilityContextProvider(id, () => ({})), /id must match/);
  }
  assert.throws(() => registerCapabilityContextProvider("valid", true), /must be a function/);
});

test("an unresponsive provider times out without blocking the capability list", async () => {
  registerCapabilityContextProvider("stuck", () => new Promise(() => {}));
  assert.deepEqual(await readCapabilityContext({}), { stuck: null });
});
