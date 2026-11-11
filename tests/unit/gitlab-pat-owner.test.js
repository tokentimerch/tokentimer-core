"use strict";

const assert = require("node:assert/strict");
const { test } = require("node:test");
const Module = require("node:module");

const modulePath = require.resolve("../../apps/api/services/gitlabIntegration");
const filters = { includePATs: true };

function httpError(status) {
  return Object.assign(new Error(`HTTP ${status}`), {
    response: { status, data: {} },
  });
}

function scanner({
  admin = true,
  username = "scanner-admin",
  users = [],
  pats = [],
  lookup = () => {
    throw httpError(404);
  },
  respond,
} = {}) {
  const calls = [];
  const originalLoad = Module._load;
  delete require.cache[modulePath];
  Module._load = function (request, parent, isMain) {
    if (request === "../utils/logger") {
      return {
        logger: Object.fromEntries(
          ["info", "debug", "warn", "error"].map((level) => [level, () => {}]),
        ),
      };
    }
    if (request === "axios") {
      return async (config) => {
        const pathname = new URL(config.url).pathname;
        calls.push({ pathname, params: config.params, timeout: config.timeout });
        if (respond) {
          const response = await respond(pathname, config);
          if (response !== undefined) return { data: response };
        }
        if (pathname === "/api/v4/user") {
          return { data: { id: 1, username, is_admin: admin } };
        }
        if (pathname === "/api/v4/users") {
          const start = (config.params.page - 1) * config.params.per_page;
          return { data: users.slice(start, start + config.params.per_page) };
        }
        if (pathname === "/api/v4/personal_access_tokens") {
          const start = ((config.params.page || 1) - 1) * 100;
          return { data: pats.slice(start, start + 100) };
        }
        const match = pathname.match(/^\/api\/v4\/users\/(\d+)$/);
        if (match) return { data: await lookup(Number(match[1])) };
        return { data: [] };
      };
    }
    return originalLoad.call(this, request, parent, isMain);
  };
  let gitlab;
  try {
    gitlab = require(modulePath);
  } finally {
    Module._load = originalLoad;
    delete require.cache[modulePath];
  }
  return {
    calls,
    lookupCalls: () =>
      calls.filter((call) => /^\/api\/v4\/users\/\d+$/.test(call.pathname)),
    scan: (options = {}) =>
      gitlab.scanGitLab({
        baseUrl: "https://gitlab.example.test",
        token: "fixture-token",
        include: { tokens: true, keys: false },
        filters,
        ...options,
      }),
  };
}

function pat(id, userId, extra = {}) {
  return { id, user_id: userId, active: true, ...extra };
}

function assertComplete(result, complete = true) {
  const summary = result.summary.find(
    (entry) => entry.type === "personal_access_tokens",
  );
  assert.equal(summary.complete, complete);
  assert.equal(summary.truncated, !complete);
}

test("non-admin missing or invalid identity IDs fail before owner enrichment", async () => {
  for (const id of [undefined, null, 0, -1, "1"]) {
    const fixture = scanner({
      admin: false,
      pats: [pat(10, id)],
      respond: (path) => path === "/api/v4/user"
        ? { id, username: "unproven", is_admin: false } : undefined,
    });
    await assert.rejects(fixture.scan(), { status: 502 });
    assert.equal(fixture.lookupCalls().length, 0);
  }
});

test("admin PAT owners come from the user cache without Admin suffixes or token metadata", async () => {
  const fixture = scanner({
    users: [{ id: 2, username: "owner", is_admin: true }],
    pats: [
      pat(10, 2, {
        name: "not-the-owner (Admin)",
        used_by: "consumer",
        location: "gitlab:users/wrong/personal_access_tokens/10",
      }),
      pat(11, undefined, { username: "not-proven", owner_username: "wrong" }),
    ],
  });
  const result = await fixture.scan();
  assert.equal(result.items[0].owner_username, "owner");
  assert.equal(result.items[0].gitlab_owner, "owner");
  assert.equal(result.items[0].gitlab_owner_is_admin, true);
  assert.equal(result.items[1].owner_username, null);
  assert.equal(fixture.lookupCalls().length, 0);
  assertComplete(result);
});

test("admin resolves inactive owners by ID and caches deleted owners", async () => {
  const fixture = scanner({
    pats: [pat(10, 2), pat(11, 2), pat(12, 3), pat(13, 3)],
    lookup: (id) => {
      if (id === 2) return { id, username: "inactive-owner", state: "blocked" };
      throw httpError(404);
    },
  });
  const result = await fixture.scan();
  assert.deepEqual(
    result.items.map((item) => item.owner_username),
    ["inactive-owner", "inactive-owner", null, null],
  );
  assert.deepEqual(
    fixture.lookupCalls().map((call) => call.pathname),
    ["/api/v4/users/2", "/api/v4/users/3"],
  );
  assert.ok(fixture.lookupCalls().every((call) => call.timeout === 5000));
  assertComplete(result);
});

test("admin resolves owners beyond the 10000 active-user cache cap", async () => {
  const fixture = scanner({
    users: Array.from({ length: 10000 }, (_, index) => ({
      id: index + 1,
      username: `owner-${index + 1}`,
    })),
    pats: [pat(10, 10001)],
    lookup: (id) => ({ id, username: "beyond-cap" }),
  });
  const result = await fixture.scan();
  assert.equal(result.items[0].owner_username, "beyond-cap");
  const userPages = fixture.calls.filter(
    (call) => call.pathname === "/api/v4/users",
  );
  assert.equal(userPages.length, 100);
  assert.ok(userPages.every((call) => call.params.active === true));
  assert.equal(fixture.lookupCalls().length, 1);
  assertComplete(result);
});

for (const status of [401, 403, 405, 429, 501]) {
  test(`admin stops owner fallback on ${status} without marking inventory incomplete`, async () => {
    const fixture = scanner({
      pats: [pat(10, 2), pat(11, 3), pat(12, 2)],
      lookup: () => {
        throw httpError(status);
      },
    });
    const result = await fixture.scan();
    assert.equal(result.items.length, 3);
    assert.ok(result.items.every((item) => item.owner_username === null));
    assert.equal(fixture.lookupCalls().length, 1);
    assertComplete(result);
  });
}

for (const status of [401, 403, 404, 429, 503]) {
  test(`admin bulk user failure ${status} does not abort PAT enumeration`, async () => {
    const fixture = scanner({
      pats: [pat(10, 2)],
      respond: (pathname) => {
        if (pathname === "/api/v4/users") throw httpError(status);
      },
      lookup: (id) => ({ id, username: "fallback-owner" }),
    });
    const result = await fixture.scan();
    assert.equal(result.items.length, 1);
    assert.equal(
      result.items[0].owner_username,
      status === 503 ? "fallback-owner" : null,
    );
    assert.equal(fixture.lookupCalls().length, status === 503 ? 1 : 0);
    assertComplete(result);
  });
}

test("admin caches transient lookup failures and rejects mismatched user responses", async () => {
  const fixture = scanner({
    pats: [pat(10, 2), pat(11, 2), pat(12, 3), pat(13, 4), pat(14, 4)],
    lookup: (id) => {
      if (id === 2) throw httpError(503);
      if (id === 3) return { id: 99, username: "wrong-owner" };
      throw Object.assign(new Error("timeout"), { code: "ECONNABORTED" });
    },
  });
  const result = await fixture.scan();
  assert.ok(result.items.every((item) => item.owner_username === null));
  assert.equal(fixture.lookupCalls().length, 3);
  assertComplete(result);
});

test("admin bounds lookup work to 20 distinct owners and caches across PAT pages", async () => {
  const fixture = scanner({
    pats: [
      ...Array.from({ length: 101 }, (_, index) => pat(index, 2)),
      ...Array.from({ length: 25 }, (_, index) => pat(index + 101, index + 3)),
    ],
    lookup: (id) => ({ id, username: `owner-${id}` }),
  });
  const result = await fixture.scan();
  assert.equal(result.items.length, 126);
  assert.equal(fixture.lookupCalls().length, 20);
  assert.equal(result.items[100].owner_username, "owner-2");
  assert.equal(result.items[119].owner_username, "owner-21");
  assert.equal(result.items[120].owner_username, null);
  assertComplete(result);
  await fixture.scan();
  assert.equal(fixture.lookupCalls().length, 40);
});

test("admin caches failed lookups across PAT pages", async () => {
  const fixture = scanner({
    pats: Array.from({ length: 101 }, (_, index) => pat(index, 2)),
  });
  const result = await fixture.scan();
  assert.equal(result.items.length, 101);
  assert.equal(fixture.lookupCalls().length, 1);
  assertComplete(result);
});

test("admin bounds fallback latency without dropping cached owners or PATs", async (t) => {
  let now = Date.now();
  t.mock.method(Date, "now", () => now);
  const fixture = scanner({
    users: [{ id: 9, username: "cached-owner" }],
    pats: [pat(10, 2), pat(11, 3), pat(12, 4), pat(13, 9)],
    lookup: (id) => {
      now += 5000;
      return { id, username: `owner-${id}` };
    },
  });
  const result = await fixture.scan();
  assert.equal(fixture.lookupCalls().length, 2);
  assert.deepEqual(result.items.map(item => item.owner_username),
    ["owner-2", "owner-3", null, "cached-owner"]);
  assertComplete(result);
});

test("owner resolution preserves PAT expiration, revocation and user exclusions", async () => {
  const fixture = scanner({
    pats: [
      pat(10, 2, { revoked: true }),
      pat(11, 2, { expires_at: "2000-01-01" }),
      pat(12, 2),
      pat(13, 3),
      pat(14, 4),
      pat(15, 5),
    ],
    lookup: (id) => {
      if (id === 2) return { id, username: "human" };
      if (id === 3) return { id, username: "administrator", is_admin: true };
      if (id === 4) return { id, username: "deploy-bot" };
      throw httpError(404);
    },
  });
  const result = await fixture.scan({
    filters: { ...filters, excludeUserPATs: true },
  });
  assert.deepEqual(
    result.items.map((item) => item.sourceObjectId),
    ["13", "14", "15"],
  );
  assert.deepEqual(result.items.map((item) => item.owner_username), [
    "administrator",
    "deploy-bot",
    null,
  ]);
  assert.equal(result.summary[0].skippedUserPATs, 1);
  assert.equal(result.summary[0].skippedExpired, 1);
  assertComplete(result);
});

test("admin does not look up filtered or deduplicated PAT owners", async () => {
  const fixture = scanner({
    pats: [
      pat(10, 2, { revoked: true }),
      pat(11, 3, { expires_at: "2000-01-01" }),
      pat(12, 4),
    ],
    respond: (pathname) => {
      if (pathname === "/api/v4/projects") return [{ id: 7, name: "project" }];
      if (pathname === "/api/v4/projects/7/access_tokens") {
        return [{ id: 20, user_id: 4 }];
      }
    },
  });
  const result = await fixture.scan({
    filters: { ...filters, includeProjectTokens: true },
  });
  assert.equal(result.items.length, 1);
  assert.equal(result.items[0].sourceKind, "gitlab-project-token");
  assert.equal(fixture.lookupCalls().length, 0);
  assertComplete(result);
});

test("admin resolves included revoked and expired PATs without changing listing filters", async () => {
  const fixture = scanner({
    pats: [
      pat(10, 2, { revoked: true }),
      pat(11, 2, { expires_at: "2000-01-01", active: false }),
    ],
    lookup: (id) => ({ id, username: "inactive-owner" }),
  });
  const result = await fixture.scan({
    filters: { ...filters, includeRevoked: true, includeExpired: true },
  });
  assert.equal(result.items.length, 2);
  assert.ok(result.items.every((item) => item.owner_username === "inactive-owner"));
  const listing = fixture.calls.find(
    (call) => call.pathname === "/api/v4/personal_access_tokens",
  );
  assert.equal(Object.hasOwn(listing.params, "state"), false);
  assert.equal(fixture.lookupCalls().length, 1);
  assertComplete(result);
});

test("owner fallback cannot hide PAT pagination failures or item truncation", async () => {
  const capped = scanner({
    pats: [pat(10, 2), pat(11, 3)],
    lookup: (id) => ({ id, username: "owner" }),
  });
  const result = await capped.scan({ maxItems: 1 });
  assert.equal(result.items.length, 1);
  assert.equal(capped.lookupCalls().length, 1);
  assertComplete(result, false);

  const failed = scanner({
    pats: Array.from({ length: 100 }, (_, index) => pat(index, 2)),
    respond: (pathname, config) => {
      if (
        pathname === "/api/v4/personal_access_tokens" &&
        config.params.page === 2
      ) {
        throw httpError(503);
      }
    },
  });
  const partial = await failed.scan();
  assert.equal(partial.items.length, 100);
  assertComplete(partial, false);
});

test("non-admin PAT owners require an explicit current-user ID match", async () => {
  const fixture = scanner({
    admin: false,
    username: "actual-owner",
    pats: [
      pat(10, 1),
      pat(11, 2, { username: "actual-owner" }),
      pat(12, undefined, { used_by: "actual-owner" }),
      pat(13, null),
      pat(14, "1"),
      pat(15, 0),
    ],
  });
  const result = await fixture.scan();
  assert.deepEqual(result.items.map((item) => item.owner_username), [
    "actual-owner",
    null,
    null,
    null,
    null,
    null,
  ]);
  assert.equal(fixture.lookupCalls().length, 0);
  assert.equal(
    fixture.calls.filter((call) => call.pathname.includes("personal_access_tokens"))
      .length,
    1,
  );
  assertComplete(result);
});

test("non-admin missing username stays empty and an old PAT endpoint adds no inferred owner", async () => {
  const missingName = scanner({ admin: false, username: null, pats: [pat(10, 1)] });
  assert.equal((await missingName.scan()).items[0].owner_username, null);
  const oldServer = scanner({
    admin: false,
    respond: (pathname) => {
      if (pathname === "/api/v4/personal_access_tokens") throw httpError(404);
    },
  });
  assert.deepEqual((await oldServer.scan()).items, []);
  assert.equal(oldServer.lookupCalls().length, 0);
});

test("non-PAT inventory never receives the structured PAT owner field", async () => {
  const fixture = scanner({
    admin: false,
    respond: (pathname) => {
      if (pathname === "/api/v4/projects") return [{ id: 7, name: "project" }];
      if (pathname === "/api/v4/groups") return [{ id: 8, name: "group" }];
      if (pathname === "/api/v4/user/keys") return [{ id: 9, title: "ssh" }];
      if (pathname === "/api/v4/projects/7/access_tokens") {
        return [{ id: 10, username: "project-bot", user_id: 1 }];
      }
      if (pathname === "/api/v4/groups/8/access_tokens") {
        return [{ id: 11, username: "group-bot", user_id: 1 }];
      }
      if (pathname === "/api/v4/projects/7/deploy_tokens") return [{ id: 12 }];
      if (pathname === "/api/v4/projects/7/triggers") {
        return [{ id: 13, owner: { username: "trigger-owner" } }];
      }
    },
  });
  const result = await fixture.scan({
    include: { tokens: true, keys: true },
    filters: {
      includeProjectTokens: true,
      includeGroupTokens: true,
      includeDeployTokens: true,
      includeTriggerTokens: true,
      includeSSHKeys: true,
    },
  });
  assert.equal(result.items.length, 5);
  assert.ok(
    result.items.every((item) => !Object.hasOwn(item, "owner_username")),
  );
  assert.equal(fixture.lookupCalls().length, 0);
});
