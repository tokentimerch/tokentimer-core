"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");

const {
  VAULT_APPROLE_BAD_ROLE,
  VAULT_APPROLE_BAD_SECRET,
  VAULT_APPROLE_MOUNT_NOT_FOUND,
  VAULT_APPROLE_INVALID_RESPONSE,
  VAULT_APPROLE_INVALID_MOUNT,
  createVaultAuthSession,
  normalizeAuthMount,
  parseVaultAuthFromBody,
  scrubVaultCredentialBody,
  vaultAppRoleLogin,
  vaultRequest,
} = require("../../apps/api/services/vaultAuth.js");

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.removeListener("error", reject);
      resolve(server.address().port);
    });
  });
}

function closeServer(server) {
  return new Promise((resolve, reject) => {
    server.close((err) => (err ? reject(err) : resolve()));
  });
}

function json(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(payload),
  });
  res.end(payload);
}

async function withVault(handler, run) {
  const hits = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      let body = null;
      try {
        body = raw ? JSON.parse(raw) : null;
      } catch (_) {
        body = raw;
      }
      hits.push({
        method: req.method,
        url: req.url,
        vaultToken: req.headers["x-vault-token"] || null,
        namespace: req.headers["x-vault-namespace"] || null,
        body,
      });
      handler(req, res, body, hits);
    });
  });
  const port = await listen(server);
  try {
    await run({
      address: `http://127.0.0.1:${port}`,
      hits,
    });
  } finally {
    await closeServer(server);
  }
}

describe("parseVaultAuthFromBody", () => {
  it("accepts token mode with optional namespace", () => {
    const parsed = parseVaultAuthFromBody({
      token: " s.abc ",
      namespace: " ns1 ",
    });
    assert.equal(parsed.error, undefined);
    assert.deepEqual(parsed.credentials, {
      token: "s.abc",
      namespace: "ns1",
    });
  });

  it("accepts AppRole mode", () => {
    const parsed = parseVaultAuthFromBody({
      roleId: "role",
      secretId: "secret",
      authMount: "custom",
    });
    assert.equal(parsed.error, undefined);
    assert.equal(parsed.credentials.roleId, "role");
    assert.equal(parsed.credentials.secretId, "secret");
    assert.equal(parsed.credentials.authMount, "custom");
  });

  it("rejects mixed token and AppRole fields", () => {
    const parsed = parseVaultAuthFromBody({
      token: "t",
      roleId: "r",
      secretId: "s",
    });
    assert.match(parsed.error, /not both/);
  });

  it("rejects token mode with authMount", () => {
    const parsed = parseVaultAuthFromBody({
      token: "t",
      authMount: "approle",
    });
    assert.match(parsed.error, /not both/);
  });

  it("rejects roleId without secretId", () => {
    const parsed = parseVaultAuthFromBody({ roleId: "r" });
    assert.match(parsed.error, /both required/);
  });

  it("rejects secretId without roleId", () => {
    const parsed = parseVaultAuthFromBody({ secretId: "s" });
    assert.match(parsed.error, /both required/);
  });

  it("rejects neither mode", () => {
    const parsed = parseVaultAuthFromBody({ address: "https://vault.example" });
    assert.match(parsed.error, /token or roleId/);
  });
});

describe("normalizeAuthMount", () => {
  it("defaults to approle and encodes segments", () => {
    assert.equal(normalizeAuthMount(""), "approle");
    assert.equal(normalizeAuthMount("/team/approle/"), "team/approle");
    assert.equal(normalizeAuthMount("a b"), "a%20b");
  });

  it("rejects dot segments", () => {
    assert.throws(
      () => normalizeAuthMount("../sys"),
      (err) => err.code === VAULT_APPROLE_INVALID_MOUNT,
    );
    assert.throws(
      () => normalizeAuthMount("foo/."),
      (err) => err.code === VAULT_APPROLE_INVALID_MOUNT,
    );
  });
});

describe("vaultAppRoleLogin", () => {
  it("reads TTL from auth.lease_duration, not the top-level field", async () => {
    await withVault(
      (_req, res) => {
        json(res, 200, {
          lease_duration: 0,
          auth: {
            client_token: "s.client",
            lease_duration: 1200,
            renewable: true,
          },
        });
      },
      async ({ address }) => {
        const result = await vaultAppRoleLogin({
          address,
          roleId: "role",
          secretId: "secret",
        });
        assert.equal(result.clientToken, "s.client");
        assert.equal(result.ttlSeconds, 1200);
      },
    );
  });

  it("maps invalid role, invalid secret, and unknown mount", async () => {
    await withVault(
      (req, res) => {
        if (req.url === "/v1/auth/approle/login") {
          json(res, 400, { errors: ["invalid role ID"] });
          return;
        }
        json(res, 404, { errors: ["no handler"] });
      },
      async ({ address }) => {
        await assert.rejects(
          () =>
            vaultAppRoleLogin({
              address,
              roleId: "bad",
              secretId: "secret",
            }),
          (err) => err.code === VAULT_APPROLE_BAD_ROLE,
        );
      },
    );

    await withVault(
      (_req, res) => json(res, 400, { errors: ["invalid secret id"] }),
      async ({ address }) => {
        await assert.rejects(
          () =>
            vaultAppRoleLogin({
              address,
              roleId: "role",
              secretId: "bad",
            }),
          (err) => err.code === VAULT_APPROLE_BAD_SECRET,
        );
      },
    );

    await withVault(
      (_req, res) => json(res, 404, { errors: [] }),
      async ({ address }) => {
        await assert.rejects(
          () =>
            vaultAppRoleLogin({
              address,
              roleId: "role",
              secretId: "secret",
              authMount: "missing",
            }),
          (err) => err.code === VAULT_APPROLE_MOUNT_NOT_FOUND,
        );
      },
    );
  });

  it("fails closed on missing auth, missing client_token, and malformed TTL", async () => {
    await withVault(
      (_req, res) => json(res, 200, { lease_duration: 1200 }),
      async ({ address }) => {
        await assert.rejects(
          () =>
            vaultAppRoleLogin({
              address,
              roleId: "role",
              secretId: "secret",
            }),
          (err) => err.code === VAULT_APPROLE_INVALID_RESPONSE,
        );
      },
    );

    await withVault(
      (_req, res) => json(res, 200, { auth: { lease_duration: 1200 } }),
      async ({ address }) => {
        await assert.rejects(
          () =>
            vaultAppRoleLogin({
              address,
              roleId: "role",
              secretId: "secret",
            }),
          (err) => err.code === VAULT_APPROLE_INVALID_RESPONSE,
        );
      },
    );

    await withVault(
      (_req, res) =>
        json(res, 200, {
          auth: { client_token: "s.x", lease_duration: "1200" },
        }),
      async ({ address }) => {
        await assert.rejects(
          () =>
            vaultAppRoleLogin({
              address,
              roleId: "role",
              secretId: "secret",
            }),
          (err) => err.code === VAULT_APPROLE_INVALID_RESPONSE,
        );
      },
    );
  });

  it("fails closed on a negative auth.lease_duration", async () => {
    await withVault(
      (_req, res) =>
        json(res, 200, {
          auth: { client_token: "s.neg", lease_duration: -1 },
        }),
      async ({ address }) => {
        await assert.rejects(
          () =>
            vaultAppRoleLogin({
              address,
              roleId: "role",
              secretId: "secret",
            }),
          (err) => err.code === VAULT_APPROLE_INVALID_RESPONSE,
        );
      },
    );
  });

  it("sends X-Vault-Namespace on login", async () => {
    await withVault(
      (req, res) => {
        assert.equal(req.headers["x-vault-namespace"], "team-a");
        json(res, 200, {
          lease_duration: 0,
          auth: { client_token: "s.ns", lease_duration: 60 },
        });
      },
      async ({ address }) => {
        await vaultAppRoleLogin({
          address,
          roleId: "role",
          secretId: "secret",
          namespace: "team-a",
        });
      },
    );
  });
});

describe("VaultAuthSession", () => {
  it("refreshes at 80% of auth.lease_duration from response receipt", async () => {
    let now = 1_000_000;
    await withVault(
      (_req, res) => {
        json(res, 200, {
          lease_duration: 0,
          auth: { client_token: `s.${now}`, lease_duration: 10 },
        });
      },
      async ({ address, hits }) => {
        const session = createVaultAuthSession({
          address,
          roleId: "role",
          secretId: "secret",
          now: () => now,
        });
        const first = await session.getToken();
        assert.equal(hits.filter((h) => h.url.includes("/login")).length, 1);
        now += 7999;
        const stillCached = await session.getToken();
        assert.equal(stillCached, first);
        assert.equal(hits.filter((h) => h.url.includes("/login")).length, 1);
        now += 2;
        await session.getToken();
        assert.equal(hits.filter((h) => h.url.includes("/login")).length, 2);
      },
    );
  });

  it("caches a zero auth.lease_duration token for this session", async () => {
    await withVault(
      (_req, res) => {
        json(res, 200, {
          lease_duration: 0,
          auth: { client_token: "s.zero", lease_duration: 0 },
        });
      },
      async ({ address, hits }) => {
        const session = createVaultAuthSession({
          address,
          roleId: "role",
          secretId: "secret",
        });
        await session.getToken();
        await session.getToken();
        assert.equal(hits.filter((h) => h.url.includes("/login")).length, 1);
      },
    );
  });

  it("shares one in-flight refresh and retries after a failed login", async () => {
    let logins = 0;
    await withVault(
      (_req, res) => {
        logins += 1;
        if (logins === 1) {
          json(res, 400, { errors: ["invalid secret id"] });
          return;
        }
        json(res, 200, {
          lease_duration: 0,
          auth: { client_token: "s.ok", lease_duration: 60 },
        });
      },
      async ({ address }) => {
        const session = createVaultAuthSession({
          address,
          roleId: "role",
          secretId: "secret",
        });
        const firstWave = await Promise.allSettled([
          session.getToken(),
          session.getToken(),
          session.getToken(),
        ]);
        assert.equal(
          firstWave.filter((r) => r.status === "rejected").length,
          3,
        );
        assert.equal(logins, 1);
        const token = await session.getToken();
        assert.equal(token, "s.ok");
        assert.equal(logins, 2);
      },
    );
  });

  it("does not re-login on a downstream 403", async () => {
    await withVault(
      (req, res) => {
        if (req.url.includes("/login")) {
          json(res, 200, {
            lease_duration: 0,
            auth: { client_token: "s.live", lease_duration: 3600 },
          });
          return;
        }
        json(res, 403, { errors: ["permission denied"] });
      },
      async ({ address, hits }) => {
        const session = createVaultAuthSession({
          address,
          roleId: "role",
          secretId: "secret",
        });
        await assert.rejects(
          () =>
            vaultRequest({
              session,
              address,
              path: "/v1/sys/mounts",
            }),
          (err) => err.status === 403,
        );
        assert.equal(hits.filter((h) => h.url.includes("/login")).length, 1);
        assert.equal(hits.filter((h) => h.url === "/v1/sys/mounts").length, 1);
      },
    );
  });

  it("sends namespace on authenticated requests in both modes", async () => {
    await withVault(
      (req, res) => {
        assert.equal(req.headers["x-vault-namespace"], "ops");
        if (req.url === "/v1/sys/mounts") {
          json(res, 200, { data: {} });
          return;
        }
        json(res, 404, {});
      },
      async ({ address }) => {
        await vaultRequest({
          address,
          token: "s.static",
          namespace: "ops",
          path: "/v1/sys/mounts",
        });
      },
    );
  });
});

describe("scrubVaultCredentialBody", () => {
  it("deletes token, roleId, and secretId", () => {
    const body = { address: "https://vault", token: "t", roleId: "r", secretId: "s" };
    scrubVaultCredentialBody(body);
    assert.equal(body.token, undefined);
    assert.equal(body.roleId, undefined);
    assert.equal(body.secretId, undefined);
    assert.equal(body.address, "https://vault");
  });
});
