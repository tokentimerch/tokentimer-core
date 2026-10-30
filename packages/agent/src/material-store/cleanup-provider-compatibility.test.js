"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const http = require("node:http");
const crypto = require("node:crypto");
const { createVaultStore, writeProtectedFile } = require("./index");
function fixture(t, address) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "tt-cleanup-test-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const tokenFile = path.join(directory, "data-token");
  writeProtectedFile(tokenFile, "isolated-data-fixture-only");
  const intent = {
    workspaceId: crypto.randomUUID(),
    groupId: crypto.randomUUID(),
    materialVersionId: crypto.randomUUID(),
    materialStoreRef: "customer",
  };
  const scope = {
    workspaceId: intent.workspaceId,
    prefix: `${intent.workspaceId}/${intent.groupId}`,
    sans: ["cleanup.example.test"],
    keyAlgorithm: "rsa",
  };
  const stores = {
    customer: {
      address,
      mount: "secret",
      tokenFile,
      timeoutMs: 10000,
      groups: { [intent.groupId]: scope },
    },
  };
  return { intent, scope, stores, directory };
}

for (const shape of ["legacy", "explicit", "canonical"])
  for (const lostResponse of [true, false]) {
    test(`Vault cleanup separates provider/operation, retries metadata first (${shape}, lost=${lostResponse})`, async (t) => {
      let f,
        deleted = false,
        posts = 0,
        journals = 0;
      const requests = [];
      const server = http.createServer((req, res) => {
        requests.push([req.method, req.url]);
        assert.equal(
          req.headers["x-vault-token"],
          "isolated-cleanup-fixture-only",
          "never use the data credential",
        );
        assert.match(req.url, /\/(metadata|delete)\//);
        if (req.method === "GET") {
          res.end(
            JSON.stringify({
              data: {
                versions: {
                  3: {
                    created_time: "2020-01-01T00:00:00Z",
                    destroyed: false,
                    deletion_time: deleted ? "2026-01-01T00:00:00Z" : "",
                  },
                },
              },
            }),
          );
        } else {
          assert.equal(req.method, "POST");
          assert.match(req.url, /\/delete\//);
          let body = "";
          req.on("data", (value) => {
            body += value;
          });
          req.on("end", () => {
            assert.deepEqual(JSON.parse(body), { versions: [3] });
            assert.equal(
              journals,
              1,
              "durable intent is recorded before the only delete",
            );
            posts++;
            deleted = true;
            if (lostResponse) req.socket.destroy();
            else res.writeHead(204).end();
          });
        }
      });
      await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
      t.after(() => new Promise((resolve) => server.close(resolve)));
      f = fixture(t, `http://127.0.0.1:${server.address().port}`);
      const tokenFile = path.join(f.directory, "cleanup-token");
      writeProtectedFile(tokenFile, "isolated-cleanup-fixture-only");

      f.scope.cleanup = {
        softDelete: true,
        tokenFile,
        profileRevision: 1,
        minimumSeconds: 3600,
      };
      const intent = {
        ...f.intent,
        ...(shape === "legacy"
          ? { type: "vault-kv2-soft-delete" }
          : {
              operation:
                shape === "canonical" ? "soft-delete" : "vault-kv2-soft-delete",
              provider: "vault-kv2",
            }),
        profileRevision: 1,
        providerVersion: 3,
        expiresAt: new Date(Date.now() + 60000).toISOString(),
        retentionPolicy: {
          minimumSeconds: 3600,
          cleanupEnabled: true,
          reportOnly: false,
          requiresApproval: true,
        },
      };
      const store = () =>
        createVaultStore(f.stores, intent, { fixtureLoopbackHttp: true });
      const options = {
        checkLease: async () => {},
        beforeDelete: async () => {
          journals++;
        },
      };
      if (lostResponse)
        await assert.rejects(store().softDeleteVersion(3, options), {
          code: "material_store_unavailable",
        });
      else
        assert.deepEqual(await store().softDeleteVersion(3, options), {
          alreadyDeleted: false,
        });
      assert.deepEqual(await store().softDeleteVersion(3, options), {
        alreadyDeleted: true,
      });
      assert.equal(posts, 1);
      assert.equal(journals, 1);
      assert.equal(
        requests.filter(([method]) => method === "GET").length,
        lostResponse ? 2 : 3,
      );
      assert.equal(
        requests.some(([, url]) => /\/(data|destroy|undelete)\//.test(url)),
        false,
      );
    });
  }

for (const scenario of ["scheduled", "retained-schedule", "retention"])
  test(`scheduled Vault deletion is not effective deletion (${scenario})`, async (t) => {
    let posts = 0,
      journals = 0;
    const future = new Date(Date.now() + 86400000).toISOString();
    const server = http.createServer((req, res) => {
      if (req.method === "POST") {
        posts++;
        req.resume();
        res.writeHead(204).end();
      } else {
        res.end(
          JSON.stringify({
            data: {
              versions: {
                3: {
                  created_time:
                    scenario === "retention"
                      ? new Date().toISOString()
                      : "2020-01-01T00:00:00Z",
                  destroyed: false,
                  deletion_time:
                    posts && scenario === "scheduled"
                      ? new Date(Date.now() - 1000).toISOString()
                      : future,
                },
              },
            },
          }),
        );
      }
    });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    t.after(() => new Promise((resolve) => server.close(resolve)));
    const f = fixture(t, `http://127.0.0.1:${server.address().port}`);
    f.scope.cleanup = {
      softDelete: true,
      tokenFile: f.stores.customer.tokenFile,
      profileRevision: 1,
      minimumSeconds: 3600,
    };
    const intent = {
      ...f.intent,
      type: "vault-kv2-soft-delete",
      profileRevision: 1,
      providerVersion: 3,
      expiresAt: new Date(Date.now() + 60000).toISOString(),
      retentionPolicy: {
        minimumSeconds: 3600,
        cleanupEnabled: true,
        reportOnly: false,
        requiresApproval: true,
      },
    };
    const run = () =>
      createVaultStore(f.stores, intent, {
        fixtureLoopbackHttp: true,
      }).softDeleteVersion(3, {
        checkLease: async () => {},
        beforeDelete: async () => {
          journals++;
        },
      });
    if (scenario === "scheduled")
      assert.deepEqual(await run(), { alreadyDeleted: false });
    else
      await assert.rejects(run(), {
        code:
          scenario === "retention"
            ? "material_cleanup_retention_protected"
            : "material_cleanup_uncertain",
      });
    assert.equal(posts, scenario === "retention" ? 0 : 1);
    assert.equal(journals, posts);
  });

test("cleanup provider confusion and policy failures cannot delete or invoke the mutation journal", async (t) => {
  let requests = 0,
    mutations = 0;
  const server = http.createServer((req, res) => {
    requests++;
    res.writeHead(500).end();
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const f = fixture(t, `http://127.0.0.1:${server.address().port}`);
  const intent = {
    ...f.intent,
    type: "vault-kv2-soft-delete",
    profileRevision: 1,
    providerVersion: 3,
    expiresAt: new Date(Date.now() + 60000).toISOString(),
    retentionPolicy: {
      minimumSeconds: 3600,
      cleanupEnabled: true,
      reportOnly: false,
      requiresApproval: true,
    },
  };
  f.scope.cleanup = {
    softDelete: true,
    tokenFile: f.stores.customer.tokenFile,
    profileRevision: 1,
    minimumSeconds: 3600,
  };
  const options = {
    checkLease: async () => {},
    beforeDelete: async () => {
      mutations++;
    },
  };
  for (const provider of ["openbao-kv2", "azure-key-vault", "unknown"]) {
    assert.throws(
      () =>
        createVaultStore(
          f.stores,
          { ...intent, provider },
          { fixtureLoopbackHttp: true },
        ),
      { code: "material_provider_mismatch" },
    );
  }
  assert.throws(
    () =>
      createVaultStore(
        f.stores,
        { ...intent, operation: "destroy" },
        { fixtureLoopbackHttp: true },
      ),
    { code: "material_provider_mismatch" },
  );
  for (const change of [
    { providerVersion: 4 },
    { profileRevision: 2 },
    { expiresAt: "2020-01-01T00:00:00Z" },
    { retentionPolicy: { ...intent.retentionPolicy, reportOnly: true } },
    { retentionPolicy: { ...intent.retentionPolicy, requiresApproval: false } },
  ]) {
    await assert.rejects(
      createVaultStore(
        f.stores,
        { ...intent, ...change },
        { fixtureLoopbackHttp: true },
      ).softDeleteVersion(3, options),
      { code: "material_cleanup_policy_denied" },
    );
  }
  await assert.rejects(
    createVaultStore(f.stores, intent, {
      fixtureLoopbackHttp: true,
    }).softDeleteVersion(3, {
      ...options,
      checkLease: async () => {
        throw new Error("expired lease");
      },
    }),
    /expired lease/,
  );
  assert.equal(requests, 0);
  assert.equal(mutations, 0);
});
