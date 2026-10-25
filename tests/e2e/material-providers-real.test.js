"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const path = require("node:path");
const fs = require("node:fs");
const os = require("node:os");
const http = require("node:http");
const {
  createMaterialStore,
  writeProtectedFile,
  readProtectedFile,
} = require("../../packages/agent/src/material-store");
const {
  computeCertificateFingerprint,
  parseDnsSans,
} = require("../../packages/agent/src/verify");

function fixture(t, provider, address) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "tt-provider-real-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const certificatePem = fs.readFileSync(
    path.join(
      __dirname,
      "../../packages/agent/src/verify/fixtures/leaf.crt.pem",
    ),
    "utf8",
  );
  const privateKeyPem = fs.readFileSync(
    path.join(
      __dirname,
      "../../packages/agent/src/verify/fixtures/leaf.key.pem",
    ),
    "utf8",
  );
  const certificate = new crypto.X509Certificate(certificatePem);
  const intent = {
    workspaceId: crypto.randomUUID(),
    groupId: crypto.randomUUID(),
    materialVersionId: crypto.randomUUID(),
    materialStoreRef: "qualification",
    provider,
  };
  const bundle = {
    schemaVersion: 1,
    workspaceId: intent.workspaceId,
    groupId: intent.groupId,
    materialVersionId: intent.materialVersionId,
    certificatePem,
    privateKeyPem,
    sans: parseDnsSans(certificate.subjectAltName),
    fingerprintSha256: computeCertificateFingerprint(certificatePem),
  };
  const tokenFile = path.join(directory, "credential");
  const scope = {
    workspaceId: intent.workspaceId,
    prefix: `qualification/${intent.workspaceId}/${intent.groupId}`,
    keyAlgorithm: certificate.publicKey.asymmetricKeyType,
    sans: bundle.sans,
  };
  const config = {
    provider,
    address,
    mount: "secret",
    tokenFile,
    groups: { [intent.groupId]: scope },
  };
  return { intent, bundle, scope, config, tokenFile, directory };
}

test(
  "real KV v2: AppRole, ACLs, rotation, exact versions, CAS and uncertain writes",
  // skip-reason: no-host — explicitly gated real, isolated OpenBao/Vault fixture.
  { skip: process.env.TT_REAL_KV !== "1", timeout: 180000 },
  async (t) => {
    const provider = process.env.TT_REAL_KV_PROVIDER || "openbao-kv2";
    assert.ok(["openbao-kv2", "vault-kv2"].includes(provider));
    const address = process.env.TT_REAL_KV_ADDRESS || "http://127.0.0.1:58207";
    const parsed = new URL(address);
    assert.equal(parsed.hostname, "127.0.0.1");
    const root =
      process.env.TT_REAL_KV_TOKEN || "isolated-openbao-fixture-only";
    const f = fixture(t, provider, address);
    const suffix = crypto.randomBytes(8).toString("hex");
    const policy = `tt-qualification-${suffix}`,
      role = policy;
    async function api(route, body, method = "POST", token = root) {
      const response = await fetch(new URL(`/v1${route}`, address), {
        method,
        headers: { "X-Vault-Token": token, "Content-Type": "application/json" },
        ...(body ? { body: JSON.stringify(body) } : {}),
      });
      assert.ok(
        response.ok,
        `fixture operation ${method} returned ${response.status}`,
      );
      return response.status === 204 ? null : response.json();
    }
    await api(
      `/sys/policies/acl/${policy}`,
      {
        policy: `path "secret/data/${f.scope.prefix}/bundles/*" { capabilities = ["create","read"] }`,
      },
      "PUT",
    );
    const mounts = await api("/sys/auth", null, "GET");
    if (!mounts["approle/"] && !mounts.data?.["approle/"])
      await api("/sys/auth/approle", { type: "approle" });
    await api(`/auth/approle/role/${role}`, {
      token_policies: [policy],
      token_ttl: "5m",
      token_max_ttl: "10m",
    });
    t.after(async () => {
      await api(`/auth/approle/role/${role}`, null, "DELETE");
      await api(`/sys/policies/acl/${policy}`, null, "DELETE");
    });
    const roleId = (
      await api(`/auth/approle/role/${role}/role-id`, null, "GET")
    ).data.role_id;
    async function login() {
      const secret = (await api(`/auth/approle/role/${role}/secret-id`, {}))
        .data.secret_id;
      return (
        await api("/auth/approle/login", { role_id: roleId, secret_id: secret })
      ).auth.client_token;
    }
    let token = await login();
    writeProtectedFile(f.tokenFile, token);
    const stores = { qualification: f.config };
    const client = createMaterialStore(stores, f.intent, {
      fixtureLoopbackHttp: true,
    });
    const receipt = await client.publish(f.bundle);
    assert.deepEqual(await client.publish(f.bundle), receipt);
    assert.deepEqual(await client.fetch(1), f.bundle);
    await assert.rejects(client.fetch(2), {
      code: "material_version_unavailable",
    });
    await api("/auth/token/revoke", { token });
    token = await login();
    writeProtectedFile(f.tokenFile, token);
    assert.deepEqual(
      await client.fetch(1),
      f.bundle,
      "the same client rereads the rotated token sink",
    );
    const foreign = crypto.randomUUID();
    const denied = createMaterialStore(
      stores,
      { ...f.intent, materialVersionId: foreign },
      { fixtureLoopbackHttp: true },
    );
    await api(
      `/sys/policies/acl/${policy}`,
      {
        policy: `path "secret/data/${f.scope.prefix}/bundles/${f.intent.materialVersionId}" { capabilities = ["read"] }`,
      },
      "PUT",
    );
    await assert.rejects(denied.fetch(1), { code: "material_auth_denied" });
    await api(
      `/sys/policies/acl/${policy}`,
      {
        policy: `path "secret/data/${f.scope.prefix}/bundles/*" { capabilities = ["create","read"] }`,
      },
      "PUT",
    );
    const object = `${f.scope.prefix}/bundles/${f.intent.materialVersionId}`;
    await api(`/secret/data/${object}`, {
      options: { cas: 1 },
      data: { unrelated: "not-a-certificate" },
    });
    assert.deepEqual(
      await client.fetch(1),
      f.bundle,
      "never reads latest after a later version appears",
    );
    await assert.rejects(client.fetch(2), { code: "material_bundle_invalid" });
    await api(`/secret/delete/${object}`, { versions: [1] });
    await assert.rejects(client.fetch(1), {
      code: "material_version_unavailable",
    });
    await api(`/secret/undelete/${object}`, { versions: [1] });
    assert.deepEqual(await client.fetch(1), f.bundle);
    // A real provider commits a new object. Only its successful POST response
    // is lost at the local transport proxy; subsequent pinned reads are real.
    const proxy = http.createServer((req, res) => {
      const upstream = http.request(
        new URL(req.url, address),
        { method: req.method, headers: req.headers },
        (response) => {
          if (req.method === "POST" && response.statusCode === 200) {
            response.resume();
            response.on("end", () => req.socket.destroy());
          } else {
            res.writeHead(response.statusCode, response.headers);
            response.pipe(res);
          }
        },
      );
      upstream.on("error", () => res.destroy());
      req.pipe(upstream);
    });
    await new Promise((resolve) => proxy.listen(0, "127.0.0.1", resolve));
    t.after(() => {
      proxy.closeAllConnections();
      proxy.close();
    });
    const nextIntent = { ...f.intent, materialVersionId: crypto.randomUUID() };
    const nextBundle = {
      ...f.bundle,
      materialVersionId: nextIntent.materialVersionId,
    };
    const proxied = createMaterialStore(
      {
        qualification: {
          ...f.config,
          address: `http://127.0.0.1:${proxy.address().port}`,
        },
      },
      nextIntent,
      { fixtureLoopbackHttp: true },
    );
    assert.equal((await proxied.publish(nextBundle)).providerVersion, 1);
    await api(`/secret/destroy/${object}`, { versions: [1] });
    await assert.rejects(client.fetch(1), {
      code: "material_version_unavailable",
    });
    await api("/auth/token/revoke", { token });
    await assert.rejects(client.fetch(1), { code: "material_auth_denied" });
  },
);

test(
  "real Azure Key Vault Secrets: publication, recovery and exact immutable retrieval",
  // skip-reason: no-host — customer-local Azure identity and dedicated vault only.
  { skip: process.env.TT_REAL_AZURE !== "1", timeout: 180000 },
  async (t) => {
    const config = JSON.parse(
      readProtectedFile(process.env.TT_REAL_AZURE_CONFIG, 32768),
    );
    assert.equal(config.provider, "azure-key-vault");
    const f = fixture(t, "azure-key-vault", config.address);
    // The vault and identity must be dedicated to this test. Unique names are
    // deliberately retained; the test requires no delete/purge permission.
    const stores = {
      qualification: { ...config, groups: { [f.intent.groupId]: f.scope } },
    };
    const client = createMaterialStore(stores, f.intent);
    const first = await client.publish(f.bundle);
    assert.deepEqual(await client.fetch(first.providerVersion), f.bundle);
    assert.deepEqual(
      await client.publish(f.bundle, { writeAttempted: true }),
      first,
    );
    await assert.rejects(client.fetch("0".repeat(32)), {
      code: "material_version_unavailable",
    });
    assert.equal(JSON.stringify(first).includes("PRIVATE KEY"), false);
  },
);
