"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const http = require("node:http");
const crypto = require("node:crypto");
const { createMaterialStore, writeProtectedJson } = require("./index");
const { CONTENT_TYPE } = require("./azure");
const { computeCertificateFingerprint, parseDnsSans } = require("../verify");

async function fixture(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tt-azure-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const tokenFile = path.join(dir, "token.json");
  function rotate(token = "synthetic-token-in-isolated-test") {
    writeProtectedJson(tokenFile, {
      accessToken: token,
      expiresOn: Date.now() + 3600000,
    });
  }
  rotate();
  const certificatePem = fs.readFileSync(
    path.join(__dirname, "../verify/fixtures/leaf.crt.pem"),
    "utf8",
  );
  const privateKeyPem = fs.readFileSync(
    path.join(__dirname, "../verify/fixtures/leaf.key.pem"),
    "utf8",
  );
  const certificate = new crypto.X509Certificate(certificatePem);
  const intent = {
    workspaceId: crypto.randomUUID(),
    groupId: crypto.randomUUID(),
    materialVersionId: crypto.randomUUID(),
    materialStoreRef: "customer",
    provider: "azure-key-vault",
  };
  const bundle = {
    schemaVersion: 1,
    workspaceId: intent.workspaceId,
    groupId: intent.groupId,
    materialVersionId: intent.materialVersionId,
    certificatePem,
    privateKeyPem,
    fingerprintSha256: computeCertificateFingerprint(certificatePem),
    sans: parseDnsSans(certificate.subjectAltName),
  };
  const versions = new Map();
  let puts = 0,
    loseWrite = false,
    status = 200,
    putStatus = 200,
    malformed = false,
    requests = [];
  const server = http.createServer((req, res) => {
    requests.push({
      method: req.method,
      path: req.url,
      auth: req.headers.authorization,
    });
    if (status !== 200) {
      res.writeHead(status).end("credential-private-key-canary");
      return;
    }
    if (req.method === "PUT" && putStatus !== 200) {
      res.writeHead(putStatus).end("credential-private-key-canary");
      return;
    }
    const url = new URL(req.url, "http://fixture");
    const object = url.pathname.split("/")[2];
    const base = `http://127.0.0.1:${server.address().port}/secrets/${object}`;
    if (req.method === "PUT") {
      let raw = "";
      req.on("data", (part) => (raw += part));
      req.on("end", () => {
        puts++;
        const value = JSON.parse(raw);
        const version = crypto.randomBytes(16).toString("hex");
        const result = { ...value, id: `${base}/${version}` };
        versions.set(version, result);
        if (loseWrite) req.socket.destroy();
        else res.end(JSON.stringify(result));
      });
    } else if (url.pathname.endsWith("/versions"))
      res.end(
        JSON.stringify({
          value: [...versions.values()].map((v) => ({ id: v.id })),
          ...(malformed ? { nextLink: "https://attacker.test/?canary" } : {}),
        }),
      );
    else {
      const value = versions.get(url.pathname.split("/")[3]);
      if (value) res.end(JSON.stringify(value));
      else res.writeHead(404).end();
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  server.keepAliveTimeout = 60000;
  t.after(() => {
    server.closeAllConnections();
    server.close();
  });
  const config = {
    provider: "azure-key-vault",
    address: `http://127.0.0.1:${server.address().port}`,
    auth: { type: "token-file", tokenFile },
    groups: {
      [intent.groupId]: {
        workspaceId: intent.workspaceId,
        prefix: `${intent.workspaceId}/${intent.groupId}`,
        keyAlgorithm: certificate.publicKey.asymmetricKeyType,
        sans: bundle.sans,
      },
    },
  };
  const stores = { customer: config };
  const client = () =>
    createMaterialStore(stores, intent, { fixtureLoopbackHttp: true });
  return {
    intent,
    bundle,
    config,
    stores,
    client,
    versions,
    rotate,
    tokenFile,
    requests,
    get puts() {
      return puts;
    },
    loseWrite() {
      loseWrite = true;
    },
    status(code) {
      status = code;
    },
    rejectWrite(code) {
      putStatus = code;
    },
    badNextLink() {
      malformed = true;
    },
  };
}

test("Azure publishes one version, pins reads, and recovers a lost write response without another PUT", async (t) => {
  const f = await fixture(t);
  f.loseWrite();
  let markers = 0;
  const receipt = await f.client().publish(f.bundle, {
    beforeWrite: () => {
      markers++;
    },
  });
  assert.equal(receipt.provider, "azure-key-vault");
  assert.match(receipt.providerVersion, /^[a-f0-9]{32}$/);
  assert.equal(markers, 1);
  assert.equal(f.puts, 1);
  assert.deepEqual(await f.client().fetch(receipt.providerVersion), f.bundle);
  assert.deepEqual(
    await f.client().publish(f.bundle, { writeAttempted: true }),
    receipt,
  );
  assert.equal(f.puts, 1);
  assert.equal(JSON.stringify(receipt).includes("PRIVATE KEY"), false);
  await assert.rejects(f.client().fetch(1), {
    code: "material_provider_version_invalid",
  });
  await assert.rejects(f.client().fetch("f".repeat(32)), {
    code: "material_version_unavailable",
  });
  const get = f.requests.find((r) => r.path.includes(receipt.providerVersion));
  assert.ok(get);
});
test("Azure never reissues a PUT after an uncertain checkpoint when the object is absent", async (t) => {
  const f = await fixture(t);
  await assert.rejects(f.client().publish(f.bundle, { writeAttempted: true }), {
    code: "material_publication_uncertain",
  });
  assert.equal(f.puts, 0);
});
test("Azure distinguishes proven write rejection from an ambiguous server failure", async (t) => {
  const f = await fixture(t);
  let writeAttempted = false;
  const journal = {
    beforeWrite: () => {
      writeAttempted = true;
    },
    writeRejected: () => {
      writeAttempted = false;
    },
  };
  f.rejectWrite(403);
  await assert.rejects(f.client().publish(f.bundle, journal), {
    code: "material_auth_denied",
  });
  assert.equal(
    writeAttempted,
    false,
    "a definite denial permits a credential repair and retry",
  );
  f.rejectWrite(500);
  await assert.rejects(f.client().publish(f.bundle, journal), {
    code: "material_publication_uncertain",
  });
  assert.equal(
    writeAttempted,
    true,
    "a server failure cannot clear the durable marker",
  );
  const attempts = f.requests.filter((r) => r.method === "PUT").length;
  await assert.rejects(
    f.client().publish(f.bundle, { ...journal, writeAttempted }),
    { code: "material_publication_uncertain" },
  );
  assert.equal(f.requests.filter((r) => r.method === "PUT").length, attempts);
});
test("Azure rejects an oversized bundle before network contact and refuses different retained key bytes", async (t) => {
  const f = await fixture(t);
  await assert.rejects(
    f.client().publish({
      ...f.bundle,
      certificatePem: f.bundle.certificatePem + " ".repeat(26 * 1024),
    }),
    { code: "material_bundle_too_large" },
  );
  assert.equal(f.requests.length, 0);
  const receipt = await f.client().publish(f.bundle);
  const stored = f.versions.get(receipt.providerVersion);
  stored.value = JSON.stringify({
    ...f.bundle,
    privateKeyPem: f.bundle.privateKeyPem + "\n",
  });
  await assert.rejects(f.client().publish(f.bundle), {
    code: "material_cas_conflict",
  });
  assert.equal(f.puts, 1);
});
test("Azure denies conflicting versions and hostile paging without following URLs", async (t) => {
  const f = await fixture(t);
  const receipt = await f.client().publish(f.bundle);
  f.versions.set("a".repeat(32), {
    ...f.versions.get(receipt.providerVersion),
    id: f.versions
      .get(receipt.providerVersion)
      .id.replace(receipt.providerVersion, "a".repeat(32)),
  });
  await assert.rejects(f.client().publish(f.bundle), {
    code: "material_cas_conflict",
  });
  // Consumer reads remain pinned even if another privileged writer adds a version.
  assert.deepEqual(await f.client().fetch(receipt.providerVersion), f.bundle);
  f.versions.delete("a".repeat(32));
  f.badNextLink();
  await assert.rejects(f.client().publish(f.bundle), {
    code: "material_cas_conflict",
  });
  assert.equal(f.puts, 1);
});
test("Azure rejects disabled, missing, wrong-identity and metadata-only material", async (t) => {
  const f = await fixture(t);
  const receipt = await f.client().publish(f.bundle);
  const stored = f.versions.get(receipt.providerVersion);
  stored.attributes.enabled = false;
  await assert.rejects(f.client().fetch(receipt.providerVersion), {
    code: "material_version_unavailable",
  });
  stored.attributes.enabled = true;
  stored.attributes.nbf = Math.floor(Date.now() / 1000) + 3600;
  await assert.rejects(f.client().fetch(receipt.providerVersion), {
    code: "material_version_unavailable",
  });
  delete stored.attributes.nbf;
  stored.contentType = "application/x-pkcs12";
  await assert.rejects(f.client().fetch(receipt.providerVersion), {
    code: "material_response_invalid",
  });
  stored.contentType = CONTENT_TYPE;
  stored.value = JSON.stringify({
    ...f.bundle,
    workspaceId: crypto.randomUUID(),
  });
  await assert.rejects(f.client().fetch(receipt.providerVersion), {
    code: "material_bundle_invalid",
  });
  stored.value = JSON.stringify(f.bundle);
  stored.id = stored.id.replace(receipt.providerVersion, "b".repeat(32));
  await assert.rejects(f.client().fetch(receipt.providerVersion), {
    code: "material_response_invalid",
  });
});
test("Azure rotates a protected customer-local token sink and redacts authentication errors", async (t) => {
  const f = await fixture(t);
  const client = f.client();
  const receipt = await client.publish(f.bundle);
  f.rotate("rotated-customer-local-token-only");
  await client.fetch(receipt.providerVersion);
  assert.equal(
    f.requests.at(-1).auth,
    "Bearer rotated-customer-local-token-only",
  );
  f.status(403);
  await assert.rejects(
    client.fetch(receipt.providerVersion),
    (e) => e.code === "material_auth_denied" && !e.message.includes("canary"),
  );
  writeProtectedJson(f.tokenFile, {
    accessToken: "expired-customer-local-token",
    expiresOn: Date.now() - 1,
  });
  await assert.rejects(client.fetch(receipt.providerVersion), {
    code: "material_auth_unavailable",
  });
});
test("Azure rejects unsupported hosts, nonexportable keys, Certificates API, and provider confusion", async (t) => {
  const f = await fixture(t);
  for (const change of [
    { address: "https://attacker.test" },
    { keyExportable: false },
    { api: "certificates" },
    { mount: "secret" },
    { auth: { type: "client-secret" } },
  ]) {
    const stores = { customer: { ...f.config, ...change } };
    assert.throws(
      () =>
        createMaterialStore(stores, f.intent, { fixtureLoopbackHttp: true }),
      /^Error: material_(store|auth)_config_invalid$/,
    );
  }
  assert.throws(
    () =>
      createMaterialStore(
        f.stores,
        { ...f.intent, provider: "vault-kv2" },
        { fixtureLoopbackHttp: true },
      ),
    { code: "material_provider_mismatch" },
  );
});
