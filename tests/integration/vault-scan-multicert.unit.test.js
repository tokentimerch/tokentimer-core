"use strict";

const { expect } = require("chai");
const net = require("net");
const path = require("path");

function resolveVaultModule() {
  const candidates = [
    path.join(
      __dirname,
      "..",
      "..",
      "apps",
      "api",
      "services",
      "vaultIntegration.js",
    ),
    path.join(
      __dirname,
      "..",
      "..",
      "apps",
      "saas",
      "integrations",
      "vaultIntegration.js",
    ),
  ];
  for (const candidate of candidates) {
    try {
      return require.resolve(candidate);
    } catch (_) {}
  }
  throw new Error("Unable to resolve vaultIntegration module in this variant");
}

// Valid self-signed test certificate (CN-less subject, expires 2026-12-26)
const TEST_PEM = `-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiIMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMTYxMjI4MTI0NjEyWhcNMjYxMjI2MTI0NjEyWjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onL
Rnrq0/IzW7yWR7QkrmBL7jTKEn5u+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFc
zGkPLPgizskuemMghRniWaoLcyehkd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQz
uVaE8AkAFmxZzow3x+VJYKdjykkJ0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgw
lL9xNAwxXFg0x/XFw005UWVRIkdgcKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf
4rEjGoXbAAEgAqeGUxrcIlbjXfbcMwIDAQABo1AwTjAdBgNVHQ4EFgQUU3m/Wqor
Ss9UgOHYm8Cd8rIDZsswHwYDVR0jBBgwFoAUU3m/WqorSs9UgOHYm8Cd8rIDZssw
DAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAmuDQrOPJlxwQzK9SXFVR
vSL1BqJ7yBbKLgKu6KD8P9xh8Wp6jShZXQPaBKnfP+7bGmFMpKRzYQ3Ly7dmRGdX
r8lHdmtPuJfC7MqThJa1cI8DZ9lZ1G6xQzMW1L1F9oH1qh0aUJGqQ3BNQJhj1Y3g
F3gHCJGpMYJ9J/PqMjXgHVk5FMHT1PlGRMPKEJRNz2pYLX3fGqLH2NHNPUxqYLYe
3/tQQTdRvQJbOdtWB0FbKjZxNNrYhX3qLZPa7f0SJ6qGJP0VYJ0M7E4Ge9fhx5wS
D8JXW0KGW1vKQRz3SqPpPxPQdEuEJHWNfHXGfqRLWLw1LzW5WPUZWTVBbqLaAhIZ
gw==
-----END CERTIFICATE-----`;

// Minimal fake Vault server over raw TCP (Node's HTTP parser rejects the
// non-standard LIST verb Vault uses for KV metadata enumeration).
function startFakeVault(routes) {
  const server = net.createServer((socket) => {
    let buf = "";
    socket.on("data", (chunk) => {
      buf += chunk.toString("utf8");
      if (buf.indexOf("\r\n\r\n") === -1) return;
      const [requestLine] = buf.split("\r\n");
      const [method, rawPath] = requestLine.split(" ");
      const routeKey = `${method} ${rawPath.split("?")[0]}`;
      const route = routes[routeKey] || { status: 404, body: { errors: [] } };
      const json = JSON.stringify(route.body);
      socket.end(
        `HTTP/1.1 ${route.status} ${route.status === 200 ? "OK" : "Not Found"}\r\n` +
          `Content-Type: application/json\r\n` +
          `Content-Length: ${Buffer.byteLength(json)}\r\n` +
          `Connection: close\r\n\r\n` +
          json,
      );
      buf = "";
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      resolve({
        address: `http://127.0.0.1:${server.address().port}`,
        close: () => new Promise((r) => server.close(r)),
      });
    });
  });
}

describe("Vault KV scan behavior", () => {
  let mod;

  before(() => {
    mod = require(resolveVaultModule());
  });

  describe("buildKvSecretItems (one item per certificate key)", () => {
    const secretMeta = {
      metadata: { created_time: "2026-01-01T00:00:00Z", updated_time: null },
    };

    it("emits one item per certificate key in a multi-cert secret", () => {
      const items = mod._test.buildKvSecretItems({
        mountPath: "secret/",
        key: "common/ca",
        secret: {
          data: {
            "root-ca": TEST_PEM,
            "app1-cert": TEST_PEM,
            "app2-cert": TEST_PEM,
          },
          ...secretMeta,
        },
      });
      expect(items).to.have.length(3);
      for (const item of items) {
        expect(item.category).to.equal("cert");
        expect(item.type).to.equal("ssl_cert");
        expect(item.path).to.equal("common/ca");
        expect(item.expiration).to.equal("2026-12-26");
      }
      const locations = items.map((i) => i.location).sort();
      expect(locations).to.deep.equal([
        "vault:secret/common/ca#app1-cert",
        "vault:secret/common/ca#app2-cert",
        "vault:secret/common/ca#root-ca",
      ]);
      const fields = items.map((i) => i.secret_key).sort();
      expect(fields).to.deep.equal(["app1-cert", "app2-cert", "root-ca"]);
      // The fixture cert has no CN, so each item falls back to its
      // "pathName/field" name; identity is carried by the per-key location
      // regardless. (Regression coverage: this used to be the raw,
      // multi-attribute subject string when the CN check mis-parsed
      // Node's newline-delimited subject format - see the dedicated
      // resolveCertName/extractCommonName tests below.)
      const names = items.map((i) => i.name).sort();
      expect(names).to.deep.equal([
        "ca/app1-cert",
        "ca/app2-cert",
        "ca/root-ca",
      ]);
    });

    it("keeps the legacy location for single-cert secrets", () => {
      const items = mod._test.buildKvSecretItems({
        mountPath: "secret/",
        key: "apps/web",
        secret: { data: { certificate: TEST_PEM }, ...secretMeta },
      });
      expect(items).to.have.length(1);
      expect(items[0].location).to.equal("vault:secret/apps/web");
      expect(items[0].category).to.equal("cert");
      expect(items[0].secret_key).to.equal("certificate");
    });

    it("ignores non-certificate keys next to certificates", () => {
      const items = mod._test.buildKvSecretItems({
        mountPath: "secret/",
        key: "apps/web",
        secret: {
          data: {
            certificate: TEST_PEM,
            private_key: "-----BEGIN RSA PRIVATE KEY-----\nxxx",
            comment: "hello",
          },
          ...secretMeta,
        },
      });
      expect(items).to.have.length(1);
      expect(items[0].category).to.equal("cert");
    });

    it("emits a single non-cert item when no value parses as a certificate", () => {
      const items = mod._test.buildKvSecretItems({
        mountPath: "secret/",
        key: "db/creds",
        secret: { data: { password: "hunter2" }, ...secretMeta },
      });
      expect(items).to.have.length(1);
      expect(items[0].category).to.equal("key_secret");
      expect(items[0].type).to.equal("password");
      expect(items[0].location).to.equal("vault:secret/db/creds");
    });
  });

  describe("resolveCertName / extractCommonName (CN extraction from subject)", () => {
    it("extracts the CN from a newline-delimited RDN string with CN last (Node's actual X509Certificate.subject format)", () => {
      const { cn } = mod._test.resolveCertName({
        subject: "C=US\nST=California\nO=Example Corp\nCN=app.example.com",
        pathName: "apps/web",
        field: "certificate",
        multipleCerts: false,
      });
      expect(cn).to.equal("app.example.com");
    });

    it("uses the extracted CN as the item name when it looks like a real domain", () => {
      const { name } = mod._test.resolveCertName({
        subject: "C=US\nST=California\nO=Example Corp\nCN=app.example.com",
        pathName: "apps/web",
        field: "certificate",
        multipleCerts: false,
      });
      expect(name).to.equal("app.example.com");
    });

    it("falls back to path/field instead of the raw subject string when CN is a generic dev value (regression: previously the entire multi-attribute subject was used as the name)", () => {
      const { cn, isGenericCN, name } = mod._test.resolveCertName({
        subject:
          "C=CH\nST=Zurich\nL=Zurich\nO=Demo Testing\nOU=Local Development\nCN=localhost",
        pathName: "common/ca",
        field: "app1-cert",
        multipleCerts: true,
      });
      expect(cn).to.equal("localhost");
      expect(isGenericCN).to.equal(true);
      expect(name).to.equal("common/ca/app1-cert");
    });

    it("falls back to path/field when the subject has no CN attribute at all", () => {
      const { cn, name } = mod._test.resolveCertName({
        subject: "C=AU\nST=Some-State\nO=Internet Widgits Pty Ltd",
        pathName: "common/ca",
        field: "root-ca",
        multipleCerts: true,
      });
      expect(cn).to.equal(null);
      expect(name).to.equal("common/ca/root-ca");
    });
  });

  describe("extractCommonName", () => {
    it("finds CN regardless of position or delimiter", () => {
      expect(
        mod._test.extractCommonName("CN=app.example.com,O=Example Corp"),
      ).to.equal("app.example.com");
      expect(
        mod._test.extractCommonName("O=Example Corp\nCN=app.example.com"),
      ).to.equal("app.example.com");
      expect(mod._test.extractCommonName("O=Example Corp")).to.equal(null);
      expect(mod._test.extractCommonName(null)).to.equal(null);
    });
  });

  describe("scanVault path prefix handling", () => {
    const routes = {
      "GET /v1/sys/mounts": {
        status: 200,
        body: {
          data: { "secret/": { type: "kv", options: { version: "2" } } },
        },
      },
      "LIST /v1/secret/metadata/": {
        status: 200,
        body: { data: { keys: ["common/"] } },
      },
      "LIST /v1/secret/metadata/common/": {
        status: 200,
        body: { data: { keys: ["ca", "other"] } },
      },
      // LIST on the leaf secret 404s exactly like real Vault
      "GET /v1/secret/data/common/ca": {
        status: 200,
        body: {
          data: {
            data: { "root-ca": TEST_PEM, "app1-cert": TEST_PEM },
            metadata: { created_time: "2026-01-01T00:00:00Z" },
          },
        },
      },
      "GET /v1/secret/data/common/other": {
        status: 200,
        body: {
          data: {
            data: { password: "hunter2" },
            metadata: { created_time: "2026-01-01T00:00:00Z" },
          },
        },
      },
    };

    let vault;

    before(async () => {
      vault = await startFakeVault(routes);
    });

    after(async () => {
      if (vault) await vault.close();
    });

    const scan = (pathPrefix) =>
      mod.scanVault({
        address: vault.address,
        token: "test-token",
        include: { kv: true, pki: false },
        pathPrefix,
      });

    it("scans everything without a prefix (multi-cert secret expands)", async () => {
      const res = await scan("");
      // 2 certs from common/ca + 1 password from common/other
      expect(res.items).to.have.length(3);
      expect(res.items.filter((i) => i.category === "cert")).to.have.length(2);
      expect(res.summary).to.deep.equal([
        { mount: "secret/", type: "kv", found: 3, truncated: false },
      ]);
    });

    it("accepts an exact secret path (leaf) as prefix", async () => {
      const res = await scan("common/ca");
      expect(res.items).to.have.length(2);
      for (const item of res.items) {
        expect(item.category).to.equal("cert");
        expect(item.path).to.equal("common/ca");
      }
    });

    it("still supports a folder prefix", async () => {
      const res = await scan("common");
      expect(res.items).to.have.length(3);
    });

    it("returns empty for a prefix that is neither folder nor secret", async () => {
      const res = await scan("does/not/exist");
      expect(res.items).to.have.length(0);
    });

    it("strips a leading mount-name segment copied into the prefix", async () => {
      // Customers often copy the full Vault path including the mount name
      // (e.g. from `vault kv get secret/common/ca`); that leading "secret/"
      // must not be treated as part of the in-mount path.
      const res = await scan("secret/common/ca");
      expect(res.items).to.have.length(2);
      for (const item of res.items) {
        expect(item.category).to.equal("cert");
        expect(item.path).to.equal("common/ca");
      }
    });

    it("treats a prefix equal to just the mount name as no prefix", async () => {
      const res = await scan("secret");
      expect(res.items).to.have.length(3);
    });
  });

  describe("scanVault category filtering", () => {
    const routes = {
      "GET /v1/sys/mounts": {
        status: 200,
        body: {
          data: { "secret/": { type: "kv", options: { version: "2" } } },
        },
      },
      "LIST /v1/secret/metadata/": {
        status: 200,
        body: { data: { keys: ["ca", "creds"] } },
      },
      "GET /v1/secret/data/ca": {
        status: 200,
        body: {
          data: {
            data: { certificate: TEST_PEM },
            metadata: { created_time: "2026-01-01T00:00:00Z" },
          },
        },
      },
      "GET /v1/secret/data/creds": {
        status: 200,
        body: {
          data: {
            data: { password: "hunter2" },
            metadata: { created_time: "2026-01-01T00:00:00Z" },
          },
        },
      },
    };

    let vault;

    before(async () => {
      vault = await startFakeVault(routes);
    });

    after(async () => {
      if (vault) await vault.close();
    });

    it("returns every category when no filter is given", async () => {
      const res = await mod.scanVault({
        address: vault.address,
        token: "test-token",
        include: { kv: true, pki: false },
      });
      expect(res.items).to.have.length(2);
    });

    it("keeps only cert items when categories is ['cert']", async () => {
      const res = await mod.scanVault({
        address: vault.address,
        token: "test-token",
        include: { kv: true, pki: false },
        categories: ["cert"],
      });
      expect(res.items).to.have.length(1);
      expect(res.items[0].category).to.equal("cert");
      expect(res.summary).to.deep.equal([
        { mount: "secret/", type: "kv", found: 1, truncated: false },
      ]);
    });

    it("keeps only key_secret items when categories is ['key_secret']", async () => {
      const res = await mod.scanVault({
        address: vault.address,
        token: "test-token",
        include: { kv: true, pki: false },
        categories: ["key_secret"],
      });
      expect(res.items).to.have.length(1);
      expect(res.items[0].category).to.equal("key_secret");
    });
  });
});
