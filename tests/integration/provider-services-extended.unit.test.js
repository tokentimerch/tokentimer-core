const { expect } = require("chai");
const Module = require("module");
const path = require("path");

function resolveServiceModule(relativePathFromApi) {
  const candidates = [
    path.join(
      __dirname,
      "..",
      "..",
      "apps",
      "api",
      "services",
      relativePathFromApi,
    ),
    path.join(
      __dirname,
      "..",
      "..",
      "apps",
      "saas",
      "integrations",
      relativePathFromApi,
    ),
  ];
  for (const candidate of candidates) {
    try {
      return require.resolve(candidate);
    } catch (_) {}
  }
  throw new Error(`Unable to resolve service module: ${relativePathFromApi}`);
}

function requireWithMocks(modulePath, mocks) {
  const resolved = require.resolve(modulePath);
  delete require.cache[resolved];
  const originalLoad = Module._load;
  const originalNodeEnv = process.env.NODE_ENV;
  process.env.NODE_ENV = "test";
  Module._load = function patchedLoad(request, parent, isMain) {
    if (Object.prototype.hasOwnProperty.call(mocks, request)) {
      return mocks[request];
    }
    return originalLoad.call(this, request, parent, isMain);
  };
  try {
    return require(modulePath);
  } finally {
    Module._load = originalLoad;
    process.env.NODE_ENV = originalNodeEnv;
  }
}

describe("Provider services extended unit coverage", () => {
  it("azure listCertificates and listKeys return empty arrays on 404", async () => {
    const axios404 = async () => {
      const err = new Error("not found");
      err.response = { status: 404, data: {} };
      err.status = 404;
      throw err;
    };
    const azure = requireWithMocks(resolveServiceModule("azureIntegration"), {
      axios: axios404,
    });
    const certs = await azure._test.listCertificates({
      vaultUrl: "https://vault.example.com",
      token: "token",
      maxItems: 10,
    });
    const keys = await azure._test.listKeys({
      vaultUrl: "https://vault.example.com",
      token: "token",
      maxItems: 10,
    });
    expect(certs).to.deep.equal([]);
    expect(keys).to.deep.equal([]);
  });

  it("azure scan returns empty result when endpoints return 403/404-style failures", async () => {
    const axiosAuthError = async () => {
      const err = new Error("forbidden");
      err.response = { status: 403, data: {} };
      throw err;
    };
    const azure = requireWithMocks(resolveServiceModule("azureIntegration"), {
      axios: axiosAuthError,
    });
    const out = await azure.scanAzure({
      vaultUrl: "https://vault.example.com",
      token: "token",
      include: { secrets: true, certificates: true, keys: true },
    });
    expect(out).to.be.an("object");
    expect(out.items).to.deep.equal([]);
    expect(out.summary).to.be.an("array");
  });

  it("azure AD paginates service principals via nextLink", async () => {
    let call = 0;
    const axiosMock = async () => {
      call += 1;
      if (call === 1) {
        return {
          data: {
            value: [{ id: "sp-1" }],
            "@odata.nextLink":
              "https://graph.microsoft.com/v1.0/servicePrincipals?$skiptoken=abc",
          },
        };
      }
      return { data: { value: [{ id: "sp-2" }] } };
    };
    const azureAd = requireWithMocks(
      resolveServiceModule("azureADIntegration"),
      {
        axios: axiosMock,
      },
    );
    const sps = await azureAd._test.listServicePrincipals({
      token: "header.payload.signature",
      maxItems: 10,
    });
    expect(sps.map((s) => s.id)).to.deep.equal(["sp-1", "sp-2"]);
  });

  it("vault parsing helpers detect data kind and parse fallback certificate strings", () => {
    const vault = require(resolveServiceModule("vaultIntegration"));

    expect(
      vault._test.inferKindFromData("secret/aws/token", {
        access_key: "AKIA...",
      }),
    ).to.deep.equal({ category: "key_secret", type: "api_key" });
    expect(
      vault._test.inferKindFromData("kv/cert/prod", {
        certificate:
          "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----",
      }),
    ).to.deep.equal({ category: "cert", type: "ssl_cert" });

    const validPem = `-----BEGIN CERTIFICATE-----
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
    const parsed = vault._test.parseCertificateFromUnknown(validPem);
    expect(parsed).to.be.an("object");
    expect(parsed).to.have.property("notAfter");
  });
});
