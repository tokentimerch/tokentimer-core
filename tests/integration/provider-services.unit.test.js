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

async function withPatchedLoad(mocks, run) {
  const originalLoad = Module._load;
  Module._load = function patchedLoad(request, parent, isMain) {
    if (Object.prototype.hasOwnProperty.call(mocks, request)) {
      return mocks[request];
    }
    return originalLoad.call(this, request, parent, isMain);
  };
  try {
    return await run();
  } finally {
    Module._load = originalLoad;
  }
}

async function expectReject(promiseFactory, pattern) {
  try {
    await promiseFactory();
    throw new Error("Expected promise to reject");
  } catch (err) {
    expect(String(err && err.message)).to.match(pattern);
  }
}

// Builds a JWT-shaped (but unsigned) token string containing a `tid` claim
// of at least `minLength` characters, since scanAzureAD now requires a
// tenant id to attribute scan results (see sourceIdentity.js) and refuses
// tokens that don't decode to one.
function fakeAzureAdToken(minLength = 0) {
  const header = Buffer.from(JSON.stringify({ alg: "none" })).toString(
    "base64",
  );
  let padLength = 0;
  let token;
  do {
    const payload = Buffer.from(
      JSON.stringify({
        tid: "11111111-1111-1111-1111-111111111111",
        aud: "https://graph.microsoft.com",
        pad: "x".repeat(padLength),
      }),
    ).toString("base64");
    token = `${header}.${payload}.signature`;
    padLength += 100;
  } while (token.length < minLength);
  return token;
}

// Every scanAWS() call now resolves the STS account id up front (it anchors
// AWS token provenance -- see sourceIdentity.js), so any test that reaches
// past input validation needs this mocked regardless of which AWS service
// it's actually exercising.
function mockSts(accountId = "123456789012") {
  class GetCallerIdentityCommand {}
  class STSClient {
    async send() {
      return { Account: accountId, Arn: "arn:aws:iam::123456789012:user/test" };
    }
  }
  return { "@aws-sdk/client-sts": { STSClient, GetCallerIdentityCommand } };
}

describe("Provider service unit coverage", () => {
  describe("AWS integration", () => {
    it("validates required credentials", async () => {
      const aws = require(resolveServiceModule("awsIntegration"));
      await expectReject(
        () => aws.scanAWS({ accessKeyId: "", secretAccessKey: "" }),
        /required/,
      );
    });

    // Regression guard: AWS STS explicitly documents that session token size
    // is not fixed ("typically less than 4096 bytes, but that can vary").
    // A stale local cap of 2000 chars silently rejected valid AssumeRole /
    // GetSessionToken credentials (e.g. with session tags or chained roles)
    // with "Invalid sessionToken format" before any AWS call was made.
    it("accepts a sessionToken above the old 2000-char cap", async () => {
      const stsMocks = mockSts();
      const aws = requireWithMocks(resolveServiceModule("awsIntegration"), stsMocks);
      const result = await withPatchedLoad(stsMocks, () =>
        aws.scanAWS({
          accessKeyId: "AKIAEXAMPLE123",
          secretAccessKey: "super-secret-key",
          sessionToken: "x".repeat(3500),
          region: "us-east-1",
          // Skip every scan type so this stays a pure validation test with no
          // AWS SDK client instantiation or network calls.
          include: { secrets: false, iam: false, certificates: false },
        }),
      );
      expect(result).to.have.property("items").that.is.an("array");
      expect(result).to.have.property("summary").that.is.an("array");
    });

    it("still rejects a sessionToken over the 5000-char hard cap", async () => {
      const aws = require(resolveServiceModule("awsIntegration"));
      await expectReject(
        () =>
          aws.scanAWS({
            accessKeyId: "AKIAEXAMPLE123",
            secretAccessKey: "super-secret-key",
            sessionToken: "x".repeat(6000),
            region: "us-east-1",
          }),
        /Invalid sessionToken format/,
      );
    });

    it("scans secrets, certificates, and IAM keys with mocked SDKs", async () => {
      class ListSecretsCommand {
        constructor(input) {
          this.input = input;
        }
      }
      class DescribeSecretCommand {
        constructor(input) {
          this.input = input;
        }
      }
      class ListUsersCommand {
        constructor(input) {
          this.input = input;
        }
      }
      class ListAccessKeysCommand {
        constructor(input) {
          this.input = input;
        }
      }
      class GetAccessKeyLastUsedCommand {
        constructor(input) {
          this.input = input;
        }
      }
      class ListCertificatesCommand {
        constructor(input) {
          this.input = input;
        }
      }
      class DescribeCertificateCommand {
        constructor(input) {
          this.input = input;
        }
      }

      class SecretsManagerClient {
        async send(command) {
          if (command instanceof ListSecretsCommand) {
            return {
              SecretList: [
                {
                  Name: "db-password",
                  ARN: "arn:aws:secretsmanager:us-east-1:123:secret:db-password",
                  Description: "database secret",
                  CreatedDate: new Date("2025-01-01T00:00:00Z"),
                  LastChangedDate: new Date("2025-01-02T00:00:00Z"),
                },
              ],
            };
          }
          if (command instanceof DescribeSecretCommand) {
            return {
              NextRotationDate: new Date("2026-01-01T00:00:00Z"),
              LastAccessedDate: new Date("2025-01-10T00:00:00Z"),
            };
          }
          throw new Error("Unexpected Secrets Manager command");
        }
      }

      class IAMClient {
        async send(command) {
          if (command instanceof ListUsersCommand) {
            return { Users: [{ UserName: "deploy-bot" }] };
          }
          if (command instanceof ListAccessKeysCommand) {
            return {
              AccessKeyMetadata: [
                {
                  AccessKeyId: "AKIA1234567890",
                  Status: "Active",
                  CreateDate: new Date("2025-02-01T00:00:00Z"),
                },
              ],
            };
          }
          if (command instanceof GetAccessKeyLastUsedCommand) {
            return {
              AccessKeyLastUsed: {
                LastUsedDate: new Date("2025-02-02T00:00:00Z"),
                ServiceName: "s3",
                Region: "us-east-1",
              },
            };
          }
          throw new Error("Unexpected IAM command");
        }
      }

      class ACMClient {
        async send(command) {
          if (command instanceof ListCertificatesCommand) {
            return {
              CertificateSummaryList: [
                {
                  DomainName: "example.com",
                  CertificateArn: "arn:aws:acm:us-east-1:123:certificate/abc",
                },
              ],
            };
          }
          if (command instanceof DescribeCertificateCommand) {
            return {
              Certificate: {
                NotAfter: new Date("2026-06-01T00:00:00Z"),
                Issuer: "LetsEncrypt",
                Serial: "serial-123",
                InUseBy: ["alb-1"],
                Type: "AMAZON_ISSUED",
              },
            };
          }
          throw new Error("Unexpected ACM command");
        }
      }

      const mocks = {
        "@aws-sdk/client-secrets-manager": {
          SecretsManagerClient,
          ListSecretsCommand,
          DescribeSecretCommand,
        },
        "@aws-sdk/client-iam": {
          IAMClient,
          ListUsersCommand,
          ListAccessKeysCommand,
          GetAccessKeyLastUsedCommand,
        },
        "@aws-sdk/client-acm": {
          ACMClient,
          ListCertificatesCommand,
          DescribeCertificateCommand,
        },
        ...mockSts(),
      };
      const aws = requireWithMocks(
        resolveServiceModule("awsIntegration"),
        mocks,
      );

      const result = await withPatchedLoad(mocks, () =>
        aws.scanAWS({
          accessKeyId: "AKIAEXAMPLE123",
          secretAccessKey: "super-secret-key",
          region: "us-east-1",
          include: { secrets: true, iam: true, certificates: true },
          maxItems: 10,
        }),
      );

      expect(result.items).to.be.an("array").with.length.greaterThan(0);
      expect(
        result.items.some((i) => i.source === "aws-secrets-manager"),
      ).to.equal(true);
      expect(result.items.some((i) => i.source === "aws-acm")).to.equal(true);
      expect(result.items.some((i) => i.source === "aws-iam-key")).to.equal(
        true,
      );
      expect(result.summary.some((s) => s.type === "secrets_manager")).to.equal(
        true,
      );
      expect(
        result.summary.some((s) => s.type === "acm_certificates"),
      ).to.equal(true);
      expect(result.summary.some((s) => s.type === "iam_keys")).to.equal(true);
    });

    // Regression guard: ACM ListCertificates defaults to server-side
    // filtering that only returns RSA_1024/RSA_2048 certificates, so ECDSA
    // and RSA_3072/RSA_4096 certs were silently missing from scans. It also
    // paginates with NextToken, which was previously ignored.
    it("requests all ACM key types and follows NextToken pagination", async () => {
      class ListCertificatesCommand {
        constructor(input) {
          this.input = input;
        }
      }
      class DescribeCertificateCommand {
        constructor(input) {
          this.input = input;
        }
      }

      const listInputs = [];
      class ACMClient {
        async send(command) {
          if (command instanceof ListCertificatesCommand) {
            listInputs.push(command.input);
            if (!command.input.NextToken) {
              return {
                CertificateSummaryList: [
                  {
                    DomainName: "ecdsa.example.com",
                    CertificateArn: "arn:aws:acm:us-east-1:123:certificate/ec",
                  },
                ],
                NextToken: "page-2",
              };
            }
            return {
              CertificateSummaryList: [
                {
                  DomainName: "rsa4096.example.com",
                  CertificateArn: "arn:aws:acm:us-east-1:123:certificate/rsa",
                },
              ],
            };
          }
          if (command instanceof DescribeCertificateCommand) {
            return {
              Certificate: {
                DomainName: command.input.CertificateArn.endsWith("ec")
                  ? "ecdsa.example.com"
                  : "rsa4096.example.com",
                NotAfter: new Date("2026-06-01T00:00:00Z"),
                Status: "ISSUED",
              },
            };
          }
          throw new Error("Unexpected ACM command");
        }
      }

      const mocks = {
        "@aws-sdk/client-acm": {
          ACMClient,
          ListCertificatesCommand,
          DescribeCertificateCommand,
        },
        ...mockSts(),
      };
      const aws = requireWithMocks(
        resolveServiceModule("awsIntegration"),
        mocks,
      );

      const result = await withPatchedLoad(mocks, () =>
        aws.scanAWS({
          accessKeyId: "AKIAEXAMPLE123",
          secretAccessKey: "super-secret-key",
          region: "us-east-1",
          include: { secrets: false, iam: false, certificates: true },
          maxItems: 10,
        }),
      );

      const certs = result.items.filter((i) => i.source === "aws-acm");
      expect(certs.map((c) => c.name).sort()).to.deep.equal([
        "ecdsa.example.com",
        "rsa4096.example.com",
      ]);
      expect(listInputs).to.have.length(2);
      for (const input of listInputs) {
        expect(input.Includes?.keyTypes).to.include.members([
          "RSA_2048",
          "RSA_4096",
          "EC_prime256v1",
          "EC_secp384r1",
          "EC_secp521r1",
        ]);
      }
      expect(listInputs[1].NextToken).to.equal("page-2");
    });
  });

  describe("Azure Key Vault integration", () => {
    it("maps response failures in azureRequest", async () => {
      const axiosMock = async () => {
        const err = new Error("forbidden");
        err.response = { status: 403, data: { error: "forbidden" } };
        throw err;
      };
      const azure = requireWithMocks(resolveServiceModule("azureIntegration"), {
        axios: axiosMock,
      });
      await expectReject(
        () =>
          azure._test.azureRequest({
            vaultUrl: "https://vault.example.com",
            token: "test-token",
            path: "/secrets",
          }),
        /(Azure Key Vault|Permission denied|forbidden|403)/i,
      );
    });

    it("returns empty list on 404 for listSecrets", async () => {
      const axiosMock = async () => {
        const err = new Error("missing");
        err.response = { status: 404, data: {} };
        err.status = 404;
        throw err;
      };
      const azure = requireWithMocks(resolveServiceModule("azureIntegration"), {
        axios: axiosMock,
      });
      const result = await azure._test.listSecrets({
        vaultUrl: "https://vault.example.com",
        token: "test-token",
        maxItems: 10,
      });
      expect(result.items).to.deep.equal([]);
    });

    it("returns null on 404 for getSecret", async () => {
      const axiosMock = async () => {
        const err = new Error("missing");
        err.response = { status: 404, data: {} };
        err.status = 404;
        throw err;
      };
      const azure = requireWithMocks(resolveServiceModule("azureIntegration"), {
        axios: axiosMock,
      });
      const result = await azure._test.getSecret({
        vaultUrl: "https://vault.example.com",
        token: "test-token",
        secretName: "db-password",
      });
      expect(result).to.equal(null);
    });

    // Regression guard: the keys list API returns the key identifier in
    // `kid`, not `id` (unlike secrets/certificates which use `id`). Reading
    // `id` meant every key was skipped as "missing name" and the keys scan
    // always reported zero items.
    it("extracts key names from the kid field returned by the keys list API", async () => {
      const axiosMock = async (config) => {
        if (config.url && config.url.includes("/keys")) {
          return {
            data: {
              value: [
                {
                  kid: "https://vault.example.com/keys/signing-key",
                  attributes: {
                    enabled: true,
                    exp: 1893456000,
                    created: 1704067200,
                  },
                },
              ],
            },
          };
        }
        return { data: { value: [] } };
      };
      const azure = requireWithMocks(resolveServiceModule("azureIntegration"), {
        axios: axiosMock,
      });
      const result = await azure.scanAzure({
        vaultUrl: "https://vault.example.com",
        token: "test-token",
        include: { secrets: false, certificates: false, keys: true },
        maxItems: 10,
      });
      const keys = result.items.filter(
        (i) => i.source === "azure-key-vault-key",
      );
      expect(keys).to.have.length(1);
      expect(keys[0].name).to.equal("signing-key");
      expect(keys[0].expiration).to.be.a("string");
    });

    it("refuses Key Vault pagination URLs that leave the vault host", async () => {
      const requestedUrls = [];
      const axiosMock = async (config) => {
        requestedUrls.push(config.url);
        expect(config.maxRedirects).to.equal(0);
        return {
          data: {
            value: [{ id: "https://vault.example.com/secrets/s1" }],
            nextLink: "http://127.0.0.1:9/secrets?api-version=7.4",
          },
        };
      };
      const azure = requireWithMocks(resolveServiceModule("azureIntegration"), {
        axios: axiosMock,
      });
      await expectReject(
        () =>
          azure._test.listSecrets({
            vaultUrl: "https://vault.example.com",
            token: "test-token",
            maxItems: 10,
          }),
        /left the expected host/,
      );
      expect(requestedUrls).to.have.length(1);
      expect(String(requestedUrls[0])).to.match(/vault\.example\.com/);
    });

    it("follows Key Vault pagination URLs that stay on the vault host", async () => {
      const requestedUrls = [];
      const axiosMock = async (config) => {
        requestedUrls.push(config.url);
        expect(config.maxRedirects).to.equal(0);
        if (requestedUrls.length === 1) {
          return {
            data: {
              value: [{ id: "s1" }],
              nextLink:
                "https://vault.example.com/secrets?api-version=7.4&$skiptoken=abc",
            },
          };
        }
        return { data: { value: [{ id: "s2" }] } };
      };
      const azure = requireWithMocks(resolveServiceModule("azureIntegration"), {
        axios: axiosMock,
      });
      const secrets = await azure._test.listSecrets({
        vaultUrl: "https://vault.example.com",
        token: "test-token",
        maxItems: 10,
      });
      expect(secrets.items.map((s) => s.id)).to.deep.equal(["s1", "s2"]);
      expect(requestedUrls[1]).to.match(/vault\.example\.com/);
      expect(requestedUrls[1]).to.match(/skiptoken=abc/);
    });
  });

  describe("Azure AD integration", () => {
    it("maps response failures in graphRequest", async () => {
      const axiosMock = async () => {
        const err = new Error("unauthorized");
        err.response = {
          status: 401,
          data: {
            error: { code: "InvalidAuthenticationToken", message: "expired" },
          },
        };
        throw err;
      };
      const azureAd = requireWithMocks(
        resolveServiceModule("azureADIntegration"),
        {
          axios: axiosMock,
        },
      );
      await expectReject(
        () =>
          azureAd._test.graphRequest({
            token: "header.payload.signature",
            path: "/applications",
          }),
        /(Microsoft Graph|InvalidAuthenticationToken|expired|401)/i,
      );
    });

    it("paginates applications via nextLink", async () => {
      const requestedUrls = [];
      const axiosMock = async (config) => {
        requestedUrls.push(config.url);
        if (requestedUrls.length === 1) {
          return {
            data: {
              value: [{ id: "app-1" }],
              "@odata.nextLink":
                "https://graph.microsoft.com/v1.0/applications?$skiptoken=abc",
            },
          };
        }
        return { data: { value: [{ id: "app-2" }] } };
      };
      const azureAd = requireWithMocks(
        resolveServiceModule("azureADIntegration"),
        {
          axios: axiosMock,
        },
      );
      const apps = await azureAd._test.listApplications({
        token: "header.payload.signature",
        maxItems: 10,
      });
      expect(apps.items.map((a) => a.id)).to.deep.equal(["app-1", "app-2"]);
      // Regression guard: @odata.nextLink already contains the /v1.0 prefix.
      // Re-prepending the Graph base URL produced /v1.0/v1.0/... which 404s
      // and silently truncated tenants with more than one page of apps.
      expect(requestedUrls[1]).to.equal(
        "https://graph.microsoft.com/v1.0/applications?$skiptoken=abc",
      );
      expect(requestedUrls[1]).to.not.match(/v1\.0\/v1\.0/);
    });

    it("refuses Graph pagination URLs that leave graph.microsoft.com", async () => {
      const requestedUrls = [];
      const axiosMock = async (config) => {
        requestedUrls.push(config.url);
        expect(config.maxRedirects).to.equal(0);
        return {
          data: {
            value: [{ id: "app-1" }],
            "@odata.nextLink": "http://127.0.0.1:9/v1.0/applications",
          },
        };
      };
      const azureAd = requireWithMocks(
        resolveServiceModule("azureADIntegration"),
        {
          axios: axiosMock,
        },
      );
      await expectReject(
        () =>
          azureAd._test.listApplications({
            token: "header.payload.signature",
            maxItems: 10,
          }),
        /left the expected host/,
      );
      expect(requestedUrls).to.have.length(1);
      expect(String(requestedUrls[0])).to.match(/graph\.microsoft\.com/);
    });

    // Regression guard: real Microsoft Graph access tokens (especially with
    // group/role claims) routinely exceed 3000 characters. A stale local cap
    // of 3000 silently rejected valid tokens with "Invalid token format"
    // before the request ever reached Microsoft Graph. The route layer
    // already allows up to 5000 chars, so the service must match.
    it("accepts a token above the old 3000-char cap and within the 5000-char route limit", async () => {
      const axiosMock = async () => ({ data: { value: [] } });
      const azureAd = requireWithMocks(
        resolveServiceModule("azureADIntegration"),
        { axios: axiosMock },
      );
      const result = await azureAd.scanAzureAD({
        token: fakeAzureAdToken(4000),
        include: { applications: true, servicePrincipals: false },
      });
      expect(result).to.have.property("items").that.is.an("array");
      expect(result).to.have.property("summary").that.is.an("array");
    });

    it("summarizes extracted credentials per sourceKind, not Graph object counts", async () => {
      const end = new Date(Date.now() + 86400000).toISOString();
      const start = new Date().toISOString();
      const secret = (keyId) => ({
        keyId,
        displayName: keyId,
        startDateTime: start,
        endDateTime: end,
      });
      const cert = (keyId) => ({
        keyId,
        displayName: keyId,
        startDateTime: start,
        endDateTime: end,
        type: "AsymmetricX509Cert",
        usage: "Verify",
      });
      const apps = [
        {
          appId: "app-1",
          displayName: "App One",
          passwordCredentials: [secret("s1"), secret("s2")],
          keyCredentials: [],
        },
        {
          appId: "app-2",
          displayName: "App Two",
          passwordCredentials: [secret("s3")],
          keyCredentials: [],
        },
        {
          appId: "app-3",
          displayName: "App Three",
          passwordCredentials: [],
          keyCredentials: [],
        },
        {
          appId: "app-4",
          displayName: "App Four",
          passwordCredentials: [],
          keyCredentials: [],
        },
      ];
      const sps = [
        {
          appId: "sp-1",
          displayName: "SP One",
          passwordCredentials: [secret("p1")],
          keyCredentials: [cert("c1"), cert("c2")],
        },
        {
          appId: "sp-2",
          displayName: "SP Two",
          passwordCredentials: [],
          keyCredentials: [],
        },
        {
          appId: "sp-3",
          displayName: "SP Three",
          passwordCredentials: [],
          keyCredentials: [],
        },
      ];
      const axiosMock = async (config) => {
        const url = String(config.url || "");
        if (url.includes("servicePrincipals")) {
          return { data: { value: sps } };
        }
        return { data: { value: apps } };
      };
      const azureAd = requireWithMocks(
        resolveServiceModule("azureADIntegration"),
        { axios: axiosMock },
      );
      const result = await azureAd.scanAzureAD({
        token: fakeAzureAdToken(),
        include: { applications: true, servicePrincipals: true },
      });

      expect(result.items).to.have.length(6);
      const byKind = Object.fromEntries(
        result.summary.map((s) => [s.sourceKind, s]),
      );
      expect(byKind["azure-ad-client-secret"]).to.include({
        type: "applications",
        found: 3,
        secrets: 3,
      });
      expect(byKind["azure-ad-client-secret"]).to.not.have.property(
        "certificates",
      );
      expect(byKind["azure-ad-certificate"]).to.include({
        type: "applications",
        found: 0,
        certificates: 0,
      });
      expect(byKind["azure-ad-sp-secret"]).to.include({
        type: "service_principals",
        found: 1,
        secrets: 1,
      });
      expect(byKind["azure-ad-sp-certificate"]).to.include({
        type: "service_principals",
        found: 2,
        certificates: 2,
      });
      expect(byKind["azure-ad-client-secret"].found).to.not.equal(apps.length);
      expect(byKind["azure-ad-sp-secret"].found).to.not.equal(sps.length);
    });

    it("still rejects a token over the 5000-char hard cap", async () => {
      const azureAd = require(resolveServiceModule("azureADIntegration"));
      await expectReject(
        () => azureAd.scanAzureAD({ token: "x".repeat(6000) }),
        /Invalid token format/,
      );
    });
  });

  describe("GCP integration", () => {
    it("maps response failures in gcpRequest", async () => {
      const axiosMock = async () => {
        const err = new Error("forbidden");
        err.response = { status: 403, data: { error: "forbidden" } };
        throw err;
      };
      const gcp = requireWithMocks(resolveServiceModule("gcpIntegration"), {
        axios: axiosMock,
      });
      await expectReject(
        () =>
          gcp._test.gcpRequest({
            accessToken: "token",
            path: "/projects/proj/secrets",
          }),
        /(GCP Secret Manager|Permission denied|forbidden|403)/i,
      );
    });

    it("returns empty list on 404 for listSecrets", async () => {
      const axiosMock = async () => {
        const err = new Error("missing");
        err.response = { status: 404, data: {} };
        throw err;
      };
      const gcp = requireWithMocks(resolveServiceModule("gcpIntegration"), {
        axios: axiosMock,
      });
      const secrets = await gcp._test.listSecrets({
        projectId: "proj",
        accessToken: "token",
        maxItems: 5,
      });
      expect(secrets.items).to.deep.equal([]);
    });

    it("returns null on 404 for getSecretVersion", async () => {
      const axiosMock = async () => {
        const err = new Error("missing");
        err.response = { status: 404, data: {} };
        throw err;
      };
      const gcp = requireWithMocks(resolveServiceModule("gcpIntegration"), {
        axios: axiosMock,
      });
      const version = await gcp._test.getSecretVersion({
        projectId: "proj",
        accessToken: "token",
        secretId: "secret-1",
      });
      expect(version).to.equal(null);
    });

    it("keeps the secrets kind complete when a version lookup fails", async () => {
      const axiosMock = async (config) => {
        const url = String(config.url || "");
        if (url.includes("/versions")) {
          if (url.includes("/blocked/")) {
            const err = new Error("denied");
            err.response = { status: 403, data: { error: "PERMISSION_DENIED" } };
            throw err;
          }
          return {
            data: {
              versions: [
                {
                  name: "projects/proj/secrets/ok/versions/1",
                  state: "ENABLED",
                },
              ],
            },
          };
        }
        return {
          data: {
            secrets: [
              { name: "projects/proj/secrets/ok" },
              { name: "projects/proj/secrets/blocked" },
            ],
          },
        };
      };
      const gcp = requireWithMocks(resolveServiceModule("gcpIntegration"), {
        axios: axiosMock,
      });
      const result = await gcp.scanGCP({
        projectId: "proj",
        accessToken: "token",
        include: { secrets: true },
      });

      expect(result.items.map((i) => i.sourceObjectId).sort()).to.deep.equal([
        "blocked",
        "ok",
      ]);
      expect(result.items.find((i) => i.sourceObjectId === "blocked")).to.include(
        { expiration: null },
      );
      expect(result.summary).to.have.length(1);
      expect(result.summary[0]).to.include({
        sourceKind: "gcp-secret-manager",
        found: 2,
        failedCount: 1,
        truncated: false,
        complete: true,
      });
    });

    it("discovers Certificate Manager and Compute Engine SSL certificates", async () => {
      const axiosMock = async (config) => {
        const url = String(config.url || "");
        if (url.includes("certificatemanager.googleapis.com")) {
          return {
            data: {
              certificates: [
                {
                  name: "projects/proj/locations/global/certificates/cm-cert",
                  expireTime: "2030-01-01T00:00:00Z",
                  createTime: "2025-01-01T00:00:00Z",
                  sanDnsnames: ["example.com"],
                  managed: { state: "ACTIVE" },
                },
              ],
            },
          };
        }
        if (url.includes("compute.googleapis.com")) {
          return {
            data: {
              items: {
                global: {
                  sslCertificates: [
                    {
                      name: "lb-ssl-cert",
                      expireTime: "2031-02-02T00:00:00Z",
                      creationTimestamp: "2025-02-02T00:00:00Z",
                      subjectAlternativeNames: ["lb.example.com"],
                    },
                  ],
                },
              },
            },
          };
        }
        return { data: { secrets: [] } };
      };
      const gcp = requireWithMocks(resolveServiceModule("gcpIntegration"), {
        axios: axiosMock,
      });
      const result = await gcp.scanGCP({
        projectId: "proj",
        accessToken: "token",
        include: { secrets: false, certificates: true },
      });

      const cmItem = result.items.find(
        (i) => i.sourceKind === "gcp-certificate-manager-cert",
      );
      expect(cmItem).to.include({
        sourceObjectId: "cm-cert",
        category: "cert",
        type: "ssl_cert",
        expiration: "2030-01-01",
      });
      expect(cmItem.dimensions).to.deep.equal({ location: "global" });

      const computeItem = result.items.find(
        (i) => i.sourceKind === "gcp-compute-ssl-cert",
      );
      expect(computeItem).to.include({
        // No selfLink in this fixture -- falls back to "<scope>/<name>".
        sourceObjectId: "global/lb-ssl-cert",
        name: "lb-ssl-cert",
        category: "cert",
        type: "ssl_cert",
        expiration: "2031-02-02",
      });
      expect(computeItem.dimensions).to.deep.equal({ location: "global" });

      const byKind = Object.fromEntries(
        result.summary.map((s) => [s.sourceKind, s]),
      );
      expect(byKind["gcp-certificate-manager-cert"]).to.include({
        found: 1,
        complete: true,
      });
      expect(byKind["gcp-compute-ssl-cert"]).to.include({
        found: 1,
        complete: true,
      });
    });

    it("reports an empty complete sub-scope for both cert kinds when the project has none", async () => {
      const axiosMock = async (config) => {
        const url = String(config.url || "");
        if (url.includes("certificatemanager.googleapis.com")) {
          return { data: { certificates: [] } };
        }
        if (url.includes("compute.googleapis.com")) {
          return { data: { items: {} } };
        }
        return { data: { secrets: [] } };
      };
      const gcp = requireWithMocks(resolveServiceModule("gcpIntegration"), {
        axios: axiosMock,
      });
      const result = await gcp.scanGCP({
        projectId: "proj",
        accessToken: "token",
        include: { secrets: false, certificates: true },
      });

      expect(result.items).to.have.length(0);
      const byKind = Object.fromEntries(
        result.summary.map((s) => [s.sourceKind, s]),
      );
      expect(byKind["gcp-certificate-manager-cert"]).to.include({
        found: 0,
        complete: true,
      });
      expect(byKind["gcp-compute-ssl-cert"]).to.include({
        found: 0,
        complete: true,
      });
    });

    it("marks a cert sub-scope incomplete on API error without failing the whole scan", async () => {
      const axiosMock = async (config) => {
        const url = String(config.url || "");
        if (url.includes("certificatemanager.googleapis.com")) {
          const err = new Error("denied");
          err.response = {
            status: 403,
            data: { error: "PERMISSION_DENIED" },
          };
          throw err;
        }
        if (url.includes("compute.googleapis.com")) {
          return { data: { items: {} } };
        }
        return {
          data: { secrets: [{ name: "projects/proj/secrets/only-secret" }] },
        };
      };
      const gcp = requireWithMocks(resolveServiceModule("gcpIntegration"), {
        axios: axiosMock,
      });
      const result = await gcp.scanGCP({
        projectId: "proj",
        accessToken: "token",
        include: { secrets: true, certificates: true },
      });

      const byKind = Object.fromEntries(
        result.summary.map((s) => [s.sourceKind, s]),
      );
      expect(byKind["gcp-certificate-manager-cert"]).to.include({
        complete: false,
        status: 403,
      });
      expect(byKind["gcp-compute-ssl-cert"]).to.include({
        found: 0,
        complete: true,
      });
      // A failed cert sub-scope must not sink the secrets sub-scope or the
      // overall scan when items were still found elsewhere.
      expect(result.items.some((i) => i.sourceKind === "gcp-secret-manager"))
        .to.equal(true);
    });

    it("discovers both regional and global Compute Engine SSL certificates via aggregatedList", async () => {
      let requestedUrl = null;
      const axiosMock = async (config) => {
        requestedUrl = String(config.url || "");
        return {
          data: {
            items: {
              global: {
                sslCertificates: [
                  {
                    name: "global-cert",
                    expireTime: "2030-06-01T00:00:00Z",
                    creationTimestamp: "2025-01-01T00:00:00Z",
                    subjectAlternativeNames: ["global.example.com"],
                  },
                ],
              },
              "regions/us-central1": {
                sslCertificates: [
                  {
                    name: "regional-cert",
                    expireTime: "2030-07-01T00:00:00Z",
                    creationTimestamp: "2025-01-02T00:00:00Z",
                    subjectAlternativeNames: ["regional.example.com"],
                    region:
                      "https://www.googleapis.com/compute/v1/projects/proj/regions/us-central1",
                  },
                ],
              },
            },
          },
        };
      };
      const gcp = requireWithMocks(resolveServiceModule("gcpIntegration"), {
        axios: axiosMock,
      });
      const result = await gcp._test.listComputeSslCertificates({
        projectId: "proj",
        accessToken: "token",
      });

      expect(requestedUrl).to.include("/aggregated/sslCertificates");
      expect(result.truncated).to.equal(false);
      const names = result.items.map((i) => i.name).sort();
      expect(names).to.deep.equal(["global-cert", "regional-cert"]);
      const globalCert = result.items.find((i) => i.name === "global-cert");
      const regionalCert = result.items.find(
        (i) => i.name === "regional-cert",
      );
      expect(globalCert.scope).to.equal("global");
      expect(regionalCert.scope).to.equal("regions/us-central1");
    });

    it("keeps same-named Compute SSL certificates in different scopes distinct, each with its own scope in dimensions", async () => {
      const axiosMock = async (config) => {
        const url = String(config.url || "");
        if (url.includes("certificatemanager.googleapis.com")) {
          return { data: { certificates: [] } };
        }
        if (url.includes("compute.googleapis.com")) {
          return {
            data: {
              items: {
                global: {
                  sslCertificates: [
                    {
                      name: "foo",
                      expireTime: "2030-06-01T00:00:00Z",
                      creationTimestamp: "2025-01-01T00:00:00Z",
                    },
                  ],
                },
                "regions/us-central1": {
                  sslCertificates: [
                    {
                      name: "foo",
                      expireTime: "2030-07-01T00:00:00Z",
                      creationTimestamp: "2025-01-02T00:00:00Z",
                    },
                  ],
                },
              },
            },
          };
        }
        return { data: { secrets: [] } };
      };
      const gcp = requireWithMocks(resolveServiceModule("gcpIntegration"), {
        axios: axiosMock,
      });
      const result = await gcp.scanGCP({
        projectId: "proj",
        accessToken: "token",
        include: { secrets: false, certificates: true },
      });

      const sslCertItems = result.items.filter(
        (i) => i.sourceKind === "gcp-compute-ssl-cert",
      );
      expect(sslCertItems).to.have.length(2);

      const ids = sslCertItems.map((i) => i.sourceObjectId);
      // Same bare name in two scopes must not collapse into one identity --
      // dedup keys on (scan_id, source_kind, source_object_id).
      expect(new Set(ids).size).to.equal(2);

      const globalItem = sslCertItems.find((i) => i.region === null);
      const regionalItem = sslCertItems.find(
        (i) => i.region === "us-central1",
      );
      expect(globalItem.dimensions).to.deep.equal({ location: "global" });
      expect(regionalItem.dimensions).to.deep.equal({
        location: "us-central1",
      });
      expect(globalItem.sourceObjectId).to.not.equal(
        regionalItem.sourceObjectId,
      );
    });

    it("marks the Compute SSL cert sub-scope incomplete when aggregatedList reports unreachable scopes, so cleanup does not run", async () => {
      const axiosMock = async (config) => {
        const url = String(config.url || "");
        if (url.includes("certificatemanager.googleapis.com")) {
          return { data: { certificates: [] } };
        }
        if (url.includes("compute.googleapis.com")) {
          return {
            data: {
              items: {
                global: {
                  sslCertificates: [
                    {
                      name: "global-cert",
                      expireTime: "2030-06-01T00:00:00Z",
                      creationTimestamp: "2025-01-01T00:00:00Z",
                    },
                  ],
                },
              },
              unreachables: ["regions/us-east1"],
            },
          };
        }
        return { data: { secrets: [] } };
      };
      const gcp = requireWithMocks(resolveServiceModule("gcpIntegration"), {
        axios: axiosMock,
      });
      const result = await gcp.scanGCP({
        projectId: "proj",
        accessToken: "token",
        include: { secrets: false, certificates: true },
      });

      const byKind = Object.fromEntries(
        result.summary.map((s) => [s.sourceKind, s]),
      );
      // A region aggregatedList could not enumerate is missing from items,
      // not confirmed empty -- cleanup must be skipped for this pass.
      expect(byKind["gcp-compute-ssl-cert"]).to.include({
        found: 1,
        complete: false,
        truncated: true,
      });
      expect(byKind["gcp-compute-ssl-cert"].unreachableScopes).to.deep.equal([
        "regions/us-east1",
      ]);
      // The reachable global certificate was still listed -- only the
      // sub-scope's completeness flag is affected, not the found items.
      expect(
        result.items.some(
          (i) =>
            i.sourceKind === "gcp-compute-ssl-cert" &&
            i.name === "global-cert",
        ),
      ).to.equal(true);
    });

    it("exposes unreachables from the raw aggregatedList response on listComputeSslCertificates", async () => {
      const axiosMock = async () => ({
        data: {
          items: {
            global: {
              sslCertificates: [{ name: "global-cert" }],
            },
          },
          unreachables: ["regions/us-east1", "regions/us-east1"],
        },
      });
      const gcp = requireWithMocks(resolveServiceModule("gcpIntegration"), {
        axios: axiosMock,
      });
      const result = await gcp._test.listComputeSslCertificates({
        projectId: "proj",
        accessToken: "token",
      });

      expect(result.unreachable).to.deep.equal(["regions/us-east1"]);
    });

    it("marks a cert sub-scope errored (not complete-empty) on a 404 from Certificate Manager", async () => {
      const axiosMock = async (config) => {
        const url = String(config.url || "");
        if (url.includes("certificatemanager.googleapis.com")) {
          const err = new Error("not found");
          err.response = {
            status: 404,
            data: { error: "API_NOT_ENABLED" },
          };
          throw err;
        }
        if (url.includes("compute.googleapis.com")) {
          return { data: { items: {} } };
        }
        return { data: { secrets: [] } };
      };
      const gcp = requireWithMocks(resolveServiceModule("gcpIntegration"), {
        axios: axiosMock,
      });
      const result = await gcp.scanGCP({
        projectId: "proj",
        accessToken: "token",
        include: { secrets: false, certificates: true },
      });

      const byKind = Object.fromEntries(
        result.summary.map((s) => [s.sourceKind, s]),
      );
      // A 404 must never be treated as "confirmed zero certificates" --
      // this sub-scope must be reported incomplete so cleanup skips it
      // instead of deleting every previously-imported certificate of this
      // kind.
      expect(byKind["gcp-certificate-manager-cert"]).to.include({
        complete: false,
        status: 404,
      });
      expect(
        result.items.some(
          (i) => i.sourceKind === "gcp-certificate-manager-cert",
        ),
      ).to.equal(false);
    });

    it("marks a cert sub-scope errored (not complete-empty) on a 404 from Compute SSL certificates", async () => {
      const axiosMock = async (config) => {
        const url = String(config.url || "");
        if (url.includes("certificatemanager.googleapis.com")) {
          return { data: { certificates: [] } };
        }
        if (url.includes("compute.googleapis.com")) {
          const err = new Error("not found");
          err.response = {
            status: 404,
            data: { error: "API_NOT_ENABLED" },
          };
          throw err;
        }
        return { data: { secrets: [] } };
      };
      const gcp = requireWithMocks(resolveServiceModule("gcpIntegration"), {
        axios: axiosMock,
      });
      const result = await gcp.scanGCP({
        projectId: "proj",
        accessToken: "token",
        include: { secrets: false, certificates: true },
      });

      const byKind = Object.fromEntries(
        result.summary.map((s) => [s.sourceKind, s]),
      );
      expect(byKind["gcp-compute-ssl-cert"]).to.include({
        complete: false,
        status: 404,
      });
      expect(
        result.items.some((i) => i.sourceKind === "gcp-compute-ssl-cert"),
      ).to.equal(false);
    });

    it("marks a cert kind incomplete (not complete) when the shared maxItems budget truncates it, even though its own listing wasn't truncated", async () => {
      const axiosMock = async (config) => {
        const url = String(config.url || "");
        if (url.includes("certificatemanager.googleapis.com")) {
          // Only one certificate, well within any per-kind page/pagination
          // limit -- listCertificateManagerCertificates's own `truncated`
          // must be false here. Any incompleteness must come purely from
          // scanGCP's shared items[]/maxItems budget already being spent
          // by secrets.
          return {
            data: {
              certificates: [
                {
                  name: "projects/proj/locations/global/certificates/cm-cert-1",
                  expireTime: "2030-01-01T00:00:00Z",
                },
              ],
            },
          };
        }
        if (url.includes("compute.googleapis.com")) {
          return { data: { items: {} } };
        }
        return {
          data: {
            secrets: [
              { name: "projects/proj/secrets/only-secret" },
            ],
          },
        };
      };
      const gcp = requireWithMocks(resolveServiceModule("gcpIntegration"), {
        axios: axiosMock,
      });
      // The one secret consumes the entire shared budget before the
      // certificate kinds get a turn, so the cert-manager kind is cut
      // short by the budget alone, not by its own pagination/page cap.
      const result = await gcp.scanGCP({
        projectId: "proj",
        accessToken: "token",
        include: { secrets: true, certificates: true },
        maxItems: 1,
      });

      const byKind = Object.fromEntries(
        result.summary.map((s) => [s.sourceKind, s]),
      );
      expect(result.items.length).to.equal(1);
      expect(result.items[0].sourceKind).to.equal("gcp-secret-manager");
      expect(byKind["gcp-certificate-manager-cert"]).to.include({
        found: 0,
        truncated: true,
        complete: false,
      });
    });
  });
});
