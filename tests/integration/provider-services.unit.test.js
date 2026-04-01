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

describe("Provider service unit coverage", () => {
  describe("AWS integration", () => {
    it("validates required credentials", async () => {
      const aws = require(resolveServiceModule("awsIntegration"));
      await expectReject(
        () => aws.scanAWS({ accessKeyId: "", secretAccessKey: "" }),
        /required/,
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
      expect(result).to.deep.equal([]);
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
      let call = 0;
      const axiosMock = async () => {
        call += 1;
        if (call === 1) {
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
      expect(apps.map((a) => a.id)).to.deep.equal(["app-1", "app-2"]);
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
      expect(secrets).to.deep.equal([]);
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
  });
});
