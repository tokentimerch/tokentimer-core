"use strict";

const { formatDateYmd } = require("./integrationUtils");
const { logger } = require("../utils/logger");

// AWS regions list (for region detection)
const ALL_AWS_REGIONS = [
  "us-east-1",
  "us-east-2",
  "us-west-1",
  "us-west-2",
  "af-south-1",
  "ap-east-1",
  "ap-south-1",
  "ap-south-2",
  "ap-northeast-1",
  "ap-northeast-2",
  "ap-northeast-3",
  "ap-southeast-1",
  "ap-southeast-2",
  "ap-southeast-3",
  "ap-southeast-4",
  "ca-central-1",
  "eu-central-1",
  "eu-central-2",
  "eu-west-1",
  "eu-west-2",
  "eu-west-3",
  "eu-south-1",
  "eu-south-2",
  "eu-north-1",
  "me-south-1",
  "me-central-1",
  "sa-east-1",
];

// AWS integration using AWS SDK
// Note: Requires AWS SDK packages: @aws-sdk/client-secrets-manager and @aws-sdk/client-iam
async function scanAWS({
  accessKeyId,
  secretAccessKey,
  sessionToken = null,
  region = "us-east-1",
  include = { secrets: true, iam: true, certificates: true },
  maxItems = 500,
}) {
  if (!accessKeyId || !secretAccessKey) {
    throw new Error("accessKeyId and secretAccessKey are required");
  }

  if (!region) {
    throw new Error("region is required");
  }

  // Validate inputs
  if (typeof accessKeyId !== "string" || accessKeyId.length > 200) {
    throw new Error("Invalid accessKeyId format");
  }
  if (typeof secretAccessKey !== "string" || secretAccessKey.length > 200) {
    throw new Error("Invalid secretAccessKey format");
  }
  if (
    sessionToken &&
    (typeof sessionToken !== "string" || sessionToken.length > 2000)
  ) {
    throw new Error("Invalid sessionToken format");
  }
  if (typeof region !== "string" || region.length > 50) {
    throw new Error("Invalid region format");
  }
  if (!Number.isInteger(maxItems) || maxItems < 1 || maxItems > 2000) {
    throw new Error("maxItems must be between 1 and 2000");
  }

  // Single region scan only
  return await scanAWSSingleRegion({
    accessKeyId,
    secretAccessKey,
    sessionToken,
    region,
    include,
    maxItems,
  });
}

// Internal function to scan a single AWS region
async function scanAWSSingleRegion({
  accessKeyId,
  secretAccessKey,
  sessionToken = null,
  region,
  include = { secrets: true, iam: true, certificates: true },
  maxItems = 500,
}) {
  logger.info("Starting AWS scan", {
    region,
    maxItems,
    includeSecrets: include.secrets,
    includeIAM: include.iam,
    includeCertificates: include.certificates,
    includeFlags: include,
  });

  const items = [];
  const summary = [];

  // Try to use AWS SDK if available
  let SecretsManagerClient, ListSecretsCommand, DescribeSecretCommand;
  let IAMClient,
    ListUsersCommand,
    ListAccessKeysCommand,
    GetAccessKeyLastUsedCommand;
  let ACMClient, ListCertificatesCommand, DescribeCertificateCommand;

  try {
    const secretsManagerModule = require("@aws-sdk/client-secrets-manager");
    SecretsManagerClient = secretsManagerModule.SecretsManagerClient;
    ListSecretsCommand = secretsManagerModule.ListSecretsCommand;
    DescribeSecretCommand = secretsManagerModule.DescribeSecretCommand;
  } catch (e) {
    logger.warn("AWS SDK for Secrets Manager not available", {
      error: e.message,
    });
    summary.push({
      type: "secrets_manager",
      note: "AWS SDK required. Install @aws-sdk/client-secrets-manager for full support.",
    });
  }

  try {
    const iamModule = require("@aws-sdk/client-iam");
    IAMClient = iamModule.IAMClient;
    ListUsersCommand = iamModule.ListUsersCommand;
    ListAccessKeysCommand = iamModule.ListAccessKeysCommand;
    GetAccessKeyLastUsedCommand = iamModule.GetAccessKeyLastUsedCommand;
  } catch (e) {
    logger.warn("AWS SDK for IAM not available", { error: e.message });
    summary.push({
      type: "iam_keys",
      note: "AWS SDK required. Install @aws-sdk/client-iam for full support.",
    });
  }

  try {
    const acmModule = require("@aws-sdk/client-acm");
    ACMClient = acmModule.ACMClient;
    ListCertificatesCommand = acmModule.ListCertificatesCommand;
    DescribeCertificateCommand = acmModule.DescribeCertificateCommand;
  } catch (e) {
    logger.warn("AWS SDK for ACM not available", { error: e.message });
    summary.push({
      type: "acm_certificates",
      note: "AWS SDK required. Install @aws-sdk/client-acm for full support.",
    });
  }

  // For Secrets Manager
  if (include.secrets && SecretsManagerClient) {
    try {
      const client = new SecretsManagerClient({
        region,
        credentials: { accessKeyId, secretAccessKey, sessionToken },
        requestHandler: {
          requestTimeout: 120000, // 120 second timeout (increased for up to 2000 items)
        },
      });
      logger.info("Listing AWS Secrets Manager secrets", { region });
      const listResponse = await client.send(new ListSecretsCommand({}));
      const secrets = listResponse.SecretList || [];
      logger.info("AWS Secrets Manager list response", {
        region,
        totalSecretsFound: secrets.length,
        maxItems,
      });

      let describedCount = 0;
      let failedCount = 0;
      const BATCH_SIZE = 10;

      for (let i = 0; i < secrets.slice(0, maxItems).length; i += BATCH_SIZE) {
        const batch = secrets.slice(i, Math.min(i + BATCH_SIZE, maxItems));

        await Promise.all(
          batch.map(async (secret) => {
            try {
              const desc = await client.send(
                new DescribeSecretCommand({ SecretId: secret.ARN }),
              );
              const expiresAt =
                desc.DeletedDate || desc.NextRotationDate || null;
              items.push({
                source: "aws-secrets-manager",
                name: secret.Name || secret.ARN,
                category: "key_secret",
                type: "secret",
                expiration: expiresAt ? formatDateYmd(expiresAt) : null,
                location: `aws:secretsmanager:${region}:${secret.ARN}`,
                description: secret.Description || null,
                created_at: secret.CreatedDate
                  ? new Date(secret.CreatedDate).toISOString()
                  : null,
                updated_at: secret.LastChangedDate
                  ? new Date(secret.LastChangedDate).toISOString()
                  : null,
                last_used_at: desc.LastAccessedDate
                  ? new Date(desc.LastAccessedDate).toISOString()
                  : null,
              });
              describedCount++;
            } catch (e) {
              failedCount++;
              logger.warn("Failed to describe AWS secret", {
                secretName: secret.Name,
                secretArn: secret.ARN,
                error: e.message,
                errorCode: e.code,
              });
              // Skip secrets we can't describe
            }
          }),
        );
      }

      const secretsCount = items.filter(
        (item) => item.source === "aws-secrets-manager",
      ).length;
      summary.push({ type: "secrets_manager", found: secretsCount });
      logger.info("AWS Secrets Manager scan completed", {
        found: secretsCount,
        described: describedCount,
        failed: failedCount,
        region,
      });
    } catch (e) {
      logger.error("AWS Secrets Manager scan failed", {
        error: e.message,
        errorCode: e.code,
        errorName: e.name,
        region,
      });
      summary.push({ type: "secrets_manager", error: e.message });
    }
  }

  // For ACM Certificates
  if (include.certificates && ACMClient) {
    try {
      const client = new ACMClient({
        region,
        credentials: { accessKeyId, secretAccessKey, sessionToken },
        requestHandler: {
          requestTimeout: 120000, // 120 second timeout (increased for up to 2000 items)
        },
      });
      logger.info("Listing AWS ACM certificates", { region });
      // ACM has a hard limit of 1000 for MaxItems
      const acmMaxItems = Math.min(maxItems, 1000);
      const listResponse = await client.send(
        new ListCertificatesCommand({ MaxItems: acmMaxItems }),
      );
      const certificates = listResponse.CertificateSummaryList || [];
      logger.info("AWS ACM list response", {
        region,
        totalCertificatesFound: certificates.length,
      });

      let describedCount = 0;
      let failedCount = 0;
      const BATCH_SIZE = 10;

      for (
        let i = 0;
        i < certificates.slice(0, maxItems).length;
        i += BATCH_SIZE
      ) {
        const batch = certificates.slice(i, Math.min(i + BATCH_SIZE, maxItems));

        await Promise.all(
          batch.map(async (cert) => {
            try {
              const desc = await client.send(
                new DescribeCertificateCommand({
                  CertificateArn: cert.CertificateArn,
                }),
              );
              const certificate = desc.Certificate;

              // Build domain list (primary + SANs)
              const domainList = [certificate.DomainName];
              if (certificate.SubjectAlternativeNames) {
                certificate.SubjectAlternativeNames.forEach((san) => {
                  if (
                    san !== certificate.DomainName &&
                    !domainList.includes(san)
                  ) {
                    domainList.push(san);
                  }
                });
              }

              items.push({
                source: "aws-acm",
                name: certificate.DomainName,
                category: "cert",
                type: "ssl_cert",
                expiration: certificate.NotAfter
                  ? formatDateYmd(certificate.NotAfter)
                  : null,
                location: `aws:acm:${region}:${cert.CertificateArn}`,
                domains: domainList, // Keep as array for proper import
                issuer: certificate.Issuer || "Amazon",
                serial_number: certificate.Serial || null,
                subject:
                  certificate.Subject?.CommonName || certificate.DomainName,
                created_at: certificate.CreatedAt
                  ? new Date(certificate.CreatedAt).toISOString()
                  : null,
                issued_at: certificate.IssuedAt
                  ? new Date(certificate.IssuedAt).toISOString()
                  : null,
                // Store status and in_use in notes/description since they're not standard fields
                description: `Status: ${certificate.Status || "Unknown"}. In use: ${certificate.InUseBy && certificate.InUseBy.length > 0 ? "Yes" : "No"}`,
              });
              describedCount++;
            } catch (e) {
              failedCount++;
              logger.warn("Failed to describe AWS certificate", {
                certificateArn: cert.CertificateArn,
                error: e.message,
                errorCode: e.code,
              });
              // Skip certificates we can't describe
            }
          }),
        );
      }

      const certsCount = items.filter(
        (item) => item.source === "aws-acm",
      ).length;
      summary.push({ type: "acm_certificates", found: certsCount });
      logger.info("AWS ACM scan completed", {
        found: certsCount,
        described: describedCount,
        failed: failedCount,
        region,
      });
    } catch (e) {
      logger.error("AWS ACM scan failed", {
        error: e.message,
        errorCode: e.code,
        errorName: e.name,
        region,
      });
      summary.push({ type: "acm_certificates", error: e.message });
    }
  }

  // For IAM Access Keys
  logger.info("AWS IAM scan check", {
    includeIAM: include.iam,
    hasIAMClient: !!IAMClient,
  });
  if (include.iam && IAMClient) {
    logger.info("Starting AWS IAM access keys scan", { region });
    try {
      const client = new IAMClient({
        region,
        credentials: { accessKeyId, secretAccessKey, sessionToken },
        requestHandler: {
          requestTimeout: 120000, // 120 second timeout (increased for up to 2000 items)
        },
      });
      const usersResponse = await client.send(new ListUsersCommand({}));
      const users = usersResponse.Users || [];
      let iamKeysCount = 0;
      const BATCH_SIZE = 10;

      // Scan IAM keys independently of items from other services
      // Apply maxItems limit per-service to ensure each service gets fair representation
      for (let i = 0; i < users.length; i += BATCH_SIZE) {
        if (iamKeysCount >= maxItems) break;
        const batch = users.slice(i, i + BATCH_SIZE);

        await Promise.all(
          batch.map(async (user) => {
            if (iamKeysCount >= maxItems) return;
            try {
              const keysResponse = await client.send(
                new ListAccessKeysCommand({ UserName: user.UserName }),
              );
              const keys = keysResponse.AccessKeyMetadata || [];

              for (const key of keys) {
                if (iamKeysCount >= maxItems) break;

                // Fetch last used information for this access key
                let lastUsedAt = null;
                try {
                  if (GetAccessKeyLastUsedCommand) {
                    const lastUsedResponse = await client.send(
                      new GetAccessKeyLastUsedCommand({
                        AccessKeyId: key.AccessKeyId,
                      }),
                    );
                    if (lastUsedResponse.AccessKeyLastUsed?.LastUsedDate) {
                      lastUsedAt = new Date(
                        lastUsedResponse.AccessKeyLastUsed.LastUsedDate,
                      ).toISOString();
                    }
                  }
                } catch (e) {
                  // Ignore errors fetching last used date
                  logger.debug("Failed to fetch last used date for IAM key", {
                    accessKeyId: key.AccessKeyId,
                    error: e.message,
                  });
                }

                items.push({
                  source: "aws-iam-key",
                  name: `${user.UserName}/${key.AccessKeyId}`,
                  category: "key_secret",
                  type: "api_key",
                  expiration: null, // IAM access keys don't have expiration dates in metadata
                  location: `aws:iam:${region}:${user.UserName}/${key.AccessKeyId}`,
                  user_name: user.UserName,
                  status: key.Status || null,
                  created_at: key.CreateDate
                    ? new Date(key.CreateDate).toISOString()
                    : null,
                  last_used_at: lastUsedAt,
                });
                iamKeysCount++;
              }
            } catch (e) {
              logger.warn("Failed to list IAM keys for user", {
                userName: user.UserName,
                error: e.message,
              });
              // Skip users we can't list keys for
            }
          }),
        );
      }
      summary.push({ type: "iam_keys", found: iamKeysCount });
      logger.info("AWS IAM scan completed", { found: iamKeysCount });
    } catch (e) {
      logger.error("AWS IAM scan failed", { error: e.message, region });
      summary.push({ type: "iam_keys", error: e.message });
    }
  }

  logger.info("AWS scan completed", { itemsFound: items.length, region });
  return { items, summary };
}

// Detect which AWS regions have secrets (lightweight scan)
async function detectAWSRegions({
  accessKeyId,
  secretAccessKey,
  sessionToken = null,
}) {
  if (!accessKeyId || !secretAccessKey) {
    throw new Error("accessKeyId and secretAccessKey are required");
  }

  // Validate inputs
  if (typeof accessKeyId !== "string" || accessKeyId.length > 200) {
    throw new Error("Invalid accessKeyId format");
  }
  if (typeof secretAccessKey !== "string" || secretAccessKey.length > 200) {
    throw new Error("Invalid secretAccessKey format");
  }
  if (
    sessionToken &&
    (typeof sessionToken !== "string" || sessionToken.length > 2000)
  ) {
    throw new Error("Invalid sessionToken format");
  }

  logger.info("Starting AWS region detection", {
    totalRegions: ALL_AWS_REGIONS.length,
  });

  // Try to load AWS SDK
  let SecretsManagerClient, ListSecretsCommand;
  let IAMClient, ListUsersCommand, ListAccessKeysCommand;
  let ACMClient, ListCertificatesCommand;
  let STSClient, GetCallerIdentityCommand;

  try {
    const secretsManagerModule = require("@aws-sdk/client-secrets-manager");
    SecretsManagerClient = secretsManagerModule.SecretsManagerClient;
    ListSecretsCommand = secretsManagerModule.ListSecretsCommand;
  } catch (_e) {
    throw new Error(
      "AWS SDK required. Install @aws-sdk/client-secrets-manager",
    );
  }

  try {
    const iamModule = require("@aws-sdk/client-iam");
    IAMClient = iamModule.IAMClient;
    ListUsersCommand = iamModule.ListUsersCommand;
    ListAccessKeysCommand = iamModule.ListAccessKeysCommand;
  } catch (e) {
    logger.warn("AWS SDK for IAM not available", { error: e.message });
  }

  try {
    const acmModule = require("@aws-sdk/client-acm");
    ACMClient = acmModule.ACMClient;
    ListCertificatesCommand = acmModule.ListCertificatesCommand;
  } catch (e) {
    logger.warn("AWS SDK for ACM not available", { error: e.message });
  }

  try {
    const stsModule = require("@aws-sdk/client-sts");
    STSClient = stsModule.STSClient;
    GetCallerIdentityCommand = stsModule.GetCallerIdentityCommand;
  } catch (e) {
    logger.warn("AWS SDK for STS not available", { error: e.message });
  }

  const regionsWithSecrets = [];
  const regionsWithCertificates = [];
  const results = [];
  let iamKeysCount = 0;
  let iamUsersCount = 0;

  // First, validate credentials using STS GetCallerIdentity
  // This is the standard AWS way to validate credentials - works with any valid credentials
  // and doesn't require any specific permissions
  if (STSClient && GetCallerIdentityCommand) {
    try {
      const stsClient = new STSClient({
        region: "us-east-1",
        credentials: { accessKeyId, secretAccessKey, sessionToken },
        requestHandler: {
          requestTimeout: 10000,
        },
      });
      const identity = await stsClient.send(new GetCallerIdentityCommand({}));
      logger.info("AWS credentials validated", {
        account: identity.Account,
        arn: identity.Arn,
      });
    } catch (_e) {
      // Any error from GetCallerIdentity means invalid credentials
      const authErr = new Error(
        "AWS authentication failed: Invalid credentials. The Access Key ID or Secret Access Key is incorrect or does not exist.\n\nPlease verify:\n• Access Key ID is correct\n• Secret Access Key is correct\n• Credentials are not expired\n• Using the right AWS account",
      );
      authErr.code = "INVALID_CREDENTIALS";
      authErr.status = 401;
      throw authErr;
    }
  } else {
    // Fallback: Try ListSecrets in us-east-1 if STS SDK not available
    try {
      const testClient = new SecretsManagerClient({
        region: "us-east-1",
        credentials: { accessKeyId, secretAccessKey, sessionToken },
        requestHandler: {
          requestTimeout: 10000,
        },
      });
      await testClient.send(new ListSecretsCommand({ MaxResults: 1 }));
      logger.info("AWS credentials validated (via Secrets Manager)");
    } catch (e) {
      // Only throw on clear authentication errors (invalid credentials)
      // Don't throw on permission errors (AccessDenied, etc.) as those are 403, not 401
      if (
        e.name === "InvalidClientTokenId" ||
        e.name === "SignatureDoesNotMatch" ||
        e.name === "UnrecognizedClientException" ||
        e.message?.includes("InvalidClientTokenId") ||
        e.message?.includes("SignatureDoesNotMatch") ||
        e.message?.includes("UnrecognizedClientException")
      ) {
        // Throw auth errors immediately
        const authErr = new Error(
          "AWS authentication failed: Invalid credentials. The Access Key ID or Secret Access Key is incorrect or does not exist.\n\nPlease verify:\n• Access Key ID is correct\n• Secret Access Key is correct\n• Credentials are not expired\n• Using the right AWS account",
        );
        authErr.code = "INVALID_CREDENTIALS";
        authErr.status = 401;
        throw authErr;
      }
      // For permission errors (AccessDenied) or other errors (region not enabled),
      // continue with region detection - user has valid credentials but may lack permissions
      logger.info("AWS credentials validated (with limited permissions)");
    }
  }

  // Check each region in parallel (with concurrency limit)
  const checkRegion = async (region) => {
    let secretCount = 0;
    let certCount = 0;

    // Check Secrets Manager
    try {
      const client = new SecretsManagerClient({
        region,
        credentials: { accessKeyId, secretAccessKey, sessionToken },
        requestHandler: {
          requestTimeout: 10000, // 10 second timeout for quick detection
        },
      });

      // Just list secrets, don't describe them
      const listResponse = await client.send(
        new ListSecretsCommand({ MaxResults: 1 }),
      );
      secretCount = listResponse.SecretList?.length || 0;

      if (secretCount > 0) {
        regionsWithSecrets.push(region);
      }
    } catch (e) {
      // Don't throw errors during region scanning - credentials were already validated
      // Region might not be enabled, lacks permissions, or has other issues
      // Just log and continue to other regions
      logger.debug("AWS region Secrets Manager check failed", {
        region,
        error: e.message,
        errorName: e.name,
      });
    }

    // Check ACM Certificates
    if (ACMClient) {
      try {
        const client = new ACMClient({
          region,
          credentials: { accessKeyId, secretAccessKey, sessionToken },
          requestHandler: {
            requestTimeout: 10000, // 10 second timeout for quick detection
          },
        });

        // Just list certificates, don't describe them
        const listResponse = await client.send(
          new ListCertificatesCommand({ MaxItems: 1 }),
        );
        certCount = listResponse.CertificateSummaryList?.length || 0;

        if (certCount > 0) {
          regionsWithCertificates.push(region);
        }
      } catch (e) {
        // Don't throw errors during region scanning - credentials were already validated
        // Region might not be enabled, lacks permissions, or has other issues
        // Just log and continue to other regions
        logger.debug("AWS region ACM check failed", {
          region,
          error: e.message,
          errorName: e.name,
        });
      }
    }

    // Record results
    if (secretCount > 0 || certCount > 0) {
      results.push({
        region,
        hasSecrets: secretCount > 0,
        hasCertificates: certCount > 0,
        secretCount,
        certCount,
      });
      logger.info("AWS region has resources", {
        region,
        secrets: secretCount,
        certificates: certCount,
      });
    } else {
      results.push({ region, hasSecrets: false, hasCertificates: false });
    }
  };

  // Process regions in batches to avoid overwhelming the API
  const batchSize = 10; // Increased from 5 to speed up detection
  for (let i = 0; i < ALL_AWS_REGIONS.length; i += batchSize) {
    const batch = ALL_AWS_REGIONS.slice(i, i + batchSize);
    await Promise.all(batch.map((region) => checkRegion(region)));
  }

  // Check for IAM users and keys (global - only need to check once)
  if (IAMClient) {
    try {
      logger.info("Checking for IAM users and access keys (global)");
      const client = new IAMClient({
        region: "us-east-1", // IAM is global, but we need to specify a region for the client
        credentials: { accessKeyId, secretAccessKey, sessionToken },
        requestHandler: {
          requestTimeout: 10000, // 10 second timeout
        },
      });

      const usersResponse = await client.send(
        new ListUsersCommand({ MaxItems: 100 }),
      );
      const users = usersResponse.Users || [];
      iamUsersCount = users.length;

      // Count total access keys across all users (limit to first 100 users for quick detection)
      for (const user of users.slice(0, 100)) {
        try {
          const keysResponse = await client.send(
            new ListAccessKeysCommand({ UserName: user.UserName }),
          );
          const keys = keysResponse.AccessKeyMetadata || [];
          iamKeysCount += keys.length;
        } catch (e) {
          logger.debug("Failed to list keys for IAM user", {
            userName: user.UserName,
            error: e.message,
          });
        }
      }

      logger.info("IAM detection completed", {
        users: iamUsersCount,
        keys: iamKeysCount,
      });
    } catch (e) {
      // Don't throw errors during region scanning - credentials were already validated
      // IAM might lack permissions or have other issues
      // Just log and continue
      logger.warn("Failed to check IAM users", {
        error: e.message,
        errorName: e.name,
      });
    }
  }

  logger.info("AWS region detection completed", {
    totalRegions: ALL_AWS_REGIONS.length,
    regionsWithSecrets: regionsWithSecrets.length,
    regionsWithCertificates: regionsWithCertificates.length,
    iamUsers: iamUsersCount,
    iamKeys: iamKeysCount,
  });

  // Only return regions with resources in allResults to reduce response size
  const relevantResults = results.filter(
    (r) => r.hasSecrets || r.hasCertificates || r.error,
  );

  return {
    regionsWithSecrets: regionsWithSecrets.sort(),
    regionsWithCertificates: regionsWithCertificates.sort(),
    allResults: relevantResults, // Only regions with resources or errors
    iam: {
      usersCount: iamUsersCount,
      keysCount: iamKeysCount,
      available: IAMClient ? true : false,
    },
    acm: {
      available: ACMClient ? true : false,
    },
  };
}

module.exports = {
  scanAWS,
  detectAWSRegions,
};

// Test-only exports for unit coverage (when AWS SDK is available)
if (process.env.NODE_ENV === "test") {
  module.exports._test = {
    // AWS SDK-dependent functions would be exported here if needed for testing
  };
}
