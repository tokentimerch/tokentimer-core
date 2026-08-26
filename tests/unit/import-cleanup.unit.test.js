"use strict";

/**
 * Unit tests for importCleanup validation and scope patterns.
 * DB-dependent deletion behavior is covered by integration tests.
 * Only the pure exports are exercised here; requiring the module creates a
 * pg Pool but never connects.
 */

const { describe, it } = require("node:test");
const assert = require("node:assert");
const {
  validateCleanupRequest,
  SOURCE_LOCATION_PATTERNS,
  PROVIDER_PREFIXES,
} = require("../../apps/api/services/importCleanup");

describe("importCleanup.validateCleanupRequest", () => {
  it("accepts undefined/null (cleanup not requested)", () => {
    assert.strictEqual(validateCleanupRequest(undefined), null);
    assert.strictEqual(validateCleanupRequest(null), null);
  });

  it("rejects non-object payloads", () => {
    assert.match(validateCleanupRequest("yes"), /must be an object/);
    assert.match(validateCleanupRequest([1]), /must be an object/);
  });

  it("ignores payloads with enabled !== true", () => {
    assert.strictEqual(validateCleanupRequest({ enabled: false }), null);
    assert.strictEqual(validateCleanupRequest({}), null);
  });

  it("requires a known provider when enabled", () => {
    assert.match(
      validateCleanupRequest({ enabled: true, provider: "bitbucket" }),
      /provider must be one of/,
    );
  });

  it("requires non-empty scannedSources with known kinds", () => {
    assert.match(
      validateCleanupRequest({
        enabled: true,
        provider: "gitlab",
        scannedSources: [],
      }),
      /non-empty array/,
    );
    assert.match(
      validateCleanupRequest({
        enabled: true,
        provider: "gitlab",
        scannedSources: ["gitlab-unknown"],
      }),
      /unknown source kind/,
    );
  });

  it("requires scannedLocations array", () => {
    assert.match(
      validateCleanupRequest({
        enabled: true,
        provider: "gitlab",
        scannedSources: ["gitlab-pat"],
        scannedLocations: "gitlab:x",
      }),
      /must be an array/,
    );
  });

  it("accepts a valid payload", () => {
    assert.strictEqual(
      validateCleanupRequest({
        enabled: true,
        provider: "gitlab",
        scannedSources: ["gitlab-pat", "gitlab-deploy-token"],
        scannedLocations: ["gitlab:personal_access_tokens/1"],
      }),
      null,
    );
  });

  it("accepts valid payloads for every non-git provider", () => {
    const validByProvider = {
      vault: ["vault-kv", "vault-pki"],
      aws: ["aws-secrets-manager", "aws-acm", "aws-iam-key"],
      azure: [
        "azure-key-vault-secret",
        "azure-key-vault-certificate",
        "azure-key-vault-key",
      ],
      "azure-ad": [
        "azure-ad-client-secret",
        "azure-ad-certificate",
        "azure-ad-sp-secret",
        "azure-ad-sp-certificate",
      ],
      gcp: ["gcp-secret-manager"],
    };
    for (const [provider, scannedSources] of Object.entries(
      validByProvider,
    )) {
      assert.strictEqual(
        validateCleanupRequest({
          enabled: true,
          provider,
          scannedSources,
          scannedLocations: [],
        }),
        null,
        `${provider} should accept its own source kinds`,
      );
    }
  });
});

describe("importCleanup.SOURCE_LOCATION_PATTERNS", () => {
  it("gitlab-pat matches both PAT location shapes", () => {
    const p = SOURCE_LOCATION_PATTERNS["gitlab-pat"];
    assert.strictEqual(p.test("gitlab:personal_access_tokens/42"), true);
    assert.strictEqual(
      p.test("gitlab:users/alice/personal_access_tokens/42"),
      true,
    );
    assert.strictEqual(p.test("gitlab:projects/7/access_tokens/42"), false);
  });

  it("gitlab token type patterns are mutually exclusive", () => {
    const samples = {
      "gitlab-project-token": "gitlab:projects/7/access_tokens/1",
      "gitlab-group-token": "gitlab:groups/3/access_tokens/1",
      "gitlab-deploy-token": "gitlab:projects/7/deploy_tokens/1",
      "gitlab-trigger-token": "gitlab:projects/7/triggers/1",
      "gitlab-ssh-key": "gitlab:user/keys/1",
    };
    for (const [kind, location] of Object.entries(samples)) {
      assert.strictEqual(
        SOURCE_LOCATION_PATTERNS[kind].test(location),
        true,
        `${kind} should match ${location}`,
      );
      for (const [otherKind, pattern] of Object.entries(
        SOURCE_LOCATION_PATTERNS,
      )) {
        if (otherKind === kind || !otherKind.startsWith("gitlab-")) continue;
        assert.strictEqual(
          pattern.test(location),
          false,
          `${otherKind} should not match ${location}`,
        );
      }
    }
  });

  it("github patterns match the integration location shapes", () => {
    assert.strictEqual(
      SOURCE_LOCATION_PATTERNS["github-ssh-key"].test("github:user/keys/9"),
      true,
    );
    assert.strictEqual(
      SOURCE_LOCATION_PATTERNS["github-secret"].test(
        "github:repos/org/repo/actions/secrets/MY_SECRET",
      ),
      true,
    );
    assert.strictEqual(
      SOURCE_LOCATION_PATTERNS["github-deploy-key"].test(
        "github:repos/org/repo/keys/12",
      ),
      true,
    );
  });

  it("vault-kv and vault-pki are mutually exclusive", () => {
    const kvLocation = "vault:secret/data/myapp/apikey";
    const pkiLocation = "vault:pki/cert/39:dd:7a:1b";

    assert.strictEqual(
      SOURCE_LOCATION_PATTERNS["vault-kv"].test(kvLocation),
      true,
    );
    assert.strictEqual(
      SOURCE_LOCATION_PATTERNS["vault-pki"].test(kvLocation),
      false,
    );
    assert.strictEqual(
      SOURCE_LOCATION_PATTERNS["vault-pki"].test(pkiLocation),
      true,
    );
    assert.strictEqual(
      SOURCE_LOCATION_PATTERNS["vault-kv"].test(pkiLocation),
      false,
    );
  });

  it("aws source patterns are scoped by kind, not region", () => {
    assert.strictEqual(
      SOURCE_LOCATION_PATTERNS["aws-secrets-manager"].test(
        "aws:secretsmanager:us-east-1:arn:aws:secretsmanager:us-east-1:123:secret:foo",
      ),
      true,
    );
    assert.strictEqual(
      SOURCE_LOCATION_PATTERNS["aws-acm"].test(
        "aws:acm:eu-west-1:arn:aws:acm:eu-west-1:123:certificate/abc",
      ),
      true,
    );
    assert.strictEqual(
      SOURCE_LOCATION_PATTERNS["aws-iam-key"].test(
        "aws:iam:us-east-1:someuser/AKIAEXAMPLE",
      ),
      true,
    );
    assert.strictEqual(
      SOURCE_LOCATION_PATTERNS["aws-iam-key"].test(
        "aws:secretsmanager:us-east-1:arn:...",
      ),
      false,
    );
  });

  it("azure key vault patterns distinguish secrets/certificates/keys", () => {
    const secret = "azure:https://my-vault.vault.azure.net/secrets/foo";
    const cert = "azure:https://my-vault.vault.azure.net/certificates/foo";
    const key = "azure:https://my-vault.vault.azure.net/keys/foo";

    assert.strictEqual(
      SOURCE_LOCATION_PATTERNS["azure-key-vault-secret"].test(secret),
      true,
    );
    assert.strictEqual(
      SOURCE_LOCATION_PATTERNS["azure-key-vault-certificate"].test(cert),
      true,
    );
    assert.strictEqual(
      SOURCE_LOCATION_PATTERNS["azure-key-vault-key"].test(key),
      true,
    );
    assert.strictEqual(
      SOURCE_LOCATION_PATTERNS["azure-key-vault-secret"].test(cert),
      false,
    );
  });

  it("azure-ad patterns distinguish apps/service-principals and secrets/certs", () => {
    const appSecret = "azure-ad:applications/app-1/secrets/key-1";
    const appCert = "azure-ad:applications/app-1/certificates/key-1";
    const spSecret = "azure-ad:servicePrincipals/sp-1/secrets/key-1";
    const spCert = "azure-ad:servicePrincipals/sp-1/certificates/key-1";

    assert.strictEqual(
      SOURCE_LOCATION_PATTERNS["azure-ad-client-secret"].test(appSecret),
      true,
    );
    assert.strictEqual(
      SOURCE_LOCATION_PATTERNS["azure-ad-certificate"].test(appCert),
      true,
    );
    assert.strictEqual(
      SOURCE_LOCATION_PATTERNS["azure-ad-sp-secret"].test(spSecret),
      true,
    );
    assert.strictEqual(
      SOURCE_LOCATION_PATTERNS["azure-ad-sp-certificate"].test(spCert),
      true,
    );
    assert.strictEqual(
      SOURCE_LOCATION_PATTERNS["azure-ad-client-secret"].test(spSecret),
      false,
    );
  });

  it("gcp-secret-manager matches Secret Manager locations", () => {
    assert.strictEqual(
      SOURCE_LOCATION_PATTERNS["gcp-secret-manager"].test(
        "gcp:my-project-123/secrets/foo",
      ),
      true,
    );
    assert.strictEqual(
      SOURCE_LOCATION_PATTERNS["gcp-secret-manager"].test(
        "gcp:my-project-123/other/foo",
      ),
      false,
    );
  });

  it("every provider prefix has a colon suffix", () => {
    for (const prefix of Object.values(PROVIDER_PREFIXES)) {
      assert.strictEqual(prefix.endsWith(":"), true);
    }
  });
});
