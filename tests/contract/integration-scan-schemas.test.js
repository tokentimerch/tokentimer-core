import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const Ajv = require("ajv");
const addFormats = require("ajv-formats");
const yaml = createRequire(require.resolve("mocha/package.json"))("js-yaml");
const spec = yaml.load(
  fs.readFileSync(
    new URL("../../packages/contracts/openapi/openapi.yaml", import.meta.url),
    "utf8",
  ),
);
const schemas = spec.components.schemas;

function validator(name) {
  const ajv = new Ajv({ allErrors: true, strict: false });
  addFormats(ajv);
  return ajv.compile({
    components: { schemas },
    $ref: `#/components/schemas/${name}`,
  });
}

const rule = {
  action: "exclude",
  matchType: "regex",
  field: "location",
  value: "^azure-ad:servicePrincipals/",
};

describe("Integration scan request contracts", () => {
  const requests = [
    ["AwsScanRequest", { accessKeyId: "id", secretAccessKey: "secret" }],
    [
      "AzureKeyVaultBearerScanRequest",
      { vaultUrl: "https://example.vault.azure.net", token: "token" },
    ],
    [
      "AzureKeyVaultClientCredentialsScanRequest",
      {
        vaultUrl: "https://example.vault.azure.net",
        authMethod: "client_credentials",
        tenantId: "tenant",
        clientId: "client",
        clientSecret: "secret",
      },
    ],
    ["AzureAdBearerScanRequest", { token: "token" }],
    [
      "AzureAdClientCredentialsScanRequest",
      {
        authMethod: "client_credentials",
        tenantId: "tenant",
        clientId: "client",
        clientSecret: "secret",
      },
    ],
    ["GcpScanRequest", { projectId: "project", accessToken: "token" }],
  ];

  for (const [name, credentials] of requests) {
    it(`${name} accepts shared filters and rejects invalid rule shapes`, () => {
      const validate = validator(name);
      assert.equal(validate({ ...credentials, filterRules: [rule] }), true);
      for (const invalid of [
        { ...rule, action: "drop" },
        { ...rule, matchType: "contains" },
        { ...rule, field: "servicePrincipalType" },
        { ...rule, value: "" },
        { ...rule, value: "x".repeat(501) },
      ]) {
        assert.equal(
          validate({ ...credentials, filterRules: [invalid] }),
          false,
        );
      }
      assert.equal(
        validate({ ...credentials, filterRules: Array(51).fill(rule) }),
        false,
      );
    });
  }

  it("wires AWS scanning to its provider-specific request", () => {
    assert.equal(
      spec.paths["/api/v1/integrations/aws/scan"].post.requestBody.content[
        "application/json"
      ].schema.$ref,
      "#/components/schemas/AwsScanRequest",
    );
  });

  for (const [name, credentials] of requests.filter(([name]) =>
    name.startsWith("AzureAd"),
  )) {
    it(`${name} supports all managed identity modes with all as the default`, () => {
      const validate = validator(name);
      const omitted = { ...credentials };
      assert.equal(validate(omitted), true);
      assert.equal(
        schemas[name].properties.managedIdentityMode.$ref,
        "#/components/schemas/EntraManagedIdentityMode",
      );
      assert.equal(schemas.EntraManagedIdentityMode.default, "all");
      for (const mode of ["all", "exclude", "only"]) {
        const request = {
          ...credentials,
          managedIdentityMode: mode,
          include: { applications: true, servicePrincipals: false },
        };
        assert.equal(validate(request), true);
      }
      for (const mode of ["managed", "", null, true]) {
        assert.equal(
          validate({ ...credentials, managedIdentityMode: mode }),
          false,
        );
      }
    });
  }

  it("publishes filter and identity settings for both saved-config writes", () => {
    for (const [endpoint, method] of [
      ["/api/v1/workspaces/{id}/auto-sync", "post"],
      ["/api/v1/workspaces/{id}/auto-sync/{configId}", "put"],
    ]) {
      const params =
        spec.paths[endpoint][method].requestBody.content["application/json"]
          .schema.properties.scan_params;
      assert.equal(params.$ref, "#/components/schemas/AutoSyncScanParams");
    }
    const validate = validator("AutoSyncScanParams");
    const settings = { filterRules: [rule] };
    assert.equal(validate(settings), true);
    assert.equal(
      schemas.AutoSyncScanParams.properties.managedIdentityMode.$ref,
      "#/components/schemas/EntraManagedIdentityMode",
    );
    assert.equal(
      validate({ managedIdentityMode: "only", filterRules: [rule] }),
      true,
    );
    assert.equal(validate({ managedIdentityMode: "unknown" }), false);
  });

  it("publishes optional normalized Entra identity metadata on scan items", () => {
    const validate = validator("IntegrationScanResponse");
    const location = "azure-ad:managedIdentities/app/certificates/key";
    const item = {
      location,
      servicePrincipalType: "ManagedIdentity",
      identityType: "managedIdentity",
      isManagedIdentity: true,
      legacyLocation: "azure-ad:servicePrincipals/app/certificates/key",
    };
    assert.equal(validate({ items: [item] }), true);
    assert.equal(validate({ items: [{ name: "non-Entra item" }] }), true);
    assert.equal(
      validate({
        items: [
          {
            ...item,
            servicePrincipalType: null,
            identityType: "servicePrincipal",
            isManagedIdentity: false,
          },
        ],
      }),
      true,
    );
    assert.equal(
      validate({ items: [{ ...item, identityType: "systemAssigned" }] }),
      false,
    );
  });
});
