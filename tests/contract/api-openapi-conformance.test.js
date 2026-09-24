import { describe, it } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..", "..");
const openApiPath = path.join(
  repoRoot,
  "packages/contracts/openapi/openapi.yaml",
);
const authCompatPath = path.join(
  repoRoot,
  "packages/contracts/api/auth-route-compat.contract.json",
);

describe("API OpenAPI conformance contract", () => {
  it("allows nullable persisted notification messages", () => {
    const yaml = fs.readFileSync(openApiPath, "utf8");
    const start = yaml.indexOf("  /api/v1/workspaces/{id}/notifications:");
    const end = yaml.indexOf(
      "  /api/v1/workspaces/{id}/notifications/{notificationId}/read:",
      start,
    );
    assert.ok(start >= 0 && end > start);
    assert.match(
      yaml.slice(start, end),
      /\n\s+message:\s*\n\s+type: string\s*\n\s+nullable: true/,
    );
  });

  it("defines required core and integration paths in static OpenAPI", () => {
    const yaml = fs.readFileSync(openApiPath, "utf8");
    const requiredPaths = [
      "/health:",
      "/api/auth/features:",
      "/api/session:",
      "/api/csrf-token:",
      "/auth/login:",
      "/auth/verify-2fa:",
      "/api/v1/integrations/vault/scan:",
      "/api/v1/integrations/vault/import:",
      "/api/v1/integrations/github/scan:",
      "/api/v1/integrations/gitlab/scan:",
      "/api/v1/integrations/aws/scan:",
      "/api/v1/integrations/azure/scan:",
      "/api/v1/integrations/azure-ad/scan:",
      "/api/v1/integrations/gcp/scan:",
    ];

    for (const marker of requiredPaths) {
      assert.ok(
        yaml.includes(marker),
        `OpenAPI is missing required path marker: ${marker}`,
      );
    }
  });

  it("keeps auth-route-compat contract aligned with static OpenAPI", () => {
    const yaml = fs.readFileSync(openApiPath, "utf8");
    const authCompat = JSON.parse(fs.readFileSync(authCompatPath, "utf8"));
    const stableRoutes = authCompat?.guarantees?.stableRoutes || [];
    assert.ok(stableRoutes.length > 0, "stableRoutes must be non-empty");

    for (const route of stableRoutes) {
      assert.ok(route.path, "each stable route requires path");
      const marker = `${route.path}:`;
      assert.ok(
        yaml.includes(marker),
        `auth-route-compat contains path missing in OpenAPI: ${route.path}`,
      );
    }
  });

  it("VaultScanRequest oneOf forbids mixed token and AppRole fields", () => {
    const yaml = fs.readFileSync(openApiPath, "utf8");
    const start = yaml.indexOf("    VaultScanRequest:");
    assert.ok(start >= 0, "VaultScanRequest schema is missing");
    const next = yaml.indexOf("\n    VaultMountsRequest:", start);
    const block = yaml.slice(start, next > start ? next : start + 4000);
    assert.match(block, /oneOf:/);
    assert.match(block, /required: \[token\]/);
    assert.match(block, /required: \[roleId, secretId\]/);
    assert.match(block, /required: \[roleId\]/);
    assert.match(block, /required: \[secretId\]/);
    assert.match(block, /required: \[authMount\]/);
    assert.match(block, /minLength: 1/);
    assert.match(block, /not:\s*\n\s+required: \[token\]/);
  });
});
