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
});
