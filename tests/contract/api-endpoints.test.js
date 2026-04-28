/**
 * Contract Tests - API Endpoints
 *
 * Verify that core API endpoints match the OpenAPI specification
 */

import { describe, it } from "node:test";
import assert from "node:assert";

const API_BASE = process.env.API_URL || "http://localhost:4000";
const contractApiRequired = process.env.CONTRACT_API_REQUIRED === "1";
const inCi = process.env.CI === "true";

async function isHealthReachable() {
  try {
    const res = await fetch(`${API_BASE}/health`);
    return res.ok;
  } catch (_) {
    return false;
  }
}

/** True only when tokentimer-core apps/api is listening on the configured port. */
async function isCoreContractApiAvailable() {
  try {
    const healthRes = await fetch(`${API_BASE}/health`);
    if (!healthRes.ok) return false;
    const featuresRes = await fetch(`${API_BASE}/api/auth/features`);
    if (!featuresRes.ok) return false;
    const data = await featuresRes.json();
    return typeof data.saml === "boolean" && typeof data.oidc === "boolean";
  } catch (_) {
    return false;
  }
}

if (
  inCi &&
  process.env.CONTRACT_API_REQUIRED !== "1" &&
  process.env.CONTRACT_API_REQUIRED !== "0"
) {
  throw new Error(
    "api-endpoints contract test requires explicit CONTRACT_API_REQUIRED in CI (set to 1 for runtime contract job, 0 for static-only jobs)",
  );
}

const healthReachable = await isHealthReachable();
const coreApiAvailable = await isCoreContractApiAvailable();

if (!healthReachable && contractApiRequired) {
  throw new Error(
    `API runtime contract checks are required but ${API_BASE}/health is unavailable`,
  );
}

if (healthReachable && !coreApiAvailable && contractApiRequired) {
  let featuresStatus = "unreachable";
  try {
    const r = await fetch(`${API_BASE}/api/auth/features`);
    featuresStatus = String(r.status);
  } catch (_) {
    featuresStatus = "error";
  }
  throw new Error(
    `API runtime contract checks require tokentimer-core apps/api at API_URL (${API_BASE}). ` +
      `GET /health succeeded but GET /api/auth/features did not return core's payload ` +
      `(status ${featuresStatus}; expected 200 with saml and oidc booleans). ` +
      `Another service may be using the same port. ` +
      `Start the core API or set API_URL to the core base URL (and restart after pulling).`,
  );
}

if (!coreApiAvailable && !contractApiRequired) {
  console.log(
    `api-endpoints contract test skipped: core API not detected at ${API_BASE} ` +
      `(need GET /health and GET /api/auth/features with saml/oidc). CONTRACT_API_REQUIRED=0`,
  );
}

const describeApi = coreApiAvailable ? describe : describe.skip;

describeApi("API Contract Tests", () => {
  describe("Health Endpoint", () => {
    it("GET /health should return 200 with health payload", async () => {
      const res = await fetch(`${API_BASE}/health`);
      assert.strictEqual(res.status, 200);

      const data = await res.json();
      assert.strictEqual(data.status, "healthy");
      assert.ok(data.timestamp);
      assert.ok(typeof data.uptime === "number");
    });
  });

  describe("Session and CSRF Endpoints", () => {
    it("GET /api/csrf-token should return token payload", async () => {
      const res = await fetch(`${API_BASE}/api/csrf-token`);
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.ok(typeof data.csrfToken === "string");
      assert.ok(data.csrfToken.length > 0);
    });

    it("GET /api/session should return session payload", async () => {
      const res = await fetch(`${API_BASE}/api/session`);
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.ok(typeof data.loggedIn === "boolean");
    });
  });

  describe("Authentication Endpoints", () => {
    it("POST /auth/login should return 401 for invalid credentials", async () => {
      const res = await fetch(`${API_BASE}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: "nonexistent@example.com",
          password: "wrongpassword",
        }),
      });

      assert.strictEqual(res.status, 401);
    });

    it("GET /api/auth/features should expose auth feature flags", async () => {
      const res = await fetch(`${API_BASE}/api/auth/features`);
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.ok(typeof data.saml === "boolean");
      assert.ok(typeof data.oidc === "boolean");
    });
  });

  describe("Protected Endpoint Authentication", () => {
    it("GET /api/v1/workspaces should require auth", async () => {
      const res = await fetch(`${API_BASE}/api/v1/workspaces`);
      assert.strictEqual(res.status, 401);
    });

    it("GET /api/tokens should require auth", async () => {
      const res = await fetch(`${API_BASE}/api/tokens`);
      assert.strictEqual(res.status, 401);
    });

    it("POST /api/v1/integrations/vault/scan should require auth", async () => {
      const res = await fetch(`${API_BASE}/api/v1/integrations/vault/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          workspace_id: "00000000-0000-0000-0000-000000000000",
        }),
      });
      // Depending on middleware order and environment, unauthenticated POSTs
      // may be rejected by CSRF first (403) or auth guard first (401).
      assert.ok(
        res.status === 401 || res.status === 403,
        `Expected 401 or 403 for unauthenticated request, got ${res.status}`,
      );
    });
  });
});
