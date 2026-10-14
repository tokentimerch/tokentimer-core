"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

const {
  createAdcsRenewalProfile,
} = require("../../apps/api/services/certops/renewalProfileAdmin");

const WORKSPACE = "11111111-1111-4111-8111-111111111111";
const ISSUER = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";

function poolFrom(handler) {
  const client = {
    async query(sql, params) {
      return handler(sql, params);
    },
    release() {},
  };
  return {
    async connect() {
      return client;
    },
    async query(sql, params) {
      return handler(sql, params);
    },
  };
}

const body = {
  name: "web auto",
  issuerId: ISSUER,
  template: "WebServer",
  target: {
    type: "windows-iis",
    reference: "www.example.com",
    store: "My",
    binding: { site: "Default Web Site", port: 443 },
  },
  keyAlgorithm: "rsa",
  keySize: 2048,
};

describe("createAdcsRenewalProfile", () => {
  it("refuses an issuer that is not a confirmed AD CS issuer", async () => {
    const db = poolFrom(async (sql) => {
      if (sql.includes("FROM certificate_issuers i")) {
        return {
          rows: [{ kind: "acme", revalidation_required: false, ca_key_sha256: "ab" }],
        };
      }
      return { rows: [] };
    });
    await assert.rejects(
      () =>
        createAdcsRenewalProfile({
          dbPool: db,
          workspaceId: WORKSPACE,
          body,
          auditWriter: async () => {},
        }),
      (error) => error.code === "CERTOPS_PROFILE_ISSUER_NOT_FOUND",
    );
  });

  it("stores the windows-iis contract and ignores a template override", async () => {
    let stored = null;
    const db = poolFrom(async (sql, params) => {
      if (sql === "BEGIN" || sql === "COMMIT") return { rows: [] };
      if (sql.includes("FROM certificate_issuers i")) {
        return {
          rows: [
            {
              kind: "adcs",
              revalidation_required: false,
              current_version: 1,
              ca_key_sha256: "ab".repeat(32),
            },
          ],
        };
      }
      if (sql.includes("INSERT INTO certificate_profiles")) {
        stored = params[6];
        return { rows: [{ id: "profile-1" }] };
      }
      if (sql.includes("FROM certops_agents")) return { rows: [] };
      if (sql.includes("WHERE cp.workspace_id")) {
        return {
          rows: [
            {
              id: "profile-1",
              name: "web auto",
              description: null,
              status: "active",
              source: "manual",
              public_metadata: stored,
            },
          ],
        };
      }
      return { rows: [] };
    });

    const created = await createAdcsRenewalProfile({
      dbPool: db,
      workspaceId: WORKSPACE,
      body,
      auditWriter: async () => {},
    });
    const metadata = JSON.parse(stored);
    assert.equal(metadata.renewalProfile.target.reference, "www.example.com");
    assert.equal(Object.hasOwn(metadata.renewalProfile, "template"), false);
    assert.equal(created.agentDeclaresName, false);
    assert.equal(created.id, "profile-1");
  });

  it("refuses an AD CS issuer that has no pinned CA certificate", async () => {
    const db = poolFrom(async (sql) => {
      if (sql.includes("FROM certificate_issuers i")) {
        return {
          rows: [
            {
              kind: "adcs",
              revalidation_required: false,
              current_version: 0,
              ca_key_sha256: null,
            },
          ],
        };
      }
      return { rows: [] };
    });
    await assert.rejects(
      () =>
        createAdcsRenewalProfile({
          dbPool: db,
          workspaceId: WORKSPACE,
          body,
          auditWriter: async () => {},
        }),
      (error) =>
        error.code === "CERTOPS_PROFILE_INVALID" &&
        /Confirm a CA certificate/.test(error.message),
    );
  });

  it("refuses a key size the algorithm does not allow", async () => {
    await assert.rejects(
      () =>
        createAdcsRenewalProfile({
          dbPool: poolFrom(async () => {
            throw new Error("key size is rejected before a query");
          }),
          workspaceId: WORKSPACE,
          body: { ...body, keySize: 1024 },
          auditWriter: async () => {},
        }),
      (error) =>
        error.code === "CERTOPS_PROFILE_INVALID" &&
        error.message === "keySize is invalid for rsa",
    );
  });

  it("refuses a profile name that already exists", async () => {
    const db = poolFrom(async (sql) => {
      if (sql === "BEGIN" || sql === "ROLLBACK") return { rows: [] };
      if (sql.includes("FROM certificate_issuers i")) {
        return {
          rows: [
            {
              kind: "adcs",
              revalidation_required: false,
              current_version: 1,
              ca_key_sha256: "ab".repeat(32),
            },
          ],
        };
      }
      if (sql.includes("INSERT INTO certificate_profiles")) {
        const error = new Error("duplicate key");
        error.code = "23505";
        throw error;
      }
      return { rows: [] };
    });
    await assert.rejects(
      () =>
        createAdcsRenewalProfile({
          dbPool: db,
          workspaceId: WORKSPACE,
          body,
          auditWriter: async () => {},
        }),
      (error) =>
        error.code === "CERTOPS_PROFILE_INVALID" &&
        error.message === "A renewal profile with this name already exists",
    );
  });
});
