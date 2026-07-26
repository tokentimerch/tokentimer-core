"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const admin = require(
  path.resolve(
    __dirname,
    "../../apps/api/services/certops/renewalProfileAdmin.js",
  ),
);
const {
  CERTOPS_RENEWAL_PROFILE_INCOMPLETE,
  CERTOPS_RENEWAL_PROFILE_INVALID,
  RENEWAL_PROFILE_SCHEMA_VERSION,
} = require(
  path.resolve(__dirname, "../../apps/api/services/certops/renewalProfile.js"),
);

const {
  CERTOPS_PROFILE_FIELD_IMMUTABLE,
  CERTOPS_PROFILE_INVALID,
  CERTOPS_PROFILE_NOT_FOUND,
  CERTOPS_PROFILE_NO_CHANGES,
  EDITABLE_PROFILE_FIELDS,
  applyRenewalProfilePatch,
  normalizeRenewBeforeDays,
  updateRenewalProfile,
} = admin;

const CERT_PATH = "/etc/ssl/certs/app.pem";

function storedProfile(overrides = {}) {
  return {
    schemaVersion: RENEWAL_PROFILE_SCHEMA_VERSION,
    profileName: "Derived: app.example.com",
    sanPolicy: {
      mode: "exact",
      sans: ["app.example.com"],
      allowWildcards: false,
    },
    keyAlgorithm: "ecdsa",
    keySize: 256,
    keyRotationPolicy: { rotateOnRenew: true },
    preferredChain: null,
    ca: {
      endpoint: "https://acme-v02.api.letsencrypt.org/directory",
      accountRef: "le-prod",
      eabRef: null,
    },
    acme: { kind: "certbot", commandRef: "issue.dns" },
    dns: { provider: "cloudflare", zone: "example.com" },
    deploymentTargets: [
      {
        type: "domain",
        reference: "app.example.com",
        certPath: CERT_PATH,
        reloadService: "nginx",
        owner: "root",
      },
    ],
    target: {
      type: "domain",
      reference: "app.example.com",
      certPath: CERT_PATH,
    },
    verification: { host: null, port: null, requireMatch: false },
    ...overrides,
  };
}

function expectCode(fn, code) {
  try {
    fn();
  } catch (error) {
    assert.equal(error.code, code, `expected ${code}, got ${error.code}`);
    return error;
  }
  assert.fail(`expected a ${code} rejection but the call succeeded`);
}

describe("CertOps renewal-profile edit boundary", () => {
  // These are the tests that matter most in this file. Profile fields become
  // agent execution fields, so every one of these paths is a request to change
  // what runs on a host with root-ish privileges.
  it("refuses to repoint certPath, the file the agent overwrites", () => {
    const error = expectCode(
      () =>
        applyRenewalProfilePatch(storedProfile(), {
          target: {
            type: "domain",
            reference: "app.example.com",
            certPath: "/etc/shadow",
          },
        }),
      CERTOPS_PROFILE_FIELD_IMMUTABLE,
    );
    assert.deepEqual(error.details.fields, ["target"]);
  });

  it("refuses to change reloadService, the unit the agent restarts", () => {
    expectCode(
      () =>
        applyRenewalProfilePatch(storedProfile(), {
          deploymentTargets: [
            {
              type: "domain",
              reference: "app.example.com",
              certPath: CERT_PATH,
              reloadService: "sshd",
            },
          ],
        }),
      CERTOPS_PROFILE_FIELD_IMMUTABLE,
    );
  });

  it("refuses to change commandRef, the command the agent executes", () => {
    expectCode(
      () =>
        applyRenewalProfilePatch(storedProfile(), {
          acme: { kind: "certbot", commandRef: "attacker.profile" },
        }),
      CERTOPS_PROFILE_FIELD_IMMUTABLE,
    );
  });

  it("refuses to repoint the ACME CA endpoint", () => {
    expectCode(
      () =>
        applyRenewalProfilePatch(storedProfile(), {
          ca: { endpoint: "http://attacker.test/directory" },
        }),
      CERTOPS_PROFILE_FIELD_IMMUTABLE,
    );
  });

  it("refuses to change the DNS provider or zone", () => {
    expectCode(
      () =>
        applyRenewalProfilePatch(storedProfile(), {
          dns: { provider: "attacker", zone: "attacker.test" },
        }),
      CERTOPS_PROFILE_FIELD_IMMUTABLE,
    );
  });

  it("rejects unknown fields instead of silently dropping them", () => {
    // Silence would be worse than refusal: an operator who believes a setting
    // took effect and finds out at renewal is the failure mode this avoids.
    const error = expectCode(
      () => applyRenewalProfilePatch(storedProfile(), { certPath: "/tmp/x" }),
      CERTOPS_PROFILE_INVALID,
    );
    assert.deepEqual(error.details.fields, ["certPath"]);
  });

  it("applies the editable fields and leaves every host field untouched", () => {
    const result = applyRenewalProfilePatch(storedProfile(), {
      sanPolicy: {
        mode: "exact",
        sans: ["app.example.com", "www.example.com"],
        allowWildcards: false,
      },
      keyAlgorithm: "rsa",
      keySize: 2048,
      keyRotationPolicy: { rotateOnRenew: false },
      verification: { host: "app.example.com", port: 443, requireMatch: true },
      preferredChain: "ISRG Root X1",
    });

    assert.deepEqual(result.sanPolicy.sans, [
      "app.example.com",
      "www.example.com",
    ]);
    assert.equal(result.keyAlgorithm, "rsa");
    assert.equal(result.keySize, 2048);
    assert.equal(result.keyRotationPolicy.rotateOnRenew, false);
    assert.equal(result.verification.requireMatch, true);
    assert.equal(result.preferredChain, "ISRG Root X1");

    assert.equal(result.target.certPath, CERT_PATH);
    assert.equal(result.deploymentTargets[0].certPath, CERT_PATH);
    assert.equal(result.deploymentTargets[0].reloadService, "nginx");
    assert.equal(result.deploymentTargets[0].owner, "root");
    assert.equal(result.acme.commandRef, "issue.dns");
    assert.equal(
      result.ca.endpoint,
      "https://acme-v02.api.letsencrypt.org/directory",
    );
    assert.equal(result.dns.provider, "cloudflare");
  });

  it("validates the merged result, not just the patched fields", () => {
    // requireMatch true with no host is valid in isolation for each field but
    // invalid as a profile, so a per-field check would let it through.
    expectCode(
      () =>
        applyRenewalProfilePatch(storedProfile(), {
          verification: { host: null, port: null, requireMatch: true },
        }),
      CERTOPS_RENEWAL_PROFILE_INCOMPLETE,
    );
  });

  it("rejects a key size that does not match the key algorithm", () => {
    expectCode(
      () => applyRenewalProfilePatch(storedProfile(), { keySize: 4096 }),
      CERTOPS_RENEWAL_PROFILE_INVALID,
    );
  });

  it("rejects wildcard SANs unless wildcards are allowed", () => {
    expectCode(
      () =>
        applyRenewalProfilePatch(storedProfile(), {
          sanPolicy: {
            mode: "exact",
            sans: ["*.example.com"],
            allowWildcards: false,
          },
        }),
      CERTOPS_RENEWAL_PROFILE_INVALID,
    );
  });

  it("refuses to edit a profile that carries no renewal configuration", () => {
    expectCode(
      () => applyRenewalProfilePatch(null, { keySize: 256 }),
      CERTOPS_PROFILE_INVALID,
    );
  });

  it("keeps the editable set to fields that cannot affect the host", () => {
    // A guard against future drift: adding a host-affecting field here would
    // silently turn this API into a remote-write primitive.
    assert.deepEqual(EDITABLE_PROFILE_FIELDS, [
      "sanPolicy",
      "keyAlgorithm",
      "keySize",
      "keyRotationPolicy",
      "verification",
      "preferredChain",
    ]);
  });
});

describe("CertOps renewal-profile threshold validation", () => {
  it("accepts a lead time inside the supported range", () => {
    assert.equal(normalizeRenewBeforeDays(1), 1);
    assert.equal(normalizeRenewBeforeDays(30), 30);
    assert.equal(normalizeRenewBeforeDays("45"), 45);
    assert.equal(normalizeRenewBeforeDays(365), 365);
  });

  it("treats null as falling back to the deployment default", () => {
    assert.equal(normalizeRenewBeforeDays(null), null);
  });

  it("rejects zero, negatives, fractions and out-of-range values", () => {
    // Zero would mean "renew on the expiry date", indistinguishable from a
    // typo, and the scheduler reads null as "use the deployment default".
    // Fractions and trailing garbage must not be silently truncated into a
    // different lead time than the operator typed.
    for (const value of [0, -1, 366, 10000, "abc", 1.5, "30days", "", true]) {
      expectCode(
        () => normalizeRenewBeforeDays(value),
        CERTOPS_PROFILE_INVALID,
      );
    }
  });
});

function createUpdatePool({
  row,
  auditFails = false,
  captured = {},
} = {}) {
  captured.queries = [];
  captured.audits = [];
  captured.released = false;
  const client = {
    async query(sql, params = []) {
      const normalized = String(sql).replace(/\s+/g, " ").trim();
      captured.queries.push({ sql: normalized, params });
      if (/^(BEGIN|COMMIT|ROLLBACK)$/.test(normalized)) return { rows: [] };
      if (normalized.startsWith("SELECT id, name, status")) {
        return { rows: row ? [row] : [] };
      }
      if (normalized.startsWith("UPDATE certificate_profiles")) {
        return { rows: [{ id: row.id }] };
      }
      return { rows: [] };
    },
    release() {
      captured.released = true;
    },
  };
  return {
    captured,
    async connect() {
      return client;
    },
    async query(sql, params = []) {
      // The post-commit re-read goes through the pool.
      captured.queries.push({
        sql: String(sql).replace(/\s+/g, " ").trim(),
        params,
      });
      return { rows: row ? [row] : [] };
    },
    auditWriter: async (event) => {
      captured.audits.push(event);
      if (auditFails) throw new Error("audit write failed");
    },
  };
}

function profileRow(overrides = {}) {
  return {
    id: "11111111-0000-4000-8000-000000000001",
    name: "Derived: app.example.com",
    status: "active",
    renew_before_days: 30,
    description: "derived",
    public_metadata: { renewalProfile: storedProfile() },
    source: "api",
    key_mode: "agent-local",
    certificate_count: 1,
    created_at: null,
    updated_at: null,
    ...overrides,
  };
}

describe("CertOps renewal-profile update transaction", () => {
  it("audits the change inside the same transaction as the write", async () => {
    const pool = createUpdatePool({ row: profileRow() });

    await updateRenewalProfile({
      dbPool: pool,
      workspaceId: "ws-1",
      profileId: "11111111-0000-4000-8000-000000000001",
      autoRenewEnabled: false,
      actorUserId: 7,
      auditWriter: pool.auditWriter,
    });

    const audit = pool.captured.audits[0];
    assert.equal(audit.action, "CERTOPS_RENEWAL_PROFILE_UPDATED");
    assert.equal(audit.actorUserId, 7);
    assert.deepEqual(audit.metadata.changes.status, {
      from: "active",
      to: "disabled",
    });
    // Sharing the transaction client is what makes the audit non-optional.
    assert.ok(audit.client, "audit must run on the transaction client");

    const order = pool.captured.queries.map((q) => q.sql);
    assert.equal(order[0], "BEGIN");
    assert.ok(order.includes("COMMIT"));
    assert.ok(pool.captured.released);
  });

  it("rolls the profile change back when its audit cannot be written", async () => {
    const pool = createUpdatePool({ row: profileRow(), auditFails: true });

    await assert.rejects(
      updateRenewalProfile({
        dbPool: pool,
        workspaceId: "ws-1",
        profileId: "11111111-0000-4000-8000-000000000001",
        autoRenewEnabled: false,
        auditWriter: pool.auditWriter,
      }),
      /audit write failed/,
    );

    const order = pool.captured.queries.map((q) => q.sql);
    assert.ok(order.includes("ROLLBACK"));
    assert.ok(!order.includes("COMMIT"));
  });

  it("locks the profile row before deciding what to change", async () => {
    const pool = createUpdatePool({ row: profileRow() });

    await updateRenewalProfile({
      dbPool: pool,
      workspaceId: "ws-1",
      profileId: "11111111-0000-4000-8000-000000000001",
      renewBeforeDays: 45,
      auditWriter: pool.auditWriter,
    });

    const select = pool.captured.queries.find((q) =>
      q.sql.startsWith("SELECT id, name, status"),
    );
    assert.match(select.sql, /FOR UPDATE/);
  });

  it("refuses a patch that would change nothing", async () => {
    const pool = createUpdatePool({ row: profileRow() });

    await assert.rejects(
      updateRenewalProfile({
        dbPool: pool,
        workspaceId: "ws-1",
        profileId: "11111111-0000-4000-8000-000000000001",
        auditWriter: pool.auditWriter,
      }),
      (error) => error.code === CERTOPS_PROFILE_NO_CHANGES,
    );
    assert.equal(pool.captured.audits.length, 0);
  });

  it("reports a missing profile as not found rather than failing opaquely", async () => {
    const pool = createUpdatePool({ row: null });

    await assert.rejects(
      updateRenewalProfile({
        dbPool: pool,
        workspaceId: "ws-1",
        profileId: "11111111-0000-4000-8000-000000000001",
        autoRenewEnabled: false,
        auditWriter: pool.auditWriter,
      }),
      (error) => error.code === CERTOPS_PROFILE_NOT_FOUND,
    );
  });

  it("does not resurrect an archived profile through the on/off toggle", async () => {
    // 'archived' is outside the two statuses this endpoint owns, so an
    // unrelated toggle must not quietly move a profile back into service.
    const pool = createUpdatePool({ row: profileRow({ status: "archived" }) });

    await assert.rejects(
      updateRenewalProfile({
        dbPool: pool,
        workspaceId: "ws-1",
        profileId: "11111111-0000-4000-8000-000000000001",
        autoRenewEnabled: true,
        auditWriter: pool.auditWriter,
      }),
      (error) => error.code === CERTOPS_PROFILE_INVALID,
    );
  });

  it("rejects a non-boolean on/off value", async () => {
    const pool = createUpdatePool({ row: profileRow() });

    await assert.rejects(
      updateRenewalProfile({
        dbPool: pool,
        workspaceId: "ws-1",
        profileId: "11111111-0000-4000-8000-000000000001",
        autoRenewEnabled: "false",
        auditWriter: pool.auditWriter,
      }),
      (error) => error.code === CERTOPS_PROFILE_INVALID,
    );
  });
});
