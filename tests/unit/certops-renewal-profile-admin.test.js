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
  listUpcomingRenewals,
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

/**
 * The all-clear is the dangerous answer.
 *
 * This view's only purpose is to expose certificates that will not renew
 * themselves. An earlier implementation inner-joined certificate_profiles, so
 * every certificate without a profile (the exact population at risk, since a
 * failed derivation leaves profile_id NULL) was omitted, and the page rendered
 * "nothing scheduled to renew" for a workspace where nothing renewed at all.
 * These tests exist so that failure mode cannot come back quietly.
 */
describe("CertOps upcoming renewals coverage", () => {
  function certificateRow(overrides = {}) {
    return {
      id: "22222222-0000-4000-8000-000000000001",
      common_name: "app.example.com",
      subject_alt_names: ["app.example.com"],
      not_after: new Date(Date.now() + 5 * 86400000),
      status: "active",
      key_mode: "agent-local",
      profile_id: "11111111-0000-4000-8000-000000000001",
      profile_name: "Derived: app.example.com",
      profile_status: "active",
      profile_key_mode: "agent-local",
      profile_public_metadata: { renewalProfile: storedProfile() },
      profile_renew_before_days: 30,
      renews_from: new Date(Date.now() - 86400000),
      last_renew_job_status: null,
      ...overrides,
    };
  }

  function listPool(rows) {
    const seen = [];
    return {
      seen,
      async query(sql, params = []) {
        const normalized = String(sql).replace(/\s+/g, " ").trim();
        seen.push(normalized);
        if (normalized.includes("COUNT(*)")) {
          return { rows: [{ total: rows.length }] };
        }
        return { rows };
      },
    };
  }

  async function listOne(overrides) {
    const pool = listPool([certificateRow(overrides)]);
    const result = await listUpcomingRenewals({
      db: pool,
      workspaceId: "ws-1",
      thresholdDays: 30,
    });
    return { item: result.items[0], queries: pool.seen };
  }

  it("reports a certificate with no profile instead of hiding it", async () => {
    const { item } = await listOne({
      profile_id: null,
      profile_name: null,
      profile_status: null,
      profile_public_metadata: null,
      profile_renew_before_days: null,
    });

    assert.equal(item.autoRenewEnabled, false);
    assert.equal(item.blockedReason, "no_profile");
    // Falls back to the deployment threshold so the row still shows a window.
    assert.equal(item.renewBeforeDays, 30);
  });

  it("does not join profiles in a way that can drop certificates", async () => {
    const { queries } = await listOne();
    const selects = queries.filter((sql) =>
      sql.includes("FROM managed_certificates"),
    );
    assert.ok(selects.length > 0, "expected a certificate query");
    for (const sql of selects) {
      assert.ok(
        !/(?<!LEFT )JOIN certificate_profiles/.test(sql),
        `inner join would hide unprotected certificates: ${sql}`,
      );
    }
  });

  it("counts the same population it lists", async () => {
    // A total computed over a narrower population than the page produces a
    // truncation notice that contradicts the table.
    const { queries } = await listOne();
    const countQuery = queries.find((sql) => sql.includes("COUNT(*)"));
    assert.ok(countQuery);
    assert.ok(!countQuery.includes("JOIN certificate_profiles"));
    assert.ok(countQuery.includes("status NOT IN"));
  });

  it("reports a profile the scheduler cannot execute as incomplete", async () => {
    const { item } = await listOne({
      profile_public_metadata: { renewalProfile: { schemaVersion: 1 } },
    });

    assert.equal(item.autoRenewEnabled, false);
    assert.equal(item.blockedReason, "incomplete_profile");
  });

  it("reports an empty renewalProfile body as incomplete, not as enabled", async () => {
    const { item } = await listOne({ profile_public_metadata: {} });

    assert.equal(item.autoRenewEnabled, false);
    assert.equal(item.blockedReason, "incomplete_profile");
  });

  it("prefers the operator's switch-off over an incompleteness defect", async () => {
    // Both are true here. Reporting the reversible decision is what lets the
    // operator recognise their own action instead of chasing a phantom bug.
    const { item } = await listOne({
      profile_status: "disabled",
      profile_public_metadata: {},
    });

    assert.equal(item.blockedReason, "auto_renew_disabled");
  });

  it("reports a certificate with no expiry rather than implying a schedule", async () => {
    const { item } = await listOne({ not_after: null, renews_from: null });

    assert.equal(item.autoRenewEnabled, false);
    assert.equal(item.blockedReason, "unknown_expiry");
  });

  it("marks a fully resolvable certificate as covered", async () => {
    const { item } = await listOne();

    assert.equal(item.autoRenewEnabled, true);
    assert.equal(item.blockedReason, null);
  });

  it("never returns the profile body, which carries deployment topology", async () => {
    const { item } = await listOne();

    for (const key of Object.keys(item)) {
      assert.ok(
        !/publicMetadata|renewalProfile|deploymentTargets|certPath/i.test(key),
        `unexpected topology field on the response: ${key}`,
      );
    }
    assert.equal(JSON.stringify(item).includes(CERT_PATH), false);
  });
});
