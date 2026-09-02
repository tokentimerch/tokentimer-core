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
  OPERATOR_OWNED_METADATA_KEY,
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

  it("takes ownership on the first real edit so the change survives a re-derivation", async () => {
    const pool = createUpdatePool({ row: profileRow() });

    await updateRenewalProfile({
      dbPool: pool,
      workspaceId: "ws-1",
      profileId: "11111111-0000-4000-8000-000000000001",
      renewBeforeDays: 45,
      auditWriter: pool.auditWriter,
    });

    const update = pool.captured.queries.find((q) =>
      q.sql.startsWith("UPDATE certificate_profiles"),
    );
    const metadata = JSON.parse(update.params[5]);
    // The marker lives beside renewalProfile in public_metadata, not in
    // certificate_profiles.source, whose CHECK has no value for a derived row.
    assert.equal(metadata[OPERATOR_OWNED_METADATA_KEY], true);
    assert.ok(metadata.renewalProfile, "the edited body must be preserved");
    assert.equal(pool.captured.audits[0].metadata.changes.operatorOwned, true);
  });

  it("does not take ownership through a patch that changes nothing", async () => {
    const pool = createUpdatePool({ row: profileRow() });

    await assert.rejects(
      () =>
        updateRenewalProfile({
          dbPool: pool,
          workspaceId: "ws-1",
          profileId: "11111111-0000-4000-8000-000000000001",
          renewBeforeDays: 30,
          auditWriter: pool.auditWriter,
        }),
      (error) => {
        assert.equal(error.code, CERTOPS_PROFILE_NO_CHANGES);
        return true;
      },
    );

    assert.equal(
      pool.captured.queries.filter((q) =>
        q.sql.startsWith("UPDATE certificate_profiles"),
      ).length,
      0,
      "a no-op request must not quietly claim the profile",
    );
  });

  it("leaves an already-owned profile's marker alone", async () => {
    const pool = createUpdatePool({
      row: profileRow({
        public_metadata: {
          renewalProfile: storedProfile(),
          [OPERATOR_OWNED_METADATA_KEY]: true,
        },
      }),
    });

    await updateRenewalProfile({
      dbPool: pool,
      workspaceId: "ws-1",
      profileId: "11111111-0000-4000-8000-000000000001",
      renewBeforeDays: 45,
      auditWriter: pool.auditWriter,
    });

    const metadata = JSON.parse(
      pool.captured.queries.find((q) =>
        q.sql.startsWith("UPDATE certificate_profiles"),
      ).params[5],
    );
    assert.equal(metadata[OPERATOR_OWNED_METADATA_KEY], true);
    assert.equal(
      pool.captured.audits[0].metadata.changes.operatorOwned,
      undefined,
      "ownership is only reported the first time it is claimed",
    );
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

  function listPool(rows, { inFlightRows = [] } = {}) {
    const seen = [];
    const calls = [];
    return {
      seen,
      calls,
      async query(sql, params = []) {
        const normalized = String(sql).replace(/\s+/g, " ").trim();
        seen.push(normalized);
        calls.push({ sql: normalized, params });
        // Checked before the generic COUNT(*) branch: the total-count query
        // is also a COUNT(*) query, so ordering here matters, same as the
        // scheduler's own mock pool dispatch.
        if (normalized.includes("AS in_flight")) {
          return { rows: inFlightRows };
        }
        if (normalized.includes("COUNT(*)")) {
          return { rows: [{ total: rows.length }] };
        }
        return { rows };
      },
    };
  }

  async function listOne(overrides, { inFlightRows } = {}) {
    const pool = listPool([certificateRow(overrides)], { inFlightRows });
    const result = await listUpcomingRenewals({
      db: pool,
      workspaceId: "ws-1",
      thresholdDays: 30,
    });
    return { item: result.items[0], queries: pool.seen, calls: pool.calls };
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

  it("returns the shared nested envelope alongside the flat fields", async () => {
    // Flat fields stay while shipped clients read them; the nested object is
    // the envelope every other CertOps list returns.
    const pool = listPool([certificateRow()]);
    const result = await listUpcomingRenewals({
      db: pool,
      workspaceId: "ws-1",
      thresholdDays: 30,
      limit: 10,
      offset: 0,
    });

    assert.deepEqual(result.pagination, { limit: 10, offset: 0, total: 1 });
    assert.equal(result.total, result.pagination.total);
    assert.equal(result.limit, result.pagination.limit);
    assert.equal(result.offset, result.pagination.offset);
  });

  it("returns the same nested envelope from the profile list", async () => {
    const profiles = {
      async query(sql) {
        if (String(sql).includes("COUNT(*)")) {
          return { rows: [{ total: 7 }] };
        }
        return { rows: [] };
      },
    };

    const result = await admin.listRenewalProfiles({
      db: profiles,
      workspaceId: "ws-1",
      limit: 2,
      offset: 4,
    });

    assert.deepEqual(result.pagination, { limit: 2, offset: 4, total: 7 });
    assert.equal(result.total, 7);
    assert.equal(result.limit, 2);
    assert.equal(result.offset, 4);
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

  // Key custody is the one blocker the sweep does not express in SQL: the row
  // survives findCertificatesDueForRenewal and is refused later, at job
  // creation, as skipped_not_agent_deployable. So a certificate with a valid
  // profile and no agent-manageable key looked covered here while never
  // renewing. These four cases pin the predicate to the one job creation uses.
  it("reports an observed-only certificate as not agent-deployable", async () => {
    // key_mode NULL is an endpoint or domain monitor: there is no key anywhere
    // for an agent to rotate, so no profile can make this renewable.
    const { item } = await listOne({ key_mode: null });

    assert.equal(item.autoRenewEnabled, false);
    assert.equal(item.blockedReason, "not_agent_deployable");
  });

  it("reports an externally held key as not agent-deployable", async () => {
    // external-unknown is the schema's value for "a key exists but not here".
    const { item } = await listOne({ key_mode: "external-unknown" });

    assert.equal(item.autoRenewEnabled, false);
    assert.equal(item.blockedReason, "not_agent_deployable");
  });

  it("reports every non-agent custody mode the schema allows", async () => {
    // managed_certificates_key_mode_check permits these, and none of them put a
    // key on an agent's filesystem. Enumerated explicitly so adding a custody
    // mode to the schema without deciding its renewal story fails here.
    for (const keyMode of [
      "cert-manager-managed",
      "appliance-managed",
      "hsm-managed",
      "vault-managed",
      "external-unknown",
    ]) {
      const { item } = await listOne({ key_mode: keyMode });
      assert.equal(
        item.blockedReason,
        "not_agent_deployable",
        `${keyMode} should not be reported as renewable`,
      );
    }
  });

  it("treats agent-local custody as renewable", async () => {
    const { item } = await listOne({ key_mode: "agent-local" });

    assert.equal(item.autoRenewEnabled, true);
    assert.equal(item.blockedReason, null);
  });

  it("treats os-store-managed custody as renewable now that the Windows executor exists", async () => {
    // Historically stayed not_agent_deployable pending the real Windows
    // store/site/binding execution path; that executor now exists
    // (packages/agent/src/index.js's executeWindowsIisRenewJob), so
    // os-store-managed is reported renewable like other agent-managed modes.
    const { item } = await listOne({ key_mode: "os-store-managed" });

    assert.equal(item.autoRenewEnabled, true);
    assert.equal(item.blockedReason, null);
  });

  it("treats proxy-agent-local custody as renewable", async () => {
    const { item } = await listOne({ key_mode: "proxy-agent-local" });

    assert.equal(item.autoRenewEnabled, true);
    assert.equal(item.blockedReason, null);
  });

  it("uses the same custody predicate as job creation", async () => {
    // A second copy of the key-mode list would drift silently, and the drift
    // shows up as this view promising a renewal the scheduler refuses.
    const { isAgentDeployableKeyMode } = require(
      path.resolve(__dirname, "../../apps/api/services/certops/jobs.js"),
    );
    for (const keyMode of [
      null,
      "external-unknown",
      "vault-managed",
      "os-store-managed",
      "agent-local",
      "proxy-agent-local",
    ]) {
      const { item } = await listOne({ key_mode: keyMode });
      assert.equal(
        item.blockedReason === "not_agent_deployable",
        !isAgentDeployableKeyMode(keyMode),
        `custody verdict diverged for key_mode=${keyMode}`,
      );
    }
  });

  it("reports custody before profile completeness", async () => {
    // Both are wrong here. Custody is the one that cannot be fixed by
    // re-issuing a profile, so naming it first points at the real remedy.
    const { item } = await listOne({
      key_mode: null,
      profile_id: null,
      profile_public_metadata: null,
    });

    assert.equal(item.blockedReason, "not_agent_deployable");
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

  // deferredReason is a live-derived signal, independent of blockedReason: a
  // certificate that is otherwise fully covered can still be waiting because
  // the scheduler would skip it this pass for lack of CA capacity. These
  // cases pin exactly which rows qualify, mirroring the guards the sweep
  // itself applies before it would create a job.
  it("marks a due, fully-resolvable certificate as deferred when its CA is at the per-CA cap", async () => {
    const { item } = await listOne(
      {
        certificate_ca_endpoint: "https://ca-a.example.com/acme",
        profile_ca_endpoint: "https://ca-a.example.com/acme",
      },
      {
        inFlightRows: [
          {
            workspace_id: "ws-1",
            ca_endpoint: "https://ca-a.example.com/acme",
            in_flight: 5,
          },
        ],
      },
    );

    assert.equal(item.deferredReason, "ca_capacity");
    assert.equal(item.autoRenewEnabled, true);
    assert.equal(item.blockedReason, null);
  });

  it("does not mark a certificate deferred when its CA still has headroom", async () => {
    const { item } = await listOne(
      {
        certificate_ca_endpoint: "https://ca-a.example.com/acme",
        profile_ca_endpoint: "https://ca-a.example.com/acme",
      },
      {
        inFlightRows: [
          {
            workspace_id: "ws-1",
            ca_endpoint: "https://ca-a.example.com/acme",
            in_flight: 4,
          },
        ],
      },
    );

    assert.equal(item.deferredReason, null);
  });

  it("does not mark a certificate deferred when it is not yet in its renewal window", async () => {
    const { item } = await listOne(
      {
        certificate_ca_endpoint: "https://ca-a.example.com/acme",
        profile_ca_endpoint: "https://ca-a.example.com/acme",
        renews_from: new Date(Date.now() + 86400000),
      },
      {
        inFlightRows: [
          {
            workspace_id: "ws-1",
            ca_endpoint: "https://ca-a.example.com/acme",
            in_flight: 5,
          },
        ],
      },
    );

    assert.equal(item.deferredReason, null);
  });

  it("does not mark a certificate deferred when it already has a non-terminal renew job", async () => {
    const { item } = await listOne(
      {
        certificate_ca_endpoint: "https://ca-a.example.com/acme",
        profile_ca_endpoint: "https://ca-a.example.com/acme",
        last_renew_job_status: "pending",
      },
      {
        inFlightRows: [
          {
            workspace_id: "ws-1",
            ca_endpoint: "https://ca-a.example.com/acme",
            in_flight: 5,
          },
        ],
      },
    );

    assert.equal(item.deferredReason, null);
  });

  it("prefers a real block reason over a capacity deferral", async () => {
    const { item } = await listOne(
      {
        certificate_ca_endpoint: "https://ca-a.example.com/acme",
        profile_ca_endpoint: "https://ca-a.example.com/acme",
        profile_public_metadata: { renewalProfile: { schemaVersion: 1 } },
      },
      {
        inFlightRows: [
          {
            workspace_id: "ws-1",
            ca_endpoint: "https://ca-a.example.com/acme",
            in_flight: 5,
          },
        ],
      },
    );

    assert.equal(item.blockedReason, "incomplete_profile");
    assert.equal(item.deferredReason, null);
  });

  it("scopes the in-flight count to the requesting workspace", async () => {
    const { calls } = await listOne();
    const inFlightCall = calls.find((call) =>
      call.sql.includes("AS in_flight"),
    );

    assert.ok(inFlightCall, "expected an in-flight count query");
    assert.ok(inFlightCall.sql.includes("workspace_id = $2"));
    assert.ok(Array.isArray(inFlightCall.params[0]));
    assert.equal(inFlightCall.params[1], "ws-1");
  });

  it("buckets an unresolvable caEndpoint into the shared unknown bucket for deferral, same as the scheduler", async () => {
    const { item } = await listOne(
      {
        certificate_ca_endpoint: null,
        profile_ca_endpoint: null,
      },
      {
        inFlightRows: [
          { workspace_id: "ws-1", ca_endpoint: null, in_flight: 5 },
        ],
      },
    );

    assert.equal(item.deferredReason, "ca_capacity");
  });
});
