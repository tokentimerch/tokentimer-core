"use strict";

/**
 * Audit coverage for the CertOps issuance and unattended-renewal lifecycle.
 *
 * These events exist because the trail for a certificate TokenTimer issued used
 * to consist of exactly one row (CERTOPS_JOB_CREATED_MANUAL, from the request
 * that started it) even though the system had since ordered a certificate from a
 * CA, written it to a host, activated it, and granted itself standing authority
 * to repeat that indefinitely. A scheduled renewal produced no row at all.
 *
 * Every assertion below is about one of two properties:
 *
 * 1. The event is emitted for the state change it claims to describe.
 * 2. It is written on the SAME transaction client as that state change, so a
 *    certificate cannot become active, and a renewal profile cannot come into
 *    existence, while their audit row rolls back.
 *
 * Property 2 is why these tests route the real writeAudit through a mock client
 * instead of injecting a stub writer: a stub would still pass if the production
 * code had used the connection pool directly.
 */

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const dispatch = require(
  path.resolve(__dirname, "../../apps/api/services/certops/agentDispatch.js"),
);
const { ensureDerivedRenewalProfile } = require(
  path.resolve(
    __dirname,
    "../../apps/api/services/certops/renewalProfileDerivation.js",
  ),
);
const { runRenewalSchedulerSweep } = require(
  path.resolve(__dirname, "../../apps/api/services/certops/renewalScheduler.js"),
);

const WORKSPACE = "11111111-1111-4111-8111-111111111111";
const CERT_ID = "22222222-2222-4222-8222-222222222222";
const PROFILE_ID = "33333333-3333-4333-8333-333333333333";

const VERIFY_METADATA = {
  step: "verify",
  fingerprintSha256: "a".repeat(64),
  serialNumber: "04AABB",
  subject: "CN=web-01.example.com",
  issuer: "CN=Staging Fake LE",
  validFrom: "Jul 26 10:00:00 2026 GMT",
  validTo: "Oct 24 10:00:00 2026 GMT",
  subjectAltNames: "web-01.example.com,alt.example.com",
};

/**
 * One client standing in for the reconciliation transaction. Audit inserts are
 * recorded through the real writeAudit, which is the point: if production code
 * ever writes an audit row off the pool instead of this client, the row simply
 * will not appear here.
 */
function reconcileClient({ metadata = VERIFY_METADATA } = {}) {
  const audits = [];
  const client = {
    query: async (text, params) => {
      const sql = typeof text === "string" ? text : text?.text || "";
      if (sql.includes("INSERT INTO audit_events")) {
        audits.push({
          actorUserId: params[0],
          subjectUserId: params[1],
          action: params[2],
          targetType: params[3],
          targetId: params[4],
          metadata: params[6],
          workspaceId: params[7],
        });
        return { rows: [] };
      }
      if (sql.includes("FROM managed_certificates")) {
        return {
          rows: [
            {
              id: CERT_ID,
              source: "agent_issuance",
              common_name: "web-01.example.com",
              deployed_cert_path: "/etc/ssl/certs/web-01.pem",
              token_id: null,
            },
          ],
        };
      }
      if (sql.includes("FROM certificate_evidence")) {
        return { rows: metadata ? [{ metadata }] : [] };
      }
      if (sql.includes("UPDATE managed_certificates")) return { rows: [] };
      throw new Error(`unexpected query: ${sql}`);
    },
  };
  return { audits, client };
}

const reconcileArgs = (client) => ({
  client,
  workspaceId: WORKSPACE,
  job: {
    id: 42,
    subject_type: "managed_certificate",
    subject_id: CERT_ID,
    claim_id: "44444444-4444-4444-8444-444444444444",
    operation: "issue",
    payload: {},
  },
  agent: { id: "agent-row-1", agentId: "edge-01" },
  linkToken: async () => 77,
  ensureRenewalProfile: async () => ({ profileId: PROFILE_ID, created: true }),
});

describe("CERTOPS_CERTIFICATE_ISSUED", () => {
  it("records the certificate coming into existence, on the promoting transaction", async () => {
    const { audits, client } = reconcileClient();
    const result = await dispatch._test.reconcileProvisionedCertificate(
      reconcileArgs(client),
    );

    assert.equal(result.promoted, true);
    assert.equal(audits.length, 1);
    const event = audits[0];
    assert.equal(event.action, "CERTOPS_CERTIFICATE_ISSUED");
    assert.equal(event.targetType, "managed_certificate");
    assert.equal(event.workspaceId, WORKSPACE);
    // audit_events.target_id is INTEGER, so a UUID subject has to live in
    // metadata or it is silently discarded and the event becomes unsearchable.
    assert.equal(event.targetId, null);
    assert.equal(event.metadata.managedCertificateId, CERT_ID);
  });

  it("has no user actor and names the acting agent the way other events do", async () => {
    const { audits, client } = reconcileClient();
    await dispatch._test.reconcileProvisionedCertificate(reconcileArgs(client));

    const event = audits[0];
    // An agent is a machine principal; actor_user_id is a users FK, so
    // attributing this to a person would be a lie.
    assert.equal(event.actorUserId, null);
    assert.equal(event.subjectUserId, null);
    // 'agentId' must mean the operator-visible agent identity here as well, not
    // an internal row id, or the same key means two things across the catalog.
    assert.equal(event.metadata.agentId, "edge-01");
  });

  it("carries the facts that make the event worth keeping", async () => {
    const { audits, client } = reconcileClient();
    await dispatch._test.reconcileProvisionedCertificate(reconcileArgs(client));

    const { metadata } = audits[0];
    // Identity of what was issued, proof of which certificate it was, when it
    // dies, where it landed, and which profile now owns its renewal.
    assert.equal(metadata.commonName, "web-01.example.com");
    assert.equal(metadata.fingerprintSha256, "a".repeat(64));
    assert.equal(metadata.serialNumber, "04AABB");
    assert.equal(metadata.issuer, "CN=Staging Fake LE");
    assert.equal(metadata.notAfter, "2026-10-24T10:00:00.000Z");
    assert.equal(metadata.deployedCertPath, "/etc/ssl/certs/web-01.pem");
    assert.equal(metadata.profileId, PROFILE_ID);
    assert.equal(metadata.jobId, "42");
    assert.equal(metadata.operation, "issue");
  });

  it("names the store/binding for a windows-iis issuance, in place of a null deployedCertPath", async () => {
    // A windows-iis target has no deployedCertPath by design (ADR-0012
    // decisions 1 and 10: its destination is a machine certificate store +
    // IIS binding, not a file). Without these fields this event would say
    // nothing at all about where the certificate landed.
    const { audits, client } = reconcileClient();
    await dispatch._test.reconcileProvisionedCertificate({
      ...reconcileArgs(client),
      job: {
        ...reconcileArgs(client).job,
        payload: {
          target: {
            type: "windows-iis",
            store: "My",
            binding: { site: "Default Web Site", port: 443, sniHost: "web-01.example.com" },
          },
        },
      },
    });

    const { metadata } = audits[0];
    assert.equal(metadata.targetType, "windows-iis");
    assert.equal(metadata.windowsStore, "My");
    assert.equal(metadata.windowsBindingSite, "Default Web Site");
    assert.equal(metadata.windowsBindingPort, 443);
    assert.equal(metadata.windowsBindingSniHost, "web-01.example.com");
  });

  it("is not emitted when there was nothing to promote", async () => {
    // An already-active certificate reconciles as a no-op. Emitting here would
    // report a second issuance every time an agent re-reported a result.
    const audits = [];
    const client = {
      query: async (text, params) => {
        const sql = typeof text === "string" ? text : text?.text || "";
        if (sql.includes("INSERT INTO audit_events")) {
          audits.push(params[2]);
          return { rows: [] };
        }
        if (sql.includes("FROM managed_certificates")) return { rows: [] };
        throw new Error(`unexpected query: ${sql}`);
      },
    };

    const result = await dispatch._test.reconcileProvisionedCertificate(
      reconcileArgs(client),
    );
    assert.equal(result, null);
    assert.deepEqual(audits, []);
  });
});

describe("CERTOPS_CERTIFICATE_ISSUANCE_UNRECONCILED", () => {
  it("records a succeeded job that left the certificate unusable", async () => {
    // The worst state CertOps can reach: job history says the work completed
    // while the certificate is not active and will never renew.
    const { audits, client } = reconcileClient({ metadata: null });
    const result = await dispatch._test.reconcileProvisionedCertificate(
      reconcileArgs(client),
    );

    assert.equal(result.promoted, false);
    assert.equal(audits.length, 1);
    assert.equal(audits[0].action, "CERTOPS_CERTIFICATE_ISSUANCE_UNRECONCILED");
    assert.equal(
      audits[0].metadata.reconciliationReason,
      "no_claim_bound_verify_evidence",
    );
    assert.equal(audits[0].metadata.managedCertificateId, CERT_ID);
  });

  it("distinguishes each reason a promotion was refused", async () => {
    // reconciliation_reason on the row only ever shows its latest value, so the
    // event is the only place the sequence of attempts survives.
    const cases = [
      [{ step: "verify", validTo: VERIFY_METADATA.validTo },
        "verify_evidence_missing_fingerprint"],
      [{ step: "verify", fingerprintSha256: "b".repeat(64) },
        "verify_evidence_missing_expiry"],
    ];
    for (const [metadata, expected] of cases) {
      const { audits, client } = reconcileClient({ metadata });
      await dispatch._test.reconcileProvisionedCertificate(
        reconcileArgs(client),
      );
      assert.equal(audits[0].metadata.reconciliationReason, expected);
    }
  });
});

// --- CERTOPS_CERTIFICATE_RENEWAL_UNRECONCILED / refreshRenewedCertificateEvidence ---

function refreshClient({ metadata = VERIFY_METADATA, tokenId = 77 } = {}) {
  const audits = [];
  const linkTokenCalls = [];
  const client = {
    query: async (text, params) => {
      const sql = typeof text === "string" ? text : text?.text || "";
      if (sql.includes("INSERT INTO audit_events")) {
        audits.push({
          action: params[2],
          metadata: params[6],
          workspaceId: params[7],
        });
        return { rows: [] };
      }
      if (sql.includes("FROM managed_certificates") && sql.includes("FOR UPDATE")) {
        return {
          rows: [
            {
              id: CERT_ID,
              common_name: "web-01.example.com",
              token_id: tokenId,
            },
          ],
        };
      }
      if (sql.includes("FROM certificate_evidence")) {
        return { rows: metadata ? [{ metadata }] : [] };
      }
      if (sql.includes("UPDATE managed_certificates")) return { rows: [] };
      throw new Error(`unexpected query: ${sql}`);
    },
  };
  const linkToken = async (args) => {
    linkTokenCalls.push(args);
    return tokenId;
  };
  return { audits, linkTokenCalls, client, linkToken };
}

const refreshArgs = (client, overrides = {}) => ({
  client,
  workspaceId: WORKSPACE,
  job: {
    id: 43,
    subject_type: "managed_certificate",
    subject_id: CERT_ID,
    claim_id: "55555555-5555-4555-8555-555555555555",
    operation: "renew",
  },
  agent: { id: "agent-row-1", agentId: "edge-01" },
  ...overrides,
});

describe("refreshRenewedCertificateEvidence (active-renewal reconciliation)", () => {
  it("refreshes not_after and mirrors the new facts to the linked token", async () => {
    const { audits, linkTokenCalls, client, linkToken } = refreshClient();
    const result = await dispatch._test.refreshRenewedCertificateEvidence(
      refreshArgs(client, { linkToken }),
    );

    assert.equal(result.refreshed, true);
    assert.equal(audits.length, 0, "a successful refresh is not audited");
    assert.equal(linkTokenCalls.length, 1);
    assert.equal(linkTokenCalls[0].existingTokenId, 77);
    assert.equal(linkTokenCalls[0].certificate.notAfter, result.notAfter);
  });

  it("does not call linkToken when the certificate has no linked token yet", async () => {
    const { linkTokenCalls, client, linkToken } = refreshClient({ tokenId: null });
    await dispatch._test.refreshRenewedCertificateEvidence(
      refreshArgs(client, { linkToken }),
    );
    assert.equal(linkTokenCalls.length, 0);
  });

  it("records a durable, auditable failure instead of a silent no-op on incomplete evidence", async () => {
    // Before this fix, incomplete verify evidence here just returned null: no
    // audit row, no reconciliation_reason, and not_after never advanced, so
    // the scheduler's (certificateId + not_after) idempotency key kept
    // colliding with the same already-succeeded job on every later sweep.
    const { audits, client, linkToken } = refreshClient({ metadata: null });
    const result = await dispatch._test.refreshRenewedCertificateEvidence(
      refreshArgs(client, { linkToken }),
    );

    assert.equal(result.refreshed, false);
    assert.equal(result.reason, "no_claim_bound_verify_evidence");
    assert.equal(audits.length, 1);
    assert.equal(audits[0].action, "CERTOPS_CERTIFICATE_RENEWAL_UNRECONCILED");
    assert.equal(
      audits[0].metadata.reconciliationReason,
      "no_claim_bound_verify_evidence",
    );
    assert.equal(audits[0].metadata.managedCertificateId, CERT_ID);
  });

  it("distinguishes missing fingerprint from missing expiry, same as first reconciliation", async () => {
    const cases = [
      [{ step: "verify", validTo: VERIFY_METADATA.validTo },
        "verify_evidence_missing_fingerprint"],
      [{ step: "verify", fingerprintSha256: "b".repeat(64) },
        "verify_evidence_missing_expiry"],
    ];
    for (const [metadata, expected] of cases) {
      const { audits, client, linkToken } = refreshClient({ metadata });
      await dispatch._test.refreshRenewedCertificateEvidence(
        refreshArgs(client, { linkToken }),
      );
      assert.equal(audits[0].metadata.reconciliationReason, expected);
    }
  });
});

// --- CERTOPS_RENEWAL_PROFILE_DERIVED ---

function issuePayload(overrides = {}) {
  return {
    caEndpoint: "https://acme-staging-v02.api.letsencrypt.org/directory",
    commandRef: "certbot.dns-cloudflare",
    acmeKind: "certbot",
    dnsProvider: "cloudflare",
    dnsZone: "example.com",
    certPath: "/etc/ssl/certs/web-01.pem",
    keyAlgorithm: "ecdsa",
    keySize: 256,
    ...overrides,
  };
}

function derivationClient({ existingProfileId = null, inserted = true } = {}) {
  const audits = [];
  const client = {
    query: async (text, params) => {
      const sql = typeof text === "string" ? text : text?.text || "";
      if (sql.includes("INSERT INTO audit_events")) {
        audits.push({
          actorUserId: params[0],
          action: params[2],
          targetType: params[3],
          metadata: params[6],
          workspaceId: params[7],
        });
        return { rows: [] };
      }
      if (sql.includes("SELECT profile_id FROM managed_certificates")) {
        return { rows: [{ profile_id: existingProfileId }] };
      }
      if (sql.includes("INSERT INTO certificate_profiles")) {
        return { rows: [{ id: PROFILE_ID, inserted }] };
      }
      if (sql.includes("UPDATE managed_certificates")) {
        return { rows: [], rowCount: 1 };
      }
      throw new Error(`unexpected query: ${sql}`);
    },
  };
  return { audits, client };
}

describe("CERTOPS_RENEWAL_PROFILE_DERIVED", () => {
  it("records the grant of recurring authority on the deriving transaction", async () => {
    // A derived profile lets the scheduler re-run this command on this host
    // against this CA forever, with no operator in the loop. Without this event
    // the trail shows PROFILE_UPDATED rows against a profile that, as far as
    // audit is concerned, never came into existence.
    const { audits, client } = derivationClient();
    await ensureDerivedRenewalProfile({
      client,
      workspaceId: WORKSPACE,
      certificateId: CERT_ID,
      payload: issuePayload(),
      certificate: {
        commonName: "web-01.example.com",
        subjectAltNames: ["web-01.example.com"],
      },
    });

    assert.equal(audits.length, 1);
    assert.equal(audits[0].action, "CERTOPS_RENEWAL_PROFILE_DERIVED");
    assert.equal(audits[0].targetType, "certificate_profile");
    assert.equal(audits[0].actorUserId, null);
    assert.equal(audits[0].workspaceId, WORKSPACE);
    assert.equal(audits[0].metadata.profileId, PROFILE_ID);
    assert.equal(audits[0].metadata.managedCertificateId, CERT_ID);
    assert.equal(audits[0].metadata.created, true);
  });

  it("records what the profile will actually run, and where", async () => {
    // The three fields that decide the real-world effect of every future
    // renewal. A reader who cannot see these cannot review the grant.
    const { audits, client } = derivationClient();
    await ensureDerivedRenewalProfile({
      client,
      workspaceId: WORKSPACE,
      certificateId: CERT_ID,
      payload: issuePayload(),
      certificate: {
        commonName: "web-01.example.com",
        subjectAltNames: ["web-01.example.com"],
      },
    });

    const { metadata } = audits[0];
    assert.equal(metadata.commandRef, "certbot.dns-cloudflare");
    assert.equal(
      metadata.caEndpoint,
      "https://acme-staging-v02.api.letsencrypt.org/directory",
    );
    assert.equal(metadata.certPath, "/etc/ssl/certs/web-01.pem");
    assert.equal(metadata.dnsProvider, "cloudflare");
    assert.equal(metadata.dnsZone, "example.com");
  });

  it("says nothing when no profile was derived", async () => {
    // Two non-grants: an operator's own profile is already linked, and a payload
    // too incomplete to derive from. Neither confers authority, so neither may
    // claim to have.
    const linked = derivationClient({ existingProfileId: PROFILE_ID });
    await ensureDerivedRenewalProfile({
      client: linked.client,
      workspaceId: WORKSPACE,
      certificateId: CERT_ID,
      payload: issuePayload(),
      certificate: { commonName: "web-01.example.com", subjectAltNames: [] },
    });
    assert.deepEqual(linked.audits, []);

    const failed = derivationClient();
    const outcome = await ensureDerivedRenewalProfile({
      client: failed.client,
      workspaceId: WORKSPACE,
      certificateId: CERT_ID,
      payload: issuePayload({ commandRef: null }),
      certificate: { commonName: "web-01.example.com", subjectAltNames: [] },
    });
    assert.equal(outcome.profileId, null);
    assert.deepEqual(failed.audits, []);
  });
});

// --- CERTOPS_JOB_CREATED_AUTOMATIC ---

/**
 * Minimal scheduler pool. The interesting part is that the audit writer is
 * injected here (the sweep's own transaction client is created internally), so
 * these tests assert the event's presence and contents; the in-transaction
 * property is covered by the client identity check below.
 */
function schedulerPool({ dueRows = [] } = {}) {
  const clients = [];
  const pool = {
    clients,
    async query(sql) {
      const text = String(sql);
      if (text.includes("disabled_count")) {
        return { rows: [{ disabled_count: 0 }] };
      }
      if (text.includes("COUNT(*)")) return { rows: [] };
      return { rows: dueRows };
    },
    async connect() {
      const client = {
        released: false,
        async query(sql, params = []) {
          const text = String(sql).trim();
          if (text.includes("pg_try_advisory_lock")) {
            return { rows: [{ acquired: true }] };
          }
          if (text.includes("pg_advisory_unlock")) {
            return { rows: [{ pg_advisory_unlock: true }] };
          }
          if (text.includes("FROM workspaces")) {
            return { rows: [{ id: params[0], certops_paused: false }] };
          }
          if (text.includes("system_settings")) {
            return { rows: [{ certops_settings: { enabled: true } }] };
          }
          return { rows: [] };
        },
        release() {
          this.released = true;
        },
      };
      clients.push(client);
      return client;
    },
  };
  return pool;
}

function dueCertificate() {
  return {
    id: CERT_ID,
    workspace_id: WORKSPACE,
    common_name: "app.example.com",
    subject_alt_names: ["app.example.com"],
    not_after: new Date("2026-08-20T00:00:00.000Z"),
    key_mode: null,
    profile_id: PROFILE_ID,
    profile_name: "web-tls",
    profile_key_mode: null,
    profile_renew_before_days: null,
    certificate_ca_endpoint: null,
    profile_ca_endpoint: "https://acme-v02.api.letsencrypt.org/directory",
    profile_public_metadata: {
      renewalProfile: {
        schemaVersion: 1,
        profileName: "web-tls",
        sanPolicy: { mode: "exact", sans: ["app.example.com"], allowWildcards: false },
        keyAlgorithm: "rsa",
        keySize: 2048,
        keyRotationPolicy: { rotateOnRenew: false },
        preferredChain: null,
        ca: {
          endpoint: "https://acme-v02.api.letsencrypt.org/directory",
          accountRef: "le-prod",
          eabRef: null,
        },
        acme: { kind: "certbot", commandRef: "renew.web" },
        dns: { provider: "cloudflare", zone: "example.com" },
        deploymentTargets: [
          {
            type: "endpoint",
            reference: "host/web",
            certPath: "/etc/ssl/certs/app.pem",
          },
        ],
        target: {
          type: "endpoint",
          reference: "host/web",
          certPath: "/etc/ssl/certs/app.pem",
        },
        verification: { host: null, port: null, requireMatch: false },
      },
    },
  };
}

describe("CERTOPS_JOB_CREATED_AUTOMATIC", () => {
  it("mirrors the manual event for jobs no human asked for", async () => {
    // The existing event is named CERTOPS_JOB_CREATED_MANUAL. Without its
    // counterpart the audit log contains only operator-initiated jobs, so
    // unattended renewal is exactly the activity it cannot account for.
    const audits = [];
    const pool = schedulerPool({ dueRows: [dueCertificate()] });
    const summary = await runRenewalSchedulerSweep({
      dbPool: pool,
      env: {},
      jobCreator: async () => ({
        job: { id: "job-1", operation: "renew", subjectType: "managed_certificate" },
        created: true,
      }),
      auditWriter: async (event) => audits.push(event),
    });

    assert.deepEqual(summary.errors, []);
    assert.equal(summary.created, 1);
    assert.equal(audits.length, 1);
    assert.equal(audits[0].action, "CERTOPS_JOB_CREATED_AUTOMATIC");
    assert.equal(audits[0].targetType, "certificate_job");
    assert.equal(audits[0].actorUserId, null);
    assert.equal(audits[0].workspaceId, WORKSPACE);
    assert.equal(audits[0].metadata.source, "automation");
    assert.equal(audits[0].metadata.trigger, "renewal_scheduler");
    assert.equal(audits[0].metadata.subjectId, CERT_ID);
    assert.equal(audits[0].metadata.commonName, "app.example.com");
    assert.equal(audits[0].metadata.profileId, PROFILE_ID);
  });

  it("writes on the job's own transaction client", async () => {
    // If this ran on the pool instead, a rolled-back renewal insert would leave
    // an audit row claiming a job that does not exist.
    let auditClient = null;
    const pool = schedulerPool({ dueRows: [dueCertificate()] });
    await runRenewalSchedulerSweep({
      dbPool: pool,
      env: {},
      jobCreator: async () => ({
        job: { id: "job-1", operation: "renew" },
        created: true,
      }),
      auditWriter: async (event) => {
        auditClient = event.client;
      },
    });

    assert.ok(auditClient, "the event must carry a transaction client");
    // The sweep holds the advisory lock on its first connection and opens a
    // second for the insert; the audit must ride the latter.
    assert.equal(auditClient, pool.clients[pool.clients.length - 1]);
  });

  it("stays silent for an idempotent replay", async () => {
    // A replay created nothing, so auditing it would report renewals that were
    // never scheduled.
    const audits = [];
    const pool = schedulerPool({ dueRows: [dueCertificate()] });
    const summary = await runRenewalSchedulerSweep({
      dbPool: pool,
      env: {},
      jobCreator: async () => ({ job: { id: "job-1" }, created: false }),
      auditWriter: async (event) => audits.push(event),
    });

    assert.equal(summary.replayed, 1);
    assert.deepEqual(audits, []);
  });
});

// --- CERTOPS_JOB_FAILED and CERTOPS_AGENT_REGISTERED ---

function resultPool({ jobRow = {}, jobUpdate = {} } = {}) {
  const audits = [];
  const transaction = [];
  const client = {
    async query(text, params) {
      const sql = typeof text === "string" ? text : text?.text || "";
      const trimmed = sql.trim().toUpperCase();
      if (trimmed === "BEGIN" || trimmed === "COMMIT" || trimmed === "ROLLBACK") {
        transaction.push(trimmed);
        return { rows: [] };
      }
      if (sql.includes("INSERT INTO audit_events")) {
        audits.push({
          actorUserId: params[0],
          action: params[2],
          targetType: params[3],
          metadata: params[6],
          workspaceId: params[7],
        });
        return { rows: [] };
      }
      if (sql.includes("SET last_sequence")) return { rows: [{ id: "agent-row-1" }] };
      if (sql.includes("FROM certops_agents")) return { rows: [{ id: "agent-row-1" }] };
      if (sql.includes("INSERT INTO certops_outbox")) {
        return { rows: [{ id: "outbox-1" }] };
      }
      if (sql.includes("FROM certificate_jobs") && sql.includes("FOR UPDATE")) {
        return {
          rows: [
            {
              id: 42,
              status: "claimed",
              claimed_by_agent_id: "agent-row-1",
              claim_id: "claim-1",
              operation: "renew",
              subject_type: "managed_certificate",
              subject_id: CERT_ID,
              mode: "real",
              source: "automation",
              payload: {},
              ...jobRow,
            },
          ],
        };
      }
      if (sql.includes("UPDATE certificate_jobs")) {
        return {
          rows: [
            {
              id: 42,
              status: params[1],
              error_code: params[2],
              completed_at: new Date(),
              needs_operator_reconciliation: false,
              reconciliation_reason: null,
              ...jobUpdate,
            },
          ],
        };
      }
      throw new Error(`unexpected query: ${sql}`);
    },
    release() {},
  };
  return {
    audits,
    transaction,
    client,
    connect: async () => client,
    query: client.query,
  };
}

const AGENT = {
  id: "agent-row-1",
  workspaceId: WORKSPACE,
  agentId: "edge-01",
  status: "active",
  protocolVersion: "1.0.0",
};

describe("CERTOPS_JOB_FAILED", () => {
  it("records a terminal failure on the ingesting transaction", async () => {
    // certificate_jobs keeps only the latest error, so a job that failed and was
    // then retried loses its own history. The event is what survives.
    const pool = resultPool();
    await dispatch.ingestResult({
      dbPool: pool,
      agent: AGENT,
      envelope: { sequence: 11 },
      body: {
        jobId: "42",
        claimId: "claim-1",
        attemptId: "claim-1",
        nonce: "n-1",
        status: "failed",
        errorMessage: "dns propagation timed out",
      },
      deps: { consumeNonce: async () => ({ consumed: true }) },
    });

    assert.equal(pool.audits.length, 1);
    const event = pool.audits[0];
    assert.equal(event.action, "CERTOPS_JOB_FAILED");
    assert.equal(event.targetType, "certificate_job");
    assert.equal(event.actorUserId, null);
    assert.equal(event.workspaceId, WORKSPACE);
    assert.equal(event.metadata.jobId, "42");
    assert.equal(event.metadata.jobStatus, "failed");
    assert.equal(event.metadata.agentId, "edge-01");
    assert.equal(event.metadata.subjectId, CERT_ID);
    assert.equal(event.metadata.errorMessage, "dns propagation timed out");
    assert.deepEqual(pool.transaction, ["BEGIN", "COMMIT"]);
  });

  it("scrubs key material out of the agent's error text", async () => {
    // The audit log is widely readable and exportable, so an agent that echoed a
    // key into its error message must not turn the trail into a key store.
    const pool = resultPool();
    await dispatch.ingestResult({
      dbPool: pool,
      agent: AGENT,
      envelope: { sequence: 11 },
      body: {
        jobId: "42",
        claimId: "claim-1",
        attemptId: "claim-1",
        nonce: "n-1",
        status: "failed",
        errorMessage:
          "deploy failed: -----BEGIN PRIVATE KEY-----\nMIIabc\n-----END PRIVATE KEY-----",
      },
      deps: { consumeNonce: async () => ({ consumed: true }) },
    });

    const { errorMessage } = pool.audits[0].metadata;
    assert.equal(errorMessage.includes("MIIabc"), false);
    assert.equal(errorMessage.includes("BEGIN PRIVATE KEY"), false);
  });

  it("flags an orphaned job, whose real-world effect is unknown", async () => {
    // The one outcome that always needs a human: the agent may or may not have
    // changed the host before it vanished.
    const pool = resultPool({
      jobUpdate: {
        needs_operator_reconciliation: true,
        reconciliation_reason: "agent_lost_mid_deploy",
      },
    });
    await dispatch.ingestResult({
      dbPool: pool,
      agent: AGENT,
      envelope: { sequence: 11 },
      body: {
        jobId: "42",
        claimId: "claim-1",
        attemptId: "claim-1",
        nonce: "n-1",
        status: "orphaned_unknown_effect",
        errorMessage:
          "lost; needsOperatorReconciliation=true; reconciliationReason=agent_lost_mid_deploy",
      },
      deps: { consumeNonce: async () => ({ consumed: true }) },
    });

    const { metadata } = pool.audits[0];
    assert.equal(metadata.jobStatus, "orphaned_unknown_effect");
    assert.equal(metadata.needsOperatorReconciliation, true);
    assert.equal(metadata.reconciliationReason, "agent_lost_mid_deploy");
  });

  it("names the store/binding a failed windows-iis job was targeting", async () => {
    // A failed windows-iis job's errorMessage is free-text agent output; this
    // is the structured substitute that lets an operator tell which store and
    // IIS site/port/SNI host the failure actually touched, without parsing
    // errorMessage.
    const pool = resultPool({
      jobRow: {
        payload: {
          target: {
            type: "windows-iis",
            store: "My",
            binding: { site: "Default Web Site", port: 443, sniHost: "web-01.example.com" },
          },
        },
      },
    });
    await dispatch.ingestResult({
      dbPool: pool,
      agent: AGENT,
      envelope: { sequence: 11 },
      body: {
        jobId: "42",
        claimId: "claim-1",
        attemptId: "claim-1",
        nonce: "n-1",
        status: "failed",
        errorMessage: "IIS binding deploy failed: BIND_FAILED",
      },
      deps: { consumeNonce: async () => ({ consumed: true }) },
    });

    const { metadata } = pool.audits[0];
    assert.equal(metadata.targetType, "windows-iis");
    assert.equal(metadata.windowsStore, "My");
    assert.equal(metadata.windowsBindingSite, "Default Web Site");
    assert.equal(metadata.windowsBindingPort, 443);
    assert.equal(metadata.windowsBindingSniHost, "web-01.example.com");
  });

  it("omits windows fields (beyond a null targetType) for a non-windows job", async () => {
    const pool = resultPool();
    await dispatch.ingestResult({
      dbPool: pool,
      agent: AGENT,
      envelope: { sequence: 11 },
      body: {
        jobId: "42",
        claimId: "claim-1",
        attemptId: "claim-1",
        nonce: "n-1",
        status: "failed",
        errorMessage: "dns propagation timed out",
      },
      deps: { consumeNonce: async () => ({ consumed: true }) },
    });

    const { metadata } = pool.audits[0];
    assert.equal(metadata.targetType, null);
    assert.equal(metadata.windowsStore, undefined);
  });

  it("does not audit a success as a failure", async () => {
    // Successes are covered by CERTOPS_CERTIFICATE_ISSUED. A row per successful
    // renewal per certificate would bury the failures.
    const pool = resultPool({
      jobRow: { subject_type: "certificate_target", subject_id: null },
    });
    await dispatch.ingestResult({
      dbPool: pool,
      agent: AGENT,
      envelope: { sequence: 11 },
      body: {
        jobId: "42",
        claimId: "claim-1",
        attemptId: "claim-1",
        nonce: "n-1",
        status: "succeeded",
      },
      deps: { consumeNonce: async () => ({ consumed: true }) },
    });

    assert.deepEqual(
      pool.audits.map((event) => event.action),
      [],
    );
  });
});

describe("CERTOPS_AGENT_REGISTERED", () => {
  const REGISTRATION_KEY_ENV = "CERTOPS_REGISTRATION_ENCRYPTION_KEY";

  function registrationPool({ replayRow = null } = {}) {
    const audits = [];
    const transaction = [];
    const client = {
      async query(text, params) {
        const sql = typeof text === "string" ? text : text?.text || "";
        const trimmed = sql.trim().toUpperCase();
        if (
          trimmed === "BEGIN" ||
          trimmed === "COMMIT" ||
          trimmed === "ROLLBACK"
        ) {
          transaction.push(trimmed);
          return { rows: [] };
        }
        if (sql.includes("INSERT INTO audit_events")) {
          audits.push({
            actorUserId: params[0],
            action: params[2],
            targetType: params[3],
            metadata: params[6],
            workspaceId: params[7],
          });
          return { rows: [] };
        }
        if (sql.includes("FROM certops_agent_bootstrap_tokens")) {
          return {
            rows: [{ id: "boot-1", status: "active", workspace_id: WORKSPACE }],
          };
        }
        if (sql.includes("FROM certops_agent_registration_replays")) {
          return { rows: replayRow ? [replayRow] : [] };
        }
        if (sql.includes("INSERT INTO certops_agents")) {
          return {
            rows: [
              {
                id: "agent-row-1",
                agent_id: "edge-01",
                protocol_version: "1.0.0",
              },
            ],
          };
        }
        if (sql.includes("INSERT INTO certops_agent_registration_replays")) {
          return { rows: [] };
        }
        throw new Error(`unexpected query: ${sql}`);
      },
      release() {},
    };
    return { audits, transaction, client, connect: async () => client };
  }

  const registerArgs = (pool) => ({
    dbPool: pool,
    bootstrapToken: { id: "boot-1", workspaceId: WORKSPACE },
    envelope: {
      schemaVersion: 1,
      protocolVersion: "1.0.0",
      messageType: "register",
      agentId: "edge-01",
      sentAt: "2026-07-26T10:00:00.000Z",
    },
    body: {
      bootstrapTokenId: "boot-1",
      agentVersion: "0.1.0",
      registrationId: "550e8400-e29b-41d4-a716-446655440000",
      hostname: "edge-01",
      platform: "linux",
      nodeVersion: "22.1.0",
      declaredTargetSelectors: ["*.example.com"],
      declaredCommandProfileNames: ["nginx-reload"],
      declaredCapabilities: ["evidence-claim-binding-v1"],
    },
    deps: {
      ensureActiveSigningKey: async () => ({
        signingKeyId: "key-1",
        publicKeyPem: "-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----",
      }),
      generateAgentCredential: () => ({
        credentialPrefix: "ttagent_0123456789abcdef",
        credentialHash: "hash",
        plaintextCredential: `ttagent_0123456789abcdef_${"b".repeat(64)}`,
      }),
      consumeBootstrapToken: async () => ({ id: "boot-1" }),
    },
  });

  it("records the enrollment that grants a machine the right to run commands", async () => {
    // Also the only record of a bootstrap token being spent: a consumed token is
    // marked 'used', which produces no revocation event. The docs already told
    // readers to "look for the agent's own registration instead".
    const saved = process.env[REGISTRATION_KEY_ENV];
    process.env[REGISTRATION_KEY_ENV] = "a".repeat(64);
    try {
      const pool = registrationPool();
      await dispatch.registerAgent(registerArgs(pool));

      assert.equal(pool.audits.length, 1);
      const event = pool.audits[0];
      assert.equal(event.action, "CERTOPS_AGENT_REGISTERED");
      assert.equal(event.targetType, "certops_agent");
      assert.equal(event.actorUserId, null);
      assert.equal(event.workspaceId, WORKSPACE);
      assert.equal(event.metadata.agentId, "edge-01");
      assert.equal(event.metadata.hostname, "edge-01");
      assert.equal(event.metadata.bootstrapTokenId, "boot-1");
      assert.equal(event.metadata.signingKeyId, "key-1");
      // What the agent claims it can do decides which jobs it may be handed, so
      // it belongs in the record of the grant.
      assert.deepEqual(event.metadata.declaredCapabilities, [
        "evidence-claim-binding-v1",
      ]);
      assert.deepEqual(pool.transaction, ["BEGIN", "COMMIT"]);
    } finally {
      if (saved === undefined) delete process.env[REGISTRATION_KEY_ENV];
      else process.env[REGISTRATION_KEY_ENV] = saved;
    }
  });

  it("never puts the credential in the audit trail", async () => {
    // The credential is returned to the agent exactly once. An audit row is the
    // last place it may appear; only the prefix identifies it.
    const saved = process.env[REGISTRATION_KEY_ENV];
    process.env[REGISTRATION_KEY_ENV] = "a".repeat(64);
    try {
      const pool = registrationPool();
      await dispatch.registerAgent(registerArgs(pool));

      const serialized = JSON.stringify(pool.audits[0].metadata);
      assert.equal(serialized.includes("b".repeat(64)), false);
      assert.equal(
        pool.audits[0].metadata.credentialPrefix,
        "ttagent_0123456789abcdef",
      );
    } finally {
      if (saved === undefined) delete process.env[REGISTRATION_KEY_ENV];
      else process.env[REGISTRATION_KEY_ENV] = saved;
    }
  });

  it("does not audit a replayed registration twice", async () => {
    // A lost-response retry is the same enrollment. Two rows would read as two
    // agents having been granted access.
    const saved = process.env[REGISTRATION_KEY_ENV];
    process.env[REGISTRATION_KEY_ENV] = "a".repeat(64);
    try {
      const cryptoModule = require(
        path.resolve(
          __dirname,
          "../../apps/api/services/certops/registrationCredentialCrypto.js",
        ),
      );
      const pool = registrationPool({
        replayRow: {
          bootstrap_token_id: "boot-1",
          registration_id: "550e8400-e29b-41d4-a716-446655440000",
          agent_id: "edge-01",
          credential_ciphertext: cryptoModule.encryptRegistrationCredential(
            `ttagent_0123456789abcdef_${"b".repeat(64)}`,
          ),
          encryption_version: cryptoModule.ENCRYPTION_VERSION,
          protocol_version: "1.0.0",
          signing_key_id: "key-1",
          signing_public_key_pem: "-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----",
        },
      });
      await dispatch.registerAgent(registerArgs(pool));

      assert.deepEqual(pool.audits, []);
    } finally {
      if (saved === undefined) delete process.env[REGISTRATION_KEY_ENV];
      else process.env[REGISTRATION_KEY_ENV] = saved;
    }
  });
});
