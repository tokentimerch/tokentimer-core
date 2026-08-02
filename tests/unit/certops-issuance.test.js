"use strict";

/**
 * Upfront issuance (ADR-0008).
 *
 * The behaviour under test is the fix for a real product hole: a bare manual
 * renew job with no subject would run a full ACME order and deploy a genuine
 * certificate, and TokenTimer would record nothing at all. These tests pin the
 * two halves of the fix that make that impossible to reintroduce silently:
 * the identity is created before the job that references it, and the identity
 * is reconciled from the agent's own evidence about what it deployed.
 */

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const fs = require("node:fs");

const {
  ISSUANCE_KEY_MODE,
  ISSUANCE_SOURCE,
  ISSUANCE_STATUS,
  createCertificateIssuanceJob,
  normalizeIssuanceRequest,
} = require(
  path.resolve(__dirname, "../../apps/api/services/certops/issuance.js"),
);
const { JOB_OPERATIONS, isTrustAnchorOperation } = require(
  path.resolve(__dirname, "../../apps/api/services/certops/jobs.js"),
);
const dispatch = require(
  path.resolve(__dirname, "../../apps/api/services/certops/agentDispatch.js"),
);
const { migrations } = require(
  path.resolve(__dirname, "../../apps/api/migrations/migrate.js"),
);

const WORKSPACE_A = "11111111-1111-4111-8111-111111111111";
const NEW_CERT_ID = "22222222-2222-4222-8222-222222222222";

const BASE_PAYLOAD = Object.freeze({
  target: { type: "domain", reference: "web-01.example.com" },
  commandRef: "certbot-csr",
  caEndpoint: "https://acme-staging-v02.api.letsencrypt.org/directory",
  certPath: "/etc/ssl/tokentimer/web-01.example.com.pem",
  dnsZone: "example.com",
  dnsProvider: "cloudflare",
});

/**
 * A valid issue request. `payload` overrides are merged into BASE_PAYLOAD, and
 * an explicit `undefined` removes the base key, so a test can assert a
 * required field is genuinely required.
 */
function validRequest({ payload, ...overrides } = {}) {
  const merged = { ...BASE_PAYLOAD, ...(payload || {}) };
  for (const key of Object.keys(payload || {})) {
    if (payload[key] === undefined) delete merged[key];
  }
  return {
    workspaceId: WORKSPACE_A,
    idempotencyKey: "issue-web-01",
    payload: merged,
    ...overrides,
  };
}

/**
 * Records every write so a test can assert not just the outcome but that no
 * certificate row was created on a rejected or replayed request.
 */
function createIssuanceClient({
  existingJobId = null,
  existingCertificateId = null,
} = {}) {
  const state = { inserts: [], queries: [] };
  const client = {
    query: async (text, params) => {
      const sql = typeof text === "string" ? text : text?.text || "";
      state.queries.push({ sql, params });
      if (sql.includes("pg_advisory_xact_lock")) {
        return { rows: [] };
      }
      if (sql.includes("FROM managed_certificates") && sql.includes("source_ref")) {
        return { rows: existingCertificateId ? [{ id: existingCertificateId }] : [] };
      }
      if (sql.includes("FROM certificate_jobs") && sql.includes("idempotency_key")) {
        return { rows: existingJobId ? [{ id: existingJobId }] : [] };
      }
      if (sql.includes("INSERT INTO managed_certificates")) {
        state.inserts.push(params);
        return {
          rows: [
            {
              id: NEW_CERT_ID,
              status: ISSUANCE_STATUS,
              source: ISSUANCE_SOURCE,
              source_ref: params[3],
              common_name: params[4],
            },
          ],
        };
      }
      throw new Error(`unexpected query: ${sql}`);
    },
  };
  return { state, client };
}

describe("certops issuance request validation", () => {
  it("accepts a well-formed request and defaults sans to the common name", () => {
    const normalized = normalizeIssuanceRequest(validRequest());
    assert.equal(normalized.idempotencyKey, "issue-web-01");
    assert.equal(normalized.commonName, "web-01.example.com");
    assert.deepEqual(normalized.sans, ["web-01.example.com"]);
    assert.equal(
      normalized.certPath,
      "/etc/ssl/tokentimer/web-01.example.com.pem",
    );
  });

  it("lowercases and de-duplicates an explicit sans list", () => {
    const normalized = normalizeIssuanceRequest(
      validRequest({
        payload: {
          sans: ["WEB-01.example.com", "alt.example.com", "alt.example.com"],
        },
      }),
    );
    assert.deepEqual(normalized.sans, ["web-01.example.com", "alt.example.com"]);
  });

  it("requires an idempotencyKey so a retry cannot create a duplicate certificate", () => {
    assert.throws(
      () => normalizeIssuanceRequest(validRequest({ idempotencyKey: undefined })),
      /idempotencyKey/,
    );
  });

  it("rejects a caller-supplied subjectId", () => {
    assert.throws(
      () =>
        normalizeIssuanceRequest(
          validRequest({ subjectType: "managed_certificate", subjectId: NEW_CERT_ID }),
        ),
      /must not carry subjectType or subjectId/,
    );
  });

  it("rejects a caller-supplied payload.certificateId", () => {
    assert.throws(
      () =>
        normalizeIssuanceRequest(
          validRequest({ payload: { certificateId: NEW_CERT_ID } }),
        ),
      /must not carry payload.certificateId/,
    );
  });

  it("requires payload.target.reference and payload.certPath", () => {
    assert.throws(
      () => normalizeIssuanceRequest(validRequest({ payload: { target: undefined } })),
      /payload.target/,
    );
    assert.throws(
      () => normalizeIssuanceRequest(validRequest({ payload: { certPath: undefined } })),
      /payload.certPath/,
    );
  });

  it("rejects a sans list that does not cover the common name", () => {
    // A certificate whose SANs omit the name its inventory row is keyed on
    // would deploy and then fail every subsequent verification.
    assert.throws(
      () =>
        normalizeIssuanceRequest(
          validRequest({ payload: { sans: ["other.example.com"] } }),
        ),
      /must include payload.target.reference/,
    );
  });

  it("rejects a certPath that is a directory or not absolute", () => {
    // Both shapes fail agent-side only after the ACME order has been placed,
    // burning a rate-limited order and stranding the row in provisioning.
    assert.throws(
      () =>
        normalizeIssuanceRequest(
          validRequest({ payload: { certPath: "/etc/ssl/tokentimer/" } }),
        ),
      /must be a file path, not a directory/,
    );
    assert.throws(
      () =>
        normalizeIssuanceRequest(
          validRequest({ payload: { certPath: "etc/ssl/web-01.pem" } }),
        ),
      /must be an absolute path/,
    );
  });

  it("rejects a target reference that is not a DNS name", () => {
    assert.throws(
      () =>
        normalizeIssuanceRequest(
          validRequest({ payload: { target: { reference: "not a hostname" } } }),
        ),
      /valid DNS name/,
    );
  });
});

describe("certops issuance job creation", () => {
  it("creates the provisioning certificate before the job", async () => {
    const { state, client } = createIssuanceClient();
    let jobOptions = null;
    await createCertificateIssuanceJob({
      ...validRequest(),
      client,
      jobCreatorOverride: async (options) => {
        jobOptions = options;
        return { job: { id: "job-1" }, created: true };
      },
    });

    assert.equal(state.inserts.length, 1, "one certificate row expected");
    const insert = state.inserts[0];
    assert.equal(insert[1], ISSUANCE_STATUS);
    assert.equal(insert[2], ISSUANCE_SOURCE);
    assert.equal(insert[3], "issue-web-01", "source_ref is the idempotency key");
    assert.equal(insert[4], "web-01.example.com");
    assert.equal(insert[6], ISSUANCE_KEY_MODE);
    assert.equal(
      insert[7],
      "file:///etc/ssl/tokentimer/web-01.example.com.pem",
      "key_reference is an opaque path pointer, never key material",
    );

    assert.equal(jobOptions.operation, "issue");
    assert.equal(jobOptions.subjectType, "managed_certificate");
    assert.equal(jobOptions.subjectId, NEW_CERT_ID);
    assert.equal(
      jobOptions.payload.certificateId,
      NEW_CERT_ID,
      "server-assigned certificateId must match the row it reconciles",
    );
    assert.equal(
      insert[9],
      "/etc/ssl/tokentimer/web-01.example.com.pem",
      "deployed_cert_path correlates the later filesystem scan of the same path",
    );
  });

  it("takes the identity advisory lock before reading the identity", async () => {
    // The workspace kill-switch lock is FOR SHARE and does not serialize two
    // issuance requests. Without this lock, concurrent POSTs with one key both
    // read "no certificate" and race the unique index into an opaque 500.
    const { state, client } = createIssuanceClient();
    await createCertificateIssuanceJob({
      ...validRequest(),
      client,
      jobCreatorOverride: async () => ({ job: { id: "job-1" }, created: true }),
    });

    const lockIndex = state.queries.findIndex((q) =>
      q.sql.includes("pg_advisory_xact_lock"),
    );
    const readIndex = state.queries.findIndex(
      (q) => q.sql.includes("FROM managed_certificates") && q.sql.includes("source_ref"),
    );
    assert.ok(lockIndex >= 0, "an identity advisory lock is expected");
    assert.ok(
      lockIndex < readIndex,
      "the lock must be held before the read-then-insert",
    );
    assert.equal(
      typeof state.queries[lockIndex].params[0],
      "string",
      "the lock key is a stable signed bigint passed as a string",
    );
  });

  it("creates no second certificate when the idempotency key replays", async () => {
    const { state, client } = createIssuanceClient({
      existingJobId: "job-1",
      existingCertificateId: NEW_CERT_ID,
    });
    await createCertificateIssuanceJob({
      ...validRequest(),
      client,
      jobCreatorOverride: async () => ({ job: { id: "job-1" }, created: false }),
    });
    assert.equal(
      state.inserts.length,
      0,
      "a replay must not create an orphan provisioning row",
    );
  });

  it("derives identical job options on the replay, so it replays instead of conflicting", async () => {
    // Regression: the replay path used to hand createCertificateJob the bare
    // request (no subjectId, no server-assigned certificateId), so its
    // creation-request hash differed from the original and a byte-identical
    // retry was reported as an idempotency conflict (HTTP 409) instead of
    // returning the original job. Found by live end-to-end testing.
    const captured = [];
    const jobCreatorOverride = async (options) => {
      captured.push(options);
      return { job: { id: "job-1" }, created: captured.length === 1 };
    };

    const first = createIssuanceClient();
    await createCertificateIssuanceJob({
      ...validRequest(),
      client: first.client,
      jobCreatorOverride,
    });

    const replay = createIssuanceClient({
      existingJobId: "job-1",
      existingCertificateId: NEW_CERT_ID,
    });
    await createCertificateIssuanceJob({
      ...validRequest(),
      client: replay.client,
      jobCreatorOverride,
    });

    assert.equal(captured.length, 2);
    const strip = ({ client, jobCreatorOverride: _ignored, ...rest }) => rest;
    assert.deepEqual(
      strip(captured[1]),
      strip(captured[0]),
      "replayed job options must be identical to the original",
    );
  });

  it("does not create an identity when the key belongs to a non-issuance job", async () => {
    // Key reused across operations: there is no issuance certificate to reuse,
    // and inventing one would leave an orphan row behind the conflict that
    // createCertificateJob is about to raise.
    const { state, client } = createIssuanceClient({ existingJobId: "job-renew" });
    let jobOptions = null;
    await createCertificateIssuanceJob({
      ...validRequest(),
      client,
      jobCreatorOverride: async (options) => {
        jobOptions = options;
        return { job: { id: "job-renew" }, created: false };
      },
    });
    assert.equal(state.inserts.length, 0);
    assert.equal(jobOptions.subjectId, undefined);
  });

  it("refuses to run without the kill-switch-locked client", async () => {
    await assert.rejects(
      () => createCertificateIssuanceJob({ ...validRequest(), client: null }),
      /kill-switch-locked client/,
    );
  });
});

describe("certops issue operation plumbing", () => {
  it("is a recognised job operation", () => {
    assert.ok(JOB_OPERATIONS.includes("issue"));
  });

  it("dispatches to agents as the renew wire action", () => {
    // The agent-facing action enum is deliberately unchanged so fielded
    // agents run issue jobs with no upgrade (ADR-0008/ADR-0002).
    assert.equal(dispatch._test.wireActionForOperation("issue"), "renew");
    assert.equal(dispatch._test.wireActionForOperation("renew"), "renew");
    assert.equal(dispatch._test.wireActionForOperation("deploy"), "deploy");
  });

  it("keeps the claim SQL's operation translation in sync with the mapper", () => {
    // The claim predicate translates operations to wire actions in SQL, while
    // dispatch does it in JS. Two copies of one mapping drift, and the failure
    // mode is silent: a new operation whose SQL arm is missing simply never
    // matches, so the job is created, sits pending forever, and no error is
    // raised anywhere. Assert the SQL arms are exactly the operations whose
    // wire action differs from their own name.
    const source = fs.readFileSync(
      path.join(__dirname, "../../apps/api/services/certops/agentDispatch.js"),
      "utf8",
    );
    const caseMatch = source.match(
      /CASE operation\s+((?:WHEN '[a-z-]+' THEN '[a-z-]+'\s*)+)ELSE operation END/,
    );
    assert.ok(caseMatch, "the claim SQL must contain the translation CASE");

    const sqlArms = new Map(
      [...caseMatch[1].matchAll(/WHEN '([a-z-]+)' THEN '([a-z-]+)'/g)].map(
        (arm) => [arm[1], arm[2]],
      ),
    );
    const translated = new Map(
      JOB_OPERATIONS.filter(
        (operation) =>
          dispatch._test.wireActionForOperation(operation) !== operation,
      ).map((operation) => [
        operation,
        dispatch._test.wireActionForOperation(operation),
      ]),
    );

    assert.deepEqual(
      [...sqlArms.entries()].sort(),
      [...translated.entries()].sort(),
      "every operation whose wire action differs needs exactly one SQL arm",
    );
  });

  it("does not raise a renewal alert for a failed issuance", () => {
    // An issuance failure has no certificate identity worth alerting on yet:
    // there is no token to anchor contact routing and nothing in the inventory
    // the operator was already relying on. The job itself is visible in the
    // dashboard and the audit trail. The set is asserted here AND exercised
    // through the resolver in certops-renewal-failure-alerts.test.js, because
    // the original bug was precisely a set that no test ever resolved against.
    assert.ok(!dispatch._test.RENEWAL_ALERTING_OPERATIONS.has("issue"));
    assert.ok(dispatch._test.RENEWAL_ALERTING_OPERATIONS.has("renew"));
    assert.ok(!dispatch._test.RENEWAL_ALERTING_OPERATIONS.has("deploy"));
  });
});

describe("certops provisioning reconciliation", () => {
  const CLAIM_ID = "33333333-3333-4333-8333-333333333333";
  const jobFixture = {
    id: 42,
    operation: "issue",
    subject_type: "managed_certificate",
    subject_id: NEW_CERT_ID,
    claim_id: CLAIM_ID,
  };

  const COMPLETE_VERIFY_METADATA = {
    step: "verify",
    fingerprintSha256: "a".repeat(64),
    serialNumber: "04AABB",
    subject: "CN=web-01.example.com",
    issuer: "CN=Staging Fake LE",
    validFrom: "Jul 26 10:00:00 2026 GMT",
    validTo: "Oct 24 10:00:00 2026 GMT",
    subjectAltNames: "web-01.example.com,alt.example.com",
  };

  function reconcileClient({
    provisioning = true,
    metadata = COMPLETE_VERIFY_METADATA,
    evidenceRows = null,
    tokenId = null,
    commonName = null,
  } = {}) {
    const state = { updates: [], evidenceQueries: [], audits: [] };
    const client = {
      query: async (text, params) => {
        const sql = typeof text === "string" ? text : text?.text || "";
        if (sql.includes("FROM managed_certificates")) {
          return {
            rows: provisioning
              ? [
                  {
                    id: NEW_CERT_ID,
                    source: "agent_issuance",
                    common_name: commonName,
                    token_id: tokenId,
                  },
                ]
              : [],
          };
        }
        if (sql.includes("FROM certificate_evidence")) {
          state.evidenceQueries.push({ sql, params });
          if (evidenceRows) return { rows: evidenceRows };
          return { rows: metadata ? [{ metadata }] : [] };
        }
        if (sql.includes("UPDATE managed_certificates")) {
          state.updates.push(params);
          return { rows: [] };
        }
        // Captured rather than stubbed at the writeAudit boundary on purpose:
        // routing the real writeAudit through this mock is what proves the audit
        // row is written on the reconciliation transaction's own client, so a
        // promotion cannot commit without its event.
        if (sql.includes("INSERT INTO audit_events")) {
          state.audits.push({
            actorUserId: params[0],
            action: params[2],
            targetType: params[3],
            targetId: params[4],
            metadata: params[6],
            workspaceId: params[7],
          });
          return { rows: [] };
        }
        throw new Error(`unexpected query: ${sql}`);
      },
    };
    return { state, client };
  }

  // Token linking is exercised on its own in the inventory tests; here it is
  // stubbed so reconciliation assertions stay about promotion decisions.
  function stubLinkToken(calls) {
    return async (options) => {
      calls.push(options);
      return 77;
    };
  }

  // Renewal profile derivation has its own dedicated test file; here it is
  // stubbed so these assertions stay about what reconciliation feeds it.
  function stubEnsureRenewalProfile(calls) {
    return async (options) => {
      calls.push(options);
      return { profileId: null, created: false, reason: "stubbed" };
    };
  }

  it("promotes a provisioning certificate and backfills from evidence", async () => {
    const { state, client } = reconcileClient();
    const linkCalls = [];

    const result = await dispatch._test.reconcileProvisionedCertificate({
      client,
      workspaceId: WORKSPACE_A,
      job: jobFixture,
      linkToken: stubLinkToken(linkCalls),
    });

    assert.equal(result.certificateId, String(NEW_CERT_ID));
    assert.equal(result.promoted, true);
    // Two writes: the promotion, then the derivation decline. This fixture's
    // payload carries no caEndpoint/commandRef, so derivation legitimately
    // declines and must leave an actionable reconciliation_reason behind rather
    // than only a null profileId inside the ISSUED audit metadata.
    assert.equal(state.updates.length, 2);
    const params = state.updates[0];
    assert.equal(params[2], "a".repeat(64));
    assert.equal(params[3], "04AABB");
    assert.equal(params[4], "CN=web-01.example.com");
    assert.equal(params[5], "CN=Staging Fake LE");
    assert.equal(params[6], new Date("Jul 26 10:00:00 2026 GMT").toISOString());
    assert.equal(params[7], new Date("Oct 24 10:00:00 2026 GMT").toISOString());
    assert.equal(params[8], "web-01.example.com,alt.example.com");
    assert.equal(state.updates[1][2], "renewal_profile_derivation_failed");
    const declined = state.audits.find(
      (row) => row.action === "CERTOPS_RENEWAL_PROFILE_DERIVATION_DECLINED",
    );
    assert.ok(declined, "decline audit event expected");
    const declinedMetadata =
      typeof declined.metadata === "string"
        ? JSON.parse(declined.metadata)
        : declined.metadata;
    assert.equal(declinedMetadata.derivationReason, "derivation_failed");
    // The detail names the missing field so an operator can fix the payload,
    // and never carries a value that would disclose deployment topology.
    assert.ok(typeof declinedMetadata.detail === "string");
    // The promotion still happened: a certificate that genuinely exists is not
    // withheld because its renewal config could not be inferred.
    const issued = state.audits.find(
      (row) => row.action === "CERTOPS_CERTIFICATE_ISSUED",
    );
    assert.ok(issued, "issued audit event expected");
    const issuedMetadata =
      typeof issued.metadata === "string"
        ? JSON.parse(issued.metadata)
        : issued.metadata;
    assert.equal(issuedMetadata.profileId, null);
    assert.equal(issuedMetadata.profileDerivationReason, "derivation_failed");
  });

  it("only considers verify-step evidence bound to this claim", async () => {
    const { state, client } = reconcileClient();
    await dispatch._test.reconcileProvisionedCertificate({
      client,
      workspaceId: WORKSPACE_A,
      job: jobFixture,
      linkToken: stubLinkToken([]),
    });

    const query = state.evidenceQueries[0];
    // The ACME step also emits validation.passed; only the verify step has read
    // the deployed file back, so the discriminator is load-bearing.
    assert.match(query.sql, /metadata->>'step' = 'verify'/);
    assert.match(query.sql, /claim_id = \$3::uuid/);
    assert.equal(query.params[2], CLAIM_ID);
  });

  it("links the token only once a verified expiry is known", async () => {
    const { client } = reconcileClient();
    const linkCalls = [];

    await dispatch._test.reconcileProvisionedCertificate({
      client,
      workspaceId: WORKSPACE_A,
      job: jobFixture,
      linkToken: stubLinkToken(linkCalls),
    });

    assert.equal(linkCalls.length, 1);
    // tokens.expiration is DATE NOT NULL, so this is the earliest moment a
    // token can legitimately exist for this certificate.
    assert.equal(
      linkCalls[0].certificate.notAfter,
      new Date("Oct 24 10:00:00 2026 GMT").toISOString(),
    );
    assert.equal(linkCalls[0].certificate.fingerprintSha256, "a".repeat(64));
  });

  it("derives commonName from the certificate row, not agent evidence", async () => {
    // The agent's verify evidence only ever carries the raw X.509 "subject" DN
    // string (e.g. "CN=web-01.example.com"), never a parsed "commonName"
    // field. Before this fix, both linkToken and ensureRenewalProfile read
    // metadata.commonName, which is always undefined, so token linking lost
    // its commonName silently and profile derivation threw "Reconciled
    // certificate has no common name" on every real issuance -- the "headline
    // fix" of section 13.1 never actually fired outside its own unit tests.
    const { client } = reconcileClient({ commonName: "web-01.example.com" });
    const linkCalls = [];
    const profileCalls = [];

    await dispatch._test.reconcileProvisionedCertificate({
      client,
      workspaceId: WORKSPACE_A,
      job: jobFixture,
      linkToken: stubLinkToken(linkCalls),
      ensureRenewalProfile: stubEnsureRenewalProfile(profileCalls),
    });

    assert.equal(linkCalls[0].certificate.commonName, "web-01.example.com");
    assert.equal(profileCalls[0].certificate.commonName, "web-01.example.com");
  });

  it("is a no-op when the subject is already active", async () => {
    const { state, client } = reconcileClient({ provisioning: false });
    const result = await dispatch._test.reconcileProvisionedCertificate({
      client,
      workspaceId: WORKSPACE_A,
      job: jobFixture,
      linkToken: stubLinkToken([]),
    });
    assert.equal(result, null);
    assert.equal(state.updates.length, 0);
  });

  it("reconciles a plain renew retry against a still-provisioning subject", async () => {
    // The retry path after a failed issuance is an ordinary renew job. Keying
    // reconciliation on the subject's status rather than the operation is what
    // makes it converge with no special casing.
    const { state, client } = reconcileClient();
    const result = await dispatch._test.reconcileProvisionedCertificate({
      client,
      workspaceId: WORKSPACE_A,
      job: { ...jobFixture, operation: "renew" },
      linkToken: stubLinkToken([]),
    });
    assert.equal(result.promoted, true);
    // Promotion plus the derivation decline this fixture's payload earns.
    assert.equal(state.updates.length, 2);
  });

  it("does not promote on ACME-step evidence alone", async () => {
    // The ACME step proves the CA issued something, not that the right file is
    // on the host. Promoting here would record requested facts as observed ones.
    const { state, client } = reconcileClient({ evidenceRows: [] });
    const linkCalls = [];

    const result = await dispatch._test.reconcileProvisionedCertificate({
      client,
      workspaceId: WORKSPACE_A,
      job: jobFixture,
      linkToken: stubLinkToken(linkCalls),
    });

    assert.equal(result.promoted, false);
    assert.equal(result.reason, "no_claim_bound_verify_evidence");
    assert.equal(linkCalls.length, 0);
    // The reason is recorded so the operator sees why, rather than inferring it.
    assert.equal(state.updates.length, 1);
    assert.equal(state.updates[0][2], "no_claim_bound_verify_evidence");
  });

  it("does not promote when verify evidence has no fingerprint", async () => {
    const { client } = reconcileClient({
      metadata: { step: "verify", validTo: "Oct 24 10:00:00 2026 GMT" },
    });
    const result = await dispatch._test.reconcileProvisionedCertificate({
      client,
      workspaceId: WORKSPACE_A,
      job: jobFixture,
      linkToken: stubLinkToken([]),
    });
    assert.equal(result.promoted, false);
    assert.equal(result.reason, "verify_evidence_missing_fingerprint");
  });

  it("does not promote when verify evidence has no expiry", async () => {
    // Activating without an expiry produces a row that looks healthy and is
    // silently unmanaged: nothing can schedule its renewal or alert on it.
    const { client } = reconcileClient({
      metadata: { step: "verify", fingerprintSha256: "b".repeat(64) },
    });
    const result = await dispatch._test.reconcileProvisionedCertificate({
      client,
      workspaceId: WORKSPACE_A,
      job: jobFixture,
      linkToken: stubLinkToken([]),
    });
    assert.equal(result.promoted, false);
    assert.equal(result.reason, "verify_evidence_missing_expiry");
  });

  it("skips jobs with no managed_certificate subject", async () => {
    const { state, client } = reconcileClient();
    assert.equal(
      await dispatch._test.reconcileProvisionedCertificate({
        client,
        workspaceId: WORKSPACE_A,
        job: { ...jobFixture, subject_type: "external" },
      }),
      null,
    );
    assert.equal(
      await dispatch._test.reconcileProvisionedCertificate({
        client,
        workspaceId: WORKSPACE_A,
        job: { ...jobFixture, subject_id: null },
      }),
      null,
    );
    assert.equal(state.updates.length, 0);
  });

  it("skips a trust-anchor job (subject_type trust_anchor), even one that also carries operation distribute-trust", async () => {
    // By-construction exclusion (ADR-0012 decisions 4-6): a trust job's
    // subject_type is never 'managed_certificate', so it must never reach
    // the FOR UPDATE lock, the certificate promotion, or renewal-profile
    // derivation this function drives.
    const { state, client } = reconcileClient();
    const result = await dispatch._test.reconcileProvisionedCertificate({
      client,
      workspaceId: WORKSPACE_A,
      job: {
        ...jobFixture,
        operation: "distribute-trust",
        subject_type: "trust_anchor",
        subject_id: "anchor-1",
      },
    });
    assert.equal(result, null);
    assert.equal(state.updates.length, 0);
  });
});

describe("refreshRenewedCertificateEvidence (renewal of an already-active certificate)", () => {
  // reconcileProvisionedCertificate only ever locks rows WHERE status =
  // 'provisioning', so a plain renew succeeding against an already-'active'
  // certificate needs its own client shape: the managed_certificates lookup
  // must reflect that current status, distinctly from the "provisioning"
  // fixture above.
  const CLAIM_ID = "44444444-4444-4444-8444-444444444444";
  const ACTIVE_CERT_ID = "55555555-5555-4555-8555-555555555555";
  const jobFixture = {
    id: 99,
    operation: "renew",
    subject_type: "managed_certificate",
    subject_id: ACTIVE_CERT_ID,
    claim_id: CLAIM_ID,
  };
  const FRESH_VERIFY_METADATA = {
    step: "verify",
    fingerprintSha256: "c".repeat(64),
    serialNumber: "05CCDD",
    subject: "CN=web-01.example.com",
    issuer: "CN=Staging Fake LE",
    validFrom: "Sep 01 10:00:00 2026 GMT",
    validTo: "Nov 30 10:00:00 2026 GMT",
    subjectAltNames: "web-01.example.com",
  };

  function activeClient({ found = true, metadata = FRESH_VERIFY_METADATA, tokenId = null } = {}) {
    const state = { updates: [], audits: [], linkTokenCalls: [] };
    const client = {
      query: async (text, params) => {
        const sql = typeof text === "string" ? text : text?.text || "";
        if (sql.includes("FROM managed_certificates")) {
          return {
            rows: found
              ? [{ id: ACTIVE_CERT_ID, common_name: "web-01.example.com", token_id: tokenId }]
              : [],
          };
        }
        if (sql.includes("FROM certificate_evidence")) {
          return { rows: metadata ? [{ metadata }] : [] };
        }
        if (sql.includes("UPDATE managed_certificates")) {
          state.updates.push({ sql, params });
          return { rows: [] };
        }
        if (sql.includes("INSERT INTO audit_events")) {
          state.audits.push(params);
          return { rows: [] };
        }
        throw new Error(`unexpected query: ${sql}`);
      },
    };
    const linkToken = async (args) => {
      state.linkTokenCalls.push(args);
      return tokenId;
    };
    return { state, client, linkToken };
  }

  it("refreshes fingerprint and not_after from fresh verify evidence", async () => {
    const { state, client } = activeClient();
    const result = await dispatch._test.refreshRenewedCertificateEvidence({
      client,
      workspaceId: WORKSPACE_A,
      job: jobFixture,
    });

    assert.deepEqual(result, {
      certificateId: String(ACTIVE_CERT_ID),
      refreshed: true,
      fingerprintSha256: "c".repeat(64),
      notAfter: new Date("Nov 30 10:00:00 2026 GMT").toISOString(),
    });
    assert.equal(state.updates.length, 1);
    const params = state.updates[0].params;
    assert.equal(params[2], "c".repeat(64));
    assert.equal(params[8], "web-01.example.com");
  });

  // This is the exact regression this function exists to close: without it,
  // findCertificatesDueForRenewal's idempotency key (certificate id +
  // not_after) never changes after the first renewal, so every later sweep
  // collides with the already-succeeded job and automatic renewal only ever
  // fires once per certificate.
  it("is the only write path that advances not_after past the first reconciliation", async () => {
    const { state, client } = activeClient();
    await dispatch._test.refreshRenewedCertificateEvidence({
      client,
      workspaceId: WORKSPACE_A,
      job: jobFixture,
    });
    assert.equal(
      state.updates[0].params[7],
      new Date("Nov 30 10:00:00 2026 GMT").toISOString(),
    );
  });

  it("mirrors the refreshed facts to the linked token in the same transaction", async () => {
    // Without this, managed_certificates.not_after advances but
    // tokens.expiration (what the token-centric dashboard and token_expiry
    // alerts actually read) stays frozen at the pre-renewal date.
    const { state, client, linkToken } = activeClient({ tokenId: 4242 });
    await dispatch._test.refreshRenewedCertificateEvidence({
      client,
      workspaceId: WORKSPACE_A,
      job: jobFixture,
      linkToken,
    });
    assert.equal(state.linkTokenCalls.length, 1);
    assert.equal(state.linkTokenCalls[0].existingTokenId, 4242);
    assert.equal(
      state.linkTokenCalls[0].certificate.notAfter,
      new Date("Nov 30 10:00:00 2026 GMT").toISOString(),
    );
  });

  it("is a no-op when the certificate is not active (e.g. still provisioning)", async () => {
    const { state, client } = activeClient({ found: false });
    const result = await dispatch._test.refreshRenewedCertificateEvidence({
      client,
      workspaceId: WORKSPACE_A,
      job: jobFixture,
    });
    assert.equal(result, null);
    assert.equal(state.updates.length, 0);
  });

  it("does not overwrite a known-good row with incomplete evidence, and records why", async () => {
    const { state, client } = activeClient({
      metadata: { step: "verify", fingerprintSha256: "d".repeat(64) },
    });
    const result = await dispatch._test.refreshRenewedCertificateEvidence({
      client,
      workspaceId: WORKSPACE_A,
      job: jobFixture,
    });
    assert.equal(result.refreshed, false);
    assert.equal(result.reason, "verify_evidence_missing_expiry");
    assert.equal(
      state.updates.length,
      1,
      "the reconciliation_reason write still happens; only the not_after refresh is skipped",
    );
    assert.match(
      state.updates[0].sql || "",
      /reconciliation_reason/,
    );
    assert.equal(
      state.audits.length,
      1,
      "the failure must be durable and visible, not a silent no-op",
    );
    assert.equal(
      state.audits[0][2],
      "CERTOPS_CERTIFICATE_RENEWAL_UNRECONCILED",
    );
  });

  it("skips jobs with no managed_certificate subject", async () => {
    const { state, client } = activeClient();
    assert.equal(
      await dispatch._test.refreshRenewedCertificateEvidence({
        client,
        workspaceId: WORKSPACE_A,
        job: { ...jobFixture, subject_type: "external" },
      }),
      null,
    );
    assert.equal(state.updates.length, 0);
  });
});

describe("migration 33 issuance vocabulary", () => {
  const migration = migrations.find((entry) => entry.version === 33);

  it("exists and widens both managed_certificates constraints", () => {
    assert.ok(migration, "migration 33 expected");
    assert.match(migration.sql, /'provisioning'/);
    assert.match(migration.sql, /'agent_issuance'/);
    assert.match(migration.sql, /managed_certificates_status_check/);
    assert.match(migration.sql, /managed_certificates_source_check/);
  });

  it("keeps the earlier statuses and sources", () => {
    for (const value of [
      "discovered",
      "active",
      "renewing",
      "expiring",
      "expired",
      "revoked",
      "decommissioned",
    ]) {
      assert.match(migration.sql, new RegExp(`'${value}'`));
    }
    for (const value of ["manual", "cert_manager", "agent_filesystem"]) {
      assert.match(migration.sql, new RegExp(`'${value}'`));
    }
  });

  it("widens the partial unique indexes that enumerate sources", () => {
    // The service-layer ON CONFLICT predicates must keep matching these index
    // predicates exactly, or arbiter inference stops resolving.
    assert.match(
      migration.sql,
      /uq_managed_certificates_workspace_source_ref[\s\S]*agent_issuance/,
    );
    assert.match(
      migration.sql,
      /uq_managed_certificates_workspace_fingerprint_import[\s\S]*agent_issuance/,
    );
  });
});

describe("migration 34 issue job operation", () => {
  const migration = migrations.find((entry) => entry.version === 34);

  it("widens certificate_jobs.operation to accept issue", () => {
    // Regression: migration 33 taught managed_certificates about issuance but
    // left this constraint alone, so every issue request failed at COMMIT with
    // an opaque HTTP 500. The unit tests could not see it because they stub the
    // database; only live testing against a real stack caught it.
    assert.ok(migration, "migration 34 expected");
    assert.match(migration.sql, /certificate_jobs_operation_check/);
    assert.match(migration.sql, /'issue'/);
  });

  it("keeps every previously accepted operation", () => {
    for (const value of ["renew", "deploy", "reload", "revoke", "noop"]) {
      assert.match(migration.sql, new RegExp(`'${value}'`));
    }
  });

  it("accepts exactly the operations the service layer declared at the time (later widened by migration 42 for trust-anchor operations)", () => {
    const declared = migration.sql.match(/operation IN \(([^)]+)\)/);
    assert.ok(declared, "operation IN (...) list expected");
    const values = declared[1]
      .split(",")
      .map((entry) => entry.trim().replace(/^'|'$/g, ""));
    const operationsAsOfMigration34 = JOB_OPERATIONS.filter(
      (operation) => !isTrustAnchorOperation(operation),
    );
    assert.deepEqual(
      [...values].sort(),
      [...operationsAsOfMigration34].sort(),
    );
  });
});
