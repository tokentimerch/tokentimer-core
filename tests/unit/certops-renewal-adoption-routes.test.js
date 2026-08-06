"use strict";

/**
 * HTTP surface for adopting a certificate into automatic renewal: the refusals
 * the adoption route turns into status codes, the detach and retry responses,
 * the redaction the renewalSetup projection performs, and the controller
 * cluster binding the token projection must not drop.
 */

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const certOpsRouter = require(
  path.resolve(__dirname, "../../apps/api/routes/certops.js"),
);
const servicePath = (name) =>
  path.resolve(__dirname, "../../apps/api/services/certops", name);

const {
  RENEWAL_SETUP_OUTCOME_CODES,
  loadResumablePreflights,
  projectRenewalPreflight,
  projectRenewalSetupState,
  renewalSetupJobCreator,
} = require(servicePath("renewalAdoption.js"));

const {
  apiTokenMetadata,
  handleCertOpsError,
  projectRenewalSetupState: routeProjection,
  withRenewalState,
} = certOpsRouter._test;

const WORKSPACE = "11111111-1111-4111-8111-111111111111";
const CERT_ID = "22222222-2222-4222-8222-222222222222";
const JOB_ID = "44444444-4444-4444-8444-444444444444";
const OUTBOX_ID = "55555555-5555-4555-8555-555555555555";

// A pg error message of the shape last_error actually stores: driver prefix,
// schema-qualified relation, constraint name. None of it may reach a response.
const DRIVER_SHAPED_ERROR =
  'error: duplicate key value violates unique constraint "certificate_profiles_workspace_id_name_key" DETAIL: Key (workspace_id, name)=(11111111-1111-4111-8111-111111111111, derived-app) already exists.';

function normalize(sql) {
  return String(sql).replace(/\s+/g, " ").trim();
}

function recordingClient(handler) {
  const queries = [];
  return {
    queries,
    async query(text, params = []) {
      const sql = normalize(typeof text === "string" ? text : text?.text || "");
      queries.push({ sql, params });
      if (["BEGIN", "COMMIT", "ROLLBACK"].includes(sql)) return { rows: [] };
      return handler(sql, params) || { rows: [], rowCount: 1 };
    },
  };
}

function certificateRow(overrides = {}) {
  return {
    id: CERT_ID,
    status: "active",
    key_mode: "agent-local",
    profile_id: null,
    deployed_cert_path: "/etc/ssl/certs/app.pem",
    deployed_agent_id: "agent-1",
    ...overrides,
  };
}

/**
 * A client that answers the jobCreator's own certificate lock and lets the
 * location count run its real SQL against a caller-supplied instance table.
 */
function adoptionClient({ certificate = certificateRow(), instances = [] }) {
  return recordingClient((sql, params) => {
    if (sql.startsWith("SELECT id, status, key_mode, profile_id")) {
      return { rows: certificate ? [certificate] : [] };
    }
    if (sql.startsWith("SELECT COUNT(DISTINCT ci.target_id)")) {
      const [, , sources, retired] = params;
      const live = instances.filter(
        (row) =>
          sources.includes(row.source) && !retired.includes(row.status),
      );
      const locations = new Set(live.map((row) => row.target_id)).size;
      return { rows: [{ locations }] };
    }
    throw new Error(`Unexpected query: ${sql}`);
  });
}

function responseRecorder() {
  return {
    statusCode: null,
    body: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(body) {
      this.body = body;
      return this;
    },
  };
}

/**
 * Runs the adoption jobCreator and maps whatever it throws through the route's
 * own error handler, so the assertion is on the status code an operator sees
 * rather than on an internal error object.
 */
async function adoptAndMapErrors({ client, mode, createJob, enqueueIntent }) {
  const creator = renewalSetupJobCreator({
    certificateId: CERT_ID,
    createJob:
      createJob ||
      (async (options) => ({
        created: true,
        job: { id: JOB_ID, mode: options.mode || "live" },
      })),
    enqueueIntent: enqueueIntent || (async () => ({ enqueued: true })),
  });

  try {
    const outcome = await creator({
      client,
      workspaceId: WORKSPACE,
      ...(mode ? { mode } : {}),
    });
    return { outcome, response: null };
  } catch (err) {
    const res = responseRecorder();
    const handled = handleCertOpsError(res, err);
    assert.ok(handled, `handleCertOpsError did not map ${err.code}`);
    return { outcome: null, response: res };
  }
}

describe("CertOps adoption route refusals", () => {
  it("refuses a certificate deployed in more than one location with 409", async () => {
    const client = adoptionClient({
      instances: [
        { target_id: "target-a", source: "agent_filesystem", status: "active" },
        { target_id: "target-b", source: "agent_filesystem", status: "active" },
      ],
    });

    const { outcome, response } = await adoptAndMapErrors({ client });

    assert.equal(outcome, null);
    assert.equal(response.statusCode, 409);
    assert.equal(
      response.body.code,
      "CERTOPS_RENEWAL_SETUP_MULTI_LOCATION",
    );
    assert.match(response.body.error, /2 locations/);
  });

  it("allows a single-location certificate that has several rotation rows", async () => {
    // Same target, three fingerprints: certificate_instances appends a row per
    // rotation, so counting rows instead of distinct targets would refuse an
    // ordinary certificate that has simply been renewed a few times.
    const client = adoptionClient({
      instances: [
        { target_id: "target-a", source: "agent_filesystem", status: "active" },
        { target_id: "target-a", source: "agent_filesystem", status: "active" },
        { target_id: "target-a", source: "agent_filesystem", status: "active" },
      ],
    });

    const enqueued = [];
    const { outcome, response } = await adoptAndMapErrors({
      client,
      enqueueIntent: async (args) => {
        enqueued.push(args);
        return { enqueued: true };
      },
    });

    assert.equal(response, null);
    assert.equal(outcome.job.id, JOB_ID);
    assert.equal(enqueued.length, 1);
    assert.equal(enqueued[0].certificateId, CERT_ID);
    assert.equal(enqueued[0].jobId, JOB_ID);
  });

  it("ignores retired and observation-only rows when counting locations", async () => {
    const client = adoptionClient({
      instances: [
        { target_id: "target-a", source: "agent_filesystem", status: "active" },
        { target_id: "target-b", source: "agent_filesystem", status: "missing" },
        { target_id: "target-c", source: "tls_probe", status: "active" },
      ],
    });

    const { outcome, response } = await adoptAndMapErrors({ client });

    assert.equal(response, null);
    assert.ok(outcome.job);
  });

  it("refuses a key mode no agent can deploy to with 409", async () => {
    const client = adoptionClient({
      certificate: certificateRow({ key_mode: "vault-managed" }),
    });

    const { response } = await adoptAndMapErrors({ client });

    assert.equal(response.statusCode, 409);
    assert.equal(
      response.body.code,
      "CERTOPS_CERTIFICATE_NOT_AGENT_DEPLOYABLE",
    );
  });

  it("adopts an os-store-managed certificate now that the Windows executor exists", async () => {
    // Historically this stayed refused with 409 pending the real Windows
    // store/site/binding execution path; that executor now exists
    // (packages/agent/src/index.js's executeWindowsIisRenewJob), so
    // os-store-managed is agent-deployable and adoption proceeds like any
    // other agent-managed key mode.
    const client = adoptionClient({
      certificate: certificateRow({ key_mode: "os-store-managed" }),
    });

    const enqueued = [];
    const { outcome, response } = await adoptAndMapErrors({
      client,
      enqueueIntent: async (args) => {
        enqueued.push(args);
        return { enqueued: true };
      },
    });

    assert.equal(response, null);
    assert.equal(outcome.job.id, JOB_ID);
    assert.equal(enqueued.length, 1);
  });

  it("refuses a certificate that already has a renewal profile with 409", async () => {
    const client = adoptionClient({
      certificate: certificateRow({ profile_id: "profile-1" }),
    });

    const { response } = await adoptAndMapErrors({ client });

    assert.equal(response.statusCode, 409);
    assert.equal(
      response.body.code,
      "CERTOPS_RENEWAL_SETUP_ALREADY_CONFIGURED",
    );
  });

  it("refuses a certificate with no recorded deployment path with 422", async () => {
    const client = adoptionClient({
      certificate: certificateRow({ deployed_cert_path: null }),
    });

    const { response } = await adoptAndMapErrors({ client });

    assert.equal(response.statusCode, 422);
    assert.equal(
      response.body.code,
      "CERTOPS_RENEWAL_SETUP_NO_DEPLOYED_PATH",
    );
  });

  it("returns 404 for a certificate that is not in this workspace", async () => {
    const client = adoptionClient({ certificate: null });

    const { response } = await adoptAndMapErrors({ client });

    assert.equal(response.statusCode, 404);
    assert.equal(response.body.code, "CERTOPS_CERTIFICATE_NOT_FOUND");
  });

  it("creates no intent row for a dry-run preflight", async () => {
    const client = adoptionClient({
      instances: [
        { target_id: "target-a", source: "agent_filesystem", status: "active" },
      ],
    });

    const enqueued = [];
    const { outcome, response } = await adoptAndMapErrors({
      client,
      mode: "dry_run",
      enqueueIntent: async (args) => {
        enqueued.push(args);
        return { enqueued: true };
      },
    });

    assert.equal(response, null);
    assert.equal(outcome.job.mode, "dry_run");
    assert.deepEqual(enqueued, []);
  });

  it("creates no second intent when job creation replayed an existing job", async () => {
    const client = adoptionClient({
      instances: [
        { target_id: "target-a", source: "agent_filesystem", status: "active" },
      ],
    });

    const enqueued = [];
    const { response } = await adoptAndMapErrors({
      client,
      createJob: async () => ({
        created: false,
        job: { id: JOB_ID, mode: "live" },
      }),
      enqueueIntent: async (args) => {
        enqueued.push(args);
        return { enqueued: true };
      },
    });

    assert.equal(response, null);
    assert.deepEqual(enqueued, []);
  });
});

describe("CertOps renewalSetup projection redaction", () => {
  const intentRow = (overrides = {}) => ({
    id: OUTBOX_ID,
    job_id: JOB_ID,
    status: "failed",
    attempt_count: 5,
    outcome_reason: null,
    last_error: DRIVER_SHAPED_ERROR,
    ...overrides,
  });

  it("never returns a driver-shaped last_error verbatim or in fragments", () => {
    const projected = projectRenewalSetupState(intentRow());
    const serialized = JSON.stringify(projected);

    assert.doesNotMatch(serialized, /duplicate key value/);
    assert.doesNotMatch(serialized, /certificate_profiles_workspace_id_name_key/);
    assert.doesNotMatch(serialized, /DETAIL/);
    assert.equal(serialized.includes(DRIVER_SHAPED_ERROR), false);
    // Nothing in the response may be a substring of the stored text either: a
    // truncated echo would still be an echo.
    assert.equal(DRIVER_SHAPED_ERROR.includes(projected.message), false);
  });

  it("reports an unrecognised failure as the generic derivation failure", () => {
    const projected = projectRenewalSetupState(intentRow());

    assert.equal(projected.state, "failed");
    assert.equal(
      projected.outcomeCode,
      RENEWAL_SETUP_OUTCOME_CODES.DERIVATION_FAILED,
    );
    assert.equal(projected.attempts, 5);
    assert.equal(projected.jobId, JOB_ID);
    assert.ok(projected.message.length > 0);
  });

  it("names the missing setting for each incomplete-profile signature", () => {
    const cases = [
      [
        "Issue job payload has no caEndpoint, so the renewal CA is unknown",
        /CA endpoint/,
      ],
      [
        "Issue job payload has no commandRef, so the ACME command profile is unknown",
        /ACME command profile/,
      ],
      [
        "Issue job payload has no dnsProvider/dnsZone, so DNS-01 renewal cannot be reproduced",
        /DNS provider and zone/,
      ],
      [
        "Issue job payload has no certPath, so the renewal has no deployment destination",
        /deployment path/,
      ],
      ["Reconciled certificate has no common name", /common name/],
    ];

    for (const [lastError, expected] of cases) {
      const projected = projectRenewalSetupState(intentRow({ last_error: lastError }));
      assert.equal(
        projected.outcomeCode,
        RENEWAL_SETUP_OUTCOME_CODES.PROFILE_INCOMPLETE,
        lastError,
      );
      assert.match(projected.message, expected);
    }
  });

  it("classifies a refused profile as invalid rather than incomplete", () => {
    const projected = projectRenewalSetupState(
      intentRow({ last_error: "renewalProfile.sanPolicy.mode is invalid" }),
    );

    assert.equal(
      projected.outcomeCode,
      RENEWAL_SETUP_OUTCOME_CODES.PROFILE_INVALID,
    );
    // The refused field name is not echoed: the authored text explains the
    // class of problem without carrying any of the stored string.
    assert.doesNotMatch(projected.message, /sanPolicy/);
  });

  it("maps each handler skip reason to an authored message", () => {
    for (const reason of Object.values(RENEWAL_SETUP_OUTCOME_CODES)) {
      if (
        reason === RENEWAL_SETUP_OUTCOME_CODES.PROFILE_INCOMPLETE ||
        reason === RENEWAL_SETUP_OUTCOME_CODES.PROFILE_INVALID ||
        reason === RENEWAL_SETUP_OUTCOME_CODES.DERIVATION_FAILED
      ) {
        continue;
      }
      const projected = projectRenewalSetupState(
        intentRow({ status: "skipped", outcome_reason: reason, last_error: null }),
      );
      assert.equal(projected.state, "skipped", reason);
      assert.equal(projected.outcomeCode, reason);
      assert.ok(projected.message && projected.message.length > 0, reason);
    }
  });

  it("reports an outcome_reason outside the vocabulary as unknown", () => {
    // outcome_reason is free text at the database level, so an unrecognised
    // value must not be forwarded on the assumption the drain wrote it.
    const projected = projectRenewalSetupState(
      intentRow({
        status: "skipped",
        outcome_reason: "ERROR: relation \"certops_outbox\" does not exist",
        last_error: null,
      }),
    );

    assert.equal(projected.outcomeCode, RENEWAL_SETUP_OUTCOME_CODES.UNKNOWN);
    assert.doesNotMatch(JSON.stringify(projected), /relation/);
  });

  it("offers an intentId only while the intent is retryable", () => {
    assert.equal(projectRenewalSetupState(intentRow()).intentId, OUTBOX_ID);

    for (const status of ["pending", "succeeded"]) {
      assert.equal(
        projectRenewalSetupState(intentRow({ status })).intentId,
        null,
        status,
      );
    }
    // A detach is the decision this rule exists for: surfacing a retry action
    // would invite the UI to offer re-linking a deliberately detached cert.
    assert.equal(
      projectRenewalSetupState(
        intentRow({
          status: "skipped",
          outcome_reason: RENEWAL_SETUP_OUTCOME_CODES.DETACHED,
        }),
      ).intentId,
      null,
    );
  });

  it("reports none, waiting and configured without an outcome", () => {
    assert.deepEqual(projectRenewalSetupState(null), {
      state: "none",
      jobId: null,
      attempts: 0,
      outcomeCode: null,
      message: null,
      intentId: null,
    });

    const waiting = projectRenewalSetupState(
      intentRow({ status: "pending", attempt_count: 1, last_error: null }),
    );
    assert.equal(waiting.state, "waiting");
    assert.equal(waiting.outcomeCode, null);
    assert.equal(waiting.message, null);

    const configured = projectRenewalSetupState(
      intentRow({ status: "succeeded", last_error: null }),
    );
    assert.equal(configured.state, "configured");
    assert.equal(configured.outcomeCode, null);
  });

  it("is the same function the route projects with", () => {
    assert.equal(routeProjection, projectRenewalSetupState);
  });
});

describe("CertOps detach route", () => {
  const detachClient = ({ profileId = "profile-1", intents = [OUTBOX_ID] } = {}) =>
    recordingClient((sql) => {
      if (sql.startsWith("SELECT mc.id, mc.common_name")) {
        return {
          rows: [
            {
              id: CERT_ID,
              common_name: "app.example.com",
              profile_id: profileId,
              profile_name: "web-tls",
            },
          ],
        };
      }
      if (sql.startsWith("SELECT id FROM certops_outbox")) {
        return { rows: intents.map((id) => ({ id })) };
      }
      return { rows: [], rowCount: 1 };
    });

  it("nulls the link and invalidates outstanding intents in one transaction", async () => {
    const { detachRenewalProfile } = require(servicePath("renewalAdoption.js"));
    const client = detachClient();
    const audits = [];

    const result = await detachRenewalProfile({
      dbPool: { async connect() { return { ...client, release() {} }; } },
      workspaceId: WORKSPACE,
      certificateId: CERT_ID,
      actorUserId: 42,
      auditWriter: async (entry) => {
        audits.push(entry);
      },
    });

    assert.equal(result.certificateId, CERT_ID);
    assert.equal(result.detachedProfileId, "profile-1");
    assert.equal(result.invalidatedIntents, 1);

    const sqls = client.queries.map((q) => q.sql);
    assert.equal(sqls[0], "BEGIN");
    assert.equal(sqls[sqls.length - 1], "COMMIT");
    assert.ok(
      sqls.some((sql) => /UPDATE managed_certificates SET profile_id = NULL/.test(sql)),
    );
    // The profile row survives: one profile can cover several certificates, so
    // deleting it would silently change what runs for a sibling.
    assert.equal(
      sqls.some((sql) => /DELETE FROM certificate_profiles/.test(sql)),
      false,
    );
    assert.ok(sqls.some((sql) => /UPDATE certops_outbox/.test(sql)));

    assert.equal(audits.length, 1);
    assert.equal(audits[0].action, "CERTOPS_RENEWAL_PROFILE_DETACHED");
    assert.equal(audits[0].metadata.invalidatedIntents, 1);
  });

  it("refuses a certificate with nothing to detach as 422", async () => {
    const { detachRenewalProfile } = require(servicePath("renewalAdoption.js"));
    const client = detachClient({ profileId: null });

    const res = responseRecorder();
    await assert.rejects(
      detachRenewalProfile({
        dbPool: { async connect() { return { ...client, release() {} }; } },
        workspaceId: WORKSPACE,
        certificateId: CERT_ID,
        auditWriter: async () => {},
      }),
      (err) => {
        assert.ok(handleCertOpsError(res, err));
        return true;
      },
    );

    assert.equal(res.statusCode, 422);
    assert.equal(res.body.code, "CERTOPS_CERTIFICATE_NOT_PROFILED");
    assert.equal(
      client.queries.some((q) => q.sql === "COMMIT"),
      false,
    );
  });

  it("is gated by a session user, so worker credentials are refused", () => {
    const { requireCertOpsSessionUser } = certOpsRouter._test;

    const res = responseRecorder();
    let advanced = false;
    requireCertOpsSessionUser(
      { isWorkerCall: true, workspace: { id: WORKSPACE } },
      res,
      () => {
        advanced = true;
      },
    );

    assert.equal(advanced, false);
    assert.equal(res.statusCode, 403);
    assert.equal(res.body.code, "INSUFFICIENT_ROLE");
  });
});

describe("CertOps renewal-setup retry route", () => {
  const { retryRenewalSetupIntent } = require(servicePath("renewalAdoption.js"));

  function retryPool({ status, eventType = "profile_derivation_requested" }) {
    return recordingClient((sql) => {
      if (sql.startsWith("SELECT event_type FROM certops_outbox")) {
        return { rows: eventType ? [{ event_type: eventType }] : [] };
      }
      if (sql.startsWith("SELECT id, status, event_type")) {
        return { rows: [{ id: OUTBOX_ID, status, event_type: eventType }] };
      }
      if (sql.startsWith("UPDATE certops_outbox")) {
        return status === "failed"
          ? {
              rows: [
                {
                  id: OUTBOX_ID,
                  event_type: eventType,
                  status: "pending",
                  attempt_count: 0,
                },
              ],
            }
          : { rows: [] };
      }
      throw new Error(`Unexpected query: ${sql}`);
    });
  }

  it("resets a failed intent to pending with a fresh attempt budget", async () => {
    const result = await retryRenewalSetupIntent({
      dbPool: retryPool({ status: "failed" }),
      workspaceId: WORKSPACE,
      outboxId: OUTBOX_ID,
    });

    assert.equal(result.id, OUTBOX_ID);
    assert.equal(result.status, "pending");
    assert.equal(result.attemptCount, 0);
  });

  it("refuses a skipped intent as 422, which is what a detach records", async () => {
    const res = responseRecorder();
    await assert.rejects(
      retryRenewalSetupIntent({
        dbPool: retryPool({ status: "skipped" }),
        workspaceId: WORKSPACE,
        outboxId: OUTBOX_ID,
      }),
      (err) => {
        assert.ok(handleCertOpsError(res, err));
        return true;
      },
    );

    assert.equal(res.statusCode, 422);
    assert.equal(res.body.code, "CERTOPS_OUTBOX_EVENT_NOT_RETRYABLE");
    assert.match(res.body.error, /skipped/);
  });

  it("refuses a succeeded or still-pending intent as 422", async () => {
    for (const status of ["succeeded", "pending"]) {
      const res = responseRecorder();
      await assert.rejects(
        retryRenewalSetupIntent({
          dbPool: retryPool({ status }),
          workspaceId: WORKSPACE,
          outboxId: OUTBOX_ID,
        }),
        (err) => {
          assert.ok(handleCertOpsError(res, err));
          return true;
        },
      );
      assert.equal(res.statusCode, 422, status);
      assert.equal(res.body.code, "CERTOPS_OUTBOX_EVENT_NOT_RETRYABLE", status);
    }
  });

  it("returns 404 for an intent that is not in this workspace", async () => {
    const res = responseRecorder();
    await assert.rejects(
      retryRenewalSetupIntent({
        dbPool: retryPool({ status: "failed", eventType: null }),
        workspaceId: WORKSPACE,
        outboxId: OUTBOX_ID,
      }),
      (err) => {
        assert.ok(handleCertOpsError(res, err));
        return true;
      },
    );

    assert.equal(res.statusCode, 404);
    assert.equal(res.body.code, "CERTOPS_OUTBOX_EVENT_NOT_FOUND");
  });

  it("refuses an outbox row of a different event type", async () => {
    // The id comes from a URL, so a caller could name any outbox row in the
    // workspace; this route only ever decides derivation intents.
    const res = responseRecorder();
    await assert.rejects(
      retryRenewalSetupIntent({
        dbPool: retryPool({ status: "failed", eventType: "job_result_recorded" }),
        workspaceId: WORKSPACE,
        outboxId: OUTBOX_ID,
      }),
      (err) => {
        assert.ok(handleCertOpsError(res, err));
        return true;
      },
    );

    assert.equal(res.statusCode, 422);
    assert.equal(res.body.code, "CERTOPS_OUTBOX_EVENT_NOT_RETRYABLE");
  });
});

describe("CertOps preflight resumability", () => {
  it("reports a completed dry run with no intent behind it", async () => {
    const completedAt = new Date("2026-07-20T10:00:00.000Z");
    const db = recordingClient(() => ({
      rows: [
        {
          certificate_id: CERT_ID,
          id: JOB_ID,
          status: "dry_run_complete",
          completed_at: completedAt,
          created_at: completedAt,
        },
      ],
    }));

    const byId = await loadResumablePreflights({
      db,
      workspaceId: WORKSPACE,
      certificateIds: [CERT_ID],
    });

    const sql = db.queries[0].sql;
    // dry_run_complete, not succeeded: a preflight never reports success, so a
    // filter on 'succeeded' would find nothing to resume from.
    assert.deepEqual(db.queries[0].params[2], "dry_run_complete");
    assert.deepEqual(db.queries[0].params[3], "profile_derivation_requested");
    assert.match(sql, /NOT EXISTS/);
    assert.match(sql, /FROM certops_outbox/);

    assert.deepEqual(projectRenewalPreflight(byId.get(CERT_ID)), {
      available: true,
      jobId: JOB_ID,
      completedAt: "2026-07-20T10:00:00.000Z",
    });
  });

  it("reports nothing to resume when no preflight row matched", async () => {
    assert.deepEqual(projectRenewalPreflight(null), {
      available: false,
      jobId: null,
      completedAt: null,
    });
  });

  it("does not query when there are no certificates to check", async () => {
    let called = false;
    const db = {
      async query() {
        called = true;
        return { rows: [] };
      },
    };

    assert.equal(
      (await loadResumablePreflights({ db, workspaceId: WORKSPACE, certificateIds: [] })).size,
      0,
    );
    assert.equal(called, false);
  });

  it("is projected on the detail response and left off list responses", async () => {
    const db = recordingClient((sql) => {
      if (sql.includes("LEFT JOIN certificate_profiles")) {
        return { rows: [] };
      }
      if (sql.startsWith("SELECT DISTINCT ON (j.subject_id)")) {
        return {
          rows: [
            {
              certificate_id: CERT_ID,
              id: JOB_ID,
              status: "dry_run_complete",
              completed_at: new Date("2026-07-20T10:00:00.000Z"),
              created_at: new Date("2026-07-20T10:00:00.000Z"),
            },
          ],
        };
      }
      return { rows: [] };
    });

    const certificates = [{ id: CERT_ID, status: "active", keyMode: "agent-local" }];

    const [detail] = await withRenewalState({
      db,
      workspaceId: WORKSPACE,
      certificates,
      includePreflight: true,
    });
    assert.equal(detail.renewalPreflight.available, true);
    assert.equal(detail.renewalPreflight.jobId, JOB_ID);

    const [listed] = await withRenewalState({
      db,
      workspaceId: WORKSPACE,
      certificates,
    });
    assert.equal("renewalPreflight" in listed, false);
    assert.ok(listed.renewalSetup);
  });
});

describe("CertOps API token metadata", () => {
  it("projects the controller cluster binding a controller token is unusable without", () => {
    const metadata = apiTokenMetadata({
      id: "token-1",
      workspaceId: WORKSPACE,
      name: "cert-manager controller",
      tokenPrefix: "tt_certops_",
      scopes: ["certops:provision:execute"],
      controllerClusterId: "cluster-a",
      status: "active",
      expiresAt: null,
      lastUsedAt: null,
      revokedAt: null,
      createdAt: "2026-07-01T00:00:00.000Z",
      updatedAt: "2026-07-01T00:00:00.000Z",
    });

    assert.equal(metadata.controllerClusterId, "cluster-a");
  });

  it("reports an unbound token's binding as null rather than omitting it", () => {
    // An absent key and an explicit null are different answers to "which
    // cluster is this bound to"; only the second one is honest.
    const metadata = apiTokenMetadata({
      id: "token-2",
      workspaceId: WORKSPACE,
      name: "read only",
      tokenPrefix: "tt_certops_",
      scopes: ["certops:read"],
      status: "active",
    });

    assert.equal("controllerClusterId" in metadata, true);
    assert.equal(metadata.controllerClusterId, null);
  });

  it("never projects token material", () => {
    const metadata = apiTokenMetadata({
      id: "token-3",
      workspaceId: WORKSPACE,
      name: "controller",
      tokenPrefix: "tt_certops_",
      scopes: ["certops:observations:write"],
      controllerClusterId: "cluster-a",
      status: "active",
      token: "tt_certops_supersecretvalue",
      tokenHash: "deadbeef",
    });

    assert.equal("token" in metadata, false);
    assert.equal("tokenHash" in metadata, false);
  });
});
