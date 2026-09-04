"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  AUTO_RENEW_DISABLED_PROFILE_STATUSES,
  DEFAULT_RENEWAL_PER_CA_CAP,
  DEFAULT_RENEWAL_THRESHOLD_DAYS,
  UNKNOWN_CA_BUCKET,
  caCapKey,
  certificateCaBucket,
  countInFlightRenewalJobsByCaEndpoint,
  findCertificatesDueForRenewal,
  renewalIdempotencyKey,
  resolveRenewalPerCaCap,
  resolveRenewalThresholdDays,
  runRenewalSchedulerSweep,
} = require(
  path.resolve(
    __dirname,
    "../../apps/api/services/certops/renewalScheduler.js",
  ),
);
const {
  CERTOPS_WORKSPACE_PAUSED,
} = require(
  path.resolve(
    __dirname,
    "../../apps/api/services/certops/workspaceKillSwitch.js",
  ),
);
const {
  CERTOPS_DISABLED,
} = require(
  path.resolve(__dirname, "../../apps/api/services/certops/settings.js"),
);
const {
  RENEWAL_PROFILE_SCHEMA_VERSION,
} = require(
  path.resolve(
    __dirname,
    "../../apps/api/services/certops/renewalProfile.js",
  ),
);
const {
  isTrustAnchorOperation,
} = require(
  path.resolve(__dirname, "../../apps/api/services/certops/jobs.js"),
);

function normalizeSql(sql) {
  return String(sql).replace(/\s+/g, " ").trim();
}

const NOT_AFTER = new Date("2026-08-01T00:00:00.000Z");

function completeRenewalProfile(overrides = {}) {
  return {
    schemaVersion: RENEWAL_PROFILE_SCHEMA_VERSION,
    sanPolicy: {
      mode: "exact",
      sans: ["app.example.com"],
      allowWildcards: false,
    },
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
        reloadService: "nginx",
      },
    ],
    target: {
      type: "endpoint",
      reference: "host/web",
      certPath: "/etc/ssl/certs/app.pem",
    },
    verification: { host: "app.example.com", port: 443, requireMatch: true },
    ...overrides,
  };
}

function dueCertificate(overrides = {}) {
  const { renewalProfileOverrides, ...rest } = overrides;
  const profile = completeRenewalProfile(renewalProfileOverrides || {});
  return {
    id: "cert-1",
    workspace_id: "ws-1",
    common_name: "app.example.com",
    subject_alt_names: ["app.example.com"],
    not_after: NOT_AFTER,
    key_mode: null,
    profile_id: "profile-1",
    profile_name: "web-tls",
    profile_key_mode: null,
    profile_renew_before_days: null,
    certificate_ca_endpoint: null,
    profile_ca_endpoint: profile.ca.endpoint,
    profile_public_metadata: { renewalProfile: profile },
    ...rest,
    profile_public_metadata:
      rest.profile_public_metadata || { renewalProfile: profile },
  };
}

/**
 * Fake pool whose connect() yields transaction-recording clients. The scan
 * query result is injectable; workspace pause state controls the FOR SHARE
 * gate inside lockWorkspaceForCertOpsSideEffect. The per-CA in-flight count
 * query is dispatched separately so tests can seed pre-existing in-flight
 * jobs per CA bucket.
 */
function createSchedulerPool({
  dueRows = [],
  inFlightRows = [],
  pausedWorkspaces = new Set(),
  requireApprovalAlwaysWorkspaces = new Set(),
  autoRenewDisabledCount = 0,
} = {}) {
  const clients = [];
  const scanQueries = [];
  const pool = {
    clients,
    scanQueries,
    async query(sql, params) {
      const normalized = normalizeSql(sql);
      scanQueries.push({ sql: normalized, params });
      // Checked before the generic COUNT(*) branch: the auto-renew-disabled
      // count is also a COUNT(*) query, so ordering here matters.
      if (normalized.includes("disabled_count")) {
        return { rows: [{ disabled_count: autoRenewDisabledCount }] };
      }
      if (normalized.includes("COUNT(*)")) {
        return { rows: inFlightRows };
      }
      return { rows: dueRows };
    },
    async connect() {
      const client = {
        released: false,
        queries: [],
        async query(sql, params = []) {
          const normalized = normalizeSql(sql);
          this.queries.push({ sql: normalized, params });
          if (
            normalized === "BEGIN" ||
            normalized === "COMMIT" ||
            normalized === "ROLLBACK"
          ) {
            return { rows: [] };
          }
          if (normalized.includes("pg_try_advisory_lock")) {
            return { rows: [{ acquired: true }] };
          }
          if (normalized.includes("pg_advisory_unlock")) {
            return { rows: [{ pg_advisory_unlock: true }] };
          }
          if (
            normalized.startsWith(
              "SELECT id, certops_paused, certops_require_approval_always FROM workspaces",
            )
          ) {
            return {
              rows: [
                {
                  id: params[0],
                  certops_paused: pausedWorkspaces.has(params[0]),
                  certops_require_approval_always: requireApprovalAlwaysWorkspaces.has(
                    params[0],
                  ),
                },
              ],
            };
          }
          if (normalized.includes("system_settings")) {
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

describe("certops renewal scheduler", () => {
  it("resolves the renewal threshold from env with a 30 day default", () => {
    assert.strictEqual(resolveRenewalThresholdDays({}), 30);
    assert.strictEqual(DEFAULT_RENEWAL_THRESHOLD_DAYS, 30);
    assert.strictEqual(
      resolveRenewalThresholdDays({ CERTOPS_RENEWAL_THRESHOLD_DAYS: "14" }),
      14,
    );
    assert.strictEqual(
      resolveRenewalThresholdDays({ CERTOPS_RENEWAL_THRESHOLD_DAYS: "0" }),
      30,
    );
    assert.strictEqual(
      resolveRenewalThresholdDays({ CERTOPS_RENEWAL_THRESHOLD_DAYS: "junk" }),
      30,
    );
  });

  it("derives a stable idempotency key from cert id and not_after", () => {
    const first = renewalIdempotencyKey("cert-1", NOT_AFTER);
    const second = renewalIdempotencyKey("cert-1", NOT_AFTER.toISOString());
    assert.strictEqual(first, second);
    assert.strictEqual(first, `certops-renewal:cert-1:${NOT_AFTER.getTime()}`);

    const nextWindow = renewalIdempotencyKey(
      "cert-1",
      new Date("2026-11-01T00:00:00.000Z"),
    );
    assert.notStrictEqual(first, nextWindow);
  });

  it("dedupes against open renew jobs via NOT EXISTS on non-terminal statuses", async () => {
    const pool = createSchedulerPool({ dueRows: [] });

    await findCertificatesDueForRenewal({
      db: pool,
      thresholdDays: 30,
      terminalStatuses: ["succeeded", "failed"],
    });

    assert.strictEqual(pool.scanQueries.length, 1);
    const { sql, params } = pool.scanQueries[0];
    assert.match(sql, /FROM managed_certificates mc/);
    assert.match(sql, /NOT EXISTS/);
    assert.match(sql, /cj\.operation = 'renew'/);
    assert.match(sql, /cj\.subject_type = 'managed_certificate'/);
    assert.match(sql, /NOT \(cj\.status = ANY\(\$2::text\[\]\)\)/);
    assert.match(sql, /mc\.status NOT IN \('revoked', 'decommissioned'\)/);
    assert.match(sql, /profile_public_metadata/);
    assert.strictEqual(params[0], "30");
    assert.deepStrictEqual(params[1], ["succeeded", "failed"]);
  });

  it("excludes certificates whose profile switched auto-renewal off", async () => {
    const pool = createSchedulerPool({ dueRows: [] });

    await findCertificatesDueForRenewal({
      db: pool,
      thresholdDays: 30,
      terminalStatuses: ["succeeded", "failed"],
    });

    const { sql, params } = pool.scanQueries[0];
    // The IS NULL half is load-bearing: cp.status is NULL when the LEFT JOIN
    // matched no profile, and `NULL = ANY(...)` is NULL, so without it every
    // profile-less certificate would be dropped from the scan and would stop
    // being reported as an incomplete profile.
    assert.match(
      sql,
      /\(cp\.status IS NULL OR NOT \(cp\.status = ANY\(\$4::text\[\]\)\)\)/,
    );
    assert.deepStrictEqual(params[3], ["disabled", "archived"]);
    assert.deepStrictEqual(
      AUTO_RENEW_DISABLED_PROFILE_STATUSES,
      ["disabled", "archived"],
    );
  });

  it("reports switched-off certificates so they are not mistaken for nothing due", async () => {
    const pool = createSchedulerPool({
      dueRows: [],
      autoRenewDisabledCount: 4,
    });

    const summary = await runRenewalSchedulerSweep({
      dbPool: pool,
      env: {},
      jobCreator: async () => {
        throw new Error("no certificate was due, nothing should be created");
      },
    });

    assert.strictEqual(summary.scanned, 0);
    assert.strictEqual(summary.created, 0);
    assert.strictEqual(summary.skippedAutoRenewDisabled, 4);
    assert.deepStrictEqual(summary.errors, []);
  });

  it("keeps creating renewals when the switched-off count query fails", async () => {
    const pool = createSchedulerPool({ dueRows: [dueCertificate()] });
    const originalQuery = pool.query.bind(pool);
    pool.query = async (sql, params) => {
      if (normalizeSql(sql).includes("disabled_count")) {
        throw new Error("count exploded");
      }
      return originalQuery(sql, params);
    };
    const warnings = [];

    const summary = await runRenewalSchedulerSweep({
      dbPool: pool,
      env: {},
      logger: { warn: (event) => warnings.push(event) },
      jobCreator: async () => ({ job: { id: "job-1" }, created: true }),
    });

    // An observability query must never cost a real renewal.
    assert.strictEqual(summary.created, 1);
    assert.strictEqual(summary.skippedAutoRenewDisabled, 0);
    assert.deepStrictEqual(summary.errors, []);
    assert.ok(
      warnings.includes("certops-renewal-scheduler-disabled-count-failed"),
    );
  });

  it("creates an automation renew job with a resolved renewal profile snapshot", async () => {
    const pool = createSchedulerPool({ dueRows: [dueCertificate()] });
    const createdJobs = [];

    const summary = await runRenewalSchedulerSweep({
      dbPool: pool,
      env: {},
      jobCreator: async (options) => {
        createdJobs.push(options);
        return { job: { id: "job-1" }, created: true };
      },
    });

    assert.strictEqual(summary.scanned, 1);
    assert.strictEqual(summary.created, 1);
    assert.strictEqual(summary.replayed, 0);
    assert.strictEqual(summary.skippedPaused, 0);
    assert.strictEqual(summary.skippedIncompleteProfile, 0);
    assert.deepStrictEqual(summary.errors, []);

    assert.strictEqual(createdJobs.length, 1);
    const job = createdJobs[0];
    assert.strictEqual(job.operation, "renew");
    assert.strictEqual(job.source, "automation");
    assert.strictEqual(job.mode, "real");
    assert.strictEqual(job.subjectType, "managed_certificate");
    assert.strictEqual(job.subjectId, "cert-1");
    assert.strictEqual(
      job.idempotencyKey,
      `certops-renewal:cert-1:${NOT_AFTER.getTime()}`,
    );
    assert.strictEqual(job.payload.certificateId, "cert-1");
    assert.strictEqual(job.payload.notAfter, NOT_AFTER.toISOString());
    assert.ok(job.payload.renewalProfile);
    assert.strictEqual(job.payload.renewalProfile.schemaVersion, 1);
    assert.strictEqual(job.payload.commandRef, "renew.web");
    assert.strictEqual(job.payload.dnsProvider, "cloudflare");
    assert.strictEqual(job.payload.dnsZone, "example.com");
    assert.strictEqual(job.payload.certPath, "/etc/ssl/certs/app.pem");
    assert.strictEqual(job.payload.keyRotation, false);

    // By-construction exclusion (ADR-0012 decision 14): every job the
    // scheduler ever creates carries this literal operation, so it can never
    // be a trust-anchor operation regardless of certificate/profile shape.
    assert.equal(isTrustAnchorOperation(job.operation), false);

    const client = pool.clients[1];
    const sqls = client.queries.map((q) => q.sql);
    assert.strictEqual(sqls[0], "BEGIN");
    assert.ok(
      sqls.some((sql) =>
        sql.startsWith(
          "SELECT id, certops_paused, certops_require_approval_always FROM workspaces",
        ),
      ),
    );
    assert.strictEqual(sqls.at(-1), "COMMIT");
    assert.strictEqual(client.released, true);
  });

  it("names the store/binding on CERTOPS_JOB_CREATED_AUTOMATIC for a windows-iis renewal, not certPath", async () => {
    const windowsTarget = {
      type: "windows-iis",
      reference: "iis-01/default-web-site",
      store: "My",
      binding: { site: "Default Web Site", port: 443, sniHost: "app.example.com" },
      thumbprintSha1: "AA".repeat(20),
    };
    const pool = createSchedulerPool({
      dueRows: [
        dueCertificate({
          renewalProfileOverrides: {
            deploymentTargets: [windowsTarget],
            target: windowsTarget,
          },
        }),
      ],
    });
    let auditMetadata = null;

    const summary = await runRenewalSchedulerSweep({
      dbPool: pool,
      env: {},
      jobCreator: async () => ({ job: { id: "job-windows-1" }, created: true }),
      auditWriter: async ({ action, metadata }) => {
        if (action === "CERTOPS_JOB_CREATED_AUTOMATIC") auditMetadata = metadata;
      },
    });

    assert.strictEqual(summary.created, 1);
    assert.ok(auditMetadata);
    assert.equal(auditMetadata.targetType, "windows-iis");
    assert.equal(auditMetadata.windowsStore, "My");
    assert.equal(auditMetadata.windowsBindingSite, "Default Web Site");
    assert.equal(auditMetadata.windowsBindingPort, 443);
    assert.equal(auditMetadata.windowsBindingSniHost, "app.example.com");
  });

  it("reports only a null targetType (no windows fields) for a non-windows automation renewal", async () => {
    const pool = createSchedulerPool({ dueRows: [dueCertificate()] });
    let auditMetadata = null;

    await runRenewalSchedulerSweep({
      dbPool: pool,
      env: {},
      jobCreator: async () => ({ job: { id: "job-1" }, created: true }),
      auditWriter: async ({ action, metadata }) => {
        if (action === "CERTOPS_JOB_CREATED_AUTOMATIC") auditMetadata = metadata;
      },
    });

    assert.ok(auditMetadata);
    assert.equal(auditMetadata.targetType, "endpoint");
    assert.equal(auditMetadata.windowsStore, null);
    assert.equal(auditMetadata.windowsBindingSite, null);
    assert.equal(auditMetadata.windowsBindingPort, null);
    assert.equal(auditMetadata.windowsBindingSniHost, null);
  });

  it("skips certificates lacking a complete renewal profile", async () => {
    const warnings = [];
    const pool = createSchedulerPool({
      dueRows: [
        dueCertificate({
          id: "cert-incomplete",
          profile_public_metadata: {},
        }),
        dueCertificate({ id: "cert-ok" }),
      ],
    });
    const createdJobs = [];

    const summary = await runRenewalSchedulerSweep({
      dbPool: pool,
      env: {},
      logger: {
        warn: (msg, meta) => warnings.push({ msg, meta }),
        error() {},
      },
      jobCreator: async (options) => {
        createdJobs.push(options);
        return { job: { id: "job-1" }, created: true };
      },
    });

    assert.strictEqual(summary.skippedIncompleteProfile, 1);
    assert.strictEqual(summary.created, 1);
    assert.deepStrictEqual(summary.errors, []);
    assert.deepStrictEqual(
      createdJobs.map((job) => job.subjectId),
      ["cert-ok"],
    );
    assert.strictEqual(warnings.length, 1);
    assert.strictEqual(
      warnings[0].msg,
      "certops-renewal-scheduler-incomplete-profile",
    );
  });

  it("sets keyRotation from the resolved profile for agent-local keys", async () => {
    const pool = createSchedulerPool({
      dueRows: [
        dueCertificate({
          key_mode: "agent-local",
          renewalProfileOverrides: {
            keyRotationPolicy: { rotateOnRenew: true },
          },
        }),
      ],
    });
    const createdJobs = [];

    await runRenewalSchedulerSweep({
      dbPool: pool,
      env: {},
      jobCreator: async (options) => {
        createdJobs.push(options);
        return { job: { id: "job-1" }, created: true };
      },
    });

    assert.strictEqual(createdJobs[0].payload.keyRotation, true);
  });

  it("counts idempotent replays without creating duplicates", async () => {
    const pool = createSchedulerPool({ dueRows: [dueCertificate()] });

    const summary = await runRenewalSchedulerSweep({
      dbPool: pool,
      env: {},
      jobCreator: async () => ({ job: { id: "job-1" }, created: false }),
    });

    assert.strictEqual(summary.created, 0);
    assert.strictEqual(summary.replayed, 1);
    assert.deepStrictEqual(summary.errors, []);
  });

  it("skips paused workspaces without erroring and rolls the transaction back", async () => {
    const pool = createSchedulerPool({
      dueRows: [
        dueCertificate({ id: "cert-paused", workspace_id: "ws-paused" }),
        dueCertificate({ id: "cert-ok", workspace_id: "ws-ok" }),
      ],
      pausedWorkspaces: new Set(["ws-paused"]),
    });
    const createdJobs = [];

    const summary = await runRenewalSchedulerSweep({
      dbPool: pool,
      env: {},
      jobCreator: async (options) => {
        createdJobs.push(options);
        return { job: { id: "job-1" }, created: true };
      },
    });

    assert.strictEqual(summary.scanned, 2);
    assert.strictEqual(summary.skippedPaused, 1);
    assert.strictEqual(summary.created, 1);
    assert.deepStrictEqual(summary.errors, []);
    assert.deepStrictEqual(
      createdJobs.map((job) => job.subjectId),
      ["cert-ok"],
    );

    const pausedClient = pool.clients[1];
    const pausedSqls = pausedClient.queries.map((q) => q.sql);
    assert.ok(pausedSqls.includes("ROLLBACK"));
    assert.ok(!pausedSqls.includes("COMMIT"));
    assert.strictEqual(pausedClient.released, true);
  });

  it("skips globally disabled deployments without erroring", async () => {
    const pool = createSchedulerPool({ dueRows: [dueCertificate()] });

    const summary = await runRenewalSchedulerSweep({
      dbPool: pool,
      env: { CERTOPS_ENABLED: "false" },
      jobCreator: async () => {
        throw new Error("job creation must not run when CertOps is disabled");
      },
    });

    assert.strictEqual(summary.skippedPaused, 1);
    assert.strictEqual(summary.created, 0);
    assert.deepStrictEqual(summary.errors, []);
  });

  it("records per-certificate failures without aborting the sweep", async () => {
    const pool = createSchedulerPool({
      dueRows: [
        dueCertificate({ id: "cert-bad" }),
        dueCertificate({ id: "cert-good" }),
      ],
    });
    const createdJobs = [];

    const summary = await runRenewalSchedulerSweep({
      dbPool: pool,
      env: {},
      jobCreator: async (options) => {
        if (options.subjectId === "cert-bad") {
          throw new Error("insert exploded");
        }
        createdJobs.push(options);
        return { job: { id: "job-2" }, created: true };
      },
    });

    assert.strictEqual(summary.created, 1);
    assert.strictEqual(summary.errors.length, 1);
    assert.strictEqual(summary.errors[0].certificateId, "cert-bad");
    assert.match(summary.errors[0].error, /insert exploded/);
    assert.deepStrictEqual(
      createdJobs.map((job) => job.subjectId),
      ["cert-good"],
    );
  });

  it("exposes the pause and disabled error codes it relies on", () => {
    assert.strictEqual(CERTOPS_WORKSPACE_PAUSED, "CERTOPS_WORKSPACE_PAUSED");
    assert.strictEqual(CERTOPS_DISABLED, "CERTOPS_DISABLED");
  });

  it("resolves the per-CA cap from env with a default of 5", () => {
    assert.strictEqual(resolveRenewalPerCaCap({}), 5);
    assert.strictEqual(DEFAULT_RENEWAL_PER_CA_CAP, 5);
    assert.strictEqual(
      resolveRenewalPerCaCap({ CERTOPS_RENEWAL_PER_CA_CAP: "2" }),
      2,
    );
  });

  it("buckets certificates by metadata caEndpoint with profile fallback", () => {
    assert.strictEqual(
      certificateCaBucket({
        certificate_ca_endpoint: "https://ca-a.example.com/acme",
        profile_ca_endpoint: "https://ca-b.example.com/acme",
      }),
      "https://ca-a.example.com/acme",
    );
    assert.strictEqual(
      certificateCaBucket({
        certificate_ca_endpoint: null,
        profile_ca_endpoint: " https://ca-b.example.com/acme ",
      }),
      "https://ca-b.example.com/acme",
    );
    assert.strictEqual(
      certificateCaBucket({
        certificate_ca_endpoint: null,
        profile_ca_endpoint: null,
      }),
      UNKNOWN_CA_BUCKET,
    );
  });

  it("counts in-flight renew jobs per payload caEndpoint with an unknown bucket", async () => {
    const pool = createSchedulerPool({
      inFlightRows: [
        {
          workspace_id: "ws-1",
          ca_endpoint: "https://ca-a.example.com/acme",
          in_flight: 3,
        },
        { workspace_id: "ws-1", ca_endpoint: null, in_flight: 2 },
        {
          workspace_id: "ws-1",
          ca_endpoint: "HTTPS://CA-A.example.com/acme/",
          in_flight: 1,
        },
      ],
    });

    const counts = await countInFlightRenewalJobsByCaEndpoint({
      db: pool,
      terminalStatuses: ["succeeded", "failed"],
    });

    assert.strictEqual(
      counts.get(caCapKey("ws-1", "https://ca-a.example.com/acme")),
      4,
    );
    assert.strictEqual(counts.get(caCapKey("ws-1", UNKNOWN_CA_BUCKET)), 2);
  });

  it("creates jobs while a CA is under its in-flight cap", async () => {
    const pool = createSchedulerPool({
      dueRows: [
        dueCertificate({
          certificate_ca_endpoint: "https://ca-a.example.com/acme",
          profile_ca_endpoint: "https://ca-a.example.com/acme",
          renewalProfileOverrides: {
            ca: {
              endpoint: "https://ca-a.example.com/acme",
              accountRef: null,
              eabRef: null,
            },
          },
        }),
      ],
      inFlightRows: [
        {
          workspace_id: "ws-1",
          ca_endpoint: "https://ca-a.example.com/acme",
          in_flight: 4,
        },
      ],
    });
    const createdJobs = [];

    const summary = await runRenewalSchedulerSweep({
      dbPool: pool,
      env: {},
      jobCreator: async (options) => {
        createdJobs.push(options);
        return { job: { id: "job-1" }, created: true };
      },
    });

    assert.strictEqual(summary.perCaCap, 5);
    assert.strictEqual(summary.created, 1);
    assert.strictEqual(summary.skippedByCaCap, 0);
    assert.strictEqual(
      createdJobs[0].payload.caEndpoint,
      "https://ca-a.example.com/acme",
    );
  });

  it("skips and reports certificates whose CA is at the cap", async () => {
    const pool = createSchedulerPool({
      dueRows: [
        dueCertificate({
          id: "cert-capped",
          certificate_ca_endpoint: "https://ca-a.example.com/acme",
          profile_ca_endpoint: "https://ca-a.example.com/acme",
          renewalProfileOverrides: {
            ca: {
              endpoint: "https://ca-a.example.com/acme",
              accountRef: null,
              eabRef: null,
            },
          },
        }),
        dueCertificate({
          id: "cert-other-ca",
          certificate_ca_endpoint: "https://ca-b.example.com/acme",
          profile_ca_endpoint: "https://ca-b.example.com/acme",
          renewalProfileOverrides: {
            ca: {
              endpoint: "https://ca-b.example.com/acme",
              accountRef: null,
              eabRef: null,
            },
          },
        }),
      ],
      inFlightRows: [
        {
          workspace_id: "ws-1",
          ca_endpoint: "https://ca-a.example.com/acme",
          in_flight: 5,
        },
      ],
    });
    const createdJobs = [];

    const summary = await runRenewalSchedulerSweep({
      dbPool: pool,
      env: {},
      jobCreator: async (options) => {
        createdJobs.push(options);
        return { job: { id: "job-1" }, created: true };
      },
    });

    assert.strictEqual(summary.scanned, 2);
    assert.strictEqual(summary.skippedByCaCap, 1);
    assert.strictEqual(summary.created, 1);
    assert.deepStrictEqual(
      createdJobs.map((job) => job.subjectId),
      ["cert-other-ca"],
    );
  });

  it("caps certificates without a resolvable caEndpoint in a shared unknown bucket", async () => {
    const pool = createSchedulerPool({
      dueRows: [
        dueCertificate({
          id: "cert-no-ca",
          certificate_ca_endpoint: null,
          profile_ca_endpoint: null,
        }),
      ],
      inFlightRows: [
        { workspace_id: "ws-1", ca_endpoint: null, in_flight: 5 },
      ],
    });

    const summary = await runRenewalSchedulerSweep({
      dbPool: pool,
      env: {},
      jobCreator: async () => {
        throw new Error("job creation must not run for a capped bucket");
      },
    });

    assert.strictEqual(summary.skippedByCaCap, 1);
    assert.strictEqual(summary.created, 0);
  });

  it("counts jobs it creates in the same sweep against the cap", async () => {
    const pool = createSchedulerPool({
      dueRows: [
        dueCertificate({
          id: "cert-first",
          certificate_ca_endpoint: "https://ca-a.example.com/acme",
          profile_ca_endpoint: "https://ca-a.example.com/acme",
          renewalProfileOverrides: {
            ca: {
              endpoint: "https://ca-a.example.com/acme",
              accountRef: null,
              eabRef: null,
            },
          },
        }),
        dueCertificate({
          id: "cert-second",
          certificate_ca_endpoint: "https://ca-a.example.com/acme",
          profile_ca_endpoint: "https://ca-a.example.com/acme",
          renewalProfileOverrides: {
            ca: {
              endpoint: "https://ca-a.example.com/acme",
              accountRef: null,
              eabRef: null,
            },
          },
        }),
      ],
      inFlightRows: [],
    });
    const createdJobs = [];

    const summary = await runRenewalSchedulerSweep({
      dbPool: pool,
      env: { CERTOPS_RENEWAL_PER_CA_CAP: "1" },
      jobCreator: async (options) => {
        createdJobs.push(options);
        return { job: { id: "job-1" }, created: true };
      },
    });

    assert.strictEqual(summary.perCaCap, 1);
    assert.strictEqual(summary.created, 1);
    assert.strictEqual(summary.skippedByCaCap, 1);
    assert.deepStrictEqual(
      createdJobs.map((job) => job.subjectId),
      ["cert-first"],
    );
  });

  it("forces the automation renew job to pending_approval when the workspace's approval policy is on", async () => {
    const pool = createSchedulerPool({
      dueRows: [dueCertificate({ workspace_id: "ws-approval" })],
      requireApprovalAlwaysWorkspaces: new Set(["ws-approval"]),
    });
    const createdJobs = [];

    const summary = await runRenewalSchedulerSweep({
      dbPool: pool,
      env: {},
      jobCreator: async (options) => {
        createdJobs.push(options);
        return { job: { id: "job-1" }, created: true };
      },
    });

    assert.strictEqual(summary.created, 1);
    assert.strictEqual(createdJobs[0].workspaceRequiresApprovalAlways, true);
  });

  it("leaves workspaceRequiresApprovalAlways false when the workspace policy is off", async () => {
    const pool = createSchedulerPool({ dueRows: [dueCertificate()] });
    const createdJobs = [];

    await runRenewalSchedulerSweep({
      dbPool: pool,
      env: {},
      jobCreator: async (options) => {
        createdJobs.push(options);
        return { job: { id: "job-1" }, created: true };
      },
    });

    assert.strictEqual(createdJobs[0].workspaceRequiresApprovalAlways, false);
  });
});
