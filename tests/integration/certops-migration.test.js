const crypto = require("crypto");

const { loadRootEnv } = require("../../scripts/load-root-env");

loadRootEnv();

const { expect, TestUtils } = require("./setup");
const { requireMigrateModule } = require("./variant-paths");
const { runMigrations, migrations } = requireMigrateModule();

const CERTOPS_TABLES = [
  "managed_certificates",
  "certificate_instances",
  "certificate_profiles",
  "certificate_targets",
];

const CERTOPS_EXECUTOR_EVENT_TABLES = [
  "certificate_executor_events",
];

const CERTOPS_MIGRATION = migrations.find(
  (migration) => migration.name === "certops_inventory_schema",
);
const CERTOPS_JOBS_EVIDENCE_MIGRATION = migrations.find(
  (migration) => migration.name === "certops_jobs_evidence_schema",
);
const CERTOPS_TOKEN_LIFECYCLE_MIGRATION = migrations.find(
  (migration) => migration.name === "certops_token_lifecycle_status",
);
const CERTOPS_MONITOR_IDENTITY_MIGRATION = migrations.find(
  (migration) =>
    migration.name === "certops_managed_certificate_monitor_identity",
);

function quoteIdentifier(identifier) {
  return `"${String(identifier).replace(/"/g, '""')}"`;
}

async function createWorkspacePair(label) {
  const ownerEmail = `${label}-${Date.now()}-${crypto.randomUUID()}@example.com`;
  const owner = await TestUtils.execQuery(
    `INSERT INTO users (email, email_original, display_name, password_hash, auth_method, email_verified)
     VALUES ($1, $2, $3, $4, 'local', TRUE)
     RETURNING id`,
    [
      ownerEmail.toLowerCase(),
      ownerEmail,
      label,
      "not-used-in-migration-test",
    ],
  );
  const ownerId = owner.rows[0].id;
  const workspaceA = crypto.randomUUID();
  const workspaceB = crypto.randomUUID();

  await TestUtils.execQuery(
    `INSERT INTO workspaces (id, name, created_by, plan)
     VALUES ($1, $2, $3, 'oss'), ($4, $5, $3, 'oss')`,
    [
      workspaceA,
      `${label} A`,
      ownerId,
      workspaceB,
      `${label} B`,
    ],
  );

  return { ownerId, workspaceA, workspaceB };
}

async function cleanupWorkspacePair(ownerId, workspaceIds) {
  await TestUtils.execQuery("DELETE FROM workspaces WHERE id = ANY($1::uuid[])", [
    workspaceIds,
  ]);
  await TestUtils.execQuery("DELETE FROM users WHERE id = $1", [ownerId]);
}

async function withScratchCertOpsSchema(callback) {
  const schemaName = `certops_migration_${crypto
    .randomUUID()
    .replace(/-/g, "")}`;
  const quotedSchema = quoteIdentifier(schemaName);

  await TestUtils.execQuery(`CREATE SCHEMA ${quotedSchema}`);
  try {
    // Migration 15's dedup re-points certificate_jobs/certificate_evidence
    // history, so the scratch schema needs the jobs/evidence tables too.
    // Their api_tokens/workspaces/users FKs resolve to public via the
    // search_path.
    await TestUtils.execQuery(
      `SET search_path TO ${quotedSchema}, public; ${CERTOPS_MIGRATION.sql}; ${CERTOPS_JOBS_EVIDENCE_MIGRATION.sql}; RESET search_path;`,
    );
    return await callback(quotedSchema);
  } finally {
    await TestUtils.execQuery(`DROP SCHEMA IF EXISTS ${quotedSchema} CASCADE`);
  }
}

async function expectForeignKeyViolation(query, params) {
  try {
    await TestUtils.execQuery(query, params);
    throw new Error("Expected foreign key violation");
  } catch (error) {
    expect(error.code).to.equal("23503");
  }
}

describe("CertOps inventory migration", function () {
  this.timeout(60000);

  before(async () => {
    await runMigrations();
  });

  it("creates the CertOps inventory tables", async () => {
    const res = await TestUtils.execQuery(
      `SELECT table_name
         FROM information_schema.tables
        WHERE table_schema = 'public'
          AND table_name = ANY($1::text[])
        ORDER BY table_name`,
      [CERTOPS_TABLES],
    );

    expect(res.rows.map((row) => row.table_name).sort()).to.deep.equal(
      CERTOPS_TABLES.slice().sort(),
    );
  });

  it("creates the CertOps executor event idempotency table", async () => {
    const res = await TestUtils.execQuery(
      `SELECT table_name
         FROM information_schema.tables
        WHERE table_schema = 'public'
          AND table_name = ANY($1::text[])
        ORDER BY table_name`,
      [CERTOPS_EXECUTOR_EVENT_TABLES],
    );

    expect(res.rows.map((row) => row.table_name).sort()).to.deep.equal(
      CERTOPS_EXECUTOR_EVENT_TABLES.slice().sort(),
    );
  });

  it("can run the migration body repeatedly", async () => {
    expect(CERTOPS_MIGRATION).to.exist;

    await TestUtils.execQuery(CERTOPS_MIGRATION.sql);
    await TestUtils.execQuery(CERTOPS_MIGRATION.sql);

    const res = await TestUtils.execQuery(
      "SELECT COUNT(*)::int AS count FROM migrations WHERE version = $1",
      [CERTOPS_MIGRATION.version],
    );
    expect(res.rows[0].count).to.equal(1);
  });

  it("adds the nullable token certificate lifecycle status idempotently", async () => {
    expect(CERTOPS_TOKEN_LIFECYCLE_MIGRATION).to.exist;
    expect(CERTOPS_TOKEN_LIFECYCLE_MIGRATION.version).to.equal(11);

    await TestUtils.execQuery(CERTOPS_TOKEN_LIFECYCLE_MIGRATION.sql);
    await TestUtils.execQuery(CERTOPS_TOKEN_LIFECYCLE_MIGRATION.sql);

    const column = await TestUtils.execQuery(
      `SELECT is_nullable, data_type
         FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'tokens'
          AND column_name = 'cert_lifecycle_status'`,
    );
    expect(column.rows).to.have.length(1);
    expect(column.rows[0].is_nullable).to.equal("YES");
    expect(column.rows[0].data_type).to.equal("text");

    const constraint = await TestUtils.execQuery(
      `SELECT COUNT(*)::int AS count
         FROM pg_constraint
        WHERE conname = 'tokens_cert_lifecycle_status_check'`,
    );
    expect(constraint.rows[0].count).to.equal(1);

    const index = await TestUtils.execQuery(
      `SELECT COUNT(*)::int AS count
         FROM pg_indexes
        WHERE schemaname = 'public'
          AND tablename = 'tokens'
          AND indexname = 'idx_tokens_workspace_cert_lifecycle_status'`,
    );
    expect(index.rows[0].count).to.equal(1);
  });

  it("does not create private-key custody columns", async () => {
    const res = await TestUtils.execQuery(
      `SELECT table_name, column_name
         FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = ANY($1::text[])
        ORDER BY table_name, ordinal_position`,
      [[...CERTOPS_TABLES, ...CERTOPS_EXECUTOR_EVENT_TABLES]],
    );

    const forbiddenFragments = [
      "private",
      "pkcs12",
      "pfx",
      "key_material",
      "key_pem",
      "key_der",
      "raw_key",
      "backup",
      "secret",
      "credential",
      "password",
    ];

    for (const row of res.rows) {
      const hit = forbiddenFragments.find((fragment) =>
        row.column_name.includes(fragment),
      );
      expect(
        hit,
        `${row.table_name}.${row.column_name} looks like private-key custody`,
      ).to.equal(undefined);
    }
  });

  it("keeps workspace isolation possible from the schema", async () => {
    const columns = await TestUtils.execQuery(
      `SELECT table_name, is_nullable
         FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = ANY($1::text[])
          AND column_name = 'workspace_id'`,
      [[...CERTOPS_TABLES, ...CERTOPS_EXECUTOR_EVENT_TABLES]],
    );

    const byTable = new Map(
      columns.rows.map((row) => [row.table_name, row.is_nullable]),
    );
    for (const tableName of [...CERTOPS_TABLES, ...CERTOPS_EXECUTOR_EVENT_TABLES]) {
      expect(byTable.get(tableName), `${tableName}.workspace_id`).to.equal(
        "NO",
      );
    }

    const workspaceFks = await TestUtils.execQuery(
      `SELECT DISTINCT tc.table_name
         FROM information_schema.table_constraints tc
         JOIN information_schema.key_column_usage kcu
           ON tc.constraint_schema = kcu.constraint_schema
          AND tc.constraint_name = kcu.constraint_name
          AND tc.table_name = kcu.table_name
         JOIN information_schema.constraint_column_usage ccu
           ON tc.constraint_schema = ccu.constraint_schema
          AND tc.constraint_name = ccu.constraint_name
        WHERE tc.constraint_type = 'FOREIGN KEY'
          AND tc.table_schema = 'public'
          AND tc.table_name = ANY($1::text[])
          AND kcu.column_name = 'workspace_id'
          AND ccu.table_name = 'workspaces'
          AND ccu.column_name = 'id'`,
      [[...CERTOPS_TABLES, ...CERTOPS_EXECUTOR_EVENT_TABLES]],
    );

    expect(workspaceFks.rows.map((row) => row.table_name).sort()).to.deep.equal(
      [...CERTOPS_TABLES, ...CERTOPS_EXECUTOR_EVENT_TABLES].sort(),
    );

    const instanceFks = await TestUtils.execQuery(
      `SELECT constraint_name
         FROM information_schema.table_constraints
        WHERE table_schema = 'public'
          AND table_name = 'certificate_instances'
          AND constraint_type = 'FOREIGN KEY'
          AND constraint_name = ANY($1::text[])
        ORDER BY constraint_name`,
      [
        [
          "fk_certificate_instances_managed_certificate",
          "fk_certificate_instances_target",
        ],
      ],
    );
    expect(instanceFks.rows.map((row) => row.constraint_name)).to.deep.equal([
      "fk_certificate_instances_managed_certificate",
      "fk_certificate_instances_target",
    ]);
  });

  it("enforces profile links within the same workspace", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-profile-fk",
    );

    try {
      await withScratchCertOpsSchema(async (schema) => {
        const profileA = crypto.randomUUID();
        await TestUtils.execQuery(
          `INSERT INTO ${schema}.certificate_profiles (id, workspace_id, name)
           VALUES ($1, $2, $3)`,
          [profileA, workspaceA, "Workspace A profile"],
        );

        await TestUtils.execQuery(
          `INSERT INTO ${schema}.managed_certificates (workspace_id, profile_id)
           VALUES ($1, $2)`,
          [workspaceA, profileA],
        );
        await TestUtils.execQuery(
          `INSERT INTO ${schema}.certificate_targets (workspace_id, profile_id, name, target_type)
           VALUES ($1, $2, $3, 'endpoint')`,
          [workspaceA, profileA, "Workspace A target"],
        );

        await expectForeignKeyViolation(
          `INSERT INTO ${schema}.managed_certificates (workspace_id, profile_id)
           VALUES ($1, $2)`,
          [workspaceB, profileA],
        );
        await expectForeignKeyViolation(
          `INSERT INTO ${schema}.certificate_targets (workspace_id, profile_id, name, target_type)
           VALUES ($1, $2, $3, 'endpoint')`,
          [workspaceB, profileA, "Cross-workspace target"],
        );
      });
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("allows null profile links and preserves workspace ownership when profiles are deleted", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-profile-delete",
    );

    try {
      await withScratchCertOpsSchema(async (schema) => {
        const profileA = crypto.randomUUID();
        await TestUtils.execQuery(
          `INSERT INTO ${schema}.certificate_profiles (id, workspace_id, name)
           VALUES ($1, $2, $3)`,
          [profileA, workspaceA, "Delete profile"],
        );

        const managed = await TestUtils.execQuery(
          `INSERT INTO ${schema}.managed_certificates (workspace_id, profile_id)
           VALUES ($1, $2)
           RETURNING id`,
          [workspaceA, profileA],
        );
        const target = await TestUtils.execQuery(
          `INSERT INTO ${schema}.certificate_targets (workspace_id, profile_id, name, target_type)
           VALUES ($1, $2, $3, 'endpoint')
           RETURNING id`,
          [workspaceA, profileA, "Delete profile target"],
        );

        await TestUtils.execQuery(
          `INSERT INTO ${schema}.managed_certificates (workspace_id, profile_id)
           VALUES ($1, NULL)`,
          [workspaceB],
        );
        await TestUtils.execQuery(
          `INSERT INTO ${schema}.certificate_targets (workspace_id, profile_id, name, target_type)
           VALUES ($1, NULL, $2, 'endpoint')`,
          [workspaceB, "Null profile target"],
        );

        await TestUtils.execQuery(
          `DELETE FROM ${schema}.certificate_profiles WHERE id = $1`,
          [profileA],
        );

        const managedAfterDelete = await TestUtils.execQuery(
          `SELECT workspace_id::text AS workspace_id, profile_id
             FROM ${schema}.managed_certificates
            WHERE id = $1`,
          [managed.rows[0].id],
        );
        const targetAfterDelete = await TestUtils.execQuery(
          `SELECT workspace_id::text AS workspace_id, profile_id
             FROM ${schema}.certificate_targets
            WHERE id = $1`,
          [target.rows[0].id],
        );

        expect(managedAfterDelete.rows[0]).to.deep.equal({
          workspace_id: workspaceA,
          profile_id: null,
        });
        expect(targetAfterDelete.rows[0]).to.deep.equal({
          workspace_id: workspaceA,
          profile_id: null,
        });
      });
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("dedupes pre-v15 duplicate monitor identities before the unique index", async () => {
    expect(CERTOPS_MONITOR_IDENTITY_MIGRATION).to.exist;

    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-monitor-dedup",
    );

    try {
      await withScratchCertOpsSchema(async (schema) => {
        // Recreate the pre-v15 uniqueness model: the only unique index was
        // (workspace_id, fingerprint_sha256) over all non-null fingerprints,
        // so duplicate (workspace_id, source, source_ref) monitor rows were
        // legal (TOCTOU race in the old bridge / NULL-fingerprint bypass).
        // The search_path is scratch-only so the unqualified DROP INDEX
        // statements (here and inside migration 15) never touch public.
        await TestUtils.execQuery(
          `SET search_path TO ${schema};
           DROP INDEX IF EXISTS uq_managed_certificates_workspace_fingerprint_import;
           DROP INDEX IF EXISTS uq_managed_certificates_workspace_source_ref;
           CREATE UNIQUE INDEX uq_managed_certificates_workspace_fingerprint
             ON managed_certificates(workspace_id, fingerprint_sha256)
             WHERE fingerprint_sha256 IS NOT NULL;
           RESET search_path;`,
        );

        const loser = crypto.randomUUID();
        const keeper = crypto.randomUUID();
        const otherWorkspaceRow = crypto.randomUUID();
        const sourceRef = "endpoint:dedup-monitor";

        await TestUtils.execQuery(
          `INSERT INTO ${schema}.managed_certificates
             (id, workspace_id, source, source_ref, fingerprint_sha256, updated_at)
           VALUES
             ($1, $4, 'endpoint_monitor', $5, 'aa11', NOW() - INTERVAL '1 day'),
             ($2, $4, 'endpoint_monitor', $5, 'bb22', NOW()),
             ($3, $6, 'endpoint_monitor', $5, 'cc33', NOW() - INTERVAL '2 days')`,
          [loser, keeper, otherWorkspaceRow, workspaceA, sourceRef, workspaceB],
        );

        const target = await TestUtils.execQuery(
          `INSERT INTO ${schema}.certificate_targets
             (workspace_id, name, target_type, source)
           VALUES ($1, 'Dedup target', 'endpoint', 'endpoint_monitor')
           RETURNING id`,
          [workspaceA],
        );
        const targetId = target.rows[0].id;

        // One child observation only the loser knows about (must be
        // re-pointed) and one the keeper already has (must be dropped as a
        // same-observation collision).
        const repointedInstance = crypto.randomUUID();
        const collidingInstance = crypto.randomUUID();
        const keeperInstance = crypto.randomUUID();
        await TestUtils.execQuery(
          `INSERT INTO ${schema}.certificate_instances
             (id, workspace_id, managed_certificate_id, target_id,
              observed_fingerprint_sha256)
           VALUES
             ($1, $4, $5, $6, 'aa11'),
             ($2, $4, $5, $6, 'bb22'),
             ($3, $4, $7, $6, 'bb22')`,
          [
            repointedInstance,
            collidingInstance,
            keeperInstance,
            workspaceA,
            loser,
            targetId,
            keeper,
          ],
        );

        await TestUtils.execQuery(
          `SET search_path TO ${schema}; ${CERTOPS_MONITOR_IDENTITY_MIGRATION.sql}; RESET search_path;`,
        );

        const survivors = await TestUtils.execQuery(
          `SELECT id::text AS id, workspace_id::text AS workspace_id
             FROM ${schema}.managed_certificates
            WHERE source = 'endpoint_monitor' AND source_ref = $1
            ORDER BY workspace_id`,
          [sourceRef],
        );
        expect(
          survivors.rows.map((row) => row.id).sort(),
        ).to.deep.equal([keeper, otherWorkspaceRow].sort());

        const instances = await TestUtils.execQuery(
          `SELECT id::text AS id, managed_certificate_id::text AS managed_certificate_id
             FROM ${schema}.certificate_instances
            ORDER BY id`,
          [],
        );
        const byId = new Map(
          instances.rows.map((row) => [row.id, row.managed_certificate_id]),
        );
        expect(byId.get(repointedInstance)).to.equal(keeper);
        expect(byId.get(keeperInstance)).to.equal(keeper);
        expect(byId.has(collidingInstance)).to.equal(false);

        const schemaName = schema.replace(/"/g, "");
        const indexes = await TestUtils.execQuery(
          `SELECT indexname
             FROM pg_indexes
            WHERE schemaname = $1
              AND tablename = 'managed_certificates'`,
          [schemaName],
        );
        const indexNames = new Set(indexes.rows.map((row) => row.indexname));
        expect(
          indexNames.has("uq_managed_certificates_workspace_source_ref"),
        ).to.equal(true);
        expect(
          indexNames.has("uq_managed_certificates_workspace_fingerprint_import"),
        ).to.equal(true);
        expect(
          indexNames.has("uq_managed_certificates_workspace_fingerprint"),
        ).to.equal(false);
      });
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("preserves job/evidence history and terminal lifecycle state across the v15 dedup", async () => {
    expect(CERTOPS_MONITOR_IDENTITY_MIGRATION).to.exist;
    expect(CERTOPS_JOBS_EVIDENCE_MIGRATION).to.exist;

    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-monitor-dedup-history",
    );

    try {
      await withScratchCertOpsSchema(async (schema) => {
        // Same pre-v15 uniqueness model as the dedup test above.
        await TestUtils.execQuery(
          `SET search_path TO ${schema};
           DROP INDEX IF EXISTS uq_managed_certificates_workspace_fingerprint_import;
           DROP INDEX IF EXISTS uq_managed_certificates_workspace_source_ref;
           CREATE UNIQUE INDEX uq_managed_certificates_workspace_fingerprint
             ON managed_certificates(workspace_id, fingerprint_sha256)
             WHERE fingerprint_sha256 IS NOT NULL;
           RESET search_path;`,
        );

        const loser = crypto.randomUUID();
        const keeper = crypto.randomUUID();
        const sourceRef = "endpoint:dedup-monitor-history";

        // The keeper-by-recency is active while the loser carries a terminal
        // status: D7 retire-first must survive the dedup on the keeper.
        await TestUtils.execQuery(
          `INSERT INTO ${schema}.managed_certificates
             (id, workspace_id, source, source_ref, status, fingerprint_sha256, updated_at)
           VALUES
             ($1, $3, 'endpoint_monitor', $4, 'revoked', 'aa11', NOW() - INTERVAL '1 day'),
             ($2, $3, 'endpoint_monitor', $4, 'active', 'bb22', NOW())`,
          [loser, keeper, workspaceA, sourceRef],
        );

        const target = await TestUtils.execQuery(
          `INSERT INTO ${schema}.certificate_targets
             (workspace_id, name, target_type, source)
           VALUES ($1, 'Dedup history target', 'endpoint', 'endpoint_monitor')
           RETURNING id`,
          [workspaceA],
        );
        const loserInstance = crypto.randomUUID();
        await TestUtils.execQuery(
          `INSERT INTO ${schema}.certificate_instances
             (id, workspace_id, managed_certificate_id, target_id,
              observed_fingerprint_sha256)
           VALUES ($1, $2, $3, $4, 'aa11')`,
          [loserInstance, workspaceA, loser, target.rows[0].id],
        );

        // FK-less text references to the loser that must be re-pointed, plus
        // controls that must stay untouched: another subject_type with the
        // same id text, and a same-shape row in another workspace.
        const loserJob = crypto.randomUUID();
        const unrelatedJob = crypto.randomUUID();
        const otherWorkspaceJob = crypto.randomUUID();
        await TestUtils.execQuery(
          `INSERT INTO ${schema}.certificate_jobs
             (id, workspace_id, operation, status, subject_type, subject_id)
           VALUES
             ($1, $4, 'revoke', 'succeeded', 'managed_certificate', $6),
             ($2, $4, 'noop', 'succeeded', 'external', $6),
             ($3, $5, 'noop', 'succeeded', 'managed_certificate', $6)`,
          [loserJob, unrelatedJob, otherWorkspaceJob, workspaceA, workspaceB, loser],
        );

        const loserEvidence = crypto.randomUUID();
        const unrelatedEvidence = crypto.randomUUID();
        await TestUtils.execQuery(
          `INSERT INTO ${schema}.certificate_evidence
             (id, workspace_id, evidence_type, subject_type, subject_id)
           VALUES
             ($1, $3, 'certificate.observed', 'managed_certificate', $4),
             ($2, $3, 'certificate.observed', 'external', $4)`,
          [loserEvidence, unrelatedEvidence, workspaceA, loser],
        );

        await TestUtils.execQuery(
          `SET search_path TO ${schema}; ${CERTOPS_MONITOR_IDENTITY_MIGRATION.sql}; RESET search_path;`,
        );

        const survivors = await TestUtils.execQuery(
          `SELECT id::text AS id, status
             FROM ${schema}.managed_certificates
            WHERE source = 'endpoint_monitor' AND source_ref = $1`,
          [sourceRef],
        );
        expect(survivors.rows).to.have.length(1);
        expect(survivors.rows[0].id).to.equal(keeper);
        expect(survivors.rows[0].status).to.equal("revoked");

        const instance = await TestUtils.execQuery(
          `SELECT managed_certificate_id::text AS managed_certificate_id
             FROM ${schema}.certificate_instances
            WHERE id = $1`,
          [loserInstance],
        );
        expect(instance.rows[0].managed_certificate_id).to.equal(keeper);

        const jobs = await TestUtils.execQuery(
          `SELECT id::text AS id, subject_id
             FROM ${schema}.certificate_jobs
            ORDER BY id`,
          [],
        );
        const jobsById = new Map(jobs.rows.map((row) => [row.id, row.subject_id]));
        expect(jobsById.get(loserJob)).to.equal(keeper);
        expect(jobsById.get(unrelatedJob)).to.equal(loser);
        expect(jobsById.get(otherWorkspaceJob)).to.equal(loser);

        const evidence = await TestUtils.execQuery(
          `SELECT id::text AS id, subject_id
             FROM ${schema}.certificate_evidence
            ORDER BY id`,
          [],
        );
        const evidenceById = new Map(
          evidence.rows.map((row) => [row.id, row.subject_id]),
        );
        expect(evidenceById.get(loserEvidence)).to.equal(keeper);
        expect(evidenceById.get(unrelatedEvidence)).to.equal(loser);

        const schemaName = schema.replace(/"/g, "");
        const indexes = await TestUtils.execQuery(
          `SELECT indexname
             FROM pg_indexes
            WHERE schemaname = $1
              AND tablename = 'managed_certificates'`,
          [schemaName],
        );
        const indexNames = new Set(indexes.rows.map((row) => row.indexname));
        expect(
          indexNames.has("uq_managed_certificates_workspace_source_ref"),
        ).to.equal(true);
      });
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("adds useful workspace and fingerprint indexes", async () => {
    const res = await TestUtils.execQuery(
      `SELECT indexname
         FROM pg_indexes
        WHERE schemaname = 'public'
          AND tablename = ANY($1::text[])`,
      [CERTOPS_TABLES],
    );
    const indexes = new Set(res.rows.map((row) => row.indexname));

    for (const indexName of [
      "idx_managed_certificates_workspace",
      "idx_managed_certificates_workspace_expiry",
      "uq_managed_certificates_workspace_fingerprint_import",
      "uq_managed_certificates_workspace_source_ref",
      "idx_certificate_instances_certificate",
      "idx_certificate_instances_workspace_fingerprint",
      "idx_certificate_targets_domain_monitor",
      "idx_certificate_profiles_workspace_status",
    ]) {
      expect(indexes.has(indexName), `missing index ${indexName}`).to.equal(
        true,
      );
    }
  });
});
