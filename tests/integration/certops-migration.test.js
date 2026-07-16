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
const CERTOPS_TOKEN_LIFECYCLE_MIGRATION = migrations.find(
  (migration) => migration.name === "certops_token_lifecycle_status",
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
    await TestUtils.execQuery(
      `SET search_path TO ${quotedSchema}, public; ${CERTOPS_MIGRATION.sql}; RESET search_path;`,
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
