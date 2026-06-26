const path = require("path");

const { loadRootEnv } = require("../../scripts/load-root-env");

loadRootEnv();

const { expect, TestUtils } = require("./setup");
const { runMigrations, migrations } = require(
  path.resolve(__dirname, "../../apps/api/migrations/migrate.js"),
);

const CERTOPS_TABLES = [
  "managed_certificates",
  "certificate_instances",
  "certificate_profiles",
  "certificate_targets",
];

const CERTOPS_MIGRATION = migrations.find(
  (migration) => migration.name === "certops_inventory_schema",
);

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

  it("does not create private-key custody columns", async () => {
    const res = await TestUtils.execQuery(
      `SELECT table_name, column_name
         FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = ANY($1::text[])
        ORDER BY table_name, ordinal_position`,
      [CERTOPS_TABLES],
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
      [CERTOPS_TABLES],
    );

    const byTable = new Map(
      columns.rows.map((row) => [row.table_name, row.is_nullable]),
    );
    for (const tableName of CERTOPS_TABLES) {
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
      [CERTOPS_TABLES],
    );

    expect(workspaceFks.rows.map((row) => row.table_name).sort()).to.deep.equal(
      CERTOPS_TABLES.slice().sort(),
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
      "uq_managed_certificates_workspace_fingerprint",
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
