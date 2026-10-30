"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const path = require("node:path");
const {
  composeMigrations,
} = require("../../apps/api/migrations/compose-migrations");
const canonical = [
  "certops_certificate_enrollments",
  "certops_adcs_evidence_types",
  "certops_profile_issuer",
  "certops_job_alert_context",
  "certops_material_distribution",
  "certops_distribution_review",
  "certops_distribution_transfer",
];
const distribution = [
  canonical[4],
  canonical[5],
  canonical[6],
  canonical[0],
  canonical[1],
  canonical[2],
  canonical[3],
];
const preview = [
  canonical[0],
  canonical[4],
  canonical[5],
  canonical[6],
  canonical[1],
  canonical[2],
  canonical[3],
];
const previous = [canonical[0],canonical[1],canonical[2],canonical[4],canonical[5],canonical[6],canonical[3]];
const core = [
  { version: 69, name: "prior", sql: "prior" },
  ...canonical.map((name, i) => ({
    version: 70 + i,
    name,
    sql:
      i === 0
        ? "CHECK ('continue-enrollment', 'adcs-preflight')"
        : i === 4
          ? "CHECK ('continue-enrollment','adcs-preflight','deploy-from-store')"
          : name,
  })),
  { version: 77, name: "future", sql: "future" },
];
const ledger = (names, length = names.length) =>
  names.slice(0, length).map((name, i) => ({ version: 70 + i, name }));

test("fresh and current Core installations retain the canonical migration history", () => {
  for (const recorded of [
    [],
    ...Array.from({ length: 8 }, (_, i) => ledger(canonical, i + 1)),
  ]) {
    if (recorded.length > canonical.length) continue;
    assert.deepEqual(composeMigrations(core, recorded), core);
  }
});
for (const [name, names, minLength] of [
  ["distribution-first", distribution, 1],
  ["enrollment-first preview", preview, 2],
  ["previous AD-CS-first distribution preview", previous, 4],
]) {
  test(`${name} installations preserve every applied name and append missing AD CS schema`, () => {
    for (let count = minLength; count <= 7; count++) {
      const result = composeMigrations(core, ledger(names, count));
      assert.deepEqual(
        result
          .filter((e) => e.version >= 70 && e.version <= 76)
          .map((e) => e.name),
        names,
      );
      assert.deepEqual(result[0], core[0]);
      assert.deepEqual(result.at(-1), core.at(-1));
      assert.deepEqual(
        composeMigrations(core, ledger(names)),
        result,
        "replay is stable",
      );
    }
  });
}
test("unknown, mixed, duplicate and gapped histories fail before SQL executes", () => {
  for (const recorded of [
    [{ version: 70, name: "unknown" }],
    [{ version: 71, name: canonical[1] }],
    [
      { version: 70, name: canonical[0] },
      { version: 72, name: canonical[2] },
    ],
    [
      { version: 70, name: canonical[3] },
      { version: 71, name: canonical[3] },
    ],
    [...ledger(distribution, 4), { version: 74, name: canonical[2] }],
    [...ledger(canonical), { version: 78, name: "unknown" }],
    [ledger(canonical, 1)[0], ledger(canonical, 1)[0]],
  ])
    assert.throws(
      () => composeMigrations(core, recorded),
      /Unsupported Core migration history/,
    );
});
test("malformed pinned migration registries cannot be composed", () => {
  assert.throws(
    () => composeMigrations(core.filter((e) => e.name !== canonical[1])),
    /inconsistent pinned Core migration/,
  );
  assert.throws(
    () => composeMigrations([...core, core[1]]),
    /inconsistent pinned Core migration/,
  );
});

test("main 78 and provider-preview 78 retain their recorded definitions and append only the missing extension", () => {
  const installed = { version: 78, name: "certops_installed_file_distribution", sql: "installed-assurance" };
  const providers = { version: 79, name: "certops_material_providers", sql: "immutable-providers" };
  const registry = [...core, installed, providers];
  const prior = [...ledger(canonical), { version: 77, name: "future" }];
  for (const [first, second] of [[installed, providers], [{ ...providers, version: 78 }, { ...installed, version: 79 }]]) {
    for (const completed of [[first], [first, second]]) {
      const recorded = [...prior, ...completed.map(({ version, name }) => ({ version, name }))];
      const planned = composeMigrations(registry, recorded);
      assert.deepEqual(planned.slice(-2), [first, second]);
      for (const entry of completed) assert.deepEqual(planned.find(row => row.version === entry.version), entry);
      assert.equal(new Set(planned.map(entry => entry.version)).size, planned.length);
    }
  }
  assert.deepEqual(composeMigrations(registry).slice(-2), [installed, providers]);
  assert.throws(() => composeMigrations([...registry, { version: 79, name: "collision", sql: "unsafe" }]), /Duplicate Core migration version/);
  assert.throws(() => composeMigrations(registry, [...prior, { version: 78, name: "unknown" }]), /Unsupported Core migration history/);
});
test("released 78-82 and provider previews compose uniquely without rewriting applied rows", () => {
  const names = ["certops_installed_file_distribution", "auto_sync_provider_stats", "auto_sync_run_metrics", "auto_sync_metric_labels", "auto_sync_system_metrics", "certops_material_providers"];
  const extensions = names.map((name, i) => ({ version: 78 + i, name, sql: `immutable-${name}` }));
  const registry = [...core, ...extensions], prior = [...ledger(canonical), { version: 77, name: "future" }];
  for (const order of [names, ...[0, 1, 3, 4].map(index => { const order = names.filter(name => name !== "certops_material_providers"); order.splice(index, 0, "certops_material_providers"); return order; })]) {
    for (let count = order === names ? 0 : order.indexOf("certops_material_providers") + 1; count <= order.length; count++) {
      const recorded = [...prior, ...order.slice(0, count).map((name, i) => ({ version: 78 + i, name }))];
      const result = composeMigrations(registry, recorded);
      assert.equal(new Set(result.map(row => row.version)).size, result.length);
      for (const row of recorded) assert.equal(result.find(entry => entry.version === row.version).name, row.name);
      assert.deepEqual(result.slice(-6).map(row => row.name), order);
      for (const entry of result.slice(-6)) assert.equal(entry.sql, `immutable-${entry.name}`);
      assert.deepEqual(composeMigrations(registry, result), result, "replay keeps the same version/name/SQL plan");
    }
  }
  const { migrations } = require("../../apps/api/migrations/migrate");
  assert.deepEqual(migrations.filter(row => row.version >= 78).map(({version, name}) => ({version, name})), extensions.map(({version, name}) => ({version, name})));
  for (const count of [1, 2, 3, 4, 5]) assert.deepEqual(composeMigrations(registry, [...prior, ...extensions.slice(0, count)]), registry);
  assert.throws(() => composeMigrations(registry, [...prior, ...extensions.slice(0, 2), {version: 80, name: names[5]}]), /Unsupported Core migration history/);
});

test("cross-PR reservations reject collisions and compose without changing supported preview rows", () => {
  const { reservations, validateMigrationReservations } = require("../../apps/api/migrations/migration-reservations.cjs");
  const { migrations } = require("../../apps/api/migrations/migrate");
  const future = Object.entries(reservations).filter(([version]) => Number(version) > 83)
    .map(([version, name]) => ({ version: Number(version), name, sql: `reviewed-${name}` }));
  const registry = [...migrations, ...future];
  validateMigrationReservations(registry);
  for (const [version, name] of [[81, "recipient_channel_verification"], [81, "pagerduty_incident_lifecycle"],
    [81, "certops_distribution_lifecycle"], [82, "certops_material_cleanup"], [92, "pagerduty_incident_lifecycle"],
    [91, "certops_distribution_resolution_delivery"]]) {
    assert.throws(() => validateMigrationReservations([...migrations.filter(row => row.version !== version), { version, name }]), /Conflicting canonical Core migration/);
  }
  assert.throws(() => validateMigrationReservations([...migrations, migrations.at(-1)]), /Duplicate Core migration/);
  const before = composeMigrations(migrations, [...ledger(canonical), { version: 77, name: "onboarding_sessions" },
    ...["certops_installed_file_distribution", "auto_sync_provider_stats", "auto_sync_run_metrics", "certops_material_providers"]
      .map((name, i) => ({ version: 78 + i, name }))]);
  const composed = composeMigrations(registry, before);
  assert.deepEqual(composed.slice(0, before.length), before);
  assert.deepEqual(composed.slice(before.length), future);
  assert.deepEqual(composeMigrations(registry, composed), composed);
});

test("all 72 legacy distribution-first definitions retain their immutable historical SQL", () => {
  const coreRoot = path.resolve(__dirname, "../..");
  const { migrations } = require(
    path.join(coreRoot, "apps/api/migrations/migrate.js"),
  );
  const previous = composeMigrations(
    migrations,
    ledger(distribution, 3),
  ).filter((e) => e.version <= 72);
  assert.equal(previous.length, 72);
  assert.equal(
    crypto.createHash("sha256").update(JSON.stringify(previous)).digest("hex"),
    "eeae27b7b0cec957338e4e126bcefed29465b6441226925cd8930d77e49087d9",
  );
});

test("all 73 enrollment-first preview definitions retain their immutable historical SQL", () => {
  const coreRoot = path.resolve(__dirname, "../..");
  const { migrations } = require(
    path.join(coreRoot, "apps/api/migrations/migrate.js"),
  );
  const previous = composeMigrations(migrations, ledger(preview, 4)).filter(
    (e) => e.version <= 73,
  );
  assert.equal(previous.length, 73);
  assert.equal(
    crypto.createHash("sha256").update(JSON.stringify(previous)).digest("hex"),
    "c5c3d63c224fedc59fb37d8f1de99fb84b2d02dbbd86e2800ae9de7564be9099",
  );
});
