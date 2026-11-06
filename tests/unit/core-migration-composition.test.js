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
test("recipient preview ledgers keep applied rows and leave room for the other open migrations", () => {
  const names = [
    ...canonical,
    "onboarding_sessions",
    "certops_installed_file_distribution",
    "auto_sync_provider_stats",
    "auto_sync_run_metrics",
    "auto_sync_metric_labels",
    "recipient_channel_verification",
    "weekly_digest_recipient_claim_token",
  ];
  const migrations = [
    { version: 69, name: "prior", sql: "prior" },
    ...names.map((name, index) => ({ version: 70 + index, name, sql: name })),
  ];
  const fresh = composeMigrations(migrations, names.slice(0, 12).map((name, index) => ({ version: 70 + index, name })));
  assert.equal(fresh.find((entry) => entry.version === 81).name, "auto_sync_metric_labels");
  assert.equal(fresh.find((entry) => entry.version === 82).name, "recipient_channel_verification");
  assert.equal(fresh.find((entry) => entry.version === 83).name, "weekly_digest_recipient_claim_token");
  const previewNames = names.slice(0, 11).concat([
    "recipient_channel_verification",
    "weekly_digest_recipient_claim_token",
  ]);
  const preview = composeMigrations(
    migrations,
    previewNames.map((name, index) => ({ version: 70 + index, name })),
  );
  assert.equal(preview.find((entry) => entry.version === 81).name, "recipient_channel_verification");
  assert.equal(preview.find((entry) => entry.version === 82).name, "weekly_digest_recipient_claim_token");
  assert.equal(preview.find((entry) => entry.version === 83).name, "auto_sync_metric_labels");
  assert.equal(preview.filter((entry) => entry.version === 83).length, 1);
  assert.throws(
    () => composeMigrations(migrations, [
      ...names.slice(0, 11).map((name, index) => ({ version: 70 + index, name })),
      { version: 81, name: "pagerduty_incident_lifecycle" },
    ]),
    /pagerduty_incident_lifecycle/,
  );
  assert.throws(
    () => composeMigrations(migrations, [
      ...names.slice(0, 11).map((name, index) => ({ version: 70 + index, name })),
      { version: 81, name: "certops_material_providers" },
    ]),
    /certops_material_providers/,
  );
  assert.throws(
    () => composeMigrations(migrations, [
      ...names.slice(0, 11).map((name, index) => ({ version: 70 + index, name })),
      { version: 81, name: "certops_distribution_lifecycle" },
    ]),
    /certops_distribution_lifecycle/,
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
  assert.deepEqual(migrations.filter(row => row.version >= 78 && row.version <= 83).map(({version, name}) => ({version, name})), extensions.map(({version, name}) => ({version, name})));
  for (const count of [1, 2, 3, 4, 5]) assert.deepEqual(composeMigrations(registry, [...prior, ...extensions.slice(0, count)]), registry);
  assert.throws(() => composeMigrations(registry, [...prior, ...extensions.slice(0, 2), {version: 80, name: names[5]}]), /Unsupported Core migration history/);
});

test("cross-PR reservations reject collisions and compose without changing supported preview rows", () => {
  const { reservations, validateMigrationReservations } = require("../../apps/api/migrations/migration-reservations.cjs");
  const { migrations } = require("../../apps/api/migrations/migrate");
  const future = Object.entries(reservations).filter(([version]) => Number(version) > 83)
    .map(([version, name]) => ({ version: Number(version), name, sql: `reviewed-${name}` }))
    .filter(entry => !migrations.some(row => row.version === entry.version || row.name === entry.name));
  const registry = [...migrations, ...future];
  validateMigrationReservations(registry);
  for (const [version, name] of [[81, "recipient_channel_verification"], [81, "pagerduty_incident_lifecycle"],
    [81, "certops_distribution_lifecycle"], [82, "certops_material_cleanup"], [86, "pagerduty_incident_lifecycle"],
    [92, "certops_distribution_resolution_delivery"]]) {
    assert.throws(() => validateMigrationReservations([...migrations.filter(row => row.version !== version && row.name !== name), { version, name }]), /Conflicting canonical Core migration/);
  }
  assert.throws(() => validateMigrationReservations([...migrations, migrations.at(-1)]), /Duplicate Core migration/);
  const before = composeMigrations(migrations, [...ledger(canonical), { version: 77, name: "onboarding_sessions" },
    ...["certops_installed_file_distribution", "auto_sync_provider_stats", "auto_sync_run_metrics", "certops_material_providers"]
      .map((name, i) => ({ version: 78 + i, name }))]);
  const composed = composeMigrations(registry, before);
  assert.deepEqual(composed.slice(0, before.length), before);
  assert.deepEqual(composed.slice(before.length).map(({ name, sql }) => ({ name, sql })),
    future.map(({ name, sql }) => ({ name, sql })));
  assert.ok(composed.slice(before.length).every(row => row.version > Math.max(...before.map(prior => prior.version))),
    "unapplied companions append after the immutable preview tail");
  assert.deepEqual(composeMigrations(registry, composed), composed);
});

test("manual rollout authority composes before or after reserved companion migrations", () => {
  const { migrations } = require("../../apps/api/migrations/migrate");
  const { reservations } = require("../../apps/api/migrations/migration-reservations.cjs");
  const future = Object.entries(reservations)
    .filter(([version]) => [86, 87, 88, 89, 90, 91, 96, 97].includes(Number(version)))
    .map(([version, name]) => ({ version:Number(version), name, sql:`future-${name}` }));
  const registry = [...migrations, ...future];
  const current = composeMigrations(migrations);
  const applied = current.map(({ version,name }) => ({ version,name }));
  const planned = composeMigrations(registry, applied);
  for (const entry of applied) assert.equal(planned.find(row => row.name === entry.name).version, entry.version);
  assert.equal(new Set(planned.map(row => row.version)).size, planned.length);
  assert.deepEqual(composeMigrations(registry, planned), planned);
});

test("the reviewed MCP 94-96 preview keeps full and partial ledgers before OAuth arrives", () => {
  const { migrations } = require("../../apps/api/migrations/migrate");
  const original = migrations.filter(entry => entry.version <= 85 || [92, 93].includes(entry.version));
  const names = ["operator_connections", "operator_enrollment_grants", "operator_action_requests"];
  for (const count of [1, 2, 3]) {
    const prior = [...original, ...names.slice(0, count).map((name, index) => ({ ...migrations.find(entry => entry.name === name), version: 94 + index }))];
    const result = composeMigrations(migrations, prior);
    for (const row of prior) assert.equal(result.find(entry => entry.name === row.name).version, row.version);
    for (const name of names) assert.equal(result.find(entry => entry.name === name).version, 94 + names.indexOf(name));
    assert.equal(result.find(entry => entry.name === "pagerduty_operator_actions").version, 97);
    assert.equal(result.find(entry => entry.name === "operator_oauth").version, 100);
    assert.deepEqual(composeMigrations(migrations, result), result);
  }
  assert.throws(() => composeMigrations(migrations, [...original, { version: 95, name: names[0] }]), /Unsupported Core migration history/);
});

test("MCP draft 96-103 upgrades without replacing the manual authority migration", () => {
  const { migrations } = require("../../apps/api/migrations/migrate");
  const original = migrations.filter((entry) => entry.version <= 85 || [92, 93, 94, 95].includes(entry.version));
  const names = ["operator_connections", "operator_enrollment_grants", "operator_action_requests", "operator_oauth", "operator_connection_lifetimes", "operator_inventory", "operator_oauth_retention", "operator_issuance"];
  for (let count = 1; count <= names.length; count++) {
    const prior = [...original, ...names.slice(0, count).map((name, index) => ({ ...migrations.find((entry) => entry.name === name), version: 96 + index }))];
    const planned = composeMigrations(migrations, prior);
    for (const row of prior) assert.equal(planned.find((entry) => entry.name === row.name).version, row.version);
    assert.ok(planned.find((entry) => entry.name === "certops_manual_rollout_authority").version > 103);
    assert.deepEqual(composeMigrations(migrations, planned), planned);
  }
});

test("MCP lifetime, inventory and retention upgrades preserve partial preview ledgers before and after companion features", () => {
  const { migrations } = require("../../apps/api/migrations/migrate");
  const { reservations } = require("../../apps/api/migrations/migration-reservations.cjs");
  const companions = Object.entries(reservations).filter(([version]) => Number(version) >= 86 && Number(version) <= 91)
    .map(([version, name]) => ({ version: Number(version), name, sql: "SELECT 1;" }));
  const integrated = [...migrations, ...companions];
  const prefix = migrations.filter((row) => row.version < 78);
  const earlierNames = ["certops_installed_file_distribution", "auto_sync_provider_stats", "auto_sync_run_metrics", "auto_sync_metric_labels", "auto_sync_system_metrics", "operator_connections", "operator_enrollment_grants", "operator_action_requests"];
  const histories = [
    migrations.filter((row) => row.version <= 102),
    [...prefix, ...["certops_installed_file_distribution", "auto_sync_provider_stats", "auto_sync_run_metrics", "certops_material_providers"].map((name, index) => ({ version: 78 + index, name }))],
    ...[1, 2, 3].map((count) => [...prefix, ...earlierNames.slice(0, 5 + count).map((name, index) => ({ version: 78 + index, name }))]),
    ...[1, 2, 3].map((count) => [...migrations.filter((row) => row.version <= 85 || [92, 93].includes(row.version)), ...["operator_connections", "operator_enrollment_grants", "operator_action_requests"].slice(0, count).map((name, index) => ({ version: 94 + index, name }))]),
  ];
  const preserve = (recorded, plan) => {
    for (const row of recorded) {
      const found = plan.find((entry) => entry.version === row.version);
      assert.equal(found?.name, row.name, `applied ${row.version}/${row.name} stays unchanged`);
      if (row.sql) assert.equal(found.sql, row.sql, `applied SQL for ${row.name} stays unchanged`);
    }
    assert.equal(new Set(plan.map((row) => row.version)).size, plan.length);
    assert.equal(new Set(plan.map((row) => row.name)).size, plan.length);
    assert.deepEqual(composeMigrations(integrated, plan), plan, "completed upgrade plan replays unchanged");
  };
  for (const history of histories) {
    for (const lastVersion of [102, 103, 104, 105, 106, 107, 108]) {
      const registry = migrations.filter((row) => row.version <= lastVersion);
      const oldPlan = composeMigrations(registry, history);
      const firstMcp = oldPlan.findIndex((row) => row.name === "operator_connections");
      for (let length = firstMcp; length <= oldPlan.length; length++) {
        const recorded = oldPlan.slice(0, length);
        preserve(recorded, composeMigrations(integrated, recorded));
        const companionsFirst = composeMigrations([...registry, ...companions], recorded);
        preserve(companionsFirst, composeMigrations(integrated, companionsFirst));
      }
    }
  }
});

test("new MCP schema dependencies cannot be recorded before their required tables", () => {
  const { migrations } = require("../../apps/api/migrations/migrate");
  const prefix = migrations.filter((row) => row.version < 99);
  for (const name of ["operator_connection_lifetimes", "operator_inventory", "operator_oauth_retention"]) {
    const entry = migrations.find((row) => row.name === name);
    assert.throws(() => composeMigrations(migrations, [...prefix, entry]), /incomplete dependency/);
  }
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

test("PagerDuty's independent slot preserves applied history while companion migrations arrive later", () => {
  const registered = require("../../apps/api/migrations/migrate").migrations;
  const migrations = registered.filter(row => row.version <= 82 || ["pagerduty_incident_lifecycle", "pagerduty_resolution_reason", "pagerduty_operator_actions", "remove_pagerduty_rest_lookup"].includes(row.name));
  const applied = migrations.map(({ version, name }) => ({ version, name, executed_at: "unchanged" }));
  const snapshot = JSON.stringify(applied);
  const companions = [
    [83, "certops_material_providers"], [84, "recipient_channel_verification"],
    [85, "weekly_digest_recipient_claim_token"], [86, "certops_distribution_lifecycle"],
    [87, "certops_distribution_incident_delivery"], [88, "certops_stable_consumer_discovery"],
    [89, "certops_material_cleanup"], [90, "certops_consumer_verification_failures"],
    [91, "certops_distribution_resolution_delivery"],
  ].map(([version, name]) => registered.find(row => row.name === name) || ({ version, name, sql: "SELECT 1" }));
  const integrated = [...migrations, ...companions].sort((a,b) => a.version-b.version);
  for (let length = 0; length <= companions.length; length++) {
    const recorded = [...applied, ...companions.slice(0,length)].sort((a,b) => a.version-b.version);
    const plan = composeMigrations(integrated, recorded);
    assert.equal(plan.find(entry => entry.name === "pagerduty_incident_lifecycle").version, 92);
    assert.deepEqual(plan.map(entry => entry.version), integrated.map(entry => entry.version));
  }
  assert.equal(JSON.stringify(applied), snapshot);
  // This PR's earlier 1-81 + 92 candidate must accept main's later migration82
  // without rewriting its already applied PagerDuty identity or timestamp.
  const previousPagerDutyCandidate = applied.filter(row => row.version !== 82);
  const laterMainPlan = composeMigrations(migrations, previousPagerDutyCandidate);
  assert.equal(laterMainPlan.find(row => row.name === "auto_sync_system_metrics").version, 82);
  assert.equal(JSON.stringify(previousPagerDutyCandidate), JSON.stringify(applied.filter(row => row.version !== 82)));
  for (const name of ["recipient_channel_verification", "certops_material_providers", "certops_distribution_lifecycle"]) {
    const incompatible = [...applied.filter(row => row.version !== 81), { version: 81, name }];
    assert.throws(() => composeMigrations(integrated, incompatible), /Unsupported Core migration history/);
  }
  assert.throws(() => composeMigrations(integrated, [{ version: 92, name: "pagerduty_incident_lifecycle" }]), /Unsupported Core migration history/);
});
