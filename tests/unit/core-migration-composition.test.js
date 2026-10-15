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
