"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");

test("the installed Mocha CLI expands recursive globs and preserves exclusions", () => {
  const Mocha = require("mocha");
  assert.equal(typeof Mocha.reporters.Spec, "function");
  assert.equal(typeof Mocha.Runner.constants, "object");
  const base = path.resolve(os.tmpdir());
  const fixture = fs.mkdtempSync(path.join(base, "tt-mocha-glob-"));
  try {
    fs.mkdirSync(path.join(fixture, "nested space"));
    for (const [file, title] of [
      ["root.test.js", "root case"],
      ["nested space/nested.test.js", "nested case"],
      ["nested space/excluded.test.js", "excluded case"],
    ]) {
      fs.writeFileSync(
        path.join(fixture, file),
        `it(${JSON.stringify(title)}, function () {});\n`,
      );
    }
    const glob = `${fixture.replaceAll("\\", "/")}/**/*.test.js`;
    const excluded = path
      .join(fixture, "nested space/excluded.test.js")
      .replaceAll("\\", "/");
    for (const extra of [[], ["--dry-run"]]) {
      const result = spawnSync(
        process.execPath,
        [
          require.resolve("mocha/bin/mocha.js"),
          "--no-config",
          "--no-package",
          glob,
          "--ignore",
          excluded,
          ...extra,
          "--reporter",
          "json",
        ],
        {
          cwd: fixture,
          encoding: "utf8",
          timeout: 30000,
        },
      );
      assert.equal(result.status, 0, result.stderr || result.error?.message);
      const report = JSON.parse(result.stdout);
      assert.equal(report.stats.tests, 2);
      assert.deepEqual(report.tests.map((entry) => entry.title).sort(), [
        "nested case",
        "root case",
      ]);
    }
  } finally {
    assert.equal(path.dirname(fs.realpathSync(fixture)), fs.realpathSync(base));
    assert.ok(path.basename(fixture).startsWith("tt-mocha-glob-"));
    fs.rmSync(fixture, { recursive: true, force: true });
  }
});
