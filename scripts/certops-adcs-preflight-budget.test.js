"use strict";
/** Source budget audit, not native execution. Count the actual descriptor sets
 * and pin every primary dispatch/cache boundary so adding a new caller requires
 * explicit budget review rather than silently producing an impossible lane. */
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  vm = require("node:vm");
const root = path.resolve(__dirname, ".."),
  main = fs.readFileSync(
    path.join(root, "tests/e2e/certops-adcs-real-e2e.test.js"),
    "utf8",
  );
const read = (file) => fs.readFileSync(path.join(root, file), "utf8");
test("actual native descriptor and cache generations fit the original18 primary budget", () => {
  const match = main.match(/const cases = (\[[^;]+\]);/);
  assert.ok(match);
  // The checked-in descriptor literal contains only reviewed public fixture data.
  assert.match(match[1], /^\[[\w\s{}:,"-]+\]$/);
  const profiles = vm.runInNewContext(match[1], Object.create(null), {
    timeout: 1000,
  });
  const safety = require("../infra/certops-adcs/safety-cases.json");
  const denied = main.match(/const deniedCases=(\[[^;]+?\])\.map/);
  assert.ok(denied);
  assert.match(denied[1], /^\[[\w\s{}:,".-]+\]$/);
  const denials = vm.runInNewContext(denied[1], Object.create(null), {
    timeout: 1000,
  });
  const initial = new Set([
    ...profiles.map((row) => row.template),
    ...denials.map((row) => row.template),
    "TTQualificationPending",
    "TTQualificationPendingOlder",
  ]);
  for (const row of safety.keyConstraintCases)
    assert.ok(
      initial.has(row.template),
      "New constraint template requires primary budget review",
    );
  assert.equal(initial.size, 11);
  const flags = new Set(safety.caFlagCases.map((row) => row.template));
  assert.equal(flags.size, safety.caFlagCases.length);
  assert.match(
    main,
    /const item=\{\.\.\.descriptor,template:renewalFixture\.item\.template\}/,
  );
  const pendingNewKeyRecovery = 1,
    freshCapacity = 2,
    automaticFreshChecks = 2,
    rootCaRechecks = 2;
  const rootMaximum =
    initial.size +
    automaticFreshChecks +
    freshCapacity +
    rootCaRechecks +
    pendingNewKeyRecovery;
  const hierarchyMaximum =
    initial.size + automaticFreshChecks + freshCapacity + 1; // cache cleared by flags; tail repopulates RSAshort
  assert.equal(rootMaximum, 18);
  assert.equal(hierarchyMaximum, 16);
  assert.ok(rootMaximum + 2 <= 20);
});
test("all primary caller and cache invalidation sites are explicitly audited", () => {
  assert.equal((main.match(/await preflight\(/g) || []).length, 6);
  assert.equal((main.match(/preflightCache\.clear\(\)/g) || []).length, 4);
  assert.equal((main.match(/preflightCache\.set\(/g) || []).length, 2);
  assert.equal((main.match(/\+\+primaryPreflightCount/g) || []).length, 5);
  assert.match(
    main,
    /assert\.equal\(count,2\);assert\.ok\(primaryPreflightCount\+count<=18/,
  );
  assert.match(
    main,
    /preflightCache\.set\(item\.template,\{issuerId,result:preflightResult\}\)/,
  );
  const helpers = [
    "algorithm-boundaries",
    "issued-cancellation",
    "journal-phase-experiment",
    "local-rules",
    "pending-elapsed",
    "submission-boundaries",
    "uncertain-abandon",
    "validity-boundaries",
  ];
  for (const name of helpers)
    assert.equal(
      (
        read(`tests/e2e/helpers/certops-adcs-${name}.js`).match(
          /await preflight\(/g,
        ) || []
      ).length,
      1,
      name,
    );
  const capacity = read("tests/e2e/helpers/certops-adcs-capacity.js");
  assert.equal((capacity.match(/await preflight\(/g) || []).length, 2);
  assert.match(capacity, /reservePrimaryPreflights\(2\)/);
  const pendingNewKey = read(
    "tests/e2e/helpers/certops-adcs-pending-ca-key-change.js",
  );
  assert.equal(
    (pendingNewKey.match(/reservePrimaryPreflights\(1\)/g) || []).length,
    1,
  );
  assert.equal((pendingNewKey.match(/\/preflight`,\s*"POST"/g) || []).length, 1);
});
