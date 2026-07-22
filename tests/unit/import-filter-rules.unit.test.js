"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert");
const {
  validateFilterRules,
  evaluateFilterRules,
  applyFilterRules,
} = require("../../apps/api/services/importFilterRules");

describe("importFilterRules.validateFilterRules", () => {
  it("accepts undefined/null (no rules)", () => {
    assert.strictEqual(validateFilterRules(undefined), null);
    assert.strictEqual(validateFilterRules(null), null);
  });

  it("accepts an empty array", () => {
    assert.strictEqual(validateFilterRules([]), null);
  });

  it("rejects a non-array payload", () => {
    assert.match(validateFilterRules("nope"), /must be an array/);
  });

  it("rejects an invalid action", () => {
    const err = validateFilterRules([
      { action: "keep", matchType: "exact", field: "name", value: "x" },
    ]);
    assert.match(err, /action/);
  });

  it("rejects an invalid matchType", () => {
    const err = validateFilterRules([
      { action: "include", matchType: "glob", field: "name", value: "x" },
    ]);
    assert.match(err, /matchType/);
  });

  it("rejects an invalid field", () => {
    const err = validateFilterRules([
      { action: "include", matchType: "exact", field: "owner", value: "x" },
    ]);
    assert.match(err, /field/);
  });

  it("rejects an empty value", () => {
    const err = validateFilterRules([
      { action: "include", matchType: "exact", field: "name", value: "" },
    ]);
    assert.match(err, /non-empty string/);
  });

  it("rejects an invalid regex with a clear error", () => {
    const err = validateFilterRules([
      { action: "include", matchType: "regex", field: "name", value: "[" },
    ]);
    assert.match(err, /not a valid regular expression/);
  });

  it("accepts a valid mixed rule set", () => {
    const err = validateFilterRules([
      {
        action: "include",
        matchType: "regex",
        field: "description",
        value: "^iac-provisioned:.*",
      },
      { action: "exclude", matchType: "exact", field: "name", value: "temp" },
      {
        action: "exclude",
        matchType: "regex",
        field: "location",
        value: "^gitlab:projects/42/",
      },
    ]);
    assert.strictEqual(err, null);
  });

  it("rejects a classic catastrophic-backtracking pattern (nested +)", () => {
    const err = validateFilterRules([
      { action: "include", matchType: "regex", field: "name", value: "^(a+)+$" },
    ]);
    assert.match(err, /potentially unsafe regular expression pattern/);
    assert.match(err, /nested quantifiers detected/);
  });

  it("rejects other common nested-quantifier shapes", () => {
    const unsafeValues = ["(a*)*", "(a+)*", "(a*)+", "(a{2,})+", "((a+))+"];
    for (const value of unsafeValues) {
      const err = validateFilterRules([
        { action: "include", matchType: "regex", field: "name", value },
      ]);
      assert.match(
        err,
        /nested quantifiers detected/,
        `expected ${value} to be rejected`,
      );
    }
  });

  it("rejects a pattern with too many quantifiers even without nesting", () => {
    const value =
      "a{1,3}b{1,3}c{1,3}d{1,3}e{1,3}f{1,3}g{1,3}h{1,3}i{1,3}j{1,3}k{1,3}";
    const err = validateFilterRules([
      { action: "include", matchType: "regex", field: "name", value },
    ]);
    assert.match(err, /too many quantifiers/);
  });

  it("still accepts common, safe regex patterns", () => {
    const safeValues = [
      "^iac-provisioned:.*",
      "^v\\d+\\.\\d+\\.\\d+$",
      "(foo|bar)+",
      "^[a-z0-9_-]+$",
      "temp-[0-9]{1,4}$",
    ];
    for (const value of safeValues) {
      const err = validateFilterRules([
        { action: "include", matchType: "regex", field: "name", value },
      ]);
      assert.strictEqual(err, null, `expected ${value} to be accepted`);
    }
  });
});

describe("importFilterRules.evaluateFilterRules", () => {
  const item = (name, description) => ({ name, description });

  it("keeps everything when no rules are defined", () => {
    assert.strictEqual(evaluateFilterRules([], item("a", "b")), true);
    assert.strictEqual(evaluateFilterRules(undefined, item("a", "b")), true);
  });

  it("denylist: only exclude rules keep non-matching items", () => {
    const rules = [
      { action: "exclude", matchType: "exact", field: "name", value: "bad" },
    ];
    assert.strictEqual(evaluateFilterRules(rules, item("good", "")), true);
    assert.strictEqual(evaluateFilterRules(rules, item("bad", "")), false);
  });

  it("allowlist: any include rule requires items to match one", () => {
    const rules = [
      {
        action: "include",
        matchType: "regex",
        field: "description",
        value: "^iac-provisioned:",
      },
    ];
    assert.strictEqual(
      evaluateFilterRules(rules, item("t1", "iac-provisioned: ci")),
      true,
    );
    assert.strictEqual(
      evaluateFilterRules(rules, item("t2", "manually created")),
      false,
    );
  });

  it("exclude wins over include", () => {
    const rules = [
      {
        action: "include",
        matchType: "regex",
        field: "name",
        value: ".*",
      },
      {
        action: "exclude",
        matchType: "exact",
        field: "name",
        value: "secret-token",
      },
    ];
    assert.strictEqual(evaluateFilterRules(rules, item("other", "")), true);
    assert.strictEqual(
      evaluateFilterRules(rules, item("secret-token", "")),
      false,
    );
  });

  it("include by exact value overrides missing convention (targeted include)", () => {
    const rules = [
      {
        action: "include",
        matchType: "regex",
        field: "description",
        value: "^iac-provisioned:",
      },
      {
        action: "include",
        matchType: "exact",
        field: "name",
        value: "legacy-but-ours",
      },
    ];
    assert.strictEqual(
      evaluateFilterRules(rules, item("legacy-but-ours", "no convention")),
      true,
    );
    assert.strictEqual(
      evaluateFilterRules(rules, item("random", "no convention")),
      false,
    );
  });

  it("matches description via notes fallback", () => {
    const rules = [
      {
        action: "include",
        matchType: "regex",
        field: "description",
        value: "^iac-",
      },
    ];
    assert.strictEqual(
      evaluateFilterRules(rules, { name: "x", notes: "iac-managed" }),
      true,
    );
  });

  it("treats a wholly empty item as an empty string", () => {
    const rules = [
      { action: "exclude", matchType: "regex", field: "description", value: "^$" },
    ];
    assert.strictEqual(evaluateFilterRules(rules, {}), false);
  });

  it("falls back to name for description when no description/notes exist (issue: description matching found nothing for token types with no separate description field, e.g. GitLab PATs/project/group/deploy tokens)", () => {
    const rules = [
      { action: "include", matchType: "exact", field: "description", value: "prod-ci-token" },
    ];
    assert.strictEqual(
      evaluateFilterRules(rules, { name: "prod-ci-token" }),
      true,
    );
    assert.strictEqual(
      evaluateFilterRules(rules, { name: "other-token" }),
      false,
    );
  });

  it("prefers a real description/notes value over the name fallback", () => {
    const rules = [
      { action: "include", matchType: "exact", field: "description", value: "real description" },
    ];
    assert.strictEqual(
      evaluateFilterRules(rules, {
        name: "unrelated-name",
        description: "real description",
      }),
      true,
    );
    assert.strictEqual(
      evaluateFilterRules(rules, { name: "real description" }),
      true,
    );
  });

  it("matches on the location field with regex and exact rules", () => {
    const regexRules = [
      {
        action: "exclude",
        matchType: "regex",
        field: "location",
        value: "^gitlab:projects/42/",
      },
    ];
    assert.strictEqual(
      evaluateFilterRules(regexRules, {
        name: "ci-token",
        location: "gitlab:projects/42/access_tokens/7",
      }),
      false,
    );
    assert.strictEqual(
      evaluateFilterRules(regexRules, {
        name: "ci-token",
        location: "gitlab:projects/99/access_tokens/7",
      }),
      true,
    );

    const exactRules = [
      {
        action: "include",
        matchType: "exact",
        field: "location",
        value: "vault:secret/data/ci",
      },
    ];
    assert.strictEqual(
      evaluateFilterRules(exactRules, {
        name: "x",
        location: "vault:secret/data/ci",
      }),
      true,
    );
    assert.strictEqual(
      evaluateFilterRules(exactRules, {
        name: "x",
        location: "vault:secret/data/other",
      }),
      false,
    );
  });

  it("treats a missing location as an empty string with no name fallback", () => {
    const rules = [
      {
        action: "include",
        matchType: "regex",
        field: "location",
        value: "ci-token",
      },
    ];
    // Unlike description, location must not fall back to the item name:
    // a rule targeting provider paths should never accidentally match names.
    assert.strictEqual(evaluateFilterRules(rules, { name: "ci-token" }), false);
    assert.strictEqual(
      evaluateFilterRules(rules, { name: "x", location: "gitlab:ci-token" }),
      true,
    );
  });

  it("truncates the matched field value so very long input cannot slow down regex matching", () => {
    // "TARGET" sits well past the input-length cap used for regex matching,
    // so a truncation-aware implementation will not find it. This proves
    // the cap is actually enforced at match time (not just documented),
    // without ever running a genuinely catastrophic pattern against a
    // large string.
    const longValue = "a".repeat(50000) + "TARGET";
    const rules = [
      { action: "include", matchType: "regex", field: "name", value: "TARGET$" },
    ];
    const start = Date.now();
    const result = evaluateFilterRules(rules, { name: longValue });
    const elapsed = Date.now() - start;
    assert.strictEqual(result, false);
    assert.ok(elapsed < 500, `expected a fast, bounded match, took ${elapsed}ms`);
  });
});

describe("importFilterRules.applyFilterRules", () => {
  it("returns original list and zero excluded with no rules", () => {
    const items = [{ name: "a" }, { name: "b" }];
    const res = applyFilterRules([], items);
    assert.strictEqual(res.items, items);
    assert.strictEqual(res.matchedCount, 2);
    assert.strictEqual(res.excludedCount, 0);
  });

  it("reports matched and excluded counts", () => {
    const rules = [
      { action: "exclude", matchType: "regex", field: "name", value: "^tmp-" },
    ];
    const res = applyFilterRules(rules, [
      { name: "tmp-1" },
      { name: "keep" },
      { name: "tmp-2" },
    ]);
    assert.strictEqual(res.matchedCount, 1);
    assert.strictEqual(res.excludedCount, 2);
    assert.deepStrictEqual(
      res.items.map((i) => i.name),
      ["keep"],
    );
  });
});
