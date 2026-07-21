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
      { action: "include", matchType: "exact", field: "location", value: "x" },
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
    ]);
    assert.strictEqual(err, null);
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

  it("treats missing fields as empty strings", () => {
    const rules = [
      { action: "exclude", matchType: "regex", field: "description", value: "^$" },
    ];
    assert.strictEqual(evaluateFilterRules(rules, { name: "x" }), false);
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
