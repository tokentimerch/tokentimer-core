"use strict";
/**
 * Defines the committed supporting database-integration test groups and mandatory case inventory.
 * Imported by the integration runner/reporter; the group contracts describe API/PostgreSQL
 * assertions and must not be interpreted as real Windows or enterprise CA execution.
 */
const fs = require("node:fs");
const path = require("node:path");
const assert = require("node:assert/strict");
// Keep every named case explicit; group consecutive cases by file only on disk.
function expandGroups(input) {
  const result = structuredClone(input);
  for (const definition of Object.values(result)) {
    if (!Object.hasOwn(definition, "requiredTestsByFile")) continue;
    assert.ok(!Object.hasOwn(definition, "requiredTests"), "Conflicting case inventories");
    assert.ok(Array.isArray(definition.requiredTestsByFile) && definition.requiredTestsByFile.length > 0);
    definition.requiredTests = definition.requiredTestsByFile.flatMap(({file, names}) => {
      assert.ok(definition.files.includes(file), "Unlisted test source");
      assert.ok(Array.isArray(names) && names.length > 0 && names.every(name => typeof name === "string" && name.length > 0));
      return names.map(name => ({file, name}));
    });
    const keys = definition.requiredTests.map(row => `${row.file}\0${row.name}`);
    assert.equal(new Set(keys).size, keys.length, "Duplicate mandatory case");
    delete definition.requiredTestsByFile;
  }
  return result;
}
const groups = expandGroups(require("../tests/integration/certops-qualification-groups.json"));
// Resolve literal names and the adjacent literal-array loops used to declare
// parameterized cases. Never execute test sources or accept a partial name.
function testNames(source) {
  const literal = '"(?:\\\\.|[^"\\\\])*"';
  const expression = `${literal}(?:\\s*\\+\\s*(?:${literal}|[A-Za-z_$][\\w$]*))*`;
  const cases = [...source.matchAll(new RegExp(`\\bit\\(\\s*(${expression})\\s*,`, "g"))];
  assert.equal(cases.length, [...source.matchAll(/\bit\(\s*"/g)].length, "Unsupported mandatory case name expression");
  return cases.flatMap(match => {
    const parts = match[1].match(new RegExp(`${literal}|[A-Za-z_$][\\w$]*`, "g"));
    if (parts.length === 1) return [JSON.parse(parts[0])];
    const loop = source.slice(0, match.index).match(/for\s*\(\s*const\s+([A-Za-z_$][\w$]*)\s+of\s+(\[[^\]\n]*\])\s*\)\s*\{\s*$/);
    assert.ok(loop, "Parameterized mandatory cases require an adjacent literal-array loop");
    const values = JSON.parse(loop[2]);
    assert.ok(values.length > 0 && values.every(value => typeof value === "string"), "Mandatory case parameters must be literal strings");
    return values.map(value => parts.map(part => {
      if (part.startsWith('"')) return JSON.parse(part);
      assert.equal(part, loop[1], "Unknown mandatory case name parameter");
      return value;
    }).join(""));
  });
}
function validateInventory() {
  for (const [group, definition] of Object.entries(groups)) {
    const actual = [];
    for (const file of definition.files) {
      const source = fs.readFileSync(path.join(__dirname, "../tests/integration", file), "utf8");
      const names = testNames(source);
      if (!names.length) throw new Error(`${group}: no literal mandatory cases in ${file}`);
      for (const name of names) actual.push(`${file}\0${name}`);
    }
    const expected = definition.requiredTests.map((entry) => `${entry.file}\0${entry.name}`);
    if (JSON.stringify(actual.sort()) !== JSON.stringify(expected.sort())) throw new Error(`${group}: mandatory case inventory drift; update committed qualification group definitions`);
  }
  return Object.keys(groups).length;
}
if (require.main === module) {
  try { console.log(`Validated ${validateInventory()} mandatory integration group inventories`); }
  catch (error) { console.error(error.message); process.exitCode = 1; }
}
module.exports = { validateInventory, groups, expandGroups, testNames };
