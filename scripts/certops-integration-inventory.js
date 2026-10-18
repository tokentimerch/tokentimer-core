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
function validateInventory() {
  for (const [group, definition] of Object.entries(groups)) {
    const actual = [];
    for (const file of definition.files) {
      const source = fs.readFileSync(path.join(__dirname, "../tests/integration", file), "utf8");
      const names = [...source.matchAll(/\bit\(\s*"([^"\n]+)"/g)].map((match) => match[1]);
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
module.exports = { validateInventory, groups, expandGroups };
