"use strict";
/**
 * Defines the committed supporting database-integration test groups and mandatory case inventory.
 * Imported by the integration runner/reporter; the group contracts describe API/PostgreSQL
 * assertions and must not be interpreted as real Windows or enterprise CA execution.
 */
const fs = require("node:fs");
const path = require("node:path");
const groups = require("../tests/integration/certops-qualification-groups.json");
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
module.exports = { validateInventory };
