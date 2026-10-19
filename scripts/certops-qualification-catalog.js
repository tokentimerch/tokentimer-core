"use strict";
/**
 * Validates the public outcome catalog and reports implementation scope separately from execution.
 * Run with node scripts/certops-qualification-catalog.js [catalog-path]. A partial mapping
 * documents supporting source; it is never a claim that a host or full outcome qualified.
 */
function validateCatalog(catalog) {
  const errors = [];
  if (catalog.schemaVersion !== 1 || !Array.isArray(catalog.scenarios) || !catalog.scenarios.length) return ["Invalid or empty scenario catalog"];
  const ids = new Set();
  for (const row of catalog.scenarios) {
    if (typeof row.id !== "string" || !/^[a-zA-Z0-9]+(?:[.-][a-zA-Z0-9]+)+$/.test(row.id) || ids.has(row.id)) errors.push(`Invalid or duplicate scenario: ${row.id}`);
    ids.add(row.id);
    if (typeof row.outcome !== "string" || !row.outcome.trim()) errors.push(`Missing outcome: ${row.id}`);
    if (!["planned", "partial", "implemented"].includes(row.status)) errors.push(`Invalid implementation status: ${row.id}`);
    if (!["unassigned", "unit", "integration", "real-host", "e2e"].includes(row.evidenceLevel)) errors.push(`Invalid evidence level: ${row.id}`);
    if (!Array.isArray(row.requiredEnvironments)) errors.push(`Invalid environment list: ${row.id}`);
    if (["partial", "implemented"].includes(row.status) && (!row.implementation || row.evidenceLevel === "unassigned" || !row.requiredEnvironments?.length)) errors.push(`Incomplete implementation mapping: ${row.id}`);
    if (row.status === "partial" && (typeof row.remainingCoverage !== "string" || !row.remainingCoverage.trim())) errors.push(`Partial scenario lacks remaining coverage: ${row.id}`);
  }
  return errors;
}
module.exports = { validateCatalog };
if (require.main === module) {
  try {
    const file = process.argv[2] || require("node:path").join(__dirname, "../docs/certops/qualification-suites.json");
    const catalog = JSON.parse(require("node:fs").readFileSync(file, "utf8"));
    const errors = validateCatalog(catalog);
    if (errors.length) { console.error(errors.join("\n")); process.exitCode = 1; }
    else console.log(`Valid catalog: ${catalog.scenarios.length} specifications, ${catalog.scenarios.filter((row) => row.status === "implemented").length} implemented, ${catalog.scenarios.filter((row) => row.status === "partial").length} partial mappings (execution evidence is separate).`);
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
