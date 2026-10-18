"use strict";
/**
 * Resolves committed mandatory scenario, capability and evidence-level contracts for qualification
 * producers and verifiers. Imported by the report tools; this metadata neither probes a host
 * nor treats supporting fixture tests as native certificate execution.
 */
function validateSuites(metadata) {
  const errors = [];
  if (metadata?.schemaVersion !== 1 || !metadata.suites || typeof metadata.suites !== "object" || Array.isArray(metadata.suites)) return ["Invalid qualification suite contract"];
  for (const [name, ids] of Object.entries(metadata.suites)) {
    if (!Array.isArray(ids) || !ids.length || ids.some((id) => typeof id !== "string" || !id) || new Set(ids).size !== ids.length) { errors.push(`Invalid mandatory scenario inventory: ${name}`); continue; }
    const capabilities = metadata.requiredCapabilities?.[name];
    if (!Array.isArray(capabilities) || !capabilities.length || capabilities.some((id) => typeof id !== "string" || !id) || new Set(capabilities).size !== capabilities.length) errors.push(`Invalid mandatory capability inventory: ${name}`);
    if (!["integration", "real-host", "e2e"].includes(metadata.suiteEvidenceLevels?.[name])) errors.push(`Missing suite evidence classification: ${name}`);
    const levels = metadata.scenarioEvidenceLevels?.[name] || {};
    for (const id of ids) if (!["unit", "integration", "real-host", "e2e"].includes(levels[id])) errors.push(`Missing scenario evidence classification: ${name}/${id}`);
    for (const id of Object.keys(levels)) if (!ids.includes(id)) errors.push(`Unrecognized scenario evidence classification: ${name}/${id}`);
  }
  if (!Object.keys(metadata.suites).length) errors.push("Empty qualification suite contract");
  return errors;
}
module.exports = { validateSuites };
