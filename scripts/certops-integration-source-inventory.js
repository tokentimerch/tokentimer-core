"use strict";
const fs = require("node:fs");
const path = require("node:path");
const root = path.resolve(__dirname, "..");
const expected = ["aws-acm", "azure-key-vault-certificate", "gcp-certificate-manager-cert", "gcp-compute-ssl-cert", "vault-kv", "vault-pki"];
function validateInventory(inventory, read = file => fs.readFileSync(path.join(root, file), "utf8")) {
  if (inventory?.schemaVersion !== 1 || !Array.isArray(inventory.sources)) throw new Error("Invalid integration source inventory");
  const kinds = inventory.sources.map(source => source.sourceKind);
  if (kinds.length !== expected.length || new Set(kinds).size !== kinds.length || expected.some(kind => !kinds.includes(kind))) throw new Error("Certificate integration source inventory is incomplete or duplicated");
  for (const source of inventory.sources) {
    if (source.liveProviderQualified !== false) throw new Error("Static inventory cannot qualify a live provider");
    for (const field of ["provider", "service", "scanner", "export", "source", "sourceKind", "objectIdentity", "instanceIdentity", "material"]) {
      if (typeof source[field] !== "string" || !source[field].trim()) throw new Error(`Missing source field: ${field}`);
    }
    if (!/^apps\/api\/services\/[A-Za-z]+Integration\.js$/.test(source.scanner)) throw new Error("Invalid scanner path");
    const code = read(source.scanner);
    if (!code.includes(`\"${source.source}\"`) || !code.includes(`\"${source.sourceKind}\"`) || !code.includes(source.export)) throw new Error(`Scanner mapping drift: ${source.sourceKind}`);
  }
  return { sources: kinds.length, liveProvidersQualified: 0 };
}
if (require.main === module) {
  const file = process.argv[2] || path.join(root, "docs/certops/integration-source-inventory.json");
  try { console.log(JSON.stringify(validateInventory(JSON.parse(fs.readFileSync(file, "utf8"))))); }
  catch (error) { console.error(error.message); process.exitCode = 1; }
}
module.exports = { validateInventory };
