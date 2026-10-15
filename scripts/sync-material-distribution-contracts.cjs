"use strict";
// Embed local $refs so consumers compiling one schema remain compatible.
// material-distribution.schema.json is the sole editable source of shapes.
const fs = require("node:fs");
const path = require("node:path");
const root = path.resolve(__dirname, "..");
const base = path.join(root, "packages/contracts/certops");
const source = JSON.parse(fs.readFileSync(path.join(base, "material-distribution.schema.json")));
source.definitions.publicationProfile = structuredClone(source.definitions.publication);
source.definitions.publicationProfile.required = source.definitions.publicationProfile.required.filter((key) => key !== "materialVersionId");
delete source.definitions.publicationProfile.properties.materialVersionId;
fs.writeFileSync(path.join(base, "material-distribution.schema.json"), JSON.stringify(source, null, 2) + "\n");
const definitions = Object.fromEntries(Object.entries(source.definitions).map(([key, value]) =>
  [`materialDistribution_${key}`, JSON.parse(JSON.stringify(value).replaceAll("#/definitions/", "#/definitions/materialDistribution_"))]));
for (const file of ["job-payload.schema.json", "agent-protocol.schema.json", "renewal-profile.schema.json"]) {
  const target = path.join(base, file);
  const schema = JSON.parse(fs.readFileSync(target));
  schema.definitions = { ...schema.definitions, ...definitions };
  if (file === "job-payload.schema.json") {
    for (const field of ["publication", "materialDeployment"]) schema.properties[field] = { $ref: `#/definitions/materialDistribution_${field}` };
    if (!schema.properties.action.enum.includes("deploy-from-store")) schema.properties.action.enum.push("deploy-from-store");
  } else if (file === "agent-protocol.schema.json") {
    const actions = schema.definitions.claimBody.properties.supportedActions.items.enum;
    if (!actions.includes("deploy-from-store")) actions.push("deploy-from-store");
    for (const field of ["publicationReceipt", "deploymentReceipt"]) schema.definitions.resultBody.properties[field] = { $ref: `#/definitions/materialDistribution_${field}` };
    schema.definitions.resultBody.properties.publicationCertificatePem = {
      type: "string", minLength: 1, maxLength: 262144,
      description: "Vetted public leaf/chain only; accepted solely with a claim-bound publication receipt. Never persisted in generic job/outbox JSON."
    };
  } else {
    schema.properties.publicationDestination = { $ref: "#/definitions/materialDistribution_publicationProfile" };
    schema.properties.deploymentTargets.minItems = 0;
    schema.allOf = [{ if: { required: ["publicationDestination"] }, then: { properties: { deploymentTargets: { maxItems: 0 } } },
      else: { properties: { deploymentTargets: { minItems: 1 } } } }];
  }
  fs.writeFileSync(target, JSON.stringify(schema, null, 2) + "\n");
}
const manifestPath = path.join(root, "contracts.manifest.json");
const manifest = JSON.parse(fs.readFileSync(manifestPath));
const namespace = manifest.namespaces.find((entry) => entry.name === "certops");
if (!namespace.entries.some((entry) => entry.id === "certops-material-distribution-schema")) namespace.entries.push({
  id: "certops-material-distribution-schema", kind: "schema", path: "packages/contracts/certops/material-distribution.schema.json", status: "existing"
});
fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + "\n");
