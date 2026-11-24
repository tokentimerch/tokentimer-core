"use strict";

const fs = require("node:fs");
const path = require("node:path");
const destinationContract = require("../packages/contracts/certops/deployment-destination.schema.json");

const protocolPath = path.join(__dirname, "../packages/contracts/certops/agent-protocol.schema.json");
const protocol = JSON.parse(fs.readFileSync(protocolPath, "utf8"));
const prefix = "deploymentDestination_";

function embedDefinition(value) {
  if (Array.isArray(value)) return value.map(embedDefinition);
  if (value === null || typeof value !== "object") return value;
  return Object.fromEntries(Object.entries(value).map(([key, entry]) => [
    key,
    key === "$ref" ? entry.replace("#/definitions/", "#/definitions/" + prefix) : embedDefinition(entry),
  ]));
}

for (const name of ["opaqueRef", "sha256", "validation", "validationReceipt"]) {
  protocol.definitions[prefix + name] = embedDefinition(destinationContract.definitions[name]);
}
const output = JSON.stringify(protocol, null, 2) + "\n";
if (process.argv.includes("--check")) {
  if (fs.readFileSync(protocolPath, "utf8") !== output) {
    process.stderr.write("Deployment destination protocol definitions are stale. Run node scripts/sync-deployment-destination-contracts.cjs.\n");
    process.exitCode = 1;
  }
} else {
  fs.writeFileSync(protocolPath, output);
}
