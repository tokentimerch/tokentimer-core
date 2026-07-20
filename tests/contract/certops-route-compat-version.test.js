import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const readJson = (relativePath) =>
  JSON.parse(fs.readFileSync(path.join(rootDir, relativePath), "utf8"));
const contractPackage = readJson("packages/contracts/package.json");
const routeCompat = readJson("packages/contracts/api/certops-route-compat.contract.json");

describe("CertOps route compatibility version", () => {
  it("matches the contracts package version exactly", () => {
    assert.equal(routeCompat.version, contractPackage.version);
  });
});
