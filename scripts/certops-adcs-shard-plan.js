"use strict";
/**
 * Plans the lab matrix of the native AD CS qualification workflow and prints GitHub step outputs.
 * "all" is the single serial lab that can produce release evidence; every other choice is diagnostic only.
 * The resource group has to match tt-certops-<run>-<number>, so the suffix is purely numeric.
 */
const { SHARD_NAMES } = require("../tests/e2e/helpers/certops-adcs-shards");

function plan({ shard = "all", scope = "comprehensive", fault = "none", attempt = "1" } = {}) {
  const run = Number.parseInt(attempt, 10);
  if (!Number.isInteger(run) || run < 1 || run > 99) throw new Error("Unsupported workflow run attempt");
  if (shard !== "parallel" && !SHARD_NAMES.includes(shard)) throw new Error("Unknown shard selection");
  if (shard === "all") return [{ shard: "all", suffix: String(run), artifactSuffix: "" }];
  if (scope !== "comprehensive" || fault !== "none") throw new Error("A diagnostic shard only applies to the plain comprehensive scope without fault injection");
  const names = SHARD_NAMES.filter((name) => name !== "all");
  const selected = shard === "parallel" ? names : [shard];
  return selected.map((name) => ({ shard: name, suffix: String(run * 100 + names.indexOf(name) + 1), artifactSuffix: `-${name}` }));
}

if (require.main === module) {
  const include = plan({
    shard: process.env.SHARD || "all",
    scope: process.env.QUALIFICATION_SCOPE || "comprehensive",
    fault: process.env.FAULT_PROFILE || "none",
    attempt: process.env.GITHUB_RUN_ATTEMPT || "1",
  });
  process.stdout.write(`matrix=${JSON.stringify({ include })}\n`);
}
module.exports = { plan };
