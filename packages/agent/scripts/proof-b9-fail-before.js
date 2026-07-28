"use strict";

/**
 * Fail-before proof helper for B9 (does not mutate the real package).
 * Builds an isolated broken tree that still uses the historical
 * apps/api secretMaterial require, then asserts require() fails.
 */

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const packageRoot = path.resolve(__dirname, "..");
const staging = fs.mkdtempSync(path.join(os.tmpdir(), "tokentimer-agent-b9-fail-"));

function copyDir(src, dest) {
  fs.mkdirSync(dest, { recursive: true });
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    if (entry.name === "node_modules") continue;
    const from = path.join(src, entry.name);
    const to = path.join(dest, entry.name);
    if (entry.isDirectory()) copyDir(from, to);
    else fs.copyFileSync(from, to);
  }
}

copyDir(packageRoot, staging);
fs.rmSync(path.join(staging, "vendor"), { recursive: true, force: true });

const evidencePath = path.join(staging, "src", "evidence", "index.js");
const evidence = fs.readFileSync(evidencePath, "utf8");
const broken = evidence.replace(
  /require\(["']\.\.\/\.\.\/vendor\/log-scrub\/secret-material\.js["']\)/,
  'require("../../../../apps/api/utils/secretMaterial.js")',
);
if (broken === evidence) {
  console.error("fail-before proof: could not rewrite evidence import");
  process.exit(2);
}
fs.writeFileSync(evidencePath, broken);

const probe = `
  try {
    require(${JSON.stringify(path.join(staging, "src", "evidence", "index.js"))});
    console.log("UNEXPECTED_SUCCESS");
    process.exit(0);
  } catch (err) {
    console.error("EXPECTED_FAIL:", err.code || err.message);
    process.exit(1);
  }
`;
const result = spawnSync(process.execPath, ["-e", probe], {
  encoding: "utf8",
  env: { ...process.env, NODE_PATH: "" },
});
fs.rmSync(staging, { recursive: true, force: true });
process.stdout.write(result.stdout || "");
process.stderr.write(result.stderr || "");
process.exit(result.status === 1 ? 0 : 1);
