"use strict";

/**
 * Refresh packages/agent/vendor copies from their monorepo sources of truth.
 * Run from the repo root or from packages/agent:
 *   node packages/agent/scripts/sync-vendor.js
 */

const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

const packageRoot = path.resolve(__dirname, "..");
const repoRoot = path.resolve(packageRoot, "..", "..");

const VENDOR_MAP = [
  {
    from: path.join(repoRoot, "packages", "log-scrub", "secret-material.js"),
    to: path.join(packageRoot, "vendor", "log-scrub", "secret-material.js"),
    attribution: [
      "/*",
      " * VENDORED COPY for self-contained agent distribution.",
      " * Source of truth: packages/log-scrub/secret-material.js (@tokentimer/log-scrub).",
      " * Refresh with: node packages/agent/scripts/sync-vendor.js",
      " * Do not edit detection logic here; change the upstream file and re-sync.",
      " */",
      "",
    ].join("\n"),
  },
  {
    from: path.join(repoRoot, "packages", "contracts", "certops", "canonical-json.cjs"),
    to: path.join(packageRoot, "vendor", "contracts", "canonical-json.cjs"),
    attribution: [
      "/*",
      " * VENDORED COPY for self-contained agent distribution.",
      " * Source of truth: packages/contracts/certops/canonical-json.cjs (@tokentimer/contracts).",
      " * Refresh with: node packages/agent/scripts/sync-vendor.js",
      " * Keep byte-identical to upstream (minus this attribution header) so the",
      " * signed-job canonicalization contract cannot drift from the control plane.",
      " */",
      "",
    ].join("\n"),
  },
  {
    // JSON schemas cannot carry a JS attribution header; copy byte-identical
    // and keep the contracts package file as the single editable source.
    from: path.join(
      repoRoot,
      "packages",
      "contracts",
      "certops",
      "agent-protocol.schema.json",
    ),
    to: path.join(
      packageRoot,
      "vendor",
      "contracts",
      "agent-protocol.schema.json",
    ),
    raw: true,
  },
];

function stripExistingAttribution(source) {
  if (source.startsWith("/*")) {
    const end = source.indexOf("*/");
    if (end !== -1) {
      const header = source.slice(0, end + 2);
      if (header.includes("VENDORED COPY")) {
        return source.slice(end + 2).replace(/^\r?\n/, "");
      }
    }
  }
  return source;
}

for (const entry of VENDOR_MAP) {
  if (!fs.existsSync(entry.from)) {
    process.stderr.write(`sync-vendor: missing upstream ${entry.from}\n`);
    process.exit(1);
  }
  const upstream = fs.readFileSync(entry.from, "utf8");
  fs.mkdirSync(path.dirname(entry.to), { recursive: true });
  if (entry.raw) {
    fs.writeFileSync(entry.to, upstream);
  } else {
    const body = stripExistingAttribution(upstream);
    fs.writeFileSync(entry.to, `${entry.attribution}${body}`);
  }
  process.stdout.write(`Synced ${path.relative(packageRoot, entry.to)}\n`);
}

// The vendored schema just changed above; regenerate the dependency-free
// standalone validator compiled from it (see build-protocol-validator.js
// for why this must not pull ajv/ajv-formats into the shipped runtime).
execFileSync(
  process.execPath,
  [path.join(__dirname, "build-protocol-validator.js")],
  { stdio: "inherit" },
);
