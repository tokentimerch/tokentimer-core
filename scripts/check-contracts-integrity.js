#!/usr/bin/env node

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

const here = __dirname;
const repoRoot = path.resolve(here, "..");
const manifestPath = path.join(repoRoot, "contracts.manifest.json");

function fail(message) {
  console.error(`contracts-integrity: ${message}`);
  process.exit(1);
}

function sha256(content) {
  return crypto.createHash("sha256").update(content).digest("hex");
}

if (!fs.existsSync(manifestPath)) {
  fail(`missing ${manifestPath}`);
}

const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
if (!Array.isArray(manifest.namespaces) || manifest.namespaces.length === 0) {
  fail("namespaces must be a non-empty array");
}

const namespaceNames = new Set();
const entryIds = new Set();
let checkedFiles = 0;

for (const ns of manifest.namespaces) {
  if (!ns.name || !Array.isArray(ns.entries)) {
    fail("each namespace requires name and entries");
  }
  if (namespaceNames.has(ns.name)) {
    fail(`duplicate namespace name: ${ns.name}`);
  }
  namespaceNames.add(ns.name);
  if (ns.entries.length === 0) {
    fail(`namespace "${ns.name}" must include at least one entry`);
  }

  for (const entry of ns.entries) {
    if (!entry.id || !entry.kind || !entry.path) {
      fail(`namespace "${ns.name}" has entry missing id/kind/path`);
    }
    const qualifiedId = `${ns.name}:${entry.id}`;
    if (entryIds.has(qualifiedId)) {
      fail(`duplicate contract entry id in namespace: ${qualifiedId}`);
    }
    entryIds.add(qualifiedId);

    const abs = path.join(repoRoot, entry.path);
    if (entry.status === "existing") {
      if (!fs.existsSync(abs)) {
        fail(`existing entry path not found: ${entry.path}`);
      }
      const raw = fs.readFileSync(abs, "utf8");
      if (raw.trim().length === 0) {
        fail(`existing entry is empty: ${entry.path}`);
      }

      if (entry.path.endsWith(".json")) {
        try {
          JSON.parse(raw);
        } catch (err) {
          fail(`invalid JSON in ${entry.path}: ${err.message}`);
        }
      }

      if (entry.path.endsWith(".yaml") || entry.path.endsWith(".yml")) {
        if (!/\bopenapi:\s*3\./.test(raw)) {
          fail(`OpenAPI YAML missing openapi version header: ${entry.path}`);
        }
      }

      const digest = sha256(raw);
      if (entry.sha256) {
        if (entry.sha256 !== digest) {
          fail(
            `SHA-256 mismatch for ${entry.path}: manifest=${entry.sha256.slice(0, 12)}..., actual=${digest.slice(0, 12)}...`,
          );
        }
      } else {
        console.log(`  digest ${entry.path}: ${digest}`);
      }
      checkedFiles += 1;
    }
  }
}

console.log(
  `contracts-integrity: ok (${manifest.namespaces.length} namespaces, ${checkedFiles} files checked)`,
);
