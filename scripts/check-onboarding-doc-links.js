#!/usr/bin/env node
"use strict";

// Validates the onboarding wizard's documentation link registry against the
// docs sources. The docs live in a separate repository (its apps/docs folder),
// apps/docs), so the root must be supplied explicitly:
//
//   TT_DOCS_ROOT=<path to apps/docs> node scripts/check-onboarding-doc-links.js
//
// It fails when a page or an explicit heading anchor is missing, so a docs
// rename cannot silently break wizard links.

const fs = require("node:fs");
const path = require("node:path");

const REGISTRY_PATH = path.resolve(
  __dirname,
  "..",
  "apps/dashboard/src/components/onboarding/docLinks.json",
);
const EDITION_DIRS = { selfHosted: "docs-selfhosted", cloud: "docs-cloud" };

function slug(heading) {
  return heading
    .toLowerCase()
    .replace(/[^\w\s-]/g, "")
    .trim()
    .replace(/\s+/g, "-");
}

function readPage(docsRoot, dir, pagePath) {
  const base = path.join(docsRoot, dir, pagePath);
  const file = [`${base}.mdx`, `${base}.md`, path.join(base, "index.mdx")].find(
    fs.existsSync,
  );
  if (!file) return null;
  let text = fs.readFileSync(file, "utf8");
  // Shared guides are imported from src/content and carry the headings.
  for (const m of text.matchAll(/from\s+'@site\/(src\/content\/[^']+)'/g)) {
    const included = path.join(docsRoot, m[1]);
    if (fs.existsSync(included)) text += "\n" + fs.readFileSync(included, "utf8");
  }
  return text;
}

function hasAnchor(text, anchor) {
  if (text.includes(`{#${anchor}}`) || text.includes(`"id": "${anchor}"`)) {
    return true;
  }
  return [...text.matchAll(/^#{1,6}\s+(.+?)\s*$/gm)].some(
    (m) => slug(m[1].replace(/\s*\{#[^}]+\}\s*$/, "")) === anchor,
  );
}

function loadRegistry(registryPath = REGISTRY_PATH) {
  const registry = JSON.parse(fs.readFileSync(registryPath, "utf8"));
  return Object.entries(registry).filter(([key]) => !key.startsWith("_"));
}

/** Returns a list of human-readable problems; empty means every link resolves. */
function validateRegistry(entries, docsRoot) {
  const problems = [];
  for (const [key, entry] of entries) {
    const variants = [["selfHosted", entry]];
    if (entry.cloud !== null) {
      variants.push(["cloud", entry.cloud === undefined ? entry : entry.cloud]);
    }
    for (const [edition, variant] of variants) {
      // Absolute links to the public core docs cannot be checked here.
      if (variant.url) continue;
      const text = readPage(docsRoot, EDITION_DIRS[edition], variant.path);
      if (text === null) {
        problems.push(`${key} (${edition}): page ${variant.path} not found`);
      } else if (!hasAnchor(text, variant.anchor)) {
        problems.push(
          `${key} (${edition}): #${variant.anchor} not found in ${variant.path}`,
        );
      }
    }
  }
  return problems;
}

function main() {
  const docsRoot = process.env.TT_DOCS_ROOT;
  if (!docsRoot || !fs.existsSync(docsRoot)) {
    console.error(
      "check-onboarding-doc-links: set TT_DOCS_ROOT to the docs sources directory (apps/docs of the docs repository)",
    );
    process.exit(2);
  }
  const entries = loadRegistry();
  const problems = validateRegistry(entries, docsRoot);
  if (problems.length > 0) {
    for (const problem of problems) console.error(`  - ${problem}`);
    console.error(`check-onboarding-doc-links: ${problems.length} broken link(s)`);
    process.exit(1);
  }
  console.log(`check-onboarding-doc-links: ok (${entries.length} links)`);
}

if (require.main === module) main();

module.exports = { loadRegistry, validateRegistry, hasAnchor, slug };
