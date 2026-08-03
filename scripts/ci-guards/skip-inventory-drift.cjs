#!/usr/bin/env node
"use strict";

// Guard: closes the "auto-generated skip inventory drift" finding from the
// M5c CI-guard backlog (tokentimer-canvas plan, "Quality and CI backlog"
// item #2). Regenerates docs/certops/skip-inventory.generated.md from the
// real test suite (scripts/generate-skip-inventory.cjs owns the scan/
// classify/render logic, required here so the two can never disagree about
// what counts as a skip) and fails if the committed copy differs, so the
// inventory can never silently drift from reality - a skip added without
// running the generator, or a reason tag edited by hand, is caught here.
//
// Also fails if any discovered skip is missing its required
// `// skip-reason: no-host|unimplemented` tag, even in the hypothetical case
// where the committed file already (incorrectly) reflects that gap.

const fs = require("node:fs");
const path = require("node:path");

const {
  OUTPUT_PATH,
  buildInventory,
  renderMarkdown,
  validateReasons,
} = require("../generate-skip-inventory.cjs");

const repoRoot = path.resolve(__dirname, "..", "..");

function relOutputPath() {
  return path.relative(repoRoot, OUTPUT_PATH).replace(/\\/g, "/");
}

function main() {
  const skips = buildInventory();
  const freshMarkdown = renderMarkdown(skips);
  const problems = validateReasons(skips);
  let failed = false;

  for (const problem of problems) {
    console.error(`::error::skip-inventory-drift: ${problem}`);
    failed = true;
  }

  let committedMarkdown = null;
  try {
    committedMarkdown = fs.readFileSync(OUTPUT_PATH, "utf8");
  } catch (_err) {
    console.error(
      `::error file=${relOutputPath()}::skip-inventory-drift: inventory ` +
        "file does not exist; run " +
        "`node scripts/generate-skip-inventory.cjs --write` and commit the result",
    );
    process.exit(1);
  }

  if (committedMarkdown !== freshMarkdown) {
    console.error(
      `::error file=${relOutputPath()}::skip-inventory-drift: committed ` +
        "skip inventory does not match the real skip set in the test " +
        "suite; run `node scripts/generate-skip-inventory.cjs --write` " +
        "and commit the result",
    );
    failed = true;
  }

  if (failed) {
    process.exit(1);
  }

  console.log(
    `skip-inventory-drift: ok (${skips.length} skip(s), inventory matches)`,
  );
}

main();
