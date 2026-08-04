#!/usr/bin/env node
"use strict";

// Scans the test suite for every skipped test and requires each one to
// carry a machine-readable reason-tag classification, so a skip can never
// silently outlive the reason it was added for. A skip must be tagged with
// a `// skip-reason: <tag>` comment immediately above the skip call
// (tolerating a short run of explanatory comment lines above the tag
// itself), where `<tag>` is exactly one of:
//
//   no-host       needs real hardware/OS/IIS not available in CI
//   unimplemented the feature the test targets does not exist yet
//
// This module owns the scan/classify/render logic and is required by
// scripts/ci-guards/skip-inventory-drift.cjs, which regenerates the
// inventory and fails CI if the committed copy has drifted from what the
// test suite actually contains, so the two can never disagree about what
// counts as a skip.
//
// This is a line-oriented heuristic scan, not a JS parser. It recognizes the
// skip syntaxes actually used in this codebase today (see docs/certops/ for
// the generated inventory): mocha's `describe.skip(...)` / `it.skip(...)`
// (a statically-named skip), mocha's `this.skip()` / node:test's
// `t.skip(...)` (a dynamic, conditional skip inside a test body, attributed
// to the nearest enclosing `it(...)`/`test(...)` title found scanning
// upward in the same file), and node:test's own options-object form
// (`it("name", { skip: <bool-or-string> }, fn)` / same for `describe`,
// second positional argument), which is attributed to the same title found
// on that line, or to the nearest enclosing `it(...)`/`test(...)` title when
// the call is split across lines (title and options object on separate
// lines).
//
// Usage:
//   node scripts/generate-skip-inventory.cjs            print to stdout
//   node scripts/generate-skip-inventory.cjs --write     write the file

const fs = require("node:fs");
const path = require("node:path");

const repoRoot = path.resolve(__dirname, "..");
const OUTPUT_PATH = path.join(
  repoRoot,
  "docs",
  "certops",
  "skip-inventory.generated.md",
);

const VALID_REASONS = new Set(["no-host", "unimplemented"]);

// Directories searched for *.test.js / *.spec.js files. These are the three
// locations this codebase's own conventions put tests in (see package.json's
// test:* scripts and tests/README-equivalent glob patterns).
const SEARCH_DIRS = ["tests", "packages", "apps"];
const IGNORED_DIR_NAMES = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  "coverage",
  ".coverage",
  ".build",
]);

function isTestFile(name) {
  return /\.test\.jsx?$/.test(name) || /\.spec\.jsx?$/.test(name);
}

function walk(dir, out) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch (_err) {
    return; // directory does not exist; nothing to scan
  }
  for (const entry of entries) {
    if (IGNORED_DIR_NAMES.has(entry.name)) continue;
    const abs = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(abs, out);
    } else if (entry.isFile() && isTestFile(entry.name)) {
      out.push(abs);
    }
  }
}

function discoverTestFiles() {
  const out = [];
  for (const dirName of SEARCH_DIRS) {
    walk(path.join(repoRoot, dirName), out);
  }
  return out.sort();
}

// describe.skip("name", ...) / it.skip("name", ...), first argument only,
// single/double/backtick quoted.
const STATIC_SKIP_RE =
  /\b(describe|it)\.skip\s*\(\s*(["'`])((?:\\.|(?!\2)[^\\])*)\2/;
// A dynamic in-body skip call with no name of its own: mocha's
// `this.skip()`, or node:test's `t.skip(...)` (the test-context parameter is
// conventionally named `t` in this codebase's node:test files).
const DYNAMIC_SKIP_RE = /\bthis\.skip\s*\(|\bt\.skip\s*\(/;
// Tracks the nearest enclosing it()/test() title so a dynamic skip can be
// attributed to a human-readable name.
const IT_TITLE_RE = /\b(?:it|test)\s*\(\s*(["'`])((?:\\.|(?!\1)[^\\])*)\1/;
// node:test's options-object form: it("name", { skip: <bool-or-string> }, fn)
// (same shape for describe/test). The options object frequently lands on its
// own line when the call is wrapped across lines, so this only detects the
// `{ skip: ... }` token itself; the enclosing call's title is resolved via
// NAMED_CALL_RE below, tracked exactly like IT_TITLE_RE but widened to
// describe(...) too since an options-object skip is legal on describe as
// well as it/test.
const OPTION_OBJECT_SKIP_RE = /\{\s*skip\s*:/;
const NAMED_CALL_RE =
  /\b(describe|it|test)\s*\(\s*(["'`])((?:\\.|(?!\2)[^\\])*)\2/;
// When a call's opening paren has nothing else on its line (the arguments
// wrap), e.g.:
//   it(
//     "name",
//     { skip: ... },
//     () => {},
//   );
// the title lands alone on the following non-empty line. This pair tracks
// that "we just opened a call and are waiting for its title" state so
// NAMED_CALL_RE's single-line assumption still resolves the right title.
const CALL_OPENER_ONLY_RE = /\b(describe|it|test)\s*\(\s*$/;
const STANDALONE_TITLE_RE = /^\s*(["'`])((?:\\.|(?!\1)[^\\])*)\1\s*,?\s*$/;

function findReasonTag(lines, skipLineIndex) {
  // Walk upward over comment-only lines, stopping at the first non-comment
  // line (or after a small bounded lookback), so the tag must be
  // "immediately above" the skip in spirit while still tolerating a short
  // explanatory comment block above the tag line itself.
  const LOOKBACK_LIMIT = 8;
  for (
    let i = skipLineIndex - 1;
    i >= 0 && i >= skipLineIndex - LOOKBACK_LIMIT;
    i -= 1
  ) {
    const line = lines[i].trim();
    if (line === "") continue;
    if (!line.startsWith("//")) break;
    const match = line.match(/skip-reason:\s*([a-z-]+)/);
    if (match) return match[1];
  }
  return null;
}

function scanFile(absPath) {
  const relPath = path.relative(repoRoot, absPath).replace(/\\/g, "/");
  const text = fs.readFileSync(absPath, "utf8");
  const lines = text.split("\n");

  const results = [];
  let lastItTitle = null;
  let lastNamedCallTitle = null;
  let lastNamedCallKind = null;
  let pendingCallKind = null;

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];

    if (pendingCallKind) {
      const standaloneMatch = line.match(STANDALONE_TITLE_RE);
      if (standaloneMatch) {
        lastNamedCallTitle = standaloneMatch[2];
        lastNamedCallKind = pendingCallKind;
        if (pendingCallKind === "it" || pendingCallKind === "test") {
          lastItTitle = standaloneMatch[2];
        }
      }
      pendingCallKind = null;
    }

    const itMatch = line.match(IT_TITLE_RE);
    if (itMatch) lastItTitle = itMatch[2];

    const namedCallMatch = line.match(NAMED_CALL_RE);
    if (namedCallMatch) {
      lastNamedCallKind = namedCallMatch[1];
      lastNamedCallTitle = namedCallMatch[3];
    } else {
      const openerMatch = line.match(CALL_OPENER_ONLY_RE);
      if (openerMatch) pendingCallKind = openerMatch[1];
    }

    const staticMatch = line.match(STATIC_SKIP_RE);
    if (staticMatch) {
      results.push({
        file: relPath,
        line: i + 1,
        name: staticMatch[3],
        kind: `${staticMatch[1]}.skip`,
        reason: findReasonTag(lines, i),
      });
      continue;
    }

    if (OPTION_OBJECT_SKIP_RE.test(line)) {
      results.push({
        file: relPath,
        line: i + 1,
        name:
          lastNamedCallTitle ||
          "(unknown - no enclosing describe()/it()/test() title found above this line)",
        kind: `${lastNamedCallKind || "it"}(..., { skip }) option-object`,
        reason: findReasonTag(lines, i),
      });
      continue;
    }

    if (DYNAMIC_SKIP_RE.test(line)) {
      results.push({
        file: relPath,
        line: i + 1,
        name:
          lastItTitle ||
          "(unknown - no enclosing it()/test() title found above this line)",
        kind: "dynamic (this.skip() / t.skip())",
        reason: findReasonTag(lines, i),
      });
    }
  }

  return results;
}

function buildInventory() {
  const skips = [];
  for (const file of discoverTestFiles()) {
    skips.push(...scanFile(file));
  }
  skips.sort((a, b) =>
    a.file === b.file ? a.line - b.line : a.file.localeCompare(b.file),
  );
  return skips;
}

function renderMarkdown(skips) {
  const lines = [];
  lines.push("# Skipped-test inventory (generated)");
  lines.push("");
  lines.push(
    "Generated by `scripts/generate-skip-inventory.cjs`. Do not hand-edit " +
      "this file: run `node scripts/generate-skip-inventory.cjs --write` to " +
      "regenerate it, and `scripts/ci-guards/skip-inventory-drift.cjs` fails " +
      "CI if this file no longer matches the real skip set in the test " +
      "suite.",
  );
  lines.push("");
  lines.push(
    "Every skip below must carry a `// skip-reason: <tag>` comment " +
      "immediately above the skip call, where `<tag>` is exactly one of:",
  );
  lines.push("");
  lines.push(
    "- `no-host`: skipped because it needs real hardware/OS/IIS not " +
      "available in CI",
  );
  lines.push(
    "- `unimplemented`: skipped because the feature does not exist yet",
  );
  lines.push("");
  lines.push(`Total skips found: ${skips.length}`);
  lines.push("");

  if (skips.length === 0) {
    lines.push("_No skipped tests found._");
    lines.push("");
    return lines.join("\n");
  }

  lines.push("| File | Line | Test/suite name | Kind | Reason |");
  lines.push("|---|---|---|---|---|");
  for (const skip of skips) {
    const reasonCell = !skip.reason
      ? "**MISSING**"
      : VALID_REASONS.has(skip.reason)
        ? `\`${skip.reason}\``
        : `**INVALID: \`${skip.reason}\`**`;
    const nameCell = skip.name.replace(/\|/g, "\\|");
    lines.push(
      `| \`${skip.file}\` | ${skip.line} | ${nameCell} | ${skip.kind} | ${reasonCell} |`,
    );
  }
  lines.push("");
  return lines.join("\n");
}

function validateReasons(skips) {
  const problems = [];
  for (const skip of skips) {
    if (!skip.reason) {
      problems.push(
        `${skip.file}:${skip.line} ("${skip.name}") has no ` +
          "// skip-reason: tag immediately above the skip call",
      );
    } else if (!VALID_REASONS.has(skip.reason)) {
      problems.push(
        `${skip.file}:${skip.line} ("${skip.name}") has an invalid reason ` +
          `tag "${skip.reason}" (must be one of: ` +
          `${Array.from(VALID_REASONS).join(", ")})`,
      );
    }
  }
  return problems;
}

function main() {
  const args = process.argv.slice(2);
  const shouldWrite = args.includes("--write");

  const skips = buildInventory();
  const markdown = renderMarkdown(skips);
  const problems = validateReasons(skips);

  if (shouldWrite) {
    fs.mkdirSync(path.dirname(OUTPUT_PATH), { recursive: true });
    fs.writeFileSync(OUTPUT_PATH, markdown, "utf8");
    console.log(
      `generate-skip-inventory: wrote ${skips.length} skip(s) to ` +
        `${path.relative(repoRoot, OUTPUT_PATH).replace(/\\/g, "/")}`,
    );
  } else {
    process.stdout.write(markdown);
  }

  if (problems.length > 0) {
    for (const problem of problems) {
      console.error(`::error::generate-skip-inventory: ${problem}`);
    }
    process.exitCode = 1;
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  OUTPUT_PATH,
  VALID_REASONS,
  buildInventory,
  renderMarkdown,
  validateReasons,
};
