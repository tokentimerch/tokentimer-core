#!/usr/bin/env node
"use strict";

// Guard: closes the "internal-identifier leak" finding from the
// M5c CI-guard backlog (tokentimer-canvas plan, "Quality and CI backlog"
// item #1, and the "public-repository rule" at the top of that plan).
// tokentimer-core is public; Linear issue IDs, linear.app URLs, the
// internal notes-repo name, milestone/wave labels, and canvas plan slugs
// must never reach it - in tracked file content OR in the current git
// ref name, since a non-compliant branch name is exposed even when the
// diff itself is clean (it appears in the PR page, fork dropdown, and
// `git ls-remote`, and survives in the merge commit after the branch is
// deleted).
//
// Scope choice: this scans the CURRENT WORKING TREE of tracked files,
// not a diff against a target branch. A diff-against-target-branch scan
// would be more precise (it only flags what is *about* to be pushed),
// but determining "the target branch" generically (main? a stacked
// parent branch?) is its own can of worms and out of scope for a first
// version; scanning the full tracked tree is the simpler, safer default
// and just means a pre-existing leak anywhere in the tree also fails
// the guard, which is the conservative direction to err in.

const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const repoRoot = path.resolve(__dirname, "..", "..");
const selfDir = path
  .relative(repoRoot, __dirname)
  .replace(/\\/g, "/");

// Binary-ish extensions are never worth scanning for text leaks and can
// contain byte sequences that look like garbage UTF-8; skip them here
// rather than trying to decode them.
const BINARY_EXTENSIONS = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".bmp",
  ".woff", ".woff2", ".ttf", ".eot", ".otf",
  ".zip", ".tar", ".gz", ".tgz", ".7z", ".rar",
  ".pdf", ".exe", ".dll", ".so", ".dylib", ".node", ".wasm",
  ".db", ".sqlite", ".sqlite3", ".pyc", ".class", ".jar",
]);

// Each pattern documents exactly which leak class it exists to catch.
// Regexes are case-insensitive and slightly over-broad by design: a
// false positive here costs one human confirmation, a false negative
// costs a permanent public leak (see the ref-name rule in the plan).
const PATTERNS = [
  {
    id: "linear-issue-id",
    // Case-sensitive on purpose: every real Linear reference observed
    // in this project's own docs/rules is written uppercase ("TOK-19",
    // "TOK-114", "TOK-140"), matching Linear's own display convention.
    // Case-insensitive would also match "tok-1", "tok-2", "tok123" -
    // fake API-token fixture names already present in
    // apps/dashboard/tests/unit and tests/integration - which are
    // false positives, not leaks. The ref-name scan below still checks
    // the lowercase branch-name form separately, since git branch
    // names are conventionally lowercase.
    re: /\bTOK-?\d+\b/g,
    describe: () => "Linear issue reference (TOK-<number>)",
  },
  {
    id: "linear-app-url",
    re: /\blinear\.app\b/gi,
    describe: () => "linear.app URL",
  },
  {
    id: "canvas-repo-name",
    re: /\btokentimer-canvas\b/g,
    describe: () => "internal notes-repo name (tokentimer-canvas)",
  },
  {
    id: "milestone-code",
    // Deliberately case-sensitive, matching the workspace-level scan
    // command already established for this exact purpose ("M1", "M5",
    // "M5c", "M12"): `\bM\d{1,2}[a-c]?\b`. Lowercase "m5c" style refs
    // are still caught because they appear as the branch-prefix form
    // "m5c/..." below, matched by wave-label's sibling patterns and by
    // the ref-name scan; keeping this one case-sensitive avoids a flood
    // of unrelated lowercase-m matches ("m5" inside a longer word) that
    // the case-insensitive form would produce.
    re: /\bM\d{1,2}[a-c]?\b/g,
    describe: () => "milestone code (M<number>[a-c])",
  },
  {
    id: "milestone-code-path-prefix",
    // The lowercase branch/path-prefix form explicitly named in the
    // plan's ref-naming table: "m5c/...".
    re: /\bm\d{1,2}[a-c]?\//g,
    describe: () => "milestone code used as a path/ref prefix (m<number>[a-c]/)",
  },
  {
    id: "wave-label",
    re: /\bwave\d[a-c]?\b/gi,
    describe: () => "wave label (wave<number>[a-c])",
  },
  {
    id: "canvas-plan-slug",
    // Illustrative pattern derived from the plan doc's own example
    // filename ("m5c_windows_execution_surface_bee29638.plan.md"): an
    // internal canvas plan slug is "<name>_<8 hex chars>.plan.md". This
    // is generic enough to catch the family, not just the one example,
    // but may need extending if the naming convention drifts.
    re: /[a-z0-9_]+_[0-9a-f]{8}\.plan\.md\b/gi,
    describe: () => "canvas plan filename slug (<name>_<hex8>.plan.md)",
  },
  {
    id: "canvas-plan-slug-literal-example",
    // The exact token from the plan doc's own worked example, kept as
    // a belt-and-suspenders literal in case the generic pattern above
    // is ever loosened or the slug appears without ".plan.md" nearby
    // (e.g. pasted into a commit message on its own).
    re: /\bbee29638\b/gi,
    describe: () => "literal canvas plan slug example (bee29638)",
  },
];

// The milestone-code pattern (`\bm\d{1,2}[a-c]?\b`) false-positives on
// SVG/PDF path data and on ordinary words that happen to scan as
// "m<digit>" inside minified or generated files. Keep this narrow -
// path additions here should be for verified false positives, not a
// general escape hatch.
const MILESTONE_CODE_FALSE_POSITIVE_EXTENSIONS = new Set([".svg"]);

// Ref names (git branch names) are conventionally lowercase-kebab, so
// the Linear-issue-id check needs a case-insensitive variant only when
// scanning the ref name; using it for file content too would reflag
// the "tok-1"-style fixture names documented above.
const REF_NAME_ONLY_PATTERNS = [
  {
    id: "linear-issue-id-ref-name",
    re: /\bTOK-?\d+\b/gi,
    describe: () => "Linear issue reference (TOK-<number>), case-insensitive",
  },
];

function fail(violations) {
  for (const v of violations) {
    console.error(
      `::error file=${v.file},line=${v.line}::leak-scan: ${v.describe} matched "${v.match}"`,
    );
  }
  console.error(
    `leak-scan: ${violations.length} potential internal-identifier leak(s) found`,
  );
  process.exit(1);
}

function listTrackedFiles() {
  const out = execFileSync("git", ["ls-files"], {
    cwd: repoRoot,
    encoding: "utf8",
  });
  return out.split("\n").filter(Boolean);
}

function scanText(relPath, text, violations) {
  const lines = text.split("\n");
  for (const pattern of PATTERNS) {
    if (
      pattern.id.startsWith("milestone-code") &&
      MILESTONE_CODE_FALSE_POSITIVE_EXTENSIONS.has(path.extname(relPath).toLowerCase())
    ) {
      continue;
    }
    for (let i = 0; i < lines.length; i += 1) {
      const line = lines[i];
      pattern.re.lastIndex = 0;
      let m;
      while ((m = pattern.re.exec(line)) !== null) {
        violations.push({
          file: relPath,
          line: i + 1,
          match: m[0],
          describe: pattern.describe(),
        });
        if (m[0].length === 0) pattern.re.lastIndex += 1;
      }
    }
  }
}

function scanRefName(violations) {
  let ref;
  try {
    ref = execFileSync("git", ["rev-parse", "--abbrev-ref", "HEAD"], {
      cwd: repoRoot,
      encoding: "utf8",
    }).trim();
  } catch (_err) {
    return; // detached HEAD or no repo; nothing to check
  }
  const refPatterns = [
    ...PATTERNS.filter((p) => p.id !== "linear-issue-id"),
    ...REF_NAME_ONLY_PATTERNS,
  ];
  for (const pattern of refPatterns) {
    pattern.re.lastIndex = 0;
    let m;
    while ((m = pattern.re.exec(ref)) !== null) {
      violations.push({
        file: "<current-branch-name>",
        line: 1,
        match: m[0],
        describe: `${pattern.describe()} in ref name "${ref}"`,
      });
      if (m[0].length === 0) pattern.re.lastIndex += 1;
    }
  }
}

function main() {
  const violations = [];

  for (const relPath of listTrackedFiles()) {
    const relPosix = relPath.replace(/\\/g, "/");
    if (relPosix.startsWith(`${selfDir}/`)) continue; // avoid self-match
    const ext = path.extname(relPosix).toLowerCase();
    if (BINARY_EXTENSIONS.has(ext)) continue;

    const abs = path.join(repoRoot, relPath);
    let buf;
    try {
      buf = fs.readFileSync(abs);
    } catch (_err) {
      continue; // deleted-in-working-tree but still tracked; nothing to scan
    }
    // A null byte is a strong binary signal for files with no
    // recognized extension; skip rather than risk garbage matches.
    if (buf.includes(0)) continue;

    scanText(relPosix, buf.toString("utf8"), violations);
  }

  scanRefName(violations);

  if (violations.length > 0) fail(violations);

  console.log("leak-scan: ok");
}

main();
