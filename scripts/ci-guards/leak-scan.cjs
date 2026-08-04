#!/usr/bin/env node
"use strict";

// Guard: catches internal-only planning references leaking into this
// public repository, in tracked file content OR in the current git ref
// name, since a non-compliant branch name is exposed even when the diff
// itself is clean (it appears in the PR page, fork dropdown, and
// `git ls-remote`, and survives in the merge commit after the branch is
// deleted). This covers issue-tracker references, milestone/wave labels,
// internal checklist IDs, and references to internal-only repositories
// or planning-tool artifacts that must never describe public,
// externally-visible engineering work.
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
// costs a permanent public leak.
const PATTERNS = [
  {
    id: "issue-tracker-id",
    // Case-sensitive on purpose: every real issue-tracker reference this
    // project has ever used historically has been written as an
    // uppercase three-letter-ish prefix plus digits, matching the
    // tracker's own display convention. Case-insensitive would also
    // match fake API-token fixture names already present in
    // apps/dashboard/tests/unit and tests/integration (lowercase
    // "tok-1"-style strings) - those are false positives, not leaks. The
    // ref-name scan below still checks the lowercase branch-name form
    // separately, since git branch names are conventionally lowercase.
    re: /\bTOK-?\d+\b/g,
    describe: () => "issue-tracker reference (TOK-<number>)",
  },
  {
    id: "issue-tracker-url",
    re: /\blinear\.app\b/gi,
    describe: () => "issue-tracker URL",
  },
  {
    id: "internal-notes-repo-name",
    re: /\btokentimer-canvas\b/g,
    describe: () => "internal notes-repo name",
  },
  {
    id: "milestone-code",
    // Deliberately case-sensitive, matching the workspace-level scan
    // command already established for this exact purpose (a capital
    // "M" followed by one or two digits and an optional trailing
    // leak-scan-allow-start
    // a/b/c letter, e.g. "M5c", "M12").
    // leak-scan-allow-end
    // Lowercase variants of the same
    // code used as a path prefix are still caught because they appear
    // as the branch-prefix form matched by the pattern immediately
    // below, and by the ref-name scan; keeping this one case-sensitive
    // avoids a flood of unrelated lowercase-m matches ("m5" inside a
    // longer word) that the case-insensitive form would produce.
    re: /\bM\d{1,2}[a-c]?\b/g,
    describe: () => "milestone code (M<number>[a-c])",
  },
  {
    id: "milestone-code-path-prefix",
    // The lowercase branch/path-prefix form of the same milestone-code
    // leak-scan-allow-start
    // convention (e.g. "m5c/...").
    // leak-scan-allow-end
    re: /\bm\d{1,2}[a-c]?\//g,
    describe: () => "milestone code used as a path/ref prefix (m<number>[a-c]/)",
  },
  {
    id: "wave-label",
    // Widened to allow an optional space, underscore, or hyphen between
    // "wave" and the digit, so it also matches the exact-string form
    // leak-scan-allow-start
    // ("Wave 2b") in addition to the compact "wave2b" form.
    // leak-scan-allow-end
    re: /\bwave[\s_-]?\d[a-c]?\b/gi,
    describe: () => "wave label (wave<number>[a-c])",
  },
  {
    id: "internal-checklist-id",
    // Internal checklist item IDs of the form
    // leak-scan-allow-start
    // "ARC-1" through "ARC-999".
    // leak-scan-allow-end
    re: /\bARC-\d{1,3}\b/g,
    describe: () => "internal checklist ID (ARC-<number>)",
  },
  {
    id: "internal-backlog-phrasing",
    // leak-scan-allow-start
    // Matches both "Quality and CI backlog" (prose form) and "Quality/CI
    // backlog" (the slug/slash form actually used in several script
    // header comments), so a leak surviving as a shorthand doesn't slip
    // past a pattern written only against the fully-spelled-out phrase.
    // leak-scan-allow-end
    re: /\bquality[\s/]+(?:and[\s/]+)?ci backlog\b/gi,
    describe: () => "internal backlog document phrasing",
  },
  {
    id: "canvas-plan-slug",
    // An internal canvas plan slug has the shape
    // "<name>_<8 hex chars>.plan.md". This is generic enough to catch
    // the family, not just one example, but may need extending if the
    // naming convention drifts.
    re: /[a-z0-9_]+_[0-9a-f]{8}\.plan\.md\b/gi,
    describe: () => "canvas plan filename slug (<name>_<hex8>.plan.md)",
  },
];

// The milestone-code pattern (`\bm\d{1,2}[a-c]?\b`) false-positives on
// SVG/PDF path data and on ordinary words that happen to scan as
// "m<digit>" inside minified or generated files. Keep this narrow -
// path additions here should be for verified false positives, not a
// general escape hatch.
const MILESTONE_CODE_FALSE_POSITIVE_EXTENSIONS = new Set([".svg"]);

// These files use "wave" as the pre-existing, real product term for a
// staged DNS-provider rollout, unrelated to internal milestone/wave
// planning labels. Exempting exact files here, rather than loosening
// the pattern, keeps the pattern itself narrow everywhere else.
const WAVE_LABEL_FALSE_POSITIVE_FILES = new Set([
  "ROADMAP.md",
  "docs/certops/agent.md",
  "packages/agent/src/dns/index.js",
  "packages/agent/src/dns/dns.test.js",
  "packages/agent/src/dns/providers/acme-dns.js",
]);

// Ref names (git branch names) are conventionally lowercase-kebab, so
// the issue-tracker-id check needs a case-insensitive variant only when
// scanning the ref name; using it for file content too would reflag
// the "tok-1"-style fixture names documented above.
const REF_NAME_ONLY_PATTERNS = [
  {
    id: "issue-tracker-id-ref-name",
    re: /\bTOK-?\d+\b/gi,
    describe: () => "issue-tracker reference (TOK-<number>), case-insensitive",
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

// A line-range exclusion mechanism for the rare, deliberate case where a
// pattern's own literal text must appear in a file for the pattern to
// exist at all (this file's own pattern definitions being the main
// case) - a comment or test fixture can bracket the literal with
// "leak-scan-allow-start" / "leak-scan-allow-end" markers (in whatever
// comment syntax the file uses; only the literal marker text matters)
// to exclude just those lines from scanning, rather than exempting an
// entire file or directory. This is narrower than the directory-wide
// self-exemption it replaces: everything outside a marked range,
// including the rest of this very file, is still scanned.
function computeAllowedLineExclusions(lines) {
  const excluded = new Set();
  let insideAllow = false;
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    if (line.includes("leak-scan-allow-start")) {
      insideAllow = true;
      excluded.add(i);
      continue;
    }
    if (line.includes("leak-scan-allow-end")) {
      insideAllow = false;
      excluded.add(i);
      continue;
    }
    if (insideAllow) excluded.add(i);
  }
  return excluded;
}

function scanText(relPath, text, violations) {
  const lines = text.split("\n");
  const excludedLines = computeAllowedLineExclusions(lines);
  for (const pattern of PATTERNS) {
    if (
      pattern.id.startsWith("milestone-code") &&
      MILESTONE_CODE_FALSE_POSITIVE_EXTENSIONS.has(path.extname(relPath).toLowerCase())
    ) {
      continue;
    }
    if (pattern.id === "wave-label" && WAVE_LABEL_FALSE_POSITIVE_FILES.has(relPath)) {
      continue;
    }
    for (let i = 0; i < lines.length; i += 1) {
      if (excludedLines.has(i)) continue;
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
    ...PATTERNS.filter((p) => p.id !== "issue-tracker-id"),
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
