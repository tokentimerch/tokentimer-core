#!/usr/bin/env node
"use strict";

// Guard: closes the "neither shipped client invokes Node" finding from
// the CertOps CI-guard backlog. The two Node-free reference clients,
// packages/agent/reference/tokentimer-protocol.sh and .ps1, exist
// specifically so an operator can talk to the protocol without a Node
// runtime; this guard statically checks their source for anything that
// would shell out to node/nodejs or a Node-based script file.

const fs = require("node:fs");
const path = require("node:path");

const repoRoot = path.resolve(__dirname, "..", "..");
const referenceDir = path.join(repoRoot, "packages/agent/reference");

const TARGET_FILES = [
  "tokentimer-protocol.sh",
  "tokentimer-protocol.ps1",
];

// Patterns that indicate shelling out to Node or a Node-authored script
// file, in either shell or PowerShell syntax. The word-boundary check on
// "node" also matches a hyphenated compound adjective like "Node-free"
// (the client's own self-description, confirmed present in both clients'
// help text/heredocs): "node" is followed by "-" then a letter, which
// still satisfies \b since \b sits between the word char "e" and the
// non-word char "-". The negative lookahead below excludes exactly that
// shape (a bare hyphen immediately after "node"/"node.exe" with no
// intervening whitespace), which is never how a real invocation is
// written, while "node -e", "node--inspect" preceded by a space, and
// "node.exe" still match normally.
const FORBIDDEN_PATTERNS = [
  { id: "node-command", re: /(^|[^\w./-])node(\.exe)?\b(?!-)/gi },
  { id: "nodejs-command", re: /\bnodejs\b/gi },
  { id: "require-call", re: /\brequire\s*\(/g },
  { id: "cjs-file-invocation", re: /[^\s"']+\.cjs\b/gi },
  { id: "mjs-file-invocation", re: /[^\s"']+\.mjs\b/gi },
  { id: "js-file-invocation", re: /[^\s"']+\.js\b/gi },
  { id: "npx-command", re: /\bnpx\b/gi },
  { id: "npm-command", re: /\bnpm\b/gi },
  { id: "pnpm-command", re: /\bpnpm\b/gi },
];

// Sentinel self-test: proves FORBIDDEN_PATTERNS still catches an actual
// invocation in each id's own idiom, and still tolerates the one known
// benign near-miss ("Node-free", the clients' own self-description).
// Without this, a future edit that quietly weakens or over-widens a
// pattern (exactly what happened with the "Node-free" false positive
// this guard once had) would only be caught if someone happened to
// re-introduce a real violation locally - a silent regression
// otherwise. Runs against in-memory sample strings, not the real
// client files, so it exercises the same two dialects (bash,
// PowerShell) both clients are written in without needing a fixture
// file for either.
const SENTINEL_POSITIVE_CASES = [
  { id: "node-command", sample: 'exec node "$SCRIPT_PATH"' },
  { id: "node-command", sample: "& node.exe .\\helper.ps1" },
  { id: "nodejs-command", sample: "command -v nodejs" },
  { id: "require-call", sample: "x=require('fs')" },
  { id: "cjs-file-invocation", sample: "node guard.cjs" },
  { id: "mjs-file-invocation", sample: "import('./thing.mjs')" },
  { id: "js-file-invocation", sample: "run helper.js" },
  { id: "npx-command", sample: "npx tsx foo.ts" },
  { id: "npm-command", sample: "npm run build" },
  { id: "pnpm-command", sample: "pnpm exec node" },
];

const SENTINEL_NEGATIVE_CASES = [
  { id: "node-command", sample: 'local desc="Node-free bash reference client"' },
  { id: "node-command", sample: "# Node-free PowerShell reference client" },
];

function selfTestPatterns() {
  const failures = [];
  for (const { id, sample } of SENTINEL_POSITIVE_CASES) {
    const pattern = FORBIDDEN_PATTERNS.find((p) => p.id === id);
    pattern.re.lastIndex = 0;
    if (!pattern.re.test(sample)) {
      failures.push(
        `sentinel: pattern "${id}" failed to match its own positive sample ${JSON.stringify(sample)}; this pattern may have regressed`,
      );
    }
  }
  for (const { id, sample } of SENTINEL_NEGATIVE_CASES) {
    const pattern = FORBIDDEN_PATTERNS.find((p) => p.id === id);
    pattern.re.lastIndex = 0;
    if (pattern.re.test(sample)) {
      failures.push(
        `sentinel: pattern "${id}" incorrectly matched the known-benign sample ${JSON.stringify(sample)}; this would false-positive on the clients' own self-description`,
      );
    }
  }
  return failures;
}

function main() {
  const selfTestFailures = selfTestPatterns();
  if (selfTestFailures.length > 0) {
    for (const f of selfTestFailures) {
      console.error(`::error::no-node-invocation: ${f}`);
    }
    console.error(
      "no-node-invocation: the guard's own detection patterns failed a sentinel self-test; " +
        "a pass against the real client files below cannot be trusted until this is fixed",
    );
    process.exit(1);
  }

  const violations = [];
  let anyFound = false;

  for (const name of TARGET_FILES) {
    const abs = path.join(referenceDir, name);
    if (!fs.existsSync(abs)) continue;
    anyFound = true;

    const relPath = path.relative(repoRoot, abs).replace(/\\/g, "/");
    const text = fs.readFileSync(abs, "utf8");
    const lines = text.split("\n");

    for (let i = 0; i < lines.length; i += 1) {
      const line = lines[i];
      // Skip comment-only lines (# for bash, # or <# ... #> for
      // PowerShell): a comment mentioning "node" in prose is not an
      // invocation. This is a heuristic, not a shell parser.
      const trimmed = line.trim();
      if (trimmed.startsWith("#")) continue;

      for (const pattern of FORBIDDEN_PATTERNS) {
        pattern.re.lastIndex = 0;
        let m;
        while ((m = pattern.re.exec(line)) !== null) {
          violations.push({
            file: relPath,
            line: i + 1,
            id: pattern.id,
            match: m[0].trim(),
          });
          if (m[0].length === 0) pattern.re.lastIndex += 1;
        }
      }
    }
  }

  if (!anyFound) {
    console.log(
      "no-node-invocation: ok (vacuous pass - neither reference client file exists at its expected path)",
    );
    return;
  }

  if (violations.length > 0) {
    for (const v of violations) {
      console.error(
        `::error file=${v.file},line=${v.line}::no-node-invocation: forbidden Node invocation (${v.id}) found: "${v.match}"`,
      );
    }
    console.error(`no-node-invocation: ${violations.length} violation(s) found`);
    process.exit(1);
  }

  console.log("no-node-invocation: ok");
}

main();
