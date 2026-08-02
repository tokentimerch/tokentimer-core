#!/usr/bin/env node
"use strict";

// Guard: closes the "neither shipped client invokes Node" finding from
// the M5c CI-guard backlog (tokentimer-canvas plan, "Quality and CI
// backlog" item #1). The two Node-free reference clients,
// packages/agent/reference/tokentimer-protocol.sh and .ps1, exist
// specifically so an operator can talk to the protocol without a Node
// runtime; this guard statically checks their source for anything that
// would shell out to node/nodejs or a Node-based script file.
//
// IMPORTANT - this guard becomes meaningful once
// packages/agent/reference/*.sh|.ps1 exist; until then it is a
// structural no-op, not a proof of anything. Neither file exists yet
// on this branch (see Wave 1c in the M5c plan), so today this guard
// only proves "the guard itself runs without error", not "the clients
// never invoke Node" - there are no clients yet to check. It exits 0
// vacuously in that case rather than failing, because failing for
// files that were never supposed to exist yet would be noise, not
// signal. Once the files land, this stops being vacuous automatically
// (same file paths, no guard change needed).

const fs = require("node:fs");
const path = require("node:path");

const repoRoot = path.resolve(__dirname, "..", "..");
const referenceDir = path.join(repoRoot, "packages/agent/reference");

const TARGET_FILES = [
  "tokentimer-protocol.sh",
  "tokentimer-protocol.ps1",
];

// Patterns that indicate shelling out to Node or a Node-authored script
// file, in either shell or PowerShell syntax.
const FORBIDDEN_PATTERNS = [
  { id: "node-command", re: /(^|[^\w./-])node(\.exe)?\b/gi },
  { id: "nodejs-command", re: /\bnodejs\b/gi },
  { id: "require-call", re: /\brequire\s*\(/g },
  { id: "cjs-file-invocation", re: /[^\s"']+\.cjs\b/gi },
  { id: "mjs-file-invocation", re: /[^\s"']+\.mjs\b/gi },
  { id: "js-file-invocation", re: /[^\s"']+\.js\b/gi },
  { id: "npx-command", re: /\bnpx\b/gi },
  { id: "npm-command", re: /\bnpm\b/gi },
  { id: "pnpm-command", re: /\bpnpm\b/gi },
];

function main() {
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
      "no-node-invocation: ok (vacuous pass - packages/agent/reference/*.sh|.ps1 do not exist yet)",
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
