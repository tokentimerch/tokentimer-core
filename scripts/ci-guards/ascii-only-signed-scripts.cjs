#!/usr/bin/env node
"use strict";

// Guard: closes the "ASCII-only over signed .ps1 sources" finding from
// the M5c CI-guard backlog (tokentimer-canvas plan, "Quality and CI
// backlog" item #1). Microsoft documents signed PowerShell scripts
// containing non-ASCII UTF-8 content failing Authenticode hash
// validation across locales when the signing host's code page differs
// from the verifying host's
// (https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/signed-powershell-script-fails-hash-mismatch).
// Every file matching packages/agent/reference/*.ps1 must therefore
// contain only ASCII bytes (0x00-0x7F): no smart quotes, no accented
// characters, no box-drawing.
//
// IMPORTANT - this guard becomes meaningful once
// packages/agent/reference/*.ps1 exist; until then it is a structural
// no-op, not a proof of anything. No .ps1 file exists yet under that
// path on this branch (see Wave 1c in the M5c plan), so the glob below
// matches nothing today and this guard passes vacuously rather than
// failing for files that were never supposed to exist yet.

const fs = require("node:fs");
const path = require("node:path");

const repoRoot = path.resolve(__dirname, "..", "..");
const referenceDir = path.join(repoRoot, "packages/agent/reference");

function findPs1Files() {
  if (!fs.existsSync(referenceDir)) return [];
  return fs
    .readdirSync(referenceDir, { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.toLowerCase().endsWith(".ps1"))
    .map((entry) => path.join(referenceDir, entry.name));
}

function firstNonAsciiByte(buf) {
  for (let i = 0; i < buf.length; i += 1) {
    if (buf[i] > 0x7f) return i;
  }
  return -1;
}

function offsetToLineColumn(buf, offset) {
  let line = 1;
  let col = 1;
  for (let i = 0; i < offset; i += 1) {
    if (buf[i] === 0x0a) {
      line += 1;
      col = 1;
    } else {
      col += 1;
    }
  }
  return { line, col };
}

function main() {
  const files = findPs1Files();

  if (files.length === 0) {
    console.log(
      "ascii-only-signed-scripts: ok (vacuous pass - packages/agent/reference/*.ps1 matches nothing yet)",
    );
    return;
  }

  const violations = [];
  for (const abs of files) {
    const buf = fs.readFileSync(abs);
    const offset = firstNonAsciiByte(buf);
    if (offset === -1) continue;
    const relPath = path.relative(repoRoot, abs).replace(/\\/g, "/");
    const { line, col } = offsetToLineColumn(buf, offset);
    violations.push({
      file: relPath,
      line,
      col,
      byte: buf[offset].toString(16).padStart(2, "0"),
    });
  }

  if (violations.length > 0) {
    for (const v of violations) {
      console.error(
        `::error file=${v.file},line=${v.line},col=${v.col}::ascii-only-signed-scripts: first non-ASCII byte 0x${v.byte} found`,
      );
    }
    console.error(`ascii-only-signed-scripts: ${violations.length} file(s) contain non-ASCII bytes`);
    process.exit(1);
  }

  console.log(`ascii-only-signed-scripts: ok (${files.length} file(s) checked)`);
}

main();
