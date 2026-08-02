#!/usr/bin/env node
"use strict";

// Guard: closes the "UTF-16/BOM encoding" finding from the M5c CI-guard
// backlog (tokentimer-canvas plan, "Quality and CI backlog" item #1).
// This project has hit a recurring, real bug where a tool-generated
// write produces UTF-16LE output (no BOM, alternating 0x00 bytes)
// instead of UTF-8, which then fails downstream JSON parsing and other
// text tooling silently until something chokes on it far from the
// write site. This guard scans every tracked text file for that exact
// byte pattern, plus a leading UTF-8 BOM (also disallowed), so the
// failure is caught at commit time instead of at parse time.

const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const repoRoot = path.resolve(__dirname, "..", "..");

// Same binary-extension denylist rationale as leak-scan.cjs: these
// file types are expected to contain arbitrary bytes, including long
// runs of 0x00, so the UTF-16 heuristic below is meaningless for them.
const BINARY_EXTENSIONS = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".bmp",
  ".woff", ".woff2", ".ttf", ".eot", ".otf",
  ".zip", ".tar", ".gz", ".tgz", ".7z", ".rar",
  ".pdf", ".exe", ".dll", ".so", ".dylib", ".node", ".wasm",
  ".db", ".sqlite", ".sqlite3", ".pyc", ".class", ".jar",
]);

function listTrackedFiles() {
  const out = execFileSync("git", ["ls-files"], {
    cwd: repoRoot,
    encoding: "utf8",
  });
  return out.split("\n").filter(Boolean);
}

function classify(buf) {
  if (buf.length === 0) return null;

  // UTF-8 BOM: EF BB BF.
  if (buf.length >= 3 && buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf) {
    return "UTF-8 BOM present (EF BB BF); strip it";
  }

  // Explicit UTF-16 BOM in either byte order.
  if (buf.length >= 2 && buf[0] === 0xff && buf[1] === 0xfe) {
    return "UTF-16LE BOM present (FF FE)";
  }
  if (buf.length >= 2 && buf[0] === 0xfe && buf[1] === 0xff) {
    return "UTF-16BE BOM present (FE FF)";
  }

  // No-BOM UTF-16LE heuristic: this is the exact recurring bug. ASCII
  // text encoded as UTF-16LE alternates a printable byte with a 0x00
  // byte (e.g. "#!/usr/bin/env node" becomes 23 00 21 00 2F 00 ...).
  // Sample enough of the file to be confident without reading it all
  // twice; a real UTF-8 text file essentially never has this ratio of
  // null bytes at even offsets.
  const sampleLen = Math.min(buf.length, 4096);
  if (sampleLen >= 8 && sampleLen % 2 === 0) {
    let evenNulls = 0;
    let oddNulls = 0;
    for (let i = 0; i < sampleLen; i += 1) {
      if (buf[i] === 0x00) {
        if (i % 2 === 0) evenNulls += 1;
        else oddNulls += 1;
      }
    }
    const halfLen = sampleLen / 2;
    // Odd positions null and even positions not (or vice versa) across
    // most of the sample is the UTF-16LE/BE-without-BOM signature; a
    // stray null byte or two in a genuinely binary-ish text file (rare)
    // won't reach this threshold.
    if (oddNulls > halfLen * 0.8 && evenNulls < halfLen * 0.05) {
      return "looks like UTF-16LE with no BOM (null byte after nearly every character)";
    }
    if (evenNulls > halfLen * 0.8 && oddNulls < halfLen * 0.05) {
      return "looks like UTF-16BE with no BOM (null byte before nearly every character)";
    }
  }

  return null;
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
      continue; // deleted-in-working-tree but still tracked
    }

    const problem = classify(buf);
    if (problem) {
      violations.push({ file: relPosix, problem });
    }
  }

  if (violations.length > 0) {
    for (const v of violations) {
      console.error(`::error file=${v.file}::encoding-check: ${v.problem}`);
    }
    console.error(`encoding-check: ${violations.length} file(s) failed the UTF-8 encoding check`);
    process.exit(1);
  }

  console.log("encoding-check: ok");
}

main();
