"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const path = require("path");

// Signature of UTF-8 text that was decoded as Windows-1252/Latin-1 and
// re-encoded: U+00C2/U+00C3 followed by a character in the UTF-8
// continuation-byte range. Legitimate accented text never produces this
// pair, so any match is corrupted source (e.g. the import-notes warning
// prefix that surfaced as strange characters in imported token notes).
const MOJIBAKE = /[\u00C2\u00C3][\u0080-\u00BF]/;

const SCAN_DIRS = ["apps/api", "apps/worker/src", "apps/dashboard/src"];
const SCAN_EXT = new Set([".js", ".jsx"]);
const SKIP_DIRS = new Set(["node_modules", "dist", "build", "coverage"]);

function collectSourceFiles(dir, out) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) {
        collectSourceFiles(path.join(dir, entry.name), out);
      }
    } else if (SCAN_EXT.has(path.extname(entry.name))) {
      out.push(path.join(dir, entry.name));
    }
  }
  return out;
}

describe("source encoding integrity", () => {
  it("app source files contain no double-encoded (mojibake) characters", () => {
    const root = path.join(__dirname, "..", "..");
    const offenders = [];
    for (const dir of SCAN_DIRS) {
      const abs = path.join(root, dir);
      if (!fs.existsSync(abs)) continue;
      for (const file of collectSourceFiles(abs, [])) {
        const text = fs.readFileSync(file, "utf8");
        const lines = text.split("\n");
        lines.forEach((line, i) => {
          if (MOJIBAKE.test(line)) {
            offenders.push(`${path.relative(root, file)}:${i + 1}`);
          }
        });
      }
    }
    assert.deepStrictEqual(
      offenders,
      [],
      `Mojibake found in: ${offenders.join(", ")}`,
    );
  });
});
