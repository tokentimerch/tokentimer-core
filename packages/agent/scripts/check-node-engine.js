"use strict";

// The package uses a bounded pair of exact semver comparators. Fail closed if
// that format changes rather than silently accepting an unsupported runtime.
function supportsNode(range, version) {
  const component = "(0|[1-9]\\d*)";
  const bound = `${component}\\.${component}\\.${component}`;
  const match = new RegExp(`^>=\\s*${bound}\\s+<\\s*${bound}$`).exec(range);
  const installed = /^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/.exec(version);
  if (!match || !installed) return false;
  const numbers = [...match.slice(1), ...installed.slice(1)].map(Number);
  if (!numbers.every(Number.isSafeInteger)) return false;
  const [lower, upper, current] = [numbers.slice(0, 3), numbers.slice(3, 6), numbers.slice(6, 9)];
  const compare = (a, b) => {
    for (let i = 0; i < 3; i += 1) {
      if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
    }
    return 0;
  };
  return compare(lower, upper) < 0 && compare(current, lower) >= 0 && compare(current, upper) < 0;
}

if (require.main === module) {
  process.exitCode = supportsNode(process.argv[2] || "", process.argv[3] || "") ? 0 : 1;
}

module.exports = { supportsNode };
