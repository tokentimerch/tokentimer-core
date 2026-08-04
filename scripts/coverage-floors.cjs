"use strict";

// Coverage floor thresholds enforced by scripts/check-coverage-threshold.js
// (wired as pnpm coverage:check:backend / coverage:check:frontend, and
// transitively pnpm test:coverage). CI fails if measured coverage on the
// corresponding lcov report drops below any of these numbers.
//
// RULE: never lower a floor to make CI green. If a floor must move, the
// change needs a real reason: a test suite that legitimately shrank for a
// documented reason, an lcov toolchain upgrade that materially recalculates
// percentages, or coverage genuinely rose past the old floor and the new,
// higher number is the one being committed. "The number is red, lower the
// number" is never a valid why:.
//
// scripts/ci-guards/coverage-floor-why.cjs enforces the mechanical half of
// this rule: every numeric threshold key below must have a `// why:`
// comment immediately above it (or a short comment block ending in one).
// It can only check that a why: was written down, not whether it is a GOOD
// reason; that judgement still belongs to code review.

module.exports = {
  backend: {
    // why: floor pinned at the coverage level already being enforced by
    // the pre-existing coverage:check:backend script (50/45/45/50) at the
    // time this config file was introduced; a starting baseline, not a
    // newly chosen target.
    lines: 50,
    // why: same baseline snapshot as lines above.
    branches: 45,
    // why: same baseline snapshot as lines above.
    functions: 45,
    // why: statements tracks lines 1:1 in this codebase's coverage
    // pipeline (see check-coverage-threshold.js: statementsPct = linesPct),
    // so it is pinned to the same baseline value as lines.
    statements: 50,
  },
  frontend: {
    // why: floor pinned at the coverage level already being enforced by
    // the pre-existing coverage:check:frontend script (10/20/10/10) at the
    // time this config file was introduced; a starting baseline, not a
    // newly chosen target. Dashboard coverage started far lower than the
    // backend's, hence the lower starting floors.
    lines: 10,
    // why: same baseline snapshot as lines above.
    branches: 20,
    // why: same baseline snapshot as lines above.
    functions: 10,
    // why: same baseline snapshot as lines above.
    statements: 10,
  },
};
