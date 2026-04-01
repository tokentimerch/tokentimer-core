#!/usr/bin/env node

// Lightweight wrapper: delegates to check-contracts-integrity.js
// Kept for backward compatibility with scripts that call `check:contracts`

const { spawnSync } = require("child_process");
const path = require("path");

const result = spawnSync(
  process.execPath,
  [path.join(__dirname, "check-contracts-integrity.js")],
  { stdio: "inherit" },
);

process.exit(typeof result.status === "number" ? result.status : 1);
