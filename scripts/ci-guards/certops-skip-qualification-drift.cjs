/**
 * Compare actual annotated skip sites with committed prerequisite/environment ownership.
 * Regenerate deliberately after source changes; mapping a skip never marks it executed. */
"use strict";
const fs = require("node:fs");
const path = require("node:path");
const { check } = require("../certops-skip-qualification.js");
try {
  const committed = JSON.parse(fs.readFileSync(path.join(__dirname, "../../docs/certops/skip-qualification.generated.json"), "utf8"));
  const errors = check(committed);
  if (errors.length) { console.error(errors.join("\n")); process.exitCode = 1; }
  else console.log("certops-skip-qualification-drift: ownership mapping matches scanner");
} catch (error) { console.error(error.message); process.exitCode = 1; }
