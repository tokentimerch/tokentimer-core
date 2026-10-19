"use strict";
// Missing or renamed supporting tests cannot silently narrow release evidence.
const fs = require("node:fs"),
  path = require("node:path");
function validate(root = path.resolve(__dirname, "..")) {
  const errors = [],
    matrix = JSON.parse(
      fs.readFileSync(
        path.join(root, "docs/certops/qualification-suites.json"),
      ),
    );
  const {
    PHASES,
    SUITE,
  } = require("../tests/wildcard-vault/ux-lab/qualification.cjs");
  const q = JSON.parse(
    fs.readFileSync(path.join(root, "docs/certops/qualification-suites.json")),
  );
  if (
    JSON.stringify(q.suites[SUITE]) !==
    JSON.stringify(PHASES.map((p) => "distribution-" + p))
  )
    errors.push("Distribution phase inventory differs from strict runner");
  const modes = matrix.slots
    .filter((s) => s.suite === SUITE)
    .map((s) => s.environment.certificateMode)
    .sort();
  if (JSON.stringify(modes) !== JSON.stringify(["ordinary", "san", "wildcard"]))
    errors.push("Distribution issuance cohort missing or duplicated");
  for (const name of ["postgres", "pr329-review", "transfer"]) {
    const slot = matrix.slots.find(
      (s) => s.id === "distribution-postgres-" + name,
    );
    const source = "tests/wildcard-vault/" + name + ".test.cjs";
    const names = [
      ...fs
        .readFileSync(path.join(root, source), "utf8")
        .matchAll(/^test\("([^"]+)"/gm),
    ].map((x) => x[1]);
    if (
      !names.length ||
      slot?.source !== source ||
      JSON.stringify(slot?.requiredTests) !== JSON.stringify(names)
    )
      errors.push("Distribution PostgreSQL mandatory inventory drift: " + name);
  }
  const vault = matrix.slots.find((s) => s.id === "distribution-vault-adapter");
  const source = "packages/agent/src/material-store/material-store.test.js";
  const names = [
    ...fs
      .readFileSync(path.join(root, source), "utf8")
      .matchAll(/^test\("([^"]+)"/gm),
  ].map((x) => x[1]);
  if (
    vault?.source !== source ||
    JSON.stringify(vault?.requiredTests) !== JSON.stringify(names)
  )
    errors.push("Real Vault mandatory inventory drift");
  return errors;
}
if (require.main === module) {
  const errors = validate();
  if (errors.length) {
    console.error(errors.join("\n"));
    process.exitCode = 1;
  } else
    console.log(
      "Distribution scenario cohorts and supporting test inventory valid; execution evidence is separate",
    );
}
module.exports = { validate };
