"use strict";

const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const workflow = fs.readFileSync(path.join(__dirname, "../.github/workflows/certops-enterprise-adcs-journal-phase-experiment.yml"), "utf8");
const [, preflight, lab] = /^  preflight:\n([\s\S]*?)^  lab:\n([\s\S]*)$/m.exec(workflow);
const source = /        run: \|\n((?: {10}[^\n]*\n)+)/.exec(preflight)[1].replace(/^ {10}/gm, "");

test("the journal-phase caller validates before environment review and token issuance", () => {
  assert.match(workflow, /^permissions: \{\}$/m);
  assert.match(preflight, /github\.repository == 'tokentimerch\/tokentimer-core'/);
  assert.match(preflight, /github\.ref == 'refs\/heads\/main'/);
  assert.doesNotMatch(preflight, /environment:|id-token:|login-oidc|provision-lab/i);
  assert.match(lab, /^    needs: preflight$/m);
  assert.match(lab, /^    environment: certops-adcs-lab$/m);
  assert.match(lab, /^      id-token: write$/m);
  assert.doesNotMatch(workflow, /accepted-before-bind|bound-before-complete/);
});

test("supported journal phases pass, while disabled phases fail before lab review", () => {
  for (const [phase, supported] of [
    ["keygen_intent", true], ["prepared", true], ["submitting", true], ["installing", true],
    ["accepted-before-bind", false], ["bound-before-complete", false], ["", false], ["Installing", false],
  ]) {
    const result = spawnSync("pwsh", ["-NoProfile", "-NonInteractive", "-Command", source], {
      encoding: "utf8", windowsHide: true, timeout: 10000, env: { ...process.env, JOURNAL_PHASE: phase },
    });
    assert.ifError(result.error);
    if (supported) assert.equal(result.status, 0, result.stderr);
    else {
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /This journal phase is unavailable/);
    }
  }
});
