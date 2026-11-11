"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { test } = require("node:test");

const root = path.resolve(__dirname, "../..");
const curlFloors = ["curl>=8.23.0-r0", "libcurl>=8.23.0-r0"];

function runtimeCommands(file) {
  const instructions = fs.readFileSync(path.join(root, file), "utf8")
    .replace(/\\\r?\n/g, " ")
    .split(/\r?\n/);
  const finalStage = instructions.findLastIndex(line => /^FROM\s/i.test(line));
  assert.ok(finalStage >= 0, "The dashboard recipe must declare its runtime stage");
  assert.match(instructions[finalStage], /^FROM nginx:/);
  return instructions.slice(finalStage + 1)
    .filter(line => /^RUN\s/i.test(line))
    .flatMap(line => line.replace(/^RUN\s+/i, "").split(/\s+&&\s+/));
}

function hasArgument(command, argument) {
  const tokens = command.match(/"[^"]*"|'[^']*'|\S+/g) || [];
  return tokens.some(token => token.replace(/^['"]|['"]$/g, "") === argument);
}

for (const file of ["deploy/compose/Dockerfile.dashboard", "apps/dashboard/Dockerfile"]) {
  test(file + " installs and verifies the patched curl runtime floor", () => {
    const commands = runtimeCommands(file);
    for (const floor of curlFloors) {
      const installation = commands.findIndex(command => /^apk\s+add\s/.test(command) && hasArgument(command, floor));
      const verification = commands.findIndex(command => /^apk\s+info\s+--exists\s/.test(command) && hasArgument(command, floor));
      assert.ok(installation >= 0, "The final runtime must install " + floor + "; an unbounded upgrade can reuse stale cache");
      assert.ok(verification > installation, "The installed-package check must enforce " + floor + " after installation");
    }
  });
}

test("Docker build context explicitly excludes root and nested temporary workspaces", () => {
  const rules = fs.readFileSync(path.join(root, ".dockerignore"), "utf8")
    .split(/\r?\n/).map(line => line.trim()).filter(line => line && !line.startsWith("#"));
  for (const rule of [".tmp/", "**/.tmp/"]) {
    assert.ok(rules.includes(rule), "Private temporary workspaces require the explicit ignore rule " + rule);
  }
});
