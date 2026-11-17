"use strict";
const { test } = require("node:test"), assert = require("node:assert/strict");
const { cleanup } = require("./owned-teardown.cjs"), { createDockerTransport } = require("./docker-transport.cjs");
test("Docker adapter scopes project cleanup and checks for remaining volumes and networks", async () => {
  const project = "tt-wildcard-ux-qual-abc", items = [
    { kind: "container", id: "a".repeat(64), project }, { kind: "volume", id: "owned-volume", project },
    { kind: "network", id: "b".repeat(64), project },
    { kind: "volume", id: "foreign-volume", project: "other" },
    { kind: "network", id: "c".repeat(64), project: "other" },
  ];
  const calls = [];
  const execute = args => {
    calls.push(args);
    const kind = args[0] === "ps" ? "container" : args[0], action = args[0] === "ps" ? "ls" : args[1];
    if (action === "ls") {
      const scoped = args.includes("--filter");
      return items.filter(item => item.kind === kind && (!scoped || item.project === project)).map(item => item.id).join("\n");
    }
    const index = items.findIndex(item => item.kind === kind && item.id === args.at(-1));
    const item = items[index];
    if (action === "inspect") {
      const labels = { "com.docker.compose.project": item.project };
      if (kind === "container") return JSON.stringify([{ Id: item.id, Config: { Labels: labels } }]);
      if (kind === "volume") return JSON.stringify([{ Name: item.id, Labels: labels }]);
      return JSON.stringify([{ Id: item.id, Labels: labels }]);
    }
    if (action === "rm") { items.splice(index, 1); return ""; }
    throw new Error("unexpected Docker command");
  };
  const result = await cleanup({ project, transport: createDockerTransport({ project, execute }) });
  assert.equal(result.ownedVolumesAbsent, true);
  assert.equal(result.ownedNetworksAbsent, true);
  assert.deepEqual(items.map(item => item.id), ["foreign-volume", "c".repeat(64)]);
  assert.deepEqual(calls.filter(args => args[1] === "rm").map(args => args[0]), ["container", "volume", "network"]);
  assert.ok(calls.every(args => !args.includes("prune")));
});
