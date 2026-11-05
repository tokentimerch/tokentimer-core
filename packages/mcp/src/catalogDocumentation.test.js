"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

test("the adapter guide lists every implemented MCP tool", () => {
  const catalog = require("../../contracts/mcp/mcp-tool-catalog.json");
  const guide = fs.readFileSync(path.join(__dirname, "..", "README.md"), "utf8");
  const implemented = catalog.tools.filter((tool) =>
    tool.routeStatus === "implemented" && ["mvp", "write"].includes(tool.contractStatus),
  );
  assert.ok(implemented.length > 0, "the implemented catalog must not be empty");
  for (const tool of implemented) {
    assert.ok(guide.includes(`\`${tool.name}\``), `${tool.name} is missing from the adapter guide`);
  }
});
