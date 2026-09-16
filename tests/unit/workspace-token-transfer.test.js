"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  buildContactGroupTransferMap,
  remapJoinRows,
} = require(
  path.resolve(
    __dirname,
    "../../apps/api/services/workspaceTokenTransfer.js",
  ),
);

describe("workspace token transfer contact-group remap", () => {
  it("keeps an id that already exists in the destination", () => {
    const { map, unmatched } = buildContactGroupTransferMap(
      [{ id: "ops", name: "Ops" }],
      [{ id: "ops", name: "Operations" }],
    );
    assert.equal(map.get("ops"), "ops");
    assert.deepEqual(unmatched, []);
  });

  it("remaps by case-insensitive name when ids differ", () => {
    const { map, unmatched } = buildContactGroupTransferMap(
      [{ id: "src-ops", name: "On-call" }],
      [{ id: "dest-ops", name: "on-call" }],
    );
    assert.equal(map.get("src-ops"), "dest-ops");
    assert.deepEqual(unmatched, []);
  });

  it("records unmatched source groups", () => {
    const { map, unmatched } = buildContactGroupTransferMap(
      [{ id: "only-src", name: "Secret" }],
      [{ id: "other", name: "Public" }],
    );
    assert.equal(map.size, 0);
    assert.deepEqual(unmatched, [{ id: "only-src", name: "Secret" }]);
  });

  it("drops join rows whose group cannot be remapped", () => {
    const idMap = new Map([["ops", "ops"]]);
    const { remapped, dropped } = remapJoinRows(
      [
        { token_id: 1, contact_group_id: "ops" },
        { token_id: 1, contact_group_id: "gone" },
      ],
      idMap,
    );
    assert.deepEqual(remapped, [{ token_id: 1, contact_group_id: "ops" }]);
    assert.deepEqual(dropped, [{ token_id: 1, contact_group_id: "gone" }]);
  });
});
