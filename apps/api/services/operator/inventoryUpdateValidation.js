"use strict";

const inventory = require("./tokenInventory");

// An update is a partial metadata change. Classification and provider-owned
// fields deliberately stay outside this first surface.
const EDITABLE_FIELDS = Object.freeze(["name", "expiresAt", "location", "usedBy", "sections", "domains", "description"]);

function normalizeUpdate(current, changes) {
  if (!changes || typeof changes !== "object" || Array.isArray(changes)) throw inventory.invalid();
  const keys = Object.keys(changes);
  if (!keys.length || keys.some((key) => !EDITABLE_FIELDS.includes(key))) throw inventory.invalid();
  inventory.assertSafe(changes);
  const candidate = inventory.normalizeRecords([{ ...current, ...changes }])[0];
  return Object.fromEntries(keys.sort().map((key) => [key, candidate[key]]));
}

module.exports = { EDITABLE_FIELDS, normalizeUpdate };
