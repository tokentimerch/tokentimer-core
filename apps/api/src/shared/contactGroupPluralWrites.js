"use strict";

function isContactGroupPluralWritesEnabled() {
  const raw = String(process.env.CONTACT_GROUP_PLURAL_WRITES || "")
    .trim()
    .toLowerCase();
  if (raw === "true" || raw === "1" || raw === "yes") return true;
  if (raw === "false" || raw === "0" || raw === "no") return false;
  return process.env.NODE_ENV === "test";
}

module.exports = { isContactGroupPluralWritesEnabled };
