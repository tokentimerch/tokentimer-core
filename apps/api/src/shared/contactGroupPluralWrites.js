"use strict";

function isContactGroupPluralWritesEnabled() {
  const raw = String(process.env.CONTACT_GROUP_PLURAL_WRITES || "")
    .trim()
    .toLowerCase();
  if (raw === "false" || raw === "0" || raw === "no") return false;
  if (raw === "true" || raw === "1" || raw === "yes") return true;
  // Unset / empty: on. Explicit false is the mixed-fleet kill switch.
  return true;
}

module.exports = { isContactGroupPluralWritesEnabled };
