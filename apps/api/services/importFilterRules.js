/**
 * Import filter rules (issue #69, V1)
 *
 * Ordered list of rules applied uniformly to provider scan results and to
 * the shared import pipeline. Each rule:
 *   { action: "include"|"exclude", matchType: "regex"|"exact",
 *     field: "name"|"description", value: string }
 *
 * Semantics:
 *   - Exclude rules win over include rules.
 *   - If at least one include rule exists, an item must match an include
 *     rule to be kept (allowlist behavior).
 *   - Only exclude rules -> denylist behavior.
 *   - No rules -> everything is kept (current behavior unchanged).
 */

const MAX_RULES = 50;
const MAX_VALUE_LENGTH = 500;

const VALID_ACTIONS = new Set(["include", "exclude"]);
const VALID_MATCH_TYPES = new Set(["regex", "exact"]);
const VALID_FIELDS = new Set(["name", "description"]);

/**
 * Validates a filterRules payload. Returns null when valid, otherwise a
 * human-readable error string suitable for a 400 response.
 */
function validateFilterRules(rules) {
  if (rules === undefined || rules === null) return null;
  if (!Array.isArray(rules)) {
    return "filterRules must be an array";
  }
  if (rules.length > MAX_RULES) {
    return `filterRules cannot contain more than ${MAX_RULES} rules`;
  }
  for (let i = 0; i < rules.length; i++) {
    const rule = rules[i];
    const label = `filterRules[${i}]`;
    if (!rule || typeof rule !== "object") {
      return `${label} must be an object`;
    }
    if (!VALID_ACTIONS.has(rule.action)) {
      return `${label}.action must be "include" or "exclude"`;
    }
    if (!VALID_MATCH_TYPES.has(rule.matchType)) {
      return `${label}.matchType must be "regex" or "exact"`;
    }
    if (!VALID_FIELDS.has(rule.field)) {
      return `${label}.field must be "name" or "description"`;
    }
    if (typeof rule.value !== "string" || rule.value.length === 0) {
      return `${label}.value must be a non-empty string`;
    }
    if (rule.value.length > MAX_VALUE_LENGTH) {
      return `${label}.value cannot exceed ${MAX_VALUE_LENGTH} characters`;
    }
    if (rule.matchType === "regex") {
      try {
        // eslint-disable-next-line no-new
        new RegExp(rule.value);
      } catch (e) {
        return `${label}.value is not a valid regular expression: ${e.message}`;
      }
    }
  }
  return null;
}

function getItemField(item, field) {
  if (!item || typeof item !== "object") return "";
  if (field === "name") {
    return typeof item.name === "string" ? item.name : "";
  }
  // Description-like field: scan items and import payloads may carry the
  // provider description under `description` or `notes`.
  if (typeof item.description === "string") return item.description;
  if (typeof item.notes === "string") return item.notes;
  return "";
}

function ruleMatches(rule, item) {
  const value = getItemField(item, rule.field);
  if (rule.matchType === "exact") {
    return value === rule.value;
  }
  try {
    return new RegExp(rule.value).test(value);
  } catch (_e) {
    // Invalid patterns are rejected at validation time; treat as no match.
    return false;
  }
}

/**
 * Returns true when the item passes the rules (should be kept).
 */
function evaluateFilterRules(rules, item) {
  if (!Array.isArray(rules) || rules.length === 0) return true;

  const includeRules = rules.filter((r) => r.action === "include");
  const excludeRules = rules.filter((r) => r.action === "exclude");

  // Exclude wins over include.
  for (const rule of excludeRules) {
    if (ruleMatches(rule, item)) return false;
  }
  if (includeRules.length > 0) {
    return includeRules.some((rule) => ruleMatches(rule, item));
  }
  return true;
}

/**
 * Applies rules to an item list. Returns { items, matchedCount, excludedCount }.
 * With no rules, returns the original list untouched.
 */
function applyFilterRules(rules, items) {
  const list = Array.isArray(items) ? items : [];
  if (!Array.isArray(rules) || rules.length === 0) {
    return { items: list, matchedCount: list.length, excludedCount: 0 };
  }
  const kept = list.filter((item) => evaluateFilterRules(rules, item));
  return {
    items: kept,
    matchedCount: kept.length,
    excludedCount: list.length - kept.length,
  };
}

module.exports = {
  validateFilterRules,
  evaluateFilterRules,
  applyFilterRules,
};
