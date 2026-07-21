/**
 * Import filter rules (issue #69, V1)
 *
 * Ordered list of rules applied uniformly to provider scan results and to
 * the shared import pipeline. Each rule:
 *   { action: "include"|"exclude", matchType: "regex"|"exact",
 *     field: "name"|"description", value: string }
 *
 * `value` for matchType "regex" uses JavaScript (ECMAScript) regex syntax,
 * evaluated case-sensitively unless wrapped as a full JS regex literal
 * (e.g. `/foo/i`), in which case the trailing flags are honored.
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

// ReDoS hardening (security review, issue #69 follow-up): the regex is
// compiled and run server-side, once per scanned item, and can be re-run
// unattended by the auto-sync worker on a cron schedule against
// attacker-influenced content (item names/descriptions from a shared
// GitLab/GitHub org). Node's regex engine is synchronous and not
// preemptible, so a catastrophic-backtracking pattern can hang the whole
// process. These limits are a pragmatic, dependency-free mitigation, not a
// full static ReDoS analyzer.
const MAX_MATCH_INPUT_LENGTH = 2000;
const MAX_REGEX_QUANTIFIERS = 10;
const MAX_REGEX_GROUPS = 10;

const VALID_ACTIONS = new Set(["include", "exclude"]);
const VALID_MATCH_TYPES = new Set(["regex", "exact"]);
const VALID_FIELDS = new Set(["name", "description"]);

/**
 * Accepts a regex value either as a bare pattern (`^foo`) or as a full
 * JavaScript regex literal (`/^foo/i`), since users commonly paste the
 * latter from regex testers/docs and `new RegExp()` would otherwise treat
 * the slashes and trailing flags as literal characters and never match.
 * Only recognized JS flags (g, i, m, s, u, y) after a trailing unescaped
 * slash are treated as a literal; anything else is used as-is.
 */
function parseRegexValue(value) {
  const src = typeof value === "string" ? value : "";
  const match = /^\/(.+)\/([a-z]*)$/s.exec(src);
  if (match && /^[gimsuy]*$/.test(match[2])) {
    return { pattern: match[1], flags: match[2] };
  }
  return { pattern: src, flags: "" };
}

/**
 * Heuristic scan for regex patterns that are likely to cause catastrophic
 * backtracking (ReDoS), e.g. `(a+)+`, `(a*)*`, `(a{2,})+`. This walks the
 * pattern source once, tracking group nesting (skipping character classes
 * and escaped characters), and flags a group as "unsafe" when it contains
 * an inner quantifier (`*`, `+`, or a bounded `{m,n}` that can repeat more
 * than once) AND the group itself is also quantified to repeat more than
 * once. That shape is what causes exponential backtracking on crafted
 * input. As a coarse secondary guard, it also caps the total number of
 * quantifiers and groups in a single pattern.
 *
 * This is intentionally a pragmatic heuristic (similar in spirit to
 * `safe-regex`), not a complete ReDoS static analyzer. It will not catch
 * every catastrophic pattern, but it blocks the common nested-quantifier
 * shapes without adding a new dependency.
 *
 * Returns a short human-readable reason string when the pattern looks
 * unsafe, otherwise null.
 */
function findUnsafeRegexReason(pattern) {
  const src = typeof pattern === "string" ? pattern : "";
  let inClass = false;
  let quantifierCount = 0;
  let groupCount = 0;
  const groupStack = [];
  let i = 0;
  const len = src.length;

  // pos points at '{'. Returns { end, repeatsMoreThanOnce } for a valid
  // {m}, {m,} or {m,n} quantifier, otherwise null (treated as a literal).
  const readBoundedQuantifier = (pos) => {
    const close = src.indexOf("}", pos);
    if (close === -1) return null;
    const inner = src.slice(pos + 1, close);
    if (!/^\d+(,\d*)?$/.test(inner)) return null;
    const parts = inner.split(",");
    const repeatsMoreThanOnce =
      parts.length === 1
        ? Number(parts[0]) > 1
        : (parts[1] === "" ? Infinity : Number(parts[1])) > 1;
    return { end: close, repeatsMoreThanOnce };
  };

  while (i < len) {
    const ch = src[i];
    if (ch === "\\") {
      i += 2;
      continue;
    }
    if (inClass) {
      if (ch === "]") inClass = false;
      i++;
      continue;
    }
    if (ch === "[") {
      inClass = true;
      i++;
      continue;
    }
    if (ch === "(") {
      groupStack.push({ hasQuantifier: false });
      groupCount++;
      i++;
      continue;
    }
    if (ch === ")") {
      const closed = groupStack.pop() || { hasQuantifier: false };
      let quantifiesGroup = false;
      const next = src[i + 1];
      if (next === "*" || next === "+") {
        quantifiesGroup = true;
      } else if (next === "{") {
        const q = readBoundedQuantifier(i + 1);
        if (q) quantifiesGroup = q.repeatsMoreThanOnce;
      }
      if (quantifiesGroup) quantifierCount++;
      if (closed.hasQuantifier && quantifiesGroup) {
        return "nested quantifiers detected";
      }
      if (
        groupStack.length > 0 &&
        (closed.hasQuantifier || quantifiesGroup)
      ) {
        groupStack[groupStack.length - 1].hasQuantifier = true;
      }
      i++;
      continue;
    }
    if (ch === "*" || ch === "+") {
      quantifierCount++;
      if (groupStack.length > 0) {
        groupStack[groupStack.length - 1].hasQuantifier = true;
      }
      i++;
      continue;
    }
    if (ch === "{") {
      const q = readBoundedQuantifier(i);
      if (q) {
        quantifierCount++;
        if (q.repeatsMoreThanOnce && groupStack.length > 0) {
          groupStack[groupStack.length - 1].hasQuantifier = true;
        }
        i = q.end + 1;
        continue;
      }
      i++;
      continue;
    }
    i++;
  }

  if (quantifierCount > MAX_REGEX_QUANTIFIERS) {
    return `too many quantifiers, max ${MAX_REGEX_QUANTIFIERS}`;
  }
  if (groupCount > MAX_REGEX_GROUPS) {
    return `too many groups, max ${MAX_REGEX_GROUPS}`;
  }
  return null;
}

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
      const { pattern, flags } = parseRegexValue(rule.value);
      try {
        new RegExp(pattern, flags);
      } catch (e) {
        return `${label}.value is not a valid regular expression: ${e.message}`;
      }
      const unsafeReason = findUnsafeRegexReason(pattern);
      if (unsafeReason) {
        return `${label}.value is a potentially unsafe regular expression pattern (${unsafeReason})`;
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
  // provider description under `description` or `notes`. GitLab personal
  // access tokens, project/group access tokens, and pipeline trigger tokens
  // all carry a real GitLab-side `description` (see gitlabIntegration.js),
  // which lands here directly. A handful of token types have no
  // description at all in their provider API (GitLab deploy tokens, SSH
  // keys, GitHub secrets/deploy keys), so for those we fall back to `name`
  // rather than silently matching nothing: for those providers the name IS
  // the only creation-time free-text the operator controls, which is
  // exactly what the "description" issue #69 is meant to match against.
  if (typeof item.description === "string" && item.description.length > 0) {
    return item.description;
  }
  if (typeof item.notes === "string" && item.notes.length > 0) {
    return item.notes;
  }
  return typeof item.name === "string" ? item.name : "";
}

function ruleMatches(rule, item) {
  const value = getItemField(item, rule.field);
  if (rule.matchType === "exact") {
    return value === rule.value;
  }
  // Bound the worst-case input size regex backtracking can run against.
  // Combined with the static nested-quantifier heuristic in
  // validateFilterRules, this keeps even an unanticipated bad pattern's
  // runtime tractable, since catastrophic backtracking cost scales with
  // input length.
  const boundedValue =
    value.length > MAX_MATCH_INPUT_LENGTH
      ? value.slice(0, MAX_MATCH_INPUT_LENGTH)
      : value;
  try {
    const { pattern, flags } = parseRegexValue(rule.value);
    return new RegExp(pattern, flags).test(boundedValue);
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
