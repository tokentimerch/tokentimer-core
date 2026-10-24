// Rules for the website step: the check settings the product supports, a list
// of websites to add together, and turning discovered hostnames into that
// list. Pure, so every rule is testable without a browser.

import { normalizeMonitorUrl } from './operations.js';

/** The only intervals the API accepts; it does not validate them on create. */
export const CHECK_INTERVALS = [
  { value: '1min', label: 'Every minute' },
  { value: '5min', label: 'Every 5 minutes' },
  { value: '30min', label: 'Every 30 minutes' },
  { value: 'hourly', label: 'Every hour' },
  { value: 'daily', label: 'Every day' },
];

export const ALERT_AFTER_MIN = 1;
export const ALERT_AFTER_MAX = 10;

/** What the wizard used before these were visible, so nothing changes by default. */
export const DEFAULT_MONITOR_SETTINGS = Object.freeze({
  checkInterval: 'hourly',
  healthCheckEnabled: true,
  alertAfterFailures: 2,
});

/**
 * Each website is checked once on creation, which can take several seconds,
 * so one batch stays small enough to finish and to review.
 */
export const MAX_STAGED_WEBSITES = 50;

/**
 * The saved setup progress keeps each address in a text field of at most 512
 * characters, with a few more for its wrapper. Longer ones could be created
 * but never recorded, so they are refused up front.
 */
export const MAX_WEBSITE_LENGTH = 500;

/** The saved setup progress holds at most 100 ids per list. */
export const MAX_SAVED_REFS = 100;

/** Newest ids first kept: merges ids and drops the oldest past the limit. */
export function mergeRefs(existing, added, max = MAX_SAVED_REFS) {
  const merged = Array.from(
    new Set([...(existing || []), ...(added || [])].filter(Boolean))
  );
  return merged.slice(-max);
}

export const MAX_SECTION_LABELS = 50;

/** Comma-separated section labels, trimmed and de-duplicated. */
export function parseSections(input) {
  const labels = Array.from(
    new Set(
      String(input || '')
        .split(',')
        .map(s => s.trim().slice(0, 200))
        .filter(Boolean)
    )
  );
  if (labels.length > MAX_SECTION_LABELS) {
    return {
      ok: false,
      labels,
      error: `Use at most ${MAX_SECTION_LABELS} labels.`,
    };
  }
  return { ok: true, labels };
}

export function validateMonitorSettings(settings) {
  const s = { ...DEFAULT_MONITOR_SETTINGS, ...(settings || {}) };
  const errors = {};
  if (!CHECK_INTERVALS.some(i => i.value === s.checkInterval)) {
    errors.checkInterval = 'Choose how often to check.';
  }
  const n = Number(s.alertAfterFailures);
  if (
    s.healthCheckEnabled &&
    (!Number.isInteger(n) || n < ALERT_AFTER_MIN || n > ALERT_AFTER_MAX)
  ) {
    errors.alertAfterFailures = `Use a whole number from ${ALERT_AFTER_MIN} to ${ALERT_AFTER_MAX}.`;
  }
  const sections = parseSections(s.section);
  if (!sections.ok) errors.section = sections.error;
  return {
    ok: Object.keys(errors).length === 0,
    errors,
    value: {
      checkInterval: s.checkInterval,
      healthCheckEnabled: Boolean(s.healthCheckEnabled),
      alertAfterFailures: Number.isInteger(n) ? n : 2,
      ...(sections.ok && sections.labels.length
        ? { section: sections.labels }
        : {}),
    },
  };
}

/**
 * The check settings last applied, read back from the saved session. Anything
 * missing or malformed gives the defaults, so a bad value never reaches the
 * form. Only the three scalars are kept.
 */
export function storedMonitorSettings(stored) {
  const s = stored && typeof stored === 'object' ? stored : null;
  if (
    !s ||
    typeof s.healthCheckEnabled !== 'boolean' ||
    typeof s.alertAfterFailures !== 'number'
  ) {
    return { ...DEFAULT_MONITOR_SETTINGS };
  }
  const check = validateMonitorSettings({
    checkInterval: s.checkInterval,
    healthCheckEnabled: s.healthCheckEnabled,
    alertAfterFailures: s.alertAfterFailures,
  });
  if (!check.ok) return { ...DEFAULT_MONITOR_SETTINGS };
  const { checkInterval, healthCheckEnabled, alertAfterFailures } = check.value;
  return { checkInterval, healthCheckEnabled, alertAfterFailures };
}

const same = (a, b) => String(a).toLowerCase() === String(b).toLowerCase();

/** Adds one typed address to the list, or says why it cannot be added. */
export function stageWebsite(list, input) {
  const url = normalizeMonitorUrl(input);
  if (!url) {
    return {
      ok: false,
      list,
      error: 'Enter a valid HTTPS address, for example https://example.com',
    };
  }
  if (list.some(u => same(u, url))) {
    return {
      ok: false,
      list,
      duplicate: true,
      error: `${url} is already in the list.`,
    };
  }
  if (url.length > MAX_WEBSITE_LENGTH) {
    return {
      ok: false,
      list,
      error: `That address is too long. Use one of up to ${MAX_WEBSITE_LENGTH} characters.`,
    };
  }
  if (list.length >= MAX_STAGED_WEBSITES) {
    return {
      ok: false,
      list,
      error: `Add up to ${MAX_STAGED_WEBSITES} websites at a time, then continue.`,
    };
  }
  return { ok: true, list: [...list, url], url };
}

/** Adds many (for example discovered hostnames), reporting what did not fit. */
export function stageMany(list, inputs) {
  let next = list;
  let added = 0;
  let duplicates = 0;
  let overLimit = 0;
  for (const input of inputs) {
    const r = stageWebsite(next, input);
    if (r.ok) {
      next = r.list;
      added += 1;
    } else if (r.duplicate) {
      duplicates += 1;
    } else if (next.length >= MAX_STAGED_WEBSITES) {
      overLimit += 1;
    }
  }
  return { list: next, added, duplicates, overLimit };
}

const HOST = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/;

export function normalizeRootDomain(input) {
  const raw = String(input || '')
    .trim()
    .toLowerCase()
    .replace(/^[a-z][a-z0-9+.-]*:\/\//, '')
    .replace(/[/?#].*$/, '')
    .replace(/^www\./, '')
    .replace(/\.$/, '');
  return HOST.test(raw) ? raw : null;
}

/**
 * Hostnames from a discovery response: those inside the root domain, without
 * wildcards, lowercased, unique and sorted.
 */
export function discoveredHostnames(items, rootDomain) {
  const root = normalizeRootDomain(rootDomain);
  if (!root) return [];
  const found = new Set();
  for (const item of Array.isArray(items) ? items : []) {
    const record = item && typeof item === 'object' ? item : { name: item };
    const raw = [
      ...(Array.isArray(record.domains) ? record.domains : []),
      record.domain,
      record.hostname,
      record.name,
      record.commonName,
    ];
    for (const value of raw) {
      const host = String(value || '')
        .trim()
        .toLowerCase()
        .replace(/\.$/, '');
      if (!host || host.includes('*') || !HOST.test(host)) continue;
      if (host === root || host.endsWith(`.${root}`)) found.add(host);
    }
  }
  return Array.from(found).sort();
}

export const hostToUrl = host => `https://${host}`;

/** Found websites shown per page, matching the Endpoint & SSL window. */
export const DISCOVERY_PAGE_SIZE = 50;

/** Case-insensitive "contains" filter over found hostnames. */
export function filterHostnames(hosts, query) {
  const q = String(query || '')
    .trim()
    .toLowerCase();
  const list = Array.isArray(hosts) ? hosts : [];
  return q ? list.filter(h => h.includes(q)) : list;
}

/** One page of a list, with the page clamped into range. */
export function paginate(items, page, size = DISCOVERY_PAGE_SIZE) {
  const list = Array.isArray(items) ? items : [];
  const pages = Math.max(1, Math.ceil(list.length / size));
  const current = Math.min(Math.max(0, Number(page) || 0), pages - 1);
  const start = current * size;
  return {
    items: list.slice(start, start + size),
    page: current,
    pages,
    from: list.length ? start + 1 : 0,
    to: Math.min(start + size, list.length),
    total: list.length,
  };
}

/**
 * Hosts a "Select all" may pick: not already monitored or listed, and only as
 * many as still fit in the batch. Works on the whole filtered list, not just
 * the visible page.
 */
export function selectableHosts(hosts, isTaken, room) {
  return (Array.isArray(hosts) ? hosts : [])
    .filter(h => !isTaken(h))
    .slice(0, Math.max(0, room));
}

const wait = s =>
  Number.isFinite(s) && s > 0 ? ` in about ${Math.ceil(s)}s` : '';

/**
 * Plain wording for a failed lookup. The API's own text can name tools or
 * deployment details, so the panel words each known code itself.
 */
export function discoveryErrorMessage(error) {
  const code = error?.code;
  const status = error?.status;
  if (code === 'ERR_CANCELED') return 'Search cancelled.';
  if (code === 'DOMAIN_CHECKER_TOOL_MISSING') {
    return 'Website discovery is not available on this server. Add websites by address instead.';
  }
  if (code === 'DOMAIN_CHECKER_BUSY') {
    return `A search for this workspace is already running. Try again${wait(error?.retryAfterSeconds) || ' in a minute'}.`;
  }
  if (code === 'DOMAIN_CHECKER_TIMEOUT') {
    return 'The search took too long and was stopped. Try again, or add websites by address.';
  }
  if (code === 'DOMAIN_CHECKER_RATE_LIMITED' || status === 429) {
    return `Too many searches. Try again${wait(error?.retryAfterSeconds) || ' in a minute'}.`;
  }
  if (code === 'INVALID_DOMAIN') return 'Enter a domain such as example.com.';
  if (code === 'DOMAIN_CHECKER_FAILED') {
    return 'The search could not finish. Try again later, or add websites by address.';
  }
  return error?.message || 'The lookup failed. Try again in a moment.';
}

/** Short notes about a result that may be incomplete, in non-technical words. */
export function discoveryNotices({ partial, truncated, cap, failedCodes }) {
  const notes = [];
  if (truncated) {
    notes.push(
      cap
        ? `The list was cut at ${cap} websites, so some are not shown.`
        : 'The list was cut at the maximum, so some are not shown.'
    );
  }
  if (partial && !truncated) {
    const codes = Array.isArray(failedCodes) ? failedCodes : [];
    const outOfTime = codes.some(c =>
      ['DOMAIN_CHECKER_TOOL_TIMEOUT', 'DOMAIN_CHECKER_ABORTED'].includes(c)
    );
    notes.push(
      outOfTime
        ? 'The search ran out of time before every source answered, so there may be more.'
        : 'Some sources did not answer, so there may be more.'
    );
  }
  return notes;
}
