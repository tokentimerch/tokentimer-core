"use strict";

const MAX_EMAIL_LENGTH = 254;

/**
 * Shared product email policy: a single ordinary address, no surrounding
 * display names or extra whitespace. Quoted RFC-exotic forms are rejected.
 * Linear scan so this cannot backtrack the way a `[^\s@]+` regex would.
 */
function isValidEmail(value) {
  if (typeof value !== "string") return false;
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > MAX_EMAIL_LENGTH) return false;

  let at = -1;
  for (let i = 0; i < trimmed.length; i++) {
    const code = trimmed.charCodeAt(i);
    if (code <= 32 || code === 127) return false;
    if (code === 64) {
      if (at !== -1) return false;
      at = i;
    }
  }
  if (at <= 0 || at === trimmed.length - 1) return false;

  const domain = trimmed.slice(at + 1);
  let lastDot = -1;
  for (let i = 0; i < domain.length; i++) {
    if (domain.charCodeAt(i) === 46) lastDot = i;
  }
  return lastDot > 0 && lastDot < domain.length - 1;
}

/**
 * Linear HTML-to-text: drop each `<...>` span in one pass. Unclosed `<`
 * is kept so user text such as "price < 100" survives.
 */
function stripHtmlToText(html) {
  const input = String(html || "");
  let out = "";
  for (let i = 0; i < input.length; i++) {
    if (input[i] !== "<") {
      out += input[i];
      continue;
    }
    const gt = input.indexOf(">", i + 1);
    if (gt === -1) {
      out += input.slice(i);
      break;
    }
    i = gt;
  }
  return out;
}

module.exports = {
  isValidEmail,
  stripHtmlToText,
};
