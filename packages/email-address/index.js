"use strict";

/**
 * Shared product email policy: a single ordinary address, no surrounding
 * display names or extra whitespace. Quoted RFC-exotic forms are rejected.
 */
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function isValidEmail(value) {
  if (typeof value !== "string") return false;
  const trimmed = value.trim();
  if (!trimmed || /\s/.test(trimmed)) return false;
  return EMAIL_RE.test(trimmed);
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
  EMAIL_RE,
  isValidEmail,
  stripHtmlToText,
};
