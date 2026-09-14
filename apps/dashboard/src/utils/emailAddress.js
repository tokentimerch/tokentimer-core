// Keep in sync with packages/email-address (API and worker).
const MAX_EMAIL_LENGTH = 254;

function isAsciiEdgeSpace(code) {
  return code === 9 || code === 10 || code === 13 || code === 32;
}

function trimAsciiEdges(value) {
  let start = 0;
  let end = value.length;
  while (start < end && isAsciiEdgeSpace(value.charCodeAt(start))) start += 1;
  while (end > start && isAsciiEdgeSpace(value.charCodeAt(end - 1))) end -= 1;
  return value.slice(start, end);
}

function isDisallowedEmailChar(char) {
  const code = char.charCodeAt(0);
  if (code <= 32 || code === 127 || code > 127) return true;
  return '"\\(),:;<>[]'.includes(char);
}

export function isValidEmail(value) {
  if (typeof value !== 'string') return false;
  const trimmed = trimAsciiEdges(value);
  if (!trimmed || trimmed.length > MAX_EMAIL_LENGTH) return false;

  let at = -1;
  for (let i = 0; i < trimmed.length; i++) {
    const char = trimmed[i];
    if (isDisallowedEmailChar(char)) return false;
    if (char === '@') {
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

export function stripHtmlToText(html) {
  const input = String(html || '');
  let out = '';
  for (let i = 0; i < input.length; i++) {
    if (input[i] !== '<') {
      out += input[i];
      continue;
    }
    const gt = input.indexOf('>', i + 1);
    if (gt === -1) {
      out += input.slice(i);
      break;
    }
    i = gt;
  }
  return out;
}
