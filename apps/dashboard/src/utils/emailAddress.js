// Keep in sync with packages/email-address (API and worker).
const MAX_EMAIL_LENGTH = 254;

export function isValidEmail(value) {
  if (typeof value !== 'string') return false;
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
