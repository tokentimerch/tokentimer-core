// Keep in sync with packages/email-address (API and worker).
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function isValidEmail(value) {
  if (typeof value !== 'string') return false;
  const trimmed = value.trim();
  if (!trimmed || /\s/.test(trimmed)) return false;
  return EMAIL_RE.test(trimmed);
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
