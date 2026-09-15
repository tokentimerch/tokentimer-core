const SENSITIVE_KEY =
  /password|secret|token|authorization|cookie|credential|api[-_]?key|access[-_]?key|private[-_]?key/i;

export function sanitizeLogValue(value, depth = 0) {
  if (value == null || typeof value !== 'object' || depth > 6) return value;
  if (Array.isArray(value)) {
    return value.map(item => sanitizeLogValue(item, depth + 1));
  }
  const out = {};
  for (const [key, nested] of Object.entries(value)) {
    if (SENSITIVE_KEY.test(key)) {
      out[key] = '[REDACTED]';
    } else if (nested && typeof nested === 'object') {
      out[key] = sanitizeLogValue(nested, depth + 1);
    } else {
      out[key] = nested;
    }
  }
  return out;
}
