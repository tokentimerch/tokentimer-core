// Builds the SMTP write for the wizard. The system-settings GET masks the
// password and marks environment-supplied fields as locked, so the write must
// never echo a mask back or try to override a locked value.

export const SMTP_FIELDS = [
  'host',
  'port',
  'user',
  'pass',
  'from_email',
  'from_name',
  'secure',
  'require_tls',
];

const MASK = /^\*{4}/;

export function isMasked(value) {
  return typeof value === 'string' && MASK.test(value);
}

/** Port guidance: do not guess encryption from the port, only suggest. */
export function suggestTls(port) {
  const p = Number(port);
  if (p === 465) return { secure: true, require_tls: false };
  if (p === 587 || p === 25) return { secure: false, require_tls: true };
  return null;
}

/**
 * @param {object} form      values the user typed (strings/booleans)
 * @param {object} current   GET smtp section: { field: { value, locked } }
 * @returns {{ payload: object, problems: string[], ignoredLocked: string[] }}
 */
export function buildSmtpPayload(form, current = {}) {
  const payload = {};
  const problems = [];
  const ignoredLocked = [];

  for (const key of SMTP_FIELDS) {
    const setting = current[key];
    if (setting?.locked) {
      if (form[key] !== undefined && form[key] !== '') ignoredLocked.push(key);
      continue;
    }
    const value = form[key];
    if (value === undefined || value === '') continue;
    // A masked secret means "unchanged"; sending it would overwrite the real
    // password with asterisks.
    if (key === 'pass' && isMasked(value)) continue;
    payload[key] = value;
  }

  const effective = key =>
    payload[key] !== undefined ? payload[key] : current[key]?.value;
  const host = effective('host');
  if (!host) problems.push('Enter the SMTP server host.');
  const port = effective('port');
  if (
    port !== undefined &&
    port !== '' &&
    !(Number(port) > 0 && Number(port) < 65536)
  ) {
    problems.push('The port must be between 1 and 65535.');
  }
  const user = effective('user');
  const pass = payload.pass !== undefined ? payload.pass : current.pass?.value;
  if (Boolean(user) !== Boolean(pass)) {
    problems.push(
      'Enter both a username and a password, or leave both empty for a relay without login.'
    );
  }
  const from = effective('from_email');
  if (!from || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(from))) {
    problems.push('Enter a valid sender email address.');
  }
  return { payload, problems, ignoredLocked };
}

/** Whether the deployment already has working email, so the step is skipped. */
export function smtpIsReady(current = {}) {
  return current.configured === true;
}

export function lockedFields(current = {}) {
  return SMTP_FIELDS.filter(k => current[k]?.locked);
}

/** Maps API failures to advice an operator can act on. */
export function explainSmtpTestError(code, message) {
  switch (code) {
    case 'SMTP_NOT_CONFIGURED':
      return 'Save the settings first, then send the test.';
    case 'SMTP_TEST_FAILED':
      return (
        `${message || 'The server refused the message.'} ` +
        'Check the host, port and TLS setting, and that the sender is allowed by your mail server.'
      );
    default:
      return message || 'The test email could not be sent.';
  }
}
