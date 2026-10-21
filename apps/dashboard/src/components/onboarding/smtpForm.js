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

// The server requires a STARTTLS upgrade unless told otherwise, so a plain
// relay or a local test server only works when the operator can say so.
export const TLS_MODES = {
  starttls: {
    label: 'STARTTLS (recommended)',
    fields: { secure: false, require_tls: true },
  },
  ssl: {
    label: 'SSL/TLS from the start (usually port 465)',
    fields: { secure: true, require_tls: false },
  },
  none: {
    label: 'No encryption (internal relay or local test server only)',
    fields: { secure: false, require_tls: false },
  },
};

export function defaultTlsMode(port) {
  return Number(port) === 465 ? 'ssl' : 'starttls';
}

const isOff = v => v === false || String(v).toLowerCase() === 'false';
const isOn = v => v === true || String(v).toLowerCase() === 'true';

/** The mode the saved settings describe, for the form to start from. */
export function tlsModeFromSaved(current = {}, port) {
  if (isOn(current.secure?.value)) return 'ssl';
  if (isOff(current.require_tls?.value)) return 'none';
  return defaultTlsMode(port);
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
    case 'SMTP_CONNECTION':
      return 'Could not connect. Check the host and port, and that the TokenTimer server (not your browser) can reach the mail server.';
    case 'SMTP_AUTH':
      return 'The mail server rejected the login. Check the username and password.';
    case 'SMTP_TIMEOUT':
      return 'The mail server did not answer in time. Check the host, the port and any firewall.';
    case 'SMTP_RATE_LIMIT':
    case 'SMTP_TEMPORARY_FAILURE':
      return `${message || 'The mail server is limiting messages.'} Try again in a few minutes.`;
    case 'SMTP_ERROR':
      // The server requires STARTTLS by default, which a plain relay or a
      // local test server cannot offer.
      return (
        `${message || 'The message could not be sent.'} ` +
        'If this server has no encryption, such as a local test server, set Connection security to "No encryption". Otherwise check the host, port, login and sender address.'
      );
    case 'SMTP_TEST_FAILED':
      return (
        `${message || 'The server refused the message.'} ` +
        'Check the host, port and TLS setting, and that the sender is allowed by your mail server.'
      );
    default:
      return message || 'The test email could not be sent.';
  }
}
