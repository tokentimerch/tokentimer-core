import { describe, expect, it } from 'vitest';
import {
  TLS_MODES,
  buildSmtpPayload,
  defaultTlsMode,
  explainSmtpTestError,
  isMasked,
  lockedFields,
  smtpIsReady,
  suggestTls,
  tlsModeFromSaved,
} from '../../src/components/onboarding/smtpForm.js';

const form = {
  host: 'smtp.example.com',
  port: '587',
  user: 'mailer',
  pass: 's3cret',
  from_email: 'alerts@example.com',
};

describe('buildSmtpPayload', () => {
  it('sends only what the user entered', () => {
    const { payload, problems } = buildSmtpPayload(form, {});
    expect(problems).toEqual([]);
    expect(payload).toEqual(form);
  });

  it('never echoes a masked password back', () => {
    const { payload } = buildSmtpPayload(
      { ...form, pass: '****cret' },
      { pass: { value: '****cret' }, user: { value: 'mailer' } }
    );
    expect(payload.pass).toBeUndefined();
    expect(isMasked('****cret')).toBe(true);
    expect(isMasked('real')).toBe(false);
  });

  it('does not try to override environment-locked fields', () => {
    const { payload, ignoredLocked } = buildSmtpPayload(form, {
      host: { value: 'env.example.com', locked: true },
    });
    expect(payload.host).toBeUndefined();
    expect(ignoredLocked).toEqual(['host']);
    expect(
      lockedFields({ host: { locked: true }, port: { locked: false } })
    ).toEqual(['host']);
  });

  it('accepts an already-locked host as satisfying the host requirement', () => {
    const { problems } = buildSmtpPayload(
      { port: '587', from_email: 'a@b.co' },
      { host: { value: 'env.example.com', locked: true } }
    );
    expect(problems).toEqual([]);
  });

  it('requires username and password together', () => {
    const half = buildSmtpPayload({ ...form, pass: '' }, {});
    expect(half.problems.join(' ')).toMatch(/both a username and a password/);
    const none = buildSmtpPayload({ ...form, user: '', pass: '' }, {});
    expect(none.problems).toEqual([]);
  });

  it('validates host, port and sender', () => {
    const bad = buildSmtpPayload(
      { host: '', port: '70000', from_email: 'nope' },
      {}
    );
    expect(bad.problems.join(' ')).toMatch(/host/);
    expect(bad.problems.join(' ')).toMatch(/port/);
    expect(bad.problems.join(' ')).toMatch(/sender/);
  });
});

describe('smtp helpers', () => {
  it('offers STARTTLS, SSL and a no-encryption mode for local relays', () => {
    expect(TLS_MODES.starttls.fields).toEqual({
      secure: false,
      require_tls: true,
    });
    expect(TLS_MODES.ssl.fields).toEqual({ secure: true, require_tls: false });
    expect(TLS_MODES.none.fields).toEqual({
      secure: false,
      require_tls: false,
    });
    expect(defaultTlsMode('465')).toBe('ssl');
    expect(defaultTlsMode('587')).toBe('starttls');
    expect(defaultTlsMode(1025)).toBe('starttls');
  });

  it('restores the saved mode, including a relay saved without encryption', () => {
    expect(tlsModeFromSaved({}, '587')).toBe('starttls');
    expect(tlsModeFromSaved({ secure: { value: 'true' } }, '465')).toBe('ssl');
    expect(
      tlsModeFromSaved(
        { secure: { value: 'false' }, require_tls: { value: 'false' } },
        '1025'
      )
    ).toBe('none');
  });

  it('sends an explicit false so an unencrypted relay can be saved', () => {
    const { payload } = buildSmtpPayload(
      { ...form, ...TLS_MODES.none.fields },
      {}
    );
    expect(payload.secure).toBe(false);
    expect(payload.require_tls).toBe(false);
  });

  it('only suggests TLS settings and never forces them', () => {
    expect(suggestTls(465)).toEqual({ secure: true, require_tls: false });
    expect(suggestTls('587')).toEqual({ secure: false, require_tls: true });
    expect(suggestTls(2525)).toBeNull();
  });

  it('skips the step when email already works', () => {
    expect(smtpIsReady({ configured: true })).toBe(true);
    expect(smtpIsReady({ configured: false })).toBe(false);
    expect(smtpIsReady()).toBe(false);
  });

  it('explains failures with something actionable', () => {
    expect(explainSmtpTestError('SMTP_NOT_CONFIGURED')).toMatch(
      /Save the settings first/
    );
    expect(
      explainSmtpTestError('SMTP_TEST_FAILED', 'Connection refused')
    ).toMatch(/Check the host, port and TLS/);
    expect(explainSmtpTestError('SMTP_AUTH')).toMatch(/username and password/);
    expect(explainSmtpTestError('SMTP_CONNECTION')).toMatch(/host and port/);
    expect(explainSmtpTestError('SMTP_ERROR', 'Failed to send email.')).toMatch(
      /No encryption/
    );
  });
});
