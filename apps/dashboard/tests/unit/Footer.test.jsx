import { describe, it, expect } from 'vitest';
import { isDashboardShellPath } from '../../src/components/Footer.jsx';

describe('isDashboardShellPath', () => {
  it('matches known dashboard-shell pages exactly', () => {
    expect(isDashboardShellPath('/dashboard')).toBe(true);
    expect(isDashboardShellPath('/control-center')).toBe(true);
  });

  it('matches the CertOps section and every nested/dynamic child route', () => {
    expect(isDashboardShellPath('/certops')).toBe(true);
    expect(isDashboardShellPath('/certops/jobs')).toBe(true);
    expect(isDashboardShellPath('/certops/certificates')).toBe(true);
    expect(isDashboardShellPath('/certops/certificates/cert-123')).toBe(true);
    expect(isDashboardShellPath('/certops/renewals')).toBe(true);
    expect(isDashboardShellPath('/certops/agents')).toBe(true);
    expect(isDashboardShellPath('/certops/settings')).toBe(true);
  });

  it('does not match a path that merely starts with the same characters', () => {
    expect(isDashboardShellPath('/certops-other')).toBe(false);
  });

  it('does not match unrelated or unknown paths', () => {
    expect(isDashboardShellPath('/login')).toBe(false);
    expect(isDashboardShellPath('/')).toBe(false);
    expect(isDashboardShellPath('/some-404-route')).toBe(false);
  });
});
