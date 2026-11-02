import { describe, it, expect } from 'vitest';
import { onboardingPath } from '../../src/utils/onboardingPath.js';
import { quickstartPath } from '../../src/components/onboarding/certopsQuickstartRules.js';

describe('onboardingPath', () => {
  it('keeps a bare guide URL when no workspace is selected', () => {
    expect(onboardingPath()).toBe('/onboarding');
    expect(onboardingPath({})).toBe('/onboarding');
  });

  it('carries the active workspace into the guide', () => {
    expect(onboardingPath({ workspaceId: 'ws-sim' })).toBe(
      '/onboarding?workspace=ws-sim'
    );
  });

  it('can open a guide area without dropping the workspace', () => {
    expect(onboardingPath({ workspaceId: 'ws-sim', area: 'certops' })).toBe(
      '/onboarding?workspace=ws-sim&area=certops'
    );
  });
});

describe('quickstartPath', () => {
  it('keeps the CertOps area and the active workspace together', () => {
    expect(quickstartPath('ws-sim')).toBe(
      '/onboarding?area=certops&workspace=ws-sim'
    );
  });
});
