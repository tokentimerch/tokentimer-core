import {
  getEditionModules,
  registerEditionModule,
} from '../onboarding/editionModules.js';
import SsoProviderStep from './SsoProviderStep.jsx';
import SsoMappingStep from './SsoMappingStep.jsx';
import {
  SSO_CAPABILITY,
  SSO_EDITION_ID,
  SSO_GOAL_ID,
  SSO_STEP_MAPPING,
  SSO_STEP_PROVIDER,
  isSsoStepSatisfied,
  ssoNextSteps,
} from './ssoSetupRules.js';

/**
 * The identity module of the setup guide: one goal that sets up single
 * sign-on. It is listed only for system administrators on a deployment whose
 * API reports the `sso.setup` capability.
 */
export const ssoEditionModule = {
  id: SSO_EDITION_ID,
  areas: [{ id: 'identity', label: 'Identity' }],
  steps: {
    // The step turns done by itself once the enabled provider can sign users
    // in, so it stays on screen until the person presses Continue. The mapping
    // step ends with the person's own action (add a mapping or skip), so it
    // does not hold.
    [SSO_STEP_PROVIDER]: {
      title: 'Connect your identity provider',
      kind: 'ui',
      holdWhenDone: true,
    },
    [SSO_STEP_MAPPING]: { title: 'Map groups to roles', kind: 'ui' },
  },
  goals: {
    [SSO_GOAL_ID]: {
      label: 'Set up single sign-on for my team',
      description:
        'Connect your identity provider so your team signs in with SSO, then map its groups to roles.',
      time: 'About 10 min',
      steps: [SSO_STEP_PROVIDER, SSO_STEP_MAPPING],
      area: 'identity',
      requires: [{ capability: SSO_CAPABILITY, scope: 'system_admin' }],
      doneText:
        'Single sign-on is enabled. Check the role mappings before inviting your team.',
    },
  },
  components: {
    [SSO_STEP_PROVIDER]: SsoProviderStep,
    [SSO_STEP_MAPPING]: SsoMappingStep,
  },
  isStepSatisfied: isSsoStepSatisfied,
  nextSteps: ssoNextSteps,
};

/** Registers once; a second call (hot reload, tests) does nothing. */
export function registerSsoEdition() {
  if (getEditionModules().some(m => m.id === SSO_EDITION_ID)) return false;
  registerEditionModule(ssoEditionModule);
  return true;
}
