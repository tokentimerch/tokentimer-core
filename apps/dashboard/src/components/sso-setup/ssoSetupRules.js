// Pure rules of the single sign-on setup goal. Nothing here
// touches React or the network, so the planner can call it freely.
//
// The real state arrives in `summary.edition.sso`, built by the API from the
// SSO provider registry and the group mappings. Done is always derived from
// that, never from a click.

export const SSO_EDITION_ID = 'sso';
export const SSO_GOAL_ID = 'sso_setup';
export const SSO_CAPABILITY = 'sso.setup';
export const SSO_STEP_PROVIDER = 'sso_provider';
export const SSO_STEP_MAPPING = 'sso_mapping';

/**
 * The SSO facts of a summary, or null when they are absent, unreadable
 * ("unknown") or not meant for this viewer. Callers must not read null as
 * "nothing is set up".
 */
export function ssoFacts(summary) {
  const sso = summary?.edition?.sso;
  if (!sso || typeof sso !== 'object') return null;
  if (sso.applicable === false) return null;
  if (!sso.providers || !sso.mappings) return null;
  return sso;
}

/** True when at least one provider is enabled and can take sign-ins now. */
export function providerReady(summary) {
  const sso = ssoFacts(summary);
  return Boolean(sso && sso.providers.signInReady > 0);
}

/** True when a mapping exists for an enabled provider that can sign in. */
export function mappingPresent(summary) {
  const sso = ssoFacts(summary);
  return Boolean(
    sso && sso.providers.signInReady > 0 && sso.mappings.forReadyProviders > 0
  );
}

/**
 * Edition rule for `registerEditionModule`: `true`/`false` for the two SSO
 * steps, `undefined` for any other step.
 */
export function isSsoStepSatisfied(stepId, ctx = {}) {
  if (stepId === SSO_STEP_PROVIDER) return providerReady(ctx.reality);
  if (stepId === SSO_STEP_MAPPING) return mappingPresent(ctx.reality);
  return undefined;
}

/** Sentences for the closing card. Plain strings. */
export function ssoNextSteps(goalId, summary) {
  if (goalId !== SSO_GOAL_ID) return undefined;
  const steps = [];
  if (!mappingPresent(summary)) {
    steps.push(
      'Add a group mapping so SSO users receive their roles on first sign-in.'
    );
  }
  steps.push(
    'Verify sign-in and workspace access with a regular user in a private browser window.'
  );
  steps.push('Invite your team to sign in with SSO.');
  steps.push(
    'Keep a local administrator sign-in until you are sure SSO works for everyone.'
  );
  return steps;
}
