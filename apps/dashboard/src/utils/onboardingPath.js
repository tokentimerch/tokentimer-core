'use strict';

/**
 * Build an /onboarding URL that keeps the active workspace (and optional area).
 * Dropping `workspace` lets WorkspaceContext fall back to the last/first
 * workspace, which is wrong after an explicit banner or selector switch.
 */
export function onboardingPath({ workspaceId, area, goal } = {}) {
  const params = new URLSearchParams();
  if (workspaceId != null && workspaceId !== '') {
    params.set('workspace', String(workspaceId));
  }
  if (area != null && area !== '') {
    params.set('area', String(area));
  }
  if (goal != null && goal !== '') {
    params.set('goal', String(goal));
  }
  const query = params.toString();
  return query ? `/onboarding?${query}` : '/onboarding';
}
