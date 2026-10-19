import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link as RouterLink } from 'react-router';
import { Box, Text, VStack } from '@chakra-ui/react';
import DashboardShell from '../DashboardShell';
import { useDashboardShellProps } from '../../hooks/useDashboardShellProps';
import SEO from '../SEO.jsx';
import {
  DashboardActionButton,
  DashboardErrorAlert,
  DashboardState,
} from '../DashboardPrimitives';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import { useWorkspace } from '../../utils/WorkspaceContext.jsx';
import { onboardingAPI } from '../../utils/onboardingApi.js';
import { SessionController } from './sessionController.js';
import { docUrl } from './docLinks.js';
import StepFrame from './StepFrame.jsx';

const FLOW = 'mega';

/**
 * Loads the three sources the wizard reasons about: the persisted session
 * (intent and progress), the capability facts, and the verified summary of
 * what really exists. Completion is never read from the session.
 */
export function useOnboardingState({ api = onboardingAPI } = {}) {
  const { workspaceId } = useWorkspace();
  const [state, setState] = useState({ status: 'loading' });
  const controllerRef = useRef(null);

  const load = useCallback(async () => {
    if (!workspaceId) return;
    setState({ status: 'loading' });
    const controller = new SessionController({
      api,
      workspaceId,
      flow: FLOW,
    });
    controllerRef.current = controller;
    // Capabilities and summary are advisory; a failure there must not block
    // resuming. Only the session itself is required.
    const [session, capabilities, summary] = await Promise.allSettled([
      controller.load(),
      api.getCapabilities(workspaceId),
      api.getSummary(workspaceId, FLOW),
    ]);
    if (controllerRef.current !== controller) return;
    if (session.status === 'rejected') {
      setState({ status: 'error', error: session.reason?.message });
      return;
    }
    setState({
      status: 'ready',
      session: session.value,
      capabilities:
        capabilities.status === 'fulfilled' ? capabilities.value : null,
      summary: summary.status === 'fulfilled' ? summary.value : null,
    });
  }, [api, workspaceId]);

  useEffect(() => {
    load();
  }, [load]);

  return { ...state, controller: controllerRef.current, reload: load };
}

export default function OnboardingPage({ session, onLogout, onAccountClick }) {
  const { pageBg, text, muted } = useDashboardTheme();
  const shellProps = useDashboardShellProps({
    session,
    onLogout,
    onAccountClick,
    pageTitle: 'Set up TokenTimer',
  });
  const onboarding = useOnboardingState();

  const docsBaseUrl = onboarding.capabilities?.docsBaseUrl;
  const docs = useMemo(
    () =>
      [
        { key: 'quickstart.firstAsset', label: 'First asset guide' },
        { key: 'alerts.contactGroups', label: 'Contact groups' },
      ]
        .map(link => ({
          label: link.label,
          url: docUrl(link.key, docsBaseUrl),
        }))
        .filter(link => link.url),
    [docsBaseUrl]
  );

  return (
    <>
      <SEO title='Set up TokenTimer' description='Guided setup' noindex />
      <Box color={text} minH='100vh' bg={pageBg}>
        <DashboardShell {...shellProps}>
          <Box px={{ base: 4, lg: 4, '2xl': 5 }} py={{ base: 5, lg: 3 }}>
            {onboarding.status === 'loading' ? (
              <DashboardState type='loading' title='Loading your setup...' />
            ) : onboarding.status === 'error' ? (
              <VStack align='stretch' spacing={3}>
                <DashboardErrorAlert>
                  {onboarding.error || 'Could not load your setup progress.'}
                </DashboardErrorAlert>
                <Box>
                  <DashboardActionButton
                    variant='outline'
                    onClick={onboarding.reload}
                  >
                    Try again
                  </DashboardActionButton>
                </Box>
              </VStack>
            ) : (
              <StepFrame
                kind='info'
                title='Welcome to guided setup'
                description='Your progress is saved to your account, so you can leave and continue later on any device.'
                docs={docs}
                actions={
                  <DashboardActionButton as={RouterLink} to='/dashboard'>
                    Go to dashboard
                  </DashboardActionButton>
                }
              >
                <Text fontSize='sm' color={muted}>
                  {onboarding.summary
                    ? `This workspace has ${onboarding.summary.assets.total} asset(s) and ${onboarding.summary.monitors.total} endpoint monitor(s).`
                    : 'The workspace summary is not available right now.'}
                </Text>
              </StepFrame>
            )}
          </Box>
        </DashboardShell>
      </Box>
    </>
  );
}
