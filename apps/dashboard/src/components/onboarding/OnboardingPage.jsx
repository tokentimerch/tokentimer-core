import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link as RouterLink } from 'react-router';
import { Badge, Box, Flex, HStack, Text, VStack } from '@chakra-ui/react';
import DashboardShell from '../DashboardShell';
import { useDashboardShellProps } from '../../hooks/useDashboardShellProps';
import SEO from '../SEO.jsx';
import {
  DashboardActionButton,
  DashboardErrorAlert,
  DashboardPanel,
  DashboardState,
} from '../DashboardPrimitives';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import { useWorkspace } from '../../utils/WorkspaceContext.jsx';
import { onboardingAPI } from '../../utils/onboardingApi.js';
import { SessionController } from './sessionController.js';
import { reconcilePending } from './reconcile.js';
import { docUrl } from './docLinks.js';
import StepFrame from './StepFrame.jsx';
import { PLANNER_VERSION, planJourney } from './journeyPlanner.js';
import { GOALS } from './modules.js';
import { clearGoal, skipStep } from './sessionTransitions.js';
import { AssetStep, GoalStep, MonitorStep } from './steps.jsx';
import { RecipientsStep, VerifyStep } from './recipientAndVerifySteps.jsx';
import { FileImportStep, IntegrationStep } from './importSteps.jsx';
import { NotificationsStep, SmtpStep } from './notificationSteps.jsx';
import { ConfigStep, ObjectiveStep } from './certopsSetupSteps.jsx';
import { AgentStep } from './certopsAgentStep.jsx';
import { ExecutionStep } from './certopsExecutionStep.jsx';
import { FirstCertificateStep, VaultStep } from './certopsFinalSteps.jsx';
import { resolveApiBaseUrl } from '../../utils/resolveApiBaseUrl.js';

// Agents reach the API from outside the browser, so a relative API base
// resolves to the page origin.
function resolveApiOrigin() {
  const base = resolveApiBaseUrl();
  if (base) return String(base).replace(/\/+$/, '');
  return window.location.origin;
}

const FLOW = 'mega';

// Follow-ups are suggestions, never incomplete items, and never repeat what
// the user just did.
export function nextSteps(goalId) {
  const thresholds =
    'Adjust alert thresholds and the delivery window in workspace preferences.';
  switch (goalId) {
    case 'monitor_https':
    case 'track_asset':
      return [
        'Import many assets at once from a file or an integration.',
        thresholds,
      ];
    case 'import_file':
    case 'import_integration':
      return [
        'Set up an endpoint monitor for the sites you depend on.',
        'Group assets into sections and assign contact groups in the inventory.',
        thresholds,
      ];
    case 'alerting':
      return [
        'Add or import assets so alerts have something to watch.',
        'Add Slack, Teams or WhatsApp channels in workspace preferences.',
      ];
    case 'certops_observe':
      return [
        'Set up automatic renewal for a certificate the agent found.',
        'Install agents on more servers.',
        thresholds,
      ];
    case 'certops_automate':
      return [
        'Issue your first certificate with the staging CA, then switch to the production CA.',
        'Set up renewal-failure alerts for the contact group.',
      ];
    case 'certops_vault':
      return [
        'Run a verified rollout once your agents declare the distribution capabilities.',
        'Keep this as a candidate feature until it is qualified for production.',
      ];
    default:
      return [thresholds];
  }
}

export const STEP_COMPONENTS = {
  goal: GoalStep,
  monitor: MonitorStep,
  asset: AssetStep,
  file_import: FileImportStep,
  integration: IntegrationStep,
  recipients: RecipientsStep,
  notifications: NotificationsStep,
  smtp: SmtpStep,
  verify: VerifyStep,
  certops_objective: ObjectiveStep,
  certops_config: ConfigStep,
  certops_agent: AgentStep,
  certops_execution: ExecutionStep,
  certops_first: FirstCertificateStep,
  certops_vault: VaultStep,
};

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
      onChange: session =>
        setState(prev =>
          prev.status === 'ready' ? { ...prev, session } : prev
        ),
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

  const refresh = useCallback(async () => {
    if (!workspaceId) return null;
    const summary = await api.getSummary(workspaceId, FLOW);
    setState(prev => (prev.status === 'ready' ? { ...prev, summary } : prev));
    return summary;
  }, [api, workspaceId]);

  useEffect(() => {
    load();
  }, [load]);

  // Close operations that succeeded on the server but were never recorded.
  const reconciledRevision = useRef(null);
  useEffect(() => {
    if (state.status !== 'ready' || !controllerRef.current) return;
    const key = `${state.session.revision}:${state.session.progress?.pending?.id}`;
    if (reconciledRevision.current === key) return;
    reconciledRevision.current = key;
    const patch = reconcilePending({
      session: state.session,
      summary: state.summary,
    });
    if (!patch) return;
    controllerRef.current
      .update(() => patch)
      .then(refresh)
      .catch(() => {});
  }, [state, refresh]);

  return {
    ...state,
    workspaceId,
    controller: controllerRef.current,
    reload: load,
    refresh,
  };
}

const STATUS_BADGE = {
  done: { label: 'Done', colorScheme: 'green' },
  current: { label: 'Now', colorScheme: 'blue' },
  skipped: { label: 'Skipped', colorScheme: 'gray' },
  upcoming: { label: 'Next', colorScheme: 'gray' },
};

function JourneyRail({ steps }) {
  const { muted } = useDashboardTheme();
  return (
    <VStack
      as='ol'
      align='stretch'
      spacing={2}
      aria-label='Setup steps'
      listStyleType='none'
      m={0}
      p={0}
    >
      {steps.map(step => {
        const badge = STATUS_BADGE[step.status] || STATUS_BADGE.upcoming;
        return (
          <HStack
            as='li'
            key={step.id}
            justify='space-between'
            aria-current={step.status === 'current' ? 'step' : undefined}
          >
            <Text
              fontSize='sm'
              fontWeight={step.status === 'current' ? 'bold' : 'normal'}
              color={step.status === 'upcoming' ? muted : 'inherit'}
            >
              {step.title}
            </Text>
            <Badge colorScheme={badge.colorScheme}>{badge.label}</Badge>
          </HStack>
        );
      })}
    </VStack>
  );
}

function DoneCard({ ctx }) {
  const { muted } = useDashboardTheme();
  const smtp = ctx.summary?.alerts?.smtpConfigured;
  const restart = async () => {
    await ctx.controller.update(session => ({
      intent: { ...session.intent, goal: '' },
      progress: { skipped: [], verified: false },
      status: 'in_progress',
    }));
    await ctx.refresh();
  };
  return (
    <StepFrame
      kind='info'
      title='You are set up'
      description={
        (ctx.session.progress?.certops?.infrastructure === 'windows' &&
          GOALS[ctx.session.intent?.goal]?.doneTextWindows) ||
        GOALS[ctx.session.intent?.goal]?.doneText ||
        'Setup is complete.'
      }
      docs={ctx.docs('alerts.thresholds', 'Alert thresholds')}
      actions={
        <>
          <DashboardActionButton variant='outline' onClick={restart}>
            Track something else
          </DashboardActionButton>
          <DashboardActionButton
            as={RouterLink}
            to='/dashboard'
            colorScheme='blue'
          >
            Go to dashboard
          </DashboardActionButton>
        </>
      }
    >
      <VStack align='stretch' spacing={2}>
        <Text fontSize='sm' color={muted}>
          Suggested next steps, all optional:
        </Text>
        {smtp !== true ? (
          <Text fontSize='sm'>
            Email delivery is not confirmed. Ask an administrator to check SMTP
            so alerts can be emailed.
          </Text>
        ) : null}
        {nextSteps(ctx.session.intent?.goal).map(text => (
          <Text key={text} fontSize='sm'>
            {text}
          </Text>
        ))}
      </VStack>
    </StepFrame>
  );
}

export default function OnboardingPage({ session, onLogout, onAccountClick }) {
  const { pageBg, text } = useDashboardTheme();
  const shellProps = useDashboardShellProps({
    session,
    onLogout,
    onAccountClick,
    pageTitle: 'Set up TokenTimer',
  });
  const onboarding = useOnboardingState();

  const docsBaseUrl = onboarding.capabilities?.docsBaseUrl;
  const docs = useCallback(
    (key, label) => {
      const url = docUrl(key, docsBaseUrl);
      return url ? [{ label, url }] : [];
    },
    [docsBaseUrl]
  );

  const plan = useMemo(
    () =>
      onboarding.status === 'ready'
        ? planJourney({
            intent: onboarding.session.intent,
            progress: onboarding.session.progress,
            operationRefs: onboarding.session.operationRefs,
            capabilities: onboarding.capabilities,
            reality: onboarding.summary,
          })
        : null,
    [onboarding]
  );

  const changeGoal = useCallback(async () => {
    await onboarding.controller.update(clearGoal);
    await onboarding.refresh();
  }, [onboarding]);

  const skip = useCallback(
    async stepId => {
      await onboarding.controller.update(s => skipStep(s, stepId));
      await onboarding.refresh();
    },
    [onboarding]
  );

  const ctx = useMemo(
    () =>
      onboarding.status === 'ready'
        ? {
            workspaceId: onboarding.workspaceId,
            controller: onboarding.controller,
            session: onboarding.session,
            summary: onboarding.summary,
            capabilities: onboarding.capabilities,
            plannerVersion: PLANNER_VERSION,
            docs,
            refresh: onboarding.refresh,
            fetchSummary: onboarding.refresh,
            skip,
            // The browser origin is the address agents must be able to reach.
            apiUrl: typeof window !== 'undefined' ? resolveApiOrigin() : '',
            isSystemAdmin:
              onboarding.capabilities?.viewer?.isSystemAdmin === true,
            userEmail: session?.email || '',
            userName: session?.name || session?.displayName || '',
          }
        : null,
    [onboarding, docs, session, skip]
  );

  const Current = plan?.currentStepId
    ? STEP_COMPONENTS[plan.currentStepId]
    : null;

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
              <Flex
                direction={{ base: 'column', lg: 'row' }}
                gap={4}
                align='flex-start'
              >
                <DashboardPanel
                  as='aside'
                  aria-label='Setup progress'
                  w={{ base: 'full', lg: '320px' }}
                  flexShrink={0}
                >
                  <Text fontWeight='bold' fontSize='sm' mb={3}>
                    Your setup
                  </Text>
                  <JourneyRail steps={plan.steps} />
                  {ctx.session.intent?.goal ? (
                    <DashboardActionButton
                      mt={3}
                      size='xs'
                      variant='ghost'
                      onClick={changeGoal}
                    >
                      Change what I am setting up
                    </DashboardActionButton>
                  ) : null}
                  <Text fontSize='xs' mt={4} opacity={0.8}>
                    Progress is saved to your account. Leave any time and
                    continue on any device.
                  </Text>
                </DashboardPanel>
                <Box as='main' flex='1' minW={0} w='full'>
                  {plan.complete ? (
                    <DoneCard ctx={ctx} />
                  ) : Current ? (
                    <Current ctx={ctx} />
                  ) : null}
                </Box>
              </Flex>
            )}
          </Box>
        </DashboardShell>
      </Box>
    </>
  );
}
