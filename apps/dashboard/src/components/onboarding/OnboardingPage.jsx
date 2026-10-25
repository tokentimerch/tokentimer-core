import {
  useCallback,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
} from 'react';
import {
  FiArrowRight,
  FiChevronDown,
  FiChevronUp,
  FiRepeat,
  FiRefreshCw,
} from 'react-icons/fi';
import { Link as RouterLink, useNavigate } from 'react-router';
import {
  Alert,
  AlertDescription,
  AlertIcon,
  Badge,
  Progress,
  Box,
  Flex,
  HStack,
  Text,
  VStack,
} from '@chakra-ui/react';
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
import StepFrame, { INFO_NOTE_PROPS } from './StepFrame.jsx';
import PrimaryButton from './PrimaryButton.jsx';
import NextStepsList from './nextStepsList.jsx';
import { PLANNER_VERSION, planJourney } from './journeyPlanner.js';
import {
  allGoals,
  editionNextSteps,
  editionStepComponents,
} from './editionModules.js';
import { clearGoal, skipStep } from './sessionTransitions.js';
import { scopeCertops } from './certopsScope.js';
import { scopeDistribution } from './distributionModel.js';
import { resolveNavigation } from './stepNavigation.js';
import {
  finishesByItself,
  hasOwnContinue,
  journeyKey,
  observedDoneStep,
} from './heldSteps.js';
import { AssetStep, GoalStep, MonitorStep } from './steps.jsx';
import { RecipientsStep, VerifyStep } from './recipientAndVerifySteps.jsx';
import { FileImportStep, IntegrationStep } from './importSteps.jsx';
import {
  FileImportModalStep,
  IntegrationModalStep,
} from './importModalStep.jsx';
import { GUIDED_IMPORT_STEPS } from './importFlow.js';
import { NotificationsStep, SmtpStep } from './notificationSteps.jsx';
import { ConfigStep, ObjectiveStep } from './certopsSetupSteps.jsx';
import { AgentStep } from './certopsAgentStep.jsx';
import { ExecutionStep } from './certopsExecutionStep.jsx';
import { FirstCertificateStep, VaultStep } from './certopsFinalSteps.jsx';
import AdcsStep from './certopsAdcsStep.jsx';
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
export function nextSteps(goalId, certops, summary = null) {
  const thresholds =
    'Adjust alert thresholds and the delivery window in workspace preferences.';
  // A real order that finished means the staging run is already done.
  const issued =
    certops?.issueJob?.status === 'succeeded' &&
    certops?.issueJob?.mode === 'real';
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
        issued
          ? 'Add a real DNS provider for your own domain and switch to the production CA. The staging certificate is not trusted by browsers.'
          : 'Issue your first certificate with the staging CA, then switch to the production CA.',
        issued
          ? 'Check renewals in the Certificates page: the issued certificate is listed there.'
          : null,
        'Set up renewal-failure alerts for the contact group.',
      ].filter(Boolean);
    case 'certops_adcs':
      return [
        'Attach the profile to your certificate in Certificate Management and watch the first enrollment there.',
        'Your setup is only proven once the first enrollment has completed against your CA.',
      ];
    case 'certops_vault':
      return [
        certops?.distribution?.verified === true
          ? 'Assign more consumers and request a rollout for each, or request a check-only rollout (no changes) to look for drift.'
          : 'Run a verified rollout once your agents declare the distribution capabilities.',
      ];
    default: {
      // An edition goal supplies its own suggestions.
      const fromEdition = editionNextSteps(goalId, summary);
      return fromEdition || [thresholds];
    }
  }
}

/**
 * The components for the two import steps. The guided steps are parked (see
 * importFlow.js); by default the import goals show the regular import dialog.
 */
export function importStepComponents(guided = GUIDED_IMPORT_STEPS) {
  return guided
    ? { file_import: FileImportStep, integration: IntegrationStep }
    : { file_import: FileImportModalStep, integration: IntegrationModalStep };
}

export const STEP_COMPONENTS = {
  goal: GoalStep,
  monitor: MonitorStep,
  asset: AssetStep,
  ...importStepComponents(),
  recipients: RecipientsStep,
  notifications: NotificationsStep,
  smtp: SmtpStep,
  verify: VerifyStep,
  certops_objective: ObjectiveStep,
  certops_config: ConfigStep,
  certops_agent: AgentStep,
  certops_execution: ExecutionStep,
  certops_first: FirstCertificateStep,
  certops_adcs: AdcsStep,
  certops_vault: VaultStep,
};

function journeyInputs(onboarding) {
  return {
    intent: onboarding.session.intent,
    progress: onboarding.session.progress,
    operationRefs: onboarding.session.operationRefs,
    capabilities: onboarding.capabilities,
    reality: onboarding.summary,
  };
}

/**
 * Loads the three sources the wizard reasons about: the persisted session
 * (intent and progress), the capability facts, and the verified summary of
 * what really exists. Completion is never read from the session.
 */
export function useOnboardingState({ api = onboardingAPI } = {}) {
  const { workspaceId } = useWorkspace();
  const [state, setState] = useState({ status: 'loading' });
  const controllerRef = useRef(null);
  const refreshRequestRef = useRef(0);

  const load = useCallback(async () => {
    setState({ status: 'loading' });
    if (!workspaceId) return;
    const controller = new SessionController({
      api,
      workspaceId,
      flow: FLOW,
      onChange: session =>
        setState(prev =>
          controllerRef.current === controller && prev.status === 'ready'
            ? { ...prev, session }
            : prev
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
    const controller = controllerRef.current;
    if (
      !workspaceId ||
      controller?.workspaceId !== workspaceId ||
      controller.api !== api
    ) {
      return null;
    }
    const request = ++refreshRequestRef.current;
    const summary = await api.getSummary(workspaceId, FLOW);
    // A previous workspace, reload or older poll must not replace newer facts.
    setState(prev =>
      controllerRef.current === controller &&
      refreshRequestRef.current === request &&
      prev.status === 'ready'
        ? { ...prev, summary }
        : prev
    );
    return summary;
  }, [api, workspaceId]);

  useEffect(() => {
    load();
    return () => {
      controllerRef.current = null;
    };
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

function JourneyRail({ steps, shownId, onSelect }) {
  const { muted } = useDashboardTheme();
  const finished = steps.filter(
    s => s.status === 'done' || s.status === 'skipped'
  ).length;
  return (
    <VStack align='stretch' spacing={2}>
      <Box data-testid='rail-progress'>
        <Text fontSize='xs' color={muted} _light={{ color: muted }} mb={1}>
          {finished} of {steps.length} steps finished
        </Text>
        <Progress
          value={steps.length ? (finished / steps.length) * 100 : 0}
          size='xs'
          borderRadius='full'
          aria-label='Setup progress'
        />
      </Box>
      <JourneyRailList steps={steps} shownId={shownId} onSelect={onSelect} />
    </VStack>
  );
}

function JourneyRailList({ steps, shownId, onSelect }) {
  const { muted } = useDashboardTheme();
  return (
    <VStack
      as='ol'
      align='stretch'
      spacing={1}
      aria-label='Setup steps'
      listStyleType='none'
      m={0}
      p={0}
    >
      {steps.map(step => {
        const badge = STATUS_BADGE[step.status] || STATUS_BADGE.upcoming;
        const reachable = step.status !== 'upcoming';
        const shown = step.id === shownId;
        const label = (
          <Text
            as='span'
            fontSize='sm'
            textAlign='left'
            fontWeight={shown || step.status === 'current' ? 'bold' : 'normal'}
            color={step.status === 'upcoming' ? muted : 'inherit'}
          >
            {step.title}
          </Text>
        );
        return (
          <HStack
            as='li'
            key={step.id}
            justify='space-between'
            aria-current={shown ? 'step' : undefined}
          >
            {reachable ? (
              <Box
                as='button'
                type='button'
                onClick={() => onSelect(step.id)}
                flex='1'
                minW={0}
                py={1}
                textAlign='left'
                borderRadius='sm'
                _hover={{ textDecoration: 'underline' }}
                _focusVisible={{ boxShadow: 'outline' }}
                aria-label={`${step.title}${
                  step.status === 'current' ? ', current step' : ', review'
                }`}
              >
                {label}
              </Box>
            ) : (
              <Box flex='1' minW={0} py={1}>
                {label}
              </Box>
            )}
            <Badge colorScheme={badge.colorScheme}>{badge.label}</Badge>
          </HStack>
        );
      })}
    </VStack>
  );
}

/**
 * Below the lg breakpoint the full list would push the active step far down
 * the page, so it folds into one summary line that opens on demand. From lg
 * up the list is always shown, as before.
 */
/**
 * The summary line of the narrow-screen steps list. A finished journey has
 * no step on screen (the closing card), so it reads as the last step, which
 * matches the "N of N steps finished" counter in the rail.
 */
export function stepSummaryLabel(steps, shownId) {
  if (!steps.length) return '';
  const found = shownId ? steps.findIndex(s => s.id === shownId) : -1;
  const index = shownId ? Math.max(found, 0) : steps.length - 1;
  return `Step ${index + 1} of ${steps.length}: ${steps[index]?.title || ''}`;
}

export function CollapsibleSteps({ steps, shownId, children }) {
  const [open, setOpen] = useState(false);
  const listId = useId();
  return (
    <>
      <Box display={{ base: 'block', lg: 'none' }}>
        <DashboardActionButton
          variant='outline'
          w='full'
          h='auto'
          py={2}
          justifyContent='space-between'
          whiteSpace='normal'
          textAlign='left'
          rightIcon={open ? <FiChevronUp /> : <FiChevronDown />}
          aria-expanded={open}
          aria-controls={listId}
          onClick={() => setOpen(value => !value)}
        >
          {stepSummaryLabel(steps, shownId)}
        </DashboardActionButton>
      </Box>
      <Box
        id={listId}
        mt={{ base: 3, lg: 0 }}
        display={{ base: open ? 'block' : 'none', lg: 'block' }}
      >
        {children(() => setOpen(false))}
      </Box>
    </>
  );
}

// Shown under a step that finished by itself, so the person reads the result
// and moves on when ready.
function StepContinueBar({ onContinue }) {
  const { muted } = useDashboardTheme();
  return (
    <HStack
      justify='flex-end'
      flexWrap='wrap'
      spacing={3}
      mt={3}
      data-testid='step-continue'
    >
      <Text fontSize='sm' color={muted} role='status'>
        This step is finished.
      </Text>
      <PrimaryButton rightIcon={<FiArrowRight />} onClick={onContinue}>
        Continue
      </PrimaryButton>
    </HStack>
  );
}

export function DoneCard({ ctx, guidedImportSteps = GUIDED_IMPORT_STEPS }) {
  const smtp = ctx.summary?.alerts?.smtpConfigured;
  const goal = allGoals()[ctx.session.intent?.goal];
  const modalImport = !guidedImportSteps && Boolean(goal?.doneTextModal);
  const windows =
    scopeCertops(ctx.session.progress?.certops, goal?.certopsObjective)
      .infrastructure === 'windows';
  // A body that hedges must not sit under a title that says all is well.
  const saved = scopeCertops(
    ctx.session.progress?.certops,
    goal?.certopsObjective
  );
  const distributionId = saved.chosenDistributionId || saved.groupId;
  const vaultVerified =
    goal?.certopsObjective === 'vault' &&
    Boolean(distributionId) &&
    scopeDistribution(
      ctx.summary?.certops?.distribution,
      distributionId
    )?.items?.some(
      item => item.id === distributionId && item.verified === true
    );
  const unverified = goal?.doneUnverified === true && !vaultVerified;
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
      title={unverified ? 'Setup finished, not verified yet' : 'You are set up'}
      description={
        (vaultVerified &&
          'Your certificate was published to Vault and its distribution has current verification evidence. Review each consumer in the certificate details, and verify the live service independently.') ||
        (windows && goal?.doneTextWindows) ||
        (modalImport && goal.doneTextModal) ||
        goal?.doneText ||
        'Setup is complete.'
      }
      docs={ctx.docs('alerts.thresholds', 'Alert thresholds')}
      actions={
        <>
          <DashboardActionButton variant='outline' onClick={restart}>
            Track something else
          </DashboardActionButton>
          {modalImport ? (
            <DashboardActionButton
              as={RouterLink}
              to='/alert-preferences'
              variant='outline'
            >
              Alert Preferences
            </DashboardActionButton>
          ) : null}
          <PrimaryButton as={RouterLink} to='/dashboard'>
            {modalImport ? 'Open the asset inventory' : 'Go to dashboard'}
          </PrimaryButton>
        </>
      }
    >
      <NextStepsList
        docs={ctx.docs}
        items={[
          smtp !== true
            ? 'Email delivery is not confirmed. Ask an administrator to check SMTP so alerts can be emailed.'
            : null,
          ...nextSteps(
            ctx.session.intent?.goal,
            ctx.summary?.certops,
            ctx.summary
          ),
        ]}
      />
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
  const navigate = useNavigate();

  const docsBaseUrl = onboarding.capabilities?.docsBaseUrl;
  const docs = useCallback(
    (key, label) => {
      const url = docUrl(key, docsBaseUrl);
      return url ? [{ label, url }] : [];
    },
    [docsBaseUrl]
  );

  // A step that finishes while the person is looking at it (a job succeeds,
  // an agent checks in) stays open until they choose to continue.
  const [heldStepId, setHeldStepId] = useState(null);
  const shownRef = useRef(null);
  // The step a Continue click just released: it must not be held again when
  // that same click is what finished it.
  const releasedRef = useRef(null);
  const releaseStep = useCallback(() => {
    releasedRef.current = shownRef.current;
    shownRef.current = null;
    setHeldStepId(null);
  }, []);

  const ready = onboarding.status === 'ready';
  const key = ready
    ? journeyKey(onboarding.session.intent, onboarding.session.progress)
    : '';
  const basePlan = useMemo(
    () => (ready ? planJourney(journeyInputs(onboarding)) : null),
    [ready, onboarding]
  );
  const observedCandidate = heldStepId
    ? null
    : observedDoneStep(shownRef.current, {
        key,
        plan: basePlan,
        session: onboarding.session,
      });
  const observedId =
    observedCandidate && releasedRef.current?.id === observedCandidate
      ? null
      : observedCandidate;
  const activeHeldId = heldStepId || observedId;
  const plan = useMemo(
    () =>
      ready && activeHeldId
        ? planJourney({
            ...journeyInputs(onboarding),
            heldStepId: activeHeldId,
          })
        : basePlan,
    [ready, onboarding, basePlan, activeHeldId]
  );
  useEffect(() => {
    if (observedId) setHeldStepId(observedId);
  }, [observedId]);

  const chosenGoal = onboarding.session?.intent?.goal || null;
  // A new goal or platform starts without any hold.
  useEffect(() => {
    shownRef.current = null;
    setHeldStepId(null);
  }, [key]);
  // A hold only makes sense while its step is done.
  useEffect(() => {
    if (
      heldStepId &&
      plan &&
      plan.steps.find(s => s.id === heldStepId)?.status !== 'done'
    ) {
      setHeldStepId(null);
    }
  }, [heldStepId, plan]);

  const changeGoal = useCallback(async () => {
    await onboarding.controller.update(clearGoal);
    await onboarding.refresh();
  }, [onboarding]);

  const skip = useCallback(
    async stepId => {
      setHeldStepId(null);
      await onboarding.controller.update(s => skipStep(s, stepId));
      await onboarding.refresh();
    },
    [onboarding]
  );

  // A finished step can be reopened. It is only a view: the planner keeps
  // deciding what is done and what comes next from server state.
  const [viewStepId, setViewStepId] = useState(null);
  const goToStep = useCallback(id => setViewStepId(id), []);

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
            release: releaseStep,
            // Opens a step that is already reached, as a view.
            goToStep,
            // Steps call this when they finish something that should leave a review.
            onDone: () => setViewStepId(null),
            // Leaves the guide without touching progress.
            leaveGuide: () => navigate('/certops'),
            // The browser origin is the address agents must be able to reach.
            apiUrl: typeof window !== 'undefined' ? resolveApiOrigin() : '',
            isSystemAdmin:
              onboarding.capabilities?.viewer?.isSystemAdmin === true,
            userEmail: session?.email || '',
            userName: session?.name || session?.displayName || '',
          }
        : null,
    [onboarding, docs, session, skip, navigate, releaseStep, goToStep]
  );

  const nav = useMemo(
    () => resolveNavigation(plan, viewStepId),
    [plan, viewStepId]
  );
  const titleOf = useCallback(
    id => plan?.steps.find(s => s.id === id)?.title || id,
    [plan]
  );
  const returnToCurrent = useCallback(() => setViewStepId(null), []);
  // What was on screen at the last commit, to notice a step turning done.
  useEffect(() => {
    shownRef.current =
      plan && !viewStepId ? { id: plan.currentStepId, key } : null;
    // The release only matters until the guide has moved off that step.
    if (releasedRef.current && plan?.currentStepId !== releasedRef.current.id) {
      releasedRef.current = null;
    }
  });
  // Leaving a step by doing something always returns to the live step.
  const stepKey = plan?.currentStepId;
  useEffect(() => {
    setViewStepId(null);
  }, [stepKey, chosenGoal]);

  const Current = nav.shownId
    ? STEP_COMPONENTS[nav.shownId] || editionStepComponents()[nav.shownId]
    : null;

  // A finished step that finished by itself waits for the person to move on.
  const shownStep = plan?.steps.find(s => s.id === nav.shownId);
  const waitingDone =
    shownStep?.status === 'done' &&
    finishesByItself(shownStep.id, {
      goal: chosenGoal,
      progress: onboarding.session?.progress,
    });
  const showContinue =
    waitingDone &&
    (nav.viewing
      ? true
      : activeHeldId === shownStep.id && !hasOwnContinue(shownStep.id));
  const continueFromStep = () => {
    if (!nav.viewing) releaseStep();
    else if (nav.nextId) goToStep(nav.nextId);
    else returnToCurrent();
  };

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
                    leftIcon={<FiRefreshCw />}
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
                  display={{
                    base: plan.steps.length > 1 ? 'block' : 'none',
                    lg: 'block',
                  }}
                  flexShrink={0}
                >
                  <Text
                    fontWeight='bold'
                    fontSize='sm'
                    mb={3}
                    display={{ base: 'none', lg: 'block' }}
                  >
                    Your setup
                  </Text>
                  <CollapsibleSteps steps={plan.steps} shownId={nav.shownId}>
                    {close => (
                      <>
                        <JourneyRail
                          steps={plan.steps}
                          shownId={nav.shownId}
                          onSelect={id => {
                            close();
                            if (id === plan.currentStepId) returnToCurrent();
                            else goToStep(id);
                          }}
                        />
                        {ctx.session.intent?.goal ? (
                          <DashboardActionButton
                            mt={4}
                            w='full'
                            colorScheme='blue'
                            variant='outline'
                            leftIcon={<FiRepeat />}
                            onClick={changeGoal}
                          >
                            Change what I am setting up
                          </DashboardActionButton>
                        ) : null}
                        <Alert {...INFO_NOTE_PROPS} mt={4}>
                          <AlertIcon />
                          <AlertDescription fontSize='xs' lineHeight='1.45'>
                            Progress is saved to your account. Leave any time
                            and continue on any device.
                          </AlertDescription>
                        </Alert>
                      </>
                    )}
                  </CollapsibleSteps>
                </DashboardPanel>
                <Box as='main' flex='1' minW={0} w='full'>
                  {plan.complete && !nav.viewing ? (
                    <DoneCard ctx={ctx} />
                  ) : Current ? (
                    <>
                      <Current
                        ctx={ctx}
                        reviewing={nav.viewing}
                        returnTo={
                          nav.viewing === 'goal' && nav.returnId
                            ? {
                                title: titleOf(nav.returnId),
                                go: returnToCurrent,
                              }
                            : null
                        }
                      />
                      {showContinue ? (
                        <StepContinueBar onContinue={continueFromStep} />
                      ) : null}
                    </>
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
