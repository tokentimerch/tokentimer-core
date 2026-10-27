import { useCallback, useEffect, useId, useRef, useState } from 'react';
import {
  Box,
  Checkbox,
  FormControl,
  FormLabel,
  Heading,
  HStack,
  Input,
  Progress,
  Select,
  SimpleGrid,
  Stack,
  Text,
  VisuallyHidden,
  VStack,
} from '@chakra-ui/react';
import { DashboardActionButton } from '../DashboardPrimitives';
import { createJob, getJob } from '../certops/certopsJobsApi.js';
import { jobStatusLabel } from '../certops/certopsJobsFormat.js';
import { verificationStages } from '../certops/distributionFormat.js';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import { certopsProgress } from './certopsSetupSteps.jsx';
import { mergeCertops, scopeCertops } from './certopsScope.js';
import {
  agentRestartCommandFor,
  buildDryRunJob,
  buildVaultConfigs,
  buildVaultConsumerAssignment,
} from './certopsConfig.js';
import {
  assignConsumer,
  readDistribution,
  requestRollout,
  retryDeployment,
  resumeRollout,
} from './vaultGuideApi.js';
import { ApprovalPolicyNote, ApprovalWaitPanel } from './approvalPolicy.jsx';
import { CopyBlock } from './blocks.jsx';
import JobActivity from './JobActivity.jsx';
import { isJobFinal } from './jobTimeline.js';
import { DetailsSection, StatusPanel, StatusTag } from './panels.jsx';
import PrimaryButton from './PrimaryButton.jsx';

const label = agent =>
  agent?.name || agent?.hostname || agent?.wireAgentId || 'agent';
const message = error =>
  error?.response?.data?.error ||
  error?.message ||
  'The request could not be completed.';
const identifier = () => globalThis.crypto.randomUUID();

// Hostnames and translated action labels can be wider than the guide's
// nested mobile column. Keep the dashboard button treatment, with room to wrap.
const actionLayout = {
  h: 'auto',
  minH: '36px',
  maxW: '100%',
  py: 2,
  whiteSpace: 'normal',
  overflowWrap: 'anywhere',
  alignSelf: { base: 'stretch', sm: 'flex-start' },
};

function VaultActionButton(props) {
  return <DashboardActionButton {...actionLayout} {...props} />;
}

function deploymentStageLabel(stage) {
  if (!stage) return 'Not requested yet';
  return verificationStages[stage] || jobStatusLabel(stage).replace(/_/g, ' ');
}

// Update against the controller's current session, so simultaneous checks on
// different agents cannot overwrite one another's returned job ids.
async function updateVault(ctx, change) {
  await ctx.controller.update(session => {
    if (session.intent?.goal && session.intent.goal !== 'certops_vault')
      return {};
    return {
      progress: {
        ...session.progress,
        certops: mergeCertops(
          session.progress?.certops,
          'vault',
          change(scopeCertops(session.progress?.certops, 'vault'))
        ),
      },
    };
  });
  await ctx.refresh();
}

function useObservedJob(workspaceId, jobId, refreshIndex = 0) {
  const [state, setState] = useState({ job: null, error: '' });
  useEffect(() => {
    setState({ job: null, error: '' });
    if (!jobId) return undefined;
    let active = true;
    let timer;
    const abort = new AbortController();
    const load = async () => {
      try {
        const result = await getJob(workspaceId, jobId, {
          signal: abort.signal,
        });
        if (active) {
          const job = result.job || result;
          setState({ job, error: '' });
          if (!isJobFinal(job.status)) timer = setTimeout(load, 5000);
        }
      } catch (error) {
        if (active) {
          setState({ job: null, error: message(error) });
          timer = setTimeout(load, 5000);
        }
      }
    };
    load();
    return () => {
      active = false;
      abort.abort();
      clearTimeout(timer);
    };
  }, [workspaceId, jobId, refreshIndex]);
  return state;
}

export function VaultAgentTest({
  ctx,
  agent,
  isIssuer = false,
  onPassed,
  disabled = false,
}) {
  const saved = certopsProgress(ctx);
  const savedId = agent?.id
    ? saved.vaultDryRunJobIds?.[agent.id] ||
      (isIssuer || agent.id === saved.chosenAgentId ? saved.dryRunJobId : '') ||
      ''
    : '';
  const [createdId, setCreatedId] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const jobId = createdId || savedId;
  const observed = useObservedJob(ctx.workspaceId, jobId);
  const sameAgent = Boolean(
    agent?.id && observed.job?.assignedAgentId === agent.id
  );
  const passed =
    observed.job?.status === 'dry_run_complete' &&
    observed.job?.operation === 'noop' &&
    // The public job-detail projection omits mode on existing servers.
    // The attributed noop's terminal status proves the signed dry run.
    (observed.job?.mode == null || observed.job.mode === 'dry_run') &&
    sameAgent;
  const notified = useRef(null);
  useEffect(() => {
    if (notified.current !== passed) {
      notified.current = passed;
      onPassed?.(passed);
    }
  }, [passed, onPassed]);
  const send = async () => {
    if (!agent || busy || disabled) return;
    setBusy(true);
    setError('');
    try {
      const result = await createJob(
        ctx.workspaceId,
        buildDryRunJob({
          assignedAgentId: agent.id,
          idempotencyKey: `wizard-vault-check-${identifier()}`,
        })
      );
      const job = result.job || result;
      setCreatedId(job.id);
      // Vault retries must not invalidate the earlier execution step's check.
      await updateVault(ctx, current => ({
        vaultDryRunJobIds: { ...current.vaultDryRunJobIds, [agent.id]: job.id },
      }));
    } catch (e) {
      setError(message(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <VStack align='stretch' spacing={3}>
      {!passed ? (
        <VaultActionButton
          variant='outline'
          aria-label={
            jobId
              ? `${isJobFinal(observed.job?.status) ? 'Retry test' : 'Checking test'} for ${label(agent)}`
              : `Send a test job to ${label(agent)}`
          }
          onClick={send}
          isLoading={busy}
          isDisabled={
            disabled ||
            !agent ||
            (Boolean(jobId) && !isJobFinal(observed.job?.status))
          }
        >
          {jobId
            ? isJobFinal(observed.job?.status)
              ? 'Retry test'
              : 'Checking test'
            : 'Send a test job'}
        </VaultActionButton>
      ) : null}
      {passed ? (
        <Text fontSize='sm'>
          This agent has passed its signed check. Continue below; no new test is
          needed.
        </Text>
      ) : null}
      {jobId ? (
        <>
          <Text fontSize='sm'>
            {passed
              ? 'Signed dry run completed'
              : observed.job?.status === 'dry_run_complete' && !sameAgent
                ? 'This check belongs to another agent. Send a new test for this selection.'
                : `Test status: ${observed.job?.status ? jobStatusLabel(observed.job.status) : 'Checking'}`}
          </Text>
          <ApprovalWaitPanel job={observed.job} />
          <JobActivity
            workspaceId={ctx.workspaceId}
            jobId={jobId}
            title={`Signed check: ${label(agent)}`}
          />
        </>
      ) : null}
      {error || observed.error ? (
        <StatusPanel status='error'>{error || observed.error}</StatusPanel>
      ) : null}
    </VStack>
  );
}

/** First-time distribution actions, using the same authenticated operations
 * as the management views. Server observations, not local checkboxes, prove
 * publication, assignment revisions and consumer convergence. */
export function VaultRolloutGuide({
  ctx,
  groupId,
  firstAgentId,
  firstBindingId,
  agents,
  config,
  approvalRequired,
}) {
  const { border, muted, dashboard } = useDashboardTheme();
  const sectionId = useId();
  const { refresh: refreshSummary, summary } = ctx;
  const saved = certopsProgress(ctx);
  const scope = `${ctx.workspaceId}/${groupId}`;
  const filesOnly = config.consumerDeliveryMode === 'files';
  const defaultProfile = filesOnly
    ? 'certificate-files'
    : `${config.consumerReloadService || 'nginx'}-public`;
  const [targets, setTargets] = useState(() =>
    saved.vaultConsumers?.length
      ? saved.vaultConsumers
      : firstAgentId
        ? [
            {
              agentId: firstAgentId,
              bindingId: firstBindingId,
              deploymentProfileRef: defaultProfile,
            },
          ]
        : []
  );
  const [pick, setPick] = useState('');
  const [state, setState] = useState({
    versions: [],
    consumers: [],
    loaded: false,
    scope: '',
    error: '',
  });
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const [summaryFailure, setSummaryFailure] = useState(null);
  const summaryReadFailed = Boolean(
    summaryFailure && summaryFailure.summary === summary
  );
  const [versionId, setVersionId] = useState(
    saved.vaultMaterialVersionId || ''
  );
  const [rolloutId, setRolloutId] = useState(saved.vaultRolloutJobId || '');
  const [requestKey, setRequestKey] = useState(
    saved.vaultRolloutRequestKey || ''
  );
  const [parallel, setParallel] = useState(saved.vaultMaxParallel || 1);
  const [refreshIndex, setRefreshIndex] = useState(0);
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  const refresh = useCallback(async () => {
    setRefreshIndex(i => i + 1);
    try {
      await refreshSummary();
      setSummaryFailure(null);
    } catch (e) {
      setSummaryFailure({ summary, error: message(e) });
    }
  }, [refreshSummary, summary]);
  useEffect(() => {
    let active = true;
    const abort = new AbortController();
    let inFlight = false;
    const load = async () => {
      if (inFlight) return;
      inFlight = true;
      try {
        const result = await readDistribution(ctx.workspaceId, groupId, {
          signal: abort.signal,
        });
        if (active) setState({ ...result, scope, loaded: true, error: '' });
      } catch (e) {
        if (active)
          setState({
            versions: [],
            consumers: [],
            loaded: false,
            scope,
            error: message(e),
          });
      } finally {
        inFlight = false;
      }
    };
    load();
    const timer = setInterval(load, 5000);
    return () => {
      active = false;
      abort.abort();
      clearInterval(timer);
    };
  }, [ctx.workspaceId, groupId, scope, refreshIndex]);
  const observedRollout = useObservedJob(
    ctx.workspaceId,
    rolloutId,
    refreshIndex
  );
  const persistTargets = async next => {
    await updateVault(ctx, () => ({
      vaultConsumers: next,
      vaultConsumerAgentId: firstAgentId,
      vaultConsumerDeliveryMode: filesOnly ? 'files' : 'service',
      vaultConsumerReloadService: config.consumerReloadService || 'nginx',
      vaultConsumerDeployPath: config.deployPath,
    }));
    setTargets(next);
  };
  const available = agents.filter(a => !targets.some(t => t.agentId === a.id));
  const add = async () => {
    if (!pick || busy) return;
    setBusy('add');
    setError('');
    try {
      await persistTargets([
        ...targets,
        {
          agentId: pick,
          bindingId: identifier(),
          deploymentProfileRef: defaultProfile,
        },
      ]);
      setPick('');
    } catch (e) {
      setError(message(e));
    } finally {
      setBusy('');
    }
  };
  const statusLoaded = state.loaded && state.scope === scope;
  const statusError = state.scope === scope ? state.error : '';
  const bindingFor = target =>
    statusLoaded &&
    state.consumers.find(
      c =>
        c.binding_id === target.bindingId &&
        c.assigned_agent_id === target.agentId &&
        c.binding_state === 'active' &&
        (c.verification_policy || 'trust') ===
          (filesOnly ? 'installed' : 'trust')
    );
  const assign = async (target, index) => {
    setBusy(target.bindingId);
    setError('');
    try {
      const result = await assignConsumer(
        ctx.workspaceId,
        groupId,
        target.bindingId,
        {
          ...buildVaultConsumerAssignment({
            agentRowId: target.agentId,
            deploymentProfileRef: target.deploymentProfileRef || defaultProfile,
            consumerDeliveryMode: filesOnly ? 'files' : 'service',
          }),
          wave: index,
        }
      );
      if (!alive.current) return;
      const row = result.binding || result;
      if (
        row.id !== target.bindingId ||
        row.assigned_agent_id !== target.agentId ||
        row.deployment_profile_ref !==
          (target.deploymentProfileRef || defaultProfile) ||
        (row.verification_policy || 'trust') !==
          (filesOnly ? 'installed' : 'trust') ||
        !Number.isInteger(row.authorization_revision)
      )
        throw new Error(
          'The server did not return the consumer authorization revision. Refresh before continuing.'
        );
      const observed = { ...row, binding_id: row.id, binding_state: row.state };
      setState(s => ({
        ...s,
        consumers: [
          ...s.consumers.filter(c => c.binding_id !== target.bindingId),
          observed,
        ],
      }));
      await persistTargets(
        targets.map(t =>
          t.bindingId === target.bindingId
            ? { ...t, confirmedRevision: null }
            : t
        )
      );
      // Do not infer completion from the PUT. The returned revision is copied
      // to the host; later convergence is independently read back below.
    } catch (e) {
      if (alive.current) setError(message(e));
    } finally {
      if (alive.current) setBusy('');
    }
  };
  // Rollout and deployment projections can reference the same job. Keep
  // each job's evidence once, while retaining every consumer's own status.
  const deploymentEvidenceOwners = new Map();
  for (const target of targets) {
    const jobId = bindingFor(target)?.latest_deployment?.jobId;
    if (jobId && jobId !== rolloutId && !deploymentEvidenceOwners.has(jobId)) {
      deploymentEvidenceOwners.set(jobId, target.bindingId);
    }
  }
  const published = statusLoaded
    ? state.versions.filter(
        v => v.state === 'published' && Date.parse(v.valid_to) > Date.now()
      )
    : [];
  const selected = published.find(v => v.id === versionId);
  const configured =
    targets.length > 0 &&
    targets.every(t => {
      const b = bindingFor(t);
      return (
        b &&
        agents.some(a => a.id === t.agentId && a.wireAgentId) &&
        t.confirmedRevision === b.authorization_revision
      );
    });
  const bindingComplete = binding =>
    Boolean(
      selected &&
      binding?.converged === true &&
      binding.desired_material_version_id === selected.id &&
      !['failed', 'blocked', 'orphaned_unknown_effect'].includes(
        binding.latest_deployment?.stage
      )
    );
  const complete = target => bindingComplete(bindingFor(target));
  // Rollouts include every active binding in the distribution, including
  // consumers assigned outside this guide and optional consumers.
  const activeBindings = statusLoaded
    ? state.consumers.filter(binding => binding.binding_state === 'active')
    : [];
  const otherBindings = activeBindings.filter(
    binding => !targets.some(target => target.bindingId === binding.binding_id)
  );
  const consumerCount = targets.length + otherBindings.length;
  const confirmedCount =
    targets.filter(complete).length +
    otherBindings.filter(bindingComplete).length;
  const consumersComplete =
    targets.length > 0 &&
    targets.every(complete) &&
    activeBindings.every(bindingComplete);
  const distributionFact = summary?.certops?.distribution?.items?.find(
    item => item.id === groupId
  );
  // Match the wizard's authoritative completion fact as well as the current
  // selected-version evidence. A successful coordinator job is not delivery.
  const allComplete =
    consumersComplete &&
    !summaryReadFailed &&
    Boolean(distributionFact?.completed || distributionFact?.verified);
  const rolloutLocked = Boolean(rolloutId || requestKey);
  // The coordinator job ID is not the rollout ID. Resume only a rollout
  // reported by the server for the currently selected version and bindings.
  const pausedRollouts = [
    ...new Set(
      targets
        .map(t => bindingFor(t))
        .filter(
          b =>
            b?.latest_deployment?.rolloutState === 'paused' &&
            b.latest_deployment.rolloutRequestJobId === rolloutId &&
            b.desired_material_version_id === selected?.id
        )
        .map(b => b.latest_deployment.rolloutId)
        .filter(Boolean)
    ),
  ];
  const pausedRolloutId =
    pausedRollouts.length === 1 ? pausedRollouts[0] : null;
  const needsRetry = targets.some(t =>
    ['failed', 'blocked', 'orphaned_unknown_effect'].includes(
      bindingFor(t)?.latest_deployment?.stage
    )
  );
  const assignedCount = targets.filter(t => bindingFor(t)).length;
  const terminalRollout = [
    'failed',
    'rejected',
    'cancelled',
    'blocked',
  ].includes(observedRollout.job?.status);
  const progress = (() => {
    if (!statusLoaded)
      return {
        status: statusError ? 'error' : 'info',
        title: statusError
          ? 'Distribution status is unavailable'
          : 'Checking distribution status',
        detail: statusError
          ? 'Refresh the status to check the latest agent results. Previous results cannot confirm this step.'
          : 'Reading the selected certificate version and consumer results.',
      };
    if (allComplete)
      return {
        status: 'success',
        title: filesOnly
          ? 'Certificate files installed on all consumers'
          : 'All consumers verified',
        detail: filesOnly
          ? 'The agents checked the installed certificate and key on disk against the selected version. No service was reloaded or checked; this does not prove the certificate is in use.'
          : 'The server reports current convergence on the selected version. Inspect each deployment’s evidence and make an independent TLS connection to the live services.',
      };
    if (consumersComplete)
      return {
        title: 'Confirming distribution completion',
        detail:
          'The consumer results are ready. Next becomes available when the server confirms the completed rollout. Refresh the status if this does not update.',
      };
    if (
      targets.length > 0 &&
      targets.every(complete) &&
      otherBindings.some(binding => !bindingComplete(binding))
    )
      return {
        title: 'Other consumers are still pending',
        detail:
          'This distribution also includes consumers assigned outside the guide. Check the pending consumers in Certificate Management, then refresh the status. Next requires every active consumer to finish.',
      };
    if (!targets.length)
      return {
        title: 'Choose a consumer',
        detail: 'Add a Linux agent below to receive the certificate.',
      };
    if (assignedCount < targets.length)
      return {
        title: rolloutLocked
          ? 'Check consumer assignments'
          : 'Assign the consumers',
        detail: rolloutLocked
          ? 'A selected consumer no longer has a matching active assignment. Check its assignment in Certificate Management, then refresh the status.'
          : 'Use Assign on each consumer card to create its installation configuration.',
      };
    if (!configured)
      return {
        title: rolloutLocked
          ? 'Consumer configuration needs attention'
          : 'Prepare the consumer hosts',
        detail: rolloutLocked
          ? 'The saved host confirmation no longer matches the current assignment. Review the consumer configuration before retrying this rollout.'
          : 'Copy each configuration to its host, restart the agent, and confirm the current configuration below.',
      };
    if (!selected)
      return {
        title: versionId
          ? 'The selected version is unavailable'
          : published.length
            ? 'Choose a certificate version'
            : 'Waiting for certificate publication',
        detail: versionId
          ? 'The selected version must be published and unexpired. Review the publication and choose an available version before deploying.'
          : published.length
            ? 'Select the published certificate version to install on these consumers.'
            : 'Complete the publish job above. A published, unexpired version will appear here automatically.',
      };
    if (observedRollout.job?.status === 'pending_approval')
      return {
        title: 'Rollout approval is required',
        detail:
          'Ask another workspace manager to approve the rollout in Certificate Management, Jobs. Installation starts after approval.',
      };
    if (needsRetry)
      return {
        status: 'warning',
        title: 'A consumer deployment needs attention',
        detail:
          'Inspect the affected consumer’s job output, resolve the reported problem on its host, then retry its deployment below.',
      };
    if (pausedRolloutId)
      return {
        status: 'warning',
        title: 'Resume the paused rollout',
        detail:
          'The consumers are ready to retry. Use Resume rollout below to continue the same deployment.',
      };
    if (terminalRollout)
      return {
        status: 'warning',
        title: 'The rollout did not complete',
        detail:
          'Review the rollout request timeline below, resolve its reported problem, then prepare another rollout.',
      };
    if (!rolloutId)
      return {
        title: requestKey ? 'Confirm the rollout request' : 'Ready to deploy',
        detail: requestKey
          ? 'The request has not been confirmed. Use Deploy the selected version again to safely recover the same request.'
          : 'Use Deploy the selected version below to start installation. Host configuration alone does not confirm delivery.',
      };
    return {
      title: filesOnly
        ? 'Waiting for confirmed file installations'
        : 'Waiting for verified consumer deployments',
      detail: filesOnly
        ? 'Each consumer must report that the selected certificate and key are installed. Check its job output if progress stops.'
        : 'Each consumer must reload its service and report the required live certificate checks. Check its job output if progress stops.',
    };
  })();
  const consumerStatus = target => {
    const binding = bindingFor(target);
    if (!statusLoaded) return ['gray', 'Checking status'];
    if (!binding) return ['orange', 'Assignment needed'];
    if (complete(target))
      return ['green', filesOnly ? 'Files installed' : 'Service verified'];
    const deployment = binding.latest_deployment;
    if (
      ['failed', 'blocked', 'orphaned_unknown_effect'].includes(
        deployment?.stage
      )
    )
      return ['red', 'Deployment needs attention'];
    if (deployment?.rolloutState === 'paused') return ['orange', 'Paused'];
    if (target.confirmedRevision !== binding.authorization_revision)
      return ['orange', 'Configuration needed'];
    if (!rolloutId && !deployment) return ['blue', 'Ready'];
    return [
      'blue',
      filesOnly ? 'Installation pending' : 'Verification pending',
    ];
  };
  const resume = async () => {
    if (!pausedRolloutId || busy || needsRetry || !configured) return;
    setBusy('resume');
    setError('');
    try {
      await resumeRollout(ctx.workspaceId, groupId, pausedRolloutId);
      refresh();
    } catch (e) {
      setError(message(e));
    } finally {
      setBusy('');
    }
  };
  const deploy = async () => {
    if (!configured || !selected || busy || rolloutId) return;
    setBusy('rollout');
    setError('');
    try {
      const key = requestKey || `wizard-vault-rollout-${identifier()}`;
      setRequestKey(key);
      await updateVault(ctx, () => ({
        vaultRolloutRequestKey: key,
        vaultMaterialVersionId: selected.id,
        vaultMaxParallel: parallel,
      }));
      const result = await requestRollout(
        ctx.workspaceId,
        groupId,
        { materialVersionId: selected.id, maxParallel: parallel },
        key
      );
      if (!alive.current) return;
      const job = result.job || result;
      setRolloutId(job.id);
      await updateVault(ctx, () => ({
        vaultRolloutJobId: job.id,
        vaultRolloutRequestKey: key,
        vaultMaterialVersionId: selected.id,
      }));
      refresh();
    } catch (e) {
      if (alive.current) setError(message(e));
    } finally {
      if (alive.current) setBusy('');
    }
  };
  return (
    <VStack align='stretch' spacing={5} minW={0} overflowWrap='anywhere'>
      <StatusPanel
        status={progress.status || 'info'}
        title={progress.title}
        testId='vault-rollout-progress'
        aria-live='polite'
      >
        <VStack align='stretch' spacing={3}>
          <Text fontSize='sm'>{progress.detail}</Text>
          {consumerCount > 0 && statusLoaded ? (
            <Box>
              <Text fontSize='xs' fontWeight='semibold' mb={1.5}>
                {confirmedCount} of {consumerCount} consumers confirmed
                {selected ? ' for the selected version' : ''}
              </Text>
              <Progress
                value={(confirmedCount / consumerCount) * 100}
                aria-label='Consumer deployment confirmations'
                size='xs'
                borderRadius='full'
                colorScheme={allComplete ? 'green' : 'blue'}
              />
            </Box>
          ) : null}
          {otherBindings.length > 0 ? (
            <Box>
              <Text fontSize='xs' fontWeight='semibold' mb={1}>
                Also in this distribution
              </Text>
              {otherBindings.map(binding => (
                <HStack
                  key={binding.binding_id}
                  flexWrap='wrap'
                  justify='space-between'
                  gap={2}
                >
                  <Text fontSize='xs' minW={0} overflowWrap='anywhere'>
                    {binding.agent_name ||
                      (agents.some(
                        agent => agent.id === binding.assigned_agent_id
                      )
                        ? label(
                            agents.find(
                              agent => agent.id === binding.assigned_agent_id
                            )
                          )
                        : `Consumer ${binding.assigned_agent_id || binding.binding_id}`)}
                  </Text>
                  <StatusTag
                    tone={bindingComplete(binding) ? 'green' : 'orange'}
                  >
                    {bindingComplete(binding) ? 'Confirmed' : 'Pending'}
                  </StatusTag>
                </HStack>
              ))}
            </Box>
          ) : null}
          <HStack justify='space-between' flexWrap='wrap' gap={2}>
            <Text fontSize='xs'>
              Consumer status updates automatically every 5 seconds.
            </Text>
            <VaultActionButton
              size='sm'
              variant='outline'
              aria-label='Refresh distribution status'
              onClick={refresh}
            >
              Refresh
            </VaultActionButton>
          </HStack>
        </VStack>
      </StatusPanel>
      <VStack
        as='section'
        aria-labelledby={`${sectionId}-consumers`}
        align='stretch'
        spacing={4}
        minW={0}
      >
        <Box>
          <Heading as='h4' size='sm' id={`${sectionId}-consumers`}>
            Consumers
          </Heading>
          <Text fontSize='sm' mt={1} color={muted} _light={{ color: muted }}>
            Assign each host and confirm its configuration before deploying.
            Current status stays visible on each card.
          </Text>
        </Box>
        <Stack
          direction={{ base: 'column', sm: 'row' }}
          align={{ base: 'stretch', sm: 'end' }}
          spacing={3}
        >
          <FormControl flex='1' minW={0}>
            <FormLabel fontSize='sm'>Additional consumer</FormLabel>
            <Select
              size='sm'
              value={pick}
              isDisabled={rolloutLocked || Boolean(busy)}
              onChange={e => setPick(e.target.value)}
              placeholder='Choose another Linux agent'
            >
              {available.map(a => (
                <option key={a.id} value={a.id}>
                  {label(a)}
                </option>
              ))}
            </Select>
          </FormControl>
          <VaultActionButton
            variant='outline'
            alignSelf={{ base: 'stretch', sm: 'flex-end' }}
            onClick={add}
            isDisabled={!pick || Boolean(busy) || rolloutLocked}
          >
            Add consumer
          </VaultActionButton>
        </Stack>
        {targets.map((target, index) => {
          const agent = agents.find(a => a.id === target.agentId);
          const binding = bindingFor(target);
          const [statusTone, statusLabel] = consumerStatus(target);
          const local =
            binding &&
            buildVaultConfigs({
              ...config,
              consumerAgentId: agent?.wireAgentId,
              consumerBindingId: target.bindingId,
              consumerDeploymentProfileRef: binding.deployment_profile_ref,
              consumerProfileRevision: binding.profile_revision,
              consumerAuthorizationRevision: binding.authorization_revision,
            });
          if (local?.ok) {
            Object.assign(local.consumer.materialBindings[target.bindingId], {
              verificationPolicy: binding.verification_policy || 'trust',
            });
          }
          return (
            <Box
              key={target.bindingId}
              as='section'
              aria-label={`Consumer ${label(agent)}`}
              borderWidth='1px'
              borderColor={border}
              borderRadius='md'
              bg={dashboard.bg.nested}
              p={{ base: 3, md: 4 }}
              minW={0}
            >
              <VStack align='stretch' spacing={3}>
                <HStack justify='space-between' flexWrap='wrap' gap={2}>
                  <Box minW={0}>
                    <Heading as='h5' size='sm' overflowWrap='anywhere'>
                      {label(agent)}
                    </Heading>
                    <Text
                      fontSize='xs'
                      color={dashboard.text.secondary}
                      _light={{ color: dashboard.text.secondary }}
                      mt={1}
                    >
                      Wave {index + 1}
                    </Text>
                  </Box>
                  <StatusTag tone={statusTone} maxW='100%' whiteSpace='normal'>
                    {statusLabel}
                  </StatusTag>
                </HStack>
                {binding ? (
                  <HStack flexWrap='wrap' spacing={3}>
                    <Text
                      fontSize='xs'
                      color={dashboard.text.secondary}
                      _light={{ color: dashboard.text.secondary }}
                    >
                      Profile: {binding.deployment_profile_ref}
                    </Text>
                    <Text
                      fontSize='xs'
                      color={dashboard.text.secondary}
                      _light={{ color: dashboard.text.secondary }}
                    >
                      Authorization revision {binding.authorization_revision}
                    </Text>
                  </HStack>
                ) : null}
                <DetailsSection
                  summary='Host configuration and signed check'
                  defaultOpen={
                    !binding ||
                    target.confirmedRevision !== binding.authorization_revision
                  }
                >
                  <FormControl>
                    <FormLabel
                      fontSize='sm'
                      htmlFor={`profile-${target.bindingId}`}
                    >
                      Deployment profile
                      <VisuallyHidden> for {label(agent)}</VisuallyHidden>
                    </FormLabel>
                    <Input
                      id={`profile-${target.bindingId}`}
                      size='sm'
                      value={target.deploymentProfileRef ?? defaultProfile}
                      isDisabled={
                        Boolean(binding) || rolloutLocked || Boolean(busy)
                      }
                      onChange={e => {
                        const { value } = e.target;
                        setTargets(current =>
                          current.map(t =>
                            t.bindingId === target.bindingId
                              ? { ...t, deploymentProfileRef: value }
                              : t
                          )
                        );
                      }}
                    />
                    <Text
                      fontSize='xs'
                      color={dashboard.text.secondary}
                      _light={{ color: dashboard.text.secondary }}
                      mt={1}
                    >
                      A local profile name: 1–64 letters, digits, underscores or
                      hyphens. Use a distinct name for another distribution on
                      this host.
                    </Text>
                  </FormControl>
                  <VaultActionButton
                    variant='outline'
                    aria-label={`Assign ${label(agent)}`}
                    onClick={() => assign(target, index)}
                    isLoading={busy === target.bindingId}
                    isDisabled={
                      Boolean(busy) ||
                      Boolean(binding) ||
                      !agent?.wireAgentId ||
                      !/^[A-Za-z0-9_-]{1,64}$/.test(
                        target.deploymentProfileRef ?? defaultProfile
                      ) ||
                      rolloutLocked
                    }
                  >
                    Assign
                  </VaultActionButton>
                  {binding ? (
                    <>
                      <Text fontSize='sm'>
                        Merge this configuration into this consumer&apos;s
                        existing agent file. Keep its enrolled identity and
                        credential settings. Use its own Vault Agent role and
                        prepare the destination paths in the preceding step,
                        then restart the agent.
                        {filesOnly
                          ? ' No web server, reload command or TLS probe is required.'
                          : ' Configure the selected service to use these paths.'}
                      </Text>
                      {local?.ok ? (
                        <CopyBlock
                          label={`Consumer configuration for ${label(agent)}`}
                          text={JSON.stringify(local.consumer, null, 2)}
                          language='json'
                        />
                      ) : null}
                      <VaultAgentTest
                        key={`${target.agentId}/${target.bindingId}`}
                        ctx={ctx}
                        agent={agent}
                        disabled={rolloutLocked || Boolean(busy)}
                      />
                      <Text fontSize='sm'>
                        After the signed check completes, set execution.dryRun
                        to false in the saved configuration and restart this
                        consumer. This enables real file installation
                        {filesOnly ? '.' : ' and service reload.'}
                      </Text>
                      <CopyBlock
                        label={`Restart ${label(agent)}`}
                        text={agentRestartCommandFor('linux')}
                      />
                    </>
                  ) : null}
                </DetailsSection>
                {binding ? (
                  <>
                    <Checkbox
                      aria-label={`Configuration saved and agent restarted for ${label(agent)}`}
                      alignItems='flex-start'
                      sx={{
                        '.chakra-checkbox__control': { mt: '3px' },
                        '.chakra-checkbox__label': {
                          fontSize: 'sm',
                          overflowWrap: 'anywhere',
                        },
                      }}
                      isDisabled={Boolean(busy) || rolloutLocked}
                      isChecked={
                        target.confirmedRevision ===
                        binding.authorization_revision
                      }
                      onChange={async e => {
                        const { checked } = e.target;
                        setBusy(target.bindingId);
                        setError('');
                        try {
                          await persistTargets(
                            targets.map(t =>
                              t.bindingId === target.bindingId
                                ? {
                                    ...t,
                                    confirmedRevision: checked
                                      ? binding.authorization_revision
                                      : null,
                                  }
                                : t
                            )
                          );
                        } catch (e) {
                          setError(message(e));
                        } finally {
                          setBusy('');
                        }
                      }}
                    >
                      Configuration saved and agent restarted
                    </Checkbox>
                    <Text fontSize='sm'>
                      Deployment:{' '}
                      {deploymentStageLabel(binding.latest_deployment?.stage)}
                    </Text>
                    {binding.latest_deployment?.jobId &&
                    deploymentEvidenceOwners.get(
                      binding.latest_deployment.jobId
                    ) === target.bindingId ? (
                      <DetailsSection
                        summary='Deployment activity'
                        defaultOpen={!complete(target)}
                      >
                        <JobActivity
                          key={`${binding.latest_deployment.jobId}:${refreshIndex}`}
                          workspaceId={ctx.workspaceId}
                          jobId={binding.latest_deployment.jobId}
                          title={`Deployment: ${label(agent)}`}
                        />
                      </DetailsSection>
                    ) : binding.latest_deployment?.jobId ? (
                      <Text
                        fontSize='xs'
                        color={dashboard.text.secondary}
                        _light={{ color: dashboard.text.secondary }}
                      >
                        {binding.latest_deployment.jobId === rolloutId
                          ? 'Evidence for this deployment is shown in the rollout timeline below.'
                          : 'This deployment shares the job evidence shown with another consumer.'}
                      </Text>
                    ) : null}
                    {['failed', 'blocked', 'orphaned_unknown_effect'].includes(
                      binding.latest_deployment?.stage
                    ) ? (
                      <>
                        <Text fontSize='sm'>
                          Retrying queues this deployment again. If the rollout
                          is paused, resume it before the retry can run.
                        </Text>
                        <VaultActionButton
                          variant='outline'
                          aria-label={`Retry deployment to ${label(agent)}`}
                          isDisabled={Boolean(busy)}
                          onClick={async () => {
                            setBusy(target.bindingId);
                            setError('');
                            try {
                              await retryDeployment(
                                ctx.workspaceId,
                                binding.latest_deployment.jobId
                              );
                              refresh();
                            } catch (e) {
                              setError(message(e));
                            } finally {
                              setBusy('');
                            }
                          }}
                        >
                          Retry deployment
                        </VaultActionButton>
                      </>
                    ) : null}
                  </>
                ) : null}
              </VStack>
            </Box>
          );
        })}
      </VStack>
      <VStack
        as='section'
        aria-labelledby={`${sectionId}-deploy`}
        align='stretch'
        spacing={4}
        borderTopWidth='1px'
        borderColor={border}
        pt={5}
        minW={0}
      >
        <Box>
          <Heading as='h4' size='sm' id={`${sectionId}-deploy`}>
            Deploy certificate
          </Heading>
          <Text fontSize='sm' mt={1} color={muted} _light={{ color: muted }}>
            Choose the published version and how many consumers can deploy at
            once.
          </Text>
        </Box>
        <SimpleGrid columns={{ base: 1, lg: 2 }} spacing={4}>
          <FormControl minW={0}>
            <FormLabel fontSize='sm'>Published certificate version</FormLabel>
            <Select
              size='sm'
              value={versionId}
              isDisabled={rolloutLocked}
              onChange={async e => {
                const { value } = e.target;
                setVersionId(value);
                setRequestKey('');
                setRolloutId('');
                try {
                  await updateVault(ctx, () => ({
                    vaultMaterialVersionId: value,
                    vaultRolloutRequestKey: '',
                    vaultRolloutJobId: '',
                  }));
                } catch (e) {
                  setError(message(e));
                }
              }}
              placeholder='Choose a published, unexpired version'
            >
              {published.map(v => (
                <option key={v.id} value={v.id}>
                  Vault version {v.provider_version} · expires{' '}
                  {new Date(v.valid_to).toISOString().slice(0, 10)}
                </option>
              ))}
            </Select>
          </FormControl>
          <FormControl minW={0}>
            <FormLabel fontSize='sm'>Maximum parallel deployments</FormLabel>
            <Select
              size='sm'
              value={parallel}
              isDisabled={rolloutLocked}
              onChange={async e => {
                const value = Number(e.target.value);
                setParallel(value);
                setRequestKey('');
                try {
                  await updateVault(ctx, () => ({
                    vaultMaxParallel: value,
                    vaultRolloutRequestKey: '',
                  }));
                } catch (e) {
                  setError(message(e));
                }
              }}
            >
              {Array.from(
                { length: Math.max(1, Math.min(16, targets.length)) },
                (_, i) => (
                  <option key={i + 1} value={i + 1}>
                    {i + 1}
                  </option>
                )
              )}
            </Select>
          </FormControl>
        </SimpleGrid>
        <Text fontSize='sm' data-testid='vault-dry-run-note'>
          A rollout itself has no dry run: deployment changes the configured
          certificate files{filesOnly ? '.' : ' and reloads the service.'} A
          signed test job only checks dispatch and local planning. Before
          deployment, set local dryRun to false and restart the prepared
          consumers.
        </Text>
        <ApprovalPolicyNote required={approvalRequired} noun='rollout' />
        <PrimaryButton
          {...actionLayout}
          onClick={deploy}
          isLoading={busy === 'rollout'}
          isDisabled={
            !configured ||
            !selected ||
            !statusLoaded ||
            Boolean(busy) ||
            Boolean(rolloutId)
          }
        >
          Deploy the selected version
        </PrimaryButton>
        {!configured ? (
          <Text fontSize='xs' color={muted} _light={{ color: muted }}>
            Assign every selected consumer and confirm its current configuration
            before deployment. These confirmations do not prove a live
            deployment.
          </Text>
        ) : null}
        {pausedRolloutId && !allComplete ? (
          <StatusPanel status='warning' title='Rollout paused'>
            <VStack align='start' spacing={3}>
              <Text fontSize='sm'>
                Repair and reconcile any uncertain consumer on its host, then
                retry the affected deployment above before resuming. Resuming
                keeps the same version and consumer assignments; it does not
                prove deployment.
              </Text>
              <VaultActionButton
                variant='outline'
                onClick={resume}
                isLoading={busy === 'resume'}
                isDisabled={Boolean(busy) || needsRetry || !configured}
              >
                Resume rollout
              </VaultActionButton>
            </VStack>
          </StatusPanel>
        ) : null}
        {rolloutId ? (
          <>
            <ApprovalWaitPanel job={observedRollout.job} />
            <DetailsSection
              summary='Rollout request timeline'
              defaultOpen={!allComplete}
            >
              <JobActivity
                key={`${rolloutId}:${refreshIndex}`}
                workspaceId={ctx.workspaceId}
                jobId={rolloutId}
                title='Rollout request timeline'
              />
            </DetailsSection>
          </>
        ) : null}
        {allComplete || terminalRollout ? (
          <VaultActionButton
            variant='outline'
            onClick={async () => {
              setRolloutId('');
              setRequestKey('');
              setVersionId('');
              try {
                await updateVault(ctx, () => ({
                  vaultRolloutJobId: '',
                  vaultRolloutRequestKey: '',
                  vaultMaterialVersionId: '',
                }));
              } catch (e) {
                setError(message(e));
              }
            }}
          >
            Prepare another rollout
          </VaultActionButton>
        ) : null}
      </VStack>
      {error || statusError || observedRollout.error || summaryReadFailed ? (
        <StatusPanel status='error'>
          {error ||
            statusError ||
            observedRollout.error ||
            summaryFailure?.error}
        </StatusPanel>
      ) : null}
    </VStack>
  );
}
