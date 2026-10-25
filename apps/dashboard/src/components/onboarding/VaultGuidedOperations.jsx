import { useCallback, useEffect, useRef, useState } from 'react';
import {
  Box,
  Checkbox,
  FormControl,
  FormLabel,
  HStack,
  Input,
  Select,
  Text,
  VStack,
} from '@chakra-ui/react';
import { DashboardActionButton } from '../DashboardPrimitives';
import { createJob, getJob } from '../certops/certopsJobsApi.js';
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
} from './vaultGuideApi.js';
import { ApprovalPolicyNote, ApprovalWaitPanel } from './approvalPolicy.jsx';
import { CopyBlock } from './blocks.jsx';
import JobActivity from './JobActivity.jsx';
import { isJobFinal } from './jobTimeline.js';
import { StatusPanel, StatusTag } from './panels.jsx';

const label = agent =>
  agent?.name || agent?.hostname || agent?.wireAgentId || 'agent';
const message = error =>
  error?.response?.data?.error ||
  error?.message ||
  'The request could not be completed.';
const identifier = () => globalThis.crypto.randomUUID();

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

function useObservedJob(workspaceId, jobId) {
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
  }, [workspaceId, jobId]);
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
        <DashboardActionButton
          variant='outline'
          onClick={send}
          isLoading={busy}
          isDisabled={
            disabled ||
            !agent ||
            (Boolean(jobId) && !isJobFinal(observed.job?.status))
          }
        >
          {jobId
            ? `${isJobFinal(observed.job?.status) ? 'Retry test' : 'Checking test'} for ${label(agent)}`
            : `Send a test job to ${label(agent)}`}
        </DashboardActionButton>
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
                : `Test status: ${observed.job?.status || 'checking'}`}
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
  const { muted } = useDashboardTheme();
  const saved = certopsProgress(ctx);
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
    error: '',
  });
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
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
  const refresh = useCallback(() => setRefreshIndex(i => i + 1), []);
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
        if (active) setState({ ...result, loaded: true, error: '' });
      } catch (e) {
        if (active)
          setState({
            versions: [],
            consumers: [],
            loaded: false,
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
  }, [ctx.workspaceId, groupId, refreshIndex]);
  const observedRollout = useObservedJob(ctx.workspaceId, rolloutId);
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
  const bindingFor = target =>
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
  const published = state.versions.filter(
    v => v.state === 'published' && Date.parse(v.valid_to) > Date.now()
  );
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
  const allComplete =
    Boolean(selected) &&
    targets.length > 0 &&
    targets.every(t => {
      const b = bindingFor(t);
      return (
        b?.converged === true && b.desired_material_version_id === selected.id
      );
    });
  const rolloutLocked = Boolean(rolloutId || requestKey);
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
    <VStack align='stretch' spacing={5}>
      <Text fontSize='sm'>
        Assign each consumer here, copy its returned configuration to that host,
        then deploy a published certificate version. Stay in this guide to
        follow the rollout and each deployment.
      </Text>
      <HStack align='end' flexWrap='wrap'>
        <FormControl flex='1' minW='220px'>
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
        <DashboardActionButton
          variant='outline'
          onClick={add}
          isDisabled={!pick || Boolean(busy) || rolloutLocked}
        >
          Add consumer
        </DashboardActionButton>
      </HStack>
      {targets.map((target, index) => {
        const agent = agents.find(a => a.id === target.agentId);
        const binding = bindingFor(target);
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
          <Box key={target.bindingId} borderWidth='1px' borderRadius='md' p={4}>
            <VStack align='stretch' spacing={3}>
              <Text fontWeight='semibold'>
                {label(agent)} · wave {index + 1}
              </Text>
              <FormControl>
                <FormLabel
                  fontSize='sm'
                  htmlFor={`profile-${target.bindingId}`}
                >
                  Deployment profile for {label(agent)}
                </FormLabel>
                <Input
                  id={`profile-${target.bindingId}`}
                  size='sm'
                  value={target.deploymentProfileRef ?? defaultProfile}
                  isDisabled={
                    Boolean(binding) || rolloutLocked || Boolean(busy)
                  }
                  onChange={e => {
                    const value = e.target.value;
                    setTargets(current =>
                      current.map(t =>
                        t.bindingId === target.bindingId
                          ? { ...t, deploymentProfileRef: value }
                          : t
                      )
                    );
                  }}
                />
                <Text fontSize='xs' color={muted}>
                  A local profile name: 1–64 letters, digits, underscores or
                  hyphens. Use a distinct name for another distribution on this
                  host.
                </Text>
              </FormControl>
              <DashboardActionButton
                variant='outline'
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
                Assign {label(agent)}
              </DashboardActionButton>
              {binding ? (
                <>
                  <Text fontSize='sm'>
                    Authorization revision {binding.authorization_revision}
                  </Text>
                  <Text fontSize='sm'>
                    Merge this configuration into this consumer&apos;s existing
                    agent file. Keep its enrolled identity and credential
                    settings. Use its own Vault Agent role and prepare the
                    destination paths in the preceding step, then restart the
                    agent.
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
                    After the signed check completes, set execution.dryRun to
                    false in the saved configuration and restart this consumer.
                    This enables real file installation
                    {filesOnly ? '.' : ' and service reload.'}
                  </Text>
                  <CopyBlock
                    label={`Restart ${label(agent)}`}
                    text={agentRestartCommandFor('linux')}
                  />
                  <Checkbox
                    isDisabled={Boolean(busy) || rolloutLocked}
                    isChecked={
                      target.confirmedRevision ===
                      binding.authorization_revision
                    }
                    onChange={async e => {
                      const checked = e.target.checked;
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
                    Configuration saved and agent restarted for {label(agent)}
                  </Checkbox>
                  <Text fontSize='sm'>
                    Deployment:{' '}
                    {binding.latest_deployment?.stage || 'Not requested yet'}
                  </Text>
                  {binding.latest_deployment?.jobId &&
                  deploymentEvidenceOwners.get(
                    binding.latest_deployment.jobId
                  ) === target.bindingId ? (
                    <JobActivity
                      workspaceId={ctx.workspaceId}
                      jobId={binding.latest_deployment.jobId}
                      title={`Deployment: ${label(agent)}`}
                    />
                  ) : binding.latest_deployment?.jobId ? (
                    <Text fontSize='xs' color={muted}>
                      {binding.latest_deployment.jobId === rolloutId
                        ? 'Evidence for this deployment is shown in the rollout timeline below.'
                        : 'This deployment shares the job evidence shown with another consumer.'}
                    </Text>
                  ) : null}
                  {['failed', 'blocked', 'orphaned_unknown_effect'].includes(
                    binding.latest_deployment?.stage
                  ) ? (
                    <DashboardActionButton
                      variant='outline'
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
                      Retry deployment to {label(agent)}
                    </DashboardActionButton>
                  ) : null}
                </>
              ) : null}
            </VStack>
          </Box>
        );
      })}
      <Text fontSize='sm' data-testid='vault-dry-run-note'>
        A rollout itself has no dry run: deployment changes the configured
        certificate files{filesOnly ? '.' : ' and reloads the service.'} A
        signed test job only checks dispatch and local planning. Before
        deployment, set local dryRun to false and restart the prepared
        consumers.
      </Text>
      <FormControl>
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
      <FormControl>
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
      <ApprovalPolicyNote required={approvalRequired} noun='rollout' />
      <DashboardActionButton
        onClick={deploy}
        isLoading={busy === 'rollout'}
        isDisabled={
          !configured ||
          !selected ||
          !state.loaded ||
          Boolean(busy) ||
          Boolean(rolloutId)
        }
      >
        Deploy the selected version
      </DashboardActionButton>
      {!configured ? (
        <Text fontSize='xs' color={muted}>
          Assign every selected consumer and confirm its current configuration
          before deployment. These confirmations do not prove a live deployment.
        </Text>
      ) : null}
      <DashboardActionButton variant='outline' onClick={refresh}>
        Refresh distribution status
      </DashboardActionButton>
      {rolloutId ? (
        <>
          <ApprovalWaitPanel job={observedRollout.job} />
          <JobActivity
            workspaceId={ctx.workspaceId}
            jobId={rolloutId}
            title='Rollout request timeline'
          />
        </>
      ) : null}
      {allComplete ? (
        <StatusPanel
          status='success'
          title={
            filesOnly
              ? 'Certificate files installed on all selected consumers'
              : 'All selected consumers verified'
          }
        >
          {filesOnly
            ? 'The agents checked the installed certificate and key on disk against the selected version. No service was reloaded or checked; this does not prove the certificate is in use.'
            : 'The server reports current convergence on the selected version. Inspect each deployment’s evidence and make an independent TLS connection to the live services.'}
        </StatusPanel>
      ) : (
        <StatusTag tone='gray'>
          {filesOnly
            ? 'Waiting for confirmed file installations'
            : 'Waiting for verified consumer deployments'}
        </StatusTag>
      )}
      {allComplete ||
      ['failed', 'rejected', 'cancelled', 'blocked'].includes(
        observedRollout.job?.status
      ) ? (
        <DashboardActionButton
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
        </DashboardActionButton>
      ) : null}
      {error || state.error || observedRollout.error ? (
        <StatusPanel status='error'>
          {error || state.error || observedRollout.error}
        </StatusPanel>
      ) : null}
    </VStack>
  );
}
