import { useCallback, useEffect, useRef, useState } from 'react';
import { Text, VStack } from '@chakra-ui/react';
import { DashboardErrorAlert } from '../DashboardPrimitives';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import StepFrame from './StepFrame.jsx';
import PrimaryButton from './PrimaryButton.jsx';
import { CopyBlock } from './blocks.jsx';
import JobActivity from './JobActivity.jsx';
import { Callout, StatusPanel, StatusTag, StepCard } from './panels.jsx';
import { GOALS } from './modules.js';
import {
  agentConfigPathFor,
  agentRestartCommandFor,
  buildDryRunJob,
} from './certopsConfig.js';
import {
  agentsFor,
  effectiveInfrastructure,
  pickGoalAgent,
} from './certopsMatrix.js';
import { certopsProgress, saveCertops } from './certopsSetupSteps.jsx';
import { useSummaryPolling } from './useSummaryPolling.js';
import { createJob, getJob } from '../certops/certopsJobsApi.js';
import {
  ApprovalPolicyNote,
  ApprovalWaitPanel,
  useJobApprovalPolicy,
} from './approvalPolicy.jsx';

// Shown as a block to merge: pasting it over the file would drop agentId.
const EXECUTION_BLOCK = `"execution": {
  "enabled": true,
  "dryRun": true
}`;

// Three stages, each proven by observed state rather than assumed.
export const EXECUTION_STAGES = [
  {
    id: 'observe',
    label: 'Observe only',
    hint: 'The agent reports but never runs jobs.',
  },
  {
    id: 'enabled',
    label: 'Execution enabled (dry run)',
    hint: 'The agent polls for jobs but refuses real work.',
  },
  {
    id: 'dryrun',
    label: 'Signed dry run completed',
    hint: 'A signed test job ended as dry_run_complete.',
  },
];

/** Where the agent is, from what the server actually saw. */
export function executionStage({ agents, dryRunJob }) {
  const live = (agents?.live || 0) > 0;
  if (!live) return { stage: 'none', done: [] };
  const done = ['observe'];
  if (agents.executionEnabled) done.push('enabled');
  if (dryRunJob?.status === 'dry_run_complete') done.push('dryrun');
  return { stage: done[done.length - 1], done };
}

export function ExecutionStep({ ctx }) {
  const { muted } = useDashboardTheme();
  const saved = certopsProgress(ctx);
  const allAgents = ctx.summary?.certops?.agents;
  const agent = pickGoalAgent(
    allAgents?.items,
    saved.objective,
    effectiveInfrastructure(saved.objective, saved.infrastructure),
    saved.chosenAgentId
  );
  const agents = agentsFor(allAgents, agent);
  const [job, setJob] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const { required: approvalRequired } = useJobApprovalPolicy(ctx.workspaceId);
  const goal = GOALS[ctx.session.intent?.goal];
  const needsExecution = goal?.certopsObjective !== 'observe';

  // Read through refs so a new ctx object on every render does not restart
  // the polling effect below.
  const latest = useRef(ctx);
  latest.current = ctx;

  const loadJob = useCallback(async () => {
    if (!saved.dryRunJobId) return;
    try {
      const res = await getJob(ctx.workspaceId, saved.dryRunJobId);
      const next = res.job || res;
      setJob(next);
      // The journey is planned from the workspace summary, so it has to be
      // re-read once the test job reaches its final state or the guide would
      // keep showing this step after it passed.
      const current = latest.current;
      if (
        next?.status === 'dry_run_complete' &&
        current.summary?.certops?.dryRun?.status !== 'dry_run_complete'
      ) {
        await current.refresh();
      }
    } catch (e) {
      setError(e.message);
    }
  }, [ctx.workspaceId, saved.dryRunJobId]);

  useEffect(() => {
    loadJob();
    if (!saved.dryRunJobId) return undefined;
    const t = setInterval(loadJob, 5000);
    return () => clearInterval(t);
  }, [loadJob, saved.dryRunJobId]);

  const state = executionStage({ agents, dryRunJob: job });
  // The agent turns execution on by itself once restarted, so keep reading
  // until the server has seen it.
  useSummaryPolling(
    ctx.refresh,
    needsExecution && Boolean(agent) && !agents?.executionEnabled
  );
  const os = saved.infrastructure === 'windows' ? 'windows' : 'linux';
  const configPath = agentConfigPathFor(os);
  const restartCommand = agentRestartCommandFor(os);

  if (!needsExecution) {
    return (
      <StepFrame
        kind='verify'
        title='Execution stays off'
        description='You chose to observe only.'
      >
        <Text fontSize='sm'>
          The agent reports what it finds and cannot run jobs. You can enable
          execution later from this guide.
        </Text>
        <PrimaryButton
          mt={3}
          onClick={() => saveCertops(ctx, { executionAcknowledged: true })}
        >
          Continue
        </PrimaryButton>
      </StepFrame>
    );
  }

  const createDryRun = async () => {
    setBusy(true);
    setError('');
    try {
      const res = await createJob(
        ctx.workspaceId,
        buildDryRunJob({
          assignedAgentId: agent.id,
          idempotencyKey: `wizard-dryrun-${agent.id}`,
        })
      );
      const created = res.job || res;
      await saveCertops(ctx, { dryRunJobId: created.id });
    } catch (e) {
      setError(
        e?.response?.data?.error ||
          e.message ||
          'Could not create the test job.'
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <StepFrame
      kind='verify'
      title='Turn on execution safely'
      description='Three stages, each confirmed by what the server observed. Real work only starts after the dry run passes.'
      docs={ctx.docs(
        saved.infrastructure === 'windows'
          ? 'certops.dryRunWindows'
          : 'certops.dryRun',
        'Dry-run guide'
      )}
      actions={
        agent && !saved.dryRunJobId ? (
          <PrimaryButton
            onClick={createDryRun}
            isLoading={busy}
            isDisabled={!state.done.includes('enabled')}
          >
            Send a test job
          </PrimaryButton>
        ) : null
      }
    >
      <VStack align='stretch' spacing={4}>
        {error ? <DashboardErrorAlert>{error}</DashboardErrorAlert> : null}
        <VStack
          as='ol'
          align='stretch'
          spacing={2}
          listStyleType='none'
          m={0}
          p={0}
          aria-label='Execution stages'
        >
          {EXECUTION_STAGES.map((s, index) => (
            <li key={s.id}>
              <StepCard
                n={index + 1}
                title={s.label}
                description={s.hint}
                status={state.done.includes(s.id) ? 'done' : undefined}
                testId={`stage-${s.id}`}
              >
                {state.done.includes(s.id) ? null : (
                  <StatusTag tone='gray' alignSelf='flex-start'>
                    Waiting
                  </StatusTag>
                )}
              </StepCard>
            </li>
          ))}
        </VStack>
        {!state.done.includes('enabled') ? (
          <Callout kind='before' title='Turn on execution on the server'>
            <VStack align='stretch' spacing={3}>
              <Text fontSize='sm'>
                Open <code>{configPath}</code> on the server. Do not replace the
                file: keep <code>agentId</code>, your policy and the other keys
                in the execution block, and set only these two values. Then
                restart the agent.
              </Text>
              <CopyBlock
                label='execution block (merge into config.json, do not replace the file)'
                text={EXECUTION_BLOCK}
                language='json'
              />
              <CopyBlock
                label='Restart the agent'
                text={restartCommand}
                prompt
              />
              {agent && !saved.dryRunJobId ? (
                <Text fontSize='xs' color={muted} data-testid='send-test-hint'>
                  Send a test job stays disabled until the agent checks in again
                  with execution enabled. This page re-checks every 15 seconds.
                </Text>
              ) : null}
            </VStack>
          </Callout>
        ) : null}
        {agent && !saved.dryRunJobId && state.done.includes('enabled') ? (
          <ApprovalPolicyNote required={approvalRequired} noun='test job' />
        ) : null}
        <ApprovalWaitPanel
          job={job}
          title='The test job is waiting for approval'
        />
        {job &&
        job.status !== 'dry_run_complete' &&
        job.status !== 'pending_approval' ? (
          <StatusPanel status='warning' title='The test job has not passed'>
            The test job is {job.status}. A passing dry run ends as
            dry_run_complete, not as succeeded.
          </StatusPanel>
        ) : null}
        {saved.dryRunJobId ? (
          <JobActivity
            workspaceId={ctx.workspaceId}
            jobId={saved.dryRunJobId}
            title='What happened to the test job'
          />
        ) : null}
        {state.done.includes('dryrun') ? (
          <StatusPanel status='success' title='The dry run passed'>
            When you are ready for real work, set <code>dryRun</code> to{' '}
            <code>false</code> in the same execution block of{' '}
            <code>{configPath}</code> and restart the agent with{' '}
            <code>{restartCommand}</code>.
          </StatusPanel>
        ) : null}
      </VStack>{' '}
    </StepFrame>
  );
}
