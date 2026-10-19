import { useCallback, useEffect, useState } from 'react';
import { Badge, HStack, Text, VStack } from '@chakra-ui/react';
import { DashboardErrorAlert } from '../DashboardPrimitives';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import StepFrame from './StepFrame.jsx';
import PrimaryButton from './PrimaryButton.jsx';
import { CopyBlock } from './blocks.jsx';
import { GOALS } from './modules.js';
import { buildDryRunJob } from './certopsConfig.js';
import { certopsProgress, saveCertops } from './certopsSetupSteps.jsx';
import { createJob, getJob } from '../certops/certopsJobsApi.js';

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
  const agents = ctx.summary?.certops?.agents;
  const agent = agents?.items?.[0];
  const [job, setJob] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const goal = GOALS[ctx.session.intent?.goal];
  const needsExecution = goal?.certopsObjective !== 'observe';

  const loadJob = useCallback(async () => {
    if (!saved.dryRunJobId) return;
    try {
      const res = await getJob(ctx.workspaceId, saved.dryRunJobId);
      setJob(res.job || res);
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
      docs={ctx.docs('certops.dryRun', 'Dry-run guide')}
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
      <VStack align='stretch' spacing={3}>
        {error ? <DashboardErrorAlert>{error}</DashboardErrorAlert> : null}
        {EXECUTION_STAGES.map(s => (
          <HStack key={s.id} align='start'>
            <Badge colorScheme={state.done.includes(s.id) ? 'green' : 'gray'}>
              {state.done.includes(s.id) ? 'Done' : 'Waiting'}
            </Badge>
            <VStack align='start' spacing={0}>
              <Text fontSize='sm' fontWeight='semibold'>
                {s.label}
              </Text>
              <Text fontSize='xs' color={muted}>
                {s.hint}
              </Text>
            </VStack>
          </HStack>
        ))}
        {!state.done.includes('enabled') ? (
          <>
            <Text fontSize='sm'>
              On the server set execution.enabled to true and keep dryRun true
              in config.json, then restart the agent.
            </Text>
            <CopyBlock
              label='config.json'
              text={JSON.stringify(
                { execution: { enabled: true, dryRun: true } },
                null,
                2
              )}
            />
          </>
        ) : null}
        {job && job.status !== 'dry_run_complete' ? (
          <Text fontSize='xs' color='orange.400'>
            Test job is {job.status}. A dry run must end as dry_run_complete,
            never succeeded.
          </Text>
        ) : null}
        {state.done.includes('dryrun') ? (
          <Text fontSize='sm'>
            The dry run passed. Set dryRun to false and restart the agent when
            you are ready for real work.
          </Text>
        ) : null}
      </VStack>
    </StepFrame>
  );
}
