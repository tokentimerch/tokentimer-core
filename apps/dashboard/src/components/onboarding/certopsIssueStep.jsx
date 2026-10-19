import { useEffect, useState } from 'react';
import {
  Alert,
  AlertDescription,
  AlertIcon,
  Badge,
  HStack,
  Text,
  VStack,
} from '@chakra-ui/react';
import { DashboardActionButton } from '../DashboardPrimitives';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import { createJob } from '../certops/certopsJobsApi.js';
import StepFrame from './StepFrame.jsx';
import PrimaryButton from './PrimaryButton.jsx';
import {
  buildIssueJob,
  issueIdempotencyKey,
  STAGING_CA,
} from './certopsConfig.js';
import { certopsProgress, saveCertops } from './certopsSetupSteps.jsx';

const ACTIVE = new Set([
  'pending_approval',
  'approved',
  'pending',
  'claimed',
  'running',
]);

/**
 * What the user should see for the issuance job, from server state only.
 * Nothing here is inferred from a stored flag.
 */
export function issueView(job) {
  if (!job) return { tone: 'gray', label: 'Not requested', active: false };
  if (job.status === 'succeeded' && job.mode === 'real') {
    return { tone: 'green', label: 'Issued', active: false, done: true };
  }
  if (ACTIVE.has(job.status)) {
    const label =
      job.status === 'pending_approval'
        ? 'Waiting for approval'
        : job.status === 'pending'
          ? 'Waiting for the agent'
          : 'In progress';
    return { tone: 'blue', label, active: true };
  }
  if (job.status === 'orphaned_unknown_effect') {
    return {
      tone: 'orange',
      label: 'Needs review',
      active: false,
      noRetry: true,
    };
  }
  return {
    tone: 'red',
    label: 'Did not complete',
    active: false,
    failed: true,
  };
}

export function canRequestIssue({ agents, dryRun, saved }) {
  const missing = [];
  if (!(agents?.live > 0)) missing.push('a live agent');
  if (agents?.executionEnabled !== true) missing.push('execution enabled');
  if (dryRun?.status !== 'dry_run_complete') missing.push('a passing dry run');
  if (!saved.zone || !saved.dnsProvider || !saved.certPath || !saved.names) {
    missing.push('the saved agent configuration');
  }
  return { ok: missing.length === 0, missing };
}

export default function IssueStep({ ctx }) {
  const { muted } = useDashboardTheme();
  const saved = certopsProgress(ctx);
  const certops = ctx.summary?.certops;
  const agent = certops?.agents?.items?.[0];
  const job = certops?.issueJob;
  const view = issueView(job);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const gate = canRequestIssue({
    agents: certops?.agents,
    dryRun: certops?.dryRun,
    saved,
  });
  const names = (saved.names || '').split(/[\s,]+/).filter(Boolean);
  const attempt = saved.issueAttempt || 1;
  const caEndpoint = saved.caEndpoint || STAGING_CA;
  const { refresh } = ctx;

  useEffect(() => {
    if (!view.active) return undefined;
    const t = setInterval(() => refresh(), 5000);
    return () => clearInterval(t);
  }, [view.active, refresh]);

  const request = async () => {
    setBusy(true);
    setError('');
    try {
      const res = await createJob(
        ctx.workspaceId,
        buildIssueJob({
          os: 'linux',
          names,
          zone: saved.zone,
          dnsProvider: saved.dnsProvider,
          certPath: saved.certPath,
          caEndpoint,
          assignedAgentId: agent.id,
          idempotencyKey: issueIdempotencyKey({
            names,
            zone: saved.zone,
            certPath: saved.certPath,
            caEndpoint,
            attempt,
          }),
        })
      );
      const created = res.job || res;
      await saveCertops(ctx, { issueJobId: created.id });
    } catch (e) {
      // The server explains a taken path itself (409), so show it as is.
      setError(
        e?.response?.data?.error || e.message || 'Could not request the order.'
      );
    } finally {
      setBusy(false);
    }
  };

  const askAgain = () =>
    saveCertops(ctx, { issueJobId: null, issueAttempt: attempt + 1 });

  return (
    <StepFrame
      kind='verify'
      title='Request your first certificate'
      description='The agent places one test order with the Let’s Encrypt staging CA and writes the result to the path you chose.'
      docs={[
        ...ctx.docs('certops.dns', 'DNS providers'),
        ...ctx.docs('certops.agentConfig', 'Agent configuration'),
      ]}
      actions={
        !job ? (
          <PrimaryButton
            onClick={request}
            isLoading={busy}
            isDisabled={!gate.ok || !agent}
          >
            Request a staging certificate
          </PrimaryButton>
        ) : view.failed ? (
          <DashboardActionButton variant='outline' onClick={askAgain}>
            Request again
          </DashboardActionButton>
        ) : (
          <DashboardActionButton variant='outline' onClick={() => refresh()}>
            Check again
          </DashboardActionButton>
        )
      }
    >
      <VStack align='stretch' spacing={3}>
        <HStack>
          <Badge colorScheme={view.tone}>{view.label}</Badge>
          <Text fontSize='sm'>
            {names.join(', ') || 'No names saved yet'} via {saved.dnsProvider}
          </Text>
        </HStack>
        {!gate.ok ? (
          <Alert status='warning' borderRadius='md'>
            <AlertIcon />
            <AlertDescription fontSize='sm'>
              Needs {gate.missing.join(', ')} first.
            </AlertDescription>
          </Alert>
        ) : null}
        {!job ? (
          <Text fontSize='sm'>
            Before you request: in the agent configuration set{' '}
            <code>execution.dryRun</code> to <code>false</code> and restart the
            agent. While it is true the agent refuses real orders, and the
            control plane cannot see that setting.
          </Text>
        ) : null}
        {job?.errorCode === 'AGENT_RESULT_BLOCKED' ? (
          <Text fontSize='sm'>
            The agent refused the order. Set <code>execution.dryRun</code> to{' '}
            <code>false</code>, restart it, then request again.
          </Text>
        ) : null}
        {job?.errorMessage ? (
          <Alert status='error' borderRadius='md'>
            <AlertIcon />
            <AlertDescription fontSize='sm'>
              {job.errorCode ? `${job.errorCode}: ` : ''}
              {job.errorMessage}
            </AlertDescription>
          </Alert>
        ) : null}
        {view.failed ? (
          <Text fontSize='sm'>
            A failed order leaves an entry in <code>provisioning</code> that
            still holds <code>{saved.certPath}</code>, so asking again with the
            same path is rejected. Retire that entry in Certificate Management,
            or go back and choose a different file name, then request again.
          </Text>
        ) : null}
        {view.noRetry ? (
          <Text fontSize='sm'>
            The agent may have placed the order before the result was lost.
            Review the job log before asking again.
          </Text>
        ) : null}
        {error ? (
          <Alert status='error' borderRadius='md'>
            <AlertIcon />
            <AlertDescription fontSize='sm'>{error}</AlertDescription>
          </Alert>
        ) : null}
        <Text fontSize='xs' color={muted}>
          CA: {caEndpoint}. Staging certificates are not trusted by browsers;
          that is intended for a first run. Asking again places a new order, and
          CAs rate limit repeated orders.
        </Text>
        {view.done ? (
          <Text fontSize='sm'>
            The certificate was issued and written to {saved.certPath}.
            Installing it into a web server and renewal are separate steps.
          </Text>
        ) : null}
      </VStack>
    </StepFrame>
  );
}
