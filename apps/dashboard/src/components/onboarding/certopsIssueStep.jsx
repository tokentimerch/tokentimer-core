import { useEffect, useState } from 'react';
import { FiRefreshCw } from 'react-icons/fi';
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
  RELOAD_SERVICES,
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
  // Windows hands the certificate to IIS, so it needs the ACME client rather
  // than a file path.
  const target =
    saved.infrastructure === 'windows' ? saved.acmeClientPath : saved.certPath;
  if (!saved.zone || !saved.dnsProvider || !target || !saved.names) {
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
  const windows = saved.infrastructure === 'windows';
  const names = (saved.names || '').split(/[\s,]+/).filter(Boolean);
  const attempt = saved.issueAttempt || 1;
  const caEndpoint = saved.caEndpoint || STAGING_CA;
  const reloadLabel = RELOAD_SERVICES[saved.reloadService]?.label || '';
  // Orders made before this was recorded fall back to the current choice.
  const jobReloadService = saved.issueReloadService ?? saved.reloadService;
  const jobReloadLabel = RELOAD_SERVICES[jobReloadService]?.label || '';
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
          os: windows ? 'windows' : 'linux',
          names,
          zone: saved.zone,
          dnsProvider: saved.dnsProvider,
          certPath: windows ? undefined : saved.certPath,
          caEndpoint,
          reloadService: windows ? '' : saved.reloadService || '',
          iisSite: saved.iisSite || 'Default Web Site',
          iisPort: saved.iisPort || 443,
          sniHost: saved.sniHost || '',
          assignedAgentId: agent.id,
          idempotencyKey: issueIdempotencyKey({
            names,
            zone: saved.zone,
            certPath: windows
              ? `iis:${saved.iisSite || 'Default Web Site'}:${saved.iisPort || 443}`
              : saved.certPath,
            caEndpoint,
            reloadService: saved.reloadService || '',
            attempt,
          }),
        })
      );
      const created = res.job || res;
      await saveCertops(ctx, {
        issueJobId: created.id,
        // The outcome text names the server this order used, even if the
        // configuration is edited afterwards.
        issueReloadService: windows ? '' : saved.reloadService || '',
      });
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
      description={
        windows
          ? 'The agent places one test order with the Let’s Encrypt staging CA, stores the result in the machine certificate store and binds it to your HTTPS listener.'
          : 'The agent places one test order with the Let’s Encrypt staging CA and writes the result to the path you chose.'
      }
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
          <DashboardActionButton
            leftIcon={<FiRefreshCw />}
            variant='outline'
            onClick={askAgain}
          >
            Request again
          </DashboardActionButton>
        ) : view.noRetry ? (
          <>
            <DashboardActionButton
              leftIcon={<FiRefreshCw />}
              variant='outline'
              onClick={() => refresh()}
            >
              Check again
            </DashboardActionButton>
            <DashboardActionButton variant='outline' onClick={askAgain}>
              I reviewed the job log, request again
            </DashboardActionButton>
          </>
        ) : (
          <DashboardActionButton
            leftIcon={<FiRefreshCw />}
            variant='outline'
            onClick={() => refresh()}
          >
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
        {view.failed && windows ? (
          <Text fontSize='sm'>
            Check the job log, then request again. The ACME client path and the
            HTTPS listener (usually an IIS site) must exist on the host, and the
            agent must be allowed to run that client.
          </Text>
        ) : null}
        {view.failed && !windows ? (
          <Text fontSize='sm'>
            A failed order leaves an entry in <code>provisioning</code> that
            still holds <code>{saved.certPath}</code>, so asking again with the
            same path is rejected. Go back and choose a different file name in
            the same folder, then request again.
          </Text>
        ) : null}
        {view.noRetry ? (
          <Text fontSize='sm'>
            {jobReloadService
              ? `The certificate may already be on disk, but the ${jobReloadLabel} check or reload failed, so the server was not reloaded and nothing was rolled back. Fix the ${jobReloadLabel} configuration, then check the job log before asking again.`
              : 'The agent may have placed the order before the result was lost. Review the job log before asking again.'}
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
        <Text fontSize='sm' data-testid='reload-note'>
          {windows
            ? `The agent stores the certificate in the ${saved.iisStore || 'My'} machine store and binds it to the HTTPS binding ${saved.iisSite || 'Default Web Site'} (usually an IIS site) on port ${saved.iisPort || 443}, replacing the certificate currently bound there.`
            : saved.reloadService
              ? `After writing the certificate, the agent checks ${reloadLabel} and then reloads it with systemctl. The configuration test happens in that check (Apache, HAProxy) or in the unit's own reload (nginx, Apache, HAProxy), so a broken configuration is not loaded.`
              : 'The certificate is written to the path above. Nothing is reloaded; you can choose a web server to reload in the configuration step.'}
        </Text>
        {view.done ? (
          <Text fontSize='sm'>
            {windows
              ? `The certificate was issued and bound to the HTTPS binding ${saved.iisSite || 'Default Web Site'}.`
              : `The certificate was issued and written to ${saved.certPath}.`}{' '}
            Installing it into a web server and renewal are separate steps.
          </Text>
        ) : null}
      </VStack>
    </StepFrame>
  );
}
