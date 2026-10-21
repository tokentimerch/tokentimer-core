import { useEffect, useState } from 'react';
import { FiRefreshCw } from 'react-icons/fi';
import {
  Alert,
  AlertDescription,
  AlertIcon,
  Badge,
  Checkbox,
  HStack,
  Text,
  VStack,
} from '@chakra-ui/react';
import { DashboardActionButton } from '../DashboardPrimitives';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import { createJob, getJob } from '../certops/certopsJobsApi.js';
import StepFrame from './StepFrame.jsx';
import PrimaryButton from './PrimaryButton.jsx';
import { CopyBlock } from './blocks.jsx';
import { pickGoalAgent } from './certopsMatrix.js';
import {
  AGENT_KEYS_DIR,
  agentConfigPathFor,
  agentRestartCommandFor,
  buildIssueJob,
  buildServerSnippet,
  issueIdempotencyKey,
  keyPathFor,
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

export const NO_CLAIM_AFTER_MS = 3 * 60 * 1000;

/**
 * Said once a request has been queued for a while and no agent has claimed
 * it. The API cannot cancel an approved request, so the text says that
 * instead of offering a button that would do nothing.
 */
export function issueWaitNotice({ status, since, now = Date.now() }) {
  if (status !== 'pending' || !since) return null;
  const waited = now - Date.parse(since);
  if (!(waited >= NO_CLAIM_AFTER_MS)) return null;
  return (
    'No agent has taken this request. Check that the agent is online and that its config.json lists the DNS provider you chose, the target names and the command profiles this request needs, then restart it. ' +
    'You cannot cancel this request from here, and until it ends its certificate file path stays locked, so asking again is not possible. Once the agent declares what it needs, it takes this same request.'
  );
}

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
  const agent = pickGoalAgent(
    certops?.agents?.items,
    saved.objective,
    saved.infrastructure
  );
  const job = certops?.issueJob;
  const view = issueView(job);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [acknowledged, setAcknowledged] = useState(false);
  const gate = canRequestIssue({
    agents: certops?.agents,
    dryRun: certops?.dryRun,
    saved,
  });
  const windows = saved.infrastructure === 'windows';
  const configPath = agentConfigPathFor(windows ? 'windows' : 'linux');
  const restartCommand = agentRestartCommandFor(windows ? 'windows' : 'linux');
  const names = (saved.names || '').split(/[\s,]+/).filter(Boolean);
  const attempt = saved.issueAttempt || 1;
  const caEndpoint = saved.caEndpoint || STAGING_CA;
  const reloadLabel = RELOAD_SERVICES[saved.reloadService]?.label || '';
  // Orders made before this was recorded fall back to the current choice.
  const jobReloadService = saved.issueReloadService ?? saved.reloadService;
  const jobReloadLabel = RELOAD_SERVICES[jobReloadService]?.label || '';
  const { refresh } = ctx;

  // The summary has no queue time, so the job itself is read to know how
  // long a request has been waiting for an agent.
  const [queuedAt, setQueuedAt] = useState(null);
  const pendingJobId = job?.status === 'pending' ? job.id : null;
  useEffect(() => {
    if (!pendingJobId) {
      setQueuedAt(null);
      return undefined;
    }
    let cancelled = false;
    getJob(ctx.workspaceId, pendingJobId)
      .then(res => {
        const detail = res.job || res;
        if (!cancelled)
          setQueuedAt(detail.queuedAt || detail.createdAt || null);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [pendingJobId, ctx.workspaceId]);
  const waitNotice = issueWaitNotice({ status: job?.status, since: queuedAt });
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
            isDisabled={!gate.ok || !agent || !acknowledged}
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
          <Alert
            status='warning'
            borderRadius='md'
            alignItems='flex-start'
            data-testid='dryrun-ack-warning'
          >
            <AlertIcon />
            <VStack align='stretch' spacing={2} flex='1' minW={0}>
              <AlertDescription fontSize='sm'>
                Before you request: while <code>execution.dryRun</code> is{' '}
                <code>true</code> the agent refuses real orders, and this page
                cannot see that setting. Open <code>{configPath}</code> on the
                server, set <code>dryRun</code> to <code>false</code> in the
                execution block (keep the other keys, do not replace the file)
                and restart the agent.
              </AlertDescription>
              <CopyBlock label='Restart the agent' text={restartCommand} />
              <Checkbox
                size='sm'
                isChecked={acknowledged}
                onChange={e => setAcknowledged(e.target.checked)}
                data-testid='dryrun-ack'
              >
                I set dryRun to false and restarted the agent
              </Checkbox>
              {!acknowledged ? (
                <Text fontSize='xs' color={muted} data-testid='ack-hint'>
                  The request button stays disabled until you tick this box
                  {gate.ok ? '.' : ` and ${gate.missing.join(', ')} are ready.`}
                </Text>
              ) : null}
            </VStack>
          </Alert>
        ) : null}
        {waitNotice ? (
          <Alert status='warning' borderRadius='md' data-testid='issue-wait'>
            <AlertIcon />
            <AlertDescription fontSize='sm'>{waitNotice}</AlertDescription>
          </Alert>
        ) : null}
        {job?.errorCode === 'AGENT_RESULT_BLOCKED' ? (
          <Text fontSize='sm'>
            The agent refused the order because it is still in dry run. Set{' '}
            <code>execution.dryRun</code> to <code>false</code>, restart it with{' '}
            <code>{restartCommand}</code>, then request again.
          </Text>
        ) : null}
        {job?.errorMessage ? (
          <Alert status='error' borderRadius='md'>
            <AlertIcon />
            <AlertDescription fontSize='sm'>
              {job.errorMessage}
              {job.errorCode ? ` (code: ${job.errorCode})` : ''}
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
            A failed order still reserves the certificate file{' '}
            <code>{saved.certPath}</code> and it cannot be retired, so asking
            again with the same path is rejected. Choose a different file name
            in the same folder (go back to the configuration step), then request
            again.
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
              ? `After writing the certificate, the agent checks that ${reloadLabel} is running and then reloads it with systemctl. The unit's own reload tests the configuration as root, so a broken configuration is not loaded.`
              : 'The certificate is written to the path above. Nothing is reloaded; you can choose a web server to reload in the configuration step.'}
        </Text>
        {!windows && saved.reloadService ? (
          <Text fontSize='xs' color={muted} data-testid='server-running-note'>
            Start {reloadLabel} before you request, for example with its default
            site. The agent checks that the unit is active before it reloads,
            and a stopped server ends the order as Needs review even though the
            certificate was written. Add the lines below to a TLS server block
            once the files exist.
          </Text>
        ) : null}
        {!windows && keyPathFor(saved.certPath) ? (
          <>
            <Text fontSize='sm' data-testid='key-note'>
              The private key is written next to the certificate, to{' '}
              <code>{keyPathFor(saved.certPath)}</code> (mode 0600, owned by the
              agent user tokentimer-agent). A copy also stays in the agent key
              store under <code>{AGENT_KEYS_DIR}</code>. A web server reads its
              certificate files as root when it starts or reloads, so it can
              read the key. Leave the owner and mode alone, or the next renewal
              cannot replace the file.
            </Text>
            <CopyBlock
              label='Point your web server at these files'
              text={buildServerSnippet({
                reloadService: saved.reloadService,
                certPath: saved.certPath,
              })}
            />
          </>
        ) : null}
        {view.done ? (
          <Text fontSize='sm'>
            {windows
              ? `The certificate was issued and bound to the HTTPS binding ${saved.iisSite || 'Default Web Site'}.`
              : `The certificate was issued and written to ${saved.certPath}, with its key in ${keyPathFor(saved.certPath)}.`}{' '}
            Installing it into a web server and renewal are separate steps.
          </Text>
        ) : null}
      </VStack>
    </StepFrame>
  );
}
