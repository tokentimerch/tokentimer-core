import { useEffect, useState } from 'react';
import { FiRefreshCw } from 'react-icons/fi';
import {
  Checkbox,
  FormControl,
  FormErrorMessage,
  FormLabel,
  HStack,
  Input,
  Radio,
  RadioGroup,
  Select,
  Text,
  VStack,
} from '@chakra-ui/react';
import { DashboardActionButton } from '../DashboardPrimitives';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import { createJob, getJob } from '../certops/certopsJobsApi.js';
import StepFrame from './StepFrame.jsx';
import PrimaryButton from './PrimaryButton.jsx';
import { CopyBlock, ErrorText } from './blocks.jsx';
import {
  agentOnPlatform,
  candidateAgents,
  capabilityGap,
  effectiveInfrastructure,
  pickGoalAgent,
  reportedCertificates,
  requiredCapabilities,
} from './certopsMatrix.js';
import {
  buildVaultConfigs,
  buildVaultPolicies,
  buildVaultPublishJob,
  buildInstallCommand,
  NGINX_RELOAD_DROPIN,
  buildVaultAgentConfig,
  buildVaultAgentHostSetup,
  buildVaultRoleCommands,
  buildConsumerNginxServer,
  buildServerSnippet,
  RELOAD_SERVICES,
  buildConsumerPlaceholderCommand,
  buildReconcileCommand,
  AGENT_STATE_DIR,
  CONSUMER_DEPLOY_PATH,
  probeHostFor,
  vaultPublishIdempotencyKey,
} from './certopsConfig.js';
import { certopsProgress, saveCertops } from './certopsSetupSteps.jsx';
import { chooseDistribution } from './certopsScope.js';
import { scopeDistribution } from './distributionModel.js';
import ExistingDistributionPick, {
  reusableDistributions,
} from './ExistingDistributionPick.jsx';
import IssueStep from './certopsIssueStep.jsx';
import {
  ApprovalPolicyNote,
  ApprovalWaitPanel,
  useJobApprovalPolicy,
} from './approvalPolicy.jsx';
import { outboxBacklogMessage } from './certopsWorkerMessages.js';
import JobActivity, { JobTimelineList } from './JobActivity.jsx';
import {
  Callout,
  DetailsSection,
  StatusPanel,
  StatusTag,
  StepCard,
} from './panels.jsx';
import {
  WAIT_POLL_MS,
  useSummaryPolling,
  vaultNeedsPolling,
} from './useSummaryPolling.js';
import WorkerWarning from './WorkerWarning.jsx';
import { VaultAgentTest, VaultRolloutGuide } from './VaultGuidedOperations.jsx';
import ConsumerBootstrapToken from './ConsumerBootstrapToken.jsx';

/** A UUID the operator uses for the consumer binding (not secret). */
function newBindingId() {
  const c = globalThis.crypto;
  if (c?.randomUUID) return c.randomUUID();
  return '00000000-0000-4000-8000-000000000001';
}

export function FirstCertificateStep({ ctx }) {
  const saved = certopsProgress(ctx);
  if (saved.objective === 'automate') {
    return <IssueStep ctx={ctx} />;
  }
  return <DiscoveredCertificateStep ctx={ctx} />;
}

function DiscoveredCertificateStep({ ctx }) {
  const { muted } = useDashboardTheme();
  const saved = certopsProgress(ctx);
  const certs = ctx.summary?.certops?.certificates;
  const workspaceTotal = certs?.observed ?? certs?.total ?? 0;
  const infra = effectiveInfrastructure(saved.objective, saved.infrastructure);
  const total = reportedCertificates(ctx.summary?.certops, {
    infrastructure: infra,
    clusterId: saved.clusterId,
    agentId: saved.chosenAgentId,
  });
  // The agent reports on its own schedule: read again until one arrives.
  useSummaryPolling(ctx.refresh, total === 0, WAIT_POLL_MS);
  // Only what the summary really carries: the agent's last check-in, or the
  // controller's last report. Nothing is inferred.
  const discoveryEvents =
    saved.infrastructure === 'kubernetes'
      ? (ctx.summary?.certops?.controllers?.clusters || [])
          .filter(c => c.lastReportedAt)
          .filter(c => !saved.clusterId || c.clusterId === saved.clusterId)
          .map(c => ({
            id: `cluster-${c.clusterId}`,
            at: c.lastReportedAt,
            label: `Controller report from ${c.clusterId}`,
            status: 'done',
          }))
      : candidateAgents(
          ctx.summary?.certops?.agents?.items,
          saved.chosenAgentId
        )
          .filter(a => agentOnPlatform(a, infra))
          .filter(a => a.lastSeenAt)
          .slice(0, 3)
          .map(a => ({
            id: `agent-${a.id}`,
            at: a.lastSeenAt,
            label: `Agent ${a.hostname || a.name || 'check-in'} last seen`,
            status: a.livenessState === 'live' ? 'done' : 'waiting',
          }));
  return (
    <StepFrame
      kind='verify'
      title='See your first certificate'
      description={`This confirms ${
        saved.infrastructure === 'kubernetes' ? 'the controller' : 'the agent'
      } is reporting real certificates into your inventory.`}
      docs={[
        ...ctx.docs('certops.inventory', 'Certificate inventory'),
        ...ctx.docs('certops.discovery', 'How discovery works'),
      ]}
      actions={
        <DashboardActionButton
          leftIcon={<FiRefreshCw />}
          variant='outline'
          onClick={() => ctx.refresh()}
        >
          Check again
        </DashboardActionButton>
      }
    >
      <VStack align='stretch' spacing={4}>
        {total > 0 ? (
          <StatusPanel
            status='success'
            title={`${total} certificate${total === 1 ? '' : 's'} in the inventory`}
          >
            Open Certificate Management, Certificates to inspect each one:
            identity, validity, observed locations and monitoring status.
          </StatusPanel>
        ) : (
          <StatusPanel status='info' title='No certificates reported yet'>
            This page checks again every 10 seconds. Use Check again to look
            now.
          </StatusPanel>
        )}
        {total === 0 && workspaceTotal > 0 ? (
          <Text fontSize='xs' color={muted} data-testid='not-from-agent'>
            The inventory already holds {workspaceTotal} certificate
            {workspaceTotal === 1 ? '' : 's'} (for example from a website
            monitor). They do not count here: this step waits for{' '}
            {saved.infrastructure === 'kubernetes'
              ? 'the Kubernetes controller'
              : 'your agent'}{' '}
            to report one.
          </Text>
        ) : null}
        {discoveryEvents.length > 0 ? (
          <JobTimelineList
            label='Discovery timeline'
            events={discoveryEvents}
          />
        ) : null}
        {total === 0 ? (
          <Callout kind='check' title='If nothing shows up'>
            <Text fontSize='sm'>
              {saved.infrastructure === 'windows'
                ? 'Discovery on Windows runs about every 30 minutes by default and reads the machine certificate store. Check that the agent service is running and that certificates exist in LocalMachine\\My. Private keys are never read.'
                : saved.infrastructure === 'kubernetes'
                  ? 'The controller reports cert-manager Certificates, so the cluster needs at least one. Read the controller pod logs and confirm the token is bound to this cluster id.'
                  : 'Discovery runs about once an hour by default. Make sure the folders you listed contain a PEM certificate and that the agent user can read them. Private keys are never read.'}
            </Text>
          </Callout>
        ) : null}
      </VStack>
    </StepFrame>
  );
}

/**
 * Two honest outcomes. Generated files only ever reach "Configuration
 * prepared". "Distribution verified" requires a rollout that the control plane
 * recorded as verified, which in turn requires qualified agents.
 */
export function vaultOutcome({ declaredByAgents, distribution }) {
  const required = requiredCapabilities('vault', 'linux');
  const missing = required.filter(c => !declaredByAgents.includes(c));
  if (distribution?.verified) return { level: 'verified', missing: [] };
  if (distribution?.completed) return { level: 'installed', missing: [] };
  if (missing.length === 0 && distribution?.groups > 0) {
    return { level: 'ready_to_roll_out', missing: [] };
  }
  return { level: 'prepared', missing };
}

/** A numbered part of the Vault guide, with who runs it and as which user. */
function Part({ n, title, who, children }) {
  return (
    <StepCard n={n} title={title} who={who} testId={`vault-part-${n}`}>
      {children}
    </StepCard>
  );
}

// Field names for the line that says why Save is off.
const VAULT_FIELD_NAMES = {
  vaultAddress: 'the Vault address',
  groupId: 'the group id',
  caFile: 'the Vault CA file',
  probeCa: 'the check CA file',
  names: 'the names',
  zone: 'the DNS zone',
  workspace: 'the workspace id',
};

export function VaultStep({ ctx }) {
  const { muted } = useDashboardTheme();
  const saved = certopsProgress(ctx);
  const [form, setForm] = useState({
    vaultAddress: saved.vaultAddress || '',
    mount: saved.vaultMount || 'secret',
    groupId: saved.groupId || '',
    caFile: saved.vaultCaFile || '',
    probeCa: saved.vaultProbeCa || '',
    deliveryMode:
      saved.vaultConsumerDeliveryMode ||
      (saved.vaultConsumers?.length ? 'service' : 'files'),
    reloadService: saved.vaultConsumerReloadService || 'nginx',
    deployPath:
      saved.vaultConsumerDeployPath ||
      (saved.vaultConsumers?.length
        ? CONSUMER_DEPLOY_PATH
        : '/etc/tokentimer/certificates'),
    // Chosen by the operator and used in the consumer config and the
    // assignment call, so it is generated once and kept.
    bindingId: saved.vaultBindingId || newBindingId(),
  });
  const [touched, setTouched] = useState({});
  const [choiceError, setChoiceError] = useState('');
  const blur = key => () =>
    setTouched(t => (t[key] ? t : { ...t, [key]: true }));
  const set = key => e => {
    blur(key)();
    setForm(f => ({ ...f, [key]: e.target.value }));
  };
  const names = (saved.names || '').split(/[\s,]+/).filter(Boolean);
  const reloadConsumer = form.deliveryMode === 'service';
  const consumerSetupLocked = Boolean(
    saved.vaultConsumers?.length ||
    saved.vaultRolloutJobId ||
    saved.vaultRolloutRequestKey
  );
  const changeConsumerSetup = async patch => {
    setChoiceError('');
    try {
      const next = { ...form, ...patch };
      await saveCertops(ctx, {
        vaultConsumerDeliveryMode: next.deliveryMode,
        vaultConsumerReloadService: next.reloadService,
        vaultConsumerDeployPath: next.deployPath,
      });
      setForm(current => ({ ...current, ...patch }));
    } catch (error) {
      setChoiceError(error.message || 'Could not save the consumer setup.');
    }
  };
  // Vault runs on Linux: a Windows agent is neither an issuer nor a consumer.
  // The consumer is a second server the operator picks by name, so every
  // Linux agent is listed; only the default issuer follows the agent choice.
  const agentItems = (ctx.summary?.certops?.agents?.items || []).filter(a =>
    agentOnPlatform(a, 'linux')
  );
  const [issuerPick, setIssuerPick] = useState(saved.vaultIssuerAgentId || '');
  const issuerId =
    issuerPick ||
    pickGoalAgent(
      ctx.summary?.certops?.agents?.items,
      'vault',
      'linux',
      saved.chosenAgentId
    )?.id ||
    '';
  const issuerWireId =
    agentItems.find(a => a.id === issuerId)?.wireAgentId || undefined;
  const [consumerPick, setConsumerPick] = useState(
    saved.vaultConsumerAgentId || ''
  );
  const consumerChoices = agentItems.filter(a => a.id !== issuerId);
  const consumerId = consumerChoices.some(agent => agent.id === consumerPick)
    ? consumerPick
    : consumerChoices[0]?.id || '';
  const consumerWireId =
    consumerChoices.find(a => a.id === consumerId)?.wireAgentId || undefined;
  // Only a distribution with work from this session counts, or the one the
  // operator chose with "My Vault distribution is already set up".
  const chosenDistributionId = saved.chosenDistributionId || '';
  const distribution = scopeDistribution(
    ctx.summary?.certops?.distribution,
    chosenDistributionId
  );
  const reusable = reusableDistributions(ctx.summary?.certops?.distribution);
  const [reuseTicked, setReuseTicked] = useState(Boolean(chosenDistributionId));
  const configInput = {
    issuerAgentId: issuerWireId,
    consumerAgentId: consumerWireId,
    vaultAddress: form.vaultAddress,
    mount: form.mount,
    workspaceId: ctx.workspaceId,
    groupId: form.groupId,
    names,
    zone: saved.zone,
    dnsProvider: saved.dnsProvider || 'cloudflare',
    caEndpoint: saved.caEndpoint || undefined,
    caFile: form.caFile.trim(),
    probeTrustCaFile: form.probeCa.trim(),
    consumerBindingId: form.bindingId,
    consumerDeliveryMode: form.deliveryMode,
    consumerReloadService: form.reloadService,
    deployPath: form.deployPath,
  };
  const out = buildVaultConfigs(configInput);
  // Consumer input errors must not remove the fields needed to correct them.
  const issuerOut = buildVaultConfigs({
    ...configInput,
    consumerDeliveryMode: 'files',
    deployPath: '/etc/tokentimer/certificates',
    probeTrustCaFile: '',
  });
  let policies = null;
  try {
    policies = buildVaultPolicies({
      mount: form.mount,
      workspaceId: ctx.workspaceId,
      groupId: form.groupId,
    });
  } catch {
    policies = null;
  }
  const declared = agentItems.flatMap(a => a.declaredCapabilities || []);
  const outcome = vaultOutcome({
    declaredByAgents: declared,
    distribution,
  });
  const gap = capabilityGap('vault', 'linux', declared);
  const backlogMessage = outboxBacklogMessage(ctx.summary?.certops);
  const [pub, setPub] = useState({ job: null, busy: false, error: '' });
  const [issuerStopped, setIssuerStopped] = useState(false);
  const { required: approvalRequired } = useJobApprovalPolicy(ctx.workspaceId);
  const publishJobId = saved.vaultPublishJobId || '';
  const [publicationAttempt] = useState(newBindingId);
  const publishKey =
    saved.vaultPublishRequestKey ||
    `${vaultPublishIdempotencyKey({
      names,
      zone: saved.zone,
      dnsProvider: saved.dnsProvider || 'cloudflare',
      caEndpoint: saved.caEndpoint || undefined,
      agentId: issuerId,
    })}-${publicationAttempt}`;
  const publishJob = buildVaultPublishJob({
    names,
    zone: saved.zone,
    dnsProvider: saved.dnsProvider || 'cloudflare',
    caEndpoint: saved.caEndpoint || undefined,
    assignedAgentId: issuerId || 'ISSUER_AGENT_ID_FROM_AGENTS',
    idempotencyKey: issuerId ? publishKey : 'vault-publish-1',
  });
  const { workspaceId, refresh } = ctx;

  // The job is read back from the server, never from a stored flag. It is
  // polled while it is still moving, so an approval elsewhere shows up here.
  const publishStatus = pub.job?.status || '';
  const publishSettled = [
    'succeeded',
    'failed',
    'rejected',
    'cancelled',
  ].includes(publishStatus);
  useEffect(() => {
    if (!publishJobId) return undefined;
    let cancelled = false;
    const load = async () => {
      try {
        const res = await getJob(workspaceId, publishJobId);
        const job = res?.job || res;
        if (!job?.id) throw new Error('The publish job could not be read.');
        if (!cancelled) setPub(p => ({ ...p, job }));
      } catch {
        if (!cancelled) setPub(p => ({ ...p, job: null }));
      }
    };
    load();
    if (publishSettled) {
      return () => {
        cancelled = true;
      };
    }
    const timer = setInterval(load, 5000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [publishJobId, workspaceId, publishSettled]);

  // The backlog warning and the rollout state change on the server, so the
  // summary is re-read while either could still move.
  useSummaryPolling(
    refresh,
    vaultNeedsPolling({
      backlogMessage,
      distribution,
      publishActive: Boolean(publishJobId) && !publishSettled,
    })
  );

  // Reusing a distribution is the operator's choice; Continue confirms it.
  const saveDistributionChoice = async id => {
    setChoiceError('');
    try {
      await ctx.controller.update(session => ({
        progress: {
          ...session.progress,
          certops: chooseDistribution(session.progress?.certops, 'vault', id),
        },
      }));
      await refresh();
    } catch (e) {
      setChoiceError(e.message || 'Could not save your choice.');
    }
  };
  const confirmDistribution = async () => {
    setChoiceError('');
    try {
      await saveCertops(ctx, {
        chosenDistributionConfirmed: chosenDistributionId,
      });
    } catch (e) {
      setChoiceError(e.message || 'Could not save your progress.');
    }
  };
  const confirmed =
    Boolean(chosenDistributionId) &&
    saved.chosenDistributionConfirmed === chosenDistributionId;

  const createPublishJob = async () => {
    if (
      pub.busy ||
      publishJobId ||
      !issuerStopped ||
      !issuerId ||
      !names.length ||
      !saved.zone
    )
      return;
    setPub(p => ({ ...p, busy: true, error: '' }));
    try {
      // Persist the exact request key before submission. A lost response can
      // be retried after reload; Start over creates a new setup attempt.
      await saveCertops(ctx, {
        vaultPublishRequestKey: publishKey,
        vaultIssuerAgentId: issuerId,
        vaultConsumerAgentId: consumerId,
        vaultBindingId: form.bindingId,
      });
      // The same key always maps to the same job server-side, so a reload or
      // a second click returns the existing job.
      const res = await createJob(workspaceId, publishJob);
      const created = res.job || res;
      const groupId = created.payload?.publication?.groupId || '';
      await saveCertops(ctx, {
        vaultPublishJobId: created.id,
        vaultIssuerAgentId: issuerId,
        vaultConsumerAgentId: consumerId,
        vaultBindingId: form.bindingId,
        ...(groupId ? { groupId } : {}),
      });
      if (groupId) setForm(f => ({ ...f, groupId }));
      setPub({ job: created, busy: false, error: '' });
      await refresh();
    } catch (e) {
      setPub(p => ({
        ...p,
        busy: false,
        error:
          e?.response?.data?.error ||
          e?.message ||
          'The job could not be created.',
      }));
    }
  };
  const { bindingId } = form;
  const [savedOk, setSavedOk] = useState(false);
  const shownErrors = key => (touched[key] ? out.fieldErrors?.[key] || [] : []);
  const missingFields = Object.keys(out.fieldErrors || {}).map(
    k => VAULT_FIELD_NAMES[k] || k
  );
  const saveSettings = async () => {
    await saveCertops(ctx, {
      vaultAddress: form.vaultAddress,
      vaultMount: form.mount,
      vaultCaFile: form.caFile.trim(),
      vaultProbeCa: form.probeCa.trim(),
      vaultBindingId: form.bindingId,
      vaultConsumerAgentId: consumerId,
      groupId: form.groupId,
      configReviewed: true,
      vaultConsumerDeliveryMode: form.deliveryMode,
      vaultConsumerReloadService: form.reloadService,
      vaultConsumerDeployPath: form.deployPath,
    });
    setSavedOk(true);
  };
  let consumerInstall = '';
  try {
    consumerInstall = buildInstallCommand({
      os: 'linux',
      apiUrl: ctx.apiUrl,
      workspaceId: ctx.workspaceId,
      writePaths: out.ok ? [form.deployPath] : [],
      reloadServices: reloadConsumer ? [form.reloadService] : [],
    });
  } catch (e) {
    consumerInstall = e.message;
  }

  return (
    <StepFrame
      kind='runbook'
      title='Share a certificate through Vault'
      description='The issuing agent publishes the certificate to your Vault and other agents pull and install it. TokenTimer never connects to Vault.'
      docs={[
        ...ctx.docs('certops.vault', 'Shared certificate runbook'),
        ...ctx.docs('certops.vaultAuth', 'Vault Agent authentication'),
        ...ctx.docs('certops.worker', 'Check the CertOps worker'),
      ]}
      actions={
        <VStack align='flex-end' spacing={1}>
          {chosenDistributionId && !confirmed ? (
            <PrimaryButton
              onClick={confirmDistribution}
              isDisabled={!distribution?.verified && !distribution?.completed}
              data-testid='vault-use-distribution'
            >
              Continue
            </PrimaryButton>
          ) : null}
          <PrimaryButton onClick={saveSettings} isDisabled={!out.ok}>
            Save these settings
          </PrimaryButton>
          {!out.ok ? (
            <Text fontSize='xs' color={muted} data-testid='vault-save-hint'>
              Save stays disabled until these are valid:{' '}
              {missingFields.join(', ')}.
            </Text>
          ) : savedOk ? (
            <Text fontSize='xs' color={muted} data-testid='vault-saved'>
              Saved. This step finishes by itself once a rollout is verified.
            </Text>
          ) : null}
        </VStack>
      }
    >
      <VStack align='stretch' spacing={4}>
        <StatusPanel
          status='warning'
          title='Prepare, publish and deploy from this guide'
        >
          Apply the generated configuration on the hosts, then return here to
          send signed checks, publish and deploy. Live deployment is only
          confirmed by the returned consumer verification evidence.
        </StatusPanel>
        {choiceError ? (
          <StatusPanel status='error' testId='vault-choice-error'>
            {choiceError}
          </StatusPanel>
        ) : null}
        <ExistingDistributionPick
          items={reusable}
          ticked={reuseTicked && reusable.length > 0}
          distributionId={chosenDistributionId}
          onTick={on => {
            setReuseTicked(on);
            if (!on) saveDistributionChoice(null);
          }}
          onDistribution={saveDistributionChoice}
        />
        {!reuseTicked && reusable.length > 0 ? (
          <Text
            fontSize='xs'
            color={muted}
            data-testid='existing-distributions-note'
          >
            {reusable.length === 1
              ? '1 completed distribution is already in this workspace. Follow the guide below for a new one, or tick the box to use it.'
              : `${reusable.length} completed distributions are already in this workspace. Follow the guide below for a new one, or tick the box to use one.`}
          </Text>
        ) : null}
        {backlogMessage ? (
          <WorkerWarning testId='vault-backlog-warning'>
            {backlogMessage}
          </WorkerWarning>
        ) : null}
        <HStack>
          <StatusTag
            tone={
              ['verified', 'installed'].includes(outcome.level)
                ? 'green'
                : 'orange'
            }
          >
            {outcome.level === 'verified'
              ? 'Distribution verified'
              : outcome.level === 'installed'
                ? 'Certificate files distributed'
                : 'Setup in progress'}
          </StatusTag>
          {gap.length ? (
            <Text fontSize='xs' color={muted}>
              Agents do not yet declare: {gap.join(', ')}.
            </Text>
          ) : null}
        </HStack>

        <Part
          n={1}
          title='Check your agents and prepare publication'
          who='You, in this dashboard (workspace manager)'
        >
          <Text fontSize='sm'>
            The issuing agent orders the certificate and publishes it to Vault.
            The group id appears on the job and is filled in below.
            {approvalRequired === false && !publishJobId
              ? ' Complete signed no-op smoke checks first. Stop only the issuing TokenTimer agent service before creating this job, and keep it stopped while you apply the returned group id to Vault policy and the local configuration in parts 2 to 5. Once ready, restart with execution enabled and dryRun false; do not start another dry-run polling phase while this real job is queued.'
              : ''}
          </Text>
          {!publishJobId ? (
            <ApprovalPolicyNote required={approvalRequired} />
          ) : null}
          <FormControl>
            <FormLabel fontSize='sm'>Issuing agent</FormLabel>
            <Select
              size='sm'
              value={issuerId}
              onChange={e => setIssuerPick(e.target.value)}
              isDisabled={Boolean(publishJobId || saved.vaultPublishRequestKey)}
              placeholder={
                agentItems.length ? undefined : 'No agent registered'
              }
            >
              {agentItems.map(a => (
                <option key={a.id} value={a.id}>
                  {a.name || a.hostname || 'agent'} ({a.wireAgentId})
                </option>
              ))}
            </Select>
          </FormControl>
          <VStack align='stretch' spacing={3}>
            <Text fontSize='sm'>
              With local execution enabled and dryRun true, send a signed test
              to the issuer here. If you already tested it in this guide, its
              existing result is shown. This does not issue or deploy
              certificates. Consumer checks belong to their assigned host
              configurations in part 6. After the issuer check completes, stop
              the issuing TokenTimer service while you prepare the
              group-specific configuration below.
            </Text>
            <VaultAgentTest
              key={`issuer/${issuerId}`}
              ctx={ctx}
              agent={agentItems.find(a => a.id === issuerId)}
              isIssuer
              disabled={Boolean(publishJobId)}
            />
            {!publishJobId ? (
              <>
                <CopyBlock
                  label='Stop the issuing agent while preparing Vault'
                  text='sudo systemctl stop tokentimer-agent'
                />
                <Checkbox
                  isChecked={issuerStopped}
                  onChange={e => setIssuerStopped(e.target.checked)}
                >
                  The issuing TokenTimer agent is stopped while I prepare Vault
                </Checkbox>
              </>
            ) : null}
          </VStack>
          <HStack align='center' spacing={3} flexWrap='wrap'>
            <DashboardActionButton
              variant='outline'
              onClick={createPublishJob}
              isLoading={pub.busy}
              isDisabled={
                Boolean(publishJobId) ||
                !issuerId ||
                !issuerStopped ||
                names.length === 0 ||
                !saved.zone
              }
            >
              Create the publish job
            </DashboardActionButton>
            {publishJobId ? (
              <Text fontSize='sm' data-testid='vault-publish-job'>
                Publish job {publishJobId}
                {pub.job?.status ? (
                  <>
                    {' '}
                    <StatusTag>{pub.job.status}</StatusTag>
                  </>
                ) : null}
              </Text>
            ) : null}
          </HStack>
          {!publishJobId ? (
            <Text
              fontSize='xs'
              color={muted}
              data-testid='vault-publication-prerequisites'
            >
              {!issuerId
                ? 'Select the issuing agent before creating publication.'
                : names.length === 0 || !saved.zone
                  ? 'Complete the certificate names and DNS zone before creating publication.'
                  : !issuerStopped
                    ? 'Stop only the issuing agent using the command above, then confirm the checkbox to enable publication.'
                    : 'Ready to create publication. Consumers can be registered and assigned later in part 6.'}
            </Text>
          ) : null}
          {pub.error ? <ErrorText>{pub.error}</ErrorText> : null}
          <ApprovalWaitPanel job={pub.job} />
          {pub.job?.status === 'pending_approval' ? (
            <Text fontSize='xs' color={muted}>
              After approval the issuing agent must be online and out of dry
              run.
            </Text>
          ) : null}
          {publishJobId ? (
            <JobActivity
              workspaceId={workspaceId}
              jobId={publishJobId}
              title='What happened to the publish job'
            />
          ) : null}
        </Part>

        <Part
          n={2}
          title='Enter your Vault details'
          who='You, in this dashboard'
        >
          {['names', 'zone'].some(k => out.fieldErrors?.[k]) ? (
            <ErrorText>
              Go back to the configuration step: the names and the DNS zone must
              be valid.
            </ErrorText>
          ) : null}
          <HStack align='start' spacing={3} flexWrap='wrap'>
            <FormControl
              flex='2 1 240px'
              isInvalid={shownErrors('vaultAddress').length > 0}
            >
              <FormLabel fontSize='sm'>Vault address</FormLabel>
              <Input
                size='sm'
                value={form.vaultAddress}
                onChange={set('vaultAddress')}
                onBlur={blur('vaultAddress')}
                placeholder='https://vault.example.com:8200'
              />
              <FormErrorMessage fontSize='xs'>
                {shownErrors('vaultAddress').map(m => (
                  <ErrorText key={m} as='span' display='block'>
                    {m}
                  </ErrorText>
                ))}
              </FormErrorMessage>
            </FormControl>
            <FormControl flex='1 1 120px'>
              <FormLabel fontSize='sm'>KV v2 mount</FormLabel>
              <Input size='sm' value={form.mount} onChange={set('mount')} />
            </FormControl>
          </HStack>
          <FormControl isInvalid={shownErrors('groupId').length > 0}>
            <FormLabel fontSize='sm'>Group id</FormLabel>
            <Input
              size='sm'
              value={form.groupId}
              onChange={set('groupId')}
              onBlur={blur('groupId')}
              placeholder='from publication.groupId'
            />
            <FormErrorMessage fontSize='xs'>
              {shownErrors('groupId').map(m => (
                <ErrorText key={m} as='span' display='block'>
                  {m}
                </ErrorText>
              ))}
            </FormErrorMessage>
            <Text fontSize='xs' mt={1} color={muted}>
              Filled in for you once the publish job in part 1 exists.
            </Text>
          </FormControl>
          <FormControl isInvalid={shownErrors('caFile').length > 0}>
            <FormLabel fontSize='sm'>Vault CA file (optional)</FormLabel>
            <Input
              size='sm'
              value={form.caFile}
              onChange={set('caFile')}
              onBlur={blur('caFile')}
              placeholder='/etc/tokentimer-agent/vault-ca.pem'
            />
            <FormErrorMessage fontSize='xs'>
              {shownErrors('caFile').map(m => (
                <ErrorText key={m} as='span' display='block'>
                  {m}
                </ErrorText>
              ))}
            </FormErrorMessage>
            <Text fontSize='xs' mt={1} color={muted}>
              Needed when Vault uses a private CA. The file stays on each host.
            </Text>
          </FormControl>
          <FormControl isInvalid={shownErrors('probeCa').length > 0}>
            <FormLabel fontSize='sm'>
              CA file for the consumer&apos;s served-certificate check
              (optional)
            </FormLabel>
            <Input
              size='sm'
              value={form.probeCa}
              onChange={set('probeCa')}
              onBlur={blur('probeCa')}
              placeholder='/etc/tokentimer-agent/issuing-ca.pem'
            />
            <FormErrorMessage fontSize='xs'>
              {shownErrors('probeCa').map(m => (
                <ErrorText key={m} as='span' display='block'>
                  {m}
                </ErrorText>
              ))}
            </FormErrorMessage>
            <Text fontSize='xs' mt={1} color={muted}>
              Needed when the certificate comes from a private CA or a test CA
              such as the Let&apos;s Encrypt staging CA: the consumer&apos;s
              trust check validates the chain against this file and fails
              without it. Use the root of the issuing CA, readable by
              tokentimer-agent on the consumer host.
            </Text>
          </FormControl>
          <DashboardActionButton
            variant='outline'
            onClick={saveSettings}
            isDisabled={!out.ok}
          >
            Save Vault connection settings
          </DashboardActionButton>
          {savedOk ? (
            <Text fontSize='xs' color={muted}>
              Vault connection settings saved.
            </Text>
          ) : null}
          <Text fontSize='xs' color={muted}>
            Consumer binding id (generated, keep it): {form.bindingId}
          </Text>
          {!out.ok ? (
            <Text fontSize='xs' color={muted}>
              The commands and files in parts 3 to 6 appear once these values
              are valid.
            </Text>
          ) : null}
        </Part>

        {issuerOut.ok ? (
          <>
            <Part
              n={3}
              title='Create the Vault policies and roles'
              who='Vault administrator, with the vault CLI'
            >
              {policies ? (
                <>
                  <CopyBlock
                    label='Vault policy: issuer (separate policy)'
                    text={policies.issuer}
                  />
                  <CopyBlock
                    label='Vault policy: consumer (separate policy)'
                    text={policies.consumer}
                  />
                  <CopyBlock
                    label='Vault policy: scanner (mandatory deny)'
                    text={policies.scanner}
                  />
                </>
              ) : null}
              <CopyBlock
                label='Vault administrator: AppRoles (save the two policies above as issuer.hcl and consumer.hcl)'
                text={buildVaultRoleCommands()}
              />
            </Part>

            <Part
              n={4}
              title='Prepare the issuing server'
              who='root (sudo) on the issuing server, then the agent user'
            >
              <Text fontSize='xs' color={muted}>
                Both configs name an agent by its wire id (agentId, and the
                consumer repeats it in materialBindings). Choose each id before
                the agent registers by setting agentId in its config.json, or
                read it from the registered agent&apos;s config.json and merge
                these keys into that file instead of replacing it. No Vault
                token is ever entered here. Both agents start in dry run.
              </Text>
              <CopyBlock
                label='Issuer agent config.json (merge into the existing file)'
                text={JSON.stringify(issuerOut.issuer, null, 2)}
                language='json'
              />
              <Text fontSize='xs' color={muted} data-testid='vault-auth-note'>
                Authentication to Vault: each agent reads a Vault token from a
                file (tokenFile) and has no login of its own, so AppRole,
                Kubernetes or other auth methods are handled by Vault Agent,
                which keeps that file fresh. The file must be owned by the agent
                user with mode 0600. The example uses AppRole: create the role
                with the policy above, put its role id and secret id in two
                files readable only by the user that runs Vault Agent, and run
                Vault Agent as the agent user.
              </Text>
              <CopyBlock
                label='Vault Agent config (AppRole, writes the issuer token file)'
                text={buildVaultAgentConfig({
                  vaultAddress: form.vaultAddress,
                  caFile: form.caFile.trim(),
                })}
              />
              <CopyBlock
                label='On each agent host: Vault Agent folders and start (needs the Vault binary)'
                text={buildVaultAgentHostSetup()}
              />
            </Part>

            <Part
              n={5}
              title='Prepare the consumer server'
              who='root (sudo) on the consumer server, then the agent user'
            >
              <ConsumerBootstrapToken workspaceId={ctx.workspaceId} />
              <FormControl as='fieldset'>
                <FormLabel as='legend' fontSize='sm'>
                  Consumer delivery
                </FormLabel>
                <RadioGroup
                  value={form.deliveryMode}
                  onChange={deliveryMode =>
                    changeConsumerSetup({ deliveryMode })
                  }
                  isDisabled={consumerSetupLocked}
                >
                  <VStack align='start' spacing={2}>
                    <Radio value='files'>
                      Distribute certificate files only
                    </Radio>
                    <Radio value='service'>
                      Distribute and reload a service
                    </Radio>
                  </VStack>
                </RadioGroup>
                <Text fontSize='xs' color={muted}>
                  File distribution does not require a web server, reload or TLS
                  listener. Service reload also checks the certificate served by
                  that service.
                  {consumerSetupLocked
                    ? ' Existing consumer assignments keep their selected delivery policy.'
                    : ''}
                </Text>
              </FormControl>
              {reloadConsumer ? (
                <FormControl>
                  <FormLabel fontSize='sm' htmlFor='vault-consumer-service'>
                    Service to reload
                  </FormLabel>
                  <Select
                    id='vault-consumer-service'
                    size='sm'
                    value={form.reloadService}
                    isDisabled={consumerSetupLocked}
                    onChange={event =>
                      changeConsumerSetup({ reloadService: event.target.value })
                    }
                  >
                    {Object.entries(RELOAD_SERVICES).map(([id, service]) => (
                      <option key={id} value={id}>
                        {service.label}
                      </option>
                    ))}
                  </Select>
                </FormControl>
              ) : null}
              <FormControl
                isInvalid={Boolean(out.fieldErrors?.deployPath?.length)}
              >
                <FormLabel fontSize='sm' htmlFor='vault-consumer-directory'>
                  Certificate destination directory
                </FormLabel>
                <Input
                  id='vault-consumer-directory'
                  size='sm'
                  value={form.deployPath}
                  isDisabled={consumerSetupLocked}
                  onChange={event =>
                    setForm(current => ({
                      ...current,
                      deployPath: event.target.value,
                    }))
                  }
                  onBlur={() =>
                    changeConsumerSetup({ deployPath: form.deployPath })
                  }
                />
                <FormErrorMessage>
                  {out.fieldErrors?.deployPath?.join(' ')}
                </FormErrorMessage>
              </FormControl>
              {reloadConsumer ? (
                <Text fontSize='sm' data-testid='vault-reload-prerequisite'>
                  Service reloads require polkit with JavaScript rules support
                  (0.106 or later). Ubuntu
                  22.04&apos;s default polkit 0.105 cannot enforce this reload
                  policy; use a compatible host such as Ubuntu 24.04. File-only
                  delivery does not need a reload grant.
                </Text>
              ) : null}
              <Text fontSize='sm'>
                Install the Vault binary first, then run the agent install
                command. Its --write-path makes the installer create{' '}
                {form.deployPath} owned by tokentimer-agent with mode 0750. That
                folder is the only place the agent writes for this rollout:
                fullchain.pem and{' '}
                {reloadConsumer && form.reloadService === 'haproxy'
                  ? 'fullchain.pem.key'
                  : 'privkey.pem'}{' '}
                (mode 0600, replaced in place) and a .bak copy of the previous
                pair after each change. The Vault CA file only needs to be
                readable by tokentimer-agent.
                {reloadConsumer
                  ? ' Install and configure the selected service; its TLS check also needs the issuing CA when that CA is private.'
                  : ' Installation is verified on disk. No service is contacted or reloaded, and success does not claim the certificate is in use.'}
              </Text>
              {out.ok ? (
                <CopyBlock
                  label='Consumer install command'
                  text={consumerInstall}
                />
              ) : null}
              {reloadConsumer && out.ok ? (
                <>
                  <Text fontSize='sm'>
                    Then create a placeholder pair as the agent user, so the
                    service can start its TLS listener before the first rollout.
                    Do not create these files as root: the agent reads the files
                    it replaces, and root-owned placeholders make the first
                    rollout fail (see the troubleshooting panel at the end).
                    Give the selected service the appropriate read access
                    without making the private key broadly readable.
                  </Text>
                  <CopyBlock
                    label='Placeholder certificate (consumer host, as the agent user)'
                    text={buildConsumerPlaceholderCommand({
                      host: probeHostFor(names) || undefined,
                      deployPath: form.deployPath,
                      keyFileName:
                        form.reloadService === 'haproxy'
                          ? 'fullchain.pem.key'
                          : 'privkey.pem',
                    })}
                  />
                  <CopyBlock
                    label={`${RELOAD_SERVICES[form.reloadService]?.label} configuration (consumer host)`}
                    text={
                      form.reloadService === 'nginx'
                        ? buildConsumerNginxServer({
                            names,
                            deployPath: form.deployPath,
                          })
                        : buildServerSnippet({
                            reloadService: form.reloadService,
                            certPath: `${form.deployPath}/fullchain.pem`,
                            keyPath: `${form.deployPath}/${form.reloadService === 'haproxy' ? 'fullchain.pem.key' : 'privkey.pem'}`,
                          })
                    }
                  />
                  {form.reloadService === 'nginx' ? (
                    <>
                      <Text fontSize='xs' color={muted}>
                        The stock nginx unit does not test its configuration on
                        reload, so run the one-time setup below as well.
                      </Text>
                      <CopyBlock
                        label='One-time nginx setup (consumer host)'
                        text={NGINX_RELOAD_DROPIN}
                      />
                    </>
                  ) : null}
                </>
              ) : null}
              <Text fontSize='sm'>
                Assign each consumer in the next part to generate its matching
                agent configuration, including the returned authorization
                revision and chosen deployment profile.
              </Text>
              <CopyBlock
                label='Vault Agent config for the consumer (writes the consumer token file)'
                text={buildVaultAgentConfig({
                  vaultAddress: form.vaultAddress,
                  caFile: form.caFile.trim(),
                  tokenFile: '/run/tokentimer-vault/consumer-token',
                })}
              />
            </Part>

            <Part
              n={6}
              title='Assign consumers and deploy'
              who='You, in this dashboard (workspace manager)'
            >
              <Text fontSize='sm'>
                Finish the host preparation above and start the issuing agent
                with dryRun false. Follow its publication timeline in part 1. A
                running CertOps worker is required to advance deployments;
                publication alone does not change a consumer service.
              </Text>
              <FormControl>
                <FormLabel fontSize='sm' htmlFor='vault-first-consumer'>
                  First consumer agent
                </FormLabel>
                <Select
                  id='vault-first-consumer'
                  size='sm'
                  value={consumerId}
                  onChange={event => setConsumerPick(event.target.value)}
                  isDisabled={consumerSetupLocked || !consumerChoices.length}
                  placeholder={
                    consumerChoices.length
                      ? undefined
                      : 'Register a consumer using the install command above'
                  }
                >
                  {consumerChoices.map(agent => (
                    <option key={agent.id} value={agent.id}>
                      {agent.name ||
                        agent.hostname ||
                        agent.wireAgentId ||
                        'agent'}
                    </option>
                  ))}
                </Select>
              </FormControl>
              {!consumerChoices.length ? (
                <Text fontSize='sm'>
                  No consumer is registered yet. Prepare and register its agent
                  in part 5, then check again. This does not block creating the
                  publication job.
                </Text>
              ) : null}
              <DashboardActionButton
                variant='outline'
                onClick={() => ctx.refresh()}
              >
                Check registered consumers
              </DashboardActionButton>
              {out.ok ? (
                <VaultRolloutGuide
                  key={`${workspaceId}/${form.groupId}/${consumerId}`}
                  ctx={ctx}
                  groupId={form.groupId}
                  firstAgentId={consumerId}
                  firstBindingId={form.bindingId}
                  agents={consumerChoices}
                  approvalRequired={approvalRequired}
                  config={{
                    vaultAddress: form.vaultAddress,
                    mount: form.mount,
                    workspaceId,
                    groupId: form.groupId,
                    names,
                    zone: saved.zone,
                    dnsProvider: saved.dnsProvider || 'cloudflare',
                    caEndpoint: saved.caEndpoint || undefined,
                    caFile: form.caFile.trim(),
                    probeTrustCaFile: form.probeCa.trim(),
                    consumerDeliveryMode: form.deliveryMode,
                    consumerReloadService: form.reloadService,
                    deployPath: form.deployPath,
                  }}
                />
              ) : (
                <Text fontSize='sm'>
                  Correct the consumer destination above before assigning or
                  deploying.
                </Text>
              )}
            </Part>

            <DetailsSection
              testId='vault-uncertain-note'
              summary='If a rollout fails or reports an uncertain result'
            >
              <Text fontSize='xs' color={muted}>
                A root-owned placeholder or a file the agent cannot overwrite
                makes the first rollout fail with material_install_failed.
              </Text>
              <Text fontSize='xs' color={muted}>
                Before the consumer agent touches a file it records an uncertain
                marker for the binding in {AGENT_STATE_DIR}
                /material-bindings. It clears the marker only after the files
                are installed and checked on disk. With service reload selected,
                the service must also reload and every probe must serve the new
                certificate. If any required action fails (for example a file
                the agent cannot overwrite, or a CA file the check cannot read
                or does not trust, reported as
                material_service_verification_failed), the rollout ends as
                orphaned_unknown_effect and every later attempt for this binding
                fails with material_binding_uncertain until the marker is
                cleared.
              </Text>
              <Text fontSize='xs' color={muted}>
                Repair the cause on the host first. Then run this as the agent
                user. It installs and reloads nothing: it only checks that the
                installed certificate and key are the ones being rolled out and
                that every probe serves them, then clears the marker.
              </Text>
              <CopyBlock
                label='Clear the marker (consumer host)'
                text={buildReconcileCommand(bindingId)}
              />
              <Text fontSize='xs' color={muted}>
                Then use Retry deployment on the affected consumer above and
                resume the rollout. If no file was replaced, the check reports
                material_reconciliation_mismatch and the marker stays: there is
                no other supported command, so prepare the folder as described
                above before the first rollout. Do not delete the files under
                material-bindings or material-locks to force a retry.
              </Text>
            </DetailsSection>
          </>
        ) : null}
      </VStack>
    </StepFrame>
  );
}
