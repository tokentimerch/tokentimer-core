import { useEffect, useState } from 'react';
import { FiRefreshCw } from 'react-icons/fi';
import {
  Box,
  FormControl,
  FormErrorMessage,
  FormLabel,
  HStack,
  Input,
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
  buildVaultConsumerAssignment,
  buildVaultPolicies,
  buildVaultPublishJob,
  buildVaultRollout,
  buildInstallCommand,
  NGINX_RELOAD_DROPIN,
  buildVaultAgentConfig,
  buildVaultAgentHostSetup,
  buildVaultRoleCommands,
  buildConsumerNginxServer,
  buildConsumerPlaceholderCommand,
  buildDryRunJob,
  buildReconcileCommand,
  buildApiCall,
  buildApiRead,
  buildApiSignIn,
  AGENT_STATE_DIR,
  CONSUMER_DEPLOY_PATH,
  probeHostFor,
  vaultPublishIdempotencyKey,
} from './certopsConfig.js';
import { certopsProgress, saveCertops } from './certopsSetupSteps.jsx';
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
    // Chosen by the operator and used in the consumer config and the
    // assignment call, so it is generated once and kept.
    bindingId: saved.vaultBindingId || newBindingId(),
  });
  const [touched, setTouched] = useState({});
  const blur = key => () =>
    setTouched(t => (t[key] ? t : { ...t, [key]: true }));
  const set = key => e => {
    blur(key)();
    setForm(f => ({ ...f, [key]: e.target.value }));
  };
  const names = (saved.names || '').split(/[\s,]+/).filter(Boolean);
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
  const [consumerPick, setConsumerPick] = useState('');
  const consumerChoices = agentItems.filter(a => a.id !== issuerId);
  const consumerId = consumerPick || consumerChoices[0]?.id || '';
  const consumerWireId =
    consumerChoices.find(a => a.id === consumerId)?.wireAgentId || undefined;
  const out = buildVaultConfigs({
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
  });
  let policies = null;
  try {
    policies = buildVaultPolicies({
      mount: form.mount,
      workspaceId: ctx.workspaceId,
      groupId: form.groupId,
    });
  } catch (_) {
    policies = null;
  }
  const declared = agentItems.flatMap(a => a.declaredCapabilities || []);
  const outcome = vaultOutcome({
    declaredByAgents: declared,
    distribution: ctx.summary?.certops?.distribution,
  });
  const gap = capabilityGap('vault', 'linux', declared);
  const backlogMessage = outboxBacklogMessage(ctx.summary?.certops);
  const [pub, setPub] = useState({ job: null, busy: false, error: '' });
  const { required: approvalRequired } = useJobApprovalPolicy(ctx.workspaceId);
  const publishJobId = saved.vaultPublishJobId || '';
  const publishKey = vaultPublishIdempotencyKey({
    names,
    zone: saved.zone,
    dnsProvider: saved.dnsProvider || 'cloudflare',
    caEndpoint: saved.caEndpoint || undefined,
    agentId: issuerId,
  });
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
        if (!cancelled) setPub(p => ({ ...p, job: res.job || res }));
      } catch (_) {
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
      distribution: ctx.summary?.certops?.distribution,
      publishActive: Boolean(publishJobId) && !publishSettled,
    })
  );

  const createPublishJob = async () => {
    setPub(p => ({ ...p, busy: true, error: '' }));
    try {
      // The same key always maps to the same job server-side, so a reload or
      // a second click returns the existing job.
      const res = await createJob(workspaceId, publishJob);
      const created = res.job || res;
      const groupId = created.payload?.publication?.groupId || '';
      await saveCertops(ctx, {
        vaultPublishJobId: created.id,
        vaultIssuerAgentId: issuerId,
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
  const groupPath = form.groupId || 'GROUP_ID';
  const agentRef = id => id || 'AGENT_ID_FROM_AGENTS';
  const saveSettings = async () => {
    await saveCertops(ctx, {
      vaultAddress: form.vaultAddress,
      vaultMount: form.mount,
      vaultCaFile: form.caFile.trim(),
      vaultProbeCa: form.probeCa.trim(),
      vaultBindingId: form.bindingId,
      groupId: form.groupId,
      configReviewed: true,
    });
    setSavedOk(true);
  };
  const apiSignIn = buildApiSignIn({
    apiUrl: ctx.apiUrl,
    workspaceId: ctx.workspaceId,
  });
  let consumerInstall = '';
  try {
    consumerInstall = buildInstallCommand({
      os: 'linux',
      apiUrl: ctx.apiUrl,
      workspaceId: ctx.workspaceId,
      writePaths: [CONSUMER_DEPLOY_PATH],
      reloadServices: ['nginx'],
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
          title='This guide only prepares the configuration'
        >
          The commands below only prepare the configuration. Distribution works
          once a rollout has been verified.
        </StatusPanel>
        {backlogMessage ? (
          <WorkerWarning testId='vault-backlog-warning'>
            {backlogMessage}
          </WorkerWarning>
        ) : null}
        <HStack>
          <StatusTag tone={outcome.level === 'verified' ? 'green' : 'orange'}>
            {outcome.level === 'verified'
              ? 'Distribution verified'
              : outcome.level === 'ready_to_roll_out'
                ? 'Ready to roll out'
                : 'Configuration prepared'}
          </StatusTag>
          {gap.length ? (
            <Text fontSize='xs' color={muted}>
              Agents do not yet declare: {gap.join(', ')}.
            </Text>
          ) : null}
        </HStack>

        <Part
          n={1}
          title='Create the publish job'
          who='You, in this dashboard (workspace manager)'
        >
          <Text fontSize='sm'>
            The issuing agent orders the certificate and publishes it to Vault.
            The group id appears on the job and is filled in below.
            {approvalRequired === false && !publishJobId
              ? ' Create it once the issuing agent is configured and out of dry run (parts 2 to 5).'
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
              isDisabled={Boolean(publishJobId)}
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
          <FormControl>
            <FormLabel fontSize='sm'>Consumer agent</FormLabel>
            <Select
              size='sm'
              value={consumerId}
              onChange={e => setConsumerPick(e.target.value)}
              placeholder={
                consumerChoices.length
                  ? undefined
                  : 'Register the consumer agent first'
              }
            >
              {consumerChoices.map(a => (
                <option key={a.id} value={a.id}>
                  {a.name || a.hostname || 'agent'} ({a.wireAgentId})
                </option>
              ))}
            </Select>
          </FormControl>
          <HStack align='center' spacing={3} flexWrap='wrap'>
            <DashboardActionButton
              variant='outline'
              onClick={createPublishJob}
              isLoading={pub.busy}
              isDisabled={
                Boolean(publishJobId) ||
                !issuerId ||
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
          <Box as='details'>
            <Box as='summary' fontSize='xs' cursor='pointer'>
              Create the same job from the API instead
            </Box>
            <Box mt={2}>
              <CopyBlock
                label='Publish job (uses the sign-in from part 6)'
                text={buildApiCall({
                  method: 'POST',
                  path: 'certops/jobs',
                  body: publishJob,
                })}
              />
            </Box>
          </Box>
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

        {out.ok ? (
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
                text={JSON.stringify(out.issuer, null, 2)}
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
              <Text fontSize='sm'>
                Install nginx and the Vault binary first, then run the install
                command. Its --write-path makes the installer create{' '}
                {CONSUMER_DEPLOY_PATH} owned by tokentimer-agent with mode 0750.
                That folder is the only place the agent writes for this rollout:
                fullchain.pem and privkey.pem (mode 0600, replaced in place) and
                a .bak copy of the previous pair after each change. The Vault CA
                file and the CA file for the check above only need to be
                readable by tokentimer-agent.
              </Text>
              <CopyBlock
                label='Consumer install command'
                text={consumerInstall}
              />
              <Text fontSize='sm'>
                Then create a placeholder pair as the agent user, so nginx can
                start its TLS listener before the first rollout. Do not create
                these files as root: the agent reads the files it replaces, and
                root-owned placeholders make the first rollout fail (see the
                troubleshooting panel at the end). nginx reads the files as
                root, so it needs nothing else.
              </Text>
              <CopyBlock
                label='Placeholder certificate (consumer host, as the agent user)'
                text={buildConsumerPlaceholderCommand({
                  host: probeHostFor(names) || undefined,
                })}
              />
              <CopyBlock
                label='nginx server block (consumer host)'
                text={buildConsumerNginxServer({ names })}
              />
              <Text fontSize='xs' color={muted}>
                The stock nginx unit does not test its configuration on reload,
                so run the one-time setup below as well.
              </Text>
              <CopyBlock
                label='One-time nginx setup (consumer host)'
                text={NGINX_RELOAD_DROPIN}
              />
              <CopyBlock
                label='Consumer agent config.json (merge into the existing file)'
                text={JSON.stringify(out.consumer, null, 2)}
                language='json'
              />
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
              title='Test, assign and roll out'
              who='You, with the API (a different workspace manager approves the rollout)'
            >
              <Text fontSize='sm'>
                These calls need a signed-in workspace manager, not a machine
                token. Run this once in a bash shell on any computer with curl.
                It asks for your TokenTimer email and password and keeps the
                session in a temporary file. API is this TokenTimer address and
                WS is your workspace id; both are filled in for you.
              </Text>
              <CopyBlock label='Sign in for the API calls' text={apiSignIn} />
              <Text
                fontSize='xs'
                color={muted}
                data-testid='vault-dry-run-note'
              >
                A signed dry run proves that an agent receives and verifies
                jobs. Run it once for each agent before you set execution.dryRun
                to false in its config and restart it. A rollout itself has no
                dry run: the first one installs the certificate for real, and a
                later check-only rollout (verificationOnly: true) just compares
                what is installed.
              </Text>
              {approvalRequired === true ? (
                <Text
                  fontSize='xs'
                  color={muted}
                  data-testid='vault-dry-run-approval'
                >
                  Job approval is on for this workspace, so each dry run also
                  waits for a workspace manager other than you to approve it.
                </Text>
              ) : null}
              <CopyBlock
                label='Signed dry run for the issuing agent'
                text={buildApiCall({
                  method: 'POST',
                  path: 'certops/jobs',
                  body: buildDryRunJob({
                    assignedAgentId: agentRef(issuerId),
                    idempotencyKey: `vault-dry-run-${agentRef(issuerId)}`,
                  }),
                })}
              />
              <CopyBlock
                label='Signed dry run for the consumer agent'
                text={buildApiCall({
                  method: 'POST',
                  path: 'certops/jobs',
                  body: buildDryRunJob({
                    assignedAgentId: agentRef(consumerId),
                    idempotencyKey: `vault-dry-run-${agentRef(consumerId)}`,
                  }),
                })}
              />
              <Text fontSize='sm'>
                Once both agents are registered, assign the consumer and request
                a rollout. A rollout always needs approval from a different
                user, whatever the workspace approval setting, and a running
                CertOps worker (the worker-certops service in Compose, the
                certops cron job in Helm). Without the worker an approved
                rollout stays pending and nothing is deployed, and renewals are
                never scheduled.
              </Text>
              <CopyBlock
                label={`Assign the consumer to group ${groupPath}`}
                text={buildApiCall({
                  method: 'PUT',
                  path: `certops/distribution-groups/${groupPath}/consumers/${bindingId}`,
                  body: buildVaultConsumerAssignment({
                    agentRowId: agentRef(consumerId),
                  }),
                })}
              />
              <Text fontSize='xs' color={muted}>
                When the publish job has succeeded, read the version id (the id
                of the newest entry in versions) and put it in the rollout below
                in place of VERSION_ID_FROM_GROUP_VERSIONS.
              </Text>
              <CopyBlock
                label='Find the published version id'
                text={buildApiRead(
                  `certops/distribution-groups/${groupPath}/versions`
                )}
              />
              <CopyBlock
                label='Request the rollout'
                text={buildApiCall({
                  method: 'POST',
                  path: `certops/distribution-groups/${groupPath}/rollouts`,
                  idempotencyKey: 'wizard-vault-rollout-1',
                  body: buildVaultRollout({
                    materialVersionId: 'VERSION_ID_FROM_GROUP_VERSIONS',
                  }),
                })}
              />
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
                are installed, nginx is reloaded and every probe serves the new
                certificate. If any of that fails (for example a file the agent
                cannot overwrite, or a CA file the check cannot read or does not
                trust, reported as material_service_verification_failed), the
                rollout ends as orphaned_unknown_effect and every later attempt
                for this binding fails with material_binding_uncertain until the
                marker is cleared.
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
                Then retry the same consumer job (POST
                .../certops/distribution-jobs/JOB_ID/retry) and resume the
                rollout. If no file was replaced, the check reports
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
