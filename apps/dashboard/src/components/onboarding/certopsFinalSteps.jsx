import { useEffect, useState } from 'react';
import { FiRefreshCw } from 'react-icons/fi';
import {
  Alert,
  AlertDescription,
  AlertIcon,
  Badge,
  FormControl,
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
import { CopyBlock } from './blocks.jsx';
import { capabilityGap, requiredCapabilities } from './certopsMatrix.js';
import {
  buildVaultConfigs,
  buildVaultConsumerAssignment,
  buildVaultPolicies,
  buildVaultPublishJob,
  buildVaultRollout,
  buildInstallCommand,
  NGINX_RELOAD_DROPIN,
  buildVaultAgentConfig,
  vaultPublishIdempotencyKey,
} from './certopsConfig.js';
import { certopsProgress, saveCertops } from './certopsSetupSteps.jsx';
import IssueStep from './certopsIssueStep.jsx';

/** A UUID the operator uses for the consumer binding (not secret). */
function newBindingId() {
  const c = globalThis.crypto;
  if (c?.randomUUID) return c.randomUUID();
  return '00000000-0000-4000-8000-000000000001';
}

export function FirstCertificateStep({ ctx }) {
  const { muted } = useDashboardTheme();
  const saved = certopsProgress(ctx);
  const automating = saved.objective === 'automate';
  if (automating) {
    return <IssueStep ctx={ctx} />;
  }
  const certs = ctx.summary?.certops?.certificates;
  const total = certs?.observed ?? certs?.total ?? 0;
  return (
    <StepFrame
      kind='verify'
      title='See your first certificate'
      description='This confirms the agent is reporting real certificates into your inventory.'
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
      <VStack align='stretch' spacing={2}>
        <HStack>
          <Badge colorScheme={total > 0 ? 'green' : 'gray'}>
            {total > 0 ? 'Found' : 'Waiting'}
          </Badge>
          <Text fontSize='sm'>
            {total > 0
              ? `${total} certificate${total === 1 ? '' : 's'} in the inventory.`
              : 'No certificates have been reported yet.'}
          </Text>
        </HStack>
        {total === 0 ? (
          <Text fontSize='xs' color={muted}>
            {saved.infrastructure === 'windows'
              ? 'Discovery on Windows runs about every 30 minutes by default and reads the machine certificate store. Check that the agent service is running and that certificates exist in LocalMachine\\My. Private keys are never read.'
              : 'Discovery runs about once an hour by default. Make sure the folders you listed contain a PEM certificate and that the agent user can read them. Private keys are never read.'}
          </Text>
        ) : (
          <Text fontSize='sm'>
            Open Certificate Management, Certificates to inspect each one:
            identity, validity, observed locations and monitoring status.
          </Text>
        )}
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
  const set = key => e => setForm(f => ({ ...f, [key]: e.target.value }));
  const names = (saved.names || '').split(/[\s,]+/).filter(Boolean);
  const agentItems = ctx.summary?.certops?.agents?.items || [];
  const [issuerPick, setIssuerPick] = useState(saved.vaultIssuerAgentId || '');
  const issuerId = issuerPick || agentItems[0]?.id || '';
  const issuerWireId =
    agentItems.find(a => a.id === issuerId)?.wireAgentId || undefined;
  const out = buildVaultConfigs({
    issuerAgentId: issuerWireId,
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
  const declared = (ctx.summary?.certops?.agents?.items || []).flatMap(
    a => a.declaredCapabilities || []
  );
  const outcome = vaultOutcome({
    declaredByAgents: declared,
    distribution: ctx.summary?.certops?.distribution,
  });
  const gap = capabilityGap('vault', 'linux', declared);
  const [pub, setPub] = useState({ job: null, busy: false, error: '' });
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
  const bindingId = form.bindingId;
  let consumerInstall = '';
  try {
    consumerInstall = buildInstallCommand({
      os: 'linux',
      apiUrl: ctx.apiUrl,
      workspaceId: ctx.workspaceId,
      writePaths: ['/etc/nginx/tokentimer'],
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
      ]}
    >
      <VStack align='stretch' spacing={3}>
        <Alert status='warning' borderRadius='md' variant='left-accent'>
          <AlertIcon />
          <AlertDescription fontSize='sm'>
            Generating files below only prepares the configuration. It does not
            mean distribution works: a verified rollout does.
          </AlertDescription>
        </Alert>
        <HStack>
          <Badge
            colorScheme={outcome.level === 'verified' ? 'green' : 'orange'}
          >
            {outcome.level === 'verified'
              ? 'Distribution verified'
              : outcome.level === 'ready_to_roll_out'
                ? 'Ready to roll out'
                : 'Configuration prepared'}
          </Badge>
          {gap.length ? (
            <Text fontSize='xs' color={muted}>
              Agents do not yet declare: {gap.join(', ')}.
            </Text>
          ) : null}
        </HStack>
        <Text fontSize='sm'>
          1. Create the publish job. It is held for approval, so you can set up
          Vault and the issuer first. A workspace manager other than the person
          who creates it must approve it (Certificate Management, Jobs): you
          cannot approve your own job. Only then does the issuer order the
          certificate and publish it to Vault. The group id appears on the job
          and is filled in below.
        </Text>
        <FormControl>
          <FormLabel fontSize='sm'>Issuing agent</FormLabel>
          <Select
            size='sm'
            value={issuerId}
            onChange={e => setIssuerPick(e.target.value)}
            isDisabled={Boolean(publishJobId)}
            placeholder={agentItems.length ? undefined : 'No agent registered'}
          >
            {agentItems.map(a => (
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
                  <Badge>{pub.job.status}</Badge>
                </>
              ) : null}
            </Text>
          ) : null}
        </HStack>
        {pub.error ? (
          <Text fontSize='xs' color='red.400'>
            {pub.error}
          </Text>
        ) : null}
        {pub.job?.status === 'pending_approval' ? (
          <Text fontSize='xs' color={muted}>
            Waiting for approval by another workspace manager. After approval
            the issuing agent must be online and out of dry run.
          </Text>
        ) : null}
        <CopyBlock
          label='The same job through the API (POST /certops/jobs)'
          text={JSON.stringify(publishJob, null, 2)}
          language='json'
        />
        <HStack align='start' spacing={3} flexWrap='wrap'>
          <FormControl flex='2 1 240px'>
            <FormLabel fontSize='sm'>Vault address</FormLabel>
            <Input
              size='sm'
              value={form.vaultAddress}
              onChange={set('vaultAddress')}
              placeholder='https://vault.example.com:8200'
            />
          </FormControl>
          <FormControl flex='1 1 120px'>
            <FormLabel fontSize='sm'>KV v2 mount</FormLabel>
            <Input size='sm' value={form.mount} onChange={set('mount')} />
          </FormControl>
        </HStack>
        <FormControl>
          <FormLabel fontSize='sm'>Group id</FormLabel>
          <Input
            size='sm'
            value={form.groupId}
            onChange={set('groupId')}
            placeholder='from publication.groupId'
          />
        </FormControl>
        <FormControl>
          <FormLabel fontSize='sm'>Vault CA file (optional)</FormLabel>
          <Input
            size='sm'
            value={form.caFile}
            onChange={set('caFile')}
            placeholder='/etc/tokentimer-agent/vault-ca.pem'
          />
          <Text fontSize='xs' mt={1} color={muted}>
            Needed when Vault uses a private CA. The file stays on each host.
          </Text>
        </FormControl>
        <FormControl>
          <FormLabel fontSize='sm'>
            CA file for the consumer&apos;s served-certificate check (optional)
          </FormLabel>
          <Input
            size='sm'
            value={form.probeCa}
            onChange={set('probeCa')}
            placeholder='/etc/tokentimer-agent/issuing-ca.pem'
          />
          <Text fontSize='xs' mt={1} color={muted}>
            Needed when the certificate comes from a private CA: the
            consumer&apos;s trust check validates the chain against this file
            and fails without it.
          </Text>
        </FormControl>
        <Text fontSize='xs' color={muted}>
          Consumer binding id (generated, keep it): {form.bindingId}
        </Text>
        {!out.ok
          ? (out.problems || []).map(p => (
              <Text key={p} fontSize='xs' color='red.400'>
                {p}
              </Text>
            ))
          : null}
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
        {out.ok ? (
          <>
            <CopyBlock
              label='Issuer agent config.json'
              text={JSON.stringify(out.issuer, null, 2)}
              language='json'
            />
            <CopyBlock
              label='Consumer agent config.json'
              text={JSON.stringify(out.consumer, null, 2)}
              language='json'
            />
            <Text fontSize='xs' color={muted}>
              Both configs name an agent by its wire id (agentId, and the
              consumer repeats it in materialBindings). Choose each id before
              the agent registers by setting agentId in its config.json, or read
              it from the registered agent&apos;s config.json and merge these
              keys into that file instead of replacing it. No Vault token is
              ever entered here. Both agents start in dry run: after a signed
              dry run passes, set execution.dryRun to false in each config and
              restart it.
            </Text>
            <Text fontSize='xs' color={muted} data-testid='vault-auth-note'>
              Authentication to Vault: each agent reads a Vault token from a
              file (tokenFile) and has no login of its own, so AppRole,
              Kubernetes or other auth methods are handled by Vault Agent, which
              keeps that file fresh. The file must be owned by the agent user
              with mode 0600. The example uses AppRole: create the role with the
              policy above, put its role id and secret id in two files readable
              only by the user that runs Vault Agent, and run Vault Agent as the
              agent user.
            </Text>
            <CopyBlock
              label='Vault Agent config (AppRole, writes the issuer token file)'
              text={buildVaultAgentConfig({
                vaultAddress: form.vaultAddress,
                caFile: form.caFile.trim(),
              })}
            />
            <Text fontSize='sm'>
              2. Install the consumer agent on its own host with the same
              installer. It needs its deploy folder and the right to reload the
              server. The stock nginx unit does not test its configuration on
              reload, so run the one-time nginx setup there as well.
            </Text>
            <CopyBlock
              label='Consumer install command'
              text={consumerInstall}
            />
            <CopyBlock
              label='One-time nginx setup (consumer host)'
              text={NGINX_RELOAD_DROPIN}
            />
            <Text fontSize='sm'>
              3. Once both agents are registered, assign the consumer and
              request a rollout. Both are API calls too, and a rollout needs
              approval from a different user and a running CertOps worker.
              Without the worker an approved rollout stays pending and nothing
              is deployed.
            </Text>
            <CopyBlock
              label={`PUT .../certops/distribution-groups/${form.groupId || 'GROUP_ID'}/consumers/${bindingId}`}
              text={JSON.stringify(
                buildVaultConsumerAssignment({
                  agentRowId: 'CONSUMER_AGENT_ID_FROM_AGENTS',
                }),
                null,
                2
              )}
              language='json'
            />
            <CopyBlock
              label={`POST .../certops/distribution-groups/${form.groupId || 'GROUP_ID'}/rollouts (Idempotency-Key header)`}
              text={JSON.stringify(
                buildVaultRollout({
                  materialVersionId: 'VERSION_ID_FROM_GROUP_VERSIONS',
                }),
                null,
                2
              )}
              language='json'
            />
          </>
        ) : null}
        <DashboardActionButton
          alignSelf='flex-start'
          variant='outline'
          onClick={() =>
            saveCertops(ctx, {
              vaultAddress: form.vaultAddress,
              vaultMount: form.mount,
              vaultCaFile: form.caFile.trim(),
              vaultProbeCa: form.probeCa.trim(),
              vaultBindingId: form.bindingId,
              groupId: form.groupId,
              configReviewed: true,
            })
          }
          isDisabled={!out.ok}
        >
          Save these settings
        </DashboardActionButton>
      </VStack>
    </StepFrame>
  );
}
