import { useEffect, useRef, useState } from 'react';
import {
  Checkbox,
  FormControl,
  FormLabel,
  Input,
  Select,
  Text,
  VStack,
} from '@chakra-ui/react';
import StepFrame from './StepFrame.jsx';
import { DashboardActionButton } from '../DashboardPrimitives';
import PrimaryButton from './PrimaryButton.jsx';
import { CopyBlock } from './blocks.jsx';
import { DetailsSection, StatusPanel } from './panels.jsx';
import { certopsProgress, saveCertops } from './certopsSetupSteps.jsx';
import { buildVaultPublishJob, buildVaultPolicies } from './certopsConfig.js';
import { createJob } from '../certops/certopsJobsApi.js';
import { retryDeployment as retryPublication } from './vaultGuideApi.js';
import {
  ApprovalPolicyNote,
  ApprovalWaitPanel,
  useJobApprovalPolicy,
} from './approvalPolicy.jsx';
import { useObservedJob, VaultAgentTest } from './VaultGuidedOperations.jsx';
import JobActivity from './JobActivity.jsx';
import { useSummaryPolling } from './useSummaryPolling.js';
import {
  MATERIAL_PROVIDERS,
  agentRequirements,
  canManageMaterial,
  materialProviderReady,
  materialAgents,
  materialConfigs,
  materialSetup,
  materialStoreSatisfied,
  materialProvider,
  materialSetupPatch,
  materialCertificateInput,
  setupErrors,
} from './materialSetupModel.js';

export function materialActionError(error) {
  const code = error?.response?.data?.error;
  return typeof code === 'string' && /^CERTOPS_[A-Z_]+$/.test(code)
    ? `${code}. Review the job and local policy, then refresh before retrying.`
    : 'The request could not be completed. Check workspace permissions and agent configuration, then retry.';
}
export function LocalStoreFields({
  provider,
  address,
  setAddress,
  mount,
  setMount,
  caFile,
  setCaFile,
}) {
  return (
    <>
      <FormControl>
        <FormLabel>Customer-local store HTTPS address</FormLabel>
        <Input
          value={address}
          onChange={e => setAddress(e.target.value)}
          placeholder={
            provider === 'azure-key-vault'
              ? 'https://customer.vault.azure.net'
              : 'https://store.example.com:8200'
          }
        />
      </FormControl>
      {provider !== 'azure-key-vault' && (
        <FormControl>
          <FormLabel>KV v2 mount</FormLabel>
          <Input value={mount} onChange={e => setMount(e.target.value)} />
        </FormControl>
      )}
      {provider !== 'azure-key-vault' && setCaFile && (
        <FormControl>
          <FormLabel>Store CA file on the agent (optional)</FormLabel>
          <Input
            value={caFile}
            onChange={e => setCaFile(e.target.value)}
            placeholder='/etc/tokentimer-agent/store-ca.pem'
          />
          <Text fontSize='xs' mt={1}>
            TLS trust: Use the store's CA certificate when the agent needs a
            custom trust anchor.
          </Text>
        </FormControl>
      )}
      <Text fontSize='sm'>
        These values only generate a host-local configuration. They are not
        saved to onboarding or sent in jobs. Never paste a token, private key,
        password or credential here.
      </Text>
    </>
  );
}

export function MaterialStoreStep({ ctx }) {
  return <MaterialStoreForm key={ctx.workspaceId} ctx={ctx} />;
}
function MaterialStoreForm({ ctx }) {
  const saved = certopsProgress(ctx);
  const [setup, setSetup] = useState(() => materialSetup(saved));
  const [address, setAddress] = useState('');
  const [mount, setMount] = useState('secret');
  const [caFile, setCaFile] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [stopped, setStopped] = useState(false);
  const [transportPassed, setTransportPassed] = useState(false);
  const [retryReviewed, setRetryReviewed] = useState(false);
  const [jobRefresh, setJobRefresh] = useState(0);
  const [attempt] = useState(() => `wizard-material-${crypto.randomUUID()}`);
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  const agents = materialAgents(ctx);
  const issuer = agents.find(a => a.id === setup.issuerAgentId);
  const provider = materialProvider(setup.provider);
  const providerFact = ctx.capabilities?.items?.find(
    item => item.id === provider?.capability
  );
  const manager = canManageMaterial(ctx);
  const qualified = materialProviderReady(ctx, setup.provider);
  const requirements = agentRequirements(issuer, setup.provider);
  // Preparation queues a signed job while the issuer is deliberately stopped;
  // the backend still requires fresh evidence when that agent claims the job.
  const preparationRequirements = agentRequirements(
    issuer,
    setup.provider,
    'issuer',
    {
      allowStoppedIssuer: stopped && transportPassed,
    }
  );
  const jobId = saved.vaultPublishJobId || '';
  const locked = Boolean(jobId || saved.vaultPublishRequestKey);
  const replaying = Boolean(
    saved.vaultPublishRequestKey && saved.materialPublicationRequest
  );
  const observed = useObservedJob(ctx.workspaceId, jobId, jobRefresh);
  const { required } = useJobApprovalPolicy(ctx.workspaceId);
  useSummaryPolling(ctx.refresh, manager);
  const groups = ctx.summary?.certops?.distribution?.items || [];
  const certificate = materialCertificateInput(saved);
  const { names } = certificate;
  const local = materialConfigs({
    setup,
    address,
    mount,
    caFile: setup.provider === 'azure-key-vault' ? '' : caFile,
    workspaceId: ctx.workspaceId,
    groupId: setup.groupId,
    ...certificate,
    issuerAgentId: issuer?.wireAgentId,
    consumerDeliveryMode: 'files',
  });
  const done = materialStoreSatisfied(ctx.summary, saved);
  const policies =
    local.ok && setup.provider !== 'azure-key-vault'
      ? buildVaultPolicies({
          mount,
          workspaceId: ctx.workspaceId,
          groupId: setup.groupId,
        })
      : null;
  const change = (field, value) =>
    setSetup(s => ({ ...s, [field]: value, groupId: '' }));
  const run = async action => {
    if (!manager || busy) return;
    setBusy(true);
    setError('');
    try {
      await action();
    } catch (e) {
      if (alive.current) setError(materialActionError(e));
    } finally {
      if (alive.current) setBusy(false);
    }
  };
  const retry = () =>
    run(async () => {
      if (
        !qualified ||
        !retryReviewed ||
        !['failed', 'blocked', 'orphaned_unknown_effect'].includes(
          observed.job?.status
        ) ||
        observed.job?.attemptCount >= 3
      )
        return;
      await retryPublication(ctx.workspaceId, jobId);
      setRetryReviewed(false);
      setJobRefresh(index => index + 1);
      await ctx.refresh();
    });
  const save = () =>
    run(async () => {
      if (setupErrors(setup).length) {
        setError(setupErrors(setup).join(' '));
        return;
      }
      await saveCertops(ctx, materialSetupPatch(saved, setup));
    });
  const publish = () =>
    run(async () => {
      if (
        !qualified ||
        (preparationRequirements.length > 0 && !replaying) ||
        !transportPassed ||
        !stopped ||
        jobId ||
        ((!names.length || !saved.zone) && !replaying)
      )
        return;
      if (setupErrors(setup).length) {
        setError(setupErrors(setup).join(' '));
        return;
      }
      const key = saved.vaultPublishRequestKey || attempt;
      const frozen = saved.materialPublicationRequest || {
        ...setup,
        names,
        zone: saved.zone,
        dnsProvider: saved.dnsProvider || 'cloudflare',
        ...(saved.caEndpoint ? { caEndpoint: saved.caEndpoint } : {}),
      };
      // Persist the request identity before POST. A lost response reuses this
      // exact body/key, including after reloading the wizard.
      await saveCertops(ctx, {
        ...materialSetupPatch(saved, setup),
        materialPublicationRequest: frozen,
        vaultPublishRequestKey: key,
        vaultIssuerAgentId: setup.issuerAgentId,
      });
      if (!alive.current) return;
      const result = await createJob(ctx.workspaceId, {
        ...buildVaultPublishJob({
          ...frozen,
          assignedAgentId: frozen.issuerAgentId,
          idempotencyKey: key,
        }),
        mode: 'real',
      });
      if (!alive.current) return;
      const job = result.job || result;
      const groupId = job.payload?.publication?.groupId;
      if (!groupId || !job.id)
        throw new Error('Publication metadata unavailable');
      const next = { ...setup, groupId };
      setSetup(next);
      await saveCertops(ctx, {
        ...materialSetupPatch(saved, next),
        vaultPublishJobId: job.id,
      });
    });
  return (
    <StepFrame
      title='Configure material store'
      kind='runbook'
      description='Choose where the issuing agent publishes shared certificate material. Credentials and private keys stay on customer hosts.'
      docs={[
        ...ctx.docs('certops.vault', 'Material distribution runbook'),
        ...ctx.docs('certops.vaultAuth', 'Vault/OpenBao Agent authentication'),
      ]}
    >
      <VStack align='stretch' spacing={4}>
        {!manager && (
          <StatusPanel status='warning'>
            A workspace manager or owner must configure the material store.
            Read-only access cannot submit jobs.
          </StatusPanel>
        )}
        <FormControl>
          <FormLabel>Material provider</FormLabel>
          <Select
            value={setup.provider}
            isDisabled={!manager || locked}
            onChange={e => change('provider', e.target.value)}
          >
            {!provider && (
              <option value={setup.provider}>Unsupported provider</option>
            )}
            {Object.entries(MATERIAL_PROVIDERS).map(([id, p]) => (
              <option key={id} value={id}>
                {p.label}
              </option>
            ))}
          </Select>
        </FormControl>
        <StatusPanel
          status={qualified ? 'info' : 'warning'}
          title={
            qualified
              ? 'Production-qualified provider path'
              : providerFact?.qualified === false
                ? 'Implemented, production capability unavailable'
                : providerFact?.qualified === true
                  ? 'Provider qualified; requirements incomplete'
                  : 'Qualification status unavailable'
          }
        >
          {qualified
            ? 'Agent capabilities and customer-local policy must still match.'
            : providerFact?.qualified === false
              ? 'Setup instructions are available, but this deployment has not qualified this provider for production. Publication and deployment actions stay disabled. An agent declaration alone cannot enable it.'
              : 'Current capability facts are unavailable or deployment requirements are incomplete. Refresh the capability facts and upgrade API and agents together when needed. Publication stays disabled until the core, distribution and provider requirements are ready.'}
        </StatusPanel>
        <FormControl>
          <FormLabel>Issuing agent</FormLabel>
          <Select
            value={setup.issuerAgentId}
            placeholder='Choose an issuing agent'
            isDisabled={!manager || locked}
            onChange={e => change('issuerAgentId', e.target.value)}
          >
            {agents.map(a => (
              <option key={a.id} value={a.id}>
                {a.name || a.hostname || a.id} ({a.platform})
              </option>
            ))}
          </Select>
        </FormControl>
        {!agents.length && (
          <StatusPanel status='warning'>
            No agents are available. Register a Linux issuer in this workspace,
            then refresh.
          </StatusPanel>
        )}
        {requirements.map(reason => (
          <Text fontSize='sm' key={reason}>
            {reason}
          </Text>
        ))}
        <FormControl>
          <FormLabel>Material store reference</FormLabel>
          <Input
            value={setup.materialStoreRef}
            isDisabled={!manager || locked}
            onChange={e => change('materialStoreRef', e.target.value)}
          />
        </FormControl>
        <FormControl>
          <FormLabel>Issuance profile reference</FormLabel>
          <Input
            value={setup.issuanceProfileRef}
            isDisabled={!manager || locked}
            onChange={e => change('issuanceProfileRef', e.target.value)}
          />
        </FormControl>
        <FormControl>
          <FormLabel>Profile revision</FormLabel>
          <Input
            type='number'
            min={1}
            value={setup.profileRevision}
            isDisabled={!manager || locked}
            onChange={e => change('profileRevision', Number(e.target.value))}
          />
        </FormControl>
        <PrimaryButton onClick={save} isDisabled={!manager || busy || locked}>
          Save public references
        </PrimaryButton>
        <FormControl>
          <FormLabel>Use an existing publication</FormLabel>
          <Select
            value={setup.groupId}
            placeholder='Select a group, or prepare a new publication below'
            isDisabled={!manager || locked}
            onChange={e => {
              const group = groups.find(g => g.id === e.target.value);
              if (group)
                setSetup({
                  provider: group.provider,
                  issuerAgentId: group.issuerAgentId,
                  materialStoreRef: group.materialStoreRef,
                  issuanceProfileRef: group.issuanceProfileRef,
                  profileRevision: group.profileRevision,
                  groupId: group.id,
                });
            }}
          >
            {groups
              .filter(g => g.active)
              .map(g => (
                <option key={g.id} value={g.id}>
                  {g.materialStoreRef} · {g.provider} · {g.id}
                </option>
              ))}
          </Select>
        </FormControl>
        <DashboardActionButton
          variant='outline'
          onClick={() => run(ctx.refresh)}
          isDisabled={!manager || busy}
        >
          Refresh persisted evidence
        </DashboardActionButton>
        <StatusPanel
          status={done ? 'success' : 'info'}
          title={
            done
              ? 'Agent publication verified'
              : 'Store connectivity not yet proven'
          }
        >
          {done
            ? 'The backend accepted an exact-version publication receipt for this provider, issuer and store. This is evidence of publication, not a continuous connectivity probe.'
            : 'A signed no-op only checks dispatch. The browser does not connect to the store. Completion requires a current, accepted publication receipt on this distribution group.'}
        </StatusPanel>
        {manager && (
          <VaultAgentTest
            key={setup.issuerAgentId}
            ctx={ctx}
            agent={issuer}
            isIssuer
            onPassed={setTransportPassed}
            disabled={!qualified || requirements.length > 0 || locked}
          />
        )}
        <DetailsSection
          summary='Prepare a real publication'
          defaultOpen={!setup.groupId || Boolean(jobId && !done)}
        >
          <VStack align='stretch' spacing={3}>
            <StatusPanel status='warning' title='Real certificate issuance'>
              This job issues a certificate and writes private material to the
              customer store. Use your staging CA first. Approval and admission
              checks still apply.
            </StatusPanel>
            <VStack align='stretch' spacing={1} fontSize='sm'>
              <Text fontWeight='semibold'>Prepare publication</Text>
              <Text>
                1. Finish the signed check and stop the issuing agent.
              </Text>
              <Text>
                2. Queue this job, then apply its group ID and policy.
              </Text>
              <Text>
                3. Restart the agent with local execution.dryRun false.
              </Text>
            </VStack>
            <ApprovalPolicyNote required={required} />
            <Checkbox
              isChecked={stopped}
              onChange={e => setStopped(e.target.checked)}
            >
              The issuing agent is stopped while I prepare its group-specific
              configuration
            </Checkbox>
            {!names.length || !saved.zone ? (
              <Text>
                Review certificate names and the DNS zone in Prepare the agent
                configuration first.
              </Text>
            ) : null}
            <PrimaryButton
              onClick={publish}
              isLoading={busy}
              isDisabled={
                !manager ||
                !qualified ||
                (preparationRequirements.length > 0 && !replaying) ||
                !transportPassed ||
                !stopped ||
                Boolean(jobId) ||
                ((!names.length || !saved.zone) && !replaying)
              }
            >
              Request real publication
            </PrimaryButton>
            {jobId && (
              <>
                <ApprovalWaitPanel job={observed.job} />
                <JobActivity
                  workspaceId={ctx.workspaceId}
                  jobId={jobId}
                  title='Publication job'
                />
                {manager &&
                  ['failed', 'blocked', 'orphaned_unknown_effect'].includes(
                    observed.job?.status
                  ) && (
                    <>
                      <Text fontSize='sm'>
                        Repair the reported cause first. For an uncertain
                        provider write, follow the runbook reconciliation
                        procedure and preserve the local checkpoint. This
                        retries the same signed job and publication version; it
                        does not create another order. Current approval and
                        authorization checks still apply.
                      </Text>
                      <Checkbox
                        isChecked={retryReviewed}
                        onChange={event =>
                          setRetryReviewed(event.target.checked)
                        }
                      >
                        I reviewed the job and completed any required host-local
                        reconciliation
                      </Checkbox>
                      <DashboardActionButton
                        onClick={retry}
                        isLoading={busy}
                        isDisabled={
                          !qualified ||
                          busy ||
                          !retryReviewed ||
                          observed.job?.attemptCount >= 3
                        }
                      >
                        Retry original publication
                      </DashboardActionButton>
                      {observed.job?.attemptCount >= 3 && (
                        <Text fontSize='sm'>
                          The original job has reached its retry limit. Review
                          its evidence and local checkpoint before planning a
                          new publication.
                        </Text>
                      )}
                    </>
                  )}
              </>
            )}
          </VStack>
        </DetailsSection>
        <DetailsSection
          summary='Customer-local store configuration'
          defaultOpen={Boolean(setup.groupId)}
        >
          <VStack align='stretch' spacing={3}>
            <LocalStoreFields
              {...{
                provider: setup.provider,
                address,
                setAddress,
                mount,
                setMount,
                caFile,
                setCaFile,
              }}
            />
            <VStack align='stretch' spacing={1} fontSize='sm'>
              <Text>
                <strong>Agent identity:</strong> Merge these fields into the
                protected existing configuration and retain its identity. Group
                ID: {setup.groupId || 'returned by the publication request'}.
              </Text>
              <Text>
                <strong>Host protection:</strong> Use owner-only files and
                directories. Configure the issuer's DNS credential file locally.
              </Text>
            </VStack>
            {setup.provider === 'azure-key-vault' ? (
              <Text fontSize='sm'>
                The example uses VM managed identity (IMDS). Workload identity
                and renewable token-file authentication are also implemented;
                configure those locally using the distribution runbook. Issuers
                need get/list/set; consumers get only. No delete or purge
                rights. Secrets bundles only, public Azure cloud, maximum 25
                KiB. Production use stays gated.
              </Text>
            ) : (
              <VStack align='stretch' spacing={1} fontSize='sm'>
                <Text>
                  <strong>Authentication:</strong> Enable KV v2. Use Vault Agent
                  or OpenBao Agent to renew a protected token sink.
                </Text>
                <Text>
                  <strong>Access:</strong> Give the issuer create/read on the
                  group bundles path and consumers read only. Never grant
                  delete, destroy or purge.
                </Text>
                <Text>
                  <strong>Scope:</strong> OpenBao namespaces, KV v1 and PKI are
                  outside this adapter.
                </Text>
              </VStack>
            )}
            {policies && (
              <>
                <CopyBlock label='Issuer KV v2 policy' text={policies.issuer} />
                <CopyBlock
                  label='Consumer KV v2 policy'
                  text={policies.consumer}
                />
              </>
            )}
            {local.ok ? (
              <CopyBlock
                label='Issuer configuration to merge locally'
                text={JSON.stringify(local.issuer, null, 2)}
              />
            ) : (
              local.problems?.map(p => (
                <Text key={p} fontSize='sm'>
                  {p}
                </Text>
              ))
            )}
            <Text fontSize='sm'>
              <strong>Uncertain publication:</strong> Preserve the local
              checkpoint and complete runbook reconciliation before retrying.
              Azure never blindly retries a write. Do not delete a pinned object
              or create a new order to hide uncertainty.
            </Text>
          </VStack>
        </DetailsSection>
        {(error || observed.error) && (
          <StatusPanel status='error'>
            {error ||
              'The publication status could not be read. Refresh before retrying.'}
          </StatusPanel>
        )}
      </VStack>
    </StepFrame>
  );
}
