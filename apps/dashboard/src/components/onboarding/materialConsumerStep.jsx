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
import {
  assignConsumer,
  requestRollout,
  readDistribution,
} from './vaultGuideApi.js';
import { verificationStages } from '../certops/distributionFormat.js';
import { buildVaultConsumerAssignment } from './certopsConfig.js';
import { useObservedJob, VaultRolloutGuide } from './VaultGuidedOperations.jsx';
import {
  ApprovalPolicyNote,
  ApprovalWaitPanel,
  useJobApprovalPolicy,
} from './approvalPolicy.jsx';
import JobActivity from './JobActivity.jsx';
import { useSummaryPolling } from './useSummaryPolling.js';
import { LocalStoreFields, materialActionError } from './materialStoreStep.jsx';
import {
  agentRequirements,
  canManageMaterial,
  featureReady,
  materialAgents,
  materialConfigs,
  materialSetup,
  materialStoreSatisfied,
  selectedMaterialGroup,
  materialProviderReady,
  materialCertificateInput,
} from './materialSetupModel.js';

function VerificationRequest({ ctx, group, disabled, real = false }) {
  const saved = certopsProgress(ctx);
  const field = real ? 'materialIisRollout' : 'materialVerification';
  const previous = saved[field];
  const current = previous?.groupId === group.id ? previous : null;
  const [busy, setBusy] = useState(false),
    [error, setError] = useState(''),
    [confirmed, setConfirmed] = useState(false);
  const observed = useObservedJob(ctx.workspaceId, current?.jobId);
  const canReset = real
    ? group.completed === true ||
      group.verified === true ||
      ['rejected', 'cancelled'].includes(observed.job?.status)
    : ['failed', 'rejected', 'cancelled', 'succeeded'].includes(
        observed.job?.status
      );
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  const request = async () => {
    if (disabled || busy || !group.publication || (real && !confirmed)) return;
    setBusy(true);
    setError('');
    try {
      const pending = current || {
        key: `wizard-material-${crypto.randomUUID()}`,
        groupId: group.id,
        versionId: group.publication.materialVersionId,
      };
      await saveCertops(ctx, { [field]: pending });
      if (!alive.current) return;
      const result = await requestRollout(
        ctx.workspaceId,
        group.id,
        {
          materialVersionId: pending.versionId,
          maxParallel: 1,
          verificationOnly: !real,
        },
        pending.key
      );
      if (!alive.current) return;
      const job = result.job || result;
      await saveCertops(ctx, { [field]: { ...pending, jobId: job.id } });
    } catch (e) {
      if (alive.current) setError(materialActionError(e));
    } finally {
      if (alive.current) setBusy(false);
    }
  };
  return (
    <VStack align='stretch' spacing={3}>
      <Text fontSize='sm'>
        Pinned material version:{' '}
        {current?.versionId ||
          group.publication?.materialVersionId ||
          'No active publication'}
        .
      </Text>
      <Text fontSize='sm'>
        {real
          ? 'This real rollout imports the private key and changes IIS bindings. It is not a test.'
          : 'The signed verification-only rollout fetches the exact pinned version and reads back the installed certificate, key, full chain and applicable TLS evidence. It does not install, import, bind or reload. Missing installation produces a failure, not a deployment.'}
      </Text>
      {real && (
        <Checkbox
          isChecked={confirmed}
          onChange={e => setConfirmed(e.target.checked)}
        >
          I applied the exact authorized binding configuration and enabled real
          execution on the consumer
        </Checkbox>
      )}
      <PrimaryButton
        onClick={request}
        isLoading={busy}
        isDisabled={disabled || (real && !confirmed) || Boolean(current?.jobId)}
      >
        {real
          ? 'Request real IIS deployment'
          : 'Check installed material (no deployment)'}
      </PrimaryButton>
      {current?.jobId && (
        <>
          <ApprovalWaitPanel job={observed.job} />
          <JobActivity
            workspaceId={ctx.workspaceId}
            jobId={current.jobId}
            title={real ? 'IIS rollout job' : 'Verification-only job'}
          />
          <DashboardActionButton
            variant='outline'
            isDisabled={busy || disabled || !canReset}
            onClick={() =>
              saveCertops(ctx, { [field]: null }).catch(() =>
                setError(
                  'Could not clear the finished request. Refresh and retry.'
                )
              )
            }
          >
            Prepare another {real ? 'IIS rollout' : 'verification'}
          </DashboardActionButton>
        </>
      )}
      {(error || observed.error) && (
        <StatusPanel status='error'>
          {error ||
            'Job status is unavailable. Refresh; do not repeat an uncertain deployment.'}
        </StatusPanel>
      )}
    </VStack>
  );
}

function IisConsumerEvidence({ ctx, groupId, enabled }) {
  const [state, setState] = useState({ rows: [], error: '' });
  useEffect(() => {
    if (!enabled) return undefined;
    let active = true;
    let inFlight = false;
    const abort = new AbortController();
    const load = async () => {
      if (inFlight) return;
      inFlight = true;
      try {
        const result = await readDistribution(ctx.workspaceId, groupId, {
          signal: abort.signal,
        });
        if (active)
          setState({
            rows: result.consumers.filter(
              row => row.agent_platform === 'win32'
            ),
            error: '',
          });
      } catch {
        if (active)
          setState({
            rows: [],
            error:
              'Consumer evidence could not be read. Refresh before requesting more work.',
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
  }, [ctx.workspaceId, groupId, enabled]);
  if (!enabled) return null;
  return (
    <VStack align='stretch' spacing={3}>
      {state.error && <StatusPanel status='error'>{state.error}</StatusPanel>}
      {state.rows.map(row => (
        <StatusPanel
          key={row.binding_id}
          status={
            row.stale ||
            ['failed', 'orphaned_unknown_effect'].includes(
              row.latest_deployment?.stage
            )
              ? 'warning'
              : 'info'
          }
          title={`IIS consumer: ${row.agent_name || row.binding_id}`}
        >
          <Text fontSize='sm'>
            {row.stale
              ? 'Evidence is stale'
              : row.converged === true
                ? 'Backend reports current convergence'
                : verificationStages[row.latest_deployment?.stage] ||
                  'Waiting for deployment evidence'}
            . Profile revision {row.profile_revision}, authorization revision{' '}
            {row.authorization_revision}.
          </Text>
          {row.latest_deployment?.failureCode && (
            <Text fontSize='sm'>
              {/^(material_[a-z_]+|CERTOPS_[A-Z_]+)$/.test(
                row.latest_deployment.failureCode
              )
                ? row.latest_deployment.failureCode
                : 'Review the deployment job for its safe diagnostic code.'}
            </Text>
          )}
          {row.latest_deployment?.jobId && (
            <JobActivity
              workspaceId={ctx.workspaceId}
              jobId={row.latest_deployment.jobId}
              title='IIS consumer deployment'
            />
          )}
        </StatusPanel>
      ))}
      <Text fontSize='sm'>
        Use the deployment job in Certificate Management to retry after local
        reconciliation. A coordinator job finishing is not proof that IIS is
        serving the certificate.
      </Text>
    </VStack>
  );
}

function IisBindingGuide({ ctx, setup, agents, enabled }) {
  const saved = certopsProgress(ctx);
  const certificate = materialCertificateInput(saved);
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  const prior =
    saved.materialIisBinding?.groupId === setup.groupId
      ? saved.materialIisBinding
      : null;
  const [agentId, setAgentId] = useState(prior?.agentId || '');
  const [profile, setProfile] = useState(prior?.profile || 'iis-public');
  const [id] = useState(() => prior?.bindingId || crypto.randomUUID());
  const [site, setSite] = useState('Customer web');
  const [error, setError] = useState(''),
    [busy, setBusy] = useState(false);
  const [binding, setBinding] = useState(null);
  const agent = agents.find(a => a.id === agentId);
  const requirements = agentRequirements(agent, setup.provider, 'consumer');
  const group = selectedMaterialGroup(ctx.summary, saved);
  const assign = async () => {
    if (
      !enabled ||
      agent?.platform !== 'win32' ||
      !agent?.wireAgentId ||
      !/^[A-Za-z0-9_-]{1,64}$/.test(profile) ||
      busy
    )
      return;
    setBusy(true);
    setError('');
    try {
      await saveCertops(ctx, {
        materialIisBinding: {
          agentId,
          profile,
          bindingId: id,
          groupId: setup.groupId,
        },
      });
      if (!alive.current) return;
      const result = await assignConsumer(ctx.workspaceId, setup.groupId, id, {
        ...buildVaultConsumerAssignment({
          agentRowId: agentId,
          deploymentProfileRef: profile,
        }),
        verificationPolicy: 'trust',
      });
      if (!alive.current) return;
      const row = result.binding || result;
      if (
        row.id !== id ||
        row.group_id !== setup.groupId ||
        row.assigned_agent_id !== agentId ||
        row.verification_policy !== 'trust' ||
        !Number.isInteger(row.authorization_revision)
      )
        throw new Error('Binding readback mismatch');
      setBinding(row);
      await ctx.refresh();
    } catch (e) {
      if (alive.current) setError(materialActionError(e));
    } finally {
      if (alive.current) setBusy(false);
    }
  };
  const bindingMatches =
    Boolean(agent?.wireAgentId) &&
    binding?.assigned_agent_id === agentId &&
    binding.deployment_profile_ref === profile;
  const config = bindingMatches
    ? {
        materialBindings: {
          [id]: {
            workspaceId: ctx.workspaceId,
            groupId: setup.groupId,
            agentId: agent.wireAgentId,
            materialStoreRef: setup.materialStoreRef,
            deploymentProfileRef: profile,
            profileRevision: binding.profile_revision,
            authorizationRevision: binding.authorization_revision,
            verificationPolicy: 'trust',
            connector: 'windows-material-iis-v1',
            serviceAccountSids: ['S-1-5-20'],
            target: {
              type: 'windows-iis',
              reference: profile,
              store: 'My',
              binding: {
                site,
                address: '*',
                port: 443,
                sniHost: certificate.names[0]?.replace('*.', 'www.'),
                store: 'My',
              },
            },
            probes: [
              {
                dialAddress: '127.0.0.1',
                port: 443,
                sni: certificate.names[0]?.replace('*.', 'www.'),
                trustCaFile: 'C:\\ProgramData\\TokenTimer\\issuer-ca.pem',
              },
            ],
          },
        },
      }
    : null;
  return (
    <VStack align='stretch' spacing={3}>
      <StatusPanel
        status={enabled ? 'info' : 'warning'}
        title={
          enabled
            ? 'Qualified Windows/IIS path'
            : 'Windows/IIS shared import is implemented but production-gated'
        }
      >
        A win32 agent requires windows-material-iis-v1, windows-cert-store-v1
        and iis-binding-v1 plus the provider, deployment and fresh
        claim-evidence capabilities. Linux endpoint targets and installed-only
        assurance are forbidden for IIS.
      </StatusPanel>
      <Text fontSize='sm'>
        Use a member Windows Server 2019 or later with IIS Management
        Scripts/Tools, Windows PowerShell 5.1, .NET 4.8 and the fixed connector
        permitted by application-control policy. Run the agent as LocalSystem.
        Pre-create the exact HTTPS binding; shared selectors and Centralized
        Certificate Store are unsupported. The connector requires non-exportable
        machine CNG keys, exact protected ACLs and signing association before
        reuse. Resolve service-account SIDs locally; never grant Everyone or
        Users.
      </Text>
      <FormControl>
        <FormLabel>Windows consumer agent</FormLabel>
        <Select
          value={agentId}
          placeholder='Choose a Windows agent'
          onChange={e => {
            setAgentId(e.target.value);
            setBinding(null);
          }}
          isDisabled={!enabled}
        >
          {agents.map(a => (
            <option key={a.id} value={a.id}>
              {a.name || a.id}
            </option>
          ))}
        </Select>
      </FormControl>
      <FormControl>
        <FormLabel>IIS deployment profile reference</FormLabel>
        <Input
          value={profile}
          onChange={e => {
            setProfile(e.target.value);
            setBinding(null);
          }}
          isDisabled={!enabled}
        />
      </FormControl>
      <FormControl>
        <FormLabel>Existing IIS site name (local configuration only)</FormLabel>
        <Input value={site} onChange={e => setSite(e.target.value)} />
      </FormControl>
      {requirements.map(reason => (
        <Text key={reason} fontSize='sm'>
          {reason}
        </Text>
      ))}
      <PrimaryButton
        isDisabled={
          !enabled || agent?.platform !== 'win32' || !agent?.wireAgentId
        }
        isLoading={busy}
        onClick={assign}
      >
        Authorize IIS binding
      </PrimaryButton>
      {config && (
        <CopyBlock
          label='Typed IIS binding to merge locally'
          text={JSON.stringify(config, null, 2)}
        />
      )}
      <Text fontSize='sm'>
        Match the local material store, provider, group, profile and
        authorization revision exactly. Protect renewable credential sinks with
        owner/SYSTEM-only ACLs. Configure every probe for the exact IIS port/SNI
        and the issuer CA. Store import alone is not listener verification. RSA,
        P-256 and P-384 are supported; P-521 is rejected before mutation.
      </Text>
      {group && (
        <VerificationRequest
          key={`real/${group.id}`}
          ctx={ctx}
          group={group}
          real
          disabled={!enabled || !bindingMatches || requirements.length > 0}
        />
      )}
      {error && <StatusPanel status='error'>{error}</StatusPanel>}
      <IisConsumerEvidence
        ctx={ctx}
        groupId={setup.groupId}
        enabled={enabled}
      />
    </VStack>
  );
}

export function MaterialConsumerStep({ ctx }) {
  return <MaterialConsumerForm key={ctx.workspaceId} ctx={ctx} />;
}
function MaterialConsumerForm({ ctx }) {
  const saved = certopsProgress(ctx),
    setup = materialSetup(saved);
  const [platform, setPlatform] = useState('linux');
  const [address, setAddress] = useState(''),
    [mount, setMount] = useState('secret');
  const [caFile, setCaFile] = useState('');
  const [assurance, setAssurance] = useState(
    saved.materialConsumerPolicy ||
      (saved.vaultConsumerDeliveryMode === 'service' ? 'trust' : 'installed')
  );
  const [service, setService] = useState(
      saved.vaultConsumerReloadService || 'nginx'
    ),
    [path, setPath] = useState(
      saved.vaultConsumerDeployPath || '/etc/tokentimer/certificates'
    );
  const [firstBindingId] = useState(
    () => saved.vaultBindingId || crypto.randomUUID()
  );
  const [probeCa, setProbeCa] = useState(saved.vaultProbeCa || '');
  const [error, setError] = useState('');
  const { required } = useJobApprovalPolicy(ctx.workspaceId);
  const manager = canManageMaterial(ctx);
  useSummaryPolling(ctx.refresh, manager);
  const providerQualified = materialProviderReady(ctx, setup.provider);
  const group = selectedMaterialGroup(ctx.summary, saved);
  const ready =
    manager && providerQualified && materialStoreSatisfied(ctx.summary, saved);
  const agents = materialAgents(ctx);
  const consumers = agents.filter(
    a => a.id !== setup.issuerAgentId && a.platform === platform
  );
  // Authorize metadata first so discovery-only agents can obtain the exact
  // local configuration. Execution still requires current capabilities.
  const configurable = consumers.filter(a => Boolean(a.wireAgentId));
  const config = {
    provider: setup.provider,
    materialStoreRef: setup.materialStoreRef,
    issuanceProfileRef: setup.issuanceProfileRef,
    issuerProfileRevision: setup.profileRevision,
    workspaceId: ctx.workspaceId,
    groupId: setup.groupId,
    vaultAddress: address,
    mount,
    caFile: setup.provider === 'azure-key-vault' ? '' : caFile,
    ...materialCertificateInput(saved),
    consumerDeliveryMode: assurance === 'installed' ? 'files' : 'service',
    consumerReloadService: service,
    deployPath: path,
    verificationPolicy: assurance,
    probeTrustCaFile: probeCa,
  };
  const local = materialConfigs({ ...config, setup, address });
  const wEnabled =
    ready && featureReady(ctx.capabilities, 'certops.windows_material_iis');
  return (
    <StepFrame
      title='Connect and validate consumers'
      kind='verify'
      description='Authorize each destination, check its local configuration and verify the exact published certificate through existing signed jobs.'
      docs={ctx.docs('certops.vault', 'Distribution and recovery runbook')}
    >
      <VStack align='stretch' spacing={4}>
        {!manager && (
          <StatusPanel status='warning'>
            A workspace manager or owner must authorize consumers and request
            jobs.
          </StatusPanel>
        )}
        {!ready && (
          <StatusPanel status='warning'>
            Complete Configure material store using a qualified provider and a
            persisted publication receipt first. A saved form or successful
            no-op does not prove publication.
          </StatusPanel>
        )}
        <FormControl>
          <FormLabel>Consumer destination</FormLabel>
          <Select value={platform} onChange={e => setPlatform(e.target.value)}>
            <option value='linux'>Linux endpoint</option>
            <option value='win32'>
              Windows / IIS (qualification required)
            </option>
          </Select>
        </FormControl>
        {!consumers.length && (
          <StatusPanel status='warning'>
            No {platform === 'linux' ? 'Linux' : 'Windows'} consumer agents are
            registered. Register a separate consumer in this workspace and
            refresh.
          </StatusPanel>
        )}
        {consumers.map(a => (
          <Text key={a.id} fontSize='sm'>
            {a.name || a.id}:{' '}
            {agentRequirements(a, setup.provider, 'consumer').join('; ') ||
              'Required capabilities declared and fresh'}
          </Text>
        ))}
        {platform === 'linux' ? (
          <>
            <Text fontSize='sm'>
              The installer/service account needs only the configured write
              paths and reload grants. Keep the existing agent identity and
              protected state directory. Configure a read-only material identity
              on every consumer.
            </Text>
            <FormControl>
              <FormLabel>Verification policy</FormLabel>
              <Select
                value={assurance}
                onChange={async e => {
                  const policy = e.target.value;
                  try {
                    await saveCertops(ctx, { materialConsumerPolicy: policy });
                    setAssurance(policy);
                  } catch (err) {
                    setError(materialActionError(err));
                  }
                }}
                isDisabled={
                  !manager ||
                  Boolean(
                    saved.vaultConsumers?.length || saved.vaultRolloutRequestKey
                  )
                }
              >
                <option value='installed'>
                  Installed files only — no reload or TLS probe
                </option>
                <option value='served'>
                  Served — exact certificate on every TLS listener
                </option>
                <option value='trust'>
                  Trust — listener, chain and hostname validation
                </option>
              </Select>
            </FormControl>
            <FormControl>
              <FormLabel>Destination directory</FormLabel>
              <Input
                value={path}
                onChange={e => setPath(e.target.value)}
                isDisabled={Boolean(saved.vaultConsumers?.length)}
              />
            </FormControl>
            {assurance !== 'installed' && (
              <FormControl>
                <FormLabel>Reload service</FormLabel>
                <Select
                  value={service}
                  onChange={e => setService(e.target.value)}
                  isDisabled={Boolean(saved.vaultConsumers?.length)}
                >
                  <option value='nginx'>nginx</option>
                  <option value='apache'>Apache</option>
                  <option value='haproxy'>HAProxy</option>
                </Select>
              </FormControl>
            )}
            <Text fontSize='sm'>
              Installed assurance securely reads back the leaf certificate,
              private key, fingerprint and complete chain. It does not prove a
              service uses those files. Served and trust require listener
              probes; trust also validates the chain and hostname. Their real
              deployment path can reload the service.
            </Text>
            {assurance !== 'installed' && (
              <FormControl>
                <FormLabel>TLS issuer CA file on consumer (optional)</FormLabel>
                <Input
                  value={probeCa}
                  onChange={e => setProbeCa(e.target.value)}
                  placeholder='/etc/tokentimer-agent/issuer-ca.pem'
                />
              </FormControl>
            )}
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
            {ready && local.ok && configurable.length > 0 ? (
              <VaultRolloutGuide
                key={`${ctx.workspaceId}/${setup.groupId}/${assurance}`}
                ctx={ctx}
                groupId={setup.groupId}
                firstAgentId={
                  configurable.some(a => a.id === saved.vaultConsumerAgentId)
                    ? saved.vaultConsumerAgentId
                    : configurable[0].id
                }
                firstBindingId={firstBindingId}
                agents={configurable}
                canDeployTo={agent =>
                  agentRequirements(agent, setup.provider, 'consumer')
                    .length === 0
                }
                config={config}
                buildLocalConfig={values =>
                  materialConfigs({ ...values, setup, address, mount })
                }
                approvalRequired={required}
              />
            ) : (
              <StatusPanel status='info'>
                Before assigning consumers, check the provider, agent
                requirements and local configuration.{' '}
                {local.problems?.join(' ')}
              </StatusPanel>
            )}
          </>
        ) : (
          <IisBindingGuide
            key={setup.groupId}
            ctx={ctx}
            setup={setup}
            agents={consumers}
            enabled={wEnabled}
          />
        )}
        <DetailsSection summary='Safe verification and recovery' defaultOpen>
          <VStack align='stretch' spacing={3}>
            <ApprovalPolicyNote
              required={required}
              noun='verification request'
            />
            {group && (
              <VerificationRequest
                key={`check/${group.id}`}
                ctx={ctx}
                group={group}
                disabled={!ready || (platform === 'win32' && !wEnabled)}
              />
            )}
            <Text fontSize='sm'>
              Completion comes only from the backend consumer matrix and current
              rollout generation. A coordinator job, a dry-run result, a stale
              receipt or an inactive binding cannot finish this step. Use Deploy
              the selected version only when you intend a real installation.
            </Text>
            <Text fontSize='sm'>
              On failure, inspect the job timeline and safe error code. For
              missing capabilities or authorization revisions, repair the
              protected host configuration and refresh. For
              orphaned_unknown_effect, preserve the journal, reconcile the
              actual filesystem/IIS/listener state locally, then retry the
              original deployment with the existing recovery action. Resume a
              paused rollout only after required consumers recover. Rollback is
              a separate explicitly approved operation in Certificate
              Management; this guide never silently rolls back.
            </Text>
            <DashboardActionButton
              variant='outline'
              onClick={() =>
                ctx
                  .refresh()
                  .catch(() =>
                    setError(
                      'Could not read current evidence. Refresh before retrying.'
                    )
                  )
              }
            >
              Refresh consumer evidence
            </DashboardActionButton>
          </VStack>
        </DetailsSection>
        {error && <StatusPanel status='error'>{error}</StatusPanel>}
      </VStack>
    </StepFrame>
  );
}
