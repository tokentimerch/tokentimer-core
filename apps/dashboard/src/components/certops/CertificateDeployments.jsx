import {
  Fragment,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import {
  Box,
  Button,
  HStack,
  Link,
  Select,
  SimpleGrid,
  Table,
  TableContainer,
  Tbody,
  Td,
  Text,
  Th,
  Thead,
  Tooltip,
  Tr,
  VStack,
} from '@chakra-ui/react';
import { Link as RouterLink } from 'react-router';
import { Truck } from 'lucide-react';
import apiClient from '../../utils/apiClient';
import Section from '../DashboardDetailsSection.jsx';
import CopyableId from '../CopyableId.jsx';
import DeploymentBadge from './DeploymentBadge.jsx';
import DeploymentHelp, {
  deploymentFieldHelp,
  providerRevisionHelp,
  refreshStatusHelp,
} from './DeploymentHelp.jsx';
import {
  combineDeploymentSummaries,
  consumerDeploymentStatus,
  consumerVersionComparison,
  deploymentStates,
  verificationDeadline,
  freshnessDeadline,
  formatFreshnessDuration,
  verificationMethods,
  verificationStages,
} from './distributionFormat.js';
import useDistributionRead, {
  serverClockOffset,
} from './useDistributionRead.js';
import { formatDateTime } from './certopsFormat.js';

const explanations = {
  failed:
    'The latest deployment failed. Review the job evidence, correct the cause, then follow the signed retry and approval workflow.',
  uncertain:
    'The deployment outcome is uncertain. Investigate the destination and reconcile locally before following the signed retry and approval workflow.',
  stale:
    'The last verification is no longer current. Check its freshness window and certificate expiry, then verify the destination again.',
  pending:
    'The expected certificate is awaiting verification. Check the agent and job evidence.',
  not_deployed:
    'No expected version is assigned. Add this destination to an approved rollout to deploy the certificate.',
  inactive: 'Historical evidence for an ended assignment or management period.',
};
const publicationLabels = {
  published: 'Published',
  allocated: 'Publication pending',
  failed: 'Publication failed',
  orphaned_unknown_effect: 'Publication outcome uncertain',
  superseded: 'Superseded',
};
const failureReasons = {
  service_unavailable: 'The destination service was unavailable.',
  verification_failed: 'The destination did not pass verification.',
  material_drift_detected:
    'The installed or served certificate has drifted from the pinned material.',
  material_auth_denied:
    'The material store denied access. Check the customer-local identity and permissions.',
  material_auth_unavailable:
    'The customer-local store credential is unavailable or expired.',
  material_version_unavailable:
    'The pinned material version is deleted, disabled, or unavailable.',
  material_publication_uncertain:
    'Publication needs customer-local reconciliation before retry.',
  material_cas_conflict:
    'The material object conflicts with the immutable publication intent.',
  material_bundle_too_large:
    'The certificate bundle exceeds the material store limit.',
  material_response_invalid:
    'The material store returned an invalid bundle or version reference.',
  material_store_config_invalid:
    'The customer-local material store configuration is unsupported.',
  material_windows_activation_failed:
    'IIS activation failed. Review and reconcile the exact listener before retry.',
  material_windows_import_failed:
    'Windows certificate import or private-key permissions failed.',
  material_windows_binding_mismatch:
    'The Windows store and configured IIS binding do not match the pinned certificate.',
  material_windows_preflight_failed:
    'The configured IIS site, HTTPS binding, or native prerequisites could not be verified.',
  material_windows_verify_failed:
    'The installed Windows certificate, private-key permissions, or IIS binding failed verification.',
};
const storeProviders = {
  'vault-kv2': 'HashiCorp Vault KV v2',
  'openbao-kv2': 'OpenBao KV v2',
  'azure-key-vault': 'Azure Key Vault',
};
const EMPTY_ROWS = [];
function SectionBody({ children }) {
  return (
    <Box py={2} minW={0}>
      {children}
    </Box>
  );
}
function profileName(ref) {
  return ref && !/^[0-9a-f]{8}-[0-9a-f-]{27}$/i.test(ref)
    ? ref
    : 'Deployment profile';
}
function providerRevision(value) {
  return value !== null && value !== undefined && value !== ''
    ? typeof value === 'string'
      ? `Azure secret version ${value}`
      : `KV v2 provider revision ${value}`
    : 'Provider revision unavailable';
}
function JobLink({ workspaceId, jobId, children = 'View job and evidence' }) {
  return jobId ? (
    <Link
      as={RouterLink}
      color='blue.400'
      fontSize='xs'
      to={`/certops/jobs?workspace=${encodeURIComponent(workspaceId)}&job=${encodeURIComponent(jobId)}`}
    >
      {children}
    </Link>
  ) : null;
}
function Fact({ label, children }) {
  const help = deploymentFieldHelp[label];
  return (
    <Box minW={0}>
      <HStack spacing={1} align='center'>
        <Text fontSize='xs' color='dashboard.modal.muted'>
          {label}
        </Text>
        {help ? <DeploymentHelp label={label} text={help} /> : null}
      </HStack>
      <Box fontSize='xs' overflowWrap='anywhere'>
        {children ?? 'Unavailable'}
      </Box>
    </Box>
  );
}
function Diagnostics({ children }) {
  return (
    <Box as='details' mt={3}>
      <Box as='summary' fontSize='xs' cursor='pointer'>
        Advanced diagnostics
      </Box>
      <SimpleGrid columns={{ base: 1, md: 2 }} spacing={3} mt={3}>
        {children}
      </SimpleGrid>
    </Box>
  );
}
function Identifier({ label, value, display }) {
  return value !== null && value !== undefined ? (
    <Fact label={label}>
      <CopyableId id={String(value)} display={display} />
    </Fact>
  ) : null;
}
function ProviderRevision({ value }) {
  return (
    <HStack as='span' display='inline-flex' spacing={0}>
      <Text as='span'>{providerRevision(value)}</Text>
      <DeploymentHelp label='Provider version' text={providerRevisionHelp} />
    </HStack>
  );
}
function ConsumerDetails({ consumer: c, status, workspaceId, now, staleData }) {
  const deadline = freshnessDeadline(c);
  const unknown = status === 'uncertain';
  return (
    <Box p={{ base: 2, md: 3 }}>
      {explanations[status] ? (
        <Text fontSize='sm' mb={3}>
          {explanations[status]}
        </Text>
      ) : null}
      <SimpleGrid columns={{ base: 1, md: 2 }} spacing={3}>
        <Fact label='Deployment profile'>
          {profileName(c.deployment_profile_ref)}
        </Fact>
        <Fact label='Assigned agent'>
          {c.assigned_agent_id
            ? c.agent_name || 'Unnamed agent'
            : 'Agent assignment missing'}
        </Fact>
        <Fact label='Expected version'>
          {c.desired_material_version_id
            ? providerRevision(c.desired_version)
            : 'Not assigned'}
        </Fact>
        <Fact label='Last confirmed version'>
          {c.observed_material_version_id
            ? `${providerRevision(c.observed_version)}${unknown ? ' (historical, current state unknown)' : ''}`
            : 'Never confirmed'}
        </Fact>
        <Fact label='Last verification'>
          {c.observed_at ? formatDateTime(c.observed_at) : 'Never verified'}
        </Fact>
        <Fact label='Verification freshness'>
          {deadline !== null
            ? `${now >= deadline ? 'Expired on' : status === 'verified' && !staleData ? 'Valid until' : 'Policy window until'} ${formatDateTime(deadline)}`
            : 'No valid verification window'}
        </Fact>
        <Fact label='Deployment status'>
          {staleData
            ? 'Unconfirmed — refresh unavailable'
            : deploymentStates[status].label}
        </Fact>
        <Fact label='Last confirmed verification'>
          {c.observed_at
            ? verificationMethods[c.verification_method] ||
              'Verification method unavailable'
            : 'No confirmation recorded'}
        </Fact>
        <Fact label='Latest execution outcome'>
          {c.latest_deployment?.stage
            ? verificationStages[c.latest_deployment.stage] ||
              'See job evidence for the recorded outcome'
            : 'No execution recorded'}
        </Fact>
        <Fact label='Verification policy'>
          {verificationMethods[c.verification_policy] || 'Unknown policy'}
        </Fact>
        <Fact label='Required destination'>
          {c.required === true
            ? 'Yes'
            : c.required === false
              ? 'No'
              : 'Not recorded'}
        </Fact>
        <Fact label='Certificate expiry on destination'>
          {c.observed_valid_to
            ? formatDateTime(c.observed_valid_to)
            : 'Not observed'}
        </Fact>
        <Fact label='Deployment evidence'>
          <JobLink
            workspaceId={workspaceId}
            jobId={c.latest_deployment?.jobId}
          />
          {!c.latest_deployment?.jobId ? 'No job recorded' : null}
        </Fact>
        {status === 'failed' ? (
          <Fact label='Failure reason'>
            {failureReasons[c.latest_deployment?.failureCode] ||
              'The job reported a deployment error. Review its evidence for the failure reason.'}
          </Fact>
        ) : null}
      </SimpleGrid>
      <Text fontSize='xs' color='dashboard.modal.muted' mt={3}>
        Versions are compared using TokenTimer material IDs.
      </Text>
      <Diagnostics>
        {[
          ['Consumer ID', c.binding_id],
          ['Agent ID', c.assigned_agent_id],
          ['Deployment profile reference', c.deployment_profile_ref],
          ['Profile revision', c.profile_revision],
          ['Authorization revision', c.authorization_revision],
          ['Expected material version ID', c.desired_material_version_id],
          [
            'Last confirmed material version ID',
            c.observed_material_version_id,
          ],
          ['Desired rollout generation', c.desired_generation],
          ['Accepted rollout generation', c.accepted_generation],
          ['Observed SHA-256 fingerprint', c.observed_fingerprint_sha256],
          ['Verification policy code', c.verification_policy],
          ['Execution stage', c.latest_deployment?.stage],
          ['Execution failure code', c.latest_deployment?.failureCode],
          ['Last job ID', c.latest_deployment?.jobId],
          ['Rollout wave', c.wave],
        ].map(([label, value]) => (
          <Identifier key={label} label={label} value={value} />
        ))}
        <Identifier
          label='Freshness policy'
          value={c.freshness_seconds}
          display={formatFreshnessDuration(c.freshness_seconds)}
        />
      </Diagnostics>
    </Box>
  );
}

function GroupDeployments({
  workspaceId,
  group,
  identityId,
  revision,
  onLoaded,
  parentError,
}) {
  const currentIdentity =
    !identityId || group.current_identity_id === identityId;
  const current = group.active && currentIdentity;
  const scope = `${workspaceId}/${group.id}/${identityId || ''}/${group.current_identity_id || ''}/${group.generation || 0}/${Boolean(group.active)}`;
  const read = useCallback(
    async (signal, startedAt) => {
      const base = `/api/v1/workspaces/${encodeURIComponent(workspaceId)}/certops/distribution-groups/${encodeURIComponent(group.id)}`;
      const [consumers, versions] = await Promise.all([
        currentIdentity
          ? apiClient.get(`${base}/consumers`, { signal })
          : Promise.resolve({ data: { consumers: [] } }),
        apiClient.get(`${base}/versions`, { signal }),
      ]);
      return {
        consumers: consumers.data.consumers || [],
        offset: serverClockOffset(consumers.data, startedAt),
        deadlines: (consumers.data.consumers || [])
          .map(c => verificationDeadline(c))
          .filter(time => time !== null)
          .map(time => time + serverClockOffset(consumers.data, startedAt)),
        versions: (versions.data.versions || []).filter(
          v =>
            !identityId ||
            v.certificate_identity_id === identityId ||
            (currentIdentity && !v.certificate_identity_id)
        ),
      };
    },
    [workspaceId, group.id, identityId, currentIdentity]
  );
  const state = useDistributionRead(scope, read);
  const { refresh } = state;
  const lastRevision = useRef(revision);
  useEffect(() => {
    if (lastRevision.current !== revision) {
      lastRevision.current = revision;
      refresh();
    }
  }, [revision, refresh]);
  const loaded = Boolean(state.data);
  useEffect(() => {
    if (loaded) onLoaded?.();
  }, [loaded, onLoaded]);
  const [page, setPage] = useState(0);
  const [expanded, setExpanded] = useState(null);
  const consumers = state.data?.consumers || EMPTY_ROWS;
  const versions = state.data?.versions || [];
  const now = state.now - (state.data?.offset || 0);
  const summary = useMemo(() => {
    const counts = {
      total: 0,
      verified: 0,
      failed: 0,
      uncertain: 0,
      stale: 0,
      pending: 0,
      not_deployed: 0,
    };
    for (const c of consumers) {
      if (c.binding_state !== 'active') continue;
      counts.total++;
      counts[consumerDeploymentStatus(c, now)]++;
    }
    const result = combineDeploymentSummaries([{ summary: counts }]);
    return {
      ...result,
      ...(!current ? { verified: 0, status: 'inactive' } : {}),
      staleData: Boolean(state.error || parentError),
    };
  }, [consumers, now, current, state.error, parentError]);
  const safePage = Math.min(
    page,
    Math.max(0, Math.ceil(consumers.length / 20) - 1)
  );
  const publication = versions.find(v => v.state === 'published');
  const attempt = versions[0];
  return (
    <VStack align='stretch' spacing={3} py={2}>
      <Box>
        <HStack justify='space-between' align='start' spacing={2}>
          <Text fontSize='sm' fontWeight='medium' overflowWrap='anywhere'>
            {group.material_store_ref} ·{' '}
            {storeProviders[group.material_store_provider || 'vault-kv2'] ||
              'Unknown provider'}
          </Text>
          <DeploymentHelp
            label='Certificate publication'
            text='Certificate material stored in the customer-controlled secret store.'
          />
        </HStack>
        <HStack spacing={2} flexWrap='wrap' fontSize='xs'>
          <Text>
            {state.error && !state.data
              ? 'Publication status unavailable'
              : state.loading
                ? 'Loading publication…'
                : attempt?.state === 'published'
                  ? 'Published to store'
                  : attempt
                    ? publicationLabels[attempt.state] ||
                      'Publication requires review'
                    : 'Not published'}
          </Text>
          {attempt ? (
            <>
              <ProviderRevision value={attempt.provider_version} />
              <Text color='dashboard.modal.muted'>
                {formatDateTime(attempt.published_at || attempt.created_at)}
              </Text>
              <JobLink
                workspaceId={workspaceId}
                jobId={attempt.publishing_job_id}
              >
                {attempt.state === 'published'
                  ? 'Publication evidence'
                  : 'Attempt evidence'}
              </JobLink>
            </>
          ) : null}
        </HStack>
        {publication && publication.id !== attempt?.id ? (
          <HStack spacing={2} flexWrap='wrap' fontSize='xs'>
            <Text>Last published:</Text>
            <ProviderRevision value={publication.provider_version} />
            <Text color='dashboard.modal.muted'>
              {formatDateTime(publication.published_at)}
            </Text>
            <JobLink
              workspaceId={workspaceId}
              jobId={publication.publishing_job_id}
            >
              Publication evidence
            </JobLink>
          </HStack>
        ) : null}
      </Box>
      {!current ? (
        <Text fontSize='xs'>
          {currentIdentity
            ? explanations.inactive
            : 'Publication history for this certificate identity. The registration currently tracks another certificate.'}
        </Text>
      ) : null}
      {state.error ? (
        <Text role='alert' fontSize='xs'>
          Details could not be refreshed.{' '}
          {state.data
            ? 'Showing the last known data. Current state is unconfirmed.'
            : 'Refresh to try again.'}
        </Text>
      ) : null}
      {state.loading ? (
        <Text role='status' fontSize='xs'>
          Loading consumers…
        </Text>
      ) : state.data ? (
        <>
          <Box alignSelf='flex-start'>
            <DeploymentBadge summary={summary} showVerified />
          </Box>
          {!consumers.length && currentIdentity ? (
            <Text fontSize='sm'>
              No consumer assignments. Add destinations to an approved rollout
              to deploy this certificate.
            </Text>
          ) : null}
          {consumers.length ? (
            <TableContainer overflowX='auto' whiteSpace='normal'>
              <Table
                size='sm'
                minW='480px'
                aria-label='Certificate deployment consumers'
              >
                <Thead>
                  <Tr>
                    {['Destination', 'Version', 'Status', 'Actions'].map(
                      label => (
                        <Th key={label} px={2}>
                          {label}
                        </Th>
                      )
                    )}
                  </Tr>
                </Thead>
                <Tbody>
                  {consumers
                    .slice(safePage * 20, (safePage + 1) * 20)
                    .map(c => {
                      const status = current
                        ? consumerDeploymentStatus(c, now)
                        : 'inactive';
                      const label =
                        status === 'verified'
                          ? 'Verified'
                          : deploymentStates[status].label;
                      const open = expanded === c.binding_id;
                      return (
                        <Fragment key={c.binding_id}>
                          <Tr>
                            <Td px={2}>
                              <Text fontSize='xs' fontWeight='medium'>
                                {c.agent_name || 'Unnamed agent'}
                              </Text>
                              <Text fontSize='xs' color='dashboard.modal.muted'>
                                {profileName(c.deployment_profile_ref)}
                                {c.agent_platform
                                  ? ` · ${{ win32: 'Windows / IIS', linux: 'Linux' }[c.agent_platform] || c.agent_platform}`
                                  : ''}
                              </Text>
                            </Td>
                            <Td px={2} fontSize='xs'>
                              <Tooltip
                                label={`Expected: ${c.desired_material_version_id ? providerRevision(c.desired_version) : 'Not assigned'}. Last confirmed: ${c.observed_material_version_id ? providerRevision(c.observed_version) : 'None'}. ${status === 'uncertain' ? 'Current service state is unknown.' : 'Compares TokenTimer material identities.'}`}
                                hasArrow
                              >
                                <Text tabIndex={0}>
                                  {consumerVersionComparison(c, status)}
                                </Text>
                              </Tooltip>
                            </Td>
                            <Td px={2}>
                              <Tooltip
                                label={
                                  state.error || parentError
                                    ? 'Last known state. Refresh unavailable. Current state is unconfirmed.'
                                    : explanations[status] ||
                                      (c.verification_method === 'trust'
                                        ? verificationMethods.trust
                                        : verificationMethods.served)
                                }
                                hasArrow
                              >
                                <Text tabIndex={0} fontSize='xs'>
                                  {state.error || parentError
                                    ? `Last known: ${label}`
                                    : label}
                                </Text>
                              </Tooltip>
                            </Td>
                            <Td px={2}>
                              <Button
                                variant='link'
                                size='xs'
                                aria-expanded={open}
                                aria-controls={`consumer-${c.binding_id}`}
                                onClick={() =>
                                  setExpanded(open ? null : c.binding_id)
                                }
                              >
                                {open ? 'Hide details' : 'Details'}
                              </Button>
                            </Td>
                          </Tr>
                          {open ? (
                            <Tr id={`consumer-${c.binding_id}`}>
                              <Td colSpan={4} px={0}>
                                <ConsumerDetails
                                  consumer={c}
                                  status={status}
                                  workspaceId={workspaceId}
                                  now={now}
                                  staleData={Boolean(
                                    state.error || parentError
                                  )}
                                />
                              </Td>
                            </Tr>
                          ) : null}
                        </Fragment>
                      );
                    })}
                </Tbody>
              </Table>
            </TableContainer>
          ) : null}
          {consumers.length > 20 ? (
            <HStack justify='space-between'>
              <Button
                size='xs'
                isDisabled={safePage === 0}
                onClick={() => {
                  setPage(safePage - 1);
                  setExpanded(null);
                }}
              >
                Previous consumers
              </Button>
              <Text fontSize='xs'>
                Page {safePage + 1} of {Math.ceil(consumers.length / 20)}
              </Text>
              <Button
                size='xs'
                isDisabled={(safePage + 1) * 20 >= consumers.length}
                onClick={() => {
                  setPage(safePage + 1);
                  setExpanded(null);
                }}
              >
                Next consumers
              </Button>
            </HStack>
          ) : null}
          <Box as='details'>
            <Box as='summary' cursor='pointer' fontSize='xs'>
              Publication history
            </Box>
            {versions.length <= 1 ? (
              <Text fontSize='xs' mt={2}>
                No earlier publication records.
              </Text>
            ) : null}
            {versions.slice(1).map(v => (
              <HStack
                key={v.id}
                spacing={2}
                mt={2}
                flexWrap='wrap'
                fontSize='xs'
              >
                <Text>
                  {publicationLabels[v.state] || 'Publication requires review'}
                </Text>
                <ProviderRevision value={v.provider_version} />
                <Text color='dashboard.modal.muted'>
                  {formatDateTime(v.published_at || v.created_at)}
                </Text>
                <JobLink
                  workspaceId={workspaceId}
                  jobId={v.publishing_job_id}
                />
              </HStack>
            ))}
          </Box>
          <Box as='details'>
            <Box as='summary' cursor='pointer' fontSize='xs'>
              Technical information
            </Box>
            <Box as='section' mt={3}>
              <Text as='h4' fontSize='xs' fontWeight='semibold'>
                Certificate publication
              </Text>
              {!versions.length ? (
                <Text fontSize='xs' mt={2}>
                  No publication records.
                </Text>
              ) : null}
              {versions.map((v, index) => (
                <Box key={v.id} mt={3}>
                  <Text as='h5' fontSize='xs' fontWeight='medium'>
                    {index === 0
                      ? 'Latest publication record'
                      : 'Previous publication record'}
                  </Text>
                  <SimpleGrid columns={{ base: 1, md: 2 }} spacing={3} mt={2}>
                    {[
                      ['Material version ID', v.id],
                      ['Certificate identity ID', v.certificate_identity_id],
                      ['SHA-256 fingerprint', v.fingerprint_sha256],
                      ['Profile revision', v.profile_revision],
                      ['Publication state code', v.state],
                      ['Publishing job ID', v.publishing_job_id],
                    ].map(([label, value]) => (
                      <Identifier key={label} label={label} value={value} />
                    ))}
                    <Fact label='Provider version'>
                      {v.provider_version !== null &&
                      v.provider_version !== undefined &&
                      v.provider_version !== ''
                        ? String(v.provider_version)
                        : 'Not assigned'}
                    </Fact>
                  </SimpleGrid>
                </Box>
              ))}
            </Box>
            <Box as='section' mt={4}>
              <Text as='h4' fontSize='xs' fontWeight='semibold'>
                Distribution configuration
              </Text>
              <SimpleGrid columns={{ base: 1, md: 2 }} spacing={3} mt={2}>
                {[
                  ['Distribution group ID', group.id],
                  ['Management period ID', group.management_period_id],
                  ['Rollout generation', group.generation],
                  ['Managed certificate ID', group.managed_certificate_id],
                ].map(([label, value]) => (
                  <Identifier key={label} label={label} value={value} />
                ))}
              </SimpleGrid>
            </Box>
          </Box>
        </>
      ) : null}
    </VStack>
  );
}

export default function CertificateDeployments({
  workspaceId,
  managedCertificateId,
  identityId,
  isOpen,
  focus = false,
}) {
  const scope =
    isOpen && workspaceId && (managedCertificateId || identityId)
      ? `${workspaceId}/${managedCertificateId || ''}/${identityId || ''}`
      : null;
  const read = useCallback(
    async signal => {
      const { data } = await apiClient.get(
        `/api/v1/workspaces/${encodeURIComponent(workspaceId)}/certops/distribution-groups`,
        {
          params: identityId
            ? { identityIds: identityId }
            : { managedCertificateIds: managedCertificateId },
          signal,
        }
      );
      return {
        groups: (data.groups || []).filter(
          g =>
            !managedCertificateId ||
            g.managed_certificate_id === managedCertificateId
        ),
      };
    },
    [workspaceId, managedCertificateId, identityId]
  );
  const state = useDistributionRead(scope, read);
  const [selection, setSelection] = useState({ scope: null, id: '' });
  const [revision, setRevision] = useState(0);
  const groups = state.data?.groups || [];
  const current = groups.filter(
    g => g.active && (!identityId || g.current_identity_id === identityId)
  );
  const selected =
    selection.scope === scope && groups.some(g => g.id === selection.id)
      ? selection.id
      : current.length === 1
        ? current[0].id
        : groups.length === 1
          ? groups[0].id
          : '';
  const group = groups.find(g => g.id === selected);
  const sectionRef = useRef(null);
  const focusSection = useCallback(() => {
    if (focus) sectionRef.current?.scrollIntoView?.({ block: 'start' });
  }, [focus]);
  const loaded = Boolean(state.data);
  useEffect(() => {
    if (focus && loaded) focusSection();
  }, [focus, loaded, focusSection]);
  return (
    <Box ref={sectionRef}>
      <Section
        title='Deployments'
        icon={Truck}
        enclosed
        headerAction={
          <DeploymentHelp
            label='Refresh status'
            text={refreshStatusHelp}
            busy={state.loading || state.refreshing}
            onAction={() => {
              state.refresh();
              setRevision(r => r + 1);
            }}
          />
        }
      >
        <SectionBody>
          {state.error ? (
            <Text role='alert' fontSize='xs'>
              Deployment information unavailable.{' '}
              {state.data
                ? 'Showing the last known data. Current state is unconfirmed.'
                : 'Check your access and refresh to try again.'}
            </Text>
          ) : null}
          {state.loading ? (
            <Text role='status' fontSize='sm'>
              Loading deployments…
            </Text>
          ) : state.data && !groups.length ? (
            <Text fontSize='sm'>Not distributed</Text>
          ) : (
            <>
              {groups.length > 1 ? (
                <Select
                  size='sm'
                  aria-label='Distribution management period'
                  value={selected}
                  onChange={event =>
                    setSelection({ scope, id: event.target.value })
                  }
                >
                  <option value=''>Select a distribution registration</option>
                  {groups.map((g, index) => (
                    <option key={g.id} value={g.id}>
                      {g.material_store_ref} ·{' '}
                      {storeProviders[
                        g.material_store_provider || 'vault-kv2'
                      ] || 'Unknown provider'}{' '}
                      · {g.active ? 'Current' : 'Ended'} ·{' '}
                      {formatDateTime(g.created_at)} · Registration {index + 1}
                    </option>
                  ))}
                </Select>
              ) : null}
              {group ? (
                <GroupDeployments
                  key={`${scope}/${group.id}`}
                  workspaceId={workspaceId}
                  group={group}
                  identityId={identityId}
                  revision={revision}
                  onLoaded={focusSection}
                  parentError={state.error}
                />
              ) : state.data ? (
                <Text fontSize='sm'>
                  Select a registration to inspect its destinations and
                  publication history.
                </Text>
              ) : null}
            </>
          )}
        </SectionBody>
      </Section>
    </Box>
  );
}
