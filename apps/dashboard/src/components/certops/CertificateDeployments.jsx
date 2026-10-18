import { useCallback, useEffect, useRef, useState } from 'react';
import {
  Box,
  Button,
  HStack,
  Link,
  Select,
  Spinner,
  Table,
  TableContainer,
  Tbody,
  Td,
  Text,
  Th,
  Thead,
  Tr,
  VStack,
} from '@chakra-ui/react';
import { Link as RouterLink } from 'react-router';
import { Truck } from 'lucide-react';
import apiClient from '../../utils/apiClient';
import Section from '../DashboardDetailsSection.jsx';
import DeploymentBadge from './DeploymentBadge.jsx';
import {
  combineDeploymentSummaries,
  consumerDeploymentStatus,
  deploymentStates,
} from './distributionFormat.js';
import { formatDateTime } from './certopsFormat.js';

const explanations = {
  failed:
    'The latest deployment failed. Inspect the job evidence before retrying.',
  uncertain:
    'Execution may have changed the service, but its result is unconfirmed. Inspect the execution evidence.',
  stale:
    'The last verification is older than the consumer freshness policy. Verify the service again.',
  pending:
    'The desired certificate has not been verified as currently served with the current assignment.',
  not_deployed:
    'No desired version is assigned. An approved rollout is required.',
  inactive:
    'This assignment or management period has ended. Previous evidence does not confirm current deployment.',
};

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

function GroupDeployments({
  workspaceId,
  group,
  identityId,
  revision,
  onLoaded,
}) {
  const [state, setState] = useState({
    loading: true,
    error: '',
    consumers: [],
    versions: [],
  });
  const currentIdentity =
    !identityId || group.current_identity_id === identityId;
  const current = group.active && currentIdentity;
  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    setState({ loading: true, error: '', consumers: [], versions: [] });
    const base = `/api/v1/workspaces/${encodeURIComponent(workspaceId)}/certops/distribution-groups/${encodeURIComponent(group.id)}`;
    Promise.all([
      currentIdentity
        ? apiClient.get(`${base}/consumers`, { signal: controller.signal })
        : Promise.resolve({ data: { consumers: [] } }),
      apiClient.get(`${base}/versions`, { signal: controller.signal }),
    ])
      .then(([consumers, versions]) => {
        if (active)
          setState({
            loading: false,
            error: '',
            consumers: consumers.data.consumers || [],
            versions: (versions.data.versions || []).filter(
              v =>
                !identityId ||
                v.certificate_identity_id === identityId ||
                (currentIdentity && !v.certificate_identity_id)
            ),
          });
      })
      .catch(() => {
        if (active)
          setState({
            loading: false,
            error: 'Deployment details could not be loaded. Refresh to retry.',
            consumers: [],
            versions: [],
          });
      });
    return () => {
      active = false;
      controller.abort();
    };
  }, [workspaceId, group.id, identityId, currentIdentity, revision]);
  useEffect(() => {
    if (!state.loading) onLoaded?.();
  }, [state.loading, onLoaded]);
  const [page, setPage] = useState(0);
  const activeConsumers = state.consumers.filter(
    c => c.binding_state === 'active'
  );
  const counts = {
    total: activeConsumers.length,
    verified: 0,
    failed: 0,
    uncertain: 0,
    stale: 0,
    pending: 0,
    not_deployed: 0,
  };
  for (const consumer of activeConsumers)
    counts[consumerDeploymentStatus(consumer)]++;
  const summary = combineDeploymentSummaries([{ summary: counts }]);
  if (!current) summary.verified = 0;
  if (!current) summary.status = 'inactive';
  const publication = state.versions.find(
    version => version.state === 'published'
  );
  const latestAttempt = state.versions[0];
  return (
    <VStack align='stretch' spacing={3} py={2}>
      <Text fontSize='sm'>
        Vault store: <strong>{group.material_store_ref}</strong>
      </Text>
      <Text fontSize='sm'>
        Published material:{' '}
        {state.loading
          ? 'Loading publication…'
          : state.error
            ? 'Unavailable'
            : publication?.state === 'published'
              ? `Version ${publication.provider_version} · ${formatDateTime(publication.published_at)}`
              : publication?.state === 'orphaned_unknown_effect'
                ? 'Publication uncertain — inspect the publishing job evidence'
                : publication
                  ? publication.state
                  : 'Not published'}
      </Text>
      {latestAttempt && latestAttempt !== publication ? (
        <Box>
          <Text fontSize='xs'>
            Latest publication attempt:{' '}
            {latestAttempt.state === 'orphaned_unknown_effect'
              ? 'Uncertain — inspect execution evidence'
              : latestAttempt.state}
          </Text>
          <JobLink
            workspaceId={workspaceId}
            jobId={latestAttempt.publishing_job_id}
          >
            Inspect latest publication attempt
          </JobLink>
        </Box>
      ) : null}
      <JobLink workspaceId={workspaceId} jobId={publication?.publishing_job_id}>
        View publication job and evidence
      </JobLink>
      <Text fontSize='xs' color='dashboard.modal.muted'>
        Publication stores certificate material. It does not prove that
        consumers currently serve it.
      </Text>
      {!current ? (
        <Text fontSize='sm'>
          {currentIdentity
            ? explanations.inactive
            : 'Historical certificate. This registration now tracks another identity; its current consumers are not shown here.'}
        </Text>
      ) : null}
      {state.loading ? (
        <HStack role='status'>
          <Spinner size='xs' />
          <Text fontSize='sm'>Loading consumers…</Text>
        </HStack>
      ) : state.error ? (
        <Text role='alert'>{state.error}</Text>
      ) : (
        <>
          <DeploymentBadge summary={summary} />
          <Text fontSize='xs'>
            {activeConsumers.length} consumers · {summary.verified} currently
            verified
            {state.consumers.length > activeConsumers.length
              ? ` · ${state.consumers.length - activeConsumers.length} ended assignments`
              : ''}
          </Text>
          {!state.consumers.length && currentIdentity ? (
            <Text fontSize='sm'>
              No consumer assignments. Add consumers and approve a rollout to
              deploy this certificate.
            </Text>
          ) : null}
          {state.consumers.length ? (
            <TableContainer overflowX='auto' whiteSpace='normal'>
              <Table
                size='sm'
                minW='700px'
                aria-label='Certificate deployment consumers'
              >
                <Thead>
                  <Tr>
                    {[
                      'Consumer',
                      'Desired / observed',
                      'Verification',
                      'Deployed expiry',
                      'Evidence',
                    ].map(label => (
                      <Th key={label}>{label}</Th>
                    ))}
                  </Tr>
                </Thead>
                <Tbody>
                  {state.consumers.slice(page * 20, (page + 1) * 20).map(c => {
                    const status = current
                      ? consumerDeploymentStatus(c)
                      : 'inactive';
                    return (
                      <Tr key={c.binding_id}>
                        <Td>
                          <Text fontSize='sm'>
                            {c.agent_name || 'Unnamed agent'}
                          </Text>
                          <Text fontSize='xs'>
                            {c.deployment_profile_ref ||
                              'Deployment profile unavailable'}
                          </Text>
                          {!c.assigned_agent_id ? (
                            <Text fontSize='xs'>Agent assignment missing</Text>
                          ) : null}
                        </Td>
                        <Td>
                          <Text fontSize='xs'>
                            Desired:{' '}
                            {c.desired_version
                              ? `Version ${c.desired_version}`
                              : 'Not assigned'}
                          </Text>
                          <Text fontSize='xs'>
                            Observed:{' '}
                            {c.observed_version
                              ? `Version ${c.observed_version}`
                              : 'Not observed'}
                          </Text>
                        </Td>
                        <Td>
                          <Text fontSize='sm'>
                            {deploymentStates[status].label}
                          </Text>
                          <Text fontSize='xs'>
                            {c.observed_at
                              ? formatDateTime(c.observed_at)
                              : 'Never verified'}
                          </Text>
                          <Text fontSize='xs'>
                            {c.verification_method || c.verification_policy}
                          </Text>
                          {explanations[status] ? (
                            <Text fontSize='xs' mt={1}>
                              {explanations[status]}
                            </Text>
                          ) : null}
                          {c.latest_deployment?.failureCode ? (
                            <Text fontSize='xs'>
                              Error: {c.latest_deployment.failureCode}
                            </Text>
                          ) : null}
                        </Td>
                        <Td fontSize='xs'>
                          {c.observed_valid_to
                            ? formatDateTime(c.observed_valid_to)
                            : 'Not observed'}
                        </Td>
                        <Td>
                          <JobLink
                            workspaceId={workspaceId}
                            jobId={c.latest_deployment?.jobId}
                          />
                          <Box as='details' mt={2}>
                            <Box as='summary' fontSize='xs' cursor='pointer'>
                              Technical details
                            </Box>
                            <Text
                              fontSize='xs'
                              whiteSpace='pre-wrap'
                              overflowWrap='anywhere'
                            >
                              {JSON.stringify(
                                {
                                  bindingId: c.binding_id,
                                  agentId: c.assigned_agent_id,
                                  desiredVersionId:
                                    c.desired_material_version_id,
                                  observedVersionId:
                                    c.observed_material_version_id,
                                  desiredGeneration: c.desired_generation,
                                  acceptedGeneration: c.accepted_generation,
                                  fingerprint: c.observed_fingerprint_sha256,
                                  freshnessSeconds: c.freshness_seconds,
                                  stage: c.latest_deployment?.stage,
                                },
                                null,
                                2
                              )}
                            </Text>
                          </Box>
                        </Td>
                      </Tr>
                    );
                  })}
                </Tbody>
              </Table>
            </TableContainer>
          ) : null}
          {state.consumers.length > 20 ? (
            <HStack justify='space-between'>
              <Button
                size='xs'
                isDisabled={page === 0}
                onClick={() => setPage(p => p - 1)}
              >
                Previous consumers
              </Button>
              <Text fontSize='xs'>
                Page {page + 1} of {Math.ceil(state.consumers.length / 20)}
              </Text>
              <Button
                size='xs'
                isDisabled={(page + 1) * 20 >= state.consumers.length}
                onClick={() => setPage(p => p + 1)}
              >
                Next consumers
              </Button>
            </HStack>
          ) : null}
          <Box as='details'>
            <Box as='summary' cursor='pointer' fontSize='xs'>
              Publication technical details and history
            </Box>
            <Text fontSize='xs' overflowWrap='anywhere'>
              Group: {group.id} · Management period:{' '}
              {group.management_period_id} · Generation: {group.generation}
            </Text>
            {state.versions.map(v => (
              <Box key={v.id} mt={2}>
                <Text fontSize='xs' overflowWrap='anywhere'>
                  {v.state} · Version {v.provider_version || 'unassigned'} ·{' '}
                  {v.id} · {v.fingerprint_sha256 || 'No fingerprint'}
                </Text>
                <JobLink
                  workspaceId={workspaceId}
                  jobId={v.publishing_job_id}
                />
              </Box>
            ))}
          </Box>
        </>
      )}
    </VStack>
  );
}

function SectionBody({ children }) {
  return (
    <Box py={2} minW={0}>
      {children}
    </Box>
  );
}

export default function CertificateDeployments({
  workspaceId,
  managedCertificateId,
  identityId,
  isOpen,
  focus = false,
}) {
  const scope = `${workspaceId}/${managedCertificateId || ''}/${identityId || ''}`;
  const [state, setState] = useState({
    scope: '',
    groups: [],
    loading: true,
    error: '',
  });
  const [selected, setSelected] = useState('');
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    if (!isOpen || !workspaceId || (!managedCertificateId && !identityId))
      return undefined;
    let active = true;
    const controller = new AbortController();
    setState({ scope, groups: [], loading: true, error: '' });
    apiClient
      .get(
        `/api/v1/workspaces/${encodeURIComponent(workspaceId)}/certops/distribution-groups`,
        {
          params: identityId
            ? { identityIds: identityId }
            : { managedCertificateIds: managedCertificateId },
          signal: controller.signal,
        }
      )
      .then(({ data }) => {
        if (!active) return;
        const groups = (data.groups || []).filter(
          g =>
            !managedCertificateId ||
            g.managed_certificate_id === managedCertificateId
        );
        const current = groups.filter(
          g => g.active && (!identityId || g.current_identity_id === identityId)
        );
        setSelected(
          current.length === 1
            ? current[0].id
            : groups.length === 1
              ? groups[0].id
              : ''
        );
        setState({ scope, groups, loading: false, error: '' });
      })
      .catch(() => {
        if (active)
          setState({
            scope,
            groups: [],
            loading: false,
            error:
              'Deployment information unavailable. Your role may not allow access, or the service could not be reached.',
          });
      });
    return () => {
      active = false;
      controller.abort();
    };
  }, [workspaceId, managedCertificateId, identityId, isOpen, scope, revision]);
  const loading = state.scope !== scope || state.loading;
  const group = !loading && state.groups.find(g => g.id === selected);
  const sectionRef = useRef(null);
  const focusSection = useCallback(() => {
    if (focus) sectionRef.current?.scrollIntoView?.({ block: 'start' });
  }, [focus]);
  useEffect(() => {
    if (focus && !loading)
      sectionRef.current?.scrollIntoView?.({ block: 'start' });
  }, [focus, loading]);
  return (
    <Box ref={sectionRef}>
      <Section
        title='Deployments'
        icon={Truck}
        enclosed
        description='Certificate publication and verified consumer deployment.'
      >
        <SectionBody>
          <HStack justify='flex-end'>
            <Button
              size='xs'
              onClick={() => setRevision(r => r + 1)}
              isLoading={loading}
            >
              Refresh deployments
            </Button>
          </HStack>
          {loading ? (
            <Text role='status' fontSize='sm'>
              Loading deployments…
            </Text>
          ) : state.error ? (
            <Text role='alert' fontSize='sm'>
              {state.error}
            </Text>
          ) : !state.groups.length ? (
            <Text fontSize='sm'>Not distributed</Text>
          ) : (
            <>
              {state.groups.length > 1 ? (
                <Select
                  size='sm'
                  aria-label='Distribution management period'
                  value={selected}
                  onChange={event => setSelected(event.target.value)}
                >
                  <option value=''>Select a distribution registration</option>
                  {state.groups.map((g, index) => (
                    <option key={g.id} value={g.id}>
                      {g.material_store_ref} · {g.active ? 'Current' : 'Ended'}{' '}
                      · {formatDateTime(g.created_at)} · Registration{' '}
                      {index + 1}
                    </option>
                  ))}
                </Select>
              ) : null}
              {group ? (
                <GroupDeployments
                  key={`${scope}/${group.id}/${revision}`}
                  workspaceId={workspaceId}
                  group={group}
                  identityId={identityId}
                  revision={revision}
                  onLoaded={focusSection}
                />
              ) : (
                <Text fontSize='sm'>
                  Select a registration to inspect its consumers and publication
                  history.
                </Text>
              )}
            </>
          )}
        </SectionBody>
      </Section>
    </Box>
  );
}
