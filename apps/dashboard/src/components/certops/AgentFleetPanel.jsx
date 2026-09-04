import { useEffect, useState } from 'react';
import {
  Alert,
  AlertDescription,
  AlertIcon,
  Badge,
  Box,
  Button,
  Checkbox,
  FormControl,
  FormHelperText,
  FormLabel,
  HStack,
  Modal,
  ModalBody,
  ModalCloseButton,
  ModalFooter,
  ModalHeader,
  ModalOverlay,
  Select,
  Spinner,
  Stack,
  Table,
  TableContainer,
  Tbody,
  Td,
  Text,
  Textarea,
  Th,
  Thead,
  Tr,
  useColorModeValue,
  VStack,
} from '@chakra-ui/react';
import {
  DashboardModalDescription,
  DashboardModalFrame,
  DashboardModalTitle,
  useDashboardModalProps,
} from '../DashboardModalFrame.jsx';
import CopyableId from '../CopyableId.jsx';
import { DashboardErrorAlert } from '../DashboardPrimitives.jsx';
import DashboardPagination from '../DashboardPagination.jsx';
import {
  CERTOPS_PAGE_SIZE_OPTIONS,
  useCertOpsListUrlState,
} from '../../hooks/useCertOpsUrlState.js';
import { useWorkspace } from '../../utils/WorkspaceContext.jsx';
import { workspaceAPI } from '../../utils/apiClient';
import { showSuccess } from '../../utils/toast.js';
import { retireAgent, updateAgentAlertSettings } from './certopsAgentsApi.js';
import { formatDateTime, formatRelativeDateTime } from './certopsJobsFormat';
import { useCertOpsCanManage } from './useCertOps.js';
import { useCertOpsAgents } from './useCertOpsAgents.js';

const AGENT_STATUS_SCHEME = {
  active: 'green',
  stale: 'orange',
  offline: 'orange',
  retired: 'gray',
};

const AGENT_STATUS_LABEL = {
  active: 'Active',
  stale: 'Stale',
  offline: 'Offline',
  retired: 'Retired',
};

// The persisted `status` column only moves toward 'active' on the agent's
// own register/heartbeat/claim calls; it is only ever demoted to 'offline'
// by the periodic stale-agent sweep (apps/worker/src/certops-worker.js).
// Between sweeps (or if the sweep isn't running), an agent that crashed or
// stopped heartbeating would otherwise still show a green "Active" badge.
// livenessState is computed live on every list/read call
// (agentRegistry.js#computeAgentCompatibility) from the same threshold the
// sweep uses, so prefer it here to catch that gap.
function displayAgentStatus(agent) {
  if (agent?.livenessState === 'stale' && agent?.status === 'active') {
    return 'stale';
  }
  return agent?.status;
}

/** Subtle status chip for an agent, JobStatusBadge conventions. */
function AgentStatusBadge({ status, fontSize = 'xs' }) {
  const key = String(status || '').toLowerCase();
  return (
    <Badge
      colorScheme={AGENT_STATUS_SCHEME[key] || 'gray'}
      variant='subtle'
      textTransform='none'
      fontWeight='medium'
      fontSize={fontSize}
      title={
        key === 'stale'
          ? 'No heartbeat received within the offline threshold; the agent is likely down and awaiting the next fleet sweep.'
          : undefined
      }
    >
      {AGENT_STATUS_LABEL[key] || (status ? String(status) : 'Unknown')}
    </Badge>
  );
}

function shortId(value) {
  const raw = String(value || '');
  return raw.length > 12 ? `${raw.slice(0, 12)}...` : raw;
}

// Friendly OS labels for the raw `platform` the agent reports at
// registration (process.platform - no new protocol field). Unknown/future
// platform values still render cleanly rather than falling back to "--".
const PLATFORM_LABELS = {
  win32: 'Windows',
  linux: 'Linux',
  darwin: 'macOS',
};

function platformLabel(platform) {
  if (!platform) return '--';
  return PLATFORM_LABELS[platform] || String(platform);
}

/** Signed millisecond offset for display, e.g. "+120 ms"; '--' when unknown. */
function formatClockOffset(value) {
  if (value === null || value === undefined) return '--';
  const ms = Number(value);
  if (!Number.isFinite(ms)) return '--';
  return `${ms < 0 ? '-' : '+'}${Math.abs(ms)} ms`;
}

const CLOCK_DRIFT_SCHEME = {
  warn: 'orange',
  alert: 'red',
};

const CLOCK_DRIFT_LABEL = {
  warn: 'Drift',
  alert: 'Drift (alert)',
};

/** Two-tier clock-drift chip, server-computed (agentRegistry.js#computeAgentCompatibility). */
function ClockDriftBadge({ clockDriftState }) {
  const key = String(clockDriftState || '').toLowerCase();
  if (key !== 'warn' && key !== 'alert') return null;
  return (
    <Badge
      colorScheme={CLOCK_DRIFT_SCHEME[key]}
      variant='subtle'
      textTransform='none'
      fontWeight='medium'
      fontSize='xs'
      title={
        key === 'alert'
          ? 'Clock offset exceeds the alert threshold (CERTOPS_AGENT_CLOCK_DRIFT_ALERT_MS).'
          : 'Clock offset exceeds the warn threshold (CERTOPS_AGENT_CLOCK_DRIFT_WARN_MS).'
      }
    >
      {CLOCK_DRIFT_LABEL[key]}
    </Badge>
  );
}

const COMPATIBILITY_SCHEME = {
  compatible: 'green',
  outdated: 'orange',
  blocked: 'red',
};

const COMPATIBILITY_LABEL = {
  compatible: 'Compatible',
  outdated: 'Outdated',
  blocked: 'Blocked',
};

/** Version/protocol compatibility chip; 'blocked' is a hard stop (agentJobEligibility.js
 *  rejects every claim from this agent with compatibility_blocked). */
function AgentCompatibilityBadge({ compatibilityState, compatibilityRange }) {
  const key = String(compatibilityState || '').toLowerCase();
  const range = compatibilityRange || {};
  const rangeText =
    `agent ${range.minAgentVersion || '?'}-${range.maxAgentVersion || '?'}, ` +
    `protocol ${range.minProtocolVersion || '?'}-${range.maxProtocolVersion || '?'}`;
  const title =
    key === 'blocked'
      ? `Outside the accepted range (${rangeText}). This agent cannot claim any job until it is upgraded.`
      : key === 'outdated'
        ? `Within the accepted range (${rangeText}) but more than one minor version behind the latest known build. Upgrade when convenient; it can still claim jobs.`
        : `Within the accepted range (${rangeText}).`;
  return (
    <Badge
      colorScheme={COMPATIBILITY_SCHEME[key] || 'gray'}
      variant='subtle'
      textTransform='none'
      fontWeight='medium'
      fontSize='xs'
      title={title}
    >
      {COMPATIBILITY_LABEL[key] || 'Unknown'}
    </Badge>
  );
}

/** NTP sync state chip: green Synced, orange Not synced, muted when unknown. */
function NtpBadge({ ntpSynced }) {
  if (ntpSynced !== true && ntpSynced !== false) {
    return (
      <Text as='span' fontSize='sm'>
        --
      </Text>
    );
  }
  return (
    <Badge
      colorScheme={ntpSynced ? 'green' : 'orange'}
      variant='subtle'
      textTransform='none'
      fontWeight='medium'
      fontSize='xs'
    >
      {ntpSynced ? 'Synced' : 'Not synced'}
    </Badge>
  );
}

/**
 * Execution capability chip: whether this agent declared any executable
 * action the last time it successfully claimed a job. Empty is ambiguous
 * between "observe-only" and "hasn't polled yet" - the title makes that
 * caveat explicit rather than asserting a diagnosis this field can't prove.
 */
function ExecutionCapabilityBadge({ supportedOperations }) {
  const declared = Array.isArray(supportedOperations) ? supportedOperations : [];
  if (declared.length > 0) {
    return (
      <Badge
        colorScheme='green'
        variant='subtle'
        textTransform='none'
        fontWeight='medium'
        fontSize='xs'
        title={`Last declared on claim: ${declared.join(', ')}`}
      >
        Enabled
      </Badge>
    );
  }
  return (
    <Badge
      colorScheme='orange'
      variant='subtle'
      textTransform='none'
      fontWeight='medium'
      fontSize='xs'
      title={
        'No executable action declared on the last claim call. Most often ' +
        'this means the agent is running observe-only (no execution block, ' +
        'or execution.enabled is not true, in its config.json) - a job ' +
        'pinned to it will sit at Pending forever. A brand-new agent that ' +
        'has not polled for a job yet looks identical here.'
      }
    >
      No capability declared
    </Badge>
  );
}

/**
 * Confirm dialog for retiring an agent (RetireCertificateModal pattern).
 * A non-forced retire is refused server-side with 409
 * CERTOPS_AGENT_RETIRE_BLOCKED while the agent holds job leases; the dialog
 * then surfaces a force option, which requires a reason.
 */
function RetireAgentModal({ isOpen, onClose, agent, onRetire }) {
  const {
    overlayProps,
    headerProps,
    bodyProps,
    footerProps,
    closeButtonProps,
    outlineButtonProps,
    dangerButtonProps,
  } = useDashboardModalProps();

  const [reason, setReason] = useState('');
  const [force, setForce] = useState(false);
  const [blocked, setBlocked] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (isOpen) {
      setReason('');
      setForce(false);
      setBlocked(false);
      setSubmitting(false);
      setError('');
    }
  }, [isOpen]);

  const forceNeedsReason = force && !reason.trim();

  const handleConfirm = async () => {
    if (submitting || forceNeedsReason) return;
    setSubmitting(true);
    setError('');
    try {
      await onRetire({
        force,
        reason: reason.trim() || undefined,
      });
    } catch (err) {
      const code = err?.response?.data?.code;
      if (
        err?.response?.status === 409 ||
        code === 'CERTOPS_AGENT_RETIRE_BLOCKED'
      ) {
        setBlocked(true);
        setError(
          'This agent still holds active job leases. Wait for its jobs to finish, or force the retirement (leased jobs will fail over).'
        );
      } else {
        setError(
          err?.response?.data?.error ||
            'Could not retire this agent. Please try again.'
        );
      }
      setSubmitting(false);
    }
  };

  const agentLabel = agent?.name || agent?.hostname || agent?.agentId || '';

  return (
    <Modal isOpen={isOpen} onClose={onClose} isCentered scrollBehavior='inside'>
      <ModalOverlay {...overlayProps} />
      <DashboardModalFrame
        type='danger'
        maxW={{ base: 'calc(100vw - 24px)', md: '520px' }}
      >
        <ModalHeader {...headerProps}>
          <DashboardModalTitle>Retire agent</DashboardModalTitle>
          <DashboardModalDescription>
            A retired agent can no longer connect or lease jobs; its credential
            is invalidated. This cannot be undone; deploy a new agent to replace
            it.
          </DashboardModalDescription>
        </ModalHeader>
        <ModalCloseButton {...closeButtonProps} />
        <ModalBody {...bodyProps}>
          <Stack spacing={3}>
            {agentLabel ? (
              <Text fontSize='sm' fontWeight='semibold'>
                Agent: {agentLabel}
              </Text>
            ) : null}
            <Box>
              <Text fontSize='sm' mb={1}>
                Reason {force ? '(required to force)' : '(optional)'}
              </Text>
              <Textarea
                value={reason}
                onChange={event => setReason(event.target.value)}
                placeholder='e.g. host decommissioned'
                size='sm'
                rows={2}
              />
            </Box>
            {blocked ? (
              <Checkbox
                isChecked={force}
                onChange={event => setForce(event.target.checked)}
                size='sm'
              >
                <Text as='span' fontSize='sm'>
                  Force retirement even though the agent holds job leases
                </Text>
              </Checkbox>
            ) : null}
            {error ? (
              <Alert status='error' borderRadius='md' variant='left-accent'>
                <AlertIcon />
                <AlertDescription fontSize='sm'>{error}</AlertDescription>
              </Alert>
            ) : null}
          </Stack>
        </ModalBody>
        <ModalFooter {...footerProps}>
          <Button
            {...outlineButtonProps}
            onClick={onClose}
            isDisabled={submitting}
          >
            Cancel
          </Button>
          <Button
            {...dangerButtonProps}
            ml={3}
            onClick={handleConfirm}
            isLoading={submitting}
            loadingText='Retiring'
            isDisabled={forceNeedsReason}
          >
            {force ? 'Force retire' : 'Retire agent'}
          </Button>
        </ModalFooter>
      </DashboardModalFrame>
    </Modal>
  );
}

/**
 * Edit an already-registered agent's downtime alert settings (T3 iteration
 * decision: the same contact-group UX as Endpoint SSL Monitor). Loads
 * workspace contact groups lazily on open, same as
 * CertificateTokenDetailModal, rather than the panel prefetching contacts it
 * only needs when this modal is open.
 */
function EditAlertingModal({ isOpen, onClose, agent, onSaved }) {
  const { workspaceId } = useWorkspace();
  const {
    overlayProps,
    headerProps,
    bodyProps,
    footerProps,
    closeButtonProps,
    outlineButtonProps,
    primaryButtonProps,
  } = useDashboardModalProps();

  const [alertsEnabled, setAlertsEnabled] = useState(true);
  const [contactGroupId, setContactGroupId] = useState('');
  const [contactGroups, setContactGroups] = useState([]);
  const [defaultContactGroupId, setDefaultContactGroupId] = useState('');
  const [loadingGroups, setLoadingGroups] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!isOpen || !agent) return undefined;
    setAlertsEnabled(agent.downtimeAlertsEnabled !== false);
    setContactGroupId(agent.contactGroupId || '');
    setError('');
    setSubmitting(false);
    if (!workspaceId) return undefined;
    let cancelled = false;
    setLoadingGroups(true);
    workspaceAPI
      .getAlertSettings(workspaceId)
      .then(settings => {
        if (cancelled) return;
        setContactGroups(
          Array.isArray(settings?.contact_groups) ? settings.contact_groups : []
        );
        setDefaultContactGroupId(settings?.default_contact_group_id || '');
      })
      .catch(() => {
        if (!cancelled) setContactGroups([]);
      })
      .finally(() => {
        if (!cancelled) setLoadingGroups(false);
      });
    return () => {
      cancelled = true;
    };
  }, [isOpen, agent, workspaceId]);

  const handleSave = async () => {
    if (!agent?.id || !workspaceId || submitting) return;
    setSubmitting(true);
    setError('');
    try {
      const { agent: updated } = await updateAgentAlertSettings(
        workspaceId,
        agent.id,
        {
          downtimeAlertsEnabled: alertsEnabled,
          contactGroupId: contactGroupId || null,
        }
      );
      showSuccess('Alert settings updated');
      if (typeof onSaved === 'function') onSaved(updated);
      onClose();
    } catch (err) {
      const code = err?.response?.data?.code;
      if (code === 'CERTOPS_AGENT_CONTACT_GROUP_INVALID') {
        setError('That contact group no longer exists in this workspace.');
      } else {
        setError(
          err?.response?.data?.error ||
            'Could not update alert settings. Please try again.'
        );
      }
      setSubmitting(false);
    }
  };

  const agentLabel = agent?.name || agent?.hostname || agent?.agentId || '';

  return (
    <Modal isOpen={isOpen} onClose={onClose} isCentered scrollBehavior='inside'>
      <ModalOverlay {...overlayProps} />
      <DashboardModalFrame maxW={{ base: 'calc(100vw - 24px)', md: '480px' }}>
        <ModalHeader {...headerProps}>
          <DashboardModalTitle>Edit alerting</DashboardModalTitle>
          <DashboardModalDescription>
            {agentLabel ? `Downtime alert settings for ${agentLabel}.` : ''}
          </DashboardModalDescription>
        </ModalHeader>
        <ModalCloseButton {...closeButtonProps} />
        <ModalBody {...bodyProps}>
          <Stack spacing={4}>
            <Checkbox
              isChecked={alertsEnabled}
              onChange={event => setAlertsEnabled(event.target.checked)}
              size='sm'
            >
              <Text as='span' fontSize='sm'>
                Alert when this agent has not been seen for 10 minutes
              </Text>
            </Checkbox>
            <FormControl isDisabled={!alertsEnabled || loadingGroups}>
              <FormLabel fontSize='sm'>Contact group</FormLabel>
              <Select
                size='sm'
                value={contactGroupId}
                onChange={event => setContactGroupId(event.target.value)}
              >
                <option value=''>Default workspace group</option>
                {contactGroups.map(g => (
                  <option key={g.id} value={g.id}>
                    {g.name}
                    {String(g.id) === String(defaultContactGroupId)
                      ? ' (default)'
                      : ''}
                  </option>
                ))}
              </Select>
              <FormHelperText>
                Down and recovery alerts go to this group's email/webhook
                channels.
              </FormHelperText>
            </FormControl>
            {error ? (
              <Alert status='error' borderRadius='md' variant='left-accent'>
                <AlertIcon />
                <AlertDescription fontSize='sm'>{error}</AlertDescription>
              </Alert>
            ) : null}
          </Stack>
        </ModalBody>
        <ModalFooter {...footerProps}>
          <Button
            {...outlineButtonProps}
            onClick={onClose}
            isDisabled={submitting}
          >
            Cancel
          </Button>
          <Button
            {...primaryButtonProps}
            ml={3}
            onClick={handleSave}
            isLoading={submitting}
            loadingText='Saving'
          >
            Save
          </Button>
        </ModalFooter>
      </DashboardModalFrame>
    </Modal>
  );
}

/**
 * Agent fleet table: name/id, status, version, protocol version, clock
 * drift, NTP sync state, pinned job-signing key, last heartbeat, and a
 * manager-only Retire action. Empty state points to the Deploy an agent
 * button on the same tab.
 *
 * @param {number} [refreshSignal] - Optional value from DeployAgentModal;
 *   changing it (e.g. right after a new agent registers) triggers an
 *   immediate refetch instead of waiting on this panel's own poll.
 * @param {import('react').ReactNode} [headerAction] - Rendered next to the
 *   panel title (the tab's "Deploy an agent" button), so the fleet keeps
 *   its own title/description without the caller duplicating them.
 */
export default function AgentFleetPanel({ refreshSignal, headerAction } = {}) {
  const { workspaceId } = useWorkspace();
  const canManage = useCertOpsCanManage();
  const { limit, offset, setPage } = useCertOpsListUrlState({
    scope: 'agent',
  });
  // The fleet list is unbounded server-side unless a limit is sent. Now that
  // this table has a page control, sending one is safe: every row past the
  // first page is reachable.
  const { enabled, agents, pagination, loading, error, refresh } =
    useCertOpsAgents(refreshSignal, { limit, offset });

  const [retireTarget, setRetireTarget] = useState(null);
  const [alertingTarget, setAlertingTarget] = useState(null);

  const muted = useColorModeValue('gray.600', 'gray.400');
  const titleColor = useColorModeValue('gray.700', 'gray.200');
  const infoBg = useColorModeValue('blue.50', 'blue.900');
  const infoBorder = useColorModeValue('blue.200', 'blue.700');
  const infoText = useColorModeValue('blue.800', 'blue.100');

  if (enabled !== true) return null;

  const handleRetire = async ({ force, reason }) => {
    if (!retireTarget?.id || !workspaceId) return;
    await retireAgent(workspaceId, retireTarget.id, { force, reason });
    showSuccess('Agent retired');
    setRetireTarget(null);
    refresh();
  };

  const firstPage = () => setPage({ offset: 0 });
  const pageIsPastEnd = Boolean(
    pagination && pagination.total > 0 && offset >= pagination.total
  );

  return (
    <Stack spacing={4} align='stretch'>
      <HStack justify='space-between' align='start' spacing={4} flexWrap='wrap'>
        <Box minW={0}>
          <Text fontSize='md' fontWeight='bold' color={titleColor}>
            Agent fleet
          </Text>
        </Box>
        {headerAction ? <Box flexShrink={0}>{headerAction}</Box> : null}
      </HStack>

      {/* Outside the header row so the banner spans the panel instead of
          shrinking to fit beside the header action. */}
      <Alert
        status='info'
        variant='subtle'
        borderRadius='md'
        bg={infoBg}
        border='1px solid'
        borderColor={infoBorder}
        py={2}
        px={3}
        w='100%'
      >
        <AlertIcon boxSize={4} />
        <AlertDescription fontSize='sm' color={infoText} lineHeight='short'>
          Agents connect outbound-only and lease jobs from this workspace. An
          agent is marked offline when it stops sending heartbeats; retire it to
          invalidate its credential permanently.
        </AlertDescription>
      </Alert>

      {error ? <DashboardErrorAlert>{error}</DashboardErrorAlert> : null}

      {loading ? (
        <HStack spacing={2} color={muted} py={4} justify='center'>
          <Spinner size='sm' />
          <Text fontSize='sm'>Loading agents...</Text>
        </HStack>
      ) : null}

      {!loading && !error && agents.length === 0 ? (
        <Box py={6} textAlign='center'>
          {pageIsPastEnd ? (
            <>
              <Text fontSize='sm' fontWeight='semibold' color={titleColor}>
                This page is past the end of the fleet.
              </Text>
              <Button size='xs' variant='ghost' mt={2} onClick={firstPage}>
                Back to the first page
              </Button>
            </>
          ) : (
            <>
              <Text fontSize='sm' fontWeight='semibold' color={titleColor}>
                No agents yet.
              </Text>
              <Text fontSize='sm' color={muted} mt={1}>
                {canManage
                  ? 'Use the Deploy an agent button on this page to install your first agent.'
                  : 'A workspace manager can deploy agents from this page.'}
              </Text>
            </>
          )}
        </Box>
      ) : null}

      {!loading && agents.length > 0 ? (
        <Box>
          <TableContainer>
            <Table size='sm' variant='simple'>
              <Thead>
                <Tr>
                  <Th>Agent</Th>
                  <Th>OS</Th>
                  <Th>Status</Th>
                  <Th>Version</Th>
                  <Th>Protocol</Th>
                  <Th>Compatibility</Th>
                  <Th>Clock drift</Th>
                  <Th>NTP</Th>
                  <Th>Execution</Th>
                  <Th>Signing key</Th>
                  <Th>Last heartbeat</Th>
                  {canManage ? <Th textAlign='right'>Actions</Th> : null}
                </Tr>
              </Thead>
              <Tbody>
                {agents.map(agent => {
                  const status = String(agent.status || '').toLowerCase();
                  return (
                    <Tr key={agent.id}>
                      <Td>
                        <Box>
                          <Text fontSize='sm' fontWeight='semibold'>
                            {agent.name || agent.hostname || 'Unnamed agent'}
                          </Text>
                          <CopyableId
                            id={agent.agentId}
                            display={shortId(agent.agentId)}
                          />
                        </Box>
                      </Td>
                      <Td>
                        <Text fontSize='sm'>
                          {platformLabel(agent.platform)}
                        </Text>
                      </Td>
                      <Td>
                        <VStack align='flex-start' spacing={0.5}>
                          <AgentStatusBadge
                            status={displayAgentStatus(agent)}
                          />
                          {['offline', 'stale'].includes(
                            String(
                              displayAgentStatus(agent) || ''
                            ).toLowerCase()
                          ) && agent.dependentAutoRenewCertificateCount > 0 ? (
                            <Text
                              fontSize='xs'
                              color='orange.600'
                              title='Auto-renew certificates whose renewal path currently depends on this agent'
                            >
                              {agent.dependentAutoRenewCertificateCount}{' '}
                              auto-renew{' '}
                              {agent.dependentAutoRenewCertificateCount === 1
                                ? 'certificate'
                                : 'certificates'}{' '}
                              affected
                            </Text>
                          ) : null}
                        </VStack>
                      </Td>
                      <Td>
                        <Text fontSize='sm' fontFamily='mono'>
                          {agent.agentVersion || '--'}
                        </Text>
                      </Td>
                      <Td>
                        <Text fontSize='sm' fontFamily='mono'>
                          {agent.protocolVersion === null ||
                          agent.protocolVersion === undefined
                            ? '--'
                            : String(agent.protocolVersion)}
                        </Text>
                      </Td>
                      <Td>
                        <AgentCompatibilityBadge
                          compatibilityState={agent.compatibilityState}
                          compatibilityRange={agent.compatibilityRange}
                        />
                      </Td>
                      <Td>
                        <HStack spacing={2}>
                          <Text fontSize='sm' fontFamily='mono'>
                            {formatClockOffset(agent.clockOffsetMs)}
                          </Text>
                          <ClockDriftBadge
                            clockDriftState={agent.clockDriftState}
                          />
                        </HStack>
                      </Td>
                      <Td>
                        <NtpBadge ntpSynced={agent.ntpSynced} />
                      </Td>
                      <Td>
                        <ExecutionCapabilityBadge
                          supportedOperations={agent.supportedOperations}
                        />
                      </Td>
                      <Td>
                        {agent.pinnedSigningKeyId ? (
                          <CopyableId
                            id={agent.pinnedSigningKeyId}
                            display={shortId(agent.pinnedSigningKeyId)}
                          />
                        ) : (
                          <Text fontSize='sm'>--</Text>
                        )}
                      </Td>
                      <Td>
                        <Text
                          fontSize='sm'
                          color={muted}
                          title={formatDateTime(agent.lastSeenAt)}
                        >
                          {formatRelativeDateTime(agent.lastSeenAt)}
                        </Text>
                      </Td>
                      {canManage ? (
                        <Td textAlign='right'>
                          <HStack spacing={2} justify='flex-end'>
                            {status !== 'retired' ? (
                              <Button
                                size='xs'
                                variant='outline'
                                onClick={() => setAlertingTarget(agent)}
                              >
                                Edit alerting
                              </Button>
                            ) : null}
                            {status !== 'retired' ? (
                              <Button
                                size='xs'
                                colorScheme='red'
                                variant='outline'
                                onClick={() => setRetireTarget(agent)}
                              >
                                Retire
                              </Button>
                            ) : null}
                          </HStack>
                        </Td>
                      ) : null}
                    </Tr>
                  );
                })}
              </Tbody>
            </Table>
          </TableContainer>
          {pagination ? (
            <Box mt={2}>
              <DashboardPagination
                limit={pagination.limit || limit}
                offset={offset}
                total={pagination.total}
                pageSizeOptions={CERTOPS_PAGE_SIZE_OPTIONS}
                noun='agents'
                onChange={setPage}
              />
            </Box>
          ) : null}
        </Box>
      ) : null}

      <RetireAgentModal
        isOpen={Boolean(retireTarget)}
        onClose={() => setRetireTarget(null)}
        agent={retireTarget}
        onRetire={handleRetire}
      />
      <EditAlertingModal
        isOpen={Boolean(alertingTarget)}
        onClose={() => setAlertingTarget(null)}
        agent={alertingTarget}
        onSaved={() => refresh()}
      />
    </Stack>
  );
}
