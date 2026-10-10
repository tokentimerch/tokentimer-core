import CertOpsBadge from './CertOpsBadge.jsx';
import { useEffect, useState } from 'react';
import {
  Alert,
  AlertDescription,
  AlertIcon,
  Box,
  Button,
  Checkbox,
  Flex,
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
  VStack,
} from '@chakra-ui/react';
import {
  DashboardModalDescription,
  DashboardModalFrame,
  DashboardModalTitle,
  useDashboardModalProps,
} from '../DashboardModalFrame.jsx';
import CopyableId from '../CopyableId.jsx';
import AgentShellConsole from './AgentShellConsole.jsx';
import { listAgentFleetLog, listAgentJobLog } from './certopsJobsApi';
import { DashboardErrorAlert } from '../DashboardPrimitives.jsx';
import DashboardPagination from '../DashboardPagination.jsx';
import {
  CERTOPS_PAGE_SIZE_OPTIONS,
  useCertOpsListUrlState,
} from '../../hooks/useCertOpsUrlState.js';
import { useDashboardThemeColors } from '../../hooks/useDashboardTheme';
import { useWorkspace } from '../../utils/WorkspaceContext.jsx';
import { workspaceAPI } from '../../utils/apiClient';
import { showSuccess } from '../../utils/toast.js';
import { retireAgent, updateAgentAlertSettings } from './certopsAgentsApi.js';
import ContactGroupCheckboxGroup from '../ContactGroupCheckboxGroup.jsx';
import {
  canonicalAgentContactGroupFields,
  hydrateContactGroupIds,
} from '../../utils/contactGroupAssignment.js';
import { formatDateTime, formatRelativeDateTime } from './certopsJobsFormat';
import { useCertOpsCanManage } from './useCertOps.js';
import { useCertOpsAgents } from './useCertOpsAgents.js';
import {
  CertOpsMobileFieldLabel,
  CertOpsSortableHeader,
  CertOpsTruncatedText,
  nextCertOpsTableSort,
  useCertOpsResponsiveTableStyles,
} from './CertOpsResponsiveTable.jsx';

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
function AgentStatusBadge({ status }) {
  const key = String(status || '').toLowerCase();
  return (
    <CertOpsBadge
      colorScheme={AGENT_STATUS_SCHEME[key] || 'gray'}
      title={
        key === 'stale'
          ? 'No heartbeat received within the offline threshold; the agent is likely down and awaiting the next fleet sweep.'
          : undefined
      }
    >
      {AGENT_STATUS_LABEL[key] || (status ? String(status) : 'Unknown')}
    </CertOpsBadge>
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

const AGENT_COLUMNS = [
  ['agent', 'Agent'],
  ['os', 'OS'],
  ['status', 'Status'],
  ['version', 'Version'],
  ['protocol', 'Protocol'],
  ['compatibility', 'Compatibility'],
  ['clockDrift', 'Clock drift'],
  ['ntp', 'NTP'],
  ['execution', 'Execution'],
  ['signingKey', 'Signing key'],
  ['lastHeartbeat', 'Last heartbeat'],
];
const AGENT_NON_SORTABLE_COLUMNS = new Set(['status', 'compatibility']);

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
    <CertOpsBadge
      colorScheme={CLOCK_DRIFT_SCHEME[key]}
      title={
        key === 'alert'
          ? 'Clock offset exceeds the alert threshold (CERTOPS_AGENT_CLOCK_DRIFT_ALERT_MS).'
          : 'Clock offset exceeds the warn threshold (CERTOPS_AGENT_CLOCK_DRIFT_WARN_MS).'
      }
    >
      {CLOCK_DRIFT_LABEL[key]}
    </CertOpsBadge>
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

/** Dummy reject-ceilings (major.999.999) are not operator-useful; hide them. */
function isUnboundedVersionCeiling(version) {
  return typeof version === 'string' && /^\d+\.999\.999$/.test(version);
}

/** Version/protocol compatibility chip; 'blocked' is a hard stop (agentJobEligibility.js
 *  rejects every claim from this agent with compatibility_blocked). */
function AgentCompatibilityBadge({ compatibilityState, compatibilityRange }) {
  const key = String(compatibilityState || '').toLowerCase();
  const range = compatibilityRange || {};
  const minAgent = range.minAgentVersion || 'unknown';
  const minProtocol = range.minProtocolVersion || 'unknown';
  const hasRealMax =
    range.maxAgentVersion && !isUnboundedVersionCeiling(range.maxAgentVersion);
  let title = 'This agent meets the versions this control plane accepts.';
  if (key === 'blocked') {
    title = hasRealMax
      ? `This agent is outside the versions this control plane accepts (agent ${minAgent} to ${range.maxAgentVersion}, protocol ${minProtocol} and above). It cannot claim any job until it is upgraded.`
      : `This agent is below the minimum this control plane accepts (agent ${minAgent}, protocol ${minProtocol}). It cannot claim any job until it is upgraded.`;
  } else if (key === 'outdated') {
    title =
      'This agent can still claim jobs, but it is more than one minor version behind the latest known build. Upgrade when convenient.';
  }
  return (
    <CertOpsBadge
      colorScheme={COMPATIBILITY_SCHEME[key] || 'gray'}
      title={title}
    >
      {COMPATIBILITY_LABEL[key] || 'Unknown'}
    </CertOpsBadge>
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
    <CertOpsBadge colorScheme={ntpSynced ? 'green' : 'orange'}>
      {ntpSynced ? 'Synced' : 'Not synced'}
    </CertOpsBadge>
  );
}

/**
 * Execution capability chip: whether this agent declared any executable
 * action the last time it successfully claimed a job. Empty is ambiguous
 * between "observe-only" and "hasn't polled yet" - the title makes that
 * caveat explicit rather than asserting a diagnosis this field can't prove.
 */
function ExecutionCapabilityBadge({ supportedOperations }) {
  const declared = Array.isArray(supportedOperations)
    ? supportedOperations
    : [];
  if (declared.length > 0) {
    return (
      <CertOpsBadge
        colorScheme='green'
        title={`Last declared on claim: ${declared.join(', ')}`}
      >
        Enabled
      </CertOpsBadge>
    );
  }
  return (
    <CertOpsBadge
      colorScheme='orange'
      title={
        'No executable action declared on the last claim call. Most often ' +
        'this means the agent is running observe-only (no execution block, ' +
        'or execution.enabled is not true, in its config.json) - a job ' +
        'pinned to it will sit at Pending forever. A brand-new agent that ' +
        'has not polled for a job yet looks identical here.'
      }
    >
      No capability declared
    </CertOpsBadge>
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
            ml={{ base: 0, md: 3 }}
            mt={{ base: 2, md: 0 }}
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
  const [contactGroupIds, setContactGroupIds] = useState([]);
  const [contactGroups, setContactGroups] = useState([]);
  const [defaultContactGroupId, setDefaultContactGroupId] = useState('');
  const [loadingGroups, setLoadingGroups] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!isOpen || !agent) return undefined;
    setAlertsEnabled(agent.downtimeAlertsEnabled !== false);
    setContactGroupIds(hydrateContactGroupIds(agent));
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
          ...canonicalAgentContactGroupFields(contactGroupIds),
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
            <FormControl
              as='fieldset'
              isDisabled={!alertsEnabled || loadingGroups}
              minW={0}
              overflow='hidden'
            >
              <FormLabel as='legend' fontSize='sm'>
                Contact groups
              </FormLabel>
              <ContactGroupCheckboxGroup
                contactGroups={contactGroups}
                value={contactGroupIds}
                onChange={setContactGroupIds}
                isDisabled={!alertsEnabled || loadingGroups}
                defaultContactGroupId={defaultContactGroupId}
                helperText=''
                maxH='160px'
              />
              <FormHelperText>
                Down and recovery alerts go to the selected groups. Leave as
                workspace default when empty.
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
            ml={{ base: 0, md: 3 }}
            mt={{ base: 2, md: 0 }}
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
const FLEET_ALL = 'all';
// Fleet aggregates many jobs. Per-job and modal-wide budgets prevent one busy
// agent from freezing the browser; open a single job for the full stream.
const FLEET_LOG_PAGE_SIZE = 200;
const FLEET_LOG_MAX_PAGES_PER_JOB = 10;
const FLEET_LOG_TOTAL_MAX_LINES = 4000;
const FLEET_LOG_MAX_CONCURRENCY = 3;

export async function loadAgentLogPages(
  workspaceId,
  jobId,
  {
    signal,
    maxPages = FLEET_LOG_MAX_PAGES_PER_JOB,
    pageSize = FLEET_LOG_PAGE_SIZE,
    maxItems = Number.POSITIVE_INFINITY,
  } = {}
) {
  const items = [];
  let cursor;
  let truncated = false;
  const pageLimit = Math.max(1, Math.min(pageSize, maxItems));
  for (let page = 0; page < maxPages; page += 1) {
    const remaining = maxItems - items.length;
    if (remaining <= 0) {
      truncated = true;
      break;
    }
    const result = await listAgentJobLog(workspaceId, jobId, {
      cursor,
      limit: Math.min(pageLimit, remaining),
      signal,
    });
    const pageItems = result?.items || [];
    items.push(...pageItems);
    if (items.length >= maxItems) {
      truncated = Boolean(result?.hasMore);
      break;
    }
    if (!result?.hasMore || !result?.nextCursor) {
      break;
    }
    if (page === maxPages - 1) {
      truncated = true;
      break;
    }
    cursor = result.nextCursor;
  }
  return { items, truncated };
}

export async function mapWithConcurrency(items, concurrency, worker) {
  const results = new Array(items.length);
  let next = 0;
  const runners = Array.from(
    { length: Math.min(Math.max(1, concurrency), Math.max(items.length, 1)) },
    async () => {
      while (next < items.length) {
        const index = next;
        next += 1;
        results[index] = await worker(items[index], index);
      }
    }
  );
  await Promise.all(runners);
  return results;
}

/**
 * Shared modal line budget. Workers claim page-sized slices and wait for an
 * in-flight peer to release unused capacity instead of skipping the job.
 */
export function createFleetLineBudget(totalLines) {
  let remaining = totalLines;
  // Workers inside withReservation, including those still waiting to claim.
  let holders = 0;
  const waiters = [];
  function notify() {
    while (waiters.length > 0) waiters.shift()();
  }
  return {
    get remaining() {
      return remaining;
    },
    get holders() {
      return holders;
    },
    /**
     * Enter as a holder first so peers waiting on an empty budget do not see
     * holders===0 between another worker's claim and its fetch.
     */
    async withReservation(wanted, work) {
      const need = Math.max(0, wanted);
      holders += 1;
      let reserved = 0;
      let used = 0;
      try {
        if (need === 0) return { reserved: 0, result: null };
        while (remaining < 1) {
          // Another holder may still return unused capacity.
          if (holders <= 1) return { reserved: 0, result: null };
          await new Promise(resolve => {
            waiters.push(resolve);
          });
        }
        reserved = Math.min(remaining, need);
        remaining -= reserved;
        const outcome = await work(reserved);
        used = Math.max(0, Math.min(reserved, Number(outcome?.used) || 0));
        return { reserved, result: outcome?.result ?? null };
      } catch (error) {
        used = 0;
        throw error;
      } finally {
        if (reserved > 0) remaining += reserved - used;
        holders = Math.max(0, holders - 1);
        notify();
      }
    },
  };
}

/**
 * Load log pages for many jobs under a shared line budget.
 * Reserves one page at a time; unused capacity is returned for other jobs.
 */
export async function loadFleetJobBatches(
  workspaceId,
  jobIds,
  {
    signal,
    concurrency = FLEET_LOG_MAX_CONCURRENCY,
    pageSize = FLEET_LOG_PAGE_SIZE,
    maxPagesPerJob = FLEET_LOG_MAX_PAGES_PER_JOB,
    totalMaxLines = FLEET_LOG_TOTAL_MAX_LINES,
    fetchPage = listAgentJobLog,
  } = {}
) {
  const budget = createFleetLineBudget(totalMaxLines);
  return mapWithConcurrency(jobIds, concurrency, async jobId => {
    try {
      const items = [];
      let cursor;
      let truncated = false;
      for (let page = 0; page < maxPagesPerJob; page += 1) {
        const room = totalMaxLines - items.length;
        if (room <= 0) {
          truncated = true;
          break;
        }
        const want = Math.min(pageSize, room);
        let reserved;
        let result;
        try {
          ({ reserved, result } = await budget.withReservation(want, async limit => {
            const pageResult = await fetchPage(workspaceId, jobId, {
              cursor,
              limit,
              signal,
            });
            const pageItems = pageResult?.items || [];
            return {
              used: Math.min(limit, pageItems.length),
              result: pageResult,
            };
          }));
        } catch {
          return { truncated: false, failed: true, jobId, lines: [] };
        }
        if (reserved <= 0) {
          truncated = true;
          break;
        }
        const pageItems = result?.items || [];
        const kept = pageItems.slice(0, reserved);
        items.push(...kept);
        if (items.length >= totalMaxLines) {
          truncated = Boolean(result?.hasMore) || pageItems.length > reserved;
          break;
        }
        if (!result?.hasMore || !result?.nextCursor) {
          break;
        }
        if (page === maxPagesPerJob - 1) {
          truncated = true;
          break;
        }
        cursor = result.nextCursor;
      }
      return {
        truncated,
        failed: false,
        jobId,
        lines: items.map(line => ({
          ...line,
          jobId,
          message: line.message
            ? `[job ${String(jobId).slice(0, 8)}] ${line.message}`
            : line.message,
        })),
      };
    } catch {
      return { truncated: false, failed: true, jobId, lines: [] };
    }
  });
}

function AgentJobLogsModal({ isOpen, onClose, agent, workspaceId }) {
  const { overlayProps, headerProps, bodyProps, closeButtonProps, footerProps } =
    useDashboardModalProps();
  const { muted, text } = useDashboardThemeColors();
  const [jobs, setJobs] = useState([]);
  const [source, setSource] = useState(FLEET_ALL);
  const [mergedLines, setMergedLines] = useState([]);
  const [truncatedJobIds, setTruncatedJobIds] = useState([]);
  const [failedJobIds, setFailedJobIds] = useState([]);
  const [loading, setLoading] = useState(false);
  const agentLabel =
    agent?.name || agent?.hostname || agent?.agentId || 'Agent';
  useEffect(() => {
    if (!isOpen || !agent?.id || !workspaceId) return undefined;
    let cancelled = false;
    const controller = new AbortController();
    setLoading(true);
    setJobs([]);
    setMergedLines([]);
    setTruncatedJobIds([]);
    setFailedJobIds([]);
    setSource(FLEET_ALL);

    (async () => {
      try {
        const result = await listAgentFleetLog(workspaceId, agent.id, {
          limit: 20,
          signal: controller.signal,
        });
        if (cancelled) return;
        const seen = new Set();
        const items = (result.items || []).filter(item => {
          if (!item?.jobId || seen.has(item.jobId)) return false;
          seen.add(item.jobId);
          return true;
        });
        setJobs(items);

        // Newest streams first from the API; reverse so the shell reads oldest→newest.
        const jobIds = [...items.map(item => item.jobId)].reverse();
        const batches = await loadFleetJobBatches(workspaceId, jobIds, {
          signal: controller.signal,
        });
        if (cancelled) return;
        setMergedLines(batches.flatMap(batch => batch.lines));
        setTruncatedJobIds(
          batches.filter(batch => batch.truncated).map(batch => batch.jobId)
        );
        setFailedJobIds(
          batches.filter(batch => batch.failed).map(batch => batch.jobId)
        );
      } catch {
        if (!cancelled) {
          setJobs([]);
          setMergedLines([]);
          setTruncatedJobIds([]);
          setFailedJobIds([]);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();

    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [isOpen, agent, workspaceId]);

  return (
    <Modal isOpen={isOpen} onClose={onClose} isCentered scrollBehavior='inside'>
      <ModalOverlay {...overlayProps} />
      <DashboardModalFrame maxW={{ base: 'calc(100vw - 24px)', md: '720px' }}>
        <ModalHeader {...headerProps}>
          <DashboardModalTitle>Agent logs</DashboardModalTitle>
          <DashboardModalDescription>
            Recent CertOps job output for {agentLabel}, across attempts.
          </DashboardModalDescription>
        </ModalHeader>
        <ModalCloseButton {...closeButtonProps} />
        <ModalBody {...bodyProps}>
          {loading ? (
            <HStack spacing={2} color={muted} py={6} justify='center'>
              <Spinner size='sm' />
              <Text fontSize='sm'>Loading agent logs...</Text>
            </HStack>
          ) : null}
          {!loading && jobs.length === 0 ? (
            <Box py={4}>
              <Text fontSize='sm' fontWeight='semibold' color={text}>
                No job logs for this agent yet.
              </Text>
              <Text fontSize='sm' color={muted} mt={1}>
                Logs appear after the agent claims and reports CertOps jobs.
              </Text>
            </Box>
          ) : null}
          {!loading && jobs.length > 0 ? (
            <Stack spacing={3}>
              <Box>
                <Text fontSize='sm' mb={1} color={muted}>
                  Source
                </Text>
                <Select
                  size='sm'
                  value={source}
                  onChange={event => setSource(event.target.value || FLEET_ALL)}
                >
                  <option value={FLEET_ALL}>
                    All recent jobs ({jobs.length})
                  </option>
                  {jobs.map(job => (
                    <option key={job.jobId} value={job.jobId}>
                      Job {String(job.jobId).slice(0, 8)} · {job.jobStatus}
                    </option>
                  ))}
                </Select>
              </Box>
              {truncatedJobIds.length > 0 ? (
                <Text fontSize='sm' color={muted}>
                  Showing up to {FLEET_LOG_TOTAL_MAX_LINES} lines across recent
                  jobs
                  {truncatedJobIds.length === 1
                    ? ` (truncated for job ${String(truncatedJobIds[0]).slice(0, 8)})`
                    : ` (truncated for ${truncatedJobIds.length} jobs)`}
                  . Open a single job Agent output panel for the full stream.
                </Text>
              ) : null}
              {failedJobIds.length > 0 ? (
                <Text fontSize='sm' color={muted}>
                  Could not load logs for{' '}
                  {failedJobIds.length === 1
                    ? `job ${String(failedJobIds[0]).slice(0, 8)}`
                    : `${failedJobIds.length} jobs`}
                  . Select a job above to retry that stream.
                </Text>
              ) : null}
              {source === FLEET_ALL ? (
                <AgentShellConsole
                  title={`Agent · ${agentLabel}`}
                  staticEntries={mergedLines}
                  maxHeight='360px'
                />
              ) : (
                <AgentShellConsole
                  workspaceId={workspaceId}
                  jobId={source}
                  title={`Agent · ${agentLabel}`}
                  maxHeight='360px'
                />
              )}
            </Stack>
          ) : null}
        </ModalBody>
        <ModalFooter {...footerProps}>
          <Button onClick={onClose}>Close</Button>
        </ModalFooter>
      </DashboardModalFrame>
    </Modal>
  );
}

export default function AgentFleetPanel({ refreshSignal, headerAction } = {}) {
  const { workspaceId } = useWorkspace();
  const canManage = useCertOpsCanManage();
  const { limit, offset, setPage } = useCertOpsListUrlState({
    scope: 'agent',
  });
  const [sort, setSort] = useState({ key: null, direction: 'asc' });
  // The fleet list is unbounded server-side unless a limit is sent. Now that
  // this table has a page control, sending one is safe: every row past the
  // first page is reachable.
  const { enabled, agents, pagination, loading, error, refresh } =
    useCertOpsAgents(refreshSignal, {
      limit,
      offset,
      ...(sort.key ? { sort: sort.key, direction: sort.direction } : {}),
    });

  const [retireTarget, setRetireTarget] = useState(null);
  const [logTarget, setLogTarget] = useState(null);
  const [alertingTarget, setAlertingTarget] = useState(null);

  const { muted, dashboard } = useDashboardThemeColors();
  const titleColor = dashboard.text.primary;
  const infoBg = dashboard.accent.interactiveSurface;
  const infoBorder = dashboard.accent.interactiveBorder;
  const infoText = dashboard.accent.interactiveForeground;
  const tableStyles = useCertOpsResponsiveTableStyles();
  const agentTableProps = {
    ...tableStyles.tableProps,
    sx: {
      ...tableStyles.tableProps.sx,
      'thead th': {
        ...tableStyles.tableProps.sx['thead th'],
        px: 2,
      },
      'thead th button': {
        px: 0,
      },
      'tbody td': {
        ...tableStyles.tableProps.sx['tbody td'],
        verticalAlign: 'top',
      },
    },
  };
  const agentPrimaryCellProps = {
    ...tableStyles.primaryCellProps,
    px: { base: 3, lg: 2 },
    py: { base: 3, lg: '0.45rem' },
    verticalAlign: 'top',
  };
  const agentCellProps = {
    ...tableStyles.cellProps,
    px: { base: 3, lg: 2 },
    py: { base: 2, lg: '0.45rem' },
    verticalAlign: 'top',
  };
  const agentActionCellProps = {
    ...tableStyles.actionCellProps,
    px: { base: 3, lg: 2 },
    py: { base: 2, lg: '0.45rem' },
    verticalAlign: 'top',
  };
  const handleSort = key => {
    setSort(current => nextCertOpsTableSort(current, key));
    setPage({ offset: 0 });
  };
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
          {pagination ? (
            <Flex justify='flex-end' mb={4}>
              <DashboardPagination
                limit={pagination.limit || limit}
                offset={offset}
                total={pagination.total}
                pageSizeOptions={CERTOPS_PAGE_SIZE_OPTIONS}
                noun='agents'
                onChange={setPage}
              />
            </Flex>
          ) : null}
          <TableContainer {...tableStyles.tableContainerProps}>
            <Table {...agentTableProps}>
              <Thead {...tableStyles.theadProps}>
                <Tr>
                  {AGENT_COLUMNS.map(([key, label]) =>
                    AGENT_NON_SORTABLE_COLUMNS.has(key) ? (
                      <Th key={key}>{label}</Th>
                    ) : (
                      <CertOpsSortableHeader
                        key={key}
                        label={label}
                        sortKey={key}
                        sort={sort}
                        onSort={handleSort}
                      />
                    )
                  )}
                  {canManage ? <Th textAlign='right'>Actions</Th> : null}
                </Tr>
              </Thead>
              <Tbody {...tableStyles.tbodyProps}>
                {agents.map(agent => {
                  const status = String(agent.status || '').toLowerCase();
                  return (
                    <Tr key={agent.id} {...tableStyles.rowProps}>
                      <Td {...agentPrimaryCellProps}>
                        <Box>
                          <CertOpsTruncatedText
                            value={
                              agent.name || agent.hostname || 'Unnamed agent'
                            }
                            fontSize='sm'
                            fontWeight='semibold'
                          />
                          <CopyableId
                            id={agent.agentId}
                            display={shortId(agent.agentId)}
                          />
                        </Box>
                      </Td>
                      <Td {...agentCellProps}>
                        <CertOpsMobileFieldLabel color={muted}>
                          OS
                        </CertOpsMobileFieldLabel>
                        <Text fontSize='sm'>
                          {platformLabel(agent.platform)}
                        </Text>
                      </Td>
                      <Td {...agentCellProps}>
                        <CertOpsMobileFieldLabel color={muted}>
                          Status
                        </CertOpsMobileFieldLabel>
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
                              color={dashboard.state.warning}
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
                      <Td {...agentCellProps}>
                        <CertOpsMobileFieldLabel color={muted}>
                          Version
                        </CertOpsMobileFieldLabel>
                        <Text fontSize='sm' fontFamily='mono'>
                          {agent.agentVersion || '--'}
                        </Text>
                      </Td>
                      <Td {...agentCellProps}>
                        <CertOpsMobileFieldLabel color={muted}>
                          Protocol
                        </CertOpsMobileFieldLabel>
                        <Text fontSize='sm' fontFamily='mono'>
                          {agent.protocolVersion === null ||
                          agent.protocolVersion === undefined
                            ? '--'
                            : String(agent.protocolVersion)}
                        </Text>
                      </Td>
                      <Td {...agentCellProps}>
                        <CertOpsMobileFieldLabel color={muted}>
                          Compatibility
                        </CertOpsMobileFieldLabel>
                        <AgentCompatibilityBadge
                          compatibilityState={agent.compatibilityState}
                          compatibilityRange={agent.compatibilityRange}
                        />
                      </Td>
                      <Td {...agentCellProps}>
                        <CertOpsMobileFieldLabel color={muted}>
                          Clock drift
                        </CertOpsMobileFieldLabel>
                        <HStack spacing={2}>
                          <Text fontSize='sm' fontFamily='mono'>
                            {formatClockOffset(agent.clockOffsetMs)}
                          </Text>
                          <ClockDriftBadge
                            clockDriftState={agent.clockDriftState}
                          />
                        </HStack>
                      </Td>
                      <Td {...agentCellProps}>
                        <CertOpsMobileFieldLabel color={muted}>
                          NTP
                        </CertOpsMobileFieldLabel>
                        <NtpBadge ntpSynced={agent.ntpSynced} />
                      </Td>
                      <Td {...agentCellProps}>
                        <CertOpsMobileFieldLabel color={muted}>
                          Execution
                        </CertOpsMobileFieldLabel>
                        <ExecutionCapabilityBadge
                          supportedOperations={agent.supportedOperations}
                        />
                      </Td>
                      <Td {...agentCellProps}>
                        <CertOpsMobileFieldLabel color={muted}>
                          Signing key
                        </CertOpsMobileFieldLabel>
                        {agent.pinnedSigningKeyId ? (
                          <CopyableId
                            id={agent.pinnedSigningKeyId}
                            display={shortId(agent.pinnedSigningKeyId)}
                          />
                        ) : (
                          <Text fontSize='sm'>--</Text>
                        )}
                      </Td>
                      <Td {...agentCellProps}>
                        <CertOpsMobileFieldLabel color={muted}>
                          Last heartbeat
                        </CertOpsMobileFieldLabel>
                        <Text
                          fontSize='sm'
                          color={muted}
                          title={formatDateTime(agent.lastSeenAt)}
                        >
                          {formatRelativeDateTime(agent.lastSeenAt)}
                        </Text>
                      </Td>
                      {canManage ? (
                        <Td {...agentActionCellProps} textAlign='right'>
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
                            <Button
                              size='xs'
                              variant='outline'
                              onClick={() => setLogTarget(agent)}
                            >
                              View logs
                            </Button>
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
        </Box>
      ) : null}

      <AgentJobLogsModal
        isOpen={Boolean(logTarget)}
        onClose={() => setLogTarget(null)}
        agent={logTarget}
        workspaceId={workspaceId}
      />
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
