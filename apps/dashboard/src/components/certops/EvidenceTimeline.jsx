import CertOpsBadge from './CertOpsBadge.jsx';
import {
  Box,
  Button,
  Flex,
  HStack,
  Icon,
  IconButton,
  Popover,
  PopoverArrow,
  PopoverBody,
  PopoverContent,
  PopoverTrigger,
  Spinner,
  Text,
  Tooltip,
  VStack,
} from '@chakra-ui/react';
import {
  AlertTriangle,
  CheckCircle2,
  Circle,
  FileSearch,
  MoreHorizontal,
  Play,
  Shield,
  X,
  XCircle,
} from 'lucide-react';
import { Link as RouterLink } from 'react-router';
import { useMemo } from 'react';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import CopyableId from '../CopyableId.jsx';
import {
  evidenceTypeLabel,
  evidenceTypeScheme,
  eventTypeLabel,
  formatDateTime,
  hasRedactionMarkers,
  jobOperationLabel,
  pendingReasonLabel,
  sameOperatorMessage,
  subjectTypeLabel,
  userFacingName,
} from './certopsJobsFormat';
import JobStatusBadge from './JobStatusBadge.jsx';
import { useCertOpsJobTimeline } from './useCertOpsJobs.js';
import AgentShellConsole from './AgentShellConsole.jsx';
import { useWorkspace } from '../../utils/WorkspaceContext.jsx';
import { useCertOpsAgents } from './useCertOpsAgents.js';
import { agentDisplayName, indexAgentsByAnyId } from './certopsAgentLabel.js';
import { truncationSummary } from './certopsPagination.js';

const REDACTION_TOOLTIP = 'Sensitive values were removed before storage.';

function ApprovedByLine({ job, color }) {
  const name = userFacingName(
    job?.approvedByUserId,
    job?.approvedByDisplayName
  );
  if (!name) return null;
  return (
    <Text fontSize='xs' color={color}>
      Approved by {name}
    </Text>
  );
}

function MetadataField({ label, children }) {
  return (
    <Box minW={0}>
      <Text fontSize='xs' color='gray.500' mb={0.5}>
        {label}
      </Text>
      {children}
    </Box>
  );
}

function AgentMetadataField({ id, label, agentsById }) {
  if (!id) return null;
  const agent =
    agentsById instanceof Map ? agentsById.get(String(id)) : null;
  const name = agentDisplayName(agent);
  return (
    <MetadataField label={label}>
      {name ? (
        <Text fontSize='xs' fontWeight='medium' noOfLines={1} title={name}>
          {name}
        </Text>
      ) : null}
      <CopyableId id={id} />
    </MetadataField>
  );
}

function JobMetadataDetails({ job, agentsById, includeJobId = true }) {
  const { dashboard } = useDashboardTheme();
  const attemptLabel =
    typeof job.attemptCount === 'number'
      ? typeof job.maxAttempts === 'number'
        ? `${job.attemptCount} of ${job.maxAttempts}`
        : String(job.attemptCount)
      : null;

  return (
    <VStack align='stretch' spacing={3}>
      {includeJobId && job.id ? (
        <MetadataField label='Job ID'>
          <CopyableId id={job.id} />
        </MetadataField>
      ) : null}
      {job.source ? (
        <MetadataField label='Executor source'>
          <Text fontSize='xs'>{job.source}</Text>
        </MetadataField>
      ) : null}
      {job.subjectId ? (
        <MetadataField
          label={subjectTypeLabel(job.subjectType) || 'Subject'}
        >
          <CopyableId id={job.subjectId} />
        </MetadataField>
      ) : null}
      {job.claimId ? (
        <MetadataField label='Claim ID'>
          <CopyableId id={job.claimId} />
        </MetadataField>
      ) : null}
      <AgentMetadataField
        id={job.claimedByAgentId}
        label='Claimed by agent'
        agentsById={agentsById}
      />
      {job.assignedAgentId &&
      job.assignedAgentId !== job.claimedByAgentId ? (
        <AgentMetadataField
          id={job.assignedAgentId}
          label='Assigned agent'
          agentsById={agentsById}
        />
      ) : null}
      {job.claimedByControllerClusterId ? (
        <MetadataField label='Claimed by controller'>
          <CopyableId id={job.claimedByControllerClusterId} />
        </MetadataField>
      ) : null}
      {job.claimedByAgentSigningKeyId ? (
        <MetadataField label="Agent's pinned signing key">
          <CopyableId id={job.claimedByAgentSigningKeyId} />
        </MetadataField>
      ) : null}
      <ApprovedByLine job={job} />
      {job.leaseExpiresAt ? (
        <MetadataField label='Lease expires'>
          <Text fontSize='xs'>{formatDateTime(job.leaseExpiresAt)}</Text>
        </MetadataField>
      ) : null}
      {attemptLabel ? (
        <MetadataField label='Attempt'>
          <Text fontSize='xs'>{attemptLabel}</Text>
        </MetadataField>
      ) : null}
      {job.approvedAt ? (
        <MetadataField label='Approved'>
          <Text fontSize='xs'>{formatDateTime(job.approvedAt)}</Text>
        </MetadataField>
      ) : null}
      {job.id ? (
        <Button
          as={RouterLink}
          to={`/audit?q=${encodeURIComponent(job.id)}`}
          size='sm'
          variant='outline'
          mt={1}
          w='100%'
          leftIcon={<Icon as={FileSearch} boxSize={3.5} />}
          color={dashboard.accent.interactiveForeground}
          borderColor={dashboard.accent.interactiveBorder}
          bg={dashboard.accent.interactiveSurface}
          _hover={{
            bg: dashboard.accent.interactiveSurface,
            borderColor: dashboard.accent.interactiveForeground,
          }}
        >
          View audit log
        </Button>
      ) : null}
    </VStack>
  );
}

function JobMetadataPopover({
  job,
  agentsById,
  includeJobId = true,
  border,
  borderStrong,
  muted,
  text,
}) {
  return (
    <Popover placement='bottom-start' isLazy>
      <PopoverTrigger>
        <IconButton
          aria-label='Job metadata'
          title='Job metadata'
          icon={<Icon as={MoreHorizontal} boxSize={5} />}
          size='sm'
          variant='outline'
          color={text}
          borderColor={borderStrong || border}
          borderWidth='1px'
          bg='transparent'
          _hover={{ bg: 'blackAlpha.50', borderColor: muted }}
          _dark={{
            color: 'white',
            borderColor: 'whiteAlpha.500',
            _hover: { bg: 'whiteAlpha.150', borderColor: 'whiteAlpha.700' },
          }}
        />
      </PopoverTrigger>
      <PopoverContent
        w='min(340px, calc(100vw - 32px))'
        borderColor={border}
      >
        <PopoverArrow />
        <PopoverBody>
          <JobMetadataDetails
            job={job}
            agentsById={agentsById}
            includeJobId={includeJobId}
          />
        </PopoverBody>
      </PopoverContent>
    </Popover>
  );
}

function RedactionBadge() {
  return (
    <Tooltip label={REDACTION_TOOLTIP} hasArrow placement='top' openDelay={250}>
      <CertOpsBadge colorScheme='orange'>Redacted</CertOpsBadge>
    </Tooltip>
  );
}

function timelineIcon(kind, type) {
  if (kind === 'evidence') {
    if (type === 'validation.passed') return CheckCircle2;
    if (type === 'validation.failed') return XCircle;
    if (type === 'policy.checked') return Shield;
    return FileSearch;
  }
  if (type === 'job.failed' || type === 'job.rejected') return XCircle;
  if (type === 'job.completed') return CheckCircle2;
  if (type === 'job.started') return Play;
  if (type === 'job.cancelled') return AlertTriangle;
  return Circle;
}

function timelineIconColor(kind, type) {
  if (kind === 'evidence') {
    return evidenceTypeScheme(type);
  }
  if (type === 'job.failed' || type === 'job.rejected') return 'red';
  if (type === 'job.completed') return 'green';
  if (type === 'job.started') return 'blue';
  if (type === 'job.cancelled') return 'orange';
  return 'gray';
}

/**
 * Human-readable summary for evidence metadata, preferred over the generic
 * subject line when present. Prefers the server-provided `metadata.summary`
 * sentence; falls back to synthesizing one from individual certificate /
 * secret / namespace / operation fields for evidence shapes that don't
 * carry a `summary` yet.
 */
function evidenceMetadataSummary(metadata) {
  if (!metadata || typeof metadata !== 'object') return '';
  if (typeof metadata.summary === 'string' && metadata.summary.trim()) {
    return metadata.summary.trim();
  }
  const { certificateName, secretName, namespace, operation } = metadata;
  const subjectName = certificateName || secretName;
  if (!subjectName && !operation && !namespace) return '';
  const parts = [];
  if (subjectName) {
    parts.push(`${certificateName ? 'Certificate' : 'Secret'} ${subjectName}`);
  }
  if (operation) parts.push(String(operation));
  let summary = parts.join(' ').trim();
  if (namespace) {
    summary = summary
      ? `${summary} in namespace ${namespace}`
      : `In namespace ${namespace}`;
  }
  return summary;
}

/**
 * True attempt number reported by the executor, when present. Log entries may
 * carry a numeric `metadata.attempt` counter (an allowed public metadata
 * field); it is authoritative regardless of pagination truncation.
 */
function reportedAttemptNumber(entry) {
  const attempt = entry?.metadata?.attempt;
  if (typeof attempt === 'number' && Number.isInteger(attempt) && attempt > 0) {
    return attempt;
  }
  return null;
}

function mergeTimelineItems(logEntries, evidence) {
  const logs = (Array.isArray(logEntries) ? logEntries : []).map(entry => ({
    kind: 'log',
    id: `log-${entry.id}`,
    sortAt: entry.createdAt || '',
    entry,
  }));
  const evidenceItems = (Array.isArray(evidence) ? evidence : []).map(item => ({
    kind: 'evidence',
    id: `evidence-${item.id}`,
    sortAt: item.observedAt || item.createdAt || '',
    entry: item,
  }));

  return [...logs, ...evidenceItems].sort((a, b) => {
    const aTime = new Date(a.sortAt).getTime();
    const bTime = new Date(b.sortAt).getTime();
    const aValid = Number.isFinite(aTime) ? aTime : 0;
    const bValid = Number.isFinite(bTime) ? bTime : 0;
    if (aValid !== bValid) return aValid - bValid;
    return String(a.id).localeCompare(String(b.id));
  });
}

function TimelineItem({
  item,
  attemptLabel,
  compact = false,
  hideDetail = false,
}) {
  const { muted, border, dashboard } = useDashboardTheme();
  const dotBg = dashboard.bg.panel;
  const isEvidence = item.kind === 'evidence';
  const { entry } = item;
  const type = isEvidence ? entry.evidenceType : entry.eventType;
  const IconCmp = timelineIcon(item.kind, type);
  const scheme = timelineIconColor(item.kind, type);
  const title = isEvidence ? evidenceTypeLabel(type) : eventTypeLabel(type);
  const timestamp = formatDateTime(
    isEvidence ? entry.observedAt || entry.createdAt : entry.createdAt
  );
  const redacted = hasRedactionMarkers(entry.metadata);
  const subjectLabel = isEvidence
    ? [subjectTypeLabel(entry.subjectType), entry.subjectId]
        .filter(Boolean)
        .join(': ')
    : '';
  const metadataSummary = isEvidence
    ? evidenceMetadataSummary(entry.metadata)
    : '';
  const detail = isEvidence
    ? metadataSummary || subjectLabel || 'No subject recorded'
    : entry.message || entry.status || '';
  const decidedByName =
    !isEvidence && (type === 'approval.granted' || type === 'approval.rejected')
      ? userFacingName(entry.createdByUserId, entry.createdByDisplayName)
      : '';

  return (
    <Box position='relative' pl={6} pb={4} _last={{ pb: 0 }}>
      <Flex
        position='absolute'
        left='-7px'
        top='2px'
        align='center'
        justify='center'
        w='14px'
        h='14px'
        borderRadius='full'
        bg={dotBg}
        borderWidth='1px'
        borderColor={border}
      >
        <Icon as={IconCmp} boxSize={2.5} color={`${scheme}.400`} />
      </Flex>

      <VStack align='stretch' spacing={1}>
        <HStack spacing={2} flexWrap='wrap'>
          <Text fontSize='sm' fontWeight='semibold'>
            {title}
          </Text>
          {attemptLabel ? (
            <CertOpsBadge colorScheme='blue'>{attemptLabel}</CertOpsBadge>
          ) : null}
          {redacted ? <RedactionBadge /> : null}
        </HStack>
        {!compact && isEvidence && entry.subjectId ? (
          <CopyableId
            id={entry.subjectId}
            label={subjectTypeLabel(entry.subjectType) || 'Subject'}
            size='xs'
          />
        ) : !hideDetail && detail ? (
          <Text fontSize='sm' color={muted}>
            {detail}
          </Text>
        ) : null}
        {compact && isEvidence && entry.subjectId ? (
          <Box as='details' fontSize='xs' color={muted}>
            <Text as='summary' cursor='pointer' w='fit-content'>
              Evidence subject
            </Text>
            <Box mt={1}>
              <CopyableId
                id={entry.subjectId}
                label={subjectTypeLabel(entry.subjectType) || 'Subject'}
                size='xs'
              />
            </Box>
          </Box>
        ) : null}
        {decidedByName ? (
          <Text fontSize='xs' color={muted}>
            Decided by {decidedByName}
          </Text>
        ) : null}
        <Text fontSize='xs' color={muted}>
          {timestamp}
        </Text>
      </VStack>
    </Box>
  );
}

/**
 * Full job + evidence timeline for a single CertOps job.
 *
 * @param {{ jobId: string, onClose?: function, refreshToken?: * }} props
 */
export default function EvidenceTimeline({
  jobId,
  onClose,
  refreshToken,
  compact = false,
  embedded = false,
}) {
  const { workspaceId } = useWorkspace();
  const { muted, border, borderStrong, text, dashboard } = useDashboardTheme();
  const failureBg = dashboard.callout.dangerSurface;
  const failureBorder = dashboard.callout.dangerBorder;
  const waitingBg = dashboard.callout.warningSurface;
  const waitingBorder = dashboard.callout.warningBorder;
  const { agents } = useCertOpsAgents();
  const agentsById = useMemo(() => indexAgentsByAnyId(agents), [agents]);
  const {
    job,
    logEntries,
    logPagination,
    evidence,
    evidencePagination,
    loading,
    error,
  } = useCertOpsJobTimeline(jobId, refreshToken);

  if (loading) {
    return (
      <Flex justify='center' align='center' py={8}>
        <Spinner size='sm' />
      </Flex>
    );
  }

  if (error) {
    return (
      <Text fontSize='sm' color={dashboard.state.danger}>
        {error}
      </Text>
    );
  }

  if (!job) {
    return (
      <Text fontSize='sm' color={muted}>
        Job not found or no longer available.
      </Text>
    );
  }

  const items = mergeTimelineItems(logEntries, evidence);
  let startedCount = 0;

  const logTruncation = truncationSummary({
    shown: Array.isArray(logEntries) ? logEntries.length : 0,
    pagination: logPagination,
    noun: 'log entries',
  });
  const logsTruncated = Boolean(logTruncation);

  const truncationNotes = [
    logTruncation,
    truncationSummary({
      shown: Array.isArray(evidence) ? evidence.length : 0,
      pagination: evidencePagination,
      noun: 'evidence items',
    }),
  ].filter(Boolean);

  return (
    <VStack align='stretch' spacing={3}>
      <HStack justify='space-between' align='center' spacing={3}>
        <HStack spacing={2} flexWrap='wrap' minW={0} flex='1'>
          <JobMetadataPopover
            job={job}
            agentsById={agentsById}
            includeJobId={!embedded || compact}
            border={border}
            borderStrong={borderStrong}
            muted={muted}
            text={text}
          />
          {!embedded && !compact ? (
            <>
              <Text fontSize='sm' fontWeight='bold'>
                {jobOperationLabel(job.operation)}
              </Text>
              <JobStatusBadge status={job.status} />
              {job.source ? <CertOpsBadge>{job.source}</CertOpsBadge> : null}
            </>
          ) : null}
        </HStack>
        {typeof onClose === 'function' ? (
          <IconButton
            aria-label='Close timeline'
            icon={<Icon as={X} boxSize={3.5} />}
            size='xs'
            variant='ghost'
            onClick={onClose}
            flexShrink={0}
          />
        ) : null}
      </HStack>

      {job.errorCode || job.errorMessage ? (
        <Box
          bg={failureBg}
          borderWidth='1px'
          borderColor={failureBorder}
          borderRadius='md'
          px={3}
          py={2}
        >
          <Text
            fontSize='xs'
            fontWeight='semibold'
            color={dashboard.state.danger}
            mb={1}
          >
            Failure reason
          </Text>
          {job.errorCode ? (
            <Text fontSize='sm' fontFamily='mono'>
              {job.errorCode}
            </Text>
          ) : null}
          {job.errorMessage ? (
            <Text fontSize='sm' color={muted}>
              {job.errorMessage}
            </Text>
          ) : null}
        </Box>
      ) : job.pendingReason?.message ? (
        <Box
          bg={waitingBg}
          borderWidth='1px'
          borderColor={waitingBorder}
          borderRadius='md'
          px={3}
          py={2}
        >
          <Text
            fontSize='xs'
            fontWeight='semibold'
            color={dashboard.callout.warningText}
            mb={1}
          >
            {pendingReasonLabel(job.pendingReason) || 'Why this is waiting'}
          </Text>
          <Text fontSize='sm' color={muted}>
            {job.pendingReason.message}
          </Text>
        </Box>
      ) : null}

      {items.length === 0 ? (
        <Text fontSize='sm' color={muted}>
          No timeline events recorded yet.
        </Text>
      ) : (
        <Box borderLeftWidth='2px' borderColor={border} ml={1} pl={1}>
          {items.map(item => {
            let attemptLabel = null;
            if (item.kind === 'log' && item.entry.eventType === 'job.started') {
              startedCount += 1;
              const reported = reportedAttemptNumber(item.entry);
              if (reported !== null) {
                // Executor-reported counter is truncation-proof.
                if (reported > 1) attemptLabel = `Attempt ${reported}`;
              } else if (startedCount > 1) {
                // Older entries may be truncated away, in which case counting
                // visible job.started entries yields a wrong absolute number;
                // fall back to a non-absolute label.
                attemptLabel = logsTruncated
                  ? 'Later attempt'
                  : `Attempt ${startedCount}`;
              }
            }
            const logMessage =
              item.kind === 'log'
                ? item.entry.message || item.entry.status || ''
                : '';
            const hideDetail =
              sameOperatorMessage(logMessage, job.errorMessage) ||
              sameOperatorMessage(logMessage, job.pendingReason?.message);
            return (
              <TimelineItem
                key={item.id}
                item={item}
                attemptLabel={attemptLabel}
                compact={compact}
                hideDetail={hideDetail}
              />
            );
          })}
        </Box>
      )}

      {truncationNotes.length > 0 ? (
        <Text fontSize='xs' color={muted}>
          {truncationNotes.join(' · ')}
        </Text>
      ) : null}
      {workspaceId && jobId ? (
        <AgentShellConsole
          workspaceId={workspaceId}
          jobId={jobId}
          title='Agent output'
          maxHeight='200px'
        />
      ) : null}
    </VStack>
  );
}
