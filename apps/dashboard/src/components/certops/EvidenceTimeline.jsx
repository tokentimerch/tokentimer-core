import CertOpsBadge from './CertOpsBadge.jsx';
import {
  Box,
  Divider,
  Flex,
  HStack,
  Icon,
  IconButton,
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
  Play,
  Shield,
  X,
  XCircle,
} from 'lucide-react';
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
import {
  JobDetailsButton,
  JobExecutionSummary,
} from './JobDetailsButton.jsx';
import { useWorkspace } from '../../utils/WorkspaceContext.jsx';
import { useCertOpsAgents } from './useCertOpsAgents.js';
import { indexAgentsByAnyId } from './certopsAgentLabel.js';
import { truncationSummary } from './certopsPagination.js';

const REDACTION_TOOLTIP = 'Sensitive values were removed before storage.';

/** Marker diameter; spine is centered through this column. */
const TIMELINE_MARKER = 24;
const TIMELINE_SPINE = 2;
const TIMELINE_GAP = 12;

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
    <Flex align='flex-start' gap={`${TIMELINE_GAP}px`} pb={5} _last={{ pb: 0 }}>
      <Flex
        flexShrink={0}
        align='center'
        justify='center'
        w={`${TIMELINE_MARKER}px`}
        h={`${TIMELINE_MARKER}px`}
        borderRadius='full'
        bg={`${scheme}.50`}
        borderWidth='1.5px'
        borderColor={`${scheme}.200`}
        boxShadow={`0 0 0 3px ${dotBg}`}
        position='relative'
        zIndex={1}
        _dark={{
          bg: `${scheme}.900`,
          borderColor: `${scheme}.600`,
        }}
      >
        <Icon
          as={IconCmp}
          boxSize={3.5}
          color={`${scheme}.500`}
          strokeWidth={2.25}
          _dark={{ color: `${scheme}.300` }}
        />
      </Flex>

      <VStack align='stretch' spacing={1} minW={0} flex={1} pt='1px'>
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
    </Flex>
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
  const { muted, border, dashboard } = useDashboardTheme();
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

  const showStandaloneHeader = !embedded;
  const timelineBody =
    items.length === 0 ? (
      <Text fontSize='sm' color={muted}>
        No timeline events recorded yet.
      </Text>
    ) : (
      <Box position='relative'>
        <Box
          aria-hidden
          position='absolute'
          left={`${(TIMELINE_MARKER - TIMELINE_SPINE) / 2}px`}
          top={`${TIMELINE_MARKER / 2}px`}
          bottom={`${TIMELINE_MARKER / 2}px`}
          w={`${TIMELINE_SPINE}px`}
          bg={border}
        />
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
    );

  return (
    <VStack align='stretch' spacing={3}>
      {showStandaloneHeader ? (
        <>
          <HStack justify='space-between' align='center' spacing={3}>
            <HStack spacing={2} flexWrap='wrap' minW={0} flex='1'>
              {!compact ? (
                <>
                  <Text fontSize='sm' fontWeight='bold'>
                    {jobOperationLabel(job.operation)}
                  </Text>
                  <JobStatusBadge status={job.status} />
                  {job.source ? <CertOpsBadge>{job.source}</CertOpsBadge> : null}
                </>
              ) : null}
              <JobDetailsButton job={job} agentsById={agentsById} />
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
          <Divider borderColor={border} opacity={0.85} />
        </>
      ) : null}

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

      <JobExecutionSummary job={job} agentsById={agentsById} />

      <Divider borderColor={border} opacity={0.85} />
      {timelineBody}

      {truncationNotes.length > 0 ? (
        <Text fontSize='xs' color={muted}>
          {truncationNotes.join(' · ')}
        </Text>
      ) : null}
      {workspaceId && jobId ? (
        <>
          <Divider borderColor={border} opacity={0.85} />
          <AgentShellConsole
            workspaceId={workspaceId}
            jobId={jobId}
            title='Agent output'
            maxHeight='200px'
          />
        </>
      ) : null}
    </VStack>
  );
}
