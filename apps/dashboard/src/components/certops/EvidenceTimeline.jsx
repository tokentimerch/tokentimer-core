import {
  Badge,
  Box,
  Flex,
  HStack,
  Icon,
  IconButton,
  Link,
  Spinner,
  Text,
  Tooltip,
  VStack,
  useColorModeValue,
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
import { Link as RouterLink } from 'react-router-dom';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import {
  evidenceTypeLabel,
  evidenceTypeScheme,
  eventTypeLabel,
  formatDateTime,
  hasRedactionMarkers,
  jobOperationLabel,
} from './certopsJobsFormat';
import JobStatusBadge from './JobStatusBadge.jsx';
import { useCertOpsJobTimeline } from './useCertOpsJobs.js';
import { truncationSummary } from './certopsPagination.js';

const REDACTION_TOOLTIP = 'Sensitive values were removed before storage.';

function RedactionBadge() {
  return (
    <Tooltip label={REDACTION_TOOLTIP} hasArrow placement='top' openDelay={250}>
      <Badge
        colorScheme='orange'
        variant='subtle'
        textTransform='none'
        fontSize='2xs'
        fontWeight='medium'
      >
        Redacted
      </Badge>
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

function TimelineItem({ item, attemptLabel }) {
  const { muted, border } = useDashboardTheme();
  const dotBg = useColorModeValue('white', 'gray.800');
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
  const detail = isEvidence
    ? [entry.subjectType, entry.subjectId].filter(Boolean).join(' / ') ||
      'No subject recorded'
    : entry.message || entry.status || '';

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
            <Badge
              colorScheme='blue'
              variant='outline'
              textTransform='none'
              fontSize='2xs'
            >
              {attemptLabel}
            </Badge>
          ) : null}
          {isEvidence ? (
            <Badge
              colorScheme={evidenceTypeScheme(type)}
              variant='subtle'
              textTransform='none'
              fontSize='2xs'
            >
              {evidenceTypeLabel(type)}
            </Badge>
          ) : null}
          {redacted ? <RedactionBadge /> : null}
        </HStack>
        {detail ? (
          <Text fontSize='sm' color={muted} noOfLines={3}>
            {detail}
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
 * @param {{ jobId: string, onClose?: function }} props
 */
export default function EvidenceTimeline({ jobId, onClose }) {
  const { muted, border } = useDashboardTheme();
  const failureBg = useColorModeValue('red.50', 'rgba(127, 29, 29, 0.28)');
  const failureBorder = useColorModeValue('red.200', 'red.700');
  const {
    job,
    logEntries,
    logPagination,
    evidence,
    evidencePagination,
    loading,
    error,
  } = useCertOpsJobTimeline(jobId);

  if (loading) {
    return (
      <Flex justify='center' align='center' py={8}>
        <Spinner size='sm' />
      </Flex>
    );
  }

  if (error) {
    return (
      <Text fontSize='sm' color='red.400'>
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

  const truncationNotes = [
    truncationSummary({
      shown: Array.isArray(logEntries) ? logEntries.length : 0,
      pagination: logPagination,
      noun: 'log entries',
    }),
    truncationSummary({
      shown: Array.isArray(evidence) ? evidence.length : 0,
      pagination: evidencePagination,
      noun: 'evidence items',
    }),
  ].filter(Boolean);

  const subjectInfo = [job.subjectType, job.subjectId]
    .filter(Boolean)
    .join(' / ');

  return (
    <VStack align='stretch' spacing={3}>
      <HStack justify='space-between' align='start' spacing={3}>
        <HStack spacing={2} flexWrap='wrap'>
          <Text fontSize='sm' fontWeight='bold'>
            {jobOperationLabel(job.operation)}
          </Text>
          <JobStatusBadge status={job.status} />
          {job.source ? (
            <Badge variant='outline' textTransform='none' fontSize='2xs'>
              {job.source}
            </Badge>
          ) : null}
          {subjectInfo ? (
            <Text fontSize='xs' color={muted}>
              {subjectInfo}
            </Text>
          ) : null}
          {job.id ? (
            <Link
              as={RouterLink}
              to={`/audit?q=${encodeURIComponent(job.id)}`}
              fontSize='xs'
              color='blue.400'
            >
              View audit log
            </Link>
          ) : null}
        </HStack>
        {typeof onClose === 'function' ? (
          <IconButton
            aria-label='Close timeline'
            icon={<Icon as={X} boxSize={3.5} />}
            size='xs'
            variant='ghost'
            onClick={onClose}
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
          <Text fontSize='xs' fontWeight='semibold' color='red.400' mb={1}>
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
              if (startedCount > 1) {
                attemptLabel = `Attempt ${startedCount}`;
              }
            }
            return (
              <TimelineItem
                key={item.id}
                item={item}
                attemptLabel={attemptLabel}
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
    </VStack>
  );
}
