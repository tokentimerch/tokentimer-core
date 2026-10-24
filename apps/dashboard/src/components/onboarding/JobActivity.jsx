import { useCallback, useEffect, useRef, useState } from 'react';
import {
  Box,
  Flex,
  HStack,
  Icon,
  Spinner,
  Text,
  VStack,
} from '@chakra-ui/react';
import {
  FiAlertTriangle,
  FiCheckCircle,
  FiCircle,
  FiClock,
  FiXCircle,
} from 'react-icons/fi';
import {
  useDashboardTheme,
  useDashboardThemeColors,
} from '../../hooks/useDashboardTheme';
import AgentShellConsole from '../certops/AgentShellConsole.jsx';
import {
  getJob,
  listJobEvidence,
  listJobLog,
} from '../certops/certopsJobsApi.js';
import { jobStatusLabel } from '../certops/certopsJobsFormat.js';
import { truncationSummary } from '../certops/certopsPagination.js';
import { SENSITIVE_PATTERN } from './certopsConfig.js';
import {
  buildJobTimeline,
  formatClock,
  formatStamp,
  isJobFinal,
} from './jobTimeline.js';
import { StatusPanel, StatusTag } from './panels.jsx';

const POLL_MS = 4000;

const STATUS_VIEW = {
  done: { icon: FiCheckCircle, tone: 'success', tag: '', tagTone: 'green' },
  failed: { icon: FiXCircle, tone: 'danger', tag: 'Failed', tagTone: 'red' },
  active: { icon: FiClock, tone: 'info', tag: 'In progress', tagTone: 'blue' },
  waiting: {
    icon: FiClock,
    tone: 'warning',
    tag: 'Waiting',
    tagTone: 'orange',
  },
  info: { icon: FiCircle, tone: 'muted', tag: '', tagTone: 'gray' },
};

/** A log line that looks like a credential is hidden, never shown or copied. */
export function hideSecretLine(message) {
  return SENSITIVE_PATTERN.test(String(message))
    ? '[line hidden: it looked like a credential]'
    : message;
}

/**
 * The events of one job as an ordered list: when it happened, what it was and
 * whether it succeeded. Pure display of what buildJobTimeline returns.
 */
export function JobTimelineList({ events, label = 'Job timeline' }) {
  const { muted, border } = useDashboardTheme();
  const { dashboard } = useDashboardThemeColors();
  const color = {
    success: dashboard.state.success,
    danger: dashboard.state.danger,
    warning: dashboard.state.warning,
    info: dashboard.accent.interactiveForeground,
    muted,
  };
  if (!events.length) {
    return (
      <Text fontSize='sm' color={muted} data-testid='timeline-empty'>
        No events have been recorded for this job yet.
      </Text>
    );
  }
  return (
    <Box
      as='ol'
      aria-label={label}
      listStyleType='none'
      m={0}
      p={0}
      data-testid='job-timeline'
    >
      {events.map((event, index) => {
        const view = STATUS_VIEW[event.status] || STATUS_VIEW.info;
        const last = index === events.length - 1;
        return (
          <Flex
            as='li'
            key={event.id}
            gap={3}
            data-status={event.status}
            data-testid='timeline-event'
          >
            <Flex direction='column' align='center' flexShrink={0} w='20px'>
              <Icon
                as={view.icon}
                boxSize={4}
                mt='2px'
                color={color[view.tone]}
                aria-hidden
              />
              {last ? null : (
                <Box
                  aria-hidden
                  flex='1'
                  w='2px'
                  my={1}
                  minH='14px'
                  bg={border}
                />
              )}
            </Flex>
            <Box flex='1' minW={0} pb={last ? 0 : 3}>
              <Flex
                direction={{ base: 'column', md: 'row' }}
                justify='space-between'
                gap={{ base: 0, md: 3 }}
              >
                <HStack spacing={2} flexWrap='wrap' minW={0}>
                  <Text fontSize='sm' fontWeight='semibold'>
                    {event.label}
                  </Text>
                  {view.tag ? (
                    <StatusTag tone={view.tagTone}>{view.tag}</StatusTag>
                  ) : null}
                </HStack>
                {event.at ? (
                  <Text
                    as='time'
                    dateTime={event.at}
                    title={formatStamp(event.at)}
                    fontSize='xs'
                    color={muted}
                    _light={{ color: muted }}
                    flexShrink={0}
                    fontFamily='mono'
                  >
                    {formatClock(event.at)}
                  </Text>
                ) : null}
              </Flex>
              {event.detail ? (
                <Text
                  fontSize='xs'
                  color={muted}
                  _light={{ color: muted }}
                  overflowWrap='anywhere'
                >
                  {hideSecretLine(event.detail)}
                </Text>
              ) : null}
            </Box>
          </Flex>
        );
      })}
    </Box>
  );
}

/**
 * Timeline and live agent output for one job, read from the server. Reads
 * the job, its event log and evidence every few seconds while the job is
 * moving and stops once it is final. The agent output panel does the same for
 * its own lines.
 */
export default function JobActivity({
  workspaceId,
  jobId,
  title = 'What happened',
  outputTitle = 'Agent output',
  showOutput = true,
}) {
  const { muted } = useDashboardTheme();
  const [state, setState] = useState({
    loading: true,
    error: '',
    job: null,
    logEntries: [],
    logPagination: null,
    evidence: [],
  });
  const [agentLines, setAgentLines] = useState([]);
  const finalRef = useRef(false);

  const load = useCallback(
    async signal => {
      try {
        const [jobRes, logRes, evidenceRes] = await Promise.all([
          getJob(workspaceId, jobId, { signal }),
          listJobLog(workspaceId, jobId, { limit: 100, signal }),
          listJobEvidence(workspaceId, jobId, { limit: 100, signal }),
        ]);
        const job = jobRes.job || jobRes;
        finalRef.current = isJobFinal(job?.status);
        setState({
          loading: false,
          error: '',
          job,
          logEntries: logRes.items || [],
          logPagination: logRes.pagination || null,
          evidence: evidenceRes.items || [],
        });
      } catch (e) {
        if (signal?.aborted) return;
        setState(s => ({
          ...s,
          loading: false,
          error: e?.response?.data?.error || e.message || 'Could not load.',
        }));
      }
    },
    [workspaceId, jobId]
  );

  useEffect(() => {
    if (!workspaceId || !jobId) return undefined;
    finalRef.current = false;
    const controller = new AbortController();
    load(controller.signal);
    const timer = setInterval(() => {
      if (finalRef.current) return;
      load(controller.signal);
    }, POLL_MS);
    return () => {
      controller.abort();
      clearInterval(timer);
    };
  }, [workspaceId, jobId, load]);

  const { job } = state;
  const events = buildJobTimeline({
    job,
    logEntries: state.logEntries,
    evidence: state.evidence,
    agentLines,
  });
  const truncated = truncationSummary({
    shown: state.logEntries.length,
    pagination: state.logPagination,
    noun: 'events',
  });

  return (
    <VStack align='stretch' spacing={3} data-testid='job-activity'>
      <HStack justify='space-between' flexWrap='wrap' spacing={2}>
        <Text as='h4' fontSize='sm' fontWeight='semibold'>
          {title}
        </Text>
        {job ? (
          <StatusTag
            tone={
              job.status === 'succeeded' || job.status === 'dry_run_complete'
                ? 'green'
                : isJobFinal(job.status)
                  ? 'red'
                  : 'blue'
            }
          >
            {jobStatusLabel(job.status)}
          </StatusTag>
        ) : null}
      </HStack>
      {state.loading && !job ? (
        <HStack spacing={2} role='status'>
          <Spinner size='xs' />
          <Text fontSize='sm' color={muted}>
            Loading the job record
          </Text>
        </HStack>
      ) : null}
      {state.error ? (
        <StatusPanel status='warning' testId='job-activity-error'>
          {state.error} The timeline is read again in a few seconds.
        </StatusPanel>
      ) : null}
      {job ? <JobTimelineList events={events} /> : null}
      {truncated ? (
        <Text fontSize='xs' color={muted} data-testid='timeline-truncated'>
          {truncated}. The full record is on the Jobs page.
        </Text>
      ) : null}
      {showOutput && job ? (
        <AgentShellConsole
          workspaceId={workspaceId}
          jobId={jobId}
          title={outputTitle}
          maxHeight='240px'
          copyable
          collapsible
          lineNumbers
          stopWhenComplete
          lineGuard={hideSecretLine}
          onItems={setAgentLines}
        />
      ) : null}
      <Flex hidden>
        <Icon as={FiAlertTriangle} />
      </Flex>
    </VStack>
  );
}
