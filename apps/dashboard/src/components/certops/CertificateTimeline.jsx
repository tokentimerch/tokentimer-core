import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Box,
  Collapse,
  HStack,
  Icon,
  Spinner,
  Text,
  VStack,
} from '@chakra-ui/react';
import { ChevronDown, ChevronRight } from 'lucide-react';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import EvidenceTimeline from './EvidenceTimeline.jsx';
import { JobDetailsButton } from './JobDetailsButton.jsx';
import JobStatusBadge from './JobStatusBadge.jsx';
import {
  formatDateTime,
  formatRelativeDateTime,
  jobOperationLabel,
} from './certopsJobsFormat';
import { useCertOpsJobs } from './useCertOpsJobs.js';
import { useCertOpsAgents } from './useCertOpsAgents.js';
import { indexAgentsByAnyId } from './certopsAgentLabel.js';
import { truncationSummary } from './certopsPagination.js';

/**
 * Compact expandable job history for one managed certificate subject.
 *
 * @param {{ subjectType?: string, subjectId: string, limit?: number }} props
 */
export default function CertificateTimeline({
  subjectType = 'managed_certificate',
  subjectId,
  limit = 10,
  defaultLatestExpanded = false,
  compact = false,
  hideWhenEmpty = false,
  renderContainer,
}) {
  const { muted, border, dashboard } = useDashboardTheme();
  const rowHoverBg = dashboard.table.rowHover;
  const expandedBg = dashboard.bg.nested;
  const { agents } = useCertOpsAgents();
  const agentsById = useMemo(() => indexAgentsByAnyId(agents), [agents]);
  const { enabled, jobs, pagination, loading, error } = useCertOpsJobs({
    subjectType,
    subjectId,
    limit,
  });
  const [expandedId, setExpandedId] = useState(null);
  const initializedSubjectRef = useRef(null);

  useEffect(() => {
    if (!jobs?.length || initializedSubjectRef.current === subjectId) return;
    initializedSubjectRef.current = subjectId;
    setExpandedId(defaultLatestExpanded ? jobs[0].id : null);
  }, [defaultLatestExpanded, jobs, subjectId]);

  const wrapContent = content =>
    typeof renderContainer === 'function' ? renderContainer(content) : content;

  if (enabled !== true) return null;

  if (loading) {
    return wrapContent(
      <HStack spacing={2} py={2}>
        <Spinner size='xs' />
        <Text fontSize='sm' color={muted}>
          Loading certificate jobs...
        </Text>
      </HStack>
    );
  }

  if (error) {
    return wrapContent(
      <Text fontSize='sm' color={dashboard.state.danger}>
        {error}
      </Text>
    );
  }

  if (!jobs || jobs.length === 0) {
    if (hideWhenEmpty) return null;

    return wrapContent(
      <Text fontSize='sm' color={muted}>
        No certificate jobs recorded yet.
      </Text>
    );
  }

  const jobsTruncation = truncationSummary({
    shown: jobs?.length || 0,
    pagination,
    noun: 'jobs',
  });

  return wrapContent(
    <VStack align='stretch' spacing={1}>
      {jobs.map(job => {
        const isOpen = expandedId === job.id;
        const expandedContent = (
          <Box
            mt={1}
            mb={2}
            ml={compact ? 1 : 5}
            pl={3}
            py={2}
            bg={compact ? 'transparent' : expandedBg}
            borderRadius={compact ? 0 : 'md'}
          >
            <EvidenceTimeline jobId={job.id} compact={compact} embedded />
          </Box>
        );
        return (
          <Box key={job.id} borderColor={border}>
            <Box
              px={compact ? 0 : 2}
              py={2}
              borderRadius='md'
              cursor='pointer'
              _hover={{ bg: rowHoverBg }}
              role='button'
              tabIndex={0}
              aria-expanded={isOpen}
              onClick={() =>
                setExpandedId(current => (current === job.id ? null : job.id))
              }
              onKeyDown={event => {
                if (event.key === 'Enter' || event.key === ' ') {
                  event.preventDefault();
                  setExpandedId(current =>
                    current === job.id ? null : job.id
                  );
                }
              }}
            >
              <HStack
                w='full'
                spacing={2}
                align='center'
                flexWrap={{ base: 'wrap', md: 'nowrap' }}
              >
                <Icon
                  as={isOpen ? ChevronDown : ChevronRight}
                  boxSize={3.5}
                  color={muted}
                  flexShrink={0}
                />
                <Text
                  fontSize='sm'
                  fontWeight='semibold'
                  flex='1'
                  noOfLines={1}
                >
                  {jobOperationLabel(job.operation)}
                </Text>
                <JobStatusBadge status={job.status} />
                <Text
                  fontSize='xs'
                  color={muted}
                  flexShrink={0}
                  title={formatDateTime(job.createdAt)}
                >
                  {formatRelativeDateTime(job.createdAt)}
                </Text>
                <Box
                  flexShrink={0}
                  onClick={event => event.stopPropagation()}
                >
                  <JobDetailsButton job={job} agentsById={agentsById} />
                </Box>
              </HStack>
            </Box>
            {compact ? (
              isOpen ? (
                expandedContent
              ) : null
            ) : (
              <Collapse in={isOpen} animateOpacity>
                {isOpen ? expandedContent : null}
              </Collapse>
            )}
          </Box>
        );
      })}
      {jobsTruncation ? (
        <Text fontSize='xs' color={muted} px={2} pt={1}>
          {jobsTruncation}
        </Text>
      ) : null}
    </VStack>
  );
}
