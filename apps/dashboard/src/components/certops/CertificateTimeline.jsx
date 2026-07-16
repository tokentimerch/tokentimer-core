import { useState } from 'react';
import {
  Box,
  Collapse,
  HStack,
  Icon,
  Spinner,
  Text,
  VStack,
  useColorModeValue,
} from '@chakra-ui/react';
import { ChevronDown, ChevronRight } from 'lucide-react';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import EvidenceTimeline from './EvidenceTimeline.jsx';
import JobStatusBadge from './JobStatusBadge.jsx';
import {
  formatDateTime,
  formatRelativeDateTime,
  jobOperationLabel,
} from './certopsJobsFormat';
import { useCertOpsJobs } from './useCertOpsJobs.js';
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
}) {
  const { muted, border } = useDashboardTheme();
  const rowHoverBg = useColorModeValue('gray.50', 'whiteAlpha.50');
  const expandedBg = useColorModeValue('gray.50', 'whiteAlpha.50');
  const { enabled, jobs, pagination, loading, error } = useCertOpsJobs({
    subjectType,
    subjectId,
    limit,
  });
  const [expandedId, setExpandedId] = useState(null);

  if (enabled !== true) return null;

  if (loading) {
    return (
      <HStack spacing={2} py={2}>
        <Spinner size='xs' />
        <Text fontSize='sm' color={muted}>
          Loading certificate jobs...
        </Text>
      </HStack>
    );
  }

  if (error) {
    return (
      <Text fontSize='sm' color='red.400'>
        {error}
      </Text>
    );
  }

  if (!jobs || jobs.length === 0) {
    return (
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

  return (
    <VStack align='stretch' spacing={1}>
      {jobs.map(job => {
        const isOpen = expandedId === job.id;
        return (
          <Box key={job.id} borderColor={border}>
            <HStack
              as='button'
              type='button'
              w='full'
              textAlign='left'
              spacing={2}
              px={2}
              py={2}
              borderRadius='md'
              _hover={{ bg: rowHoverBg }}
              onClick={() =>
                setExpandedId(current => (current === job.id ? null : job.id))
              }
              aria-expanded={isOpen}
            >
              <Icon
                as={isOpen ? ChevronDown : ChevronRight}
                boxSize={3.5}
                color={muted}
                flexShrink={0}
              />
              <Text fontSize='sm' fontWeight='medium' flex='1' noOfLines={1}>
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
            </HStack>
            <Collapse in={isOpen} animateOpacity>
              <Box
                mt={1}
                mb={2}
                ml={5}
                pl={3}
                py={2}
                borderLeftWidth='2px'
                borderColor={border}
                bg={expandedBg}
                borderRadius='md'
              >
                {isOpen ? <EvidenceTimeline jobId={job.id} /> : null}
              </Box>
            </Collapse>
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
