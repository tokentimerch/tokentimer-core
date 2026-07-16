import { useState } from 'react';
import {
  Box,
  Collapse,
  HStack,
  Icon,
  SimpleGrid,
  Text,
  VStack,
  useColorModeValue,
} from '@chakra-ui/react';
import { ChevronDown, ChevronRight } from 'lucide-react';
import DashboardShell from '../../components/DashboardShell';
import { useDashboardShellProps } from '../../hooks/useDashboardShellProps';
import SEO from '../../components/SEO.jsx';
import ApiTokenPanel from '../../components/certops/ApiTokenPanel.jsx';
import EvidenceTimeline from '../../components/certops/EvidenceTimeline.jsx';
import JobStatusBadge from '../../components/certops/JobStatusBadge.jsx';
import {
  formatDateTime,
  formatRelativeDateTime,
  jobOperationLabel,
} from '../../components/certops/certopsJobsFormat';
import { useCertOpsAvailability } from '../../components/certops/useCertOps.js';
import { useCertOpsJobs } from '../../components/certops/useCertOpsJobs.js';
import {
  DashboardActionButton,
  DashboardPanel,
  DashboardPanelHeader,
  DashboardState,
} from '../../components/DashboardPrimitives';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';

const JOB_LIST_LIMIT = 20;

/**
 * Executor-reported job list with expandable evidence timelines.
 * Read-only surface backed by the workspace job/log/evidence APIs.
 */
function ExecutorJobsPanel() {
  const { muted, border } = useDashboardTheme();
  const rowHoverBg = useColorModeValue('gray.50', 'whiteAlpha.50');
  const expandedBg = useColorModeValue('gray.50', 'whiteAlpha.50');
  const { jobs, loading, error, refresh } = useCertOpsJobs({
    limit: JOB_LIST_LIMIT,
  });
  const [expandedId, setExpandedId] = useState(null);

  return (
    <DashboardPanel>
      <DashboardPanelHeader
        title='Machine executor jobs'
        description='Certificate jobs reported by machine tokens and the API'
        action={
          <DashboardActionButton
            variant='outline'
            onClick={refresh}
            isLoading={loading}
          >
            Refresh
          </DashboardActionButton>
        }
      />
      {loading && jobs.length === 0 ? (
        <DashboardState type='loading' title='Loading executor jobs...' />
      ) : error ? (
        <Text fontSize='sm' color='red.400'>
          {error}
        </Text>
      ) : jobs.length === 0 ? (
        <DashboardState
          title='No executor-reported certificate jobs yet'
          description='Jobs appear here once an external executor reports lifecycle events through the CertOps executor API.'
          py={6}
        />
      ) : (
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
                    setExpandedId(current =>
                      current === job.id ? null : job.id
                    )
                  }
                  aria-expanded={isOpen}
                >
                  <Icon
                    as={isOpen ? ChevronDown : ChevronRight}
                    boxSize={3.5}
                    color={muted}
                    flexShrink={0}
                  />
                  <Text
                    fontSize='sm'
                    fontWeight='medium'
                    flexShrink={0}
                    noOfLines={1}
                  >
                    {jobOperationLabel(job.operation)}
                  </Text>
                  <Text fontSize='xs' color={muted} flex='1' noOfLines={1}>
                    {job.source ? `Source: ${job.source}` : ''}
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
        </VStack>
      )}
    </DashboardPanel>
  );
}

/**
 * CertOps orchestration page (D6): machine executor jobs, evidence timelines,
 * and scoped machine API-token management. Mounted via the /certops/* splat
 * route so orchestration surfaces stay out of the read-only Control Center.
 */
export default function CertOpsOperations({
  session,
  onLogout,
  onAccountClick,
}) {
  const { pageBg, text } = useDashboardTheme();
  const { ready, enabled, error: availabilityError } = useCertOpsAvailability();

  const shellProps = useDashboardShellProps({
    session,
    onLogout,
    onAccountClick,
    pageTitle: 'Certificate operations',
  });

  return (
    <>
      <SEO
        title='Certificate operations'
        description='Machine executor jobs, evidence timelines, and scoped API tokens'
        noindex
      />
      <Box color={text} minH='100vh' bg={pageBg}>
        <DashboardShell {...shellProps}>
          <Box
            px={{ base: 4, lg: 4, '2xl': 5 }}
            py={{ base: 5, lg: 3 }}
            w='100%'
            minW={0}
            maxW='100%'
          >
            {!ready ? (
              <DashboardState
                type='loading'
                title='Checking certificate operations availability...'
              />
            ) : availabilityError ? (
              <DashboardState
                title='Could not load certificate operations status'
                description='The availability check failed. This does not mean the feature is disabled. Retry in a moment.'
              />
            ) : enabled ? (
              <SimpleGrid columns={{ base: 1, xl: 2 }} spacing={3}>
                <ExecutorJobsPanel />
                <DashboardPanel>
                  <ApiTokenPanel />
                </DashboardPanel>
              </SimpleGrid>
            ) : (
              <DashboardState
                title='Certificate operations is not enabled'
                description='Certificate operations is not enabled for this workspace yet.'
              />
            )}
          </Box>
        </DashboardShell>
      </Box>
    </>
  );
}
