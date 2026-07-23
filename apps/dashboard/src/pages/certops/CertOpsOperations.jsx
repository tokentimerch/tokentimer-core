import { useState } from 'react';
import {
  Alert,
  AlertDescription,
  AlertIcon,
  Box,
  Button,
  Collapse,
  FormControl,
  FormHelperText,
  FormLabel,
  HStack,
  Icon,
  Input,
  Modal,
  ModalBody,
  ModalCloseButton,
  ModalContent,
  ModalFooter,
  ModalHeader,
  ModalOverlay,
  Select,
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
import AgentFleetPanel from '../../components/certops/AgentFleetPanel.jsx';
import DeployAgentPanel from '../../components/certops/DeployAgentPanel.jsx';
import EvidenceTimeline from '../../components/certops/EvidenceTimeline.jsx';
import JobStatusBadge from '../../components/certops/JobStatusBadge.jsx';
import {
  CERTOPS_JOB_OPERATIONS,
  CERTOPS_SUBJECT_TYPES,
  createJob,
} from '../../components/certops/certopsJobsApi.js';
import {
  formatDateTime,
  formatRelativeDateTime,
  jobOperationLabel,
  subjectTypeLabel,
  truncateId,
} from '../../components/certops/certopsJobsFormat';
import {
  useCertOpsAvailability,
  useCertOpsCanManage,
} from '../../components/certops/useCertOps.js';
import { useCertOpsJobs } from '../../components/certops/useCertOpsJobs.js';
import { truncationSummary } from '../../components/certops/certopsPagination.js';
import {
  DashboardActionButton,
  DashboardPanel,
  DashboardPanelHeader,
  DashboardState,
} from '../../components/DashboardPrimitives';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import { useWorkspace } from '../../utils/WorkspaceContext.jsx';
import { showError, showSuccess } from '../../utils/toast.js';

const JOB_LIST_LIMIT = 20;
const SUBJECT_ID_MAX_LENGTH = 128;

function createJobErrorMessage(err) {
  const code = err?.response?.data?.code;
  const status = err?.response?.status;
  if (status === 403 || code === 'INSUFFICIENT_ROLE') {
    return 'You need workspace manager permission to create a job.';
  }
  if (code === 'PRIVATE_KEY_MATERIAL_REJECTED') {
    return 'Private key or secret material is not accepted in job fields.';
  }
  if (code === 'CERTOPS_JOB_IDEMPOTENCY_CONFLICT') {
    return 'This idempotency key was already used with different job details.';
  }
  return err?.response?.data?.error || err?.message || 'Could not create job.';
}

/**
 * Manual job creation modal: the exception path for creating
 * a CertOps job before the certops-scheduler exists. Always posts with
 * source "api"; the server never accepts a client-supplied source.
 */
function CreateManualJobModal({ isOpen, onClose, onCreated }) {
  const { workspaceId } = useWorkspace();
  const [operation, setOperation] = useState('');
  const [subjectType, setSubjectType] = useState('');
  const [subjectId, setSubjectId] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const resetForm = () => {
    setOperation('');
    setSubjectType('');
    setSubjectId('');
  };

  const handleClose = () => {
    if (submitting) return;
    resetForm();
    onClose();
  };

  const canSubmit =
    Boolean(operation) &&
    Boolean(workspaceId) &&
    !submitting &&
    (!subjectType || Boolean(subjectId.trim())) &&
    (!subjectId.trim() || Boolean(subjectType));

  const handleSubmit = async () => {
    if (!canSubmit) return;
    setSubmitting(true);
    try {
      const body = { operation };
      if (subjectType) body.subjectType = subjectType;
      if (subjectId.trim()) body.subjectId = subjectId.trim();
      const { job } = await createJob(workspaceId, body);
      showSuccess(
        'Job created',
        job?.id ? `Job ID: ${truncateId(job.id)}` : undefined
      );
      resetForm();
      onClose();
      onCreated?.();
    } catch (err) {
      showError('Create failed', createJobErrorMessage(err));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Modal isOpen={isOpen} onClose={handleClose} isCentered size='lg'>
      <ModalOverlay />
      <ModalContent>
        <ModalHeader>Create manual job</ModalHeader>
        <ModalCloseButton isDisabled={submitting} />
        <ModalBody>
          <VStack align='stretch' spacing={4}>
            <Alert status='info' variant='subtle' borderRadius='md'>
              <AlertIcon boxSize={4} />
              <AlertDescription fontSize='sm'>
                Manual job creation is an exception path for driving certificate
                operations before automated scheduling ships. The job is
                recorded with source &quot;api&quot; and appears at the start of
                the job&apos;s history.
              </AlertDescription>
            </Alert>
            <FormControl isRequired>
              <FormLabel fontSize='sm'>Operation</FormLabel>
              <Select
                size='sm'
                placeholder='Select an operation'
                value={operation}
                onChange={event => setOperation(event.target.value)}
              >
                {CERTOPS_JOB_OPERATIONS.map(op => (
                  <option key={op} value={op}>
                    {jobOperationLabel(op)}
                  </option>
                ))}
              </Select>
            </FormControl>
            <FormControl>
              <FormLabel fontSize='sm'>Subject type (optional)</FormLabel>
              <Select
                size='sm'
                placeholder='No subject'
                value={subjectType}
                onChange={event => setSubjectType(event.target.value)}
              >
                {CERTOPS_SUBJECT_TYPES.map(type => (
                  <option key={type} value={type}>
                    {subjectTypeLabel(type)}
                  </option>
                ))}
              </Select>
              <FormHelperText>
                Required together with subject ID, or leave both empty.
              </FormHelperText>
            </FormControl>
            <FormControl>
              <FormLabel fontSize='sm'>Subject ID (optional)</FormLabel>
              <Input
                size='sm'
                value={subjectId}
                onChange={event => setSubjectId(event.target.value)}
                maxLength={SUBJECT_ID_MAX_LENGTH}
                placeholder='e.g. a managed certificate ID'
              />
            </FormControl>
          </VStack>
        </ModalBody>
        <ModalFooter>
          <Button onClick={handleClose} isDisabled={submitting} mr={3}>
            Cancel
          </Button>
          <Button
            colorScheme='blue'
            onClick={handleSubmit}
            isDisabled={!canSubmit}
            isLoading={submitting}
            loadingText='Creating'
          >
            Create job
          </Button>
        </ModalFooter>
      </ModalContent>
    </Modal>
  );
}

/**
 * Executor-reported job list with expandable evidence timelines.
 * Read-only surface backed by the workspace job/log/evidence APIs, plus a
 * manager-only manual job creation entry point (exception path).
 */
function ExecutorJobsPanel() {
  const { muted, border } = useDashboardTheme();
  const rowHoverBg = useColorModeValue('gray.50', 'whiteAlpha.50');
  const expandedBg = useColorModeValue('gray.50', 'whiteAlpha.50');
  const canManage = useCertOpsCanManage();
  const { jobs, pagination, loading, error, refresh } = useCertOpsJobs({
    limit: JOB_LIST_LIMIT,
  });
  const [expandedId, setExpandedId] = useState(null);
  const [createOpen, setCreateOpen] = useState(false);
  const jobsTruncation = truncationSummary({
    shown: jobs?.length || 0,
    pagination,
    noun: 'jobs',
  });

  return (
    <DashboardPanel>
      <DashboardPanelHeader
        title='Machine executor jobs'
        description='Certificate jobs reported by machine tokens and the API'
        action={
          <HStack spacing={2}>
            {canManage ? (
              <DashboardActionButton
                colorScheme='blue'
                onClick={() => setCreateOpen(true)}
              >
                Create manual job
              </DashboardActionButton>
            ) : null}
            <DashboardActionButton
              variant='outline'
              onClick={refresh}
              isLoading={loading}
            >
              Refresh
            </DashboardActionButton>
          </HStack>
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
                  <Text
                    fontSize='xs'
                    color={muted}
                    fontFamily='mono'
                    flexShrink={0}
                    title={job.id}
                  >
                    {truncateId(job.id)}
                  </Text>
                  <Text fontSize='xs' color={muted} flex='1' noOfLines={1}>
                    {job.subjectId
                      ? `${subjectTypeLabel(job.subjectType) || 'Subject'}: ${job.subjectId}`
                      : job.source
                        ? `Source: ${job.source}`
                        : ''}
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
      )}
      <CreateManualJobModal
        isOpen={createOpen}
        onClose={() => setCreateOpen(false)}
        onCreated={refresh}
      />
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
  const {
    ready,
    enabled,
    error: availabilityError,
    retry: retryAvailability,
  } = useCertOpsAvailability();

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
                action={
                  <DashboardActionButton
                    variant='outline'
                    onClick={retryAvailability}
                  >
                    Retry
                  </DashboardActionButton>
                }
              />
            ) : enabled ? (
              <SimpleGrid columns={{ base: 1, xl: 2 }} spacing={3}>
                <ExecutorJobsPanel />
                <DashboardPanel>
                  <ApiTokenPanel />
                </DashboardPanel>
                <DashboardPanel>
                  <DeployAgentPanel />
                </DashboardPanel>
                <DashboardPanel>
                  <AgentFleetPanel />
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
