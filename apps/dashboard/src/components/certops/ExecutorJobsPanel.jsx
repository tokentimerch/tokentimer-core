import { useCallback, useMemo, useState } from 'react';
import {
  Box,
  Button,
  Collapse,
  HStack,
  Icon,
  Text,
  Tooltip,
  VStack,
  useColorModeValue,
} from '@chakra-ui/react';
import { ChevronDown, ChevronRight } from 'lucide-react';
import CopyableId from '../CopyableId.jsx';
import ApprovalDecisionModal from './ApprovalDecisionModal.jsx';
import CreateManualJobModal from './CreateManualJobModal.jsx';
import EvidenceTimeline from './EvidenceTimeline.jsx';
import JobStatusBadge from './JobStatusBadge.jsx';
import { approveJob, rejectJob } from './certopsJobsApi.js';
import {
  formatDateTime,
  formatRelativeDateTime,
  jobOperationLabel,
  subjectTypeLabel,
  truncateId,
} from './certopsJobsFormat';
import { useCertOpsCanManage } from './useCertOps.js';
import { useCertOpsJobs } from './useCertOpsJobs.js';
import { useCertOpsAgents } from './useCertOpsAgents.js';
import {
  formatAgentLabel,
  indexAgentsByAnyId,
} from './certopsAgentLabel.js';
import DashboardPagination from '../DashboardPagination.jsx';
import {
  CERTOPS_JOB_FILTERS,
  CERTOPS_PAGE_SIZE_OPTIONS,
  useCertOpsListUrlState,
} from '../../hooks/useCertOpsUrlState.js';
import {
  DashboardActionButton,
  DashboardPanel,
  DashboardPanelHeader,
  DashboardState,
} from '../DashboardPrimitives';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import { useWorkspace } from '../../utils/WorkspaceContext.jsx';
import { showError, showSuccess } from '../../utils/toast.js';

const PAUSED_CREATE_REASON =
  'Certificate operations are paused for this workspace, so new jobs are refused. Resume from the Settings tab first.';

// Statuses whose jobs are waiting on an agent claim: while the workspace is
// paused the control plane stops handing them out, so they sit in place
// rather than failing, and the row has to say so.
const AWAITING_EXECUTION_STATUSES = new Set(['pending', 'queued', 'claimed']);

/**
 * Maps approve/reject failures to a message that explains the specific
 * gate that fired (see docs/certops's approvals guide: the non-requester
 * rule only applies to approve, and a job can legitimately race out of
 * pending_approval before the decision lands).
 */
function approvalDecisionErrorMessage(err, decision) {
  const code = err?.response?.data?.code;
  const status = err?.response?.status;
  if (code === 'CERTOPS_APPROVAL_SELF_APPROVAL_FORBIDDEN') {
    return 'You requested this job, so you cannot approve it yourself. Ask another workspace manager or admin to review it.';
  }
  if (code === 'CERTOPS_APPROVAL_JOB_NOT_PENDING_APPROVAL') {
    return 'This job already left "Pending approval" (someone else may have just decided it). Refreshing the list.';
  }
  if (status === 403 || code === 'INSUFFICIENT_ROLE') {
    return `You need workspace manager permission to ${decision} a job.`;
  }
  return (
    err?.response?.data?.error ||
    err?.message ||
    `Could not ${decision} this job.`
  );
}

/**
 * Executor-reported job list with expandable evidence timelines.
 * Read-only surface backed by the workspace job/log/evidence APIs, plus a
 * manager-only manual job creation entry point (exception path) and
 * manager-only approve/reject actions on jobs at `pending_approval`.
 *
 * `certOpsPaused` only gates job *creation*: the API refuses new work while a
 * workspace is paused, but leaves approve/reject open on purpose, because
 * rejecting a queued job is what an operator needs during the incident that
 * caused the pause.
 */
export default function ExecutorJobsPanel({ certOpsPaused = false }) {
  const { muted, border } = useDashboardTheme();
  const rowHoverBg = useColorModeValue('gray.50', 'whiteAlpha.50');
  const expandedBg = useColorModeValue('gray.50', 'whiteAlpha.50');
  const canManage = useCertOpsCanManage();
  const { agents } = useCertOpsAgents();
  const agentsById = useMemo(() => indexAgentsByAnyId(agents), [agents]);
  const { workspaceId } = useWorkspace();
  const {
    limit,
    offset,
    filters,
    setPage,
    clearFilters,
    activeFilterLabels,
    hasActiveFilters,
  } = useCertOpsListUrlState({ filters: CERTOPS_JOB_FILTERS });
  const { jobs, pagination, loading, error, refresh } = useCertOpsJobs({
    limit,
    offset,
    status: filters.status || undefined,
    operation: filters.operation || undefined,
    source: filters.source || undefined,
  });
  const [expandedId, setExpandedId] = useState(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [decisionTarget, setDecisionTarget] = useState(null);
  // Bumped alongside the list refresh so an already-expanded row's
  // EvidenceTimeline (a separate hook instance, not something the list's own
  // refresh() touches) refetches too, instead of silently going stale while
  // the top-level "Refresh" button spins.
  const [timelineRefreshToken, setTimelineRefreshToken] = useState(0);

  const refreshAll = useCallback(() => {
    refresh();
    setTimelineRefreshToken(tick => tick + 1);
  }, [refresh]);

  const firstPage = () => setPage({ offset: 0 });
  const pageIsPastEnd = Boolean(
    pagination && pagination.total > 0 && offset >= pagination.total
  );

  const handleDecision = async reason => {
    if (!decisionTarget || !workspaceId) return;
    const { job, decision } = decisionTarget;
    const decide = decision === 'approve' ? approveJob : rejectJob;
    try {
      await decide(workspaceId, job.id, { reason });
      showSuccess(decision === 'approve' ? 'Job approved' : 'Job rejected');
      setDecisionTarget(null);
      refreshAll();
    } catch (err) {
      showError(
        decision === 'approve' ? 'Approve failed' : 'Reject failed',
        approvalDecisionErrorMessage(err, decision)
      );
      if (
        err?.response?.data?.code ===
        'CERTOPS_APPROVAL_JOB_NOT_PENDING_APPROVAL'
      ) {
        setDecisionTarget(null);
        refreshAll();
      }
    }
  };

  return (
    <DashboardPanel>
      <DashboardPanelHeader
        title='Machine executor jobs'
        description='Certificate jobs reported by machine tokens and the API'
        action={
          <HStack spacing={2}>
            {canManage ? (
              <Tooltip
                label={certOpsPaused ? PAUSED_CREATE_REASON : undefined}
                isDisabled={!certOpsPaused}
                shouldWrapChildren
              >
                <DashboardActionButton
                  colorScheme='blue'
                  onClick={() => setCreateOpen(true)}
                  isDisabled={certOpsPaused}
                >
                  Create manual job
                </DashboardActionButton>
              </Tooltip>
            ) : null}
            <DashboardActionButton
              variant='outline'
              onClick={refreshAll}
              isLoading={loading}
            >
              Refresh
            </DashboardActionButton>
          </HStack>
        }
      />
      {canManage && certOpsPaused ? (
        <Text fontSize='xs' color={muted} mb={2}>
          {PAUSED_CREATE_REASON} Approving and rejecting queued jobs stays
          available.
        </Text>
      ) : null}
      {hasActiveFilters ? (
        // A filtered list that comes up short has to say it is filtered, or the
        // short answer reads as the whole truth. This is most likely when the
        // view arrived through a link someone else built.
        <HStack spacing={2} mb={2} flexWrap='wrap'>
          <Text fontSize='xs' color={muted}>
            Filtered by{' '}
            {activeFilterLabels
              .map(entry => `${entry.label}: ${entry.value}`)
              .join(', ')}
          </Text>
          <Button size='xs' variant='ghost' onClick={clearFilters}>
            Clear filters
          </Button>
        </HStack>
      ) : null}
      {loading && jobs.length === 0 ? (
        <DashboardState type='loading' title='Loading executor jobs...' />
      ) : error ? (
        <Text fontSize='sm' color='red.400'>
          {error}
        </Text>
      ) : jobs.length === 0 ? (
        pageIsPastEnd ? (
          // A shared link can outlive the page it pointed at. Saying "no jobs"
          // here would be a different claim than the one that is true.
          <DashboardState
            title='This page is past the end of the list'
            description='The jobs this link pointed at have moved or aged out.'
            py={6}
            action={
              <Button size='xs' variant='ghost' onClick={firstPage}>
                Back to the first page
              </Button>
            }
          />
        ) : (
          <DashboardState
            title={
              hasActiveFilters
                ? 'No jobs match these filters'
                : 'No executor-reported certificate jobs yet'
            }
            description={
              hasActiveFilters
                ? 'Clear the filters above to see every job this workspace has recorded.'
                : 'Jobs appear here once an external executor reports lifecycle events through the CertOps executor API.'
            }
            py={6}
          />
        )
      ) : (
        <VStack align='stretch' spacing={1}>
          {jobs.map(job => {
            const isOpen = expandedId === job.id;
            const awaitingApproval = job.status === 'pending_approval';
            const stalledByPause =
              certOpsPaused && AWAITING_EXECUTION_STATUSES.has(job.status);
            const agentLabel = formatAgentLabel(
              job.assignedAgentId || job.claimedByAgentId,
              agentsById
            );
            const subject = job.subjectId
              ? `${subjectTypeLabel(job.subjectType) || 'Subject'}: ${job.subjectId}`
              : job.source
                ? `Source: ${job.source}`
                : '';
            return (
              <Box key={job.id} borderColor={border}>
                <HStack
                  w='full'
                  spacing={2}
                  px={2}
                  py={2}
                  borderRadius='md'
                  cursor='pointer'
                  _hover={{ bg: rowHoverBg }}
                  role='button'
                  tabIndex={0}
                  aria-expanded={isOpen}
                  onClick={() =>
                    setExpandedId(current =>
                      current === job.id ? null : job.id
                    )
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
                  <Box
                    flexShrink={0}
                    onClick={event => event.stopPropagation()}
                  >
                    <CopyableId id={job.id} display={truncateId(job.id)} />
                  </Box>
                  <Text fontSize='xs' color={muted} flex='1' noOfLines={1}>
                    {[agentLabel, subject].filter(Boolean).join(' · ')}
                  </Text>
                  {stalledByPause ? (
                    <Text fontSize='xs' color={muted} flexShrink={0}>
                      Not executable while paused
                    </Text>
                  ) : null}
                  <JobStatusBadge status={job.status} />
                  <Text
                    fontSize='xs'
                    color={muted}
                    flexShrink={0}
                    title={formatDateTime(job.createdAt)}
                  >
                    {formatRelativeDateTime(job.createdAt)}
                  </Text>
                  {canManage && awaitingApproval ? (
                    <HStack
                      spacing={1}
                      flexShrink={0}
                      onClick={event => event.stopPropagation()}
                    >
                      <Button
                        size='xs'
                        colorScheme='green'
                        onClick={() =>
                          setDecisionTarget({ job, decision: 'approve' })
                        }
                      >
                        Approve
                      </Button>
                      <Button
                        size='xs'
                        colorScheme='red'
                        variant='outline'
                        onClick={() =>
                          setDecisionTarget({ job, decision: 'reject' })
                        }
                      >
                        Reject
                      </Button>
                    </HStack>
                  ) : null}
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
                    {isOpen ? (
                      <EvidenceTimeline
                        jobId={job.id}
                        refreshToken={timelineRefreshToken}
                      />
                    ) : null}
                  </Box>
                </Collapse>
              </Box>
            );
          })}
          {pagination ? (
            <Box px={2} pt={2}>
              <DashboardPagination
                limit={pagination.limit || limit}
                offset={offset}
                total={pagination.total}
                pageSizeOptions={CERTOPS_PAGE_SIZE_OPTIONS}
                noun='jobs'
                onChange={setPage}
              />
            </Box>
          ) : null}
        </VStack>
      )}
      <CreateManualJobModal
        isOpen={createOpen}
        onClose={() => setCreateOpen(false)}
        onCreated={refreshAll}
      />
      <ApprovalDecisionModal
        isOpen={Boolean(decisionTarget)}
        onClose={() => setDecisionTarget(null)}
        job={decisionTarget?.job}
        decision={decisionTarget?.decision}
        onDecide={handleDecision}
      />
    </DashboardPanel>
  );
}
