import { useEffect, useState } from 'react';
import {
  Box,
  Button,
  Modal,
  ModalBody,
  ModalCloseButton,
  ModalFooter,
  ModalHeader,
  ModalOverlay,
  Text,
  Textarea,
  VStack,
} from '@chakra-ui/react';
import {
  DashboardModalDescription,
  DashboardModalFrame,
  DashboardModalTitle,
  useDashboardModalProps,
} from '../DashboardModalFrame.jsx';
import {
  jobOperationLabel,
  subjectTypeLabel,
  truncateId,
} from './certopsJobsFormat';
import JobApprovalScope, {
  cleanupScopeAvailable,
} from './JobApprovalScope.jsx';
import { getJob } from './certopsJobsApi.js';
import { useWorkspace } from '../../utils/WorkspaceContext.jsx';

/**
 * Confirm dialog for approving or rejecting a job at `pending_approval`.
 * `reason` is optional free text recorded on the approval/rejection job-log
 * entry and audit row (see docs/certops's approvals guide).
 */
export default function ApprovalDecisionModal({
  isOpen,
  onClose,
  job,
  decision,
  onDecide,
}) {
  const {
    overlayProps,
    headerProps,
    bodyProps,
    footerProps,
    closeButtonProps,
    outlineButtonProps,
    dangerButtonProps,
    primaryButtonProps,
  } = useDashboardModalProps();

  const [reason, setReason] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const { workspaceId } = useWorkspace();
  const jobId = job?.id;
  const scopeKey = `${workspaceId}:${jobId}`;
  const [scopeState, setScopeState] = useState(null);

  useEffect(() => {
    if (!isOpen || !workspaceId || !jobId) {
      setScopeState(null);
      return undefined;
    }
    const controller = new AbortController();
    let cancelled = false;
    setScopeState({ key: scopeKey, loading: true });
    // The Jobs list deliberately omits payloads. Always fetch the immutable
    // detail for this decision instead of approving its abbreviated summary.
    getJob(workspaceId, jobId, { signal: controller.signal })
      .then(data => {
        const detail = data?.job || data;
        if (detail?.id !== jobId || detail?.workspaceId !== workspaceId) {
          throw new Error('Approval scope identity mismatch');
        }
        if (!cancelled) setScopeState({ key: scopeKey, job: detail });
      })
      .catch(() => {
        if (!cancelled) setScopeState({ key: scopeKey, error: true });
      });
    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [isOpen, workspaceId, jobId, scopeKey]);

  useEffect(() => {
    if (isOpen) {
      setReason('');
      setSubmitting(false);
    }
  }, [isOpen, jobId, workspaceId]);

  const approving = decision === 'approve';
  const currentScope = scopeState?.key === scopeKey ? scopeState : null;
  const scopeJob = currentScope?.job;
  const loadingScope = !currentScope || currentScope.loading;
  const jobNotPending = scopeJob && scopeJob.status !== 'pending_approval';
  const scopeUnavailable =
    approving && (!scopeJob || !cleanupScopeAvailable(scopeJob));

  const handleClose = () => {
    if (submitting) return;
    onClose();
  };

  const handleConfirm = async () => {
    if (submitting || scopeUnavailable || jobNotPending) return;
    setSubmitting(true);
    try {
      await onDecide(reason.trim() || undefined);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={handleClose}
      isCentered
      scrollBehavior='inside'
    >
      <ModalOverlay {...overlayProps} />
      <DashboardModalFrame
        type={approving ? 'standard' : 'danger'}
        maxW={{ base: 'calc(100vw - 24px)', md: '680px' }}
      >
        <ModalHeader {...headerProps}>
          <DashboardModalTitle>
            {approving ? 'Approve job' : 'Reject job'}
          </DashboardModalTitle>
          <DashboardModalDescription>
            {approving
              ? 'The job moves to "Pending" and becomes claimable by an agent.'
              : 'The job moves directly to the terminal "Rejected" status. This cannot be undone.'}
          </DashboardModalDescription>
        </ModalHeader>
        <ModalCloseButton {...closeButtonProps} isDisabled={submitting} />
        <ModalBody {...bodyProps}>
          <VStack align='stretch' spacing={3}>
            {job ? (
              <Text fontSize='sm'>
                {jobOperationLabel(job.operation)} job{' '}
                <Text as='span' fontFamily='mono' fontSize='xs'>
                  {truncateId(job.id)}
                </Text>
                {job.subjectId
                  ? ` (${subjectTypeLabel(job.subjectType) || 'Subject'}: ${job.subjectId})`
                  : ''}
              </Text>
            ) : null}
            {loadingScope ? (
              <Text fontSize='sm'>Loading approval scope...</Text>
            ) : currentScope.error ? (
              <Text role='alert' fontSize='sm'>
                Could not load exact approval scope. Close and reopen the dialog
                to retry.
              </Text>
            ) : (
              <JobApprovalScope job={scopeJob} />
            )}
            {jobNotPending ? (
              <Text role='alert' fontSize='sm'>
                This job is no longer pending approval. Refresh Jobs.
              </Text>
            ) : null}
            <Box>
              <Text fontSize='sm' mb={1}>
                Reason (optional)
              </Text>
              <Textarea
                size='sm'
                rows={2}
                value={reason}
                onChange={event => setReason(event.target.value)}
                placeholder={
                  approving
                    ? 'e.g. confirmed with the domain owner'
                    : 'e.g. wrong certificate target'
                }
              />
            </Box>
          </VStack>
        </ModalBody>
        <ModalFooter {...footerProps}>
          <Button
            {...outlineButtonProps}
            onClick={handleClose}
            isDisabled={submitting}
          >
            Cancel
          </Button>
          <Button
            {...(approving ? primaryButtonProps : dangerButtonProps)}
            ml={3}
            onClick={handleConfirm}
            isDisabled={scopeUnavailable || jobNotPending}
            isLoading={submitting}
            loadingText={approving ? 'Approving' : 'Rejecting'}
          >
            {approving ? 'Approve' : 'Reject'}
          </Button>
        </ModalFooter>
      </DashboardModalFrame>
    </Modal>
  );
}
