import { useEffect, useState } from 'react';
import {
  Box,
  Button,
  Checkbox,
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
import AssistantApprovalReview from './AssistantApprovalReview.jsx';
import { getApprovalReview } from './certopsJobsApi.js';

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
  workspaceId,
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
  const [reviewState, setReviewState] = useState(null);
  const [acknowledged, setAcknowledged] = useState(false);
  const [now, setNow] = useState(Date.now());
  const assistant = Boolean(job?.requestedByConnectionId);

  useEffect(() => {
    setReviewState(null);
    setAcknowledged(false);
    if (!isOpen || !assistant || !workspaceId || !job?.id) return;
    const controller = new AbortController();
    getApprovalReview(workspaceId, job.id, { signal: controller.signal })
      .then(result => {
        if (!controller.signal.aborted)
          setReviewState(
            result.review ? { review: result.review } : { error: true }
          );
      })
      .catch(() => {
        if (!controller.signal.aborted) setReviewState({ error: true });
      });
    return () => controller.abort();
  }, [isOpen, assistant, workspaceId, job?.id]);

  useEffect(() => {
    if (!isOpen || !assistant) return;
    setNow(Date.now());
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [isOpen, assistant]);

  useEffect(() => {
    if (isOpen) {
      setReason('');
      setSubmitting(false);
    }
  }, [isOpen]);

  const approving = decision === 'approve';
  const review = reviewState?.review;
  const reviewValid =
    review?.canApprove !== false &&
    review?.current === true &&
    new Date(review.approvalExpiresAt).getTime() > now &&
    new Date(review.connection.expiresAt).getTime() > now;
  const approvalBlocked = assistant && (!reviewValid || !acknowledged);

  const handleClose = () => {
    if (submitting) return;
    onClose();
  };

  const handleConfirm = async () => {
    if (submitting || (approving && approvalBlocked)) return;
    setSubmitting(true);
    try {
      const accepted = await onDecide(
        reason.trim() || undefined,
        approving && assistant ? review.reviewHash : undefined
      );
      if (assistant && accepted === false) {
        setReviewState({ error: true });
        setAcknowledged(false);
      }
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Modal isOpen={isOpen} onClose={handleClose} isCentered>
      <ModalOverlay {...overlayProps} />
      <DashboardModalFrame
        type={approving ? 'standard' : 'danger'}
        maxW={{ base: 'calc(100vw - 24px)', md: assistant ? '720px' : '520px' }}
        maxH='calc(100vh - 48px)'
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
        <ModalBody {...bodyProps} overflowY='auto'>
          <VStack align='stretch' spacing={3}>
            {assistant && !reviewState ? (
              <Text role='status'>Loading assistant approval review…</Text>
            ) : null}
            {assistant && reviewState?.error ? (
              <Text role='alert'>
                Cannot load the assistant review. Close and reopen to retry.
                Approval is unavailable; rejection remains available.
              </Text>
            ) : null}
            {review ? <AssistantApprovalReview review={review} /> : null}
            {review?.canApprove === false ? (
              <Text role='alert'>
                You requested this job. A different workspace manager or admin
                must approve it.
              </Text>
            ) : null}
            {review && !reviewValid && review.canApprove !== false ? (
              <Text role='alert'>
                This request changed, ended or expired. Do not approve it;
                request a fresh preview.
              </Text>
            ) : null}
            {assistant && approving && reviewValid ? (
              <Checkbox
                isChecked={acknowledged}
                onChange={event => setAcknowledged(event.target.checked)}
              >
                I reviewed the requester, connection, destinations and complete
                renewal effect.
              </Checkbox>
            ) : null}
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
            isLoading={submitting}
            isDisabled={approving && approvalBlocked}
            loadingText={approving ? 'Approving' : 'Rejecting'}
          >
            {approving ? 'Approve' : 'Reject'}
          </Button>
        </ModalFooter>
      </DashboardModalFrame>
    </Modal>
  );
}
