import { useEffect, useId, useRef, useState } from 'react';
import {
  Box,
  Button,
  Checkbox,
  Alert,
  AlertIcon,
  FormControl,
  FormLabel,
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
    fieldProps,
    labelProps,
  } = useDashboardModalProps();

  const reasonId = useId();
  const cancelRef = useRef(null);
  const [reload, setReload] = useState(0);
  const [reason, setReason] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [reviewState, setReviewState] = useState(null);
  const [acknowledged, setAcknowledged] = useState(false);
  const [now, setNow] = useState(Date.now());
  const assistant = Boolean(job?.requestedByConnectionId);

  const reviewKey = JSON.stringify([
    workspaceId,
    job?.id,
    job?.requestedByConnectionId,
    decision,
  ]);

  useEffect(() => {
    setReviewState(null);
    setAcknowledged(false);
    if (!isOpen || !assistant || !workspaceId || !job?.id) return;
    const controller = new AbortController();
    getApprovalReview(workspaceId, job.id, { signal: controller.signal })
      .then(result => {
        if (!controller.signal.aborted)
          setReviewState(
            result.review
              ? { key: reviewKey, review: result.review }
              : { key: reviewKey, error: true }
          );
      })
      .catch(() => {
        if (!controller.signal.aborted)
          setReviewState({ key: reviewKey, error: true });
      });
    return () => controller.abort();
  }, [isOpen, assistant, workspaceId, job?.id, reviewKey, reload]);

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
  }, [isOpen, reviewKey]);

  const approving = decision === 'approve';
  const currentState = reviewState?.key === reviewKey ? reviewState : null;
  const review = currentState?.review;
  const reviewValid =
    review?.canApprove === true &&
    /^[a-f0-9]{64}$/.test(review?.reviewHash || '') &&
    review?.effect &&
    review?.connection?.id === job?.requestedByConnectionId &&
    review?.current === true &&
    new Date(review.approvalExpiresAt).getTime() > now &&
    new Date(review.connection?.expiresAt).getTime() > now;
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
        setReviewState({ key: reviewKey, error: true });
        setAcknowledged(false);
      }
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
      initialFocusRef={cancelRef}
    >
      <ModalOverlay {...overlayProps} />
      <DashboardModalFrame
        type={approving ? 'standard' : 'danger'}
        maxW={{ base: 'calc(100vw - 24px)', md: assistant ? '880px' : '520px' }}
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
            {assistant && !currentState ? (
              <Text role='status'>Loading assistant approval review…</Text>
            ) : null}
            {assistant && currentState?.error ? (
              <Alert status='warning' borderRadius='md' alignItems='flex-start'>
                <AlertIcon />
                <Box flex='1'>
                  <Text fontSize='sm'>
                    The assistant review could not load. Approval is
                    unavailable; you can still reject this job.
                  </Text>
                  <Button
                    {...outlineButtonProps}
                    mt={2}
                    size='sm'
                    onClick={() => setReload(value => value + 1)}
                  >
                    Retry review
                  </Button>
                </Box>
              </Alert>
            ) : null}
            {review && !approving ? (
              <Box as='details'>
                <Box
                  as='summary'
                  cursor='pointer'
                  fontSize='sm'
                  fontWeight='semibold'
                >
                  View renewal request
                </Box>
                <Box mt={3}>
                  <AssistantApprovalReview review={review} />
                </Box>
              </Box>
            ) : null}
            {review && approving ? (
              <AssistantApprovalReview review={review} />
            ) : null}
            {approving && review?.canApprove === false ? (
              <Text role='alert'>
                You requested this job. A different workspace manager or admin
                must approve it.
              </Text>
            ) : null}
            {approving &&
            review &&
            !reviewValid &&
            review.canApprove !== false ? (
              <Text role='alert'>
                This request cannot be approved. It changed, ended or expired,
                or its review is incomplete. Request a fresh preview.
              </Text>
            ) : null}
            {assistant && approving && reviewValid ? (
              <Checkbox
                isChecked={acknowledged}
                onChange={event => setAcknowledged(event.target.checked)}
              >
                I reviewed this request and its renewal settings and
                destinations.
              </Checkbox>
            ) : null}
            {job ? (
              <Text fontSize='sm'>
                {jobOperationLabel(job.operation)} job{' '}
                <Text as='span' fontFamily='mono' fontSize='xs'>
                  {truncateId(job.id)}
                </Text>
                {job.subjectId
                  ? ` (${subjectTypeLabel(job.subjectType) || 'Subject'}: ${truncateId(job.subjectId)})`
                  : ''}
              </Text>
            ) : null}
            <FormControl>
              <FormLabel {...labelProps} htmlFor={reasonId}>
                Reason (optional)
              </FormLabel>
              <Textarea
                {...fieldProps}
                id={reasonId}
                maxLength={1024}
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
            </FormControl>
          </VStack>
        </ModalBody>
        <ModalFooter {...footerProps}>
          <Button
            {...outlineButtonProps}
            ref={cancelRef}
            onClick={handleClose}
            isDisabled={submitting}
          >
            Cancel
          </Button>
          <Button
            {...(approving ? primaryButtonProps : dangerButtonProps)}
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
