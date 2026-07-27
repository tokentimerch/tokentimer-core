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

  useEffect(() => {
    if (isOpen) {
      setReason('');
      setSubmitting(false);
    }
  }, [isOpen]);

  const approving = decision === 'approve';

  const handleClose = () => {
    if (submitting) return;
    onClose();
  };

  const handleConfirm = async () => {
    if (submitting) return;
    setSubmitting(true);
    try {
      await onDecide(reason.trim() || undefined);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Modal isOpen={isOpen} onClose={handleClose} isCentered>
      <ModalOverlay {...overlayProps} />
      <DashboardModalFrame
        type={approving ? 'standard' : 'danger'}
        maxW={{ base: 'calc(100vw - 24px)', md: '520px' }}
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
            loadingText={approving ? 'Approving' : 'Rejecting'}
          >
            {approving ? 'Approve' : 'Reject'}
          </Button>
        </ModalFooter>
      </DashboardModalFrame>
    </Modal>
  );
}
