import { useRef, useState } from 'react';
import {
  AlertDialog,
  AlertDialogBody,
  AlertDialogContent,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogOverlay,
  Box,
  Button,
} from '@chakra-ui/react';
import { cancelJob } from './certopsJobsApi.js';
import { showError, showSuccess, showWarning } from '../../utils/toast.js';

export default function CancelCertOpsJob({ workspaceId, job, onCancelled }) {
  const [isOpen, setIsOpen] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const requestInFlight = useRef(false);
  const keepRunningRef = useRef(null);
  if (job.canCancel !== true) return null;

  const confirm = async () => {
    if (requestInFlight.current) return;
    requestInFlight.current = true;
    setSubmitting(true);
    try {
      const result = await cancelJob(workspaceId, job.id);
      setIsOpen(false);
      if (result.needsOperatorReconciliation) {
        showWarning(
          'Host verification required',
          'The agent may already have made changes. Verify the host before retrying.'
        );
      } else {
        showSuccess('Job cancelled');
      }
      onCancelled();
    } catch (error) {
      const code = error?.response?.data?.code;
      if (
        code === 'CERTOPS_JOB_CANCELLATION_UNAVAILABLE' ||
        code === 'CERTOPS_JOB_CANCELLATION_UNSUPPORTED' ||
        error?.response?.status === 404
      ) {
        showError(
          'Job can no longer be cancelled',
          error?.response?.data?.error ||
            'The job changed while you were reviewing it.'
        );
        setIsOpen(false);
        onCancelled();
      } else {
        showError('Could not cancel job', error?.response?.data?.error);
      }
    } finally {
      requestInFlight.current = false;
      setSubmitting(false);
    }
  };

  return (
    <Box>
      <Button
        size='sm'
        variant='outline'
        colorScheme='red'
        onClick={() => setIsOpen(true)}
      >
        Cancel job
      </Button>
      <AlertDialog
        isOpen={isOpen}
        leastDestructiveRef={keepRunningRef}
        onClose={() => {
          if (!submitting) setIsOpen(false);
        }}
        isCentered
      >
        <AlertDialogOverlay />
        <AlertDialogContent>
          <AlertDialogHeader>Cancel this job?</AlertDialogHeader>
          <AlertDialogBody>
            TokenTimer will stop further control-plane execution for this job.
            An agent already running a job that changes the host may finish or
            leave changes. If the outcome is uncertain, verify the host before
            retrying.
          </AlertDialogBody>
          <AlertDialogFooter gap={3}>
            <Button
              ref={keepRunningRef}
              onClick={() => setIsOpen(false)}
              isDisabled={submitting}
            >
              Keep job
            </Button>
            <Button colorScheme='red' onClick={confirm} isLoading={submitting}>
              Cancel job
            </Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Box>
  );
}
