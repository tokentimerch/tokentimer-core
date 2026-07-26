import { useEffect, useState } from 'react';
import {
  Alert,
  AlertDescription,
  AlertIcon,
  Badge,
  Box,
  Button,
  HStack,
  Modal,
  ModalBody,
  ModalCloseButton,
  ModalFooter,
  ModalHeader,
  ModalOverlay,
  Spinner,
  Text,
  Textarea,
  useColorModeValue,
} from '@chakra-ui/react';
import {
  DashboardModalDescription,
  DashboardModalFrame,
  DashboardModalTitle,
  useDashboardModalProps,
} from '../DashboardModalFrame.jsx';
import { DashboardErrorAlert } from '../DashboardPrimitives.jsx';
import { showSuccess } from '../../utils/toast.js';
import {
  useCertOpsIsWorkspaceAdmin,
  useCertOpsWorkspaceKillSwitch,
} from './useCertOps.js';

/**
 * Confirm dialog for pausing or resuming CertOps for the workspace.
 * `reason` is optional free text recorded on the pause/resume audit event,
 * mirroring the RetireAgentModal reason field.
 */
function KillSwitchConfirmModal({ isOpen, onClose, pausing, onConfirm }) {
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
  const [error, setError] = useState('');

  useEffect(() => {
    if (isOpen) {
      setReason('');
      setSubmitting(false);
      setError('');
    }
  }, [isOpen]);

  const handleConfirm = async () => {
    if (submitting) return;
    setSubmitting(true);
    setError('');
    try {
      await onConfirm(reason.trim() || undefined);
    } catch (err) {
      setError(
        err?.response?.data?.error ||
          `Could not ${pausing ? 'pause' : 'resume'} certificate operations. Please try again.`
      );
      setSubmitting(false);
    }
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} isCentered scrollBehavior='inside'>
      <ModalOverlay {...overlayProps} />
      <DashboardModalFrame
        type={pausing ? 'danger' : 'standard'}
        maxW={{ base: 'calc(100vw - 24px)', md: '520px' }}
      >
        <ModalHeader {...headerProps}>
          <DashboardModalTitle>
            {pausing
              ? 'Pause certificate operations'
              : 'Resume certificate operations'}
          </DashboardModalTitle>
          <DashboardModalDescription>
            {pausing
              ? 'New provisioning intent and command delivery to agents stop immediately. Already-leased jobs keep running, and agents can still report observations and evidence.'
              : 'Agents and the API resume accepting new provisioning intent and command delivery for this workspace.'}
          </DashboardModalDescription>
        </ModalHeader>
        <ModalCloseButton {...closeButtonProps} />
        <ModalBody {...bodyProps}>
          <Box>
            <Text fontSize='sm' mb={1}>
              Reason (optional)
            </Text>
            <Textarea
              value={reason}
              onChange={event => setReason(event.target.value)}
              placeholder={
                pausing
                  ? 'e.g. investigating a misissued certificate'
                  : 'e.g. incident resolved'
              }
              size='sm'
              rows={2}
            />
          </Box>
          {error ? (
            <Alert
              status='error'
              borderRadius='md'
              variant='left-accent'
              mt={3}
            >
              <AlertIcon />
              <AlertDescription fontSize='sm'>{error}</AlertDescription>
            </Alert>
          ) : null}
        </ModalBody>
        <ModalFooter {...footerProps}>
          <Button
            {...outlineButtonProps}
            onClick={onClose}
            isDisabled={submitting}
          >
            Cancel
          </Button>
          <Button
            {...(pausing ? dangerButtonProps : primaryButtonProps)}
            ml={3}
            onClick={handleConfirm}
            isLoading={submitting}
            loadingText={pausing ? 'Pausing' : 'Resuming'}
          >
            {pausing ? 'Pause' : 'Resume'}
          </Button>
        </ModalFooter>
      </DashboardModalFrame>
    </Modal>
  );
}

/**
 * Workspace-local CertOps kill switch (incident control).
 *
 * Backed by GET/PUT /api/v1/workspaces/:id/certops/settings. The underlying
 * routes stay reachable even while the deployment-wide certops.enabled
 * rollout flag is off, but the CertOps page only mounts this panel once
 * useCertOpsAvailability resolves `enabled: true`: pausing/resuming a
 * feature that is not rolled out for the deployment at all is not a
 * meaningful control to surface to workspace admins. Pausing blocks new
 * provisioning intent and command delivery only; it does not stop
 * already-leased jobs or passive observation/evidence reporting. Only
 * workspace admins can change it (certops.kill_switch.manage); other roles
 * see the current state read-only.
 */
export default function WorkspaceKillSwitchPanel() {
  const isAdmin = useCertOpsIsWorkspaceAdmin();
  const { certOpsPaused, loading, error, saving, setPaused } =
    useCertOpsWorkspaceKillSwitch();
  const [confirmOpen, setConfirmOpen] = useState(false);

  const titleColor = useColorModeValue('gray.700', 'gray.200');
  const muted = useColorModeValue('gray.600', 'gray.400');

  const handleConfirm = async reason => {
    const next = !certOpsPaused;
    await setPaused(next, reason);
    showSuccess(
      next
        ? 'Certificate operations paused for this workspace'
        : 'Certificate operations resumed for this workspace'
    );
    setConfirmOpen(false);
  };

  return (
    <Box>
      <HStack justify='space-between' align='flex-start' mb={1} spacing={3}>
        <Text fontSize='md' fontWeight='bold' color={titleColor}>
          Certificate operations kill switch
        </Text>
        {loading ? (
          <Spinner size='sm' />
        ) : certOpsPaused !== undefined ? (
          <Badge
            colorScheme={certOpsPaused ? 'red' : 'green'}
            variant='subtle'
            textTransform='none'
            fontWeight='medium'
            fontSize='xs'
          >
            {certOpsPaused ? 'Paused' : 'Active'}
          </Badge>
        ) : null}
      </HStack>
      <Text fontSize='sm' color={muted} mb={3}>
        Pausing stops new provisioning intent and command delivery to agents for
        this workspace only. Already-leased jobs keep running, and agents can
        still report observations and evidence while paused.
      </Text>

      {error ? <DashboardErrorAlert>{error}</DashboardErrorAlert> : null}

      {!loading && !error && certOpsPaused !== undefined ? (
        isAdmin ? (
          <Button
            size='sm'
            colorScheme={certOpsPaused ? 'green' : 'red'}
            variant={certOpsPaused ? 'solid' : 'outline'}
            onClick={() => setConfirmOpen(true)}
            isLoading={saving}
          >
            {certOpsPaused
              ? 'Resume certificate operations'
              : 'Pause certificate operations'}
          </Button>
        ) : (
          <Text fontSize='xs' color={muted}>
            Only workspace admins can pause or resume certificate operations.
          </Text>
        )
      ) : null}

      <KillSwitchConfirmModal
        isOpen={confirmOpen}
        onClose={() => setConfirmOpen(false)}
        pausing={!certOpsPaused}
        onConfirm={handleConfirm}
      />
    </Box>
  );
}
