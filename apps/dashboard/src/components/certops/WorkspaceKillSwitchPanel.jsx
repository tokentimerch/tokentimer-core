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
} from '@chakra-ui/react';
import {
  DashboardModalDescription,
  DashboardModalFrame,
  DashboardModalTitle,
  useDashboardModalProps,
} from '../DashboardModalFrame.jsx';
import { DashboardErrorAlert } from '../DashboardPrimitives.jsx';
import { useDashboardThemeColors } from '../../hooks/useDashboardTheme';
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
            ml={{ base: 0, md: 3 }}
            mt={{ base: 2, md: 0 }}
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
 * rollout flag is off, but the CertOps layout only mounts this banner once
 * useCertOpsAvailability resolves `enabled: true`: pausing/resuming a
 * feature that is not rolled out for the deployment at all is not a
 * meaningful control to surface to workspace admins. Pausing blocks new
 * provisioning intent and command delivery only; it does not stop
 * already-leased jobs or passive observation/evidence reporting. Only
 * workspace admins can change it (certops.kill_switch.manage); other roles
 * see the current state read-only.
 *
 * Rendered as a compact banner above every CertOps tab. While operations are
 * active it stays a single quiet line: a banner that shouts on the happy path
 * stops being read, and the one state that matters is the paused one.
 * The always-require-approval policy lives on the Settings tab, not here.
 * `onPausedChange` lets the layout share the resolved state with the tabs
 * instead of every tab refetching the same setting.
 */
export default function WorkspaceKillSwitchPanel({ onPausedChange }) {
  const isAdmin = useCertOpsIsWorkspaceAdmin();
  const { certOpsPaused, loading, error, saving, setPaused } =
    useCertOpsWorkspaceKillSwitch();
  const [confirmOpen, setConfirmOpen] = useState(false);

  const { muted, dashboard } = useDashboardThemeColors();
  const quietBg = dashboard.bg.field;
  const quietBorder = dashboard.border.subtle;

  useEffect(() => {
    onPausedChange?.({ certOpsPaused, loading, error });
  }, [onPausedChange, certOpsPaused, loading, error]);

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

  const resolved = !loading && !error && certOpsPaused !== undefined;

  const actionOrNote = resolved ? (
    isAdmin ? (
      <Button
        size='xs'
        colorScheme={certOpsPaused ? 'green' : 'gray'}
        variant={certOpsPaused ? 'solid' : 'outline'}
        onClick={() => setConfirmOpen(true)}
        isLoading={saving}
        flexShrink={0}
      >
        {certOpsPaused
          ? 'Resume certificate operations'
          : 'Pause certificate operations'}
      </Button>
    ) : (
      <Text fontSize='xs' color={muted} flexShrink={0}>
        Only workspace admins can pause or resume certificate operations.
      </Text>
    )
  ) : null;

  const confirmModal = (
    <KillSwitchConfirmModal
      isOpen={confirmOpen}
      onClose={() => setConfirmOpen(false)}
      pausing={!certOpsPaused}
      onConfirm={handleConfirm}
    />
  );

  if (error) {
    return (
      <Box mb={3}>
        <DashboardErrorAlert>{error}</DashboardErrorAlert>
        {confirmModal}
      </Box>
    );
  }

  if (certOpsPaused) {
    return (
      <Box mb={3}>
        <Alert
          status='warning'
          borderRadius='md'
          variant='left-accent'
          bg={dashboard.callout.warningSurface}
          borderColor={dashboard.callout.warningBorder}
          color={dashboard.callout.warningText}
        >
          <AlertIcon />
          <Box
            flex='1'
            minW={0}
            display='flex'
            flexDirection={{ base: 'column', md: 'row' }}
            alignItems={{ base: 'stretch', md: 'center' }}
          >
            <Box flex='1' minW={0}>
              <HStack spacing={2} align='center' flexWrap='wrap'>
                <Text fontSize='sm' fontWeight='bold'>
                  Certificate operations are paused for this workspace
                </Text>
                <Badge
                  colorScheme='red'
                  variant='subtle'
                  textTransform='none'
                  fontWeight='medium'
                  fontSize='xs'
                >
                  Paused
                </Badge>
              </HStack>
              <AlertDescription fontSize='sm' display='block'>
                New provisioning intent and command delivery to agents are
                refused. Already-leased jobs keep running, and agents can still
                report observations and evidence.
              </AlertDescription>
            </Box>
            <Box mt={{ base: 3, md: 0 }} ml={{ base: 0, md: 4 }}>
              {actionOrNote}
            </Box>
          </Box>
        </Alert>
        {confirmModal}
      </Box>
    );
  }

  return (
    <Box mb={3}>
      <Box
        px={3}
        py={1.5}
        bg={quietBg}
        borderWidth='1px'
        borderColor={quietBorder}
        borderRadius='md'
      >
        <HStack spacing={3} align='center'>
          {loading ? <Spinner size='xs' /> : null}
          {resolved ? (
            <Badge
              colorScheme='green'
              variant='subtle'
              textTransform='none'
              fontWeight='medium'
              fontSize='xs'
            >
              Active
            </Badge>
          ) : null}
          <Text fontSize='xs' color={muted} flex='1' noOfLines={1}>
            {resolved
              ? 'Certificate operations are running for this workspace.'
              : 'Checking the certificate operations kill switch...'}
          </Text>
          {actionOrNote}
        </HStack>
      </Box>
      {confirmModal}
    </Box>
  );
}
