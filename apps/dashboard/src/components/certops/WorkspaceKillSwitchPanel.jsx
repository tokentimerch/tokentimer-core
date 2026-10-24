import CertOpsBadge from './CertOpsBadge.jsx';
import { useEffect, useState } from 'react';
import {
  Alert,
  AlertDescription,
  AlertIcon,
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
import {
  DashboardActionButton,
  DashboardErrorAlert,
} from '../DashboardPrimitives.jsx';
import { SettingsActionRow } from '../SettingsPageShell.jsx';
import { FiPause, FiPlay } from 'react-icons/fi';
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
 * The layout owns one controller and hands it to every view, so pausing from
 * the Settings tab is seen by the others at once. Modes:
 * - `alertOnly` (layout, above the other tabs): nothing while operations are
 *   running. Only the paused warning and load errors appear, because a paused
 *   workspace must stay visible on every tab and a banner that speaks on the
 *   happy path stops being read.
 * - `row` (Settings tab): one setting row in the same layout as Preferences
 *   and Account, with a status badge and the Pause or Resume button.
 * - `default`: the paused warning, or the status line with the Pause control
 *   while running. `flush` drops the outer margin for use inside a panel.
 * Without a `controller` the panel loads the setting itself.
 * The always-require-approval policy lives on the Settings tab, not here.
 * `onPausedChange` lets a caller follow the resolved state.
 */
export default function WorkspaceKillSwitchPanel({
  controller,
  mode = 'default',
  flush = false,
  showDivider = false,
  onPausedChange,
}) {
  if (controller) {
    return (
      <KillSwitchView
        controller={controller}
        mode={mode}
        flush={flush}
        showDivider={showDivider}
        onPausedChange={onPausedChange}
      />
    );
  }
  return (
    <OwnStateKillSwitch
      mode={mode}
      flush={flush}
      showDivider={showDivider}
      onPausedChange={onPausedChange}
    />
  );
}

function OwnStateKillSwitch(props) {
  const controller = useCertOpsWorkspaceKillSwitch();
  return <KillSwitchView controller={controller} {...props} />;
}

function KillSwitchView({
  controller,
  mode,
  flush,
  showDivider,
  onPausedChange,
}) {
  const isAdmin = useCertOpsIsWorkspaceAdmin();
  const { certOpsPaused, loading, error, saving, setPaused } = controller;
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

  if (mode === 'row') {
    return (
      <>
        <SettingsActionRow
          label='Certificate operations'
          status={
            resolved ? (
              <CertOpsBadge colorScheme={certOpsPaused ? 'red' : 'green'}>
                {certOpsPaused ? 'Paused' : 'Active'}
              </CertOpsBadge>
            ) : null
          }
          description={
            error
              ? error
              : !resolved
                ? 'Checking the certificate operations kill switch...'
                : certOpsPaused
                  ? 'Certificate operations are paused for this workspace.'
                  : 'Certificate operations are running for this workspace.'
          }
          note={
            certOpsPaused && resolved
              ? 'New provisioning intent and command delivery to agents are refused. Already-leased jobs keep running, and agents can still report observations and evidence.'
              : resolved && isAdmin
                ? 'Pausing stops new provisioning and command delivery during an incident. Already-leased jobs keep running.'
                : null
          }
          showDivider={showDivider}
        >
          {loading ? <Spinner size='sm' /> : null}
          {resolved && isAdmin ? (
            <DashboardActionButton
              colorScheme={certOpsPaused ? 'blue' : undefined}
              variant={certOpsPaused ? 'solid' : 'outline'}
              leftIcon={certOpsPaused ? <FiPlay /> : <FiPause />}
              onClick={() => setConfirmOpen(true)}
              isLoading={saving}
              w={{ base: 'full', sm: 'auto' }}
            >
              {certOpsPaused
                ? 'Resume certificate operations'
                : 'Pause certificate operations'}
            </DashboardActionButton>
          ) : resolved ? (
            <Text fontSize='xs' color={muted}>
              Only workspace admins can pause or resume certificate operations.
            </Text>
          ) : null}
        </SettingsActionRow>
        {confirmModal}
      </>
    );
  }

  if (error) {
    return (
      <Box mb={flush ? 0 : 3}>
        <DashboardErrorAlert>{error}</DashboardErrorAlert>
        {confirmModal}
      </Box>
    );
  }

  // Quiet while running: the status line lives on the Settings tab.
  if (mode === 'alertOnly' && !certOpsPaused) return null;

  if (certOpsPaused) {
    return (
      <Box mb={flush ? 0 : 3}>
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
                <CertOpsBadge colorScheme='red'>Paused</CertOpsBadge>
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
    <Box mb={flush ? 0 : 3}>
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
            <CertOpsBadge colorScheme='green'>Active</CertOpsBadge>
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
