import { useEffect, useState } from 'react';
import {
  Alert,
  AlertDescription,
  AlertIcon,
  Badge,
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
  ModalFooter,
  ModalHeader,
  ModalOverlay,
  Select,
  Spinner,
  Stack,
  Table,
  Tbody,
  Td,
  Text,
  Textarea,
  Th,
  Thead,
  Tr,
  useColorModeValue,
  VStack,
} from '@chakra-ui/react';
import { ChevronDown, ChevronRight } from 'lucide-react';
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
import CopyableId from '../CopyableId.jsx';
import CreateManualJobModal from './CreateManualJobModal.jsx';
import {
  CERTOPS_TRUST_ANCHOR_TYPES,
  createTrustAnchor,
  retireTrustAnchor,
} from './certopsTrustAnchorsApi.js';
import {
  useCertOpsTrustAnchorInstallations,
  useCertOpsTrustAnchors,
} from './useCertOpsTrustAnchors.js';
import { formatDateTime, truncateId } from './certopsJobsFormat';
import { useWorkspace } from '../../utils/WorkspaceContext.jsx';
import { showSuccess } from '../../utils/toast.js';

const ANCHOR_STATUS_SCHEME = { active: 'green', revoked: 'gray' };
const ANCHOR_TYPE_LABEL = { root: 'Root', intermediate: 'Intermediate' };

const LIVE_INSTALLATION_STATE_SET = new Set([
  'pending_install',
  'installed',
  'pending_remove',
]);

const INSTALLATION_STATE_SCHEME = {
  pending_install: 'orange',
  installed: 'green',
  pending_remove: 'orange',
  removed: 'gray',
};
const INSTALLATION_STATE_LABEL = {
  pending_install: 'Pending install',
  installed: 'Installed',
  pending_remove: 'Pending remove',
  removed: 'Removed',
};

function AnchorStatusBadge({ status }) {
  const key = String(status || '').toLowerCase();
  return (
    <Badge
      colorScheme={ANCHOR_STATUS_SCHEME[key] || 'gray'}
      variant='subtle'
      textTransform='none'
      fontWeight='medium'
      fontSize='xs'
    >
      {key === 'active'
        ? 'Active'
        : key === 'revoked'
          ? 'Revoked'
          : status || 'Unknown'}
    </Badge>
  );
}

function InstallationStateBadge({ state }) {
  const key = String(state || '').toLowerCase();
  return (
    <Badge
      colorScheme={INSTALLATION_STATE_SCHEME[key] || 'gray'}
      variant='subtle'
      textTransform='none'
      fontWeight='medium'
      fontSize='xs'
    >
      {INSTALLATION_STATE_LABEL[key] || (state ? String(state) : 'Unknown')}
    </Badge>
  );
}

const ANCHOR_TRUST_ANCHOR_PEM_ERROR_MESSAGE =
  'That does not look like a single CA certificate (Basic Constraints CA=true). Bundles and leaf/server certificates are rejected.';

function createTrustAnchorErrorMessage(err) {
  const code = err?.response?.data?.code;
  if (code === 'CERTOPS_TRUST_ANCHOR_PEM_INVALID') {
    return ANCHOR_TRUST_ANCHOR_PEM_ERROR_MESSAGE;
  }
  if (err?.response?.status === 403) {
    return 'Trust-anchor management requires workspace admin.';
  }
  return err?.response?.data?.error || 'Could not approve this trust anchor.';
}

/**
 * Approve a CA certificate as a workspace trust anchor. Re-submitting the
 * same fingerprint (e.g. to fix a typo'd name) updates the row in place
 * rather than creating a duplicate; the server does not distinguish this
 * case in its response, so this form always shows a plain success toast.
 */
function CreateTrustAnchorModal({ isOpen, onClose, onCreated }) {
  const {
    overlayProps,
    headerProps,
    bodyProps,
    footerProps,
    closeButtonProps,
    outlineButtonProps,
    primaryButtonProps,
  } = useDashboardModalProps();

  const [name, setName] = useState('');
  const [anchorType, setAnchorType] = useState(CERTOPS_TRUST_ANCHOR_TYPES[0]);
  const [pem, setPem] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (isOpen) {
      setName('');
      setAnchorType(CERTOPS_TRUST_ANCHOR_TYPES[0]);
      setPem('');
      setSubmitting(false);
      setError('');
    }
  }, [isOpen]);

  const canSubmit = Boolean(name.trim() && anchorType && pem.trim());

  const handleSubmit = async () => {
    if (!canSubmit || submitting) return;
    setSubmitting(true);
    setError('');
    try {
      await onCreated({ name: name.trim(), anchorType, pem: pem.trim() });
    } catch (err) {
      setError(createTrustAnchorErrorMessage(err));
      setSubmitting(false);
    }
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} isCentered scrollBehavior='inside'>
      <ModalOverlay {...overlayProps} />
      <DashboardModalFrame maxW={{ base: 'calc(100vw - 24px)', md: '560px' }}>
        <ModalHeader {...headerProps}>
          <DashboardModalTitle>Approve a trust anchor</DashboardModalTitle>
          <DashboardModalDescription>
            Only the public CA certificate is ever sent or stored; a private key
            is never accepted here.
          </DashboardModalDescription>
        </ModalHeader>
        <ModalCloseButton {...closeButtonProps} isDisabled={submitting} />
        <ModalBody {...bodyProps}>
          <VStack align='stretch' spacing={4}>
            <FormControl isRequired>
              <FormLabel fontSize='sm'>Name</FormLabel>
              <Input
                size='sm'
                value={name}
                onChange={event => setName(event.target.value)}
                placeholder='e.g. Internal Root CA 2026'
                maxLength={255}
                autoComplete='off'
              />
            </FormControl>
            <FormControl isRequired>
              <FormLabel fontSize='sm'>Anchor type</FormLabel>
              <Select
                size='sm'
                value={anchorType}
                onChange={event => setAnchorType(event.target.value)}
              >
                {CERTOPS_TRUST_ANCHOR_TYPES.map(type => (
                  <option key={type} value={type}>
                    {ANCHOR_TYPE_LABEL[type] || type}
                  </option>
                ))}
              </Select>
              <FormHelperText>
                Determines which OS store a distribute-trust job installs into
                (Root vs. intermediate/CA); this cannot be changed after
                creation.
              </FormHelperText>
            </FormControl>
            <FormControl isRequired>
              <FormLabel fontSize='sm'>CA certificate (PEM)</FormLabel>
              <Textarea
                size='sm'
                fontFamily='mono'
                fontSize='xs'
                rows={8}
                value={pem}
                onChange={event => setPem(event.target.value)}
                placeholder='-----BEGIN CERTIFICATE-----...'
              />
              <FormHelperText>
                Exactly one certificate with Basic Constraints CA=true. Bundles
                and leaf/server certificates are rejected.
              </FormHelperText>
            </FormControl>
            {error ? (
              <Alert status='error' borderRadius='md' variant='left-accent'>
                <AlertIcon />
                <AlertDescription fontSize='sm'>{error}</AlertDescription>
              </Alert>
            ) : null}
          </VStack>
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
            {...primaryButtonProps}
            ml={3}
            onClick={handleSubmit}
            isDisabled={!canSubmit}
            isLoading={submitting}
            loadingText='Approving'
          >
            Approve anchor
          </Button>
        </ModalFooter>
      </DashboardModalFrame>
    </Modal>
  );
}

/**
 * Retire a trust anchor (idempotent server-side: retiring an
 * already-revoked anchor just returns retiredNow: false). Does not touch
 * anything already installed on an agent; that requires a separate
 * revoke-trust job per installation.
 */
function RetireTrustAnchorModal({ isOpen, onClose, anchor, onRetire }) {
  const {
    overlayProps,
    headerProps,
    bodyProps,
    footerProps,
    closeButtonProps,
    dangerButtonProps,
    outlineButtonProps,
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
      await onRetire({ reason: reason.trim() || undefined });
    } catch (err) {
      setError(
        err?.response?.data?.error || 'Could not retire this trust anchor.'
      );
      setSubmitting(false);
    }
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} isCentered scrollBehavior='inside'>
      <ModalOverlay {...overlayProps} />
      <DashboardModalFrame
        type='danger'
        maxW={{ base: 'calc(100vw - 24px)', md: '480px' }}
      >
        <ModalHeader {...headerProps}>
          <DashboardModalTitle>Retire trust anchor</DashboardModalTitle>
          <DashboardModalDescription>
            Marks this anchor as no longer approved for new distribute-trust
            jobs. It does not remove anything already installed on an agent;
            revoke each installation separately if it must come off the hosts it
            already reached.
          </DashboardModalDescription>
        </ModalHeader>
        <ModalCloseButton {...closeButtonProps} isDisabled={submitting} />
        <ModalBody {...bodyProps}>
          <VStack align='stretch' spacing={3}>
            {anchor?.name ? (
              <Text fontSize='sm' fontWeight='semibold'>
                Anchor: {anchor.name}
              </Text>
            ) : null}
            <FormControl>
              <FormLabel fontSize='sm'>Reason (optional)</FormLabel>
              <Textarea
                size='sm'
                rows={2}
                value={reason}
                onChange={event => setReason(event.target.value)}
                placeholder='e.g. CA replaced, rotated ahead of expiry'
              />
            </FormControl>
            {error ? (
              <Alert status='error' borderRadius='md' variant='left-accent'>
                <AlertIcon />
                <AlertDescription fontSize='sm'>{error}</AlertDescription>
              </Alert>
            ) : null}
          </VStack>
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
            {...dangerButtonProps}
            ml={3}
            onClick={handleConfirm}
            isLoading={submitting}
            loadingText='Retiring'
          >
            Retire anchor
          </Button>
        </ModalFooter>
      </DashboardModalFrame>
    </Modal>
  );
}

/**
 * Anchor row's expanded body: installation rows for that anchor, loaded
 * on demand (only while expanded), plus the distribute/revoke actions
 * that open CreateManualJobModal in trust mode with this data.
 */
function AnchorInstallationsBody({
  anchor,
  onDistribute,
  onRevoke,
  isWorkspaceAdmin,
}) {
  const { installations, loading, error, refresh } =
    useCertOpsTrustAnchorInstallations(anchor.id);
  const muted = useColorModeValue('gray.600', 'gray.400');

  return (
    <VStack align='stretch' spacing={3}>
      <HStack justify='space-between' align='center' flexWrap='wrap'>
        <Text fontSize='xs' color={muted}>
          Where this anchor has been distributed and its current state on each
          host.
        </Text>
        <HStack spacing={2}>
          {isWorkspaceAdmin ? (
            <Button
              size='xs'
              colorScheme='blue'
              variant='outline'
              onClick={() => onDistribute(anchor, installations)}
              isDisabled={anchor.status !== 'active'}
            >
              Distribute to an agent
            </Button>
          ) : null}
          <Button
            type='button'
            size='xs'
            variant='outline'
            onClick={event => {
              event.stopPropagation();
              refresh();
            }}
            isLoading={loading}
          >
            Refresh
          </Button>
        </HStack>
      </HStack>
      {error ? <DashboardErrorAlert>{error}</DashboardErrorAlert> : null}
      {loading && installations.length === 0 ? (
        <HStack spacing={2} color={muted} py={2} justify='center'>
          <Spinner size='sm' />
          <Text fontSize='sm'>Loading installations...</Text>
        </HStack>
      ) : null}
      {!loading && !error && installations.length === 0 ? (
        <Text fontSize='sm' color={muted} py={1}>
          Not distributed to any agent yet.
        </Text>
      ) : null}
      {installations.length > 0 ? (
        <Table size='sm' variant='simple'>
          <Thead>
            <Tr>
              <Th>Owner</Th>
              <Th>Host</Th>
              <Th>Store</Th>
              <Th>State</Th>
              <Th>Last attempt</Th>
              {isWorkspaceAdmin ? <Th textAlign='right'>Actions</Th> : null}
            </Tr>
          </Thead>
          <Tbody>
            {installations.map(row => (
              <Tr key={row.id}>
                <Td>
                  <Text fontSize='sm'>{row.owner}</Text>
                </Td>
                <Td>
                  <Text fontSize='sm'>{row.host || '--'}</Text>
                </Td>
                <Td>
                  <Text fontSize='sm' fontFamily='mono'>
                    {row.store}
                  </Text>
                </Td>
                <Td>
                  <VStack align='flex-start' spacing={0.5}>
                    <InstallationStateBadge state={row.transitionState} />
                    {row.lastError ? (
                      <Text fontSize='xs' color='red.500' noOfLines={1}>
                        {row.lastError}
                      </Text>
                    ) : null}
                  </VStack>
                </Td>
                <Td>
                  <Text
                    fontSize='sm'
                    color={muted}
                    title={formatDateTime(row.lastAttemptAt)}
                  >
                    {row.lastAttemptAt
                      ? formatDateTime(row.lastAttemptAt)
                      : '--'}
                  </Text>
                </Td>
                {isWorkspaceAdmin ? (
                  <Td textAlign='right'>
                    {LIVE_INSTALLATION_STATE_SET.has(row.transitionState) ? (
                      <Button
                        size='xs'
                        colorScheme='red'
                        variant='outline'
                        onClick={() => onRevoke(anchor, installations)}
                      >
                        Revoke
                      </Button>
                    ) : (
                      <Text fontSize='xs' color={muted}>
                        --
                      </Text>
                    )}
                  </Td>
                ) : null}
              </Tr>
            ))}
          </Tbody>
        </Table>
      ) : null}
    </VStack>
  );
}

/**
 * Trust-anchor management panel (0.14.1): approve/retire CA certificates as
 * workspace trust anchors, and drive distribute-trust/revoke-trust jobs
 * against them through CreateManualJobModal's narrower trustOp mode.
 *
 * Gated on workspace admin, matching the certops.trust_anchor.manage bar
 * every trust-anchor route enforces server-side; non-admins see nothing
 * here (same pattern as the workspace kill switch), rather than a 403
 * banner for a surface they can't act on anyway.
 */
export default function TrustAnchorsPanel() {
  const { workspaceId } = useWorkspace();
  const { enabled, isAdmin, anchors, loading, error, refresh } =
    useCertOpsTrustAnchors();
  const [expandedId, setExpandedId] = useState(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [retireTarget, setRetireTarget] = useState(null);
  const [jobModalTarget, setJobModalTarget] = useState(null);

  const muted = useColorModeValue('gray.600', 'gray.400');
  const titleColor = useColorModeValue('gray.700', 'gray.200');
  const infoBg = useColorModeValue('blue.50', 'blue.900');
  const infoBorder = useColorModeValue('blue.200', 'blue.700');
  const infoText = useColorModeValue('blue.800', 'blue.100');

  if (enabled !== true || !isAdmin) return null;

  return (
    <Stack spacing={4} align='stretch'>
      <HStack justify='space-between' align='start' spacing={4} flexWrap='wrap'>
        <Box minW={0}>
          <Text fontSize='md' fontWeight='bold' color={titleColor}>
            Trust anchors
          </Text>
        </Box>
        <DashboardActionButton
          colorScheme='blue'
          onClick={() => setCreateOpen(true)}
        >
          Approve a trust anchor
        </DashboardActionButton>
      </HStack>

      <Alert
        status='info'
        variant='subtle'
        borderRadius='md'
        bg={infoBg}
        border='1px solid'
        borderColor={infoBorder}
        py={2}
        px={3}
        w='100%'
      >
        <AlertIcon boxSize={4} />
        <AlertDescription fontSize='sm' color={infoText} lineHeight='short'>
          A trust anchor is a CA certificate approved for distribution to
          agent-managed OS trust stores. Retiring an anchor stops new
          distribute-trust jobs; it does not remove anything already installed
          on a host.
        </AlertDescription>
      </Alert>

      {error ? <DashboardErrorAlert>{error}</DashboardErrorAlert> : null}

      {loading && anchors.length === 0 ? (
        <HStack spacing={2} color={muted} py={4} justify='center'>
          <Spinner size='sm' />
          <Text fontSize='sm'>Loading trust anchors...</Text>
        </HStack>
      ) : null}

      {!loading && !error && anchors.length === 0 ? (
        <Box py={6} textAlign='center'>
          <Text fontSize='sm' fontWeight='semibold' color={titleColor}>
            No trust anchors approved yet.
          </Text>
          <Text fontSize='sm' color={muted} mt={1}>
            Approve a CA certificate above to make it distributable to agents.
          </Text>
        </Box>
      ) : null}

      {anchors.length > 0 ? (
        <VStack align='stretch' spacing={1}>
          {anchors.map(anchor => {
            const isOpen = expandedId === anchor.id;
            return (
              <Box key={anchor.id}>
                <HStack
                  w='full'
                  spacing={2}
                  px={2}
                  py={2}
                  borderRadius='md'
                  cursor='pointer'
                  role='button'
                  tabIndex={0}
                  aria-expanded={isOpen}
                  onClick={() =>
                    setExpandedId(current =>
                      current === anchor.id ? null : anchor.id
                    )
                  }
                  onKeyDown={event => {
                    if (event.key === 'Enter' || event.key === ' ') {
                      event.preventDefault();
                      setExpandedId(current =>
                        current === anchor.id ? null : anchor.id
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
                  <Box minW={0} flex='1'>
                    <Text fontSize='sm' fontWeight='semibold' noOfLines={1}>
                      {anchor.name}
                    </Text>
                    <HStack
                      spacing={2}
                      onClick={event => event.stopPropagation()}
                    >
                      <Text fontSize='xs' color={muted}>
                        {ANCHOR_TYPE_LABEL[anchor.anchorType] ||
                          anchor.anchorType}
                      </Text>
                      <CopyableId
                        id={anchor.fingerprintSha256}
                        display={truncateId(anchor.fingerprintSha256, {
                          head: 12,
                          tail: 6,
                        })}
                      />
                    </HStack>
                  </Box>
                  <AnchorStatusBadge status={anchor.status} />
                  <Text fontSize='xs' color={muted} flexShrink={0}>
                    {formatDateTime(anchor.createdAt)}
                  </Text>
                  {anchor.status === 'active' ? (
                    <Box
                      flexShrink={0}
                      onClick={event => event.stopPropagation()}
                    >
                      <Button
                        size='xs'
                        colorScheme='red'
                        variant='outline'
                        onClick={() => setRetireTarget(anchor)}
                      >
                        Retire
                      </Button>
                    </Box>
                  ) : null}
                </HStack>
                <Collapse in={isOpen} animateOpacity>
                  <Box mt={1} mb={2} ml={5} pl={3} py={2}>
                    {isOpen ? (
                      <AnchorInstallationsBody
                        anchor={anchor}
                        isWorkspaceAdmin={isAdmin}
                        onDistribute={(target, installations) =>
                          setJobModalTarget({
                            anchorId: target.id,
                            anchorName: target.name,
                            anchorFingerprint: target.fingerprintSha256,
                            operation: 'distribute-trust',
                            installations,
                          })
                        }
                        onRevoke={(target, installations) =>
                          setJobModalTarget({
                            anchorId: target.id,
                            anchorName: target.name,
                            anchorFingerprint: target.fingerprintSha256,
                            operation: 'revoke-trust',
                            installations,
                          })
                        }
                      />
                    ) : null}
                  </Box>
                </Collapse>
              </Box>
            );
          })}
        </VStack>
      ) : null}

      <CreateTrustAnchorModal
        isOpen={createOpen}
        onClose={() => setCreateOpen(false)}
        onCreated={async ({ name, anchorType, pem }) => {
          await createTrustAnchor(workspaceId, { name, anchorType, pem });
          showSuccess('Trust anchor approved');
          setCreateOpen(false);
          refresh();
        }}
      />
      <RetireTrustAnchorModal
        isOpen={Boolean(retireTarget)}
        onClose={() => setRetireTarget(null)}
        anchor={retireTarget}
        onRetire={async ({ reason }) => {
          await retireTrustAnchor(workspaceId, retireTarget.id, { reason });
          showSuccess('Trust anchor retired');
          setRetireTarget(null);
          refresh();
        }}
      />
      <CreateManualJobModal
        isOpen={Boolean(jobModalTarget)}
        onClose={() => setJobModalTarget(null)}
        trustOp={jobModalTarget}
        onCreated={() => setJobModalTarget(null)}
      />
    </Stack>
  );
}
