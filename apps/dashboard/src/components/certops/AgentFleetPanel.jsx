import { useEffect, useState } from 'react';
import {
  Alert,
  AlertDescription,
  AlertIcon,
  Badge,
  Box,
  Button,
  Checkbox,
  HStack,
  Modal,
  ModalBody,
  ModalCloseButton,
  ModalFooter,
  ModalHeader,
  ModalOverlay,
  Spinner,
  Stack,
  Table,
  TableContainer,
  Tbody,
  Td,
  Text,
  Textarea,
  Th,
  Thead,
  Tr,
  useColorModeValue,
} from '@chakra-ui/react';
import {
  DashboardModalDescription,
  DashboardModalFrame,
  DashboardModalTitle,
  useDashboardModalProps,
} from '../DashboardModalFrame.jsx';
import CopyableId from '../CopyableId.jsx';
import { DashboardErrorAlert } from '../DashboardPrimitives.jsx';
import { useWorkspace } from '../../utils/WorkspaceContext.jsx';
import { showSuccess } from '../../utils/toast.js';
import { retireAgent } from './certopsAgentsApi.js';
import { formatDateTime, formatRelativeDateTime } from './certopsJobsFormat';
import { useCertOpsCanManage } from './useCertOps.js';
import { useCertOpsAgents } from './useCertOpsAgents.js';

const AGENT_STATUS_SCHEME = {
  active: 'green',
  offline: 'orange',
  retired: 'gray',
};

const AGENT_STATUS_LABEL = {
  active: 'Active',
  offline: 'Offline',
  retired: 'Retired',
};

/** Subtle status chip for an agent, JobStatusBadge conventions. */
function AgentStatusBadge({ status, fontSize = 'xs' }) {
  const key = String(status || '').toLowerCase();
  return (
    <Badge
      colorScheme={AGENT_STATUS_SCHEME[key] || 'gray'}
      variant='subtle'
      textTransform='none'
      fontWeight='medium'
      fontSize={fontSize}
    >
      {AGENT_STATUS_LABEL[key] || (status ? String(status) : 'Unknown')}
    </Badge>
  );
}

function shortId(value) {
  const raw = String(value || '');
  return raw.length > 12 ? `${raw.slice(0, 12)}...` : raw;
}

/**
 * Confirm dialog for retiring an agent (RetireCertificateModal pattern).
 * A non-forced retire is refused server-side with 409
 * CERTOPS_AGENT_RETIRE_BLOCKED while the agent holds job leases; the dialog
 * then surfaces a force option, which requires a reason.
 */
function RetireAgentModal({ isOpen, onClose, agent, onRetire }) {
  const {
    overlayProps,
    headerProps,
    bodyProps,
    footerProps,
    closeButtonProps,
    outlineButtonProps,
    dangerButtonProps,
  } = useDashboardModalProps();

  const [reason, setReason] = useState('');
  const [force, setForce] = useState(false);
  const [blocked, setBlocked] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (isOpen) {
      setReason('');
      setForce(false);
      setBlocked(false);
      setSubmitting(false);
      setError('');
    }
  }, [isOpen]);

  const forceNeedsReason = force && !reason.trim();

  const handleConfirm = async () => {
    if (submitting || forceNeedsReason) return;
    setSubmitting(true);
    setError('');
    try {
      await onRetire({
        force,
        reason: reason.trim() || undefined,
      });
    } catch (err) {
      const code = err?.response?.data?.code;
      if (
        err?.response?.status === 409 ||
        code === 'CERTOPS_AGENT_RETIRE_BLOCKED'
      ) {
        setBlocked(true);
        setError(
          'This agent still holds active job leases. Wait for its jobs to finish, or force the retirement (leased jobs will fail over).'
        );
      } else {
        setError(
          err?.response?.data?.error ||
            'Could not retire this agent. Please try again.'
        );
      }
      setSubmitting(false);
    }
  };

  const agentLabel = agent?.name || agent?.hostname || agent?.agentId || '';

  return (
    <Modal isOpen={isOpen} onClose={onClose} isCentered scrollBehavior='inside'>
      <ModalOverlay {...overlayProps} />
      <DashboardModalFrame
        type='danger'
        maxW={{ base: 'calc(100vw - 24px)', md: '520px' }}
      >
        <ModalHeader {...headerProps}>
          <DashboardModalTitle>Retire agent</DashboardModalTitle>
          <DashboardModalDescription>
            A retired agent can no longer connect or lease jobs; its credential
            is invalidated. This cannot be undone; deploy a new agent to replace
            it.
          </DashboardModalDescription>
        </ModalHeader>
        <ModalCloseButton {...closeButtonProps} />
        <ModalBody {...bodyProps}>
          <Stack spacing={3}>
            {agentLabel ? (
              <Text fontSize='sm' fontWeight='semibold'>
                Agent: {agentLabel}
              </Text>
            ) : null}
            <Box>
              <Text fontSize='sm' mb={1}>
                Reason {force ? '(required to force)' : '(optional)'}
              </Text>
              <Textarea
                value={reason}
                onChange={event => setReason(event.target.value)}
                placeholder='e.g. host decommissioned'
                size='sm'
                rows={2}
              />
            </Box>
            {blocked ? (
              <Checkbox
                isChecked={force}
                onChange={event => setForce(event.target.checked)}
                size='sm'
              >
                <Text as='span' fontSize='sm'>
                  Force retirement even though the agent holds job leases
                </Text>
              </Checkbox>
            ) : null}
            {error ? (
              <Alert status='error' borderRadius='md' variant='left-accent'>
                <AlertIcon />
                <AlertDescription fontSize='sm'>{error}</AlertDescription>
              </Alert>
            ) : null}
          </Stack>
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
            isDisabled={forceNeedsReason}
          >
            {force ? 'Force retire' : 'Retire agent'}
          </Button>
        </ModalFooter>
      </DashboardModalFrame>
    </Modal>
  );
}

/**
 * Agent fleet table: name/id, status, version, last heartbeat, and a
 * manager-only Retire action. Empty state points to the Deploy an agent
 * panel on the same page.
 */
export default function AgentFleetPanel() {
  const { workspaceId } = useWorkspace();
  const canManage = useCertOpsCanManage();
  const { enabled, agents, loading, error, refresh } = useCertOpsAgents();

  const [retireTarget, setRetireTarget] = useState(null);

  const muted = useColorModeValue('gray.600', 'gray.400');
  const titleColor = useColorModeValue('gray.700', 'gray.200');
  const infoBg = useColorModeValue('blue.50', 'blue.900');
  const infoBorder = useColorModeValue('blue.200', 'blue.700');
  const infoText = useColorModeValue('blue.800', 'blue.100');

  if (enabled !== true) return null;

  const handleRetire = async ({ force, reason }) => {
    if (!retireTarget?.id || !workspaceId) return;
    await retireAgent(workspaceId, retireTarget.id, { force, reason });
    showSuccess('Agent retired');
    setRetireTarget(null);
    refresh();
  };

  return (
    <Stack spacing={4} align='stretch'>
      <Box>
        <Text fontSize='md' fontWeight='bold' color={titleColor} mb={1}>
          Agent fleet
        </Text>
        <Alert
          status='info'
          variant='subtle'
          borderRadius='md'
          bg={infoBg}
          border='1px solid'
          borderColor={infoBorder}
          py={2}
          px={3}
        >
          <AlertIcon boxSize={4} />
          <AlertDescription fontSize='sm' color={infoText} lineHeight='short'>
            Agents connect outbound-only and lease jobs from this workspace. An
            agent is marked offline when it stops sending heartbeats; retire it
            to invalidate its credential permanently.
          </AlertDescription>
        </Alert>
      </Box>

      {error ? <DashboardErrorAlert>{error}</DashboardErrorAlert> : null}

      {loading ? (
        <HStack spacing={2} color={muted} py={4} justify='center'>
          <Spinner size='sm' />
          <Text fontSize='sm'>Loading agents...</Text>
        </HStack>
      ) : null}

      {!loading && !error && agents.length === 0 ? (
        <Box py={6} textAlign='center'>
          <Text fontSize='sm' fontWeight='semibold' color={titleColor}>
            No agents yet.
          </Text>
          <Text fontSize='sm' color={muted} mt={1}>
            {canManage
              ? 'Use the Deploy an agent panel on this page to install your first agent.'
              : 'A workspace manager can deploy agents from this page.'}
          </Text>
        </Box>
      ) : null}

      {!loading && agents.length > 0 ? (
        <TableContainer>
          <Table size='sm' variant='simple'>
            <Thead>
              <Tr>
                <Th>Agent</Th>
                <Th>Status</Th>
                <Th>Version</Th>
                <Th>Last heartbeat</Th>
                {canManage ? <Th textAlign='right'>Actions</Th> : null}
              </Tr>
            </Thead>
            <Tbody>
              {agents.map(agent => {
                const status = String(agent.status || '').toLowerCase();
                return (
                  <Tr key={agent.id}>
                    <Td>
                      <Box>
                        <Text fontSize='sm' fontWeight='semibold'>
                          {agent.name || agent.hostname || 'Unnamed agent'}
                        </Text>
                        <CopyableId
                          id={agent.agentId}
                          display={shortId(agent.agentId)}
                        />
                      </Box>
                    </Td>
                    <Td>
                      <AgentStatusBadge status={agent.status} />
                    </Td>
                    <Td>
                      <Text fontSize='sm' fontFamily='mono'>
                        {agent.agentVersion || '--'}
                      </Text>
                    </Td>
                    <Td>
                      <Text
                        fontSize='sm'
                        color={muted}
                        title={formatDateTime(agent.lastSeenAt)}
                      >
                        {formatRelativeDateTime(agent.lastSeenAt)}
                      </Text>
                    </Td>
                    {canManage ? (
                      <Td textAlign='right'>
                        {status !== 'retired' ? (
                          <Button
                            size='xs'
                            colorScheme='red'
                            variant='outline'
                            onClick={() => setRetireTarget(agent)}
                          >
                            Retire
                          </Button>
                        ) : null}
                      </Td>
                    ) : null}
                  </Tr>
                );
              })}
            </Tbody>
          </Table>
        </TableContainer>
      ) : null}

      <RetireAgentModal
        isOpen={Boolean(retireTarget)}
        onClose={() => setRetireTarget(null)}
        agent={retireTarget}
        onRetire={handleRetire}
      />
    </Stack>
  );
}
