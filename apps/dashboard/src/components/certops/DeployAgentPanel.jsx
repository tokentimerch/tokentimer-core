import { useEffect, useRef, useState } from 'react';
import {
  Alert,
  AlertDescription,
  AlertDialog,
  AlertDialogBody,
  AlertDialogContent,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogOverlay,
  AlertIcon,
  Badge,
  Box,
  Button,
  Code,
  FormControl,
  FormHelperText,
  FormLabel,
  HStack,
  Input,
  Modal,
  ModalBody,
  ModalContent,
  ModalFooter,
  ModalHeader,
  ModalOverlay,
  Spinner,
  Stack,
  Text,
  useColorModeValue,
  VStack,
} from '@chakra-ui/react';
import CopyableCodeBlock from '../CopyableCodeBlock.jsx';
import { DashboardErrorAlert } from '../DashboardPrimitives.jsx';
import { useWorkspace } from '../../utils/WorkspaceContext.jsx';
import { showError, showSuccess } from '../../utils/toast.js';
import {
  AGENT_BOOTSTRAP_TOKEN_NAME_MAX_LENGTH,
  buildInstallCommand,
  createBootstrapToken,
  listAgents,
  revokeBootstrapToken,
} from './certopsAgentsApi.js';
import { formatDate } from './certopsFormat';
import { useCertOpsCanManage } from './useCertOps.js';
import { useCertOpsBootstrapTokens } from './useCertOpsAgents.js';

const TOKEN_STATUS_SCHEME = {
  active: 'green',
  used: 'blue',
  revoked: 'red',
  expired: 'orange',
};

/** Poll cadence while waiting for the freshly installed agent to register. */
const WAIT_POLL_INTERVAL_MS = 10000;

function displayTokenStatus(token) {
  const status = String(token?.status || '').toLowerCase();
  if (status && status !== 'active') return status;
  if (token?.expiresAt) {
    const expires = new Date(token.expiresAt);
    if (!Number.isNaN(expires.getTime()) && expires.getTime() < Date.now()) {
      return 'expired';
    }
  }
  return status || 'active';
}

function toIsoExpiry(localValue) {
  if (!localValue) return null;
  const date = new Date(localValue);
  if (Number.isNaN(date.getTime())) return null;
  return date.toISOString();
}

function localDatetimeValue(date) {
  const pad = n => String(n).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function nowLocalDatetimeValue() {
  return localDatetimeValue(new Date());
}

/** Default token expiry: 24 hours out (server requires expiry <= 30 days). */
function defaultExpiryLocalValue() {
  return localDatetimeValue(new Date(Date.now() + 24 * 60 * 60 * 1000));
}

function createErrorMessage(err) {
  const code = err?.response?.data?.code;
  const status = err?.response?.status;
  if (status === 403 || code === 'INSUFFICIENT_ROLE') {
    return 'You need workspace manager permission to create bootstrap tokens.';
  }
  if (code === 'CERTOPS_AGENT_BOOTSTRAP_TOKEN_NAME_INVALID') {
    return 'Token name is invalid. Use a non-empty name up to 128 characters.';
  }
  if (
    code === 'CERTOPS_AGENT_BOOTSTRAP_TOKEN_EXPIRY_INVALID' ||
    code === 'CERTOPS_AGENT_BOOTSTRAP_TOKEN_INVALID'
  ) {
    return 'Expiry is invalid. Choose a future date within the next 30 days.';
  }
  return (
    err?.response?.data?.error ||
    err?.message ||
    'Could not create bootstrap token.'
  );
}

function revokeErrorMessage(err) {
  const code = err?.response?.data?.code;
  const status = err?.response?.status;
  if (status === 403 || code === 'INSUFFICIENT_ROLE') {
    return 'You need workspace manager permission to revoke bootstrap tokens.';
  }
  return (
    err?.response?.data?.error ||
    err?.message ||
    'Could not revoke bootstrap token.'
  );
}

/**
 * Guided "Deploy an agent" flow:
 *  1. create a bootstrap token (show-once secret, ApiTokenPanel pattern),
 *  2. copy a pre-filled install command (CopyableCodeBlock),
 *  3. wait for the agent to register (polls GET /certops/agents and compares
 *     against the agent ids snapshotted when the wait started).
 * Manager-gated: viewers see a read-only explainer, no token list or actions.
 */
export default function DeployAgentPanel({ onAgentRegistered }) {
  const { workspaceId } = useWorkspace();
  const canManage = useCertOpsCanManage();
  const { enabled, tokens, loading, error, refresh } =
    useCertOpsBootstrapTokens();

  const [name, setName] = useState('');
  const [expiresLocal, setExpiresLocal] = useState(defaultExpiryLocalValue());
  const [creating, setCreating] = useState(false);
  const [plaintextToken, setPlaintextToken] = useState('');
  const [showOnceOpen, setShowOnceOpen] = useState(false);
  const [revokeTarget, setRevokeTarget] = useState(null);
  const [revoking, setRevoking] = useState(false);
  // 'idle' | 'waiting' | 'registered'
  const [waitState, setWaitState] = useState('idle');
  const [registeredAgent, setRegisteredAgent] = useState(null);
  const knownAgentIdsRef = useRef(null);
  const revokeCancelRef = useRef(null);

  // Show-once secret and wait state are workspace-scoped: switching
  // workspaces clears the secret from memory and aborts the wait.
  const activeWorkspaceRef = useRef(workspaceId);
  useEffect(() => {
    activeWorkspaceRef.current = workspaceId;
    setPlaintextToken('');
    setShowOnceOpen(false);
    setRevokeTarget(null);
    setWaitState('idle');
    setRegisteredAgent(null);
    knownAgentIdsRef.current = null;
  }, [workspaceId]);

  // Poll the fleet while waiting; success when an agent id appears that was
  // not in the snapshot taken when the wait started.
  useEffect(() => {
    if (waitState !== 'waiting' || !workspaceId) return undefined;
    let cancelled = false;
    const requestWorkspaceId = workspaceId;

    const poll = async () => {
      try {
        const data = await listAgents(requestWorkspaceId);
        if (cancelled || activeWorkspaceRef.current !== requestWorkspaceId) {
          return;
        }
        const items = Array.isArray(data?.items) ? data.items : [];
        if (knownAgentIdsRef.current === null) {
          knownAgentIdsRef.current = new Set(items.map(agent => agent.id));
          return;
        }
        const fresh = items.find(
          agent =>
            !knownAgentIdsRef.current.has(agent.id) &&
            agent.status !== 'retired'
        );
        if (fresh) {
          setRegisteredAgent(fresh);
          setWaitState('registered');
          showSuccess('Agent registered');
          if (typeof onAgentRegistered === 'function') onAgentRegistered();
        }
      } catch (_) {
        // Transient poll failures are silent; the next tick retries.
      }
    };

    poll();
    const timer = setInterval(poll, WAIT_POLL_INTERVAL_MS);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [waitState, workspaceId, onAgentRegistered]);

  const muted = useColorModeValue('gray.600', 'gray.400');
  const border = useColorModeValue('gray.200', 'gray.700');
  const rowBg = useColorModeValue('gray.50', 'gray.800');
  const infoBg = useColorModeValue('blue.50', 'blue.900');
  const infoBorder = useColorModeValue('blue.200', 'blue.700');
  const infoText = useColorModeValue('blue.800', 'blue.100');
  const titleColor = useColorModeValue('gray.700', 'gray.200');
  const successBg = useColorModeValue('green.50', 'green.900');
  const successBorder = useColorModeValue('green.200', 'green.700');

  if (enabled !== true) return null;

  const expiresAtIso = toIsoExpiry(expiresLocal);
  const expiryInPast =
    Boolean(expiresAtIso) && new Date(expiresAtIso).getTime() <= Date.now();
  const canSubmit =
    Boolean(name.trim()) &&
    Boolean(expiresAtIso) &&
    !expiryInPast &&
    !creating &&
    Boolean(workspaceId);

  const apiUrl =
    typeof window !== 'undefined' && window.location
      ? window.location.origin
      : '';
  const installCommand = buildInstallCommand({
    apiUrl,
    workspaceId: workspaceId || '<workspace-id>',
    bootstrapToken: plaintextToken || null,
  });

  const beginWaiting = () => {
    knownAgentIdsRef.current = null;
    setRegisteredAgent(null);
    setPlaintextToken('');
    setWaitState('waiting');
  };

  const handleCreate = async () => {
    if (!canSubmit) return;
    const requestWorkspaceId = workspaceId;
    setCreating(true);
    try {
      const result = await createBootstrapToken(requestWorkspaceId, {
        name: name.trim(),
        expiresAt: expiresAtIso,
      });
      if (activeWorkspaceRef.current !== requestWorkspaceId) return;
      // Only enter the show-once flow when the response carries the secret;
      // a success state without the token would be unrecoverable.
      const plaintext =
        typeof result?.plaintextToken === 'string'
          ? result.plaintextToken.trim()
          : '';
      if (!plaintext) {
        showError(
          'Create failed',
          'The server response did not include the token value. The token may have been created; check the list and revoke it if needed.'
        );
        refresh();
        return;
      }
      setName('');
      setExpiresLocal(defaultExpiryLocalValue());
      setPlaintextToken(plaintext);
      setShowOnceOpen(true);
      showSuccess('Bootstrap token created');
    } catch (err) {
      if (activeWorkspaceRef.current !== requestWorkspaceId) return;
      showError('Create failed', createErrorMessage(err));
    } finally {
      setCreating(false);
    }
  };

  // Keeps the plaintext in memory for the step-2 install command; it is
  // cleared when the wait starts, on workspace switch, and on unmount.
  const handleShowOnceClose = () => {
    setShowOnceOpen(false);
    refresh();
  };

  const handleRevoke = async () => {
    if (!revokeTarget?.id || !workspaceId) return;
    const requestWorkspaceId = workspaceId;
    setRevoking(true);
    try {
      await revokeBootstrapToken(requestWorkspaceId, revokeTarget.id);
      if (activeWorkspaceRef.current !== requestWorkspaceId) return;
      showSuccess('Bootstrap token revoked');
      setRevokeTarget(null);
      refresh();
    } catch (err) {
      if (activeWorkspaceRef.current !== requestWorkspaceId) return;
      showError('Revoke failed', revokeErrorMessage(err));
    } finally {
      setRevoking(false);
    }
  };

  return (
    <Stack spacing={4} align='stretch'>
      <Box>
        <Text fontSize='md' fontWeight='bold' color={titleColor} mb={1}>
          Deploy an agent
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
            Agents run on your infrastructure and connect outbound-only. Keys
            never leave the agent host. Deploying takes three steps: create a
            single-use bootstrap token, run the install command on the target
            host, then wait for the agent to register.
          </AlertDescription>
        </Alert>
      </Box>

      {error ? <DashboardErrorAlert>{error}</DashboardErrorAlert> : null}

      {!canManage ? (
        <Text fontSize='sm' color={muted}>
          Deploying agents requires workspace manager permission. Ask a
          workspace manager to create a bootstrap token and install the agent.
        </Text>
      ) : (
        <Stack spacing={4} align='stretch'>
          <Box
            border='1px solid'
            borderColor={border}
            borderRadius='12px'
            p={{ base: 3.5, md: 4 }}
          >
            <Text fontSize='sm' fontWeight='semibold' color={titleColor} mb={3}>
              Step 1: Create a bootstrap token
            </Text>
            <VStack align='stretch' spacing={4}>
              <FormControl isRequired>
                <FormLabel fontSize='sm'>Name</FormLabel>
                <Input
                  value={name}
                  onChange={event => setName(event.target.value)}
                  maxLength={AGENT_BOOTSTRAP_TOKEN_NAME_MAX_LENGTH}
                  placeholder='e.g. dc1-edge-agent'
                  size='sm'
                />
                <FormHelperText>
                  Up to {AGENT_BOOTSTRAP_TOKEN_NAME_MAX_LENGTH} characters.
                  Single-use: one token registers exactly one agent.
                </FormHelperText>
              </FormControl>

              <FormControl isRequired isInvalid={expiryInPast}>
                <FormLabel fontSize='sm'>Expires</FormLabel>
                <Input
                  type='datetime-local'
                  value={expiresLocal}
                  onChange={event => setExpiresLocal(event.target.value)}
                  min={nowLocalDatetimeValue()}
                  size='sm'
                  maxW='280px'
                />
                <FormHelperText>
                  {expiryInPast
                    ? 'Expiry must be in the future.'
                    : 'Required; at most 30 days out. Defaults to 24 hours.'}
                </FormHelperText>
              </FormControl>

              <Button
                colorScheme='blue'
                size='sm'
                alignSelf='flex-start'
                onClick={handleCreate}
                isDisabled={!canSubmit}
                isLoading={creating}
                loadingText='Creating'
              >
                Create bootstrap token
              </Button>
            </VStack>
          </Box>

          <Box
            border='1px solid'
            borderColor={border}
            borderRadius='12px'
            p={{ base: 3.5, md: 4 }}
          >
            <Text fontSize='sm' fontWeight='semibold' color={titleColor} mb={3}>
              Step 2: Run the installer on the target host
            </Text>
            <VStack align='stretch' spacing={3}>
              <Text fontSize='sm' color={muted}>
                From the unpacked agent package directory (
                <Code fontSize='xs'>packages/agent/scripts</Code>) on a Linux
                host with Node 22+:
              </Text>
              <CopyableCodeBlock
                code={installCommand}
                label='Install command'
                copyable
                monospace
              />
              {!plaintextToken ? (
                <Text fontSize='xs' color={muted}>
                  Create a bootstrap token in step 1 to pre-fill the command;
                  the secret is only available until you leave this step.
                </Text>
              ) : (
                <Text fontSize='xs' color={muted}>
                  The command includes the one-time token. Run it now; the token
                  is cleared from this page when you start waiting.
                </Text>
              )}
              <Button
                size='sm'
                alignSelf='flex-start'
                colorScheme='blue'
                variant='outline'
                onClick={beginWaiting}
                isDisabled={waitState === 'waiting'}
              >
                I ran the installer
              </Button>
            </VStack>
          </Box>

          {waitState === 'waiting' ? (
            <Box
              border='1px solid'
              borderColor={border}
              borderRadius='12px'
              p={{ base: 3.5, md: 4 }}
            >
              <Text
                fontSize='sm'
                fontWeight='semibold'
                color={titleColor}
                mb={2}
              >
                Step 3: Waiting for the agent to register
              </Text>
              <HStack spacing={2} color={muted}>
                <Spinner size='sm' />
                <Text fontSize='sm'>
                  Checking every {WAIT_POLL_INTERVAL_MS / 1000}s. The agent
                  should appear within about a minute of the service starting.
                </Text>
              </HStack>
              <Button
                size='xs'
                variant='ghost'
                mt={3}
                onClick={() => setWaitState('idle')}
              >
                Stop waiting
              </Button>
            </Box>
          ) : null}

          {waitState === 'registered' && registeredAgent ? (
            <Box
              border='1px solid'
              borderColor={successBorder}
              bg={successBg}
              borderRadius='12px'
              p={{ base: 3.5, md: 4 }}
            >
              <Text fontSize='sm' fontWeight='semibold' color={titleColor}>
                Agent registered
              </Text>
              <Text fontSize='sm' color={muted} mt={1}>
                {registeredAgent.name ||
                  registeredAgent.hostname ||
                  registeredAgent.agentId}{' '}
                is now connected. Manage it in the Agent fleet panel.
              </Text>
              <Button
                size='xs'
                variant='outline'
                mt={3}
                onClick={() => setWaitState('idle')}
              >
                Deploy another agent
              </Button>
            </Box>
          ) : null}

          <Box>
            <Text fontSize='sm' fontWeight='semibold' color={titleColor} mb={2}>
              Bootstrap tokens
            </Text>

            {loading ? (
              <HStack spacing={2} color={muted} py={3} justify='center'>
                <Spinner size='sm' />
                <Text fontSize='sm'>Loading bootstrap tokens...</Text>
              </HStack>
            ) : null}

            {!loading && tokens.length === 0 ? (
              <Text fontSize='sm' color={muted}>
                No bootstrap tokens yet. Used and expired tokens also show up
                here.
              </Text>
            ) : null}

            {!loading && tokens.length > 0 ? (
              <Stack spacing={2} align='stretch'>
                {tokens.map(token => {
                  const status = displayTokenStatus(token);
                  const canRevoke = status === 'active';
                  return (
                    <Box
                      key={token.id}
                      border='1px solid'
                      borderColor={border}
                      borderRadius='12px'
                      bg={rowBg}
                      p={3}
                    >
                      <HStack
                        justify='space-between'
                        align='start'
                        spacing={3}
                        flexWrap='wrap'
                      >
                        <Box minW={0}>
                          <Text
                            fontSize='sm'
                            fontWeight='semibold'
                            noOfLines={1}
                          >
                            {token.name || 'Unnamed token'}
                          </Text>
                          <Code fontSize='xs' mt={1}>
                            {token.tokenPrefix || '--'}
                          </Code>
                        </Box>
                        <HStack spacing={2} flexShrink={0}>
                          <Badge
                            colorScheme={TOKEN_STATUS_SCHEME[status] || 'gray'}
                            variant='subtle'
                            textTransform='none'
                          >
                            {status}
                          </Badge>
                          {canRevoke ? (
                            <Button
                              size='xs'
                              colorScheme='red'
                              variant='outline'
                              onClick={() => setRevokeTarget(token)}
                            >
                              Revoke
                            </Button>
                          ) : null}
                        </HStack>
                      </HStack>
                      <HStack
                        spacing={{ base: 3, md: 6 }}
                        flexWrap='wrap'
                        fontSize='xs'
                        color={muted}
                        mt={2}
                      >
                        <Text>Created {formatDate(token.createdAt)}</Text>
                        <Text>
                          Expires{' '}
                          {token.expiresAt ? formatDate(token.expiresAt) : '--'}
                        </Text>
                        {token.usedAt ? (
                          <Text>Used {formatDate(token.usedAt)}</Text>
                        ) : null}
                      </HStack>
                    </Box>
                  );
                })}
              </Stack>
            ) : null}
          </Box>
        </Stack>
      )}

      <Modal
        isOpen={showOnceOpen}
        onClose={handleShowOnceClose}
        closeOnOverlayClick={false}
        closeOnEsc={false}
        isCentered
        size='lg'
      >
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>Bootstrap token created</ModalHeader>
          <ModalBody>
            <VStack align='stretch' spacing={4}>
              <Alert status='warning' borderRadius='md' variant='left-accent'>
                <AlertIcon />
                <AlertDescription>
                  This token is shown only once and registers exactly one agent.
                  Use it in the install command in step 2, or store it in your
                  secret manager now.
                </AlertDescription>
              </Alert>
              <CopyableCodeBlock
                code={plaintextToken}
                label='Bootstrap token'
                copyable
                monospace
              />
              <Text fontSize='xs' color={muted}>
                Closing this dialog keeps the token pre-filled in the step 2
                install command until you start waiting for the agent.
              </Text>
            </VStack>
          </ModalBody>
          <ModalFooter>
            <Button colorScheme='blue' onClick={handleShowOnceClose}>
              Continue to install
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>

      <AlertDialog
        isOpen={Boolean(revokeTarget)}
        leastDestructiveRef={revokeCancelRef}
        onClose={() => (revoking ? null : setRevokeTarget(null))}
        isCentered
      >
        <AlertDialogOverlay />
        <AlertDialogContent>
          <AlertDialogHeader fontSize='lg' fontWeight='bold'>
            Revoke bootstrap token
          </AlertDialogHeader>
          <AlertDialogBody>
            A revoked token can no longer register an agent. Agents that already
            registered are unaffected. This cannot be undone.
            {revokeTarget?.name ? (
              <Text mt={3} fontSize='sm' color={muted}>
                Token: {revokeTarget.name}
              </Text>
            ) : null}
          </AlertDialogBody>
          <AlertDialogFooter>
            <Button
              ref={revokeCancelRef}
              onClick={() => setRevokeTarget(null)}
              isDisabled={revoking}
            >
              Cancel
            </Button>
            <Button
              colorScheme='red'
              ml={3}
              onClick={handleRevoke}
              isLoading={revoking}
              loadingText='Revoking'
            >
              Revoke
            </Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Stack>
  );
}
