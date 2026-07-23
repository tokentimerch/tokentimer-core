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
  createBootstrapToken,
  listAgents,
  revokeBootstrapToken,
} from './certopsAgentsApi.js';
import { formatDate } from './certopsFormat';
import { useCertOpsCanManage } from './useCertOps.js';
import {
  useCertOpsAgents,
  useCertOpsBootstrapTokens,
} from './useCertOpsAgents.js';

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

/**
 * Copy-paste install command without the bootstrap token: the installer reads
 * the token from a hidden interactive prompt (or from the
 * TOKENTIMER_AGENT_BOOTSTRAP_TOKEN environment variable) when no
 * --bootstrap-token flag is given, so the secret never lands in shell history.
 */
function buildTokenlessInstallCommand({ apiUrl, workspaceId }) {
  return [
    `sudo ./install-agent.sh \\`,
    `  --api-url '${apiUrl}' \\`,
    `  --workspace-id '${workspaceId}'`,
  ].join('\n');
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
 *  2. copy a pre-filled install command (CopyableCodeBlock); the installer
 *     prompts for the token, which is never embedded in the command,
 *  3. wait for the agent to register (polls GET /certops/agents and reports
 *     an agent whose id was not known when the token was created, or whose
 *     registration timestamp is at or after token creation).
 * Manager-gated: viewers see a read-only explainer, no token list or actions.
 */
export default function DeployAgentPanel({ onAgentRegistered }) {
  const { workspaceId } = useWorkspace();
  const canManage = useCertOpsCanManage();
  const { enabled, tokens, loading, error, refresh } =
    useCertOpsBootstrapTokens();
  const { agents: fleetAgents } = useCertOpsAgents();

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
  // Baseline snapshot of agent row ids, captured when the bootstrap token is
  // created (not on the first poll tick): an agent that registers between
  // token creation and the first poll must still be detected as new.
  const knownAgentIdsRef = useRef(null);
  // Token creation time; agents registered at or after it count as new even
  // if the baseline list was stale and already contained their id.
  const tokenCreatedAtRef = useRef(null);
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
    tokenCreatedAtRef.current = null;
  }, [workspaceId]);

  // Poll the fleet while waiting; success when an agent appears that was not
  // in the token-creation baseline, or that registered after the token was
  // created (timestamp check covers a stale baseline).
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
        const baselineIds = knownAgentIdsRef.current;
        const tokenCreatedAtMs = tokenCreatedAtRef.current;
        if (baselineIds === null && tokenCreatedAtMs === null) {
          // No token was created in this session; fall back to snapshotting
          // the fleet on the first tick, as before.
          knownAgentIdsRef.current = new Set(items.map(agent => agent.id));
          return;
        }
        const fresh = items.find(agent => {
          if (agent.status === 'retired') return false;
          if (baselineIds !== null && !baselineIds.has(agent.id)) return true;
          if (tokenCreatedAtMs !== null) {
            const registeredAtMs = new Date(
              agent.createdAt || agent.registeredAt || NaN
            ).getTime();
            if (
              !Number.isNaN(registeredAtMs) &&
              registeredAtMs >= tokenCreatedAtMs
            ) {
              return true;
            }
          }
          return false;
        });
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
  const installCommand = buildTokenlessInstallCommand({
    apiUrl,
    workspaceId: workspaceId || '<workspace-id>',
  });

  const beginWaiting = () => {
    // Keep the baseline captured at token creation; it must predate any
    // agent registered by this token. Only clear the show-once secret.
    setRegisteredAgent(null);
    setPlaintextToken('');
    setWaitState('waiting');
  };

  const handleCreate = async () => {
    if (!canSubmit) return;
    const requestWorkspaceId = workspaceId;
    // Snapshot the fleet and the creation time before the request: any agent
    // registering from now on can only come from this (or a newer) token.
    const baselineIds = new Set(
      (Array.isArray(fleetAgents) ? fleetAgents : []).map(agent => agent.id)
    );
    const createdAtMs = Date.now();
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
      knownAgentIdsRef.current = baselineIds;
      tokenCreatedAtRef.current = createdAtMs;
      setShowOnceOpen(true);
      showSuccess('Bootstrap token created');
    } catch (err) {
      if (activeWorkspaceRef.current !== requestWorkspaceId) return;
      showError('Create failed', createErrorMessage(err));
    } finally {
      setCreating(false);
    }
  };

  // The plaintext stays in memory only to drive the step-2 guidance; it is
  // cleared when the wait starts, on workspace switch, and on unmount. It is
  // never embedded in the install command.
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
                  Create a bootstrap token in step 1 first. The command never
                  contains the token; the installer asks for it separately.
                </Text>
              ) : (
                <Text fontSize='xs' color={muted}>
                  The command does not include the token. The installer will
                  prompt for it (hidden input); paste the token from step 1 at
                  the prompt, or set the TOKENTIMER_AGENT_BOOTSTRAP_TOKEN
                  environment variable before running.
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
                  The installer will ask for it at a hidden prompt; copy it now,
                  or store it in your secret manager.
                </AlertDescription>
              </Alert>
              <CopyableCodeBlock
                code={plaintextToken}
                label='Bootstrap token'
                copyable
                monospace
              />
              <Text fontSize='xs' color={muted}>
                The install command in step 2 does not contain the token. Paste
                the token at the installer prompt when asked.
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
