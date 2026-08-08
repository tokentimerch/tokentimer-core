import { useEffect, useRef, useState } from 'react';
import {
  Alert,
  AlertDescription,
  AlertIcon,
  Box,
  Button,
  ButtonGroup,
  Checkbox,
  Code,
  FormControl,
  FormHelperText,
  FormLabel,
  HStack,
  Input,
  Link as ChakraLink,
  Modal,
  ModalBody,
  ModalCloseButton,
  ModalFooter,
  ModalHeader,
  ModalOverlay,
  Select,
  Spinner,
  Text,
  VStack,
} from '@chakra-ui/react';
import {
  DashboardModalDescription,
  DashboardModalFrame,
  DashboardModalTitle,
  useDashboardModalProps,
} from '../DashboardModalFrame.jsx';
import CopyableCodeBlock from '../CopyableCodeBlock.jsx';
import { resolveApiBaseUrl } from '../../utils/resolveApiBaseUrl.js';
import { useWorkspace } from '../../utils/WorkspaceContext.jsx';
import { workspaceAPI } from '../../utils/apiClient';
import { showError, showSuccess } from '../../utils/toast.js';
import { useDashboardThemeColors } from '../../hooks/useDashboardTheme.js';
import {
  AGENT_BOOTSTRAP_TOKEN_NAME_MAX_LENGTH,
  createBootstrapToken,
  listAgents,
} from './certopsAgentsApi.js';
import { useCertOpsCanManage } from './useCertOps.js';
import { useCertOpsAgents } from './useCertOpsAgents.js';

/** Poll cadence while waiting for the freshly installed agent to register. */
const WAIT_POLL_INTERVAL_MS = 10000;

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
 * Same contract on both platforms; only the installer script and shell
 * differ (see certops-agent-install-windows.mdx for the native Windows
 * Service installer this Windows command drives).
 */
function buildTokenlessInstallCommand({ apiUrl, workspaceId, os }) {
  if (os === 'windows') {
    return [
      '.\\install-agent.ps1 `',
      `  --api-url '${apiUrl}' \``,
      `  --workspace-id '${workspaceId}'`,
    ].join('\n');
  }
  return [
    `sudo ./install-agent.sh \\`,
    `  --api-url '${apiUrl}' \\`,
    `  --workspace-id '${workspaceId}'`,
  ].join('\n');
}

/**
 * Full install runbook, anchored to the platform-specific step this modal
 * reproduces interactively. Self-hosted docs (`/docs/self-hosted/...`), not
 * cloud: this file lives in the self-hosted dashboard bundle.
 */
function buildInstallDocsUrl(os) {
  const base = 'https://tokentimer.ch/docs/self-hosted/runbooks';
  return os === 'windows'
    ? `${base}/certops-agent-install-windows#windows-install`
    : `${base}/certops-agent-install#install`;
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

/**
 * Guided "Deploy an agent" flow, as a modal launched from a button on the
 * Agents tab (U4). The bootstrap-token list and its revoke dialog stay
 * inline on the tab, since they are ongoing state rather than a one-time
 * task; this modal only carries the install/create/wait steps.
 *
 *  1. copy a pre-filled install command (CopyableCodeBlock) and run it on the
 *     target host; the installer pauses at a hidden prompt asking for a
 *     bootstrap token, which is never embedded in the command,
 *  2. create a bootstrap token (show-once secret) and paste it at that prompt,
 *  3. wait for the agent to register (polls GET /certops/agents and reports
 *     an agent whose id was not known when the token was created, or whose
 *     registration timestamp is at or after token creation).
 *
 * **The show-once secret is the hazard a modal introduces that a page did
 * not have.** An accidental backdrop click or Escape must not destroy an
 * unacknowledged credential, so once the secret is on screen this modal
 * disables the close button, the overlay click, and Escape, and requires the
 * explicit "Continue" acknowledgement below. The registration poll survives
 * being backgrounded (it is driven by the wait state, not by modal
 * visibility) and is always cancelled on unmount.
 */
export default function DeployAgentModal({
  isOpen,
  onClose,
  onAgentRegistered,
  certOpsPaused = false,
}) {
  const { workspaceId } = useWorkspace();
  const canManage = useCertOpsCanManage();
  const { muted } = useDashboardThemeColors();
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
  const [expiresLocal, setExpiresLocal] = useState(defaultExpiryLocalValue());
  const [downtimeAlertsEnabled, setDowntimeAlertsEnabled] = useState(true);
  const [contactGroupId, setContactGroupId] = useState('');
  const [contactGroups, setContactGroups] = useState([]);
  const [defaultContactGroupId, setDefaultContactGroupId] = useState('');
  const [creating, setCreating] = useState(false);
  const [plaintextToken, setPlaintextToken] = useState('');
  const [secretAcknowledged, setSecretAcknowledged] = useState(false);
  // 'linux' | 'windows'; only changes which install command/instructions
  // step 1 shows, never anything server-side (both platforms register
  // through the same bootstrap-token flow below).
  const [targetOs, setTargetOs] = useState('linux');
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

  const { agents: fleetAgents } = useCertOpsAgents();

  // Contact groups load lazily when the modal opens, same pattern as
  // CertificateTokenDetailModal / AgentFleetPanel's Edit alerting modal.
  useEffect(() => {
    if (!isOpen || !workspaceId) return undefined;
    let cancelled = false;
    workspaceAPI
      .getAlertSettings(workspaceId)
      .then(settings => {
        if (cancelled) return;
        setContactGroups(
          Array.isArray(settings?.contact_groups)
            ? settings.contact_groups
            : []
        );
        setDefaultContactGroupId(settings?.default_contact_group_id || '');
      })
      .catch(() => {
        if (!cancelled) setContactGroups([]);
      });
    return () => {
      cancelled = true;
    };
  }, [isOpen, workspaceId]);

  const resetWizard = () => {
    setName('');
    setExpiresLocal(defaultExpiryLocalValue());
    setDowntimeAlertsEnabled(true);
    setContactGroupId('');
    setCreating(false);
    setPlaintextToken('');
    setSecretAcknowledged(false);
    setWaitState('idle');
    setRegisteredAgent(null);
    setTargetOs('linux');
    knownAgentIdsRef.current = null;
    tokenCreatedAtRef.current = null;
  };

  // Poll the fleet while waiting; success when an agent appears that was not
  // in the token-creation baseline, or that registered after the token was
  // created (timestamp check covers a stale baseline). Driven by waitState,
  // not isOpen: closing the modal while still watching would otherwise
  // silently stop the poll with no way to resume it, and onAgentRegistered
  // must fire even if the operator has moved off this modal.
  useEffect(() => {
    if (waitState !== 'waiting' || !workspaceId) return undefined;
    let cancelled = false;
    const requestWorkspaceId = workspaceId;

    const poll = async () => {
      try {
        const data = await listAgents(requestWorkspaceId);
        if (cancelled) return;
        const items = Array.isArray(data?.items) ? data.items : [];
        const baselineIds = knownAgentIdsRef.current;
        const tokenCreatedAtMs = tokenCreatedAtRef.current;
        if (baselineIds === null && tokenCreatedAtMs === null) {
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

  const expiresAtIso = toIsoExpiry(expiresLocal);
  const expiryInPast =
    Boolean(expiresAtIso) && new Date(expiresAtIso).getTime() <= Date.now();
  const canSubmit =
    Boolean(name.trim()) &&
    Boolean(expiresAtIso) &&
    !expiryInPast &&
    !creating &&
    !certOpsPaused &&
    Boolean(workspaceId);

  const apiUrl =
    typeof window !== 'undefined' && window.location
      ? resolveApiBaseUrl() || window.location.origin
      : '';
  const installCommand = buildTokenlessInstallCommand({
    apiUrl,
    workspaceId: workspaceId || '<workspace-id>',
    os: targetOs,
  });

  const hasUnacknowledgedSecret =
    Boolean(plaintextToken) && !secretAcknowledged;

  const beginWaiting = () => {
    setRegisteredAgent(null);
    setWaitState('waiting');
  };

  const handleCreate = async () => {
    if (!canSubmit) return;
    const requestWorkspaceId = workspaceId;
    const baselineIds = new Set(
      (Array.isArray(fleetAgents) ? fleetAgents : []).map(agent => agent.id)
    );
    const createdAtMs = Date.now();
    setCreating(true);
    try {
      const result = await createBootstrapToken(requestWorkspaceId, {
        name: name.trim(),
        expiresAt: expiresAtIso,
        downtimeAlertsEnabled,
        contactGroupId: contactGroupId || null,
      });
      const plaintext =
        typeof result?.plaintextToken === 'string'
          ? result.plaintextToken.trim()
          : '';
      if (!plaintext) {
        showError(
          'Create failed',
          'The server response did not include the token value. The token may have been created; check the bootstrap token list and revoke it if needed.'
        );
        return;
      }
      knownAgentIdsRef.current = baselineIds;
      tokenCreatedAtRef.current = createdAtMs;
      setPlaintextToken(plaintext);
      setSecretAcknowledged(false);
      showSuccess('Bootstrap token created');
    } catch (err) {
      showError('Create failed', createErrorMessage(err));
    } finally {
      setCreating(false);
    }
  };

  const handleClose = () => {
    if (hasUnacknowledgedSecret) return;
    onClose();
  };

  if (!canManage) return null;

  return (
    <Modal
      isOpen={isOpen}
      onClose={handleClose}
      closeOnOverlayClick={!hasUnacknowledgedSecret}
      closeOnEsc={!hasUnacknowledgedSecret}
      isCentered
      scrollBehavior='inside'
    >
      <ModalOverlay {...overlayProps} />
      <DashboardModalFrame maxW={{ base: 'calc(100vw - 24px)', md: '640px' }}>
        <ModalHeader {...headerProps}>
          <DashboardModalTitle>Deploy an agent</DashboardModalTitle>
          <DashboardModalDescription>
            Agents run on your infrastructure and connect outbound-only. Keys
            never leave the agent host.
          </DashboardModalDescription>
        </ModalHeader>
        {!hasUnacknowledgedSecret ? (
          <ModalCloseButton {...closeButtonProps} />
        ) : null}
        <ModalBody {...bodyProps}>
          <VStack align='stretch' spacing={4}>
            <Box>
              <Text fontSize='sm' fontWeight='semibold' mb={2}>
                Step 1: Run the installer on the target host
              </Text>
              <VStack align='stretch' spacing={2}>
                <ButtonGroup size='xs' isAttached variant='outline'>
                  <Button
                    colorScheme={targetOs === 'linux' ? 'blue' : undefined}
                    variant={targetOs === 'linux' ? 'solid' : 'outline'}
                    onClick={() => setTargetOs('linux')}
                  >
                    Linux
                  </Button>
                  <Button
                    colorScheme={targetOs === 'windows' ? 'blue' : undefined}
                    variant={targetOs === 'windows' ? 'solid' : 'outline'}
                    onClick={() => setTargetOs('windows')}
                  >
                    Windows
                  </Button>
                </ButtonGroup>
                {targetOs === 'windows' ? (
                  <Text fontSize='sm' color={muted}>
                    From an elevated (Administrator) PowerShell prompt (
                    <Code fontSize='xs'>powershell.exe</Code> or{' '}
                    <Code fontSize='xs'>pwsh</Code>), in the unpacked agent
                    package's directory:
                  </Text>
                ) : (
                  <Text fontSize='sm' color={muted}>
                    From the unpacked agent package directory (
                    <Code fontSize='xs'>packages/agent/scripts</Code>) on a Linux
                    host with Node 22+:
                  </Text>
                )}
                <CopyableCodeBlock
                  code={installCommand}
                  label='Install command'
                  copyable
                  monospace
                />
                <Text fontSize='xs' color={muted}>
                  The command does not include a token. The installer will pause
                  with a hidden prompt asking for one; create a bootstrap token
                  in step 2 below and paste it there, or set the
                  TOKENTIMER_AGENT_BOOTSTRAP_TOKEN environment variable before
                  running.
                </Text>
                <Text fontSize='xs'>
                  <ChakraLink
                    onClick={() =>
                      window.open(
                        buildInstallDocsUrl(targetOs),
                        '_blank',
                        'noopener,noreferrer'
                      )
                    }
                    cursor='pointer'
                    color='blue.500'
                    textDecoration='underline'
                    isExternal
                  >
                    Full install guide ({targetOs === 'windows' ? 'Windows' : 'Linux'})
                  </ChakraLink>
                </Text>
              </VStack>
            </Box>

            <Box>
              <Text fontSize='sm' fontWeight='semibold' mb={2}>
                Step 2: Create a bootstrap token
              </Text>
              <VStack align='stretch' spacing={3}>
                <FormControl isRequired isDisabled={hasUnacknowledgedSecret}>
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

                <FormControl
                  isRequired
                  isInvalid={expiryInPast}
                  isDisabled={hasUnacknowledgedSecret}
                >
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

                <FormControl isDisabled={hasUnacknowledgedSecret}>
                  <Checkbox
                    isChecked={downtimeAlertsEnabled}
                    onChange={event =>
                      setDowntimeAlertsEnabled(event.target.checked)
                    }
                    size='sm'
                  >
                    <Text as='span' fontSize='sm'>
                      Agent downtime alerts
                    </Text>
                  </Checkbox>
                  <FormHelperText>
                    Alert when this agent has not been seen for 10 minutes.
                  </FormHelperText>
                </FormControl>

                {downtimeAlertsEnabled ? (
                  <FormControl
                    isDisabled={hasUnacknowledgedSecret}
                    maxW='280px'
                  >
                    <FormLabel fontSize='sm'>Contact group</FormLabel>
                    <Select
                      size='sm'
                      value={contactGroupId}
                      onChange={event => setContactGroupId(event.target.value)}
                    >
                      <option value=''>Default workspace group</option>
                      {contactGroups.map(g => (
                        <option key={g.id} value={g.id}>
                          {g.name}
                          {String(g.id) === String(defaultContactGroupId)
                            ? ' (default)'
                            : ''}
                        </option>
                      ))}
                    </Select>
                  </FormControl>
                ) : null}

                {!plaintextToken ? (
                  <Button
                    {...primaryButtonProps}
                    size='sm'
                    alignSelf='flex-start'
                    onClick={handleCreate}
                    isDisabled={!canSubmit}
                    isLoading={creating}
                    loadingText='Creating'
                  >
                    Create bootstrap token
                  </Button>
                ) : null}
                {certOpsPaused && !plaintextToken ? (
                  <Text fontSize='xs' color={muted}>
                    Certificate operations are paused for this workspace, so new
                    bootstrap tokens are refused.
                  </Text>
                ) : null}

                {plaintextToken ? (
                  <Alert
                    status='warning'
                    borderRadius='md'
                    variant='left-accent'
                  >
                    <AlertIcon />
                    <VStack align='stretch' spacing={3} flex='1'>
                      <AlertDescription fontSize='sm'>
                        This token is shown only once and registers exactly one
                        agent. The installer will ask for it at a hidden prompt;
                        copy it now, or store it in your secret manager.
                      </AlertDescription>
                      <CopyableCodeBlock
                        code={plaintextToken}
                        label='Bootstrap token'
                        copyable
                        monospace
                      />
                      {!secretAcknowledged ? (
                        <Button
                          size='sm'
                          colorScheme='orange'
                          alignSelf='flex-start'
                          onClick={() => setSecretAcknowledged(true)}
                        >
                          I have saved this token
                        </Button>
                      ) : null}
                    </VStack>
                  </Alert>
                ) : null}

                {plaintextToken && secretAcknowledged ? (
                  <Text fontSize='xs' color={muted}>
                    Paste the token at the installer's hidden prompt in step 1,
                    then watch for the agent to register:
                  </Text>
                ) : null}
                {plaintextToken && secretAcknowledged ? (
                  <Button
                    size='sm'
                    alignSelf='flex-start'
                    variant='outline'
                    onClick={beginWaiting}
                    isDisabled={waitState === 'waiting'}
                  >
                    I pasted the token, start watching
                  </Button>
                ) : null}
              </VStack>
            </Box>

            {waitState === 'waiting' ? (
              <Box>
                <Text fontSize='sm' fontWeight='semibold' mb={2}>
                  Step 3: Waiting for the agent to register
                </Text>
                <HStack spacing={2}>
                  <Spinner size='sm' />
                  <Text fontSize='sm'>
                    Checking every {WAIT_POLL_INTERVAL_MS / 1000}s. The agent
                    should appear within about a minute of the service starting.
                  </Text>
                </HStack>
                <Button
                  size='xs'
                  variant='ghost'
                  mt={2}
                  onClick={() => setWaitState('idle')}
                >
                  Stop waiting
                </Button>
              </Box>
            ) : null}

            {waitState === 'registered' && registeredAgent ? (
              <Alert status='success' borderRadius='md' variant='left-accent'>
                <AlertIcon />
                <VStack align='stretch' spacing={2} flex='1'>
                  <Text fontSize='sm' fontWeight='semibold'>
                    Agent registered
                  </Text>
                  <Text fontSize='sm'>
                    {registeredAgent.name ||
                      registeredAgent.hostname ||
                      registeredAgent.agentId}{' '}
                    is now connected. Manage it in the agent fleet table.
                  </Text>
                  <Button
                    size='xs'
                    variant='outline'
                    alignSelf='flex-start'
                    onClick={resetWizard}
                  >
                    Deploy another agent
                  </Button>
                </VStack>
              </Alert>
            ) : null}
          </VStack>
        </ModalBody>
        <ModalFooter {...footerProps}>
          <Button
            {...outlineButtonProps}
            onClick={handleClose}
            isDisabled={hasUnacknowledgedSecret}
          >
            {waitState === 'registered' ? 'Done' : 'Cancel'}
          </Button>
        </ModalFooter>
      </DashboardModalFrame>
    </Modal>
  );
}
