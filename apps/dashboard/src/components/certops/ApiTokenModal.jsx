import { useEffect, useState } from 'react';
import {
  Alert,
  AlertDescription,
  AlertIcon,
  Button,
  Checkbox,
  CheckboxGroup,
  FormControl,
  FormHelperText,
  FormLabel,
  Input,
  Modal,
  ModalBody,
  ModalCloseButton,
  ModalFooter,
  ModalHeader,
  ModalOverlay,
  Stack,
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
import { useDashboardThemeColors } from '../../hooks/useDashboardTheme.js';
import { useWorkspace } from '../../utils/WorkspaceContext.jsx';
import { showError, showSuccess } from '../../utils/toast.js';
import { tokenAPI } from '../../utils/apiClient';
import {
  CERTOPS_CONTROLLER_TOKEN_SCOPES,
  CERTOPS_TOKEN_NAME_MAX_LENGTH,
  CERTOPS_TOKEN_SCOPES,
  createApiToken,
} from './certopsTokensApi.js';
import {
  CERTOPS_SCOPE_META,
  CONTROLLER_CLUSTER_ID_MAX_LENGTH,
  isValidControllerClusterId,
} from './certopsTokenScopeMeta.js';

const CONTROLLER_SCOPE_SET = new Set(CERTOPS_CONTROLLER_TOKEN_SCOPES);

function toIsoExpiry(localValue) {
  if (!localValue) return null;
  const date = new Date(localValue);
  if (Number.isNaN(date.getTime())) return null;
  return date.toISOString();
}

function nowLocalDatetimeValue() {
  const date = new Date();
  const pad = n => String(n).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function createErrorMessage(err) {
  const code = err?.response?.data?.code;
  const status = err?.response?.status;
  if (status === 403 || code === 'INSUFFICIENT_ROLE') {
    return 'You need workspace manager permission to manage API tokens.';
  }
  if (code === 'CERTOPS_API_TOKEN_NAME_INVALID') {
    return 'Token name is invalid. Use a non-empty name up to 128 characters.';
  }
  if (code === 'CERTOPS_API_TOKEN_SCOPE_INVALID') {
    return 'One or more selected scopes are not allowed.';
  }
  if (code === 'CERTOPS_API_TOKEN_CONTROLLER_CLUSTER_INVALID') {
    return 'Cluster ID is required for controller scopes, and must be a valid Kubernetes cluster identifier (lowercase letters, digits, hyphens).';
  }
  if (code === 'CERTOPS_API_TOKEN_INVALID') {
    return 'Expiry is invalid. Choose a future date or leave it empty.';
  }
  return (
    err?.response?.data?.error || err?.message || 'Could not create API token.'
  );
}

/**
 * Create-token wizard for machine API tokens (U11), as a modal launched from
 * the Settings tab's header action. Ongoing token/revoke state stays inline
 * on the tab (ApiTokenList), same split as DeployAgentModal/BootstrapTokenList
 * on the Agents tab: creation is a one-time task, the inventory is not.
 *
 * Selecting a controller scope (`certops:observations:write` or
 * `certops:provision:execute`) requires a cluster ID, which the server uses
 * to bind the token to exactly one cert-manager controller cluster; deselecting
 * the last controller scope clears the field, mirroring the server's
 * "required with, forbidden without" validation.
 */
export default function ApiTokenModal({
  isOpen,
  onClose,
  onCreated,
  certOpsPaused = false,
}) {
  const { workspaceId } = useWorkspace();
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
  const [scopes, setScopes] = useState([]);
  const [clusterId, setClusterId] = useState('');
  const [expiresLocal, setExpiresLocal] = useState('');
  const [creating, setCreating] = useState(false);
  const [plaintextToken, setPlaintextToken] = useState('');
  const [secretAcknowledged, setSecretAcknowledged] = useState(false);
  const [monitorExpiry, setMonitorExpiry] = useState(true);
  const [createdTokenInfo, setCreatedTokenInfo] = useState(null);

  const requiresClusterId = scopes.some(scope =>
    CONTROLLER_SCOPE_SET.has(scope)
  );

  // Deselecting the last controller scope clears the field rather than
  // leaving a stale value the next submit would silently resurrect.
  useEffect(() => {
    if (!requiresClusterId && clusterId) setClusterId('');
  }, [requiresClusterId, clusterId]);

  const resetWizard = () => {
    setName('');
    setScopes([]);
    setClusterId('');
    setExpiresLocal('');
    setCreating(false);
    setPlaintextToken('');
    setSecretAcknowledged(false);
    setMonitorExpiry(true);
    setCreatedTokenInfo(null);
  };

  // Unlike DeployAgentModal, there is no background poll to preserve across
  // a close, so each open starts the wizard fresh rather than resuming
  // wherever a previous session left off.
  useEffect(() => {
    if (isOpen) resetWizard();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isOpen]);

  const expiresAtIso = toIsoExpiry(expiresLocal);
  const expiryInPast =
    Boolean(expiresAtIso) && new Date(expiresAtIso).getTime() <= Date.now();
  const clusterIdInvalid =
    requiresClusterId && !isValidControllerClusterId(clusterId);

  const canSubmit =
    Boolean(name.trim()) &&
    scopes.length > 0 &&
    !expiryInPast &&
    !clusterIdInvalid &&
    !creating &&
    !certOpsPaused &&
    Boolean(workspaceId);

  const hasUnacknowledgedSecret =
    Boolean(plaintextToken) && !secretAcknowledged;

  const handleCreate = async () => {
    if (!canSubmit) return;
    const requestWorkspaceId = workspaceId;
    setCreating(true);
    try {
      const payload = { name: name.trim(), scopes: [...scopes] };
      if (expiresAtIso) payload.expiresAt = expiresAtIso;
      if (requiresClusterId) payload.controllerClusterId = clusterId.trim();

      const result = await createApiToken(requestWorkspaceId, payload);
      const plaintext =
        typeof result?.plaintextToken === 'string'
          ? result.plaintextToken.trim()
          : '';
      if (!plaintext) {
        showError(
          'Create failed',
          'The server response did not include the token value. The token may have been created; check the list and revoke it if needed.'
        );
        return;
      }
      setCreatedTokenInfo({
        id: result?.token?.id || null,
        name: result?.token?.name || name.trim(),
        expiresAt: result?.token?.expiresAt || expiresAtIso || null,
      });
      setPlaintextToken(plaintext);
      setSecretAcknowledged(false);
      showSuccess('API token created');
    } catch (err) {
      showError('Create failed', createErrorMessage(err));
    } finally {
      setCreating(false);
    }
  };

  const handleAcknowledge = async () => {
    if (monitorExpiry && createdTokenInfo?.expiresAt && workspaceId) {
      try {
        await tokenAPI.createToken({
          name: `${createdTokenInfo.name || 'Machine token'} (CertOps)`,
          type: 'api_key',
          category: 'key_secret',
          expiresAt: createdTokenInfo.expiresAt,
          workspace_id: workspaceId,
          certopsApiTokenId: createdTokenInfo.id || undefined,
        });
        try {
          window.dispatchEvent(new CustomEvent('tt:tokens-updated'));
        } catch (_) {}
      } catch (_err) {
        showError(
          'Monitoring not added',
          'The machine token was created, but TokenTimer could not add it for expiration monitoring. Add it manually if needed.'
        );
      }
    }
    setSecretAcknowledged(true);
    if (typeof onCreated === 'function') onCreated();
  };

  const handleClose = () => {
    if (hasUnacknowledgedSecret) return;
    onClose();
  };

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
          <DashboardModalTitle>Create machine API token</DashboardModalTitle>
          <DashboardModalDescription>
            Machine tokens are for external executors (certbot hooks, ACME
            clients, cert-manager controllers, CI). They bypass user sessions;
            scope them minimally and rotate on any suspicion of exposure.
          </DashboardModalDescription>
        </ModalHeader>
        {!hasUnacknowledgedSecret ? (
          <ModalCloseButton {...closeButtonProps} />
        ) : null}
        <ModalBody {...bodyProps}>
          {!plaintextToken ? (
            <VStack align='stretch' spacing={4}>
              <FormControl isRequired>
                <FormLabel fontSize='sm'>Name</FormLabel>
                <Input
                  value={name}
                  onChange={event => setName(event.target.value)}
                  maxLength={CERTOPS_TOKEN_NAME_MAX_LENGTH}
                  placeholder='e.g. certbot-prod-hook'
                  size='sm'
                />
                <FormHelperText>
                  Up to {CERTOPS_TOKEN_NAME_MAX_LENGTH} characters. Do not paste
                  key material into the name.
                </FormHelperText>
              </FormControl>

              <FormControl isRequired>
                <FormLabel fontSize='sm'>Scopes</FormLabel>
                <CheckboxGroup value={scopes} onChange={setScopes}>
                  <Stack spacing={2}>
                    {CERTOPS_TOKEN_SCOPES.map(scope => {
                      const meta = CERTOPS_SCOPE_META[scope];
                      return (
                        <Checkbox key={scope} value={scope} size='sm'>
                          <Text as='span' fontSize='sm'>
                            <Text as='span' fontWeight='semibold'>
                              {meta?.short || scope}
                            </Text>
                            {meta?.description ? (
                              <Text as='span' color={muted}>
                                {`: ${meta.description}`}
                              </Text>
                            ) : null}
                          </Text>
                        </Checkbox>
                      );
                    })}
                  </Stack>
                </CheckboxGroup>
              </FormControl>

              {requiresClusterId ? (
                <FormControl
                  isRequired
                  isInvalid={clusterIdInvalid && Boolean(clusterId)}
                >
                  <FormLabel fontSize='sm'>Cluster ID</FormLabel>
                  <Input
                    value={clusterId}
                    onChange={event => setClusterId(event.target.value)}
                    maxLength={CONTROLLER_CLUSTER_ID_MAX_LENGTH}
                    placeholder='e.g. prod-eu-west-1'
                    size='sm'
                    fontFamily='mono'
                  />
                  <FormHelperText>
                    Binds this token to one cert-manager controller cluster; the
                    server rejects requests naming a different cluster.
                    Lowercase letters, digits, and hyphens; cannot start or end
                    with a hyphen.
                  </FormHelperText>
                </FormControl>
              ) : null}

              <FormControl isInvalid={expiryInPast}>
                <FormLabel fontSize='sm'>Expires (optional)</FormLabel>
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
                    : 'Leave empty for no expiry.'}
                </FormHelperText>
              </FormControl>

              {certOpsPaused ? (
                <Text fontSize='xs' color={muted}>
                  Certificate operations are paused for this workspace, so new
                  machine tokens are refused.
                </Text>
              ) : null}
            </VStack>
          ) : (
            <VStack align='stretch' spacing={4}>
              <Alert status='warning' borderRadius='md' variant='left-accent'>
                <AlertIcon />
                <AlertDescription fontSize='sm'>
                  This token is shown only once. Store it in your secret manager
                  now. Anyone with this token can act on this workspace within
                  its scopes. TokenTimer never stores or accepts private keys;
                  do not paste key material into token names.
                </AlertDescription>
              </Alert>
              <CopyableCodeBlock
                code={plaintextToken}
                label='API token'
                copyable
                monospace
              />
              {createdTokenInfo?.expiresAt ? (
                <Checkbox
                  isChecked={monitorExpiry}
                  onChange={event => setMonitorExpiry(event.target.checked)}
                  size='sm'
                  isDisabled={secretAcknowledged}
                >
                  <Text as='span' fontSize='sm'>
                    Monitor this token&apos;s expiration with TokenTimer
                  </Text>
                </Checkbox>
              ) : null}
              {createdTokenInfo?.expiresAt && monitorExpiry ? (
                <Text fontSize='xs' color={muted}>
                  The TokenTimer entry is removed automatically if this machine
                  token is revoked.
                </Text>
              ) : null}
              {!secretAcknowledged ? (
                <Button
                  {...primaryButtonProps}
                  size='sm'
                  alignSelf='flex-start'
                  onClick={handleAcknowledge}
                >
                  I stored the token
                </Button>
              ) : (
                <Button
                  size='sm'
                  variant='outline'
                  alignSelf='flex-start'
                  onClick={resetWizard}
                >
                  Create another token
                </Button>
              )}
            </VStack>
          )}
        </ModalBody>
        <ModalFooter {...footerProps}>
          <Button
            {...outlineButtonProps}
            onClick={handleClose}
            isDisabled={hasUnacknowledgedSecret}
          >
            {secretAcknowledged ? 'Done' : 'Cancel'}
          </Button>
          {!plaintextToken ? (
            <Button
              {...primaryButtonProps}
              ml={3}
              onClick={handleCreate}
              isDisabled={!canSubmit}
              isLoading={creating}
              loadingText='Creating'
            >
              Create token
            </Button>
          ) : null}
        </ModalFooter>
      </DashboardModalFrame>
    </Modal>
  );
}
