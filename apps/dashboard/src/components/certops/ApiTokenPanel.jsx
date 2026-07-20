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
  Checkbox,
  CheckboxGroup,
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
import { tokenAPI } from '../../utils/apiClient';
import {
  CERTOPS_TOKEN_NAME_MAX_LENGTH,
  CERTOPS_TOKEN_SCOPES,
  createApiToken,
  revokeApiToken,
} from './certopsTokensApi.js';
import { formatDate } from './certopsFormat';
import { useCertOpsCanManage } from './useCertOps.js';
import { useCertOpsApiTokens } from './useCertOpsJobs.js';

const SCOPE_META = {
  'certops:read': {
    short: 'read',
    description: 'read certificates and jobs',
  },
  'certops:events:write': {
    short: 'events:write',
    description: 'report job lifecycle events',
  },
  'certops:jobs:read': {
    short: 'jobs:read',
    description: 'poll job status',
  },
  'certops:evidence:write': {
    short: 'evidence:write',
    description: 'attach evidence records',
  },
};

const STATUS_SCHEME = {
  active: 'green',
  revoked: 'red',
  expired: 'orange',
};

function scopeShortLabel(scope) {
  return (
    SCOPE_META[scope]?.short || String(scope || '').replace(/^certops:/, '')
  );
}

function displayStatus(token) {
  const status = String(token?.status || '').toLowerCase();
  if (status === 'revoked') return 'revoked';
  if (status === 'expired') return 'expired';
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
  if (code === 'CERTOPS_API_TOKEN_INVALID') {
    return 'Expiry is invalid. Choose a future date or leave it empty.';
  }
  return (
    err?.response?.data?.error || err?.message || 'Could not create API token.'
  );
}

function revokeErrorMessage(err) {
  const code = err?.response?.data?.code;
  const status = err?.response?.status;
  if (status === 403 || code === 'INSUFFICIENT_ROLE') {
    return 'You need workspace manager permission to revoke API tokens.';
  }
  return (
    err?.response?.data?.error || err?.message || 'Could not revoke API token.'
  );
}

/**
 * Machine API-token management for CertOps M2: create (show once), list,
 * revoke, scopes, last used, and handling warnings.
 */
export default function ApiTokenPanel() {
  const { workspaceId } = useWorkspace();
  const canManage = useCertOpsCanManage();
  const { enabled, tokens, loading, error, refresh } = useCertOpsApiTokens();

  const [name, setName] = useState('');
  const [scopes, setScopes] = useState([]);
  const [expiresLocal, setExpiresLocal] = useState('');
  const [creating, setCreating] = useState(false);
  const [plaintextToken, setPlaintextToken] = useState('');
  const [showOnceOpen, setShowOnceOpen] = useState(false);
  const [monitorExpiry, setMonitorExpiry] = useState(true);
  const [createdTokenInfo, setCreatedTokenInfo] = useState(null);
  const [revokeTarget, setRevokeTarget] = useState(null);
  const [revoking, setRevoking] = useState(false);
  const revokeCancelRef = useRef(null);

  // The show-once secret and any pending create/revoke belong to a single
  // workspace: switching workspaces clears the secret from memory and lets
  // in-flight responses know they are stale.
  const activeWorkspaceRef = useRef(workspaceId);
  useEffect(() => {
    activeWorkspaceRef.current = workspaceId;
    setPlaintextToken('');
    setShowOnceOpen(false);
    setCreatedTokenInfo(null);
    setRevokeTarget(null);
  }, [workspaceId]);

  const muted = useColorModeValue('gray.600', 'gray.400');
  const border = useColorModeValue('gray.200', 'gray.700');
  const rowBg = useColorModeValue('gray.50', 'gray.800');
  const infoBg = useColorModeValue('blue.50', 'blue.900');
  const infoBorder = useColorModeValue('blue.200', 'blue.700');
  const infoText = useColorModeValue('blue.800', 'blue.100');
  const titleColor = useColorModeValue('gray.700', 'gray.200');

  if (enabled !== true) return null;

  const expiresAtIso = toIsoExpiry(expiresLocal);
  const expiryInPast =
    Boolean(expiresAtIso) && new Date(expiresAtIso).getTime() <= Date.now();

  const canSubmit =
    Boolean(name.trim()) &&
    scopes.length > 0 &&
    !expiryInPast &&
    !creating &&
    Boolean(workspaceId);

  const handleCreate = async () => {
    if (!canSubmit) return;
    const requestWorkspaceId = workspaceId;
    setCreating(true);
    try {
      const payload = {
        name: name.trim(),
        scopes: [...scopes],
      };
      const expiresAt = toIsoExpiry(expiresLocal);
      if (expiresAt) payload.expiresAt = expiresAt;

      const result = await createApiToken(requestWorkspaceId, payload);
      // Stale-response guard: if the workspace changed while the request was
      // in flight, discard the result. Never surface another workspace's
      // secret in the current workspace's UI.
      if (activeWorkspaceRef.current !== requestWorkspaceId) return;
      // Guard: only enter the show-once flow when the create response
      // actually carries the plaintext secret; a success state without the
      // token would be unrecoverable for the user.
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
      setScopes([]);
      setExpiresLocal('');
      setCreatedTokenInfo({
        id: result?.token?.id || null,
        name: result?.token?.name || name.trim(),
        expiresAt: result?.token?.expiresAt || expiresAt || null,
      });
      setPlaintextToken(plaintext);
      setShowOnceOpen(true);
      showSuccess('API token created');
    } catch (err) {
      if (activeWorkspaceRef.current !== requestWorkspaceId) return;
      showError('Create failed', createErrorMessage(err));
    } finally {
      setCreating(false);
    }
  };

  const handleShowOnceClose = async () => {
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
        // Tell the dashboard's token list (rendered on a different route) to
        // reload, same as the import/endpoint flows do, so the new TokenTimer
        // entry shows up without a manual refresh.
        try {
          window.dispatchEvent(new CustomEvent('tt:tokens-updated'));
        } catch (_) {}
      } catch (err) {
        showError(
          'Monitoring not added',
          'The machine token was created, but TokenTimer could not add it for expiration monitoring. Add it manually if needed.'
        );
      }
    }
    setShowOnceOpen(false);
    setPlaintextToken('');
    setCreatedTokenInfo(null);
    setMonitorExpiry(true);
    refresh();
  };

  const handleRevoke = async () => {
    if (!revokeTarget?.id || !workspaceId) return;
    const requestWorkspaceId = workspaceId;
    setRevoking(true);
    try {
      await revokeApiToken(requestWorkspaceId, revokeTarget.id);
      if (activeWorkspaceRef.current !== requestWorkspaceId) return;
      showSuccess('API token revoked');
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
          Machine API tokens
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
            Machine tokens are for external executors (certbot hooks, ACME
            clients, CI). They bypass user sessions; scope them minimally and
            rotate on any suspicion of exposure.
          </AlertDescription>
        </Alert>
      </Box>

      {error ? <DashboardErrorAlert>{error}</DashboardErrorAlert> : null}

      {canManage ? (
        <Box
          border='1px solid'
          borderColor={border}
          borderRadius='12px'
          p={{ base: 3.5, md: 4 }}
        >
          <Text fontSize='sm' fontWeight='semibold' color={titleColor} mb={3}>
            Create token
          </Text>
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
                    const meta = SCOPE_META[scope];
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

            <Button
              colorScheme='blue'
              size='sm'
              alignSelf='flex-start'
              onClick={handleCreate}
              isDisabled={!canSubmit}
              isLoading={creating}
              loadingText='Creating'
            >
              Create token
            </Button>
          </VStack>
        </Box>
      ) : null}

      {loading ? (
        <HStack spacing={2} color={muted} py={4} justify='center'>
          <Spinner size='sm' />
          <Text fontSize='sm'>Loading API tokens...</Text>
        </HStack>
      ) : null}

      {!loading && tokens.length === 0 ? (
        <Box py={6} textAlign='center'>
          <Text fontSize='sm' fontWeight='semibold' color={titleColor}>
            No machine tokens yet.
          </Text>
          {canManage ? (
            <Text fontSize='sm' color={muted} mt={1}>
              Create one to let an external executor report certificate
              lifecycle events.
            </Text>
          ) : null}
        </Box>
      ) : null}

      {!loading && tokens.length > 0 ? (
        <Stack spacing={3} align='stretch'>
          {tokens.map(token => {
            const status = displayStatus(token);
            const canRevoke = status === 'active';
            return (
              <Box
                key={token.id}
                border='1px solid'
                borderColor={border}
                borderRadius='12px'
                bg={rowBg}
                p={{ base: 3.5, md: 4 }}
              >
                <HStack
                  justify='space-between'
                  align='start'
                  spacing={3}
                  flexWrap='wrap'
                  mb={2}
                >
                  <Box minW={0}>
                    <Text fontSize='sm' fontWeight='semibold' noOfLines={1}>
                      {token.name || 'Unnamed token'}
                    </Text>
                    <Code fontSize='xs' mt={1}>
                      {token.tokenPrefix || '--'}
                    </Code>
                  </Box>
                  <HStack spacing={2} flexShrink={0}>
                    <Badge
                      colorScheme={STATUS_SCHEME[status] || 'gray'}
                      variant='subtle'
                      textTransform='none'
                    >
                      {status}
                    </Badge>
                    {canManage && canRevoke ? (
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

                <HStack flexWrap='wrap' spacing={2} mb={3}>
                  {(Array.isArray(token.scopes) ? token.scopes : []).map(
                    scope => (
                      <Badge
                        key={`${token.id}-${scope}`}
                        variant='outline'
                        textTransform='none'
                        fontFamily='mono'
                        fontSize='xs'
                      >
                        {scopeShortLabel(scope)}
                      </Badge>
                    )
                  )}
                </HStack>

                <HStack
                  spacing={{ base: 3, md: 6 }}
                  flexWrap='wrap'
                  fontSize='sm'
                  color={muted}
                >
                  <Text>Created {formatDate(token.createdAt)}</Text>
                  <Text>
                    Last used{' '}
                    {token.lastUsedAt
                      ? formatDate(token.lastUsedAt)
                      : 'Never used'}
                  </Text>
                  <Text>
                    Expiry{' '}
                    {token.expiresAt
                      ? formatDate(token.expiresAt)
                      : 'No expiry'}
                  </Text>
                </HStack>
              </Box>
            );
          })}
        </Stack>
      ) : null}

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
          <ModalHeader>Store this token now</ModalHeader>
          <ModalBody>
            <VStack align='stretch' spacing={4}>
              <Alert status='warning' borderRadius='md' variant='left-accent'>
                <AlertIcon />
                <AlertDescription>
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
            </VStack>
          </ModalBody>
          <ModalFooter>
            <Button colorScheme='blue' onClick={handleShowOnceClose}>
              I stored the token
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
            Revoke API token
          </AlertDialogHeader>
          <AlertDialogBody>
            Revoking immediately breaks any executor using this token. This
            cannot be undone.
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
