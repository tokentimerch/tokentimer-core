import { useRef, useState } from 'react';
import {
  Alert,
  AlertDialog,
  AlertDialogBody,
  AlertDialogContent,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogOverlay,
  Badge,
  Box,
  Button,
  Code,
  HStack,
  Spinner,
  Stack,
  Text,
  useColorModeValue,
} from '@chakra-ui/react';
import DashboardPagination from '../DashboardPagination.jsx';
import { DashboardErrorAlert } from '../DashboardPrimitives.jsx';
import {
  CERTOPS_PAGE_SIZE_OPTIONS,
  useCertOpsListUrlState,
} from '../../hooks/useCertOpsUrlState.js';
import { useWorkspace } from '../../utils/WorkspaceContext.jsx';
import { showError, showSuccess } from '../../utils/toast.js';
import { revokeBootstrapToken } from './certopsAgentsApi.js';
import { formatDate } from './certopsFormat';
import { useCertOpsCanManage } from './useCertOps.js';
import { useCertOpsBootstrapTokens } from './useCertOpsAgents.js';

const TOKEN_STATUS_SCHEME = {
  active: 'green',
  used: 'blue',
  revoked: 'red',
  expired: 'orange',
};

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
 * Bootstrap-token inventory, inline on the Agents tab (U4): ongoing
 * credential state, unlike the one-time install wizard in DeployAgentModal,
 * so it stays on the page rather than behind a modal. Paginated
 * server-side, same as the fleet table it sits next to.
 */
export default function BootstrapTokenList() {
  const { workspaceId } = useWorkspace();
  const canManage = useCertOpsCanManage();
  const { limit, offset, setPage } = useCertOpsListUrlState({
    scope: 'bootstrap',
  });
  const { enabled, tokens, pagination, loading, error, refresh } =
    useCertOpsBootstrapTokens({ limit, offset });

  const [revokeTarget, setRevokeTarget] = useState(null);
  const [revoking, setRevoking] = useState(false);
  const revokeCancelRef = useRef(null);

  const muted = useColorModeValue('gray.600', 'gray.400');
  const border = useColorModeValue('gray.200', 'gray.700');
  const rowBg = useColorModeValue('gray.50', 'gray.800');
  const titleColor = useColorModeValue('gray.700', 'gray.200');

  if (enabled !== true || !canManage) return null;

  const firstPage = () => setPage({ offset: 0 });
  const pageIsPastEnd = Boolean(
    pagination && pagination.total > 0 && offset >= pagination.total
  );

  const handleRevoke = async () => {
    if (!revokeTarget?.id || !workspaceId) return;
    setRevoking(true);
    try {
      await revokeBootstrapToken(workspaceId, revokeTarget.id);
      showSuccess('Bootstrap token revoked');
      setRevokeTarget(null);
      refresh();
    } catch (err) {
      showError('Revoke failed', revokeErrorMessage(err));
    } finally {
      setRevoking(false);
    }
  };

  return (
    <Stack spacing={3} align='stretch'>
      <Text fontSize='sm' fontWeight='semibold' color={titleColor}>
        Bootstrap tokens
      </Text>

      {error ? <DashboardErrorAlert>{error}</DashboardErrorAlert> : null}

      {loading ? (
        <HStack spacing={2} color={muted} py={3} justify='center'>
          <Spinner size='sm' />
          <Text fontSize='sm'>Loading bootstrap tokens...</Text>
        </HStack>
      ) : null}

      {!loading && !error && tokens.length === 0 ? (
        <Box py={4} textAlign='center'>
          {pageIsPastEnd ? (
            <>
              <Text fontSize='sm' fontWeight='semibold' color={titleColor}>
                This page is past the end of the list.
              </Text>
              <Button size='xs' variant='ghost' mt={2} onClick={firstPage}>
                Back to the first page
              </Button>
            </>
          ) : (
            <Text fontSize='sm' color={muted}>
              No bootstrap tokens yet. Used and expired tokens also show up
              here.
            </Text>
          )}
        </Box>
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
                    <Text fontSize='sm' fontWeight='semibold' noOfLines={1}>
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

      {!loading && pagination ? (
        <Box mt={1}>
          <DashboardPagination
            limit={pagination.limit || limit}
            offset={offset}
            total={pagination.total}
            pageSizeOptions={CERTOPS_PAGE_SIZE_OPTIONS}
            noun='bootstrap tokens'
            onChange={setPage}
          />
        </Box>
      ) : null}

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
            <Alert
              status='warning'
              borderRadius='md'
              variant='left-accent'
              mb={3}
            >
              A revoked token can no longer register an agent. Agents that
              already registered are unaffected. This cannot be undone.
            </Alert>
            {revokeTarget?.name ? (
              <Text fontSize='sm' color={muted}>
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
