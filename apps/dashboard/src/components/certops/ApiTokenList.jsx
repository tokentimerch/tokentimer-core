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
} from '@chakra-ui/react';
import DashboardPagination from '../DashboardPagination.jsx';
import { DashboardErrorAlert } from '../DashboardPrimitives.jsx';
import { useDashboardThemeColors } from '../../hooks/useDashboardTheme';
import {
  CERTOPS_PAGE_SIZE_OPTIONS,
  useCertOpsListUrlState,
} from '../../hooks/useCertOpsUrlState.js';
import { useWorkspace } from '../../utils/WorkspaceContext.jsx';
import { showError, showSuccess } from '../../utils/toast.js';
import { revokeApiToken } from './certopsTokensApi.js';
import { certOpsScopeShortLabel } from './certopsTokenScopeMeta.js';
import { formatDate } from './certopsFormat';
import { useCertOpsCanManage } from './useCertOps.js';
import { useCertOpsApiTokens } from './useCertOpsJobs.js';

const STATUS_SCHEME = {
  active: 'green',
  revoked: 'red',
  expired: 'orange',
};

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
 * Machine API-token inventory, inline on the Settings tab: ongoing
 * credential state, unlike the one-time create flow in ApiTokenModal, so it
 * stays on the page rather than behind a modal (same split as
 * BootstrapTokenList / DeployAgentModal on the Agents tab). Paginated
 * server-side: a credential inventory silently truncated is a
 * security-relevant wrong answer, so a limit is always sent.
 */
export default function ApiTokenList() {
  const { workspaceId } = useWorkspace();
  const canManage = useCertOpsCanManage();
  const { limit, offset, setPage } = useCertOpsListUrlState({
    scope: 'token',
  });
  const { enabled, tokens, pagination, loading, error, refresh } =
    useCertOpsApiTokens({ limit, offset });

  const [revokeTarget, setRevokeTarget] = useState(null);
  const [revoking, setRevoking] = useState(false);
  const revokeCancelRef = useRef(null);

  const { muted, border, dashboard } = useDashboardThemeColors();
  const rowBg = dashboard.bg.nested;
  const titleColor = dashboard.text.primary;

  if (enabled !== true) return null;

  const firstPage = () => setPage({ offset: 0 });
  const pageIsPastEnd = Boolean(
    pagination && pagination.total > 0 && offset >= pagination.total
  );

  const handleRevoke = async () => {
    if (!revokeTarget?.id || !workspaceId) return;
    setRevoking(true);
    try {
      await revokeApiToken(workspaceId, revokeTarget.id);
      showSuccess('API token revoked');
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
        Machine API tokens
      </Text>

      {error ? <DashboardErrorAlert>{error}</DashboardErrorAlert> : null}

      {loading ? (
        <HStack spacing={2} color={muted} py={3} justify='center'>
          <Spinner size='sm' />
          <Text fontSize='sm'>Loading API tokens...</Text>
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
            <>
              <Text fontSize='sm' fontWeight='semibold' color={titleColor}>
                No machine tokens yet.
              </Text>
              {canManage ? (
                <Text fontSize='sm' color={muted} mt={1}>
                  Create one to let an external executor report certificate
                  lifecycle events, or a cert-manager controller drive
                  provisioning.
                </Text>
              ) : null}
            </>
          )}
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
                        {certOpsScopeShortLabel(scope)}
                      </Badge>
                    )
                  )}
                  {token.controllerClusterId ? (
                    <Badge
                      variant='solid'
                      colorScheme='purple'
                      textTransform='none'
                      fontFamily='mono'
                      fontSize='xs'
                      title='This token is bound to a single cert-manager controller cluster.'
                    >
                      cluster: {token.controllerClusterId}
                    </Badge>
                  ) : null}
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

      {!loading && pagination ? (
        <Box mt={1}>
          <DashboardPagination
            limit={pagination.limit || limit}
            offset={offset}
            total={pagination.total}
            pageSizeOptions={CERTOPS_PAGE_SIZE_OPTIONS}
            noun='API tokens'
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
            Revoke API token
          </AlertDialogHeader>
          <AlertDialogBody>
            <Alert
              status='warning'
              borderRadius='md'
              variant='left-accent'
              mb={3}
            >
              Revoking immediately breaks any executor using this token. This
              cannot be undone.
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
