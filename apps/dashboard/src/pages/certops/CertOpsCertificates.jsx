import { useEffect, useState } from 'react';
import {
  Badge,
  Box,
  Button,
  HStack,
  Select,
  Table,
  TableContainer,
  Tbody,
  Td,
  Text,
  Th,
  Thead,
  Tooltip,
  Tr,
  useColorModeValue,
} from '@chakra-ui/react';
import { Archive } from 'lucide-react';
import CopyableId from '../../components/CopyableId.jsx';
import RenewalBadge from '../../components/certops/RenewalBadge.jsx';
import KeyLocalityBadge from '../../components/certops/KeyLocalityBadge.jsx';
import RetireCertificateModal from '../../components/certops/RetireCertificateModal.jsx';
import SetupRenewalModal from '../../components/certops/SetupRenewalModal.jsx';
import DetachRenewalProfileModal from '../../components/certops/DetachRenewalProfileModal.jsx';
import CertificateTokenDetailModal from '../../components/certops/CertificateTokenDetailModal.jsx';
import {
  listCertificates,
  retireCertificate,
  retryRenewalSetupIntent,
} from '../../components/certops/certopsApi.js';
import {
  MANAGED_CERTIFICATE_SOURCES,
  MANAGED_CERTIFICATE_STATUSES,
  RENEWAL_SETUP_STATES,
  RENEWAL_STATES,
  expiryDescriptor,
  formatDate,
  isRetiredStatus,
  renewalSetupDescriptor,
  sourceLabel,
  statusLabel,
  statusScheme,
} from '../../components/certops/certopsFormat.js';
import { useCertOpsCanManage } from '../../components/certops/useCertOps.js';
import { useCertOpsCertificates } from '../../components/certops/useCertOpsCertificates.js';
import {
  DashboardActionButton,
  DashboardErrorAlert,
  DashboardPanel,
  DashboardPanelHeader,
  DashboardState,
} from '../../components/DashboardPrimitives';
import DashboardPagination from '../../components/DashboardPagination.jsx';
import {
  CERTOPS_CERTIFICATE_FILTERS,
  CERTOPS_PAGE_SIZE_OPTIONS,
  useCertOpsListUrlState,
} from '../../hooks/useCertOpsUrlState.js';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import { useWorkspace } from '../../utils/WorkspaceContext.jsx';
import { showError, showSuccess } from '../../utils/toast.js';

function certificateDisplayName(certificate) {
  if (certificate?.commonName) return certificate.commonName;
  const sans = Array.isArray(certificate?.subjectAltNames)
    ? certificate.subjectAltNames
    : [];
  if (sans.length > 0) return sans[0];
  return certificate?.sourceRef || certificate?.id || 'Unnamed certificate';
}

/**
 * Shows the state of an in-flight or resolved "Set up automatic renewal"
 * intent underneath the steady-state renewal badge. Renders nothing for the
 * ordinary `none` state, since most certificates have never had setup
 * attempted and a permanent placeholder badge would just be noise.
 */
function RenewalSetupStatus({ renewalSetup, onRetry, retrying, canManage }) {
  const descriptor = renewalSetupDescriptor(renewalSetup);
  if (!descriptor) return null;
  return (
    <HStack spacing={1} mt={1}>
      <Tooltip
        label={descriptor.message}
        hasArrow
        placement='top'
        openDelay={250}
      >
        <Badge
          colorScheme={descriptor.scheme}
          variant='subtle'
          textTransform='none'
          fontWeight='medium'
          fontSize='xs'
        >
          {descriptor.label}
        </Badge>
      </Tooltip>
      {canManage && descriptor.canRetry ? (
        <Button
          size='xs'
          variant='ghost'
          isLoading={retrying}
          onClick={onRetry}
        >
          Retry
        </Button>
      ) : null}
    </HStack>
  );
}

/**
 * Counts retired (revoked/decommissioned) certificates, independent of the
 * page the "Retired" toggle currently shows.
 *
 * The list route only takes one `excludeRetired` boolean, so this is the
 * difference of two lightweight (`limit: 1`) totals rather than a row scan:
 * every certificate matching the current source filter, minus the active
 * ones. Scoped to `source` only (not `status`), matching the toggle itself,
 * which stays orthogonal to a specific status pick.
 */
function useRetiredCertificateCount({ workspaceId, enabled, source, tick }) {
  const [count, setCount] = useState(null);

  useEffect(() => {
    if (!workspaceId || enabled !== true) {
      setCount(null);
      return undefined;
    }
    let cancelled = false;
    const controller = new AbortController();
    Promise.all([
      listCertificates(workspaceId, {
        limit: 1,
        offset: 0,
        source,
        excludeRetired: false,
        signal: controller.signal,
      }),
      listCertificates(workspaceId, {
        limit: 1,
        offset: 0,
        source,
        excludeRetired: true,
        signal: controller.signal,
      }),
    ])
      .then(([all, active]) => {
        if (cancelled) return;
        const allTotal = Number(all?.pagination?.total ?? 0);
        const activeTotal = Number(active?.pagination?.total ?? 0);
        setCount(Math.max(0, allTotal - activeTotal));
      })
      .catch(() => {
        // The count is a convenience on the toggle label, not something the
        // list depends on, so a failed fetch just leaves it unlabeled rather
        // than surfacing a second error alongside the list's own.
        if (!cancelled) setCount(null);
      });
    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [workspaceId, enabled, source, tick]);

  return count;
}

/**
 * Certificates tab: the managed certificate inventory for this workspace.
 *
 * Retired certificates (revoked/decommissioned) are hidden by default via
 * `excludeRetired`, the same convention the token inventory and the Control
 * Center summary use (see isRetiredStatus/RETIRE_STATUSES), so the daily view
 * is not dominated by dead certificates. The "Retired" toggle asks the server
 * for them explicitly rather than filtering a fetched page client-side, so
 * the total and pagination stay correct for whichever population is shown.
 */
export default function CertOpsCertificates() {
  const { muted } = useDashboardTheme();
  const rowHoverBg = useColorModeValue('gray.50', 'whiteAlpha.50');
  const canManage = useCertOpsCanManage();
  const { workspaceId } = useWorkspace();
  const {
    limit,
    offset,
    filters,
    setPage,
    setFilter,
    clearFilters,
    activeFilterLabels,
    hasActiveFilters,
  } = useCertOpsListUrlState({ filters: CERTOPS_CERTIFICATE_FILTERS });

  const showRetired = filters.showRetired === 'true';
  // An explicit status pick is more precise than the coarse retired toggle;
  // let it through even if that status happens to be revoked/decommissioned.
  const excludeRetired = !filters.status && !showRetired ? true : undefined;

  const { certificates, pagination, loading, error, refresh, enabled } =
    useCertOpsCertificates({
      limit,
      offset,
      status: filters.status || undefined,
      source: filters.source || undefined,
      excludeRetired,
    });

  const [retireTarget, setRetireTarget] = useState(null);
  const [setupTarget, setSetupTarget] = useState(null);
  const [detachTarget, setDetachTarget] = useState(null);
  const [detailsTarget, setDetailsTarget] = useState(null);
  const [retryingId, setRetryingId] = useState(null);
  const [retiredCountTick, setRetiredCountTick] = useState(0);

  const retiredCount = useRetiredCertificateCount({
    workspaceId,
    enabled,
    source: filters.source || undefined,
    tick: retiredCountTick,
  });

  const firstPage = () => setPage({ offset: 0 });
  const pageIsPastEnd = Boolean(
    pagination && pagination.total > 0 && offset >= pagination.total
  );

  const handleRetire = async ({ status, reason }) => {
    if (!retireTarget?.id || !workspaceId) return;
    try {
      await retireCertificate(workspaceId, retireTarget.id, {
        status,
        reason,
      });
      showSuccess(
        status === 'revoked'
          ? 'Certificate revoked'
          : 'Certificate decommissioned'
      );
      setRetireTarget(null);
      refresh();
      setRetiredCountTick(tick => tick + 1);
    } catch (err) {
      showError(
        'Retire failed',
        err?.response?.data?.error ||
          err?.message ||
          'Could not retire this certificate.'
      );
      throw err;
    }
  };

  const visibleFilterLabels = activeFilterLabels.filter(
    entry => entry.key !== 'showRetired'
  );

  const handleRetryRenewalSetup = async certificate => {
    const intentId = certificate?.renewalSetup?.intentId;
    if (!intentId || !workspaceId) return;
    setRetryingId(certificate.id);
    try {
      await retryRenewalSetupIntent(workspaceId, intentId);
      showSuccess('Automatic renewal setup retried');
      refresh();
    } catch (err) {
      showError(
        'Retry failed',
        err?.response?.data?.error ||
          err?.message ||
          'Could not retry automatic renewal setup.'
      );
    } finally {
      setRetryingId(null);
    }
  };

  return (
    <DashboardPanel>
      <DashboardPanelHeader
        title='Certificates'
        description='Managed certificate inventory for this workspace'
        action={
          <DashboardActionButton
            variant='outline'
            onClick={refresh}
            isLoading={loading}
          >
            Refresh
          </DashboardActionButton>
        }
      />

      <HStack spacing={2} mb={3} flexWrap='wrap'>
        <Select
          size='sm'
          maxW='200px'
          value={filters.status}
          onChange={event => setFilter('status', event.target.value)}
        >
          <option value=''>All statuses</option>
          {MANAGED_CERTIFICATE_STATUSES.map(value => (
            <option key={value} value={value}>
              {statusLabel(value)}
            </option>
          ))}
        </Select>
        <Select
          size='sm'
          maxW='200px'
          value={filters.source}
          onChange={event => setFilter('source', event.target.value)}
        >
          <option value=''>All sources</option>
          {MANAGED_CERTIFICATE_SOURCES.map(value => (
            <option key={value} value={value}>
              {sourceLabel(value)}
            </option>
          ))}
        </Select>
        <Button
          size='sm'
          variant={showRetired ? 'solid' : 'outline'}
          colorScheme='gray'
          leftIcon={<Archive size={14} />}
          onClick={() => setFilter('showRetired', showRetired ? '' : 'true')}
          aria-pressed={showRetired}
          title='Show revoked and decommissioned certificates'
        >
          Retired
          {retiredCount !== null ? (
            <Box
              as='span'
              ml={2}
              px={1.5}
              borderRadius='sm'
              bg={showRetired ? 'whiteAlpha.300' : 'blackAlpha.200'}
              fontSize='xs'
              fontWeight='semibold'
              lineHeight='1.5'
            >
              {retiredCount}
            </Box>
          ) : null}
        </Button>
      </HStack>

      {visibleFilterLabels.length > 0 ? (
        <HStack spacing={2} mb={2} flexWrap='wrap'>
          <Text fontSize='xs' color={muted}>
            Filtered by{' '}
            {visibleFilterLabels
              .map(entry => `${entry.label}: ${entry.value}`)
              .join(', ')}
          </Text>
          <Button size='xs' variant='ghost' onClick={clearFilters}>
            Clear filters
          </Button>
        </HStack>
      ) : null}

      {error ? <DashboardErrorAlert>{error}</DashboardErrorAlert> : null}

      {loading && certificates.length === 0 ? (
        <DashboardState
          type='loading'
          title='Loading managed certificates...'
        />
      ) : !loading && !error && certificates.length === 0 ? (
        pageIsPastEnd ? (
          <DashboardState
            title='This page is past the end of the list'
            description='The certificates this link pointed at have moved or aged out.'
            py={6}
            action={
              <Button size='xs' variant='ghost' onClick={firstPage}>
                Back to the first page
              </Button>
            }
          />
        ) : (
          <DashboardState
            title={
              hasActiveFilters
                ? 'No certificates match these filters'
                : 'No managed certificates yet'
            }
            description={
              hasActiveFilters
                ? 'Clear the filters above to see the rest of the inventory.'
                : 'Certificates appear here once TokenTimer discovers, imports, or issues one for this workspace.'
            }
            py={6}
          />
        )
      ) : (
        <Box>
          <TableContainer>
            <Table size='sm' variant='simple'>
              <Thead>
                <Tr>
                  <Th>Certificate</Th>
                  <Th>Status</Th>
                  <Th>Expiry</Th>
                  <Th>Renewal</Th>
                  <Th>Key locality</Th>
                  <Th>Source</Th>
                  <Th textAlign='right'>Actions</Th>
                </Tr>
              </Thead>
              <Tbody>
                {certificates.map(certificate => {
                  const expiry = expiryDescriptor(certificate.notAfter);
                  const sans = Array.isArray(certificate.subjectAltNames)
                    ? certificate.subjectAltNames
                    : [];
                  const extraSans = Math.max(0, sans.length - 1);
                  const retired = isRetiredStatus(certificate.status);
                  return (
                    <Tr key={certificate.id} _hover={{ bg: rowHoverBg }}>
                      <Td maxW='260px'>
                        <Text fontSize='sm' fontWeight='semibold' noOfLines={1}>
                          {certificateDisplayName(certificate)}
                        </Text>
                        <HStack spacing={2}>
                          <CopyableId
                            id={certificate.id}
                            display={`${String(certificate.id).slice(0, 12)}...`}
                          />
                          {extraSans > 0 ? (
                            <Badge
                              variant='outline'
                              textTransform='none'
                              fontSize='xs'
                            >
                              +{extraSans} SAN{extraSans === 1 ? '' : 's'}
                            </Badge>
                          ) : null}
                        </HStack>
                      </Td>
                      <Td>
                        <Badge
                          colorScheme={statusScheme(certificate.status)}
                          variant='subtle'
                          textTransform='none'
                          fontWeight='medium'
                        >
                          {statusLabel(certificate.status)}
                        </Badge>
                        {certificate.reconciliationReason ? (
                          <Tooltip
                            label={`Facts on this certificate may be stale: ${certificate.reconciliationReason}`}
                          >
                            <Badge
                              ml={2}
                              colorScheme='orange'
                              variant='outline'
                              textTransform='none'
                              fontSize='xs'
                            >
                              Unreconciled
                            </Badge>
                          </Tooltip>
                        ) : null}
                      </Td>
                      <Td>
                        <Box>
                          <Badge
                            colorScheme={expiry.scheme}
                            variant='subtle'
                            fontSize='xs'
                          >
                            {expiry.label}
                          </Badge>
                          <Text fontSize='xs' color={muted} mt={1}>
                            {formatDate(certificate.notAfter)}
                          </Text>
                        </Box>
                      </Td>
                      <Td>
                        <RenewalBadge renewal={certificate.renewal} />
                        <RenewalSetupStatus
                          renewalSetup={certificate.renewalSetup}
                          onRetry={() => handleRetryRenewalSetup(certificate)}
                          retrying={retryingId === certificate.id}
                          canManage={canManage}
                        />
                      </Td>
                      <Td>
                        <KeyLocalityBadge
                          keyMode={certificate.keyMode}
                          keyReference={certificate.keyReference}
                        />
                      </Td>
                      <Td>
                        <Text fontSize='sm'>
                          {sourceLabel(certificate.source)}
                        </Text>
                      </Td>
                      {canManage ? (
                        <Td textAlign='right'>
                          <HStack
                            spacing={1}
                            justify='flex-end'
                            flexWrap='wrap'
                          >
                            <Button
                              size='xs'
                              variant='ghost'
                              isDisabled={!certificate.tokenId}
                              title={
                                certificate.tokenId
                                  ? undefined
                                  : 'No linked token to show'
                              }
                              onClick={() => setDetailsTarget(certificate)}
                            >
                              Details
                            </Button>
                            {!retired ? (
                              <>
                                {certificate.renewal?.profileId ? (
                                  <Button
                                    size='xs'
                                    variant='outline'
                                    onClick={() => setDetachTarget(certificate)}
                                  >
                                    Detach
                                  </Button>
                                ) : certificate.renewal?.state ===
                                    RENEWAL_STATES.notConfigured &&
                                  certificate.renewalSetup?.state !==
                                    RENEWAL_SETUP_STATES.waiting ? (
                                  <Button
                                    size='xs'
                                    colorScheme='blue'
                                    variant='outline'
                                    onClick={() => setSetupTarget(certificate)}
                                  >
                                    Set up renewal
                                  </Button>
                                ) : null}
                                <Button
                                  size='xs'
                                  colorScheme='red'
                                  variant='outline'
                                  onClick={() => setRetireTarget(certificate)}
                                >
                                  Retire
                                </Button>
                              </>
                            ) : null}
                          </HStack>
                        </Td>
                      ) : (
                        <Td textAlign='right'>
                          <Button
                            size='xs'
                            variant='ghost'
                            isDisabled={!certificate.tokenId}
                            title={
                              certificate.tokenId
                                ? undefined
                                : 'No linked token to show'
                            }
                            onClick={() => setDetailsTarget(certificate)}
                          >
                            Details
                          </Button>
                        </Td>
                      )}
                    </Tr>
                  );
                })}
              </Tbody>
            </Table>
          </TableContainer>
          {pagination ? (
            <Box mt={2}>
              <DashboardPagination
                limit={pagination.limit || limit}
                offset={offset}
                total={pagination.total}
                pageSizeOptions={CERTOPS_PAGE_SIZE_OPTIONS}
                noun='certificates'
                onChange={setPage}
              />
            </Box>
          ) : null}
        </Box>
      )}

      <RetireCertificateModal
        isOpen={Boolean(retireTarget)}
        onClose={() => setRetireTarget(null)}
        token={null}
        certificate={retireTarget}
        onRetire={handleRetire}
      />

      <SetupRenewalModal
        isOpen={Boolean(setupTarget)}
        onClose={() => setSetupTarget(null)}
        workspaceId={workspaceId}
        certificate={setupTarget}
        onSetUp={() => {
          showSuccess(
            'Renewing now',
            'Automatic renewal will be configured once this renewal job succeeds.'
          );
          setSetupTarget(null);
          refresh();
        }}
      />

      <DetachRenewalProfileModal
        isOpen={Boolean(detachTarget)}
        onClose={() => setDetachTarget(null)}
        workspaceId={workspaceId}
        certificate={detachTarget}
        onDetached={() => {
          showSuccess('Renewal profile detached');
          setDetachTarget(null);
          refresh();
        }}
      />

      <CertificateTokenDetailModal
        isOpen={Boolean(detailsTarget)}
        onClose={() => setDetailsTarget(null)}
        workspaceId={workspaceId}
        tokenId={detailsTarget?.tokenId}
        canManage={canManage}
      />
    </DashboardPanel>
  );
}
