import { useMemo, useState } from 'react';
import {
  Badge,
  Box,
  Button,
  Flex,
  HStack,
  Spinner,
  Table,
  TableContainer,
  Tbody,
  Td,
  Text,
  Thead,
  Tooltip,
  Tr,
  useColorModeValue,
} from '@chakra-ui/react';
import { DashboardErrorAlert } from '../DashboardPrimitives.jsx';
import DashboardPagination from '../DashboardPagination.jsx';
import {
  CERTOPS_PAGE_SIZE_OPTIONS,
  useCertOpsListUrlState,
} from '../../hooks/useCertOpsUrlState.js';
import JobStatusBadge from './JobStatusBadge.jsx';
import {
  CertOpsMobileFieldLabel,
  CertOpsSortableHeader,
  nextCertOpsTableSort,
  sortCertOpsTableRows,
  useCertOpsResponsiveTableStyles,
} from './CertOpsResponsiveTable.jsx';
import { useCertOpsUpcomingRenewals } from './useCertOpsRenewals.js';
import { expiryDescriptor, formatDate } from './certopsFormat';

/**
 * Upcoming automatic renewals.
 *
 * Answers one question an operator could not previously ask: what is the
 * scheduler going to do next, and is anything expiring that it will not act on.
 * Certificates the scheduler will skip are listed here rather than filtered out,
 * because a skipped certificate and an empty schedule look identical from the
 * outside and only one of them is safe.
 *
 * The distinction between "switched off" and "not covered" is load-bearing. The
 * first is a decision the operator made and can undo from the panel below. The
 * second is a defect, usually an issuance whose renewal profile never got
 * derived, and no amount of toggling will fix it. Labelling both "Off" would
 * send an operator to the wrong control.
 */

const BLOCKED_REASONS = {
  auto_renew_disabled: {
    label: 'Off',
    tooltip:
      'Automatic renewal is switched off on this profile. This certificate will expire unless it is renewed manually.',
  },
  no_profile: {
    label: 'No profile',
    tooltip:
      'This certificate has no renewal profile, so the scheduler will never pick it up. Profiles are created automatically when an agent issues a certificate; a missing one means that step did not complete.',
  },
  incomplete_profile: {
    label: 'Incomplete',
    tooltip:
      'This certificate has a renewal profile the scheduler cannot execute, so no renewal job will ever be created from it. Re-issue the certificate to rebuild a working profile.',
  },
  not_agent_deployable: {
    label: 'No key access',
    tooltip:
      "No agent holds this certificate's private key, so no agent can renew it. This is typical of a certificate that was only observed from the outside, such as by an endpoint or domain monitor. Renewing it automatically requires issuing it through CertOps.",
  },
  unknown_expiry: {
    label: 'No expiry',
    tooltip:
      'This certificate has no recorded expiry date, so the scheduler cannot tell when it is due. It will never be renewed on schedule.',
  },
};

const BLOCKED_FALLBACK = {
  label: 'Not renewing',
  tooltip:
    'The scheduler will not renew this certificate automatically. It will expire unless it is renewed manually.',
};

const RENEWAL_COLUMNS = [
  ['certificate', 'Certificate'],
  ['expires', 'Expires'],
  ['renewalWindow', 'Renewal window'],
  ['autoRenew', 'Auto-renew'],
  ['lastAttempt', 'Last attempt'],
];

function renewalSortValue(item, key) {
  if (key === 'certificate') return item.commonName || '';
  if (key === 'expires') {
    const value = Date.parse(item.notAfter);
    return Number.isNaN(value) ? null : value;
  }
  if (key === 'renewalWindow') {
    const value = Date.parse(item.renewsFrom);
    return Number.isNaN(value) ? null : value;
  }
  if (key === 'autoRenew') return item.autoRenewEnabled ? 1 : 0;
  if (key === 'lastAttempt') return item.lastRenewJobStatus || '';
  return '';
}

function blockedDescriptor(reason) {
  return BLOCKED_REASONS[reason] || BLOCKED_FALLBACK;
}

function renewalWindowLabel(renewsFrom) {
  if (!renewsFrom) return '--';
  const from = new Date(renewsFrom);
  if (Number.isNaN(from.getTime())) return '--';
  return from.getTime() <= Date.now()
    ? 'Due now'
    : `From ${formatDate(renewsFrom)}`;
}

/**
 * One sentence naming what is wrong, so the operator does not have to hover
 * every badge to find out whether they are looking at a choice or a fault.
 *
 * The two groups are kept apart rather than totalled because they need
 * different responses, and the wording avoids naming a single cause: the
 * uncovered group can be a missing profile, an unusable one, absent key
 * custody, or an unknown expiry, and each badge names its own reason.
 *
 * The counts are of the rows on screen. When the schedule spans more than one
 * page the sentence says so, because a count that silently covers only part of
 * the list would understate the problem.
 */
function warningSentence(switchedOff, uncovered, paged = false) {
  const parts = [];
  const scope = paged ? ' on this page' : '';
  if (uncovered.length > 0) {
    parts.push(
      uncovered.length === 1
        ? `1 certificate${scope} will not be renewed automatically, for the reason shown against it`
        : `${uncovered.length} certificates${scope} will not be renewed automatically, for the reasons shown against them`
    );
  }
  if (switchedOff.length > 0) {
    parts.push(
      switchedOff.length === 1
        ? `1 certificate${scope} has automatic renewal switched off`
        : `${switchedOff.length} certificates${scope} have automatic renewal switched off`
    );
  }
  if (parts.length === 0) return '';
  return `${parts.join(', and ')}. Affected certificates will expire unless they are renewed by hand.`;
}

export default function UpcomingRenewalsPanel({ refreshSignal }) {
  const { limit, offset, setPage } = useCertOpsListUrlState({
    scope: 'schedule',
  });
  const { renewals, pagination, loading, error } = useCertOpsUpcomingRenewals(
    refreshSignal,
    { limit, offset }
  );

  const titleColor = useColorModeValue('gray.700', 'gray.200');
  const muted = useColorModeValue('gray.600', 'gray.400');
  const tableStyles = useCertOpsResponsiveTableStyles();
  const [sort, setSort] = useState({ key: null, direction: 'asc' });
  const sortedRenewals = useMemo(
    () => sortCertOpsTableRows(renewals, sort, renewalSortValue),
    [renewals, sort]
  );

  const switchedOff = renewals.filter(
    item => item.blockedReason === 'auto_renew_disabled'
  );
  const uncovered = renewals.filter(
    item =>
      !item.autoRenewEnabled && item.blockedReason !== 'auto_renew_disabled'
  );
  const paged = Boolean(pagination && pagination.total > renewals.length);
  const warning = warningSentence(switchedOff, uncovered, paged);
  const firstPage = () => setPage({ offset: 0 });
  const pageIsPastEnd = Boolean(
    pagination && pagination.total > 0 && offset >= pagination.total
  );

  return (
    <Box>
      <HStack justify='space-between' align='flex-start' mb={1} spacing={3}>
        <Text fontSize='md' fontWeight='bold' color={titleColor}>
          Upcoming renewals
        </Text>
        {loading ? <Spinner size='sm' /> : null}
      </HStack>
      <Text fontSize='sm' color={muted} mb={3}>
        Every certificate the renewal scheduler considers, soonest expiry first,
        including any it cannot act on. The renewal window is the date the
        scheduler starts attempting a renewal, calculated from the expiry date
        minus the profile lead time.
      </Text>

      {error ? <DashboardErrorAlert>{error}</DashboardErrorAlert> : null}

      {!loading && !error && warning ? (
        <Text fontSize='sm' color='orange.400' mb={3} fontWeight='medium'>
          {warning}
        </Text>
      ) : null}

      {loading ? (
        <HStack spacing={2} color={muted} py={4} justify='center'>
          <Spinner size='sm' />
          <Text fontSize='sm'>Loading renewal schedule...</Text>
        </HStack>
      ) : null}

      {/* Only claim the schedule is empty once a read actually succeeded.
          "Nothing scheduled" reads as "all clear", so it must never stand in
          for a refused or failed read. This list is no longer filtered on
          having a usable profile, so an empty table now genuinely means the
          workspace has no renewable certificates at all. */}
      {!loading && !error && renewals.length === 0 ? (
        <Box py={6} textAlign='center'>
          {pageIsPastEnd ? (
            <>
              <Text fontSize='sm' fontWeight='semibold' color={titleColor}>
                This page is past the end of the schedule.
              </Text>
              <Button size='xs' variant='ghost' mt={2} onClick={firstPage}>
                Back to the first page
              </Button>
            </>
          ) : (
            <>
              <Text fontSize='sm' fontWeight='semibold' color={titleColor}>
                No renewable certificates.
              </Text>
              <Text fontSize='sm' color={muted} mt={1}>
                Certificates appear here once an agent issues or discovers one.
              </Text>
            </>
          )}
        </Box>
      ) : null}

      {!loading && renewals.length > 0 ? (
        <>
          {pagination ? (
            <Flex justify='flex-end' mb={4}>
              <DashboardPagination
                limit={pagination.limit || limit}
                offset={offset}
                total={pagination.total}
                pageSizeOptions={CERTOPS_PAGE_SIZE_OPTIONS}
                noun='certificates'
                onChange={setPage}
              />
            </Flex>
          ) : null}
          <TableContainer {...tableStyles.tableContainerProps}>
            <Table {...tableStyles.tableProps}>
              <Thead {...tableStyles.theadProps}>
                <Tr>
                  {RENEWAL_COLUMNS.map(([key, label]) => (
                    <CertOpsSortableHeader
                      key={key}
                      label={label}
                      sortKey={key}
                      sort={sort}
                      onSort={sortKey =>
                        setSort(current =>
                          nextCertOpsTableSort(current, sortKey)
                        )
                      }
                    />
                  ))}
                </Tr>
              </Thead>
              <Tbody {...tableStyles.tbodyProps}>
                {sortedRenewals.map(item => {
                  const expiry = expiryDescriptor(item.notAfter);
                  return (
                    <Tr key={item.certificateId} {...tableStyles.rowProps}>
                      <Td {...tableStyles.primaryCellProps}>
                        <Text fontSize='sm' fontWeight='medium'>
                          {item.commonName || '--'}
                        </Text>
                        {item.profileName ? (
                          <Text fontSize='xs' color={muted}>
                            {item.profileName}
                          </Text>
                        ) : null}
                      </Td>
                      <Td {...tableStyles.cellProps}>
                        <CertOpsMobileFieldLabel color={muted}>
                          Expires
                        </CertOpsMobileFieldLabel>
                        <HStack spacing={2}>
                          <Text fontSize='sm'>{formatDate(item.notAfter)}</Text>
                          <Badge
                            colorScheme={expiry.scheme}
                            variant='subtle'
                            textTransform='none'
                            fontWeight='medium'
                            fontSize='xs'
                          >
                            {expiry.label}
                          </Badge>
                        </HStack>
                      </Td>
                      <Td {...tableStyles.cellProps}>
                        <CertOpsMobileFieldLabel color={muted}>
                          Renewal window
                        </CertOpsMobileFieldLabel>
                        <Text fontSize='sm'>
                          {renewalWindowLabel(item.renewsFrom)}
                        </Text>
                        <Text fontSize='xs' color={muted}>
                          {item.renewBeforeDays} days before expiry
                        </Text>
                      </Td>
                      <Td {...tableStyles.cellProps}>
                        <CertOpsMobileFieldLabel color={muted}>
                          Auto-renew
                        </CertOpsMobileFieldLabel>
                        {item.autoRenewEnabled ? (
                          <Badge
                            colorScheme='green'
                            variant='subtle'
                            textTransform='none'
                            fontWeight='medium'
                            fontSize='xs'
                          >
                            On
                          </Badge>
                        ) : (
                          <Tooltip
                            label={
                              blockedDescriptor(item.blockedReason).tooltip
                            }
                            hasArrow
                            placement='top'
                            openDelay={250}
                          >
                            <Badge
                              colorScheme='orange'
                              variant='solid'
                              textTransform='none'
                              fontWeight='medium'
                              fontSize='xs'
                            >
                              {blockedDescriptor(item.blockedReason).label}
                            </Badge>
                          </Tooltip>
                        )}
                      </Td>
                      <Td {...tableStyles.fullWidthCellProps}>
                        <CertOpsMobileFieldLabel color={muted}>
                          Last attempt
                        </CertOpsMobileFieldLabel>
                        {item.lastRenewJobStatus ? (
                          <JobStatusBadge status={item.lastRenewJobStatus} />
                        ) : (
                          <Text fontSize='xs' color={muted}>
                            Never renewed
                          </Text>
                        )}
                      </Td>
                    </Tr>
                  );
                })}
              </Tbody>
            </Table>
          </TableContainer>
        </>
      ) : null}
    </Box>
  );
}
