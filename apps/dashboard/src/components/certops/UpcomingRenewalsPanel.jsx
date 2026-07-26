import {
  Badge,
  Box,
  HStack,
  Spinner,
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
import { DashboardErrorAlert } from '../DashboardPrimitives.jsx';
import JobStatusBadge from './JobStatusBadge.jsx';
import { useCertOpsUpcomingRenewals } from './useCertOpsRenewals.js';
import { expiryDescriptor, formatDate } from './certopsFormat';
import { truncationSummary } from './certopsPagination';

/**
 * Upcoming automatic renewals (W8).
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
 */
function warningSentence(switchedOff, uncovered) {
  const parts = [];
  if (uncovered.length > 0) {
    parts.push(
      uncovered.length === 1
        ? '1 certificate cannot be renewed automatically because its renewal profile is missing or unusable'
        : `${uncovered.length} certificates cannot be renewed automatically because their renewal profiles are missing or unusable`
    );
  }
  if (switchedOff.length > 0) {
    parts.push(
      switchedOff.length === 1
        ? '1 certificate has automatic renewal switched off'
        : `${switchedOff.length} certificates have automatic renewal switched off`
    );
  }
  if (parts.length === 0) return '';
  return `${parts.join(', and ')}. Affected certificates will expire unless they are renewed by hand.`;
}

export default function UpcomingRenewalsPanel({ refreshSignal }) {
  const { renewals, total, loading, error } =
    useCertOpsUpcomingRenewals(refreshSignal);

  const titleColor = useColorModeValue('gray.700', 'gray.200');
  const muted = useColorModeValue('gray.600', 'gray.400');

  const switchedOff = renewals.filter(
    item => item.blockedReason === 'auto_renew_disabled'
  );
  const uncovered = renewals.filter(
    item => !item.autoRenewEnabled && item.blockedReason !== 'auto_renew_disabled'
  );
  const warning = warningSentence(switchedOff, uncovered);
  const summary = truncationSummary({
    shown: renewals.length,
    pagination: { total },
    noun: 'certificates',
  });

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
          <Text fontSize='sm' fontWeight='semibold' color={titleColor}>
            No renewable certificates.
          </Text>
          <Text fontSize='sm' color={muted} mt={1}>
            Certificates appear here once an agent issues or discovers one.
          </Text>
        </Box>
      ) : null}

      {!loading && renewals.length > 0 ? (
        <>
          <TableContainer>
            <Table size='sm' variant='simple'>
              <Thead>
                <Tr>
                  <Th>Certificate</Th>
                  <Th>Expires</Th>
                  <Th>Renewal window</Th>
                  <Th>Auto-renew</Th>
                  <Th>Last attempt</Th>
                </Tr>
              </Thead>
              <Tbody>
                {renewals.map(item => {
                  const expiry = expiryDescriptor(item.notAfter);
                  return (
                    <Tr key={item.certificateId}>
                      <Td>
                        <Text fontSize='sm' fontWeight='medium'>
                          {item.commonName || '--'}
                        </Text>
                        {item.profileName ? (
                          <Text fontSize='xs' color={muted}>
                            {item.profileName}
                          </Text>
                        ) : null}
                      </Td>
                      <Td>
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
                      <Td>
                        <Text fontSize='sm'>
                          {renewalWindowLabel(item.renewsFrom)}
                        </Text>
                        <Text fontSize='xs' color={muted}>
                          {item.renewBeforeDays} days before expiry
                        </Text>
                      </Td>
                      <Td>
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
                            label={blockedDescriptor(item.blockedReason).tooltip}
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
                      <Td>
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
          {summary ? (
            <Text fontSize='xs' color={muted} mt={2}>
              {summary}
            </Text>
          ) : null}
        </>
      ) : null}
    </Box>
  );
}
