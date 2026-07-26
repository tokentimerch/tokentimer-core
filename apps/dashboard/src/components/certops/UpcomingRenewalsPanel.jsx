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
 * scheduler going to do next, and is anything expiring with renewal switched
 * off. Certificates with automatic renewal disabled are listed here rather than
 * filtered out, because a switched-off certificate and an empty schedule look
 * identical from the outside and only one of them is safe.
 */

function renewalWindowLabel(renewsFrom) {
  if (!renewsFrom) return '--';
  const from = new Date(renewsFrom);
  if (Number.isNaN(from.getTime())) return '--';
  return from.getTime() <= Date.now()
    ? 'Due now'
    : `From ${formatDate(renewsFrom)}`;
}

export default function UpcomingRenewalsPanel({ refreshSignal }) {
  const { renewals, total, loading, error } =
    useCertOpsUpcomingRenewals(refreshSignal);

  const titleColor = useColorModeValue('gray.700', 'gray.200');
  const muted = useColorModeValue('gray.600', 'gray.400');

  const switchedOff = renewals.filter(item => !item.autoRenewEnabled);
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
        Active certificates with a renewal profile, soonest expiry first. The
        renewal window is the date the scheduler starts attempting a renewal,
        calculated from the expiry date minus the profile lead time.
      </Text>

      {error ? <DashboardErrorAlert>{error}</DashboardErrorAlert> : null}

      {!loading && !error && switchedOff.length > 0 ? (
        <Text fontSize='sm' color='orange.400' mb={3} fontWeight='medium'>
          {switchedOff.length === 1
            ? '1 certificate below will not renew automatically and will expire unless it is renewed by hand.'
            : `${switchedOff.length} certificates below will not renew automatically and will expire unless they are renewed by hand.`}
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
          for a refused or failed read. */}
      {!loading && !error && renewals.length === 0 ? (
        <Box py={6} textAlign='center'>
          <Text fontSize='sm' fontWeight='semibold' color={titleColor}>
            Nothing scheduled to renew.
          </Text>
          <Text fontSize='sm' color={muted} mt={1}>
            Certificates appear here once an agent issues one, which creates its
            renewal profile automatically.
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
                            label='Automatic renewal is switched off on this profile. This certificate will expire unless it is renewed manually.'
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
                              Off
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
