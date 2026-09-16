import {
  Badge,
  Box,
  HStack,
  Link,
  SimpleGrid,
  Table,
  Tbody,
  Td,
  Text,
  Th,
  Thead,
  Tr,
  VStack,
  useColorModeValue,
} from '@chakra-ui/react';
import { Link as RouterLink } from 'react-router';

const ELIGIBILITY_META = {
  outside_threshold: { label: 'Outside threshold', scheme: 'gray' },
  due: { label: 'Due', scheme: 'orange' },
  suppressed: { label: 'Suppressed', scheme: 'purple' },
};

const DELIVERY_META = {
  pending: { label: 'Queued / pending', scheme: 'yellow' },
  sent: { label: 'Sent', scheme: 'green' },
  sent_unverified: { label: 'Delivery unverified', scheme: 'gray' },
  discarded: { label: 'Discarded', scheme: 'gray' },
  failed: { label: 'Failed', scheme: 'red' },
  blocked: { label: 'Blocked', scheme: 'orange' },
  limit_exceeded: { label: 'Limit exceeded', scheme: 'orange' },
  partial: { label: 'Partially delivered', scheme: 'orange' },
};

function formatDateTime(value) {
  if (!value) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString();
}

function formatDateOnly(value) {
  if (!value) return null;
  if (/^\d{4}-\d{2}-\d{2}$/.test(String(value))) {
    const [year, month, day] = String(value).split('-').map(Number);
    const date = new Date(year, month - 1, day);
    if (Number.isNaN(date.getTime())) return String(value);
    return date.toLocaleDateString();
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleDateString();
}

export function formatAlertThreshold(threshold) {
  if (threshold === null || threshold === undefined) return null;
  if (threshold === 0) return 'Expiry day';
  if (threshold < 0)
    return `${Math.abs(threshold)} days after expiry`;
  return `${threshold} days before expiry`;
}

export function formatExpiryDistance(days) {
  if (days === null || days === undefined) return 'Expiry unavailable';
  if (days === 0) return 'Expires today';
  if (days < 0) return `Expired ${Math.abs(days)} days ago`;
  if (days === 1) return 'Expires in: 1 day';
  return `Expires in: ${days} days`;
}

export function formatChannelLabel(channel) {
  if (!channel) return null;
  if (channel === 'webhooks') return 'Webhook';
  if (channel === 'whatsapp') return 'WhatsApp';
  if (channel === 'email') return 'Email';
  return String(channel).charAt(0).toUpperCase() + String(channel).slice(1);
}

export function formatChannelsList(channels) {
  if (!Array.isArray(channels) || channels.length === 0) return null;
  return channels
    .map(channel => {
      if (channel === 'webhooks') return 'Webhooks';
      return formatChannelLabel(channel);
    })
    .filter(Boolean)
    .join(', ');
}

function addDaysToDateOnly(expirationDate, thresholdDays) {
  if (!expirationDate || !/^\d{4}-\d{2}-\d{2}$/.test(String(expirationDate))) {
    return null;
  }
  if (!Number.isFinite(thresholdDays)) return null;
  const [year, month, day] = String(expirationDate).split('-').map(Number);
  const date = new Date(Date.UTC(year, month - 1, day));
  date.setUTCDate(date.getUTCDate() - thresholdDays);
  return date.toISOString().slice(0, 10);
}

/** Upcoming thresholds not yet reached, chronological (nearest first). */
export function getUpcomingThresholds(eligibility) {
  if (!eligibility) return [];
  const thresholds = Array.isArray(eligibility.effective_thresholds)
    ? eligibility.effective_thresholds
    : [];
  const days = eligibility.days_until_expiry;
  const expiration = eligibility.metadata?.expiration_date;

  if (Number.isFinite(days) && thresholds.length > 0) {
    return thresholds
      .filter(threshold => Number.isFinite(threshold) && days > threshold)
      .sort((a, b) => b - a)
      .map(threshold => ({
        threshold,
        at:
          addDaysToDateOnly(expiration, threshold) ||
          (eligibility.next_threshold === threshold
            ? eligibility.next_evaluation_at
            : null),
      }));
  }

  if (
    eligibility.next_threshold !== null &&
    eligibility.next_threshold !== undefined
  ) {
    return [
      {
        threshold: eligibility.next_threshold,
        at: eligibility.next_evaluation_at || null,
      },
    ];
  }
  return [];
}

export function eligibilityExplanation(eligibility) {
  if (!eligibility) return 'Eligibility is unavailable.';
  const threshold = formatAlertThreshold(eligibility.effective_threshold);
  switch (eligibility.reason) {
    case 'threshold_reached':
      return `${threshold || 'The effective threshold'} has been reached.`;
    case 'threshold_not_reached':
      return eligibility.next_threshold !== null &&
        eligibility.next_threshold !== undefined
        ? `The next effective threshold is ${formatAlertThreshold(eligibility.next_threshold)}.`
        : 'No effective threshold has been reached.';
    case 'post_expiry_threshold_not_configured':
      return eligibility.metadata?.expired_at_import
        ? 'This asset was already expired when imported, and no post-expiry threshold is configured.'
        : 'The asset is expired, and no post-expiry threshold is configured.';
    case 'stale_import_threshold':
      return `Imported after the ${threshold || 'effective'} threshold; stale catch-up is suppressed.`;
    case 'retired_certificate':
      return 'Expiry alerts are suppressed for retired certificates.';
    case 'no_eligible_channels':
      return 'The threshold is reached, but the selected contact group has no eligible recipients or channels.';
    case 'invalid_expiration':
      return 'No valid expiration date is available for evaluation.';
    default:
      return 'Eligibility could not be explained.';
  }
}

export function deliveryExplanation(delivery) {
  if (!delivery) return 'No alert has been generated for this asset.';
  switch (delivery.reason) {
    case 'retired_certificate':
      return 'The alert was discarded because the certificate is retired.';
    case 'endpoint_recovered':
      return 'The alert was discarded because the endpoint recovered.';
    case 'alert_discarded':
      return 'The alert was discarded without delivery.';
    case 'delivery_unverified':
      return 'The queue row is closed, but there is no recorded successful delivery.';
    case 'delivery_window':
      return 'Delivery is deferred until the configured delivery window opens.';
    case 'monthly_plan_limit':
      return 'Delivery is blocked by the monthly or plan limit.';
    case 'max_attempts':
      return 'Delivery is blocked after the maximum retry attempts.';
    case 'retry_scheduled':
      return 'Another delivery attempt is scheduled.';
    default:
      if (delivery.status === 'pending')
        return 'The alert is queued for delivery.';
      if (delivery.status === 'sent') return 'The alert was delivered.';
      if (delivery.status === 'failed') return 'The latest delivery failed.';
      if (delivery.status === 'partial')
        return 'Some delivery channels succeeded.';
      if (delivery.status === 'blocked') return 'Delivery is blocked.';
      return 'Delivery information is available.';
  }
}

export function AlertEligibilityBadge({ status }) {
  const meta = ELIGIBILITY_META[status] || ELIGIBILITY_META.outside_threshold;
  return (
    <Badge colorScheme={meta.scheme} textTransform='none' whiteSpace='nowrap'>
      {meta.label}
    </Badge>
  );
}

export function AlertDeliveryBadge({ status }) {
  if (!status) {
    return (
      <Badge colorScheme='gray' textTransform='none' whiteSpace='nowrap'>
        No alert
      </Badge>
    );
  }
  const meta = DELIVERY_META[status] || {
    label: String(status).replaceAll('_', ' '),
    scheme: 'gray',
  };
  return (
    <Badge colorScheme={meta.scheme} textTransform='none' whiteSpace='nowrap'>
      {meta.label}
    </Badge>
  );
}

function buildDashboardAssetPath(tokenId, workspaceId) {
  const params = new URLSearchParams();
  if (workspaceId) params.set('workspace', workspaceId);
  params.set('token-id', String(tokenId));
  return `/dashboard?${params.toString()}`;
}

export function buildAlertLifecycleEventPath({
  tokenId,
  attemptId,
  workspaceId,
} = {}) {
  if (tokenId === null || tokenId === undefined) return '/dashboard';
  if (attemptId === null || attemptId === undefined) {
    return buildDashboardAssetPath(tokenId, workspaceId);
  }
  const params = new URLSearchParams();
  if (workspaceId) params.set('workspace', workspaceId);
  params.set('token-id', String(tokenId));
  params.set('alert-event', `delivery:${attemptId}`);
  return `/dashboard?${params.toString()}`;
}

/** @deprecated Prefer buildAlertLifecycleEventPath for delivery attempts. */
export function buildAlertAuditPath(tokenName, tokenId) {
  const query = tokenName || tokenId;
  return query ? `/audit?q=${encodeURIComponent(String(query))}` : '/audit';
}

export function AlertUpcomingSection({ alertState, ...boxProps }) {
  const muted = useColorModeValue('gray.600', 'dashboard.modal.muted');
  const text = useColorModeValue('gray.800', 'dashboard.modal.text');
  const border = useColorModeValue('gray.200', 'dashboard.modal.border');
  const eligibility = alertState?.eligibility;
  const delivery = alertState?.delivery;
  const upcoming = getUpcomingThresholds(eligibility);
  const nextAttempt = delivery?.next_attempt_at || null;

  if (!eligibility && !nextAttempt) return null;

  const primary = upcoming[0] || null;
  const secondary = upcoming[1] || null;

  return (
    <Box
      role='region'
      aria-label='Upcoming alerts'
      borderTop='1px solid'
      borderColor={border}
      pt={4}
      mt={4}
      {...boxProps}
    >
      <Text fontSize='xs' fontWeight='semibold' color={muted} mb={2}>
        Upcoming
      </Text>
      <VStack align='stretch' spacing={1}>
        {primary ? (
          <Text fontSize='sm' color={text}>
            Next threshold: {formatAlertThreshold(primary.threshold)}
            {primary.at ? ` · ${formatDateOnly(primary.at)}` : ''}
          </Text>
        ) : (
          <Text fontSize='sm' color={muted}>
            No further thresholds configured
          </Text>
        )}
        {secondary ? (
          <Text fontSize='sm' color={muted}>
            Then: {formatAlertThreshold(secondary.threshold)}
            {secondary.at ? ` · ${formatDateOnly(secondary.at)}` : ''}
          </Text>
        ) : null}
        {nextAttempt ? (
          <Text fontSize='sm' color={text}>
            Next delivery attempt: {formatDateTime(nextAttempt)}
          </Text>
        ) : null}
      </VStack>
    </Box>
  );
}

export default function AlertStateDisplay({
  alertState,
  showHeading = true,
  showUpcoming = false,
  compact = false,
  ...boxProps
}) {
  const panelBg = useColorModeValue('gray.50', 'rgba(8, 13, 22, 0.58)');
  const border = useColorModeValue('gray.200', 'dashboard.modal.border');
  const muted = useColorModeValue('gray.600', 'dashboard.modal.muted');
  const text = useColorModeValue('gray.800', 'dashboard.modal.text');
  if (!alertState?.eligibility) return null;

  const { eligibility, delivery } = alertState;
  const latestAttemptId = delivery?.latest_attempt?.id;
  const realAttempt = latestAttemptId ? delivery.latest_attempt : null;
  const lastDeliveryChannel = formatChannelLabel(realAttempt?.channel);
  const channels = formatChannelsList(eligibility.eligible_channels);
  const currentThreshold = formatAlertThreshold(eligibility.effective_threshold);
  const deliveryThreshold = formatAlertThreshold(delivery?.threshold_days);
  const thresholdsDiffer =
    deliveryThreshold != null &&
    currentThreshold != null &&
    Number(delivery.threshold_days) !== Number(eligibility.effective_threshold);
  let attemptLine = null;
  if (realAttempt) {
    attemptLine = (
      <Text color={muted} fontSize='xs'>
        Last delivery
        {lastDeliveryChannel ? `: ${lastDeliveryChannel}` : ''}
        {' · '}
        {formatDateTime(realAttempt.attempted_at)}
      </Text>
    );
  } else if (delivery?.last_attempt_at) {
    attemptLine = (
      <Text color={muted} fontSize='xs'>
        {delivery.status === 'discarded' ? 'Discarded' : 'Last queue attempt'}
        {' · '}
        {formatDateTime(delivery.last_attempt_at)}
      </Text>
    );
  } else if (!delivery) {
    attemptLine = (
      <Text color={muted} fontSize='xs'>
        No delivery yet
      </Text>
    );
  }

  return (
    <Box
      role='region'
      aria-label='Alert eligibility and delivery'
      border={compact ? 0 : '1px solid'}
      borderColor={border}
      borderRadius='md'
      bg={compact ? 'transparent' : panelBg}
      p={compact ? 0 : 4}
      {...boxProps}
    >
      {showHeading ? (
        <Text color={text} fontSize='sm' fontWeight='semibold' mb={3}>
          Current status
        </Text>
      ) : null}
      <SimpleGrid
        columns={{ base: 1, md: 2 }}
        spacing={4}
        position='relative'
        _before={{
          content: '""',
          display: { base: 'none', md: 'block' },
          position: 'absolute',
          top: 0,
          bottom: 0,
          left: '50%',
          width: '1px',
          bg: border,
          pointerEvents: 'none',
        }}
      >
        <VStack align='stretch' spacing={1.5} data-testid='alert-eligibility'>
          <HStack justify='space-between' align='start'>
            <Text color={muted} fontSize='xs' fontWeight='semibold'>
              Eligibility
            </Text>
            <AlertEligibilityBadge status={eligibility.status} />
          </HStack>
          <Text color={text} fontSize='sm'>
            {formatExpiryDistance(eligibility.days_until_expiry)}
          </Text>
          {currentThreshold ? (
            <Text color={muted} fontSize='xs'>
              Current threshold: {currentThreshold}
            </Text>
          ) : null}
          {channels ? (
            <Text color={muted} fontSize='xs'>
              Channels: {channels}
            </Text>
          ) : null}
        </VStack>

        <VStack
          align='stretch'
          spacing={1.5}
          data-testid='alert-delivery'
          borderTopWidth={{ base: '1px', md: 0 }}
          borderColor={border}
          pt={{ base: 4, md: 0 }}
          mt={{ base: 2, md: 0 }}
        >
          <HStack justify='space-between' align='start'>
            <Text color={muted} fontSize='xs' fontWeight='semibold'>
              Delivery
            </Text>
            <AlertDeliveryBadge status={delivery?.status} />
          </HStack>
          {thresholdsDiffer ? (
            <Text color={muted} fontSize='xs'>
              Previous alert: {deliveryThreshold}
            </Text>
          ) : null}
          {attemptLine}
          {realAttempt ? (
            <Text color='blue.400' fontSize='xs' fontWeight='semibold'>
              View in audit logs
            </Text>
          ) : null}
        </VStack>
      </SimpleGrid>
      {showUpcoming ? <AlertUpcomingSection alertState={alertState} /> : null}
    </Box>
  );
}

export function AlertEligibilityOverview({ tokens = [], workspaceId }) {
  const muted = useColorModeValue('gray.600', 'rgba(148, 163, 184, 0.92)');
  const records = tokens.filter(token => token.alert_state?.eligibility);

  if (records.length === 0) {
    return (
      <Text color={muted} fontSize='sm'>
        No assets are available for eligibility evaluation.
      </Text>
    );
  }

  return (
    <>
      <Box display={{ base: 'block', lg: 'none' }}>
        <VStack align='stretch' spacing={3}>
          {records.map(token => (
            <Box key={token.id}>
              <Link
                as={RouterLink}
                to={buildDashboardAssetPath(token.id, workspaceId)}
                fontSize='sm'
                fontWeight='semibold'
                color='blue.400'
                display='inline-block'
                mb={2}
              >
                {token.name || `Asset #${token.id}`}
              </Link>
              <AlertStateDisplay
                alertState={token.alert_state}
              />
            </Box>
          ))}
        </VStack>
      </Box>

      <Box overflowX='auto' display={{ base: 'none', lg: 'block' }}>
        <Table size='sm' variant='simple'>
          <Thead>
            <Tr>
              <Th>Asset</Th>
              <Th>Eligibility</Th>
              <Th>Threshold / expiry</Th>
              <Th>Delivery</Th>
              <Th>Next</Th>
            </Tr>
          </Thead>
          <Tbody>
            {records.map(token => {
              const { eligibility, delivery } = token.alert_state;
              const latestAttemptId = delivery?.latest_attempt?.id;
              const realAttempt = latestAttemptId
                ? delivery.latest_attempt
                : null;
              const upcoming = getUpcomingThresholds(eligibility);
              return (
                <Tr key={token.id}>
                  <Td>
                    <Link
                      as={RouterLink}
                      to={buildDashboardAssetPath(token.id, workspaceId)}
                      color='blue.400'
                      fontWeight='semibold'
                    >
                      {token.name || `Asset #${token.id}`}
                    </Link>
                  </Td>
                  <Td>
                    <AlertEligibilityBadge status={eligibility.status} />
                  </Td>
                  <Td minW='180px'>
                    <Text fontSize='sm'>
                      {formatAlertThreshold(eligibility.effective_threshold) ||
                        'Not reached'}
                    </Text>
                    <Text color={muted} fontSize='xs'>
                      {formatExpiryDistance(eligibility.days_until_expiry)}
                    </Text>
                  </Td>
                  <Td minW='180px'>
                    <AlertDeliveryBadge status={delivery?.status} />
                    {realAttempt ? (
                      <Link
                        as={RouterLink}
                        to={buildAlertLifecycleEventPath({
                          tokenId: token.id,
                          attemptId: latestAttemptId,
                          workspaceId,
                        })}
                        color='blue.400'
                        fontSize='xs'
                        fontWeight='semibold'
                        display='block'
                        mt={1}
                      >
                        View latest attempt
                      </Link>
                    ) : null}
                  </Td>
                  <Td minW='190px'>
                    {upcoming[0] ? (
                      <Text fontSize='xs'>
                        {formatAlertThreshold(upcoming[0].threshold)}
                        {upcoming[0].at
                          ? ` · ${formatDateOnly(upcoming[0].at)}`
                          : ''}
                      </Text>
                    ) : null}
                    {delivery?.next_attempt_at ? (
                      <Text fontSize='xs'>
                        Retry: {formatDateTime(delivery.next_attempt_at)}
                      </Text>
                    ) : null}
                    {!upcoming[0] && !delivery?.next_attempt_at ? (
                      <Text color={muted} fontSize='xs'>
                        -
                      </Text>
                    ) : null}
                  </Td>
                </Tr>
              );
            })}
          </Tbody>
        </Table>
      </Box>
    </>
  );
}
