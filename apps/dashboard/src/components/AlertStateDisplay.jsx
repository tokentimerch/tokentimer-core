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

export function formatAlertThreshold(threshold) {
  if (threshold === null || threshold === undefined) return null;
  if (threshold === 0) return 'Expiry day (0)';
  if (threshold < 0)
    return `${Math.abs(threshold)} days after expiry (${threshold})`;
  return `${threshold} days before expiry`;
}

export function formatExpiryDistance(days) {
  if (days === null || days === undefined) return 'Expiry unavailable';
  if (days === 0) return 'Expires today';
  if (days < 0) return `${Math.abs(days)} days since expiry`;
  return `${days} days until expiry`;
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

export function buildAlertAuditPath(tokenName, tokenId) {
  const query = tokenName || tokenId;
  return query ? `/audit?q=${encodeURIComponent(String(query))}` : '/audit';
}

export default function AlertStateDisplay({
  alertState,
  tokenName,
  tokenId,
  canViewAudit = false,
  ...boxProps
}) {
  const panelBg = useColorModeValue('gray.50', 'rgba(8, 13, 22, 0.58)');
  const border = useColorModeValue('gray.200', 'dashboard.modal.border');
  const muted = useColorModeValue('gray.600', 'dashboard.modal.muted');
  const text = useColorModeValue('gray.800', 'dashboard.modal.text');
  if (!alertState?.eligibility) return null;

  const { eligibility, delivery } = alertState;
  const latestAttemptAt =
    delivery?.latest_attempt?.attempted_at || delivery?.last_attempt_at;

  return (
    <Box
      role='region'
      aria-label='Alert eligibility and delivery'
      border='1px solid'
      borderColor={border}
      borderRadius='md'
      bg={panelBg}
      p={4}
      {...boxProps}
    >
      <Text color={text} fontSize='sm' fontWeight='semibold' mb={3}>
        Alerting
      </Text>
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
            {eligibilityExplanation(eligibility)}
          </Text>
          <Text color={muted} fontSize='xs'>
            {formatExpiryDistance(eligibility.days_until_expiry)}
          </Text>
          {eligibility.eligible_channels?.length > 0 ? (
            <Text color={muted} fontSize='xs'>
              Eligible channels: {eligibility.eligible_channels.join(', ')}
            </Text>
          ) : null}
          {eligibility.next_evaluation_at ? (
            <Text color={muted} fontSize='xs'>
              Next eligibility evaluation: {eligibility.next_evaluation_at}
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
          <Text color={text} fontSize='sm'>
            {deliveryExplanation(delivery)}
          </Text>
          {delivery?.created_at ? (
            <Text color={muted} fontSize='xs'>
              Latest alert: {formatDateTime(delivery.created_at)}
            </Text>
          ) : null}
          {latestAttemptAt ? (
            canViewAudit ? (
              <Link
                as={RouterLink}
                to={buildAlertAuditPath(tokenName, tokenId)}
                color='blue.400'
                fontSize='xs'
                fontWeight='semibold'
              >
                View latest attempt · {formatDateTime(latestAttemptAt)}
              </Link>
            ) : (
              <Text color={muted} fontSize='xs'>
                Latest attempt: {formatDateTime(latestAttemptAt)}
              </Text>
            )
          ) : null}
          {delivery?.next_attempt_at ? (
            <Text color={muted} fontSize='xs'>
              Next delivery attempt: {formatDateTime(delivery.next_attempt_at)}
            </Text>
          ) : null}
          {delivery?.error_message ? (
            <Text color={muted} fontSize='xs' wordBreak='break-word'>
              {delivery.error_message}
            </Text>
          ) : null}
        </VStack>
      </SimpleGrid>
    </Box>
  );
}

function buildDashboardAssetPath(tokenId, workspaceId) {
  const params = new URLSearchParams();
  if (workspaceId) params.set('workspace', workspaceId);
  params.set('token-id', String(tokenId));
  return `/dashboard?${params.toString()}`;
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
                tokenName={token.name}
                tokenId={token.id}
                canViewAudit
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
              <Th>Why</Th>
              <Th>Threshold / expiry</Th>
              <Th>Delivery</Th>
              <Th>Next</Th>
            </Tr>
          </Thead>
          <Tbody>
            {records.map(token => {
              const { eligibility, delivery } = token.alert_state;
              const latestAttemptAt =
                delivery?.latest_attempt?.attempted_at ||
                delivery?.last_attempt_at;
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
                  <Td minW='260px'>
                    <Text fontSize='sm'>
                      {eligibilityExplanation(eligibility)}
                    </Text>
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
                    <Text color={muted} fontSize='xs' mt={1}>
                      {deliveryExplanation(delivery)}
                    </Text>
                    {latestAttemptAt ? (
                      <Link
                        as={RouterLink}
                        to={buildAlertAuditPath(token.name, token.id)}
                        color='blue.400'
                        fontSize='xs'
                        fontWeight='semibold'
                      >
                        View latest attempt
                      </Link>
                    ) : null}
                  </Td>
                  <Td minW='190px'>
                    {eligibility.next_evaluation_at ? (
                      <Text fontSize='xs'>
                        Eligibility: {eligibility.next_evaluation_at}
                      </Text>
                    ) : null}
                    {delivery?.next_attempt_at ? (
                      <Text fontSize='xs'>
                        Delivery: {formatDateTime(delivery.next_attempt_at)}
                      </Text>
                    ) : null}
                    {!eligibility.next_evaluation_at &&
                    !delivery?.next_attempt_at ? (
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
