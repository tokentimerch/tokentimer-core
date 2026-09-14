import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Badge,
  Box,
  Button,
  Circle,
  HStack,
  Link,
  Spinner,
  Text,
  VStack,
  useColorModeValue,
} from '@chakra-ui/react';
import { Link as RouterLink } from 'react-router';
import {
  AlertTriangle,
  Ban,
  BellRing,
  CheckCircle2,
  Clock3,
  RotateCcw,
  Send,
  XCircle,
} from 'lucide-react';
import { tokenAPI } from '../utils/apiClient';

const EVENT_META = {
  threshold_reached: {
    label: 'Threshold reached',
    color: '#f59e0b',
    icon: Clock3,
  },
  alert_queued: { label: 'Alert queued', color: '#3b82f6', icon: BellRing },
  alert_not_queued: {
    label: 'Alert not queued',
    color: '#a855f7',
    icon: Ban,
  },
  delivery_deferred: {
    label: 'Delivery deferred',
    color: '#eab308',
    icon: Clock3,
  },
  delivery_attempted: {
    label: 'Delivery attempted',
    color: '#64748b',
    icon: Send,
  },
  delivery_failed: {
    label: 'Delivery failed',
    color: '#ef4444',
    icon: XCircle,
  },
  delivery_succeeded: {
    label: 'Alert sent',
    color: '#22c55e',
    icon: CheckCircle2,
  },
  delivery_partial: {
    label: 'Partially delivered',
    color: '#f97316',
    icon: AlertTriangle,
  },
  delivery_blocked: {
    label: 'Delivery blocked',
    color: '#ef4444',
    icon: Ban,
  },
  retry_scheduled: {
    label: 'Retry scheduled',
    color: '#6366f1',
    icon: Clock3,
  },
  alert_requeued: {
    label: 'Alert requeued',
    color: '#6366f1',
    icon: RotateCcw,
  },
};

const REASON_LABELS = {
  delivery_window: 'Delivery window',
  no_eligible_channels: 'No eligible recipients or channels',
  monthly_limit: 'Monthly or plan limit',
  max_attempts: 'Maximum retry attempts reached',
  permanent_channel_failure: 'Permanent channel failure',
  manual_retry: 'Manual retry',
  bulk_requeue: 'Bulk requeue',
  partial_delivery: 'Some channels failed',
};

function formatThreshold(threshold) {
  if (threshold === null || threshold === undefined) return null;
  if (threshold === 0) return 'Expiry-day threshold';
  if (threshold < 0) return `${Math.abs(threshold)}-day post-expiry threshold`;
  return `${threshold}-day threshold`;
}

function formatChannel(channel) {
  if (!channel) return null;
  if (channel === 'webhooks') return 'Webhook';
  if (channel === 'whatsapp') return 'WhatsApp';
  return channel.charAt(0).toUpperCase() + channel.slice(1);
}

export function formatAlertLifecycleEvent(event) {
  const meta = EVENT_META[event.type] || {
    label: String(event.type || 'Alert event').replaceAll('_', ' '),
    color: '#64748b',
    icon: BellRing,
  };
  const details = [
    formatChannel(event.channel),
    formatThreshold(event.threshold_days),
    REASON_LABELS[event.reason],
  ].filter(Boolean);
  return { ...meta, details };
}

export function formatAlertLifecycleTime(value, relative = false) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value || '');
  if (!relative) return date.toLocaleString();
  const diffSeconds = Math.max(
    0,
    Math.floor((Date.now() - date.getTime()) / 1000)
  );
  if (diffSeconds < 60) return 'Just now';
  const minutes = Math.floor(diffSeconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return days < 7 ? `${days}d ago` : date.toLocaleDateString();
}

export function buildAlertLifecycleAssetPath(tokenId, workspaceId) {
  if (tokenId === null || tokenId === undefined) return null;
  const params = new URLSearchParams();
  if (workspaceId) params.set('workspace', workspaceId);
  params.set('token-id', String(tokenId));
  return `/dashboard?${params.toString()}`;
}

export function AlertLifecycleEventRow({
  event,
  showAsset = false,
  workspaceId,
  relativeTime = false,
}) {
  const border = useColorModeValue('gray.200', 'dashboard.modal.border');
  const muted = useColorModeValue('gray.600', 'dashboard.modal.muted');
  const text = useColorModeValue('gray.800', 'dashboard.modal.text');
  const meta = formatAlertLifecycleEvent(event);
  const EventIcon = meta.icon;
  const assetPath = buildAlertLifecycleAssetPath(
    event.token_id,
    workspaceId || event.workspace_id
  );

  return (
    <HStack align='start' spacing={3} py={2.5} minW={0}>
      <Circle
        size='28px'
        bg={`${meta.color}20`}
        color={meta.color}
        flex='0 0 auto'
        mt={0.5}
      >
        <EventIcon size={14} aria-hidden='true' />
      </Circle>
      <Box
        minW={0}
        flex='1'
        borderBottom='1px solid'
        borderColor={border}
        pb={2.5}
      >
        <HStack
          align='start'
          justify='space-between'
          spacing={2}
          flexWrap='wrap'
        >
          <Box minW={0}>
            {showAsset && event.token_name ? (
              assetPath ? (
                <Link
                  as={RouterLink}
                  to={assetPath}
                  color='blue.400'
                  fontSize='sm'
                  fontWeight='semibold'
                >
                  {event.token_name}
                </Link>
              ) : (
                <Text color={text} fontSize='sm' fontWeight='semibold'>
                  {event.token_name}
                </Text>
              )
            ) : null}
            <Text color={text} fontSize='sm' fontWeight='medium'>
              {meta.label}
            </Text>
          </Box>
          <Text
            color={muted}
            fontSize='xs'
            whiteSpace='nowrap'
            title={formatAlertLifecycleTime(event.occurred_at)}
          >
            {formatAlertLifecycleTime(event.occurred_at, relativeTime)}
          </Text>
        </HStack>
        {meta.details.length > 0 ? (
          <HStack mt={1} spacing={1.5} flexWrap='wrap'>
            {meta.details.map(detail => (
              <Badge
                key={detail}
                colorScheme='gray'
                variant='subtle'
                textTransform='none'
              >
                {detail}
              </Badge>
            ))}
          </HStack>
        ) : null}
        {event.error_message ? (
          <Text color={muted} fontSize='xs' mt={1} wordBreak='break-word'>
            {event.error_message}
          </Text>
        ) : null}
      </Box>
    </HStack>
  );
}

function UpcomingAlertActivity({ alertState }) {
  const muted = useColorModeValue('gray.600', 'dashboard.modal.muted');
  const upcoming = [
    alertState?.eligibility?.next_evaluation_at
      ? {
          label: 'Next eligibility evaluation',
          at: alertState.eligibility.next_evaluation_at,
        }
      : null,
    alertState?.delivery?.next_attempt_at
      ? {
          label: 'Next delivery attempt',
          at: alertState.delivery.next_attempt_at,
        }
      : null,
  ].filter(Boolean);
  if (upcoming.length === 0) return null;
  return (
    <Box
      mt={3}
      pt={3}
      borderTop='1px solid'
      borderColor='dashboard.modal.border'
    >
      <Text fontSize='xs' fontWeight='semibold' color={muted} mb={1}>
        Upcoming
      </Text>
      {upcoming.map(item => (
        <Text key={`${item.label}:${item.at}`} fontSize='xs' color={muted}>
          {item.label}: {formatAlertLifecycleTime(item.at)}
        </Text>
      ))}
    </Box>
  );
}

export default function AlertLifecycleTimeline({
  tokenId,
  alertState,
  enabled = true,
  pageSize = 20,
  ...boxProps
}) {
  const muted = useColorModeValue('gray.600', 'dashboard.modal.muted');
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState('');
  const [hasMore, setHasMore] = useState(false);
  const requestGenerationRef = useRef(0);
  const validTokenId = Number.isInteger(Number(tokenId)) && Number(tokenId) > 0;

  const loadPage = useCallback(
    async (offset = 0) => {
      const generation = ++requestGenerationRef.current;
      if (
        !enabled ||
        !validTokenId ||
        typeof tokenAPI.getAlertTimeline !== 'function'
      ) {
        setEvents([]);
        setHasMore(false);
        setLoading(false);
        setLoadingMore(false);
        return;
      }
      offset === 0 ? setLoading(true) : setLoadingMore(true);
      setError('');
      try {
        const page = await tokenAPI.getAlertTimeline(tokenId, pageSize, offset);
        if (generation !== requestGenerationRef.current) return;
        setEvents(current =>
          offset === 0 ? page.items || [] : [...current, ...(page.items || [])]
        );
        setHasMore(Boolean(page.pagination?.hasMore));
      } catch (loadError) {
        if (generation !== requestGenerationRef.current) return;
        setError(loadError?.message || 'Failed to load alert history');
      } finally {
        if (generation === requestGenerationRef.current) {
          setLoading(false);
          setLoadingMore(false);
        }
      }
    },
    [enabled, pageSize, tokenId, validTokenId]
  );

  useEffect(() => {
    setEvents([]);
    setHasMore(false);
    setError('');
    loadPage(0);
  }, [loadPage]);

  const chronologicalEvents = useMemo(() => [...events].reverse(), [events]);

  return (
    <Box role='region' aria-label='Alert history' minW={0} {...boxProps}>
      <Text fontSize='sm' fontWeight='semibold' mb={2}>
        Alert history
      </Text>
      {loading ? (
        <HStack spacing={2} py={2}>
          <Spinner size='xs' />
          <Text fontSize='sm' color={muted}>
            Loading alert history...
          </Text>
        </HStack>
      ) : error ? (
        <Text fontSize='sm' color='red.400' wordBreak='break-word'>
          {error}
        </Text>
      ) : chronologicalEvents.length === 0 ? (
        <Text fontSize='sm' color={muted}>
          No alert history recorded yet.
        </Text>
      ) : (
        <VStack align='stretch' spacing={0}>
          {chronologicalEvents.map(event => (
            <AlertLifecycleEventRow key={event.id} event={event} />
          ))}
        </VStack>
      )}
      {hasMore ? (
        <Button
          mt={2}
          size='xs'
          variant='outline'
          onClick={() => loadPage(events.length)}
          isLoading={loadingMore}
        >
          Load more
        </Button>
      ) : null}
      <UpcomingAlertActivity alertState={alertState} />
    </Box>
  );
}
