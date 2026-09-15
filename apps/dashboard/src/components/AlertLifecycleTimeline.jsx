import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Badge,
  Box,
  Button,
  Circle,
  Collapse,
  HStack,
  Icon,
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
  ChevronDown,
  ChevronRight,
  RotateCcw,
  Send,
  XCircle,
} from 'lucide-react';
import { tokenAPI } from '../utils/apiClient';
import {
  AlertUpcomingSection,
  formatChannelLabel,
} from './AlertStateDisplay.jsx';

const EVENT_META = {
  threshold_reached: {
    label: 'Threshold reached',
    color: '#f59e0b',
    icon: Clock3,
  },
  alert_queued: { label: 'Alert queued', color: '#3b82f6', icon: BellRing },
  alert_discarded: {
    label: 'Alert discarded',
    color: '#64748b',
    icon: Ban,
  },
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
  endpoint_health: 'Endpoint health',
  certificate_renewal_failure: 'Certificate renewal failure',
  agent_health: 'Agent health',
  endpoint_recovered: 'Endpoint recovered',
  retired_certificate: 'Retired certificate',
};

export function formatThresholdGroupLabel(threshold) {
  if (threshold === null || threshold === undefined) return 'Other activity';
  if (threshold === 0) return 'Expiry-day threshold';
  if (threshold < 0) return `${Math.abs(threshold)}-day post-expiry threshold`;
  return `${threshold}-day threshold`;
}

function formatThresholdBadge(threshold) {
  if (threshold === null || threshold === undefined) return null;
  if (threshold === 0) return 'Expiry day';
  if (threshold < 0) return `${Math.abs(threshold)}-day post-expiry`;
  return `${threshold}-day threshold`;
}

function formatChannel(channel) {
  return formatChannelLabel(channel);
}

export function formatAlertLifecycleEvent(event, { includeThreshold = true } = {}) {
  const meta = EVENT_META[event.type] || {
    label: String(event.type || 'Alert event').replaceAll('_', ' '),
    color: '#64748b',
    icon: BellRing,
  };
  const details = [
    formatChannel(event.channel),
    includeThreshold ? formatThresholdBadge(event.threshold_days) : null,
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

export function formatAlertLifecycleEventTime(event) {
  if (!event?.occurred_at) return '';
  if (event.type === 'threshold_reached') {
    const date = new Date(event.occurred_at);
    if (Number.isNaN(date.getTime())) return String(event.occurred_at);
    return date.toLocaleDateString();
  }
  return formatAlertLifecycleTime(event.occurred_at);
}

export function buildAlertLifecycleAssetPath(tokenId, workspaceId) {
  if (tokenId === null || tokenId === undefined) return null;
  const params = new URLSearchParams();
  if (workspaceId) params.set('workspace', workspaceId);
  params.set('token-id', String(tokenId));
  return `/dashboard?${params.toString()}`;
}

export function groupAlertLifecycleEvents(events) {
  const groups = new Map();
  for (const event of events) {
    const key =
      event.threshold_days === null || event.threshold_days === undefined
        ? 'none'
        : String(event.threshold_days);
    if (!groups.has(key)) {
      groups.set(key, {
        threshold_days:
          key === 'none' ? null : Number.parseInt(key, 10),
        events: [],
      });
    }
    groups.get(key).events.push(event);
  }

  const sorted = [...groups.values()].sort((a, b) => {
    if (a.threshold_days === null) return 1;
    if (b.threshold_days === null) return -1;
    return b.threshold_days - a.threshold_days;
  });

  for (const group of sorted) {
    group.events.sort(
      (a, b) => new Date(a.occurred_at) - new Date(b.occurred_at)
    );
    const reached = group.events.find(item => item.type === 'threshold_reached');
    group.reached_at = reached?.occurred_at || null;
    // Threshold groups already show the crossing in the header; omit the
    // duplicate threshold_reached child row. Keep all events for "Other".
    if (group.threshold_days !== null) {
      group.events = group.events.filter(
        item => item.type !== 'threshold_reached'
      );
    }
  }
  return sorted;
}

function eventSpecificBadges(event) {
  return [REASON_LABELS[event.reason]].filter(Boolean);
}

function eventExpansionDetails(event) {
  const details = [];
  if (event.error_message) {
    details.push({ label: 'Detail', value: event.error_message });
  }
  return details;
}

export function AlertLifecycleEventRow({
  event,
  showAsset = false,
  workspaceId,
  relativeTime = false,
  showTime = true,
  focused = false,
  includeThresholdBadge = true,
}) {
  const border = useColorModeValue('gray.200', 'dashboard.modal.border');
  const muted = useColorModeValue('gray.600', 'dashboard.modal.muted');
  const text = useColorModeValue('gray.800', 'dashboard.modal.text');
  const focusBg = useColorModeValue('blue.50', 'rgba(59, 130, 246, 0.12)');
  const meta = formatAlertLifecycleEvent(event, {
    includeThreshold: includeThresholdBadge,
  });
  const EventIcon = meta.icon;
  const assetPath = buildAlertLifecycleAssetPath(
    event.token_id,
    workspaceId || event.workspace_id
  );
  const timeLabel = relativeTime
    ? formatAlertLifecycleTime(event.occurred_at, true)
    : formatAlertLifecycleEventTime(event);
  const channel = formatChannel(event.channel);

  return (
    <HStack
      align='start'
      spacing={3}
      py={2.5}
      minW={0}
      data-alert-event-id={event.id}
      bg={focused ? focusBg : undefined}
      borderRadius={focused ? 'md' : undefined}
      px={focused ? 2 : undefined}
    >
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
              {[
                meta.label,
                channel,
                !relativeTime && showTime ? timeLabel : null,
              ]
                .filter(Boolean)
                .join(' · ')}
            </Text>
          </Box>
          {showTime && relativeTime ? (
            <Text
              color={muted}
              fontSize='xs'
              whiteSpace='nowrap'
              title={formatAlertLifecycleTime(event.occurred_at)}
            >
              {timeLabel}
            </Text>
          ) : null}
        </HStack>
        {event.error_message ? (
          <Text color={muted} fontSize='xs' mt={1} wordBreak='break-word'>
            {event.error_message}
          </Text>
        ) : null}
      </Box>
    </HStack>
  );
}

function AlertLifecycleExpandableRow({
  event,
  focused = false,
  defaultExpanded = false,
}) {
  const [expanded, setExpanded] = useState(defaultExpanded || focused);
  const muted = useColorModeValue('gray.600', 'dashboard.modal.muted');
  const text = useColorModeValue('gray.800', 'dashboard.modal.text');
  const hoverBg = useColorModeValue('gray.100', 'dashboard.table.rowHover');
  const focusBg = useColorModeValue('blue.50', 'rgba(59, 130, 246, 0.12)');
  const meta = formatAlertLifecycleEvent(event, { includeThreshold: false });
  const rowRef = useRef(null);
  const channel = formatChannel(event.channel);
  const timeLabel = formatAlertLifecycleEventTime(event);
  const expansion = eventExpansionDetails(event);
  const badges = eventSpecificBadges(event);
  const hasDetails = expansion.length > 0 || badges.length > 0;

  useEffect(() => {
    if (focused || defaultExpanded) setExpanded(true);
  }, [focused, defaultExpanded]);

  useEffect(() => {
    if (!focused || !rowRef.current) return;
    const timer = window.setTimeout(() => {
      rowRef.current?.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    }, 160);
    return () => window.clearTimeout(timer);
  }, [focused, event.id]);

  const summary = [meta.label, channel, timeLabel].filter(Boolean).join(' · ');

  if (!hasDetails) {
    return (
      <Box
        ref={rowRef}
        data-alert-event-id={event.id}
        px={2}
        py={2}
        bg={focused ? focusBg : undefined}
        borderRadius={focused ? 'md' : undefined}
      >
        <Text fontSize='sm' fontWeight='medium' color={text} pl={5}>
          {summary}
        </Text>
      </Box>
    );
  }

  return (
    <Box
      ref={rowRef}
      data-alert-event-id={event.id}
      bg={focused ? focusBg : undefined}
      borderRadius={focused ? 'md' : undefined}
    >
      <HStack
        as='button'
        type='button'
        w='full'
        textAlign='left'
        spacing={2}
        px={2}
        py={2}
        borderRadius='md'
        _hover={{ bg: hoverBg }}
        onClick={() => setExpanded(current => !current)}
        aria-expanded={expanded}
      >
        <Icon
          as={expanded ? ChevronDown : ChevronRight}
          boxSize={3.5}
          color={muted}
          flexShrink={0}
        />
        <Text fontSize='sm' fontWeight='medium' color={text} flex='1' minW={0}>
          {summary}
        </Text>
      </HStack>
      <Collapse in={expanded} animateOpacity={false}>
        <Box
          ml={5}
          pl={3}
          pb={2}
          borderLeftWidth='2px'
          borderColor='dashboard.modal.border'
        >
          {badges.length > 0 ? (
            <HStack spacing={1.5} flexWrap='wrap' mb={1}>
              {badges.map(detail => (
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
          {expansion.map(item => (
            <Text
              key={`${item.label}:${item.value}`}
              color={muted}
              fontSize='xs'
              wordBreak='break-word'
            >
              {item.label === 'Detail'
                ? item.value
                : `${item.label}: ${item.value}`}
            </Text>
          ))}
        </Box>
      </Collapse>
    </Box>
  );
}

function ThresholdHistoryGroup({ group, focusedId }) {
  const muted = useColorModeValue('gray.600', 'dashboard.modal.muted');
  const text = useColorModeValue('gray.800', 'dashboard.modal.text');
  const border = useColorModeValue('gray.200', 'dashboard.modal.border');
  const reachedLabel = group.reached_at
    ? formatAlertLifecycleEventTime({
        type: 'threshold_reached',
        occurred_at: group.reached_at,
      })
    : null;

  return (
    <Box
      borderTop='1px solid'
      borderColor={border}
      pt={3}
      mt={3}
      _first={{ borderTop: 0, pt: 0, mt: 0 }}
    >
      <HStack spacing={2} mb={1} flexWrap='wrap'>
        <Badge colorScheme='orange' variant='subtle' textTransform='none'>
          {formatThresholdGroupLabel(group.threshold_days)}
        </Badge>
        {reachedLabel && group.threshold_days !== null ? (
          <Text fontSize='xs' color={muted}>
            Reached {reachedLabel}
          </Text>
        ) : null}
      </HStack>
      <VStack align='stretch' spacing={0}>
        {group.events.map(event => (
          <AlertLifecycleExpandableRow
            key={event.id}
            event={event}
            focused={focusedId === String(event.id)}
            defaultExpanded={focusedId === String(event.id)}
          />
        ))}
      </VStack>
      {group.events.length === 0 && !group.reached_at ? (
        <Text fontSize='sm' color={text}>
          No events
        </Text>
      ) : null}
    </Box>
  );
}

export default function AlertLifecycleTimeline({
  tokenId,
  alertState,
  enabled = true,
  pageSize = 20,
  compact = false,
  showHeading = true,
  showUpcoming = false,
  focusEventId = null,
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
  const groups = useMemo(
    () => groupAlertLifecycleEvents(chronologicalEvents),
    [chronologicalEvents]
  );
  const focusedId = focusEventId ? String(focusEventId) : null;

  useEffect(() => {
    if (!focusedId || loading || loadingMore || !hasMore) return;
    const hasFocusTarget = events.some(
      event => String(event.id) === focusedId
    );
    if (!hasFocusTarget) {
      loadPage(events.length);
    }
  }, [events, focusedId, hasMore, loadPage, loading, loadingMore]);

  return (
    <Box role='region' aria-label='Alert history' minW={0} {...boxProps}>
      {showHeading ? (
        <Text fontSize='sm' fontWeight='semibold' mb={2}>
          History
        </Text>
      ) : null}
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
      ) : compact ? (
        <VStack align='stretch' spacing={0}>
          {groups.map(group => (
            <ThresholdHistoryGroup
              key={
                group.threshold_days === null
                  ? 'none'
                  : String(group.threshold_days)
              }
              group={group}
              focusedId={focusedId}
            />
          ))}
        </VStack>
      ) : (
        <VStack align='stretch' spacing={0}>
          {chronologicalEvents.map(event => (
            <AlertLifecycleEventRow
              key={event.id}
              event={event}
              focused={focusedId === String(event.id)}
            />
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
      {showUpcoming ? <AlertUpcomingSection alertState={alertState} /> : null}
    </Box>
  );
}
