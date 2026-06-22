import { useMemo, useState } from 'react';
import { Link as RouterLink, useLocation } from 'react-router-dom';
import {
  Alert,
  AlertDescription,
  AlertIcon,
  Badge,
  Box,
  Circle,
  Flex,
  HStack,
  Link,
  SimpleGrid,
  Spinner,
  Table,
  Tbody,
  Td,
  Text,
  Th,
  Thead,
  Tooltip,
  Tr,
  VStack,
  useColorModeValue,
} from '@chakra-ui/react';
import {
  AlertTriangle,
  CalendarClock,
  Clock3,
  ArrowDownUp,
  Infinity,
  KeyRound,
  Layers,
  PlugZap,
  RefreshCw,
  ShieldAlert,
} from 'lucide-react';
import DashboardShell from '../components/DashboardShell';
import {
  DashboardActionButton,
  DashboardPanel as SharedDashboardPanel,
  DashboardPanelHeader,
  DashboardState,
} from '../components/DashboardPrimitives';
import SEO from '../components/SEO.jsx';
import TruncatedText from '../components/TruncatedText';
import { useControlCenterData } from '../hooks/useControlCenterData';
import { useControlCenterStats } from '../hooks/useControlCenterStats';
import { useDashboardTheme } from '../hooks/useDashboardTheme';
import { formatDate } from '../utils/apiClient';

const EMPTY_BUCKETS = Object.freeze({});
const EMPTY_LIST = Object.freeze([]);

const PRIVILEGE_LEVEL_TOOLTIP =
  'Heuristic ranking for review priority, not provider-native scope analysis. ' +
  'Score starts at 2 points per scope, then adds weight for keywords like admin (+50), ' +
  'owner (+40), delete (+25), write/manage (+20), full (+15), and wildcards or "all" (+30). ' +
  'High: score 40+, medium: 15-39, low: below 15.';

function buildImportAutoSyncManagePath(provider, workspaceId) {
  const params = new URLSearchParams();
  if (workspaceId) params.set('workspace', workspaceId);
  if (provider) params.set('import', provider);
  params.set('autoSyncManage', '1');
  return `/dashboard?${params.toString()}`;
}

function buildDashboardTokenPath(tokenId, workspaceId) {
  if (tokenId == null || tokenId === '') return null;
  const params = new URLSearchParams();
  if (workspaceId) params.set('workspace', workspaceId);
  params.set('token-id', String(tokenId));
  return `/dashboard?${params.toString()}`;
}

function formatPercent(count, total) {
  if (!total) return '0.0%';
  return `${((count / total) * 100).toFixed(1)}%`;
}

function formatAttentionDays(daysLeft) {
  if (daysLeft == null) return 'No expiry';
  if (daysLeft < 0) return `${Math.abs(daysLeft)} days overdue`;
  if (daysLeft === 0) return 'Due today';
  return `${daysLeft} days`;
}

function getAttentionMeta(bucket, daysLeft) {
  if (bucket === 'expired' || daysLeft < 0) {
    return {
      Icon: AlertTriangle,
      color: '#f43f5e',
      bg: 'rgba(244, 63, 94, 0.14)',
    };
  }
  if (bucket === 'expiring7' || (daysLeft != null && daysLeft <= 7)) {
    return {
      Icon: AlertTriangle,
      color: '#ef4444',
      bg: 'rgba(239, 68, 68, 0.14)',
    };
  }
  return {
    Icon: Clock3,
    color: '#f97316',
    bg: 'rgba(249, 115, 22, 0.14)',
  };
}

function getStatusBadge(status) {
  const colorMap = {
    pending: 'yellow',
    failed: 'red',
    blocked: 'orange',
    limit_exceeded: 'orange',
    partial: 'orange',
    sent: 'green',
  };
  let label = status.replace('_', ' ');
  if (status === 'limit_exceeded') label = 'Limit exceeded';
  else if (status === 'blocked') label = 'Blocked';
  else if (status === 'partial') label = 'Partial';
  return (
    <Badge colorScheme={colorMap[status] || 'gray'} textTransform='capitalize'>
      {label}
    </Badge>
  );
}

function friendlyErrorMessage(errorMsg) {
  if (!errorMsg) return '';
  const msg = String(errorMsg);
  if (msg === 'OUT_OF_WINDOW') return 'Waiting for delivery window to open';
  if (msg.includes('MAX_ATTEMPTS')) return 'Max retry attempts exceeded';
  if (msg.includes('NO_CONTACTS_DEFINED')) return 'No contacts configured';
  return msg;
}

function formatProviderLabel(provider) {
  if (!provider) return 'Unknown';
  return String(provider)
    .split(/[-_]/g, ' ')
    .map(part => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ');
}

function getPrivilegeLevelBadge(level) {
  const map = {
    high: { label: 'High', colorScheme: 'red' },
    medium: { label: 'Medium', colorScheme: 'orange' },
    low: { label: 'Low', colorScheme: 'gray' },
  };
  const meta = map[level] || map.low;
  return (
    <Tooltip label={PRIVILEGE_LEVEL_TOOLTIP} fontSize='xs' maxW='320px'>
      <Badge
        colorScheme={meta.colorScheme}
        textTransform='capitalize'
        px={2}
        py={0.5}
        borderRadius='md'
        cursor='help'
      >
        {meta.label}
      </Badge>
    </Tooltip>
  );
}

function getPrivilegeAccent(level) {
  const map = {
    high: '#ef4444',
    medium: '#f97316',
    low: '#64748b',
  };
  return map[level] || '#64748b';
}

function getAutoSyncHealthBadge(health) {
  const map = {
    healthy: { label: 'Healthy', colorScheme: 'green' },
    failed: { label: 'Failed', colorScheme: 'red' },
    paused: { label: 'Paused', colorScheme: 'gray' },
    scheduled: { label: 'Scheduled', colorScheme: 'yellow' },
    overdue: { label: 'Overdue', colorScheme: 'orange' },
  };
  const meta = map[health] || map.scheduled;
  return (
    <Badge
      colorScheme={meta.colorScheme}
      textTransform='capitalize'
      px={2}
      py={0.5}
      borderRadius='md'
    >
      {meta.label}
    </Badge>
  );
}

function getAutoSyncAccent(health) {
  const map = {
    healthy: '#22c55e',
    failed: '#ef4444',
    paused: '#64748b',
    scheduled: '#eab308',
    overdue: '#f97316',
  };
  return map[health] || '#64748b';
}

function CompactEmptyState({ children }) {
  const { muted } = useDashboardTheme();
  return (
    <Text color={muted} fontSize='sm'>
      {children}
    </Text>
  );
}

function formatRelativeTime(dateStr) {
  const date = new Date(dateStr);
  const now = new Date();
  const diffMs = now - date;
  const diffMins = Math.floor(diffMs / (1000 * 60));
  const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
  const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

  if (diffMins < 1) return 'Just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;
  return date.toLocaleDateString();
}

function getAlertChannelAttempts(alert) {
  if (alert.channel === 'email') {
    return typeof alert.attempts_email === 'number'
      ? alert.attempts_email
      : alert.attempts;
  }
  if (alert.channel === 'webhooks') {
    return typeof alert.attempts_webhooks === 'number'
      ? alert.attempts_webhooks
      : alert.attempts;
  }
  return alert.attempts;
}

function ControlCenterPanel({
  title,
  description,
  action,
  children,
  bodyProps,
  ...props
}) {
  const { border } = useDashboardTheme();

  return (
    <SharedDashboardPanel
      p={0}
      h='100%'
      display='flex'
      flexDirection='column'
      {...props}
    >
      {(title || description || action) && (
        <Box
          px={{ base: 4, md: 5 }}
          py={3}
          borderBottom='1px solid'
          borderColor={border}
        >
          <DashboardPanelHeader
            title={title}
            description={description}
            action={action}
            mb={0}
          />
        </Box>
      )}
      <Box
        p={{ base: 4, md: 5 }}
        flex='1'
        display='flex'
        flexDirection='column'
        minH={0}
        {...bodyProps}
      >
        {children}
      </Box>
    </SharedDashboardPanel>
  );
}

function InsightPanelSummary({ icon: Icon, accent, label, value, detail }) {
  const { text, muted, border } = useDashboardTheme();
  const summaryBg = useColorModeValue('gray.50', 'rgba(8, 13, 22, 0.58)');

  return (
    <Flex
      align='center'
      gap={3}
      px={3}
      py={2.5}
      mb={3}
      borderRadius='md'
      border='1px solid'
      borderColor={border}
      bg={summaryBg}
    >
      <Circle size='34px' bg={`${accent}22`} color={accent} flex='0 0 auto'>
        <Icon size={16} strokeWidth={2} />
      </Circle>
      <Box minW={0} flex='1'>
        <Text
          color={muted}
          fontSize='xs'
          textTransform='uppercase'
          letterSpacing='0.04em'
        >
          {label}
        </Text>
        <Text color={text} fontSize='xl' fontWeight='bold' lineHeight='1.1'>
          {value}
        </Text>
        {detail ? (
          <Text color={muted} fontSize='xs' mt={0.5}>
            {detail}
          </Text>
        ) : null}
      </Box>
    </Flex>
  );
}

function InsightListShell({ children, emptyMessage }) {
  const { border } = useDashboardTheme();
  const listBg = useColorModeValue(
    'rgba(248, 250, 252, 0.72)',
    'rgba(8, 13, 22, 0.42)'
  );

  if (!children) {
    return <CompactEmptyState>{emptyMessage}</CompactEmptyState>;
  }

  return (
    <Box
      border='1px solid'
      borderColor={border}
      borderRadius='md'
      bg={listBg}
      overflow='hidden'
      maxH='320px'
      overflowY='auto'
    >
      <VStack align='stretch' spacing={0} divider={<Box h='1px' bg={border} />}>
        {children}
      </VStack>
    </Box>
  );
}

function InsightListRow({
  accent,
  icon: Icon,
  title,
  titleTo,
  subtitle,
  meta,
  trailing,
  children,
}) {
  const { text, muted } = useDashboardTheme();
  const hoverBg = useColorModeValue(
    'rgba(255, 255, 255, 0.92)',
    'rgba(30, 41, 59, 0.38)'
  );
  const titleNode = titleTo ? (
    <Link
      as={RouterLink}
      to={titleTo}
      color={text}
      fontSize='sm'
      fontWeight='semibold'
      noOfLines={1}
      _hover={{ color: accent, textDecoration: 'underline' }}
    >
      {title}
    </Link>
  ) : (
    <Text color={text} fontSize='sm' fontWeight='semibold' noOfLines={1}>
      {title}
    </Text>
  );

  return (
    <Flex
      align='start'
      gap={3}
      px={3}
      py={3}
      borderLeft='3px solid'
      borderLeftColor={accent}
      _hover={{ bg: hoverBg }}
      transition='background 0.15s ease'
    >
      {Icon ? (
        <Circle
          size='32px'
          bg={`${accent}18`}
          color={accent}
          flex='0 0 auto'
          mt={0.5}
        >
          <Icon size={15} strokeWidth={2} />
        </Circle>
      ) : null}
      <Box minW={0} flex='1'>
        <Flex justify='space-between' align='start' gap={2}>
          <Box minW={0} flex='1'>
            {titleNode}
            {subtitle ? (
              <Text color={muted} fontSize='xs' mt={0.5} noOfLines={1}>
                {subtitle}
              </Text>
            ) : null}
          </Box>
          {trailing ? <Box flexShrink={0}>{trailing}</Box> : null}
        </Flex>
        {meta ? (
          <Text color={muted} fontSize='xs' mt={1.5} noOfLines={1}>
            {meta}
          </Text>
        ) : null}
        {children}
      </Box>
    </Flex>
  );
}

function getCategoryChipProps(category) {
  const map = {
    cert: { label: 'Certificate', colorScheme: 'blue' },
    key_secret: { label: 'Key/Secret', colorScheme: 'purple' },
    license: { label: 'License', colorScheme: 'green' },
    general: { label: 'General', colorScheme: 'gray' },
  };
  return map[category] || { label: category || 'Asset', colorScheme: 'gray' };
}

function PrivilegeScopePreview({ text }) {
  const previewBg = useColorModeValue(
    'rgba(139, 92, 246, 0.08)',
    'rgba(139, 92, 246, 0.14)'
  );

  return (
    <Box mt={2} px={2.5} py={1.5} borderRadius='md' bg={previewBg}>
      <TruncatedText text={text} maxLines={2} maxWidth='100%' />
    </Box>
  );
}

function MetricCard({ icon: Icon, label, value, detail, accent }) {
  const { text, muted } = useDashboardTheme();

  return (
    <SharedDashboardPanel p={4} minH='96px'>
      <HStack align='center' spacing={3}>
        <Circle size='38px' bg={`${accent}22`} color={accent} flex='0 0 auto'>
          <Icon size={19} strokeWidth={2} />
        </Circle>
        <Box minW={0}>
          <Text color={muted} fontSize='sm' lineHeight='1.25'>
            {label}
          </Text>
          <Text color={text} fontSize='2xl' fontWeight='bold' lineHeight='1.1'>
            {value}
          </Text>
          <Text color={muted} fontSize='xs' mt={1}>
            {detail}
          </Text>
        </Box>
      </HStack>
    </SharedDashboardPanel>
  );
}

function ControlStatCard({ label, value, help, color }) {
  const { text, muted } = useDashboardTheme();
  const valueColor = color || text;

  return (
    <SharedDashboardPanel p={4} minH='108px'>
      <VStack align='stretch' spacing={1}>
        <Text color={muted} fontSize='sm' lineHeight='1.25'>
          {label}
        </Text>
        <Text
          color={valueColor}
          style={{ color: valueColor }}
          fontSize='2xl'
          fontWeight='bold'
        >
          {value}
        </Text>
        {help ? (
          <Text color={muted} fontSize='xs'>
            {help}
          </Text>
        ) : null}
      </VStack>
    </SharedDashboardPanel>
  );
}

function AlertQueueMobileCard({ alert, channelAttempts }) {
  const { text, muted, border, dashboard } = useDashboardTheme();
  const cardBg = useColorModeValue('white', dashboard.bg.panelHover);
  const detailBg = useColorModeValue('gray.50', 'rgba(8, 13, 22, 0.58)');
  const channelLabel = alert.channel_display || alert.channel || 'None';
  const errorMessage = friendlyErrorMessage(
    alert.channel_error_message || alert.error_message || ''
  );

  return (
    <Box
      bg={cardBg}
      border='1px solid'
      borderColor={border}
      borderRadius='md'
      p={4}
    >
      <VStack align='stretch' spacing={3}>
        <Flex align='start' justify='space-between' gap={3}>
          <Box minW={0}>
            <Text
              color={text}
              fontSize='sm'
              fontWeight='semibold'
              noOfLines={2}
            >
              {alert.token_name || `Token #${alert.token_id}`}
            </Text>
            <Text color={muted} fontSize='xs' noOfLines={1}>
              {alert.token_type || 'Unknown'}
            </Text>
          </Box>
          {getStatusBadge(alert.status)}
        </Flex>

        <SimpleGrid columns={2} spacing={3}>
          <Box>
            <Text color={muted} fontSize='xs'>
              Days
            </Text>
            <Text color={text} fontSize='sm' fontWeight='medium'>
              {alert.threshold_days}
            </Text>
          </Box>
          <Box>
            <Text color={muted} fontSize='xs'>
              Due
            </Text>
            <Text color={text} fontSize='sm' fontWeight='medium'>
              {alert.due_date
                ? new Date(alert.due_date).toISOString().slice(0, 10)
                : '-'}
            </Text>
          </Box>
          <Box>
            <Text color={muted} fontSize='xs'>
              Channel
            </Text>
            <Badge colorScheme={alert.channel === 'email' ? 'green' : 'blue'}>
              {channelLabel}
            </Badge>
          </Box>
          <Box>
            <Text color={muted} fontSize='xs'>
              Attempts
            </Text>
            <Text color={text} fontSize='sm' fontWeight='medium'>
              {channelAttempts}
            </Text>
          </Box>
        </SimpleGrid>

        {errorMessage ? (
          <Box bg={detailBg} border='1px solid' borderColor={border} p={3}>
            <Text color={muted} fontSize='xs' mb={1}>
              Error
            </Text>
            <Text color={text} fontSize='sm' wordBreak='break-word'>
              {errorMessage}
            </Text>
          </Box>
        ) : null}

        <Text color={muted} fontSize='xs'>
          Updated {formatRelativeTime(alert.updated_at)}
        </Text>
      </VStack>
    </Box>
  );
}

function SectionState({
  status,
  error,
  emptyTitle,
  emptyDetail,
  unauthorizedTitle = 'Access restricted',
  unauthorizedDetail = 'You need manager or admin access to view this section.',
  children,
}) {
  const { muted } = useDashboardTheme();

  if (status === 'loading' || status === 'refreshing') {
    return (
      <HStack spacing={3} py={4} justify='center'>
        <Spinner size='sm' color='blue.300' />
        <Text color={muted} fontSize='sm'>
          {status === 'refreshing' ? 'Refreshing…' : 'Loading…'}
        </Text>
      </HStack>
    );
  }

  if (status === 'unauthorized') {
    return (
      <Alert status='warning' variant='left-accent'>
        <AlertIcon />
        <Box>
          <AlertDescription fontWeight='medium'>
            {unauthorizedTitle}
          </AlertDescription>
          <Text color={muted} fontSize='sm' mt={1}>
            {unauthorizedDetail}
          </Text>
        </Box>
      </Alert>
    );
  }

  if (status === 'error') {
    return (
      <Alert status='error' variant='left-accent'>
        <AlertIcon />
        <AlertDescription>
          {error || 'Failed to load this section.'}
        </AlertDescription>
      </Alert>
    );
  }

  if (status === 'empty') {
    return (
      <DashboardState title={emptyTitle} description={emptyDetail} py={6} />
    );
  }

  return (
    <VStack align='stretch' spacing={3}>
      {status === 'partial' ? (
        <Alert status='warning' variant='left-accent'>
          <AlertIcon />
          <AlertDescription>
            Some data could not be loaded. Showing the latest available results.
          </AlertDescription>
        </Alert>
      ) : null}
      {children}
    </VStack>
  );
}

const CONTROL_CENTER_PAGE_LAYOUT = {
  variant: 'wide',
  contentProps: {
    px: { base: 4, lg: 4, '2xl': 5 },
    py: { base: 5, lg: 3 },
  },
};

function useControlCenterShellProps({
  theme,
  location,
  session,
  alertData,
  selectedWorkspace,
  dashboardCanSeeManagerNav,
  onLogout,
  onAccountClick,
}) {
  const { workspaces, setSelectedWorkspaceId } = alertData;

  return useMemo(() => {
    const sessionName =
      session?.displayName || session?.name || session?.email || 'User';
    const sessionEmail = session?.email || '';
    const sessionInitials = String(sessionName)
      .split(/\s+/)
      .filter(Boolean)
      .slice(0, 2)
      .map(part => part[0])
      .join('')
      .toUpperCase();

    return {
      dashboardColors: theme,
      currentPath: location.pathname,
      sessionName,
      sessionEmail,
      sessionInitials,
      dashboardWorkspaces: workspaces,
      dashboardWorkspace: selectedWorkspace,
      workspaceLabel: selectedWorkspace?.name || 'Current workspace',
      onWorkspaceSelect: workspace => {
        if (workspace?.id) {
          setSelectedWorkspaceId(workspace.id);
        }
      },
      dashboardNotifications: [],
      onLogout,
      onAccountClick,
      dashboardCanSeeManagerNav,
      isSystemAdmin: session?.isAdmin === true,
      pageTitle: 'Control center',
    };
  }, [
    theme,
    location.pathname,
    session,
    workspaces,
    setSelectedWorkspaceId,
    selectedWorkspace,
    onLogout,
    onAccountClick,
    dashboardCanSeeManagerNav,
  ]);
}

export default function ControlCenter({ session, onLogout, onAccountClick }) {
  const location = useLocation();
  const theme = useDashboardTheme();
  const { pageBg, surface, text, muted, border } = theme;

  const tableHeadBg = useColorModeValue('gray.50', 'rgba(8, 13, 22, 0.84)');
  const tableHeadColor = useColorModeValue(
    'gray.600',
    'rgba(148, 163, 184, 0.92)'
  );
  const tableCellColor = useColorModeValue(
    'gray.800',
    'rgba(226, 232, 240, 0.94)'
  );
  const successValueColor = useColorModeValue('#15803d', '#22c55e');
  const cautionValueColor = useColorModeValue('#c2410c', '#fb923c');
  const pendingValueColor = useColorModeValue('#b45309', '#facc15');
  const blockedValueColor = useColorModeValue('#b91c1c', '#f87171');
  const healthChartInnerBg = surface;

  const assetStats = useControlCenterStats();
  const alertData = useControlCenterData();

  const selectedWorkspace = useMemo(
    () =>
      alertData.workspaces.find(
        workspace => workspace.id === alertData.selectedWorkspaceId
      ) ||
      alertData.eligibleWorkspaces.find(
        workspace => workspace.id === alertData.selectedWorkspaceId
      ) ||
      null,
    [
      alertData.workspaces,
      alertData.eligibleWorkspaces,
      alertData.selectedWorkspaceId,
    ]
  );

  const dashboardCanSeeManagerNav =
    alertData.isAdminAny ||
    alertData.eligibleWorkspaces.length > 0 ||
    alertData.workspaces.length <= 1;

  const statsData = assetStats.data;
  const buckets = statsData?.buckets || EMPTY_BUCKETS;
  const totalAssets = statsData?.totalAssets || 0;
  const sources = statsData?.sources || EMPTY_LIST;
  const needsAttention = statsData?.needsAttention || EMPTY_LIST;
  const neverExpires = statsData?.neverExpires || EMPTY_LIST;
  const privilegeHighlights = statsData?.privilegeHighlights || EMPTY_LIST;
  const autoSyncRows = statsData?.autoSync || EMPTY_LIST;
  const [privilegeSortDesc, setPrivilegeSortDesc] = useState(true);

  const sortedPrivilegeHighlights = useMemo(() => {
    const list = [...privilegeHighlights];
    list.sort((a, b) => {
      const diff = (a.score || 0) - (b.score || 0);
      if (diff !== 0) {
        return privilegeSortDesc ? -diff : diff;
      }
      return String(a.name || '').localeCompare(String(b.name || ''));
    });
    return list;
  }, [privilegeHighlights, privilegeSortDesc]);

  const autoSyncHealthSummary = useMemo(() => {
    const healthy = autoSyncRows.filter(row => row.health === 'healthy').length;
    const failed = autoSyncRows.filter(row => row.health === 'failed').length;
    const paused = autoSyncRows.filter(row => row.health === 'paused').length;
    return { healthy, failed, paused };
  }, [autoSyncRows]);

  const neverExpiresCount = neverExpires.length || buckets.neverExpires || 0;

  const healthSegments = useMemo(() => {
    const total = Math.max(totalAssets, 1);
    const healthyPercent = ((buckets.healthy || 0) / total) * 100;
    const duePercent = ((buckets.expiring8To30 || 0) / total) * 100;
    const criticalCount = Math.max(
      (buckets.critical || 0) - (buckets.expired || 0),
      0
    );
    const criticalPercent = (criticalCount / total) * 100;
    return {
      gradient: `conic-gradient(#22c55e 0 ${healthyPercent}%, #f97316 ${healthyPercent}% ${
        healthyPercent + duePercent
      }%, #ef4444 ${healthyPercent + duePercent}% ${
        healthyPercent + duePercent + criticalPercent
      }%, #64748b ${healthyPercent + duePercent + criticalPercent}% 100%)`,
    };
  }, [totalAssets, buckets]);

  const usageRatio = alertData.planInfo.alertLimitMonth
    ? Math.min(
        1,
        (alertData.stats.monthUsage || 0) / alertData.planInfo.alertLimitMonth
      )
    : 0;
  const usageColor =
    usageRatio >= 0.9
      ? blockedValueColor
      : usageRatio >= 0.75
        ? cautionValueColor
        : successValueColor;

  const assetSectionStatus = assetStats.isUnauthorized
    ? 'unauthorized'
    : assetStats.isLoading
      ? 'loading'
      : assetStats.isRefreshing
        ? 'refreshing'
        : assetStats.isError
          ? 'error'
          : assetStats.isPartial
            ? 'partial'
            : !statsData
              ? 'empty'
              : 'ready';

  const alertSectionStatus = alertData.unauthorized
    ? 'unauthorized'
    : alertData.loading
      ? 'loading'
      : alertData.refreshing
        ? 'refreshing'
        : alertData.error
          ? 'error'
          : alertData.noEligibleAccess
            ? 'unauthorized'
            : alertData.partial
              ? 'partial'
              : 'ready';

  const handleRefreshAll = () => {
    assetStats.refetch();
    alertData.refresh();
  };

  const dashboardShellProps = useControlCenterShellProps({
    theme,
    location,
    session,
    alertData,
    selectedWorkspace,
    dashboardCanSeeManagerNav,
    onLogout,
    onAccountClick,
  });

  return (
    <>
      <SEO
        title='Control center'
        description='Asset health overview, alert delivery statistics, and alert queue'
        noindex
      />
      <Box
        color={text}
        minH='100vh'
        bg={pageBg}
        sx={{
          '.chakra-table th': {
            color: tableHeadColor,
            borderColor: border,
            background: tableHeadBg,
            fontSize: '0.72rem',
            letterSpacing: '0',
            textTransform: 'none',
          },
          '.chakra-table td': {
            color: tableCellColor,
            borderColor: border,
          },
        }}
      >
        <DashboardShell {...dashboardShellProps}>
          <Box
            {...CONTROL_CENTER_PAGE_LAYOUT.contentProps}
            data-tour='control-center-page'
          >
            <VStack spacing={6} align='stretch'>
              <Box>
                <SectionState
                  status={
                    assetSectionStatus === 'ready'
                      ? 'ready'
                      : assetSectionStatus
                  }
                  error={assetStats.error}
                  emptyTitle='No asset statistics yet'
                  emptyDetail='Add assets to your workspace to see health metrics here.'
                  unauthorizedDetail='Select a workspace where you have manager or admin access.'
                >
                  <Box data-tour='control-center-metrics'>
                    <SimpleGrid
                      columns={{ base: 1, sm: 2, xl: 5 }}
                      spacing={3}
                      mb={3}
                    >
                      <MetricCard
                        icon={Layers}
                        label='Total assets'
                        value={totalAssets}
                        detail='Across all sections'
                        accent='#3b82f6'
                      />
                      <MetricCard
                        icon={Clock3}
                        label='Expiring in 7 days'
                        value={buckets.expiring7 || 0}
                        detail={`${formatPercent(buckets.expiring7 || 0, totalAssets)} of total`}
                        accent='#f59e0b'
                      />
                      <MetricCard
                        icon={CalendarClock}
                        label='Expiring in 8–30 days'
                        value={buckets.expiring8To30 || 0}
                        detail={`${formatPercent(buckets.expiring8To30 || 0, totalAssets)} of total`}
                        accent='#f97316'
                      />
                      <MetricCard
                        icon={ShieldAlert}
                        label='Critical / expired'
                        value={buckets.critical || 0}
                        detail={`${formatPercent(buckets.critical || 0, totalAssets)} of total`}
                        accent='#ef4444'
                      />
                      <MetricCard
                        icon={PlugZap}
                        label='Asset categories'
                        value={sources.length}
                        detail={
                          sources.length > 0
                            ? 'Categories reporting assets'
                            : 'No categorized assets yet'
                        }
                        accent='#22c55e'
                      />
                    </SimpleGrid>

                    <SimpleGrid
                      columns={{ base: 1, xl: 3 }}
                      spacing={3}
                      alignItems='stretch'
                    >
                      <ControlCenterPanel title='Needs attention'>
                        {needsAttention.length === 0 ? (
                          <Text color={muted} fontSize='sm'>
                            All clear. No assets are due soon.
                          </Text>
                        ) : (
                          <VStack align='stretch' spacing={3}>
                            {needsAttention.map(item => {
                              const meta = getAttentionMeta(
                                item.bucket,
                                item.daysLeft
                              );
                              const AttentionIcon = meta.Icon;
                              return (
                                <HStack key={item.id} spacing={3} align='start'>
                                  <Circle
                                    size='38px'
                                    bg={meta.bg}
                                    color={meta.color}
                                    flex='0 0 auto'
                                  >
                                    <AttentionIcon size={18} />
                                  </Circle>
                                  <Box minW={0} flex='1'>
                                    <Text
                                      color={text}
                                      fontSize='sm'
                                      fontWeight='medium'
                                      noOfLines={1}
                                    >
                                      {item.name}
                                    </Text>
                                    <Text
                                      color={muted}
                                      fontSize='xs'
                                      noOfLines={1}
                                    >
                                      {[item.type, item.category]
                                        .filter(Boolean)
                                        .join(' · ') || 'Asset'}
                                    </Text>
                                  </Box>
                                  <Text
                                    color={meta.color}
                                    fontSize='xs'
                                    fontWeight='semibold'
                                    textAlign='right'
                                  >
                                    {formatAttentionDays(item.daysLeft)}
                                  </Text>
                                </HStack>
                              );
                            })}
                          </VStack>
                        )}
                      </ControlCenterPanel>

                      <ControlCenterPanel title='Asset health overview'>
                        <HStack
                          spacing={5}
                          align='center'
                          direction={{ base: 'column', sm: 'row' }}
                        >
                          <Circle
                            size='112px'
                            bg={healthSegments.gradient}
                            boxShadow='0 0 0 1px rgba(148, 163, 184, 0.12) inset'
                            flex='0 0 auto'
                          >
                            <Circle size='64px' bg={healthChartInnerBg}>
                              <Text color={text} fontWeight='bold'>
                                {totalAssets}
                              </Text>
                            </Circle>
                          </Circle>
                          <VStack align='stretch' spacing={2} flex='1'>
                            {[
                              ['Healthy', buckets.healthy || 0, '#22c55e'],
                              [
                                'Due soon',
                                buckets.expiring8To30 || 0,
                                '#f97316',
                              ],
                              [
                                'Critical',
                                Math.max(
                                  (buckets.critical || 0) -
                                    (buckets.expired || 0),
                                  0
                                ),
                                '#ef4444',
                              ],
                              ['Expired', buckets.expired || 0, '#64748b'],
                            ].map(([label, count, color]) => (
                              <Flex
                                key={label}
                                justify='space-between'
                                gap={3}
                                fontSize='sm'
                              >
                                <HStack spacing={2} minW={0}>
                                  <Circle size='8px' bg={color} />
                                  <Text color={muted}>{label}</Text>
                                </HStack>
                                <Text color={text} fontWeight='medium'>
                                  {count} ({formatPercent(count, totalAssets)})
                                </Text>
                              </Flex>
                            ))}
                          </VStack>
                        </HStack>
                      </ControlCenterPanel>

                      <ControlCenterPanel title='Asset sources'>
                        {sources.length === 0 ? (
                          <Text color={muted} fontSize='sm'>
                            No asset sources yet.
                          </Text>
                        ) : (
                          <VStack align='stretch' spacing={3}>
                            {sources.slice(0, 5).map(source => (
                              <HStack
                                key={source.key || source.name}
                                spacing={3}
                              >
                                <Circle
                                  size='30px'
                                  bg='rgba(59, 130, 246, 0.14)'
                                  color='#60a5fa'
                                >
                                  <PlugZap size={15} />
                                </Circle>
                                <Box flex='1' minW={0}>
                                  <Text
                                    color={text}
                                    fontSize='sm'
                                    noOfLines={1}
                                  >
                                    {source.name}
                                  </Text>
                                  <Text color={muted} fontSize='xs'>
                                    {source.count} asset(s)
                                  </Text>
                                </Box>
                              </HStack>
                            ))}
                          </VStack>
                        )}
                      </ControlCenterPanel>
                    </SimpleGrid>
                  </Box>

                  <SimpleGrid
                    columns={{ base: 1, xl: 3 }}
                    spacing={3}
                    mt={3}
                    data-tour='control-center-insights'
                  >
                    <ControlCenterPanel
                      title='Never expires'
                      description='Perpetual assets with no expiry date'
                    >
                      <InsightPanelSummary
                        icon={Infinity}
                        accent='#3b82f6'
                        label='Perpetual assets'
                        value={neverExpiresCount}
                        detail={
                          totalAssets
                            ? `${formatPercent(neverExpiresCount, totalAssets)} of workspace inventory`
                            : 'Across this workspace'
                        }
                      />
                      <InsightListShell emptyMessage='No perpetual assets in this workspace.'>
                        {neverExpires.length > 0
                          ? neverExpires.map(item => {
                              const chip = getCategoryChipProps(item.category);
                              return (
                                <InsightListRow
                                  key={item.id}
                                  accent='#3b82f6'
                                  icon={Infinity}
                                  title={item.name}
                                  titleTo={buildDashboardTokenPath(
                                    item.id,
                                    alertData.selectedWorkspaceId
                                  )}
                                  subtitle={item.type || 'Asset'}
                                  trailing={
                                    <Badge
                                      colorScheme={chip.colorScheme}
                                      variant='subtle'
                                      fontSize='xs'
                                    >
                                      {item.categoryLabel || chip.label}
                                    </Badge>
                                  }
                                  meta={
                                    item.section
                                      ? `Section: ${item.section}`
                                      : 'No section assigned'
                                  }
                                />
                              );
                            })
                          : null}
                      </InsightListShell>
                    </ControlCenterPanel>

                    <ControlCenterPanel
                      title='Scopes & privileges'
                      description={
                        <Tooltip
                          label={PRIVILEGE_LEVEL_TOOLTIP}
                          fontSize='xs'
                          maxW='320px'
                        >
                          <Text as='span' cursor='help'>
                            Credentials ranked by scope count and privilege
                            keywords
                          </Text>
                        </Tooltip>
                      }
                      action={
                        <DashboardActionButton
                          size='sm'
                          variant='outline'
                          borderColor={border}
                          leftIcon={<ArrowDownUp size={14} />}
                          onClick={() => setPrivilegeSortDesc(prev => !prev)}
                          isDisabled={privilegeHighlights.length === 0}
                        >
                          {privilegeSortDesc ? 'Highest first' : 'Lowest first'}
                        </DashboardActionButton>
                      }
                    >
                      <InsightPanelSummary
                        icon={KeyRound}
                        accent='#8b5cf6'
                        label='Scoped credentials'
                        value={privilegeHighlights.length}
                        detail={
                          privilegeHighlights.filter(
                            item => item.level === 'high'
                          ).length
                            ? `${
                                privilegeHighlights.filter(
                                  item => item.level === 'high'
                                ).length
                              } high-privilege asset(s) need review`
                            : 'Review API keys with the broadest scopes'
                        }
                      />
                      <InsightListShell emptyMessage='No scopes or privileges recorded on assets yet.'>
                        {sortedPrivilegeHighlights.length > 0
                          ? sortedPrivilegeHighlights.map(item => (
                              <InsightListRow
                                key={item.id}
                                accent={getPrivilegeAccent(item.level)}
                                icon={KeyRound}
                                title={item.name}
                                titleTo={buildDashboardTokenPath(
                                  item.id,
                                  alertData.selectedWorkspaceId
                                )}
                                subtitle={item.type || 'Credential'}
                                trailing={getPrivilegeLevelBadge(item.level)}
                              >
                                <PrivilegeScopePreview
                                  text={item.preview || item.privileges}
                                />
                                <HStack spacing={2} mt={2}>
                                  <Badge variant='outline' fontSize='xs'>
                                    {item.scopeCount || 0} scope(s)
                                  </Badge>
                                  <Badge
                                    variant='subtle'
                                    colorScheme='purple'
                                    fontSize='xs'
                                  >
                                    Score {item.score || 0}
                                  </Badge>
                                </HStack>
                              </InsightListRow>
                            ))
                          : null}
                      </InsightListShell>
                    </ControlCenterPanel>

                    <ControlCenterPanel
                      title='Auto-sync'
                      description='Integration schedules and last run health'
                    >
                      <InsightPanelSummary
                        icon={RefreshCw}
                        accent='#22c55e'
                        label='Active jobs'
                        value={autoSyncRows.length}
                        detail={
                          autoSyncRows.length
                            ? `${autoSyncHealthSummary.healthy} healthy · ${autoSyncHealthSummary.failed} failed · ${autoSyncHealthSummary.paused} paused`
                            : 'Connect imports to keep inventory fresh'
                        }
                      />
                      <InsightListShell emptyMessage='No auto-sync jobs configured for this workspace.'>
                        {autoSyncRows.length > 0
                          ? autoSyncRows.map(row => (
                              <InsightListRow
                                key={row.id || row.provider}
                                accent={getAutoSyncAccent(row.health)}
                                icon={RefreshCw}
                                title={formatProviderLabel(row.provider)}
                                subtitle={row.scheduleLabel}
                                trailing={getAutoSyncHealthBadge(row.health)}
                                meta={
                                  row.lastSyncAt
                                    ? `Last sync ${formatRelativeTime(row.lastSyncAt)}${
                                        row.lastSyncItemsCount != null
                                          ? ` · ${row.lastSyncItemsCount} item(s)`
                                          : ''
                                      }`
                                    : 'No successful sync yet'
                                }
                              >
                                {row.nextSyncAt ? (
                                  <Text color={muted} fontSize='xs' mt={2}>
                                    Next run {formatDate(row.nextSyncAt)}
                                  </Text>
                                ) : null}
                                {row.lastSyncError &&
                                row.health === 'failed' ? (
                                  <Text
                                    color={blockedValueColor}
                                    fontSize='xs'
                                    mt={1}
                                    noOfLines={2}
                                  >
                                    {row.lastSyncError}
                                  </Text>
                                ) : null}
                                {row.provider ? (
                                  <Link
                                    as={RouterLink}
                                    to={buildImportAutoSyncManagePath(
                                      row.provider,
                                      alertData.selectedWorkspaceId
                                    )}
                                    fontSize='xs'
                                    fontWeight='semibold'
                                    color='#22c55e'
                                    mt={2}
                                    display='inline-block'
                                    _hover={{ textDecoration: 'underline' }}
                                  >
                                    Manage auto-sync in Import tokens
                                  </Link>
                                ) : null}
                              </InsightListRow>
                            ))
                          : null}
                      </InsightListShell>
                    </ControlCenterPanel>
                  </SimpleGrid>
                </SectionState>
              </Box>

              <SectionState
                status={
                  alertSectionStatus === 'ready' ? 'ready' : alertSectionStatus
                }
                error={alertData.error}
                emptyTitle='No alert delivery data'
                emptyDetail='Alert statistics appear when you have manager access to a workspace.'
                unauthorizedDetail='Alert delivery statistics require manager or admin access.'
              >
                {alertData.isAdminAny && !alertData.hasManagerOrViewerRole ? (
                  <ControlCenterPanel title='Organization (admin only)' mb={4}>
                    <SimpleGrid
                      columns={{ base: 1, sm: 2, md: 3, lg: 5 }}
                      spacing={3}
                    >
                      <ControlStatCard
                        label='Workspaces'
                        value={alertData.orgWorkspaceCount}
                        help='Across organization'
                      />
                      <ControlStatCard
                        label='Members'
                        value={alertData.planInfo.memberCount || 0}
                        help='Across organization'
                      />
                      <ControlStatCard
                        label='Tokens'
                        value={alertData.orgTokenCount || 0}
                        help='Across workspaces'
                      />
                      <ControlStatCard
                        label='Email/webhook deliveries'
                        value={alertData.orgStats.monthUsage}
                        help='This month, all workspaces'
                      />
                      {(alertData.stats.whatsappMonth || 0) > 0 ? (
                        <ControlStatCard
                          label='WhatsApp deliveries'
                          value={alertData.stats.whatsappMonth || 0}
                          help='This month, across organization'
                        />
                      ) : null}
                    </SimpleGrid>
                  </ControlCenterPanel>
                ) : null}

                {alertData.eligibleWorkspaces.length > 0 ? (
                  <ControlCenterPanel
                    title='Alert delivery (this month)'
                    mb={4}
                  >
                    <SimpleGrid
                      columns={{ base: 1, sm: 2, md: 3, lg: 5 }}
                      spacing={3}
                    >
                      <ControlStatCard
                        label='Successful deliveries'
                        value={
                          typeof alertData.stats.allMonthSuccesses ===
                            'number' && alertData.stats.allMonthSuccesses >= 0
                            ? alertData.stats.allMonthSuccesses
                            : alertData.stats.monthUsage
                        }
                        color={usageColor}
                      />
                      <ControlStatCard
                        label='Email successes'
                        value={alertData.stats.emailsMonth || 0}
                      />
                      <ControlStatCard
                        label='Webhook successes'
                        value={alertData.stats.webhooksMonth || 0}
                      />
                      {(alertData.stats.whatsappMonth || 0) > 0 ? (
                        <ControlStatCard
                          label='WhatsApp successes'
                          value={alertData.stats.whatsappMonth || 0}
                        />
                      ) : null}
                      <ControlStatCard
                        label='Tokens'
                        value={alertData.workspaceTokenCount}
                        help='In this workspace'
                      />
                    </SimpleGrid>
                  </ControlCenterPanel>
                ) : null}

                {alertData.eligibleWorkspaces.length > 0 ? (
                  <SimpleGrid columns={{ base: 1, md: 2 }} spacing={3} mb={4}>
                    <ControlStatCard
                      label='Pending'
                      value={alertData.queueSummary.pending || 0}
                      help='Awaiting delivery'
                      color={pendingValueColor}
                    />
                    <ControlStatCard
                      label='Blocked'
                      value={alertData.queueSummary.blocked || 0}
                      help='Delivery blocked'
                      color={blockedValueColor}
                    />
                  </SimpleGrid>
                ) : null}
              </SectionState>

              {alertData.eligibleWorkspaces.length > 0 ? (
                <ControlCenterPanel
                  data-tour='control-center-alert-queue'
                  title='Alert queue (workspace)'
                  action={
                    <DashboardActionButton
                      onClick={handleRefreshAll}
                      isLoading={
                        assetStats.isRefreshing || alertData.refreshing
                      }
                      variant='outline'
                      borderColor={border}
                    >
                      Refresh
                    </DashboardActionButton>
                  }
                >
                  <SectionState
                    status={
                      alertSectionStatus === 'ready'
                        ? 'ready'
                        : alertSectionStatus
                    }
                    error={alertData.error}
                    emptyTitle='No pending or failed alerts'
                    emptyDetail='Alerts appear here when they are queued for delivery but have not been sent yet, or when delivery has failed.'
                    unauthorizedDetail='The alert queue requires manager or admin access.'
                  >
                    <VStack align='stretch' spacing={4}>
                      <VStack align='start' spacing={2}>
                        <Tooltip
                          label={alertData.requeueDisabledReason}
                          hasArrow
                          placement='top'
                        >
                          <Box as='span' display='inline-block'>
                            <DashboardActionButton
                              colorScheme='blue'
                              variant='solid'
                              onClick={() => alertData.requeueAlerts()}
                              isDisabled={!alertData.canRequeue}
                            >
                              Requeue blocked/failed
                            </DashboardActionButton>
                          </Box>
                        </Tooltip>
                        <Text fontSize='xs' color={muted}>
                          Admins can requeue failed alerts for the selected
                          workspace.
                        </Text>
                      </VStack>

                      <Alert status='info' variant='left-accent'>
                        <AlertIcon />
                        <AlertDescription>
                          This shows alerts that are pending, blocked (failed),
                          or exceeded limits. Each row represents one delivery
                          channel (email or webhook). Successfully sent alerts
                          are not shown here but are counted in the delivery
                          statistics above.{' '}
                          {alertData.retryHintDate
                            ? `If you reached your monthly alerting limit, delivery will resume on ${formatDate(alertData.retryHintDate)} (start of next month).`
                            : ''}
                        </AlertDescription>
                      </Alert>

                      {alertData.queue.length === 0 ? (
                        <DashboardState
                          title='No pending or failed alerts'
                          py={4}
                        />
                      ) : (
                        <>
                          <Box display={{ base: 'block', lg: 'none' }}>
                            <VStack align='stretch' spacing={3}>
                              {alertData.queue.map(alert => (
                                <AlertQueueMobileCard
                                  key={`${alert.id}-${alert.channel}-mobile`}
                                  alert={alert}
                                  channelAttempts={getAlertChannelAttempts(
                                    alert
                                  )}
                                />
                              ))}
                            </VStack>
                          </Box>

                          <Box
                            overflowX='auto'
                            display={{ base: 'none', lg: 'block' }}
                          >
                            <Table size='sm' variant='simple'>
                              <Thead>
                                <Tr>
                                  <Th>Token</Th>
                                  <Th isNumeric width='80px'>
                                    Days
                                  </Th>
                                  <Th width='130px'>Due</Th>
                                  <Th>Status</Th>
                                  <Th>Channel</Th>
                                  <Th isNumeric>Attempts</Th>
                                  <Th>Error</Th>
                                  <Th>Updated</Th>
                                </Tr>
                              </Thead>
                              <Tbody>
                                {alertData.queue.map(alert => {
                                  const channelAttempts =
                                    getAlertChannelAttempts(alert);

                                  return (
                                    <Tr key={`${alert.id}-${alert.channel}`}>
                                      <Td>
                                        <VStack align='start' spacing={0}>
                                          <Text fontWeight='medium'>
                                            {alert.token_name ||
                                              `Token #${alert.token_id}`}
                                          </Text>
                                          <Text fontSize='sm' color={muted}>
                                            {alert.token_type || 'Unknown'}
                                          </Text>
                                        </VStack>
                                      </Td>
                                      <Td isNumeric>{alert.threshold_days}</Td>
                                      <Td>
                                        {alert.due_date
                                          ? new Date(alert.due_date)
                                              .toISOString()
                                              .slice(0, 10)
                                          : '-'}
                                      </Td>
                                      <Td>{getStatusBadge(alert.status)}</Td>
                                      <Td>
                                        <Badge
                                          colorScheme={
                                            alert.channel === 'email'
                                              ? 'green'
                                              : 'blue'
                                          }
                                          size='sm'
                                        >
                                          {alert.channel_display ||
                                            alert.channel ||
                                            'None'}
                                        </Badge>
                                      </Td>
                                      <Td isNumeric>{channelAttempts}</Td>
                                      <Td maxW='200px'>
                                        <TruncatedText
                                          text={friendlyErrorMessage(
                                            alert.channel_error_message ||
                                              alert.error_message ||
                                              ''
                                          )}
                                          maxLines={3}
                                          maxWidth='200px'
                                        />
                                      </Td>
                                      <Td>
                                        {formatRelativeTime(alert.updated_at)}
                                      </Td>
                                    </Tr>
                                  );
                                })}
                              </Tbody>
                            </Table>
                          </Box>
                        </>
                      )}
                    </VStack>
                  </SectionState>
                </ControlCenterPanel>
              ) : null}
            </VStack>
          </Box>
        </DashboardShell>
      </Box>
    </>
  );
}
