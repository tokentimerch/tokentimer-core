import { useMemo } from 'react';
import { useLocation } from 'react-router-dom';
import {
  Alert,
  AlertDescription,
  AlertIcon,
  Badge,
  Box,
  Button,
  Circle,
  Flex,
  Heading,
  HStack,
  SimpleGrid,
  Spinner,
  Stat,
  StatHelpText,
  StatLabel,
  StatNumber,
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
  Layers,
  PlugZap,
  ShieldAlert,
} from 'lucide-react';
import DashboardShell from '../components/DashboardShell';
import SEO from '../components/SEO.jsx';
import TruncatedText from '../components/TruncatedText';
import { useControlCenterData } from '../hooks/useControlCenterData';
import { useControlCenterStats } from '../hooks/useControlCenterStats';
import { useDashboardTheme } from '../hooks/useDashboardTheme';
import { formatDate } from '../utils/apiClient';

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

function DashboardPanel({ title, action, children, ...props }) {
  const { surface, text, border } = useDashboardTheme();
  const panelShadow = useColorModeValue(
    '0 1px 3px rgba(0, 0, 0, 0.08)',
    '0 16px 48px rgba(0, 0, 0, 0.2)'
  );

  return (
    <Box
      bg={surface}
      border='1px solid'
      borderColor={border}
      borderRadius='md'
      boxShadow={panelShadow}
      overflow='hidden'
      {...props}
    >
      {(title || action) && (
        <Flex
          align='center'
          justify='space-between'
          px={{ base: 4, md: 5 }}
          py={3}
          borderBottom='1px solid'
          borderColor={border}
        >
          <Text color={text} fontWeight='semibold' fontSize='sm'>
            {title}
          </Text>
          {action}
        </Flex>
      )}
      <Box p={{ base: 4, md: 5 }}>{children}</Box>
    </Box>
  );
}

function MetricCard({ icon: Icon, label, value, detail, accent }) {
  const { surface, text, muted, border } = useDashboardTheme();
  const cardShadow = useColorModeValue(
    '0 1px 3px rgba(0, 0, 0, 0.08)',
    '0 14px 42px rgba(0, 0, 0, 0.18)'
  );

  return (
    <Box
      bg={surface}
      border='1px solid'
      borderColor={border}
      borderRadius='md'
      p={4}
      minH='84px'
      boxShadow={cardShadow}
    >
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
  const { muted, text } = useDashboardTheme();

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
      <VStack spacing={2} py={6}>
        <Text color={text} fontSize='sm' fontWeight='medium'>
          {emptyTitle}
        </Text>
        {emptyDetail ? (
          <Text color={muted} fontSize='xs' textAlign='center'>
            {emptyDetail}
          </Text>
        ) : null}
      </VStack>
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
      dashboardWorkspaces: alertData.workspaces,
      dashboardWorkspace: selectedWorkspace,
      workspaceLabel: selectedWorkspace?.name || 'Current workspace',
      onWorkspaceSelect: workspace => {
        if (workspace?.id) {
          alertData.setSelectedWorkspaceId(workspace.id);
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
    alertData.workspaces,
    alertData.setSelectedWorkspaceId,
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

  const outlineButtonColor = useColorModeValue(
    'gray.700',
    'rgba(226, 232, 240, 0.94)'
  );
  const outlineButtonHoverBg = useColorModeValue(
    'gray.100',
    'rgba(30, 41, 59, 0.72)'
  );
  const outlineButtonHoverColor = useColorModeValue('gray.900', 'white');
  const tableHeadBg = useColorModeValue('gray.50', 'rgba(8, 13, 22, 0.84)');
  const tableHeadColor = useColorModeValue(
    'gray.600',
    'rgba(148, 163, 184, 0.92)'
  );
  const tableCellColor = useColorModeValue(
    'gray.800',
    'rgba(226, 232, 240, 0.94)'
  );
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
  const buckets = statsData?.buckets || {};
  const totalAssets = statsData?.totalAssets || 0;
  const sources = statsData?.sources || [];
  const needsAttention = statsData?.needsAttention || [];

  const healthSegments = useMemo(() => {
    const total = Math.max(totalAssets, 1);
    const healthyPercent = ((buckets.healthy || 0) / total) * 100;
    const duePercent = ((buckets.expiring8To30 || 0) / total) * 100;
    const criticalCount = Math.max(
      (buckets.critical || 0) - (buckets.expired || 0),
      0
    );
    const criticalPercent = (criticalCount / total) * 100;
    const expiredPercent = ((buckets.expired || 0) / total) * 100;

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
      ? 'red.500'
      : usageRatio >= 0.75
        ? 'orange.500'
        : 'green.500';

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
              <Box data-tour='control-center-metrics'>
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
                    <DashboardPanel title='Needs attention'>
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
                                  fontWeight='bold'
                                  textAlign='right'
                                >
                                  {formatAttentionDays(item.daysLeft)}
                                </Text>
                              </HStack>
                            );
                          })}
                        </VStack>
                      )}
                    </DashboardPanel>

                    <DashboardPanel title='Asset health overview'>
                      <HStack spacing={5} align='center'>
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
                            ['Due soon', buckets.expiring8To30 || 0, '#f97316'],
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
                    </DashboardPanel>

                    <DashboardPanel title='Asset sources'>
                      {sources.length === 0 ? (
                        <Text color={muted} fontSize='sm'>
                          No asset sources yet.
                        </Text>
                      ) : (
                        <VStack align='stretch' spacing={3}>
                          {sources.slice(0, 5).map(source => (
                            <HStack key={source.key || source.name} spacing={3}>
                              <Circle
                                size='30px'
                                bg='rgba(59, 130, 246, 0.14)'
                                color='#60a5fa'
                              >
                                <PlugZap size={15} />
                              </Circle>
                              <Box flex='1' minW={0}>
                                <Text color={text} fontSize='sm' noOfLines={1}>
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
                    </DashboardPanel>
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
                  <Box
                    bg={surface}
                    p={4}
                    borderRadius='md'
                    border='1px solid'
                    borderColor={border}
                    mb={4}
                  >
                    <Heading size='sm' mb={3} color={text}>
                      Organization (admin only)
                    </Heading>
                    <SimpleGrid
                      columns={{ base: 1, sm: 2, md: 3, lg: 5 }}
                      spacing={4}
                    >
                      <Stat
                        bg={surface}
                        p={4}
                        borderRadius='md'
                        border='1px solid'
                        borderColor={border}
                      >
                        <StatLabel>Workspaces</StatLabel>
                        <StatNumber>{alertData.orgWorkspaceCount}</StatNumber>
                        <StatHelpText>Across organization</StatHelpText>
                      </Stat>
                      <Stat
                        bg={surface}
                        p={4}
                        borderRadius='md'
                        border='1px solid'
                        borderColor={border}
                      >
                        <StatLabel>Members</StatLabel>
                        <StatNumber>
                          {alertData.planInfo.memberCount || 0}
                        </StatNumber>
                        <StatHelpText>Across organization</StatHelpText>
                      </Stat>
                      <Stat
                        bg={surface}
                        p={4}
                        borderRadius='md'
                        border='1px solid'
                        borderColor={border}
                      >
                        <StatLabel>Tokens</StatLabel>
                        <StatNumber>
                          {alertData.planInfo.tokenCount || 0}
                        </StatNumber>
                        <StatHelpText>Across workspaces</StatHelpText>
                      </Stat>
                      <Stat
                        bg={surface}
                        p={4}
                        borderRadius='md'
                        border='1px solid'
                        borderColor={border}
                      >
                        <StatLabel>Email/webhook deliveries (month)</StatLabel>
                        <StatNumber>{alertData.orgStats.monthUsage}</StatNumber>
                        <StatHelpText>All workspaces</StatHelpText>
                      </Stat>
                      {(alertData.stats.whatsappMonth || 0) > 0 ? (
                        <Stat
                          bg={surface}
                          p={4}
                          borderRadius='md'
                          border='1px solid'
                          borderColor={border}
                        >
                          <StatLabel>WhatsApp deliveries (month)</StatLabel>
                          <StatNumber>
                            {alertData.stats.whatsappMonth || 0}
                          </StatNumber>
                          <StatHelpText>Across organization</StatHelpText>
                        </Stat>
                      ) : null}
                    </SimpleGrid>
                  </Box>
                ) : null}

                {alertData.eligibleWorkspaces.length > 0 ? (
                  <Box
                    bg={surface}
                    p={4}
                    borderRadius='md'
                    border='1px solid'
                    borderColor={border}
                    mb={4}
                  >
                    <Heading size='sm' mb={3} color={text}>
                      Alert delivery (this month)
                    </Heading>
                    <SimpleGrid
                      columns={{ base: 1, sm: 2, md: 3, lg: 5 }}
                      spacing={4}
                    >
                      <Stat
                        bg={surface}
                        p={4}
                        borderRadius='md'
                        border='1px solid'
                        borderColor={border}
                      >
                        <StatLabel>Successful deliveries</StatLabel>
                        <StatNumber color={usageColor}>
                          {typeof alertData.stats.allMonthSuccesses ===
                            'number' && alertData.stats.allMonthSuccesses >= 0
                            ? alertData.stats.allMonthSuccesses
                            : alertData.stats.monthUsage}
                        </StatNumber>
                      </Stat>
                      <Stat
                        bg={surface}
                        p={4}
                        borderRadius='md'
                        border='1px solid'
                        borderColor={border}
                      >
                        <StatLabel>Email successes</StatLabel>
                        <StatNumber>
                          {alertData.stats.emailsMonth || 0}
                        </StatNumber>
                      </Stat>
                      <Stat
                        bg={surface}
                        p={4}
                        borderRadius='md'
                        border='1px solid'
                        borderColor={border}
                      >
                        <StatLabel>Webhook successes</StatLabel>
                        <StatNumber>
                          {alertData.stats.webhooksMonth || 0}
                        </StatNumber>
                      </Stat>
                      {(alertData.stats.whatsappMonth || 0) > 0 ? (
                        <Stat
                          bg={surface}
                          p={4}
                          borderRadius='md'
                          border='1px solid'
                          borderColor={border}
                        >
                          <StatLabel>WhatsApp successes</StatLabel>
                          <StatNumber>
                            {alertData.stats.whatsappMonth || 0}
                          </StatNumber>
                        </Stat>
                      ) : null}
                      <Stat
                        bg={surface}
                        p={4}
                        borderRadius='md'
                        border='1px solid'
                        borderColor={border}
                      >
                        <StatLabel>Tokens</StatLabel>
                        <StatNumber>{alertData.workspaceTokenCount}</StatNumber>
                        <StatHelpText>In this workspace</StatHelpText>
                      </Stat>
                    </SimpleGrid>
                  </Box>
                ) : null}

                {alertData.eligibleWorkspaces.length > 0 ? (
                  <SimpleGrid columns={{ base: 1, md: 2 }} spacing={4} mb={4}>
                    <Stat
                      bg={surface}
                      p={4}
                      borderRadius='md'
                      border='1px solid'
                      borderColor={border}
                    >
                      <StatLabel>Pending</StatLabel>
                      <StatNumber color='yellow.500'>
                        {alertData.queueSummary.pending || 0}
                      </StatNumber>
                      <StatHelpText>Awaiting delivery</StatHelpText>
                    </Stat>
                    <Stat
                      bg={surface}
                      p={4}
                      borderRadius='md'
                      border='1px solid'
                      borderColor={border}
                    >
                      <StatLabel>Blocked</StatLabel>
                      <StatNumber color='red.500'>
                        {alertData.queueSummary.blocked || 0}
                      </StatNumber>
                      <StatHelpText>Delivery blocked</StatHelpText>
                    </Stat>
                  </SimpleGrid>
                ) : null}
              </SectionState>

              {alertData.eligibleWorkspaces.length > 0 ? (
                <Box
                  data-tour='control-center-alert-queue'
                  bg={surface}
                  p={6}
                  borderRadius='md'
                  boxShadow='sm'
                  border='1px solid'
                  borderColor={border}
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
                      <Flex
                        align='center'
                        justify='space-between'
                        gap={3}
                        flexWrap='wrap'
                      >
                        <Heading size='md' color={text}>
                          Alert queue (workspace)
                        </Heading>
                        <Button
                          onClick={handleRefreshAll}
                          isLoading={
                            assetStats.isRefreshing || alertData.refreshing
                          }
                          size='sm'
                          variant='outline'
                          borderColor={border}
                          color={outlineButtonColor}
                          _hover={{
                            bg: outlineButtonHoverBg,
                            color: outlineButtonHoverColor,
                          }}
                        >
                          Refresh
                        </Button>
                      </Flex>
                      <VStack align='start' spacing={2}>
                        <Tooltip
                          label={alertData.requeueDisabledReason}
                          hasArrow
                          placement='top-start'
                        >
                          <Button
                            size='sm'
                            colorScheme='blue'
                            variant='solid'
                            onClick={() => alertData.requeueAlerts()}
                            isDisabled={!alertData.canRequeue}
                          >
                            Requeue blocked/failed
                          </Button>
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
                        <VStack spacing={4} py={4}>
                          <Text color={muted} fontSize='lg'>
                            No pending or failed alerts
                          </Text>
                        </VStack>
                      ) : (
                        <Box overflowX='auto'>
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
                                  alert.channel === 'email'
                                    ? typeof alert.attempts_email === 'number'
                                      ? alert.attempts_email
                                      : alert.attempts
                                    : alert.channel === 'webhooks'
                                      ? typeof alert.attempts_webhooks ===
                                        'number'
                                        ? alert.attempts_webhooks
                                        : alert.attempts
                                      : alert.attempts;

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
                      )}
                    </VStack>
                  </SectionState>
                </Box>
              ) : null}
            </VStack>
          </Box>
        </DashboardShell>
      </Box>
    </>
  );
}
