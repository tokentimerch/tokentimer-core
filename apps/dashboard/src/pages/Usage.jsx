import { useEffect, useRef, useState } from 'react';
import {
  Box,
  Heading,
  Text,
  VStack,
  HStack,
  useColorModeValue,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  Badge,
  Button,
  Tooltip,
  Alert,
  AlertIcon,
  AlertDescription,
  SimpleGrid,
  Stat,
  StatLabel,
  StatNumber,
  StatHelpText,
  Select,
} from '@chakra-ui/react';
import apiClient, {
  API_ENDPOINTS,
  alertAPI,
  tokenAPI,
  formatDate,
  workspaceAPI,
} from '../utils/apiClient';
import Navigation from '../components/Navigation';
import SEO from '../components/SEO.jsx';
import TruncatedText from '../components/TruncatedText';
import { useWorkspace } from '../utils/WorkspaceContext.jsx';
import { logger } from '../utils/logger';

export default function Usage({
  session,
  onLogout,
  onAccountClick,
  onNavigateToDashboard,
  onNavigateToLanding,
}) {
  const { workspaceId, selectWorkspace } = useWorkspace();
  const [loading, setLoading] = useState(true);
  const [queue, setQueue] = useState([]);
  const [stats, setStats] = useState({ byChannel: [], monthUsage: 0 });
  const [_orgStats, setOrgStats] = useState({ monthUsage: 0 });
  const [_orgWorkspaceCount, setOrgWorkspaceCount] = useState(0);
  const [_workspaceMemberCount, setWorkspaceMemberCount] = useState(0);
  const [workspaces, setWorkspaces] = useState([]);
  const [selectedWorkspaceId, setSelectedWorkspaceId] = useState(
    workspaceId || ''
  );
  const [isAdminAny, setIsAdminAny] = useState(false);
  const [hasManagerOrViewerRole, setHasManagerOrViewerRole] = useState(false);
  const [planInfo, setPlanInfo] = useState({
    plan: 'oss',
    alertLimitMonth: 30,
    tokenCount: 0,
    tokenLimit: 0,
  });
  const [workspaceTokenCount, setWorkspaceTokenCount] = useState(0);

  const [_upgrading] = useState(false);
  const [_downgrading] = useState(false);
  const [error, setError] = useState('');
  const [refreshing, setRefreshing] = useState(false);
  const [retryHintDate, setRetryHintDate] = useState(null);
  const lastLoadedRef = useRef('');
  const loadGenerationRef = useRef(0);

  const cardBg = useColorModeValue('rgba(255, 255, 255, 0.95)', 'gray.800');
  const borderColor = useColorModeValue('gray.400', 'gray.600');
  const subtextColor = useColorModeValue('gray.600', 'gray.400');
  const selectBg = useColorModeValue('rgba(255, 255, 255, 0.72)', 'gray.800');
  const selectBorder = useColorModeValue('gray.200', 'gray.600');
  const selectColor = useColorModeValue('gray.800', 'gray.100');
  const selectHoverBorder = useColorModeValue('gray.300', 'gray.500');
  const selectFocusBorder = useColorModeValue('blue.500', 'blue.300');

  const loadData = async (isRefresh = false) => {
    const generation = ++loadGenerationRef.current;
    try {
      if (isRefresh) {
        setRefreshing(true);
      } else {
        setLoading(true);
      }
      setError('');
      // Load workspaces first so we can determine role-based access before calling stats
      const wsRes = await apiClient.get(
        '/api/v1/workspaces?limit=100&offset=0'
      );
      const wsItems = wsRes?.data?.items || [];

      // Discard results if a newer load was started (prevents stale concurrent loads from overwriting state)
      if (generation !== loadGenerationRef.current) return;

      setWorkspaces(wsItems);
      setOrgWorkspaceCount(wsItems.length);
      const eligibleRoles = new Set(['admin', 'workspace_manager']);
      const adminAny = wsItems.some(
        w => String(w.role).toLowerCase() === 'admin'
      );
      setIsAdminAny(adminAny);

      // Check if user has workspace_manager or viewer role in ANY workspace
      const hasManagerOrViewer = wsItems.some(w => {
        const role = String(w.role).toLowerCase();
        return role === 'workspace_manager' || role === 'viewer';
      });
      setHasManagerOrViewerRole(hasManagerOrViewer);

      // Determine if the currently selected workspace is eligible (manager/admin)
      const selectedItem =
        wsItems.find(w => w.id === selectedWorkspaceId) || null;
      const selectedIsEligible = selectedItem
        ? eligibleRoles.has(String(selectedItem.role))
        : false;
      const eligibleWorkspaces = wsItems.filter(w =>
        eligibleRoles.has(String(w.role))
      );

      // Auto-select first eligible workspace if none selected (UI sync only, continue loading)
      if (!selectedWorkspaceId && eligibleWorkspaces.length > 0) {
        setSelectedWorkspaceId(eligibleWorkspaces[0].id);
      }
      if (selectedWorkspaceId && !selectedIsEligible) {
        // Avoid 403s: do not keep a viewer-only selection that would trigger restricted calls
        // Keep the state for UI but ensure we don't call restricted endpoints below
      }

      // Use an effective workspace id for privileged endpoints (stats, members, etc.) only if eligible
      const effectiveWorkspaceId = selectedIsEligible
        ? selectedWorkspaceId
        : eligibleWorkspaces[0]?.id || '';

      // Record the target we are about to fetch for to prevent duplicate re-fetch
      lastLoadedRef.current =
        selectedWorkspaceId || effectiveWorkspaceId || '__none__';

      // For users with eligible workspaces, make API calls
      // For viewers without eligible workspaces, skip API calls to avoid 403 errors
      if (eligibleWorkspaces.length > 0 || wsItems.length <= 1) {
        // Prepare parallel requests
        const queuePromise = effectiveWorkspaceId
          ? apiClient.get(API_ENDPOINTS.ALERT_QUEUE, {
              params: { workspace_id: effectiveWorkspaceId },
            })
          : apiClient.get(API_ENDPOINTS.ALERT_QUEUE);
        const statsPromise = effectiveWorkspaceId
          ? apiClient.get(API_ENDPOINTS.ALERT_STATS, {
              params: { workspace_id: effectiveWorkspaceId },
            })
          : Promise.resolve({ data: { byChannel: [], monthUsage: 0 } });
        const planPromise = effectiveWorkspaceId
          ? apiClient.get(API_ENDPOINTS.ACCOUNT_PLAN, {
              params: { workspace_id: effectiveWorkspaceId },
            })
          : apiClient.get(API_ENDPOINTS.ACCOUNT_PLAN);
        const tokensPromise = effectiveWorkspaceId
          ? tokenAPI.getTokens({ workspace_id: effectiveWorkspaceId })
          : tokenAPI.getTokens();
        const membersPromise = effectiveWorkspaceId
          ? workspaceAPI
              .listMembers(effectiveWorkspaceId, 100, 0)
              .catch(() => ({ items: [] }))
          : Promise.resolve({ items: [] });
        const orgUsagePromise = adminAny
          ? apiClient
              .get('/api/organization/usage')
              .catch(() => ({ data: { monthUsage: 0 } }))
          : Promise.resolve({ data: { monthUsage: 0 } });

        const [queueRes, statsRes, planRes, tokensRes, membersRes, orgRes] =
          await Promise.all([
            queuePromise,
            statsPromise,
            planPromise,
            tokensPromise,
            membersPromise,
            orgUsagePromise,
          ]);

        // Discard results if a newer load was started
        if (generation !== loadGenerationRef.current) return;

        const queueData = queueRes?.data || {};
        const statsData = statsRes?.data || {};
        const planData = planRes?.data || {};
        setQueue(queueData.alerts || []);

        // Sort byChannel with successes-first, failures-last (by success rate desc)
        const byChannel = Array.isArray(statsData.byChannel)
          ? [...statsData.byChannel].sort((a, b) => {
              const ra = a.attempts ? a.successes / a.attempts : 0;
              const rb = b.attempts ? b.successes / b.attempts : 0;
              return rb - ra;
            })
          : [];

        // Extract email/webhooks successes for the current month from delivery stats
        const emailRow = byChannel.find(
          r => String(r.channel || '').toLowerCase() === 'email'
        );
        const emailsMonth = emailRow ? Number(emailRow.successes || 0) : 0;
        const webhooksRow = byChannel.find(
          r => String(r.channel || '').toLowerCase() === 'webhooks'
        );
        const webhooksMonth = webhooksRow
          ? Number(webhooksRow.successes || 0)
          : 0;
        const whatsappRow = byChannel.find(
          r => String(r.channel || '').toLowerCase() === 'whatsapp'
        );
        const whatsappMonth = whatsappRow
          ? Number(whatsappRow.successes || 0)
          : 0;

        // When no workspace is selected, fall back to organization-level month usage from plan API
        // If we fetched workspace-scoped stats (eligible role), use them; otherwise fall back to org/user plan usage
        // Note: monthUsage now excludes WhatsApp and represents Email+Webhooks only
        const didFetchWorkspaceStats = Boolean(effectiveWorkspaceId);
        const effectiveMonthUsage = didFetchWorkspaceStats
          ? statsData.monthUsage || 0
          : planData.alertUsageMonth || 0;

        setStats({
          byChannel,
          monthUsage: effectiveMonthUsage,
          emailsMonth,
          webhooksMonth,
          whatsappMonth,
          allMonthSuccesses:
            Number(emailsMonth) + Number(webhooksMonth) + Number(whatsappMonth),
        });
        setPlanInfo({
          plan: planData.plan || 'oss',
          alertLimitMonth: planData.alertLimitMonth || 30,
          tokenCount: planData.tokenCount || 0,
          tokenLimit: planData.tokenLimit || 0,
          memberCount: Math.max(1, planData.memberCount || 0), // at least the admin
          memberLimit:
            planData.memberLimit === Infinity ? 0 : planData.memberLimit || 0,
          workspaceLimit:
            planData.workspaceLimit === Infinity
              ? 0
              : planData.workspaceLimit || 0,
        });

        // Workspaces were already loaded earlier

        // Org-level usage (admin only) — already fetched in parallel
        setOrgStats({ monthUsage: orgRes?.data?.monthUsage || 0 });

        // Workspace token and member counts
        const workspaceTokens = tokensRes?.items || [];
        setWorkspaceTokenCount(workspaceTokens.length);
        setWorkspaceMemberCount(
          Array.isArray(membersRes?.items) ? membersRes.items.length : 0
        );

        // Compute retry hint date: anchored to earliest token creation, 30-day cycles
        const tokens = workspaceTokens;
        let earliestCreated = null;
        for (const t of tokens) {
          if (t?.created_at) {
            const d = new Date(t.created_at);
            if (!isNaN(d)) {
              if (!earliestCreated || d < earliestCreated) earliestCreated = d;
            }
          }
        }
        // Show plan reset date as the first day of next month
        const now2 = new Date();
        setRetryHintDate(new Date(now2.getFullYear(), now2.getMonth() + 1, 1));
      } else {
        // For viewers without eligible workspaces, just load basic plan info
        try {
          const planRes = await apiClient.get(API_ENDPOINTS.ACCOUNT_PLAN);
          const planData = planRes?.data || {};
          setPlanInfo(planData);
        } catch (planError) {
          logger.warn('Failed to load plan info for viewer:', planError);
          // Set default plan info for viewers
          setPlanInfo({
            plan: 'oss',
            alertLimitMonth: 100,
            tokenCount: 0,
            tokenLimit: 50,
          });
        }
        setQueue([]);
        setStats({ byChannel: [], monthUsage: 0 });
        setWorkspaceTokenCount(0);
        setWorkspaceMemberCount(0);
        setOrgStats({ monthUsage: 0 });
      }
    } catch (e) {
      if (generation === loadGenerationRef.current) {
        setError('Failed to load usage data');
      }
    } finally {
      if (generation === loadGenerationRef.current) {
        setLoading(false);
        setRefreshing(false);
      }
    }
  };

  useEffect(() => {
    loadData();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedWorkspaceId]);

  // Sync selectedWorkspaceId with context changes
  useEffect(() => {
    if (workspaceId && workspaceId !== selectedWorkspaceId)
      setSelectedWorkspaceId(workspaceId);
    if (!workspaceId) setSelectedWorkspaceId('');
  }, [workspaceId, selectedWorkspaceId]);

  const getStatusBadge = status => {
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
      <Badge
        colorScheme={colorMap[status] || 'gray'}
        textTransform='capitalize'
      >
        {label}
      </Badge>
    );
  };

  const formatRelativeTime = dateStr => {
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
  };

  // Translate technical error messages to user-friendly text
  const friendlyErrorMessage = errorMsg => {
    if (!errorMsg) return '';
    const msg = String(errorMsg);

    // Out of window
    if (msg === 'OUT_OF_WINDOW') {
      return 'Waiting for delivery window to open';
    }

    // Other common patterns
    if (msg.includes('MAX_ATTEMPTS')) {
      return 'Max retry attempts exceeded';
    }
    if (msg.includes('NO_CONTACTS_DEFINED')) {
      return 'No contacts configured';
    }

    // Return original message if no pattern matches
    return msg;
  };

  // Calculate queue summary stats
  const queueSummary = queue.reduce((acc, alert) => {
    acc[alert.status] = (acc[alert.status] || 0) + 1;
    return acc;
  }, {});

  // Delivery usage thresholds: >=90% red, >=75% orange, else green
  const usageRatio = planInfo.alertLimitMonth
    ? Math.min(1, (stats.monthUsage || 0) / planInfo.alertLimitMonth)
    : 0;
  const usageColor =
    usageRatio >= 0.9
      ? 'red.500'
      : usageRatio >= 0.75
        ? 'orange.500'
        : 'green.500';

  // Workspaces where user has privileged role
  const eligibleWorkspaces = workspaces.filter(
    w => w.role === 'admin' || w.role === 'workspace_manager'
  );

  // Core: stats are always visible (no plan-based hiding)

  if (loading) {
    return (
      <>
        <Navigation
          user={session}
          onLogout={onLogout}
          onAccountClick={onAccountClick}
          onNavigateToDashboard={onNavigateToDashboard}
          onNavigateToLanding={onNavigateToLanding}
        />
        <Box maxW='6xl' mx='auto' p={{ base: 4, md: 6 }} overflowX='hidden'>
          <Text>Loading usage data...</Text>
        </Box>
      </>
    );
  }

  return (
    <>
      <SEO
        title='Usage'
        description='View your usage statistics and alert queue'
        noindex
      />
      <Navigation
        user={session}
        onLogout={onLogout}
        onAccountClick={onAccountClick}
        onNavigateToDashboard={onNavigateToDashboard}
        onNavigateToLanding={onNavigateToLanding}
      />
      <Box maxW='6xl' mx='auto' p={6} data-tour='usage-page'>
        <VStack spacing={6} align='stretch'>
          <HStack justify='space-between' align='center'>
            <Heading size='lg'>Usage</Heading>
            <Button
              onClick={() => loadData(true)}
              isLoading={refreshing}
              size='sm'
              variant='outline'
            >
              Refresh
            </Button>
          </HStack>

          {error && (
            <Alert status='error'>
              <AlertIcon />
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}

          {/* Organization (admin) and workspace (manager/admin) usage */}
          {isAdminAny && !hasManagerOrViewerRole && (
            <Box
              bg={cardBg}
              p={4}
              borderRadius='md'
              border='1px solid'
              borderColor={borderColor}
            >
              <Heading size='sm' mb={3}>
                Organization (admin only)
              </Heading>
              <SimpleGrid
                columns={{ base: 1, sm: 2, md: 3, lg: 5 }}
                spacing={4}
              >
                <Stat
                  bg={cardBg}
                  p={4}
                  borderRadius='md'
                  border='1px solid'
                  borderColor={borderColor}
                >
                  <StatLabel>Workspaces</StatLabel>
                  <StatNumber>{_orgWorkspaceCount}</StatNumber>
                  <StatHelpText>Across organization</StatHelpText>
                </Stat>
                <Stat
                  bg={cardBg}
                  p={4}
                  borderRadius='md'
                  border='1px solid'
                  borderColor={borderColor}
                >
                  <StatLabel>Members</StatLabel>
                  <StatNumber>{planInfo.memberCount || 0}</StatNumber>
                  <StatHelpText>Across organization</StatHelpText>
                </Stat>
                <Stat
                  bg={cardBg}
                  p={4}
                  borderRadius='md'
                  border='1px solid'
                  borderColor={borderColor}
                >
                  <StatLabel>Tokens</StatLabel>
                  <StatNumber>{planInfo.tokenCount || 0}</StatNumber>
                  <StatHelpText>Across workspaces</StatHelpText>
                </Stat>
                <Stat
                  bg={cardBg}
                  p={4}
                  borderRadius='md'
                  border='1px solid'
                  borderColor={borderColor}
                >
                  <StatLabel>Email/webhook deliveries (month)</StatLabel>
                  <StatNumber>{_orgStats.monthUsage}</StatNumber>
                  <StatHelpText>All workspaces</StatHelpText>
                </Stat>
                {(stats.whatsappMonth || 0) > 0 && (
                  <Stat
                    bg={cardBg}
                    p={4}
                    borderRadius='md'
                    border='1px solid'
                    borderColor={borderColor}
                  >
                    <StatLabel>WhatsApp deliveries (month)</StatLabel>
                    <StatNumber>{stats.whatsappMonth || 0}</StatNumber>
                    <StatHelpText>Across organization</StatHelpText>
                  </Stat>
                )}
              </SimpleGrid>
            </Box>
          )}

          {eligibleWorkspaces.length > 0 && (
            <Box
              data-tour='usage-metrics'
              bg={cardBg}
              p={4}
              borderRadius='md'
              border='1px solid'
              borderColor={borderColor}
            >
              <HStack mb={3}>
                <Text fontWeight='semibold'>Workspace:</Text>
                {eligibleWorkspaces.length === 0 ? (
                  <Text color={subtextColor}>Personal workspace</Text>
                ) : (
                  <Select
                    size='sm'
                    value={selectedWorkspaceId}
                    onChange={e => {
                      const id = e.target.value;
                      setSelectedWorkspaceId(id);
                      if (id) selectWorkspace(id, { replace: true });
                    }}
                    onClick={e => e.stopPropagation()}
                    bg={selectBg}
                    borderColor={selectBorder}
                    color={selectColor}
                    _hover={{
                      borderColor: selectHoverBorder,
                    }}
                    _focus={{
                      borderColor: selectFocusBorder,
                      boxShadow: '0 0 0 1px var(--chakra-colors-blue-500)',
                    }}
                    maxW='280px'
                  >
                    {eligibleWorkspaces.map(w => (
                      <option key={w.id} value={w.id}>
                        {w.name} ({w.role})
                      </option>
                    ))}
                  </Select>
                )}
              </HStack>
              <SimpleGrid
                columns={{ base: 1, sm: 2, md: 3, lg: 5 }}
                spacing={4}
              >
                <Stat
                  bg={cardBg}
                  p={4}
                  borderRadius='md'
                  border='1px solid'
                  borderColor={borderColor}
                >
                  <StatLabel>Successful deliveries</StatLabel>
                  <StatNumber color={usageColor}>
                    {typeof stats.allMonthSuccesses === 'number' &&
                    stats.allMonthSuccesses >= 0
                      ? stats.allMonthSuccesses
                      : stats.monthUsage}
                  </StatNumber>
                </Stat>
                <Stat
                  bg={cardBg}
                  p={4}
                  borderRadius='md'
                  border='1px solid'
                  borderColor={borderColor}
                >
                  <StatLabel>Email successes</StatLabel>
                  <StatNumber>{stats.emailsMonth || 0}</StatNumber>
                </Stat>
                <Stat
                  bg={cardBg}
                  p={4}
                  borderRadius='md'
                  border='1px solid'
                  borderColor={borderColor}
                >
                  <StatLabel>Webhook successes</StatLabel>
                  <StatNumber>{stats.webhooksMonth || 0}</StatNumber>
                </Stat>
                {(stats.whatsappMonth || 0) > 0 && (
                  <Stat
                    bg={cardBg}
                    p={4}
                    borderRadius='md'
                    border='1px solid'
                    borderColor={borderColor}
                  >
                    <StatLabel>WhatsApp successes</StatLabel>
                    <StatNumber>{stats.whatsappMonth || 0}</StatNumber>
                  </Stat>
                )}
                <Stat
                  bg={cardBg}
                  p={4}
                  borderRadius='md'
                  border='1px solid'
                  borderColor={borderColor}
                >
                  <StatLabel>Tokens</StatLabel>
                  <StatNumber>{workspaceTokenCount}</StatNumber>
                  <StatHelpText>In this workspace</StatHelpText>
                </Stat>
              </SimpleGrid>
            </Box>
          )}

          {/* Queue status (for selected workspace) - Only show for managers and admins */}
          {eligibleWorkspaces.length > 0 && (
            <SimpleGrid columns={{ base: 1, md: 2 }} spacing={4}>
              <Stat
                bg={cardBg}
                p={4}
                borderRadius='md'
                border='1px solid'
                borderColor={borderColor}
              >
                <StatLabel>Pending</StatLabel>
                <StatNumber color='yellow.500'>
                  {queueSummary.pending || 0}
                </StatNumber>
                <StatHelpText>Awaiting delivery</StatHelpText>
              </Stat>
              <Stat
                bg={cardBg}
                p={4}
                borderRadius='md'
                border='1px solid'
                borderColor={borderColor}
              >
                <StatLabel>Blocked</StatLabel>
                <StatNumber color='red.500'>
                  {queueSummary.blocked || 0}
                </StatNumber>
                <StatHelpText>Delivery blocked</StatHelpText>
              </Stat>
            </SimpleGrid>
          )}

          {/* Alert Queue - Only show for managers and admins */}
          {eligibleWorkspaces.length > 0 && (
            <Box
              data-tour='usage-alert-queue'
              bg={cardBg}
              p={6}
              borderRadius='md'
              boxShadow='sm'
              border='1px solid'
              borderColor={borderColor}
            >
              <VStack align='stretch' spacing={4}>
                <Heading size='md'>Alert Queue (workspace)</Heading>
                <VStack align='start' spacing={2}>
                  {(() => {
                    const atLimit =
                      (planInfo?.alertLimitMonth || 0) > 0 &&
                      (stats?.monthUsage || 0) >=
                        (planInfo?.alertLimitMonth || 0);
                    const btnTitle = atLimit
                      ? `Monthly limit reached. ${
                          retryHintDate
                            ? `Delivery resumes on ${formatDate(retryHintDate)}.`
                            : 'Delivery resumes next month.'
                        }`
                      : 'Requeue failed or plan-limit blocked alerts for this workspace';
                    return (
                      <HStack>
                        <Tooltip
                          label={btnTitle}
                          hasArrow
                          placement='top-start'
                        >
                          <Button
                            size='sm'
                            colorScheme='blue'
                            variant='solid'
                            title={btnTitle}
                            onClick={async () => {
                              try {
                                await alertAPI.requeueAlerts({
                                  workspaceId: selectedWorkspaceId || null,
                                });
                                await loadData(true);
                              } catch (_) {}
                            }}
                            isDisabled={!selectedWorkspaceId || atLimit}
                          >
                            Requeue blocked/failed
                          </Button>
                        </Tooltip>
                      </HStack>
                    );
                  })()}
                  <Text fontSize='xs' color={subtextColor}>
                    Admins can requeue failed alerts for the selected workspace.
                  </Text>
                </VStack>
                {workspaces.length > 0 && (
                  <HStack>
                    <Text fontWeight='semibold'>Workspace:</Text>
                    <Select
                      size='sm'
                      value={selectedWorkspaceId}
                      onChange={e => {
                        const id = e.target.value;
                        setSelectedWorkspaceId(id);
                        if (id) selectWorkspace(id, { replace: true });
                      }}
                      onClick={e => e.stopPropagation()}
                      bg={selectBg}
                      borderColor={selectBorder}
                      color={selectColor}
                      _hover={{
                        borderColor: selectHoverBorder,
                      }}
                      _focus={{
                        borderColor: selectFocusBorder,
                        boxShadow: '0 0 0 1px var(--chakra-colors-blue-500)',
                      }}
                      maxW='280px'
                    >
                      {workspaces
                        .filter(
                          w =>
                            w.role === 'admin' || w.role === 'workspace_manager'
                        )
                        .map(w => (
                          <option key={w.id} value={w.id}>
                            {w.name} ({w.role})
                          </option>
                        ))}
                    </Select>
                  </HStack>
                )}
                <Alert status='info' variant='left-accent'>
                  <AlertIcon />
                  <AlertDescription>
                    This shows alerts that are pending, blocked (failed), or
                    exceeded limits. Each row represents one delivery channel
                    (email or webhook). Successfully sent alerts are not shown
                    here but are counted in the statistics above.{' '}
                    {retryHintDate
                      ? `If you reached your monthly alerting limit, the delivery will resume on ${formatDate(retryHintDate)} (start of next month) or after the limit resets next month.`
                      : ''}
                  </AlertDescription>
                </Alert>

                {queue.length === 0 ? (
                  <VStack spacing={4} py={8}>
                    <Text color={subtextColor} fontSize='lg'>
                      No pending or failed alerts
                    </Text>
                    <Text color='gray.400' fontSize='sm' textAlign='center'>
                      Alerts appear here when they{"'"}re queued for delivery
                      but haven{"'"}t been sent yet, or when delivery has
                      failed. Successfully sent alerts are removed from this
                      queue.
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
                        {queue.map(a => {
                          const now = new Date();
                          const nextAt = a.next_attempt_at
                            ? new Date(a.next_attempt_at)
                            : null;
                          const cooldownActive = nextAt && nextAt > now;
                          const remainingMs = cooldownActive ? nextAt - now : 0;
                          const _remainingMin = Math.max(
                            0,
                            Math.floor(remainingMs / 60000)
                          );
                          const _remainingSec = Math.max(
                            0,
                            Math.floor((remainingMs % 60000) / 1000)
                          );
                          const channelAttempts =
                            a.channel === 'email'
                              ? typeof a.attempts_email === 'number'
                                ? a.attempts_email
                                : a.attempts
                              : a.channel === 'webhooks'
                                ? typeof a.attempts_webhooks === 'number'
                                  ? a.attempts_webhooks
                                  : a.attempts
                                : a.attempts;

                          return (
                            <Tr key={`${a.id}-${a.channel}`}>
                              <Td>
                                <VStack align='start' spacing={0}>
                                  <Text fontWeight='medium'>
                                    {a.token_name || `Token #${a.token_id}`}
                                  </Text>
                                  <Text fontSize='sm' color={subtextColor}>
                                    {a.token_type || 'Unknown'}
                                  </Text>
                                </VStack>
                              </Td>
                              <Td isNumeric>{a.threshold_days}</Td>
                              <Td>
                                {a.due_date
                                  ? new Date(a.due_date)
                                      .toISOString()
                                      .slice(0, 10)
                                  : '-'}
                              </Td>
                              <Td>{getStatusBadge(a.status)}</Td>
                              <Td>
                                <Badge
                                  colorScheme={
                                    a.channel === 'email' ? 'green' : 'blue'
                                  }
                                  size='sm'
                                >
                                  {a.channel_display || a.channel || 'None'}
                                </Badge>
                              </Td>
                              <Td isNumeric>{channelAttempts}</Td>
                              <Td maxW='200px'>
                                <TruncatedText
                                  text={friendlyErrorMessage(
                                    a.channel_error_message ||
                                      a.error_message ||
                                      ''
                                  )}
                                  maxLines={3}
                                  maxWidth='200px'
                                />
                              </Td>
                              <Td>{formatRelativeTime(a.updated_at)}</Td>
                            </Tr>
                          );
                        })}
                      </Tbody>
                    </Table>
                  </Box>
                )}
              </VStack>
            </Box>
          )}
        </VStack>
      </Box>
    </>
  );
}
