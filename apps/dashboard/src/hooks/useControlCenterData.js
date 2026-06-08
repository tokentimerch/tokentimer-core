import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import apiClient, {
  API_ENDPOINTS,
  alertAPI,
  tokenAPI,
  formatDate,
  workspaceAPI,
} from '../utils/apiClient';
import { useWorkspace } from '../utils/WorkspaceContext.jsx';
import { logger } from '../utils/logger';

const ELIGIBLE_ROLES = new Set(['admin', 'workspace_manager']);

/**
 * Load alert queue, delivery stats, and workspace context for Control Center.
 *
 * @param {string} [initialWorkspaceId]
 */
export function useControlCenterData(initialWorkspaceId = '') {
  const { workspaceId, selectWorkspace } = useWorkspace();
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState('');
  const [unauthorized, setUnauthorized] = useState(false);
  const [queue, setQueue] = useState([]);
  const [stats, setStats] = useState({ byChannel: [], monthUsage: 0 });
  const [orgStats, setOrgStats] = useState({ monthUsage: 0 });
  const [orgWorkspaceCount, setOrgWorkspaceCount] = useState(0);
  const [workspaceMemberCount, setWorkspaceMemberCount] = useState(0);
  const [workspaces, setWorkspaces] = useState([]);
  const [selectedWorkspaceId, setSelectedWorkspaceId] = useState(
    initialWorkspaceId || workspaceId || ''
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
  const [retryHintDate, setRetryHintDate] = useState(null);
  const [partial, setPartial] = useState(false);

  const lastLoadedRef = useRef('');
  const loadGenerationRef = useRef(0);

  const loadData = useCallback(
    async (isRefresh = false) => {
      const generation = ++loadGenerationRef.current;
      try {
        if (isRefresh) {
          setRefreshing(true);
        } else {
          setLoading(true);
        }
        setError('');
        setUnauthorized(false);
        setPartial(false);

        const wsRes = await apiClient.get(
          '/api/v1/workspaces?limit=100&offset=0'
        );
        const wsItems = wsRes?.data?.items || [];

        if (generation !== loadGenerationRef.current) return;

        setWorkspaces(wsItems);
        setOrgWorkspaceCount(wsItems.length);

        const adminAny = wsItems.some(
          workspace => String(workspace.role).toLowerCase() === 'admin'
        );
        setIsAdminAny(adminAny);

        const hasManagerOrViewer = wsItems.some(workspace => {
          const role = String(workspace.role).toLowerCase();
          return role === 'workspace_manager' || role === 'viewer';
        });
        setHasManagerOrViewerRole(hasManagerOrViewer);

        const selectedItem =
          wsItems.find(workspace => workspace.id === selectedWorkspaceId) ||
          null;
        const selectedIsEligible = selectedItem
          ? ELIGIBLE_ROLES.has(String(selectedItem.role).toLowerCase())
          : false;
        const eligibleWorkspaces = wsItems.filter(workspace =>
          ELIGIBLE_ROLES.has(String(workspace.role).toLowerCase())
        );

        if (!selectedWorkspaceId && eligibleWorkspaces.length > 0) {
          setSelectedWorkspaceId(eligibleWorkspaces[0].id);
        }

        const effectiveWorkspaceId = selectedIsEligible
          ? selectedWorkspaceId
          : eligibleWorkspaces[0]?.id || '';

        lastLoadedRef.current =
          selectedWorkspaceId || effectiveWorkspaceId || '__none__';

        if (eligibleWorkspaces.length > 0 || wsItems.length <= 1) {
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

          if (generation !== loadGenerationRef.current) return;

          const queueData = queueRes?.data || {};
          const statsData = statsRes?.data || {};
          const planData = planRes?.data || {};
          setQueue(queueData.alerts || []);

          const byChannel = Array.isArray(statsData.byChannel)
            ? [...statsData.byChannel].sort((a, b) => {
                const rateA = a.attempts ? a.successes / a.attempts : 0;
                const rateB = b.attempts ? b.successes / b.attempts : 0;
                return rateB - rateA;
              })
            : [];

          const emailRow = byChannel.find(
            row => String(row.channel || '').toLowerCase() === 'email'
          );
          const emailsMonth = emailRow ? Number(emailRow.successes || 0) : 0;
          const webhooksRow = byChannel.find(
            row => String(row.channel || '').toLowerCase() === 'webhooks'
          );
          const webhooksMonth = webhooksRow
            ? Number(webhooksRow.successes || 0)
            : 0;
          const whatsappRow = byChannel.find(
            row => String(row.channel || '').toLowerCase() === 'whatsapp'
          );
          const whatsappMonth = whatsappRow
            ? Number(whatsappRow.successes || 0)
            : 0;

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
              Number(emailsMonth) +
              Number(webhooksMonth) +
              Number(whatsappMonth),
          });
          setPlanInfo({
            plan: planData.plan || 'oss',
            alertLimitMonth: planData.alertLimitMonth || 30,
            tokenCount: planData.tokenCount || 0,
            tokenLimit: planData.tokenLimit || 0,
            memberCount: Math.max(1, planData.memberCount || 0),
            memberLimit:
              planData.memberLimit === Infinity ? 0 : planData.memberLimit || 0,
            workspaceLimit:
              planData.workspaceLimit === Infinity
                ? 0
                : planData.workspaceLimit || 0,
          });

          setOrgStats({ monthUsage: orgRes?.data?.monthUsage || 0 });

          const workspaceTokens = tokensRes?.items || [];
          setWorkspaceTokenCount(workspaceTokens.length);
          setWorkspaceMemberCount(
            Array.isArray(membersRes?.items) ? membersRes.items.length : 0
          );

          const now = new Date();
          setRetryHintDate(new Date(now.getFullYear(), now.getMonth() + 1, 1));
        } else {
          try {
            const planRes = await apiClient.get(API_ENDPOINTS.ACCOUNT_PLAN);
            const planData = planRes?.data || {};
            setPlanInfo(planData);
          } catch (planError) {
            logger.warn('Failed to load plan info for viewer:', planError);
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
      } catch (err) {
        if (generation !== loadGenerationRef.current) return;

        const httpStatus = err?.response?.status;
        if (httpStatus === 403) {
          setUnauthorized(true);
          setError(
            err?.response?.data?.error ||
              'You do not have access to control center data for this workspace.'
          );
        } else {
          setError(
            err?.response?.data?.error ||
              err?.message ||
              'Failed to load usage data'
          );
        }
      } finally {
        if (generation === loadGenerationRef.current) {
          setLoading(false);
          setRefreshing(false);
        }
      }
    },
    [selectedWorkspaceId]
  );

  useEffect(() => {
    loadData(false);
  }, [loadData]);

  useEffect(() => {
    if (workspaceId && workspaceId !== selectedWorkspaceId) {
      setSelectedWorkspaceId(workspaceId);
    }
    if (!workspaceId) {
      setSelectedWorkspaceId('');
    }
  }, [workspaceId, selectedWorkspaceId]);

  const refresh = useCallback(() => loadData(true), [loadData]);

  const eligibleWorkspaces = useMemo(
    () =>
      workspaces.filter(workspace =>
        ELIGIBLE_ROLES.has(String(workspace.role).toLowerCase())
      ),
    [workspaces]
  );

  const noEligibleAccess =
    !loading &&
    !refreshing &&
    eligibleWorkspaces.length === 0 &&
    workspaces.length > 0;

  const queueSummary = useMemo(
    () =>
      queue.reduce((acc, alert) => {
        acc[alert.status] = (acc[alert.status] || 0) + 1;
        return acc;
      }, {}),
    [queue]
  );

  const atLimit =
    (planInfo?.alertLimitMonth || 0) > 0 &&
    (stats?.monthUsage || 0) >= (planInfo?.alertLimitMonth || 0);

  const canRequeue =
    Boolean(selectedWorkspaceId) &&
    eligibleWorkspaces.some(
      workspace => workspace.id === selectedWorkspaceId
    ) &&
    !atLimit;

  const requeueDisabledReason = atLimit
    ? `Monthly limit reached. ${
        retryHintDate
          ? `Delivery resumes on ${formatDate(retryHintDate)}.`
          : 'Delivery resumes next month.'
      }`
    : !selectedWorkspaceId
      ? 'Select a workspace first'
      : 'Requeue failed or plan-limit blocked alerts for this workspace';

  const requeueAlerts = useCallback(async () => {
    try {
      await alertAPI.requeueAlerts({
        workspaceId: selectedWorkspaceId || null,
      });
      await loadData(true);
    } catch (err) {
      logger.warn('Failed to requeue alerts', err);
    }
  }, [loadData, selectedWorkspaceId]);

  const handleSetSelectedWorkspaceId = useCallback(
    id => {
      setSelectedWorkspaceId(id);
      if (id) {
        selectWorkspace(id, { replace: true });
      }
    },
    [selectWorkspace]
  );

  return {
    loading,
    refreshing,
    error,
    unauthorized,
    partial,
    noEligibleAccess,
    queue,
    stats,
    orgStats,
    orgWorkspaceCount,
    workspaceMemberCount,
    workspaces,
    selectedWorkspaceId,
    setSelectedWorkspaceId: handleSetSelectedWorkspaceId,
    isAdminAny,
    hasManagerOrViewerRole,
    planInfo,
    workspaceTokenCount,
    retryHintDate,
    eligibleWorkspaces,
    queueSummary,
    canRequeue,
    requeueDisabledReason,
    requeueAlerts,
    loadData,
    refresh,
  };
}
