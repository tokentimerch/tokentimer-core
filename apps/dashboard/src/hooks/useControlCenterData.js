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
const ALERT_ACTIVITY_PAGE_SIZE = 12;
export const ALERT_ELIGIBILITY_PAGE_SIZE_OPTIONS = [5, 10, 20, 50, 100];
const ELIGIBILITY_SUMMARY_FALLBACK_PAGE_SIZE = 500;

async function loadEligibilitySummary(workspaceId) {
  try {
    const response = await apiClient.get(
      API_ENDPOINTS.WORKSPACE_CONTROL_CENTER_ALERT_ELIGIBILITY_SUMMARY(
        workspaceId
      ),
      { _suppressLog: true }
    );
    return response.data;
  } catch (summaryError) {
    // A locally running API can lag behind the dashboard while the new route
    // is being rolled out. Use the existing paginated token API in that case.
    if (summaryError?.response?.status !== 404) throw summaryError;
  }

  const counts = { outside_threshold: 0, due: 0, suppressed: 0 };
  let offset = 0;
  let total = 0;
  do {
    const page = await tokenAPI.getTokens({
      workspace_id: workspaceId,
      limit: ELIGIBILITY_SUMMARY_FALLBACK_PAGE_SIZE,
      offset,
    });
    const items = page.items || [];
    total = page.total || 0;
    for (const token of items) {
      const status = token.alert_state?.eligibility?.status;
      if (Object.hasOwn(counts, status)) counts[status]++;
    }
    offset += items.length;
    if (items.length === 0) break;
  } while (offset < total);
  return { total, counts };
}

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
  const [eligibilityAssets, setEligibilityAssets] = useState([]);
  const [eligibilitySummary, setEligibilitySummary] = useState({
    outside_threshold: 0,
    due: 0,
    suppressed: 0,
  });
  const [eligibilityTotal, setEligibilityTotal] = useState(0);
  const [eligibilityWorkspaceId, setEligibilityWorkspaceId] = useState('');
  const [eligibilityLimit, setEligibilityLimit] = useState(10);
  const [eligibilityOffset, setEligibilityOffset] = useState(0);
  const [eligibilityLoading, setEligibilityLoading] = useState(false);
  const [eligibilityError, setEligibilityError] = useState('');
  const [eligibilityReloadTick, setEligibilityReloadTick] = useState(0);
  const [stats, setStats] = useState({ byChannel: [], monthUsage: 0 });
  const [orgStats, setOrgStats] = useState({ monthUsage: 0 });
  const [orgWorkspaceCount, setOrgWorkspaceCount] = useState(0);
  const [orgTokenCount, setOrgTokenCount] = useState(0);
  const [workspaceMemberCount, setWorkspaceMemberCount] = useState(0);
  const [workspaces, setWorkspaces] = useState([]);
  const [selectedWorkspaceId, setSelectedWorkspaceId] = useState(
    initialWorkspaceId || workspaceId || ''
  );
  const [isAdminAny, setIsAdminAny] = useState(false);
  const [hasManagerOrViewerRole, setHasManagerOrViewerRole] = useState(false);
  const [planInfo, setPlanInfo] = useState({
    plan: 'oss',
    // 0 means "no monthly alerting limit configured", matching the
    // memberLimit/workspaceLimit convention below.
    alertLimitMonth: 0,
    tokenCount: 0,
    tokenLimit: 0,
  });
  const [workspaceTokenCount, setWorkspaceTokenCount] = useState(0);
  const [retryHintDate, setRetryHintDate] = useState(null);
  const [partial, setPartial] = useState(false);
  const [alertActivity, setAlertActivity] = useState([]);
  const [alertActivityLoading, setAlertActivityLoading] = useState(false);
  const [alertActivityLoadingMore, setAlertActivityLoadingMore] =
    useState(false);
  const [alertActivityError, setAlertActivityError] = useState('');
  const [alertActivityHasMore, setAlertActivityHasMore] = useState(false);

  const lastLoadedRef = useRef('');
  const loadGenerationRef = useRef(0);
  const eligibilityGenerationRef = useRef(0);

  useEffect(() => {
    const generation = ++eligibilityGenerationRef.current;
    let active = true;
    if (!eligibilityWorkspaceId) {
      setEligibilityAssets([]);
      setEligibilityLoading(false);
      return;
    }
    setEligibilityLoading(true);
    setEligibilityError('');
    tokenAPI
      .getTokens({
        workspace_id: eligibilityWorkspaceId,
        limit: eligibilityLimit,
        offset: eligibilityOffset,
      })
      .then(page => {
        if (!active || generation !== eligibilityGenerationRef.current) return;
        const total = page.total || 0;
        if (eligibilityOffset > 0 && eligibilityOffset >= total) {
          setEligibilityOffset(
            total > 0
              ? Math.floor((total - 1) / eligibilityLimit) * eligibilityLimit
              : 0
          );
          return;
        }
        setEligibilityAssets(
          (page.items || []).filter(token => token.alert_state?.eligibility)
        );
        setEligibilityTotal(total);
      })
      .catch(pageError => {
        if (!active || generation !== eligibilityGenerationRef.current) return;
        setEligibilityError(
          pageError?.message || 'Failed to load eligibility page'
        );
        setEligibilityAssets([]);
      })
      .finally(() => {
        if (active && generation === eligibilityGenerationRef.current)
          setEligibilityLoading(false);
      });
    return () => {
      active = false;
    };
  }, [
    eligibilityWorkspaceId,
    eligibilityLimit,
    eligibilityOffset,
    eligibilityReloadTick,
  ]);

  const loadData = useCallback(
    async (isRefresh = false) => {
      const generation = ++loadGenerationRef.current;
      setAlertActivityLoadingMore(false);
      try {
        if (isRefresh) {
          setRefreshing(true);
        } else {
          setLoading(true);
        }
        setError('');
        setUnauthorized(false);
        setPartial(false);
        setAlertActivityLoading(true);
        setAlertActivityError('');

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
          const defaultWorkspaceId = eligibleWorkspaces[0].id;
          setSelectedWorkspaceId(defaultWorkspaceId);
          selectWorkspace(defaultWorkspaceId, { replace: true });
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
          // Selected plan data is workspace-scoped; this aggregate value backs
          // the "Across workspaces" organization card.
          const orgPlanPromise = adminAny
            ? apiClient
                .get(API_ENDPOINTS.ACCOUNT_PLAN)
                .catch(() => ({ data: { tokenCount: 0 } }))
            : Promise.resolve({ data: { tokenCount: 0 } });
          const eligibilitySummaryPromise = effectiveWorkspaceId
            ? loadEligibilitySummary(effectiveWorkspaceId)
            : Promise.resolve({ total: 0, counts: {} });
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
          const alertActivityPromise = effectiveWorkspaceId
            ? apiClient
                .get(
                  API_ENDPOINTS.WORKSPACE_CONTROL_CENTER_ALERT_ACTIVITY(
                    effectiveWorkspaceId
                  ),
                  { params: { limit: ALERT_ACTIVITY_PAGE_SIZE, offset: 0 } }
                )
                .then(response => ({ data: response.data, error: null }))
                .catch(activityError => ({
                  data: null,
                  error:
                    activityError?.response?.data?.error ||
                    activityError?.message ||
                    'Failed to load recent alert activity',
                }))
            : Promise.resolve({
                data: {
                  items: [],
                  pagination: { hasMore: false },
                },
                error: null,
              });

          const [
            queueRes,
            statsRes,
            planRes,
            orgPlanRes,
            eligibilitySummaryRes,
            membersRes,
            orgRes,
            activityResult,
          ] = await Promise.all([
            queuePromise,
            statsPromise,
            planPromise,
            orgPlanPromise,
            eligibilitySummaryPromise,
            membersPromise,
            orgUsagePromise,
            alertActivityPromise,
          ]);

          if (generation !== loadGenerationRef.current) return;

          const queueData = queueRes?.data || {};
          const statsData = statsRes?.data || {};
          const planData = planRes?.data || {};
          const orgPlanData = orgPlanRes?.data || {};
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
            alertLimitMonth:
              planData.alertLimitMonth === Infinity
                ? 0
                : planData.alertLimitMonth || 0,
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
          setOrgTokenCount(orgPlanData.tokenCount || 0);

          const summaryData = eligibilitySummaryRes || {};
          setEligibilitySummary({
            outside_threshold: summaryData.counts?.outside_threshold || 0,
            due: summaryData.counts?.due || 0,
            suppressed: summaryData.counts?.suppressed || 0,
          });
          setWorkspaceTokenCount(summaryData.total || 0);
          setEligibilityWorkspaceId(effectiveWorkspaceId);
          setEligibilityReloadTick(tick => tick + 1);
          setWorkspaceMemberCount(
            Array.isArray(membersRes?.items) ? membersRes.items.length : 0
          );
          setAlertActivity(activityResult.data?.items || []);
          setAlertActivityHasMore(
            Boolean(activityResult.data?.pagination?.hasMore)
          );
          setAlertActivityError(activityResult.error || '');

          const now = new Date();
          setRetryHintDate(new Date(now.getFullYear(), now.getMonth() + 1, 1));
        } else {
          try {
            const planRes = await apiClient.get(API_ENDPOINTS.ACCOUNT_PLAN);
            const planData = planRes?.data || {};
            setPlanInfo(planData);
            setOrgTokenCount(planData.tokenCount || 0);
          } catch (planError) {
            logger.warn('Failed to load plan info for viewer:', planError);
            setPlanInfo({
              plan: 'oss',
              alertLimitMonth: 0,
              tokenCount: 0,
              tokenLimit: 0,
            });
            setOrgTokenCount(0);
          }
          setQueue([]);
          setEligibilityAssets([]);
          setEligibilityWorkspaceId('');
          setEligibilitySummary({
            outside_threshold: 0,
            due: 0,
            suppressed: 0,
          });
          setEligibilityTotal(0);
          setStats({ byChannel: [], monthUsage: 0 });
          setWorkspaceTokenCount(0);
          setWorkspaceMemberCount(0);
          setOrgStats({ monthUsage: 0 });
          setOrgTokenCount(0);
          setAlertActivity([]);
          setAlertActivityHasMore(false);
          setAlertActivityError('');
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
          setAlertActivityLoading(false);
        }
      }
    },
    [selectedWorkspaceId, selectWorkspace]
  );

  useEffect(() => {
    loadData(false);
  }, [loadData]);

  useEffect(() => {
    if (workspaceId && workspaceId !== selectedWorkspaceId) {
      setEligibilityOffset(0);
      setEligibilityAssets([]);
      setEligibilityTotal(0);
      setEligibilitySummary({ outside_threshold: 0, due: 0, suppressed: 0 });
      setEligibilityWorkspaceId('');
      setSelectedWorkspaceId(workspaceId);
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

  const changeEligibilityPage = useCallback(({ limit, offset }) => {
    setEligibilityLimit(limit);
    setEligibilityOffset(offset);
  }, []);

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

  const loadMoreAlertActivity = useCallback(async () => {
    if (
      !selectedWorkspaceId ||
      !alertActivityHasMore ||
      alertActivityLoadingMore
    ) {
      return;
    }
    const generation = loadGenerationRef.current;
    setAlertActivityLoadingMore(true);
    setAlertActivityError('');
    try {
      const response = await apiClient.get(
        API_ENDPOINTS.WORKSPACE_CONTROL_CENTER_ALERT_ACTIVITY(
          selectedWorkspaceId
        ),
        {
          params: {
            limit: ALERT_ACTIVITY_PAGE_SIZE,
            offset: alertActivity.length,
          },
        }
      );
      if (generation !== loadGenerationRef.current) return;
      const page = response?.data || {};
      setAlertActivity(current => [...current, ...(page.items || [])]);
      setAlertActivityHasMore(Boolean(page.pagination?.hasMore));
    } catch (activityError) {
      if (generation !== loadGenerationRef.current) return;
      setAlertActivityError(
        activityError?.response?.data?.error ||
          activityError?.message ||
          'Failed to load recent alert activity'
      );
    } finally {
      if (generation === loadGenerationRef.current) {
        setAlertActivityLoadingMore(false);
      }
    }
  }, [
    alertActivity.length,
    alertActivityHasMore,
    alertActivityLoadingMore,
    selectedWorkspaceId,
  ]);

  const handleSetSelectedWorkspaceId = useCallback(
    id => {
      ++loadGenerationRef.current;
      setAlertActivityLoadingMore(false);
      setEligibilityOffset(0);
      setEligibilityAssets([]);
      setEligibilityTotal(0);
      setEligibilitySummary({ outside_threshold: 0, due: 0, suppressed: 0 });
      setEligibilityWorkspaceId('');
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
    eligibilityAssets,
    eligibilitySummary,
    eligibilityTotal,
    eligibilityLimit,
    eligibilityOffset,
    eligibilityLoading,
    eligibilityError,
    changeEligibilityPage,
    stats,
    orgStats,
    orgWorkspaceCount,
    orgTokenCount,
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
    alertActivity,
    alertActivityLoading,
    alertActivityLoadingMore,
    alertActivityError,
    alertActivityHasMore,
    loadMoreAlertActivity,
  };
}
