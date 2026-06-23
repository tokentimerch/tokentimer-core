import { useEffect, useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Box,
  Text,
  Flex,
  HStack,
  VStack,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  Badge,
  Select,
  Input,
  InputGroup,
  InputLeftElement,
  Button,
  IconButton,
  useColorModeValue,
} from '@chakra-ui/react';
import {
  FiBriefcase,
  FiChevronDown,
  FiChevronRight,
  FiChevronUp,
  FiDownload,
  FiRefreshCw,
  FiSearch,
  FiUser,
} from 'react-icons/fi';
import DashboardShell from '../components/DashboardShell';
import { useDashboardShellProps } from '../hooks/useDashboardShellProps';
import SEO from '../components/SEO.jsx';
import { useDashboardTheme } from '../hooks/useDashboardTheme';
import TruncatedText from '../components/TruncatedText';
import apiClient, {
  API_ENDPOINTS,
  alertAPI,
  workspaceAPI,
} from '../utils/apiClient';
import { useWorkspace } from '../utils/WorkspaceContext.jsx';

function _download(filename, text, type = 'text/plain') {
  const element = document.createElement('a');
  const file = new Blob([text], { type });
  element.href = URL.createObjectURL(file);
  element.download = filename;
  document.body.appendChild(element);
  element.click();
  document.body.removeChild(element);
}

function formatDateTime(dateString) {
  try {
    const d = new Date(dateString);
    return d.toLocaleString();
  } catch (_) {
    return String(dateString || '');
  }
}

const AUDIT_FILTER_VALUE_RE = /^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2})?$/;
const AUDIT_DATE_ONLY_RE = /^\d{4}-\d{2}-\d{2}$/;

function dateInputToAuditDateParam(value, boundary = 'start') {
  if (!value || !AUDIT_FILTER_VALUE_RE.test(value)) return null;

  if (AUDIT_DATE_ONLY_RE.test(value)) {
    const localDate =
      boundary === 'end'
        ? new Date(`${value}T23:59:59.999`)
        : new Date(`${value}T00:00:00`);
    if (Number.isNaN(localDate.getTime())) return null;
    return localDate.toISOString();
  }

  const normalized = value.length === 16 ? `${value}:00` : value;
  const date = new Date(normalized);
  if (Number.isNaN(date.getTime())) return null;
  return date.toISOString();
}

// Exhaustive list of all possible audit actions
// This allows filtering for any action type, even if not present in the current loaded events
const ALL_ACTION_TYPES = [
  // Authentication
  'LOGIN_SUCCESS',
  'LOGIN_FAILED',
  'LOGIN_SUCCESS_2FA',
  'MEMBERSHIP_SYNCED_FROM_SSO',
  'LOGOUT',
  'PASSWORD_CHANGED',
  'PASSWORD_RESET_REQUESTED',
  'PASSWORD_RESET_COMPLETED',
  'EMAIL_VERIFIED',
  'EMAIL_VERIFICATION_SENT',
  'EMAIL_VERIFICATION_RESENT',
  'EMAIL_VERIFICATION_FAILED',
  'TWO_FACTOR_ENABLED',
  'TWO_FACTOR_DISABLED',
  // Token operations
  'TOKEN_CREATED',
  'TOKEN_UPDATED',
  'TOKEN_DELETED',
  'TOKEN_IMPORTED',
  'TOKENS_IMPORTED',
  'TOKENS_TRANSFERRED_BETWEEN_WORKSPACES',
  'TOKENS_REASSIGNED_CONTACT_GROUP',
  // Alert operations
  'ALERT_QUEUED',
  'ALERT_SENT',
  'ALERT_SEND_FAILED',
  'ALERT_NOT_QUEUED_NO_CHANNEL',
  'ALERT_CHANNELS_UPDATED',
  'ALERT_MANUAL_RETRY',
  'ALERT_PARTIAL_SUCCESS',
  'ALERT_BLOCKED_MAX_ATTEMPTS',
  'ALERT_BLOCKED_WHATSAPP_ERROR',
  'ALERT_RETRY_SCHEDULED',
  'ALERTS_BULK_REQUEUED',
  // Settings
  'ALERT_PREFS_UPDATED',
  'WORKSPACE_ALERT_SETTINGS_UPDATED',
  // Plan changes
  // Workspace operations
  'WORKSPACE_CREATED',
  'WORKSPACE_RENAMED',
  'WORKSPACE_DELETED',
  'WORKSPACE_MEMBERSHIP_ACCEPTED',
  // Member management
  'MEMBER_INVITED_OR_UPDATED',
  'MEMBER_ROLE_CHANGED',
  'MEMBER_REMOVED',
  'INVITE_EMAIL_SENT',
  'INVITATION_CANCELLED',
  // Contact management
  'WORKSPACE_CONTACT_CREATED',
  'WORKSPACE_CONTACT_UPDATED',
  'WORKSPACE_CONTACT_DELETED',
  // Integrations
  'INTEGRATION_SCAN',
  'INTEGRATION_DETECT_REGIONS',
  'AUTO_SYNC_CREATED',
  'AUTO_SYNC_UPDATED',
  'AUTO_SYNC_DELETED',
  'AUTO_SYNC_TRIGGERED',
  'AUTO_SYNC_FAILED',
  // WhatsApp
  'WHATSAPP_TEST_SENT',
  'WHATSAPP_TEST_FAILED',
  'WHATSAPP_TEST_SENT_TEMPLATE',
  'WHATSAPP_TEST_FAILED_TEMPLATE',
  'WHATSAPP_TEST_ERROR',
  'WHATSAPP_TEST_RATE_LIMITED',
  // Limits
  'LIMIT_WARNING_SENT',
  'LIMIT_REMINDER_SENT',
  'CHANNEL_LIMIT_WARNING_SENT',
  'CHANNEL_LIMIT_REACHED_SENT',
  // Domain monitors
  'DOMAIN_MONITOR_CREATED',
  'DOMAIN_MONITOR_UPDATED',
  'DOMAIN_MONITOR_DELETED',
  'DOMAIN_MONITOR_HEALTH_CHECK',
  // Domain checker (subfinder)
  'DOMAIN_CHECKER_LOOKUP',
  'DOMAIN_CHECKER_IMPORT',
  // Digests
  'WEEKLY_DIGEST_SENT',
].sort();

/** Fixed column shares so the audit table uses the full width evenly. */
const AUDIT_TABLE_COLUMN_WIDTHS = {
  time: '15%',
  action: '17%',
  user: '16%',
  workspace: '17%',
  metadata: '35%',
};

const AUDIT_PAGE_SIZE_OPTIONS = [5, 10, 20, 50, 100];
const AUDIT_CONTROL_HEIGHT = '32px';

function getAuditEventKey(ev) {
  return String(ev?.id ?? `${ev?.action || 'event'}-${ev?.occurred_at || ''}`);
}

export default function Audit({ session, onLogout, onAccountClick }) {
  const navigate = useNavigate();
  const theme = useDashboardTheme();
  const { pageBg, surface, text, muted, border, inputBg, dashboard } = theme;
  const strongBorder = dashboard.border.strong;
  const secondaryText = dashboard.text.secondary;
  const panelHoverBg = dashboard.bg.panelHover;
  const accentColor = dashboard.accent.primary;
  const tableHeaderBg = useColorModeValue('gray.50', 'rgba(8, 13, 22, 0.84)');
  const tableCellColor = useColorModeValue(
    'gray.800',
    'rgba(226, 232, 240, 0.94)'
  );
  const fieldTextColor = useColorModeValue(
    'gray.900',
    'rgba(248, 250, 252, 0.96)'
  );
  const optionBg = useColorModeValue('white', '#0f172a');
  const optionColor = useColorModeValue('gray.900', 'white');
  const searchIconColor = useColorModeValue(
    'var(--chakra-colors-gray-500)',
    'rgba(148, 163, 184, 0.86)'
  );
  const dateInputColorScheme = useColorModeValue('light', 'dark');
  const datePickerIconFilter = useColorModeValue(
    'none',
    'brightness(0) invert(1)'
  );
  const paginationControlColor = useColorModeValue(
    'gray.600',
    'rgba(203, 213, 225, 0.9)'
  );
  const paginationPageBg = useColorModeValue(
    'blue.50',
    'rgba(37, 99, 235, 0.18)'
  );
  const paginationPageColor = useColorModeValue('blue.700', 'white');
  const paginationPageBorder = useColorModeValue(
    'blue.200',
    'rgba(59, 130, 246, 0.38)'
  );
  const mobileCardBg = useColorModeValue('white', 'rgba(13, 19, 26, 0.78)');
  const mobileDetailBg = useColorModeValue('gray.50', 'rgba(8, 13, 22, 0.58)');
  const mobileSubtleBorder = useColorModeValue(
    'gray.200',
    'rgba(148, 163, 184, 0.16)'
  );
  const mobileAccentBg = useColorModeValue(
    'blue.50',
    'rgba(147, 197, 253, 0.1)'
  );
  const mobileAccentBorder = useColorModeValue(
    'blue.200',
    'rgba(147, 197, 253, 0.34)'
  );
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(false);
  const [hasMore, setHasMore] = useState(true);
  const [error, setError] = useState('');
  const [query, setQuery] = useState('');
  const [actionFilter, setActionFilter] = useState('');
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');
  const [auditPage, setAuditPage] = useState(1);
  const [auditPageSize, setAuditPageSize] = useState(10);
  const [expandedEventIds, setExpandedEventIds] = useState(() => new Set());
  const [scope, setScope] = useState(() => {
    try {
      return localStorage.getItem('tt_audit_scope') || 'user';
    } catch (_) {
      return 'user';
    }
  }); // 'workspace' | 'organization' | 'user'
  const [workspaces, setWorkspaces] = useState([]);
  const [isManagerOrAdminAny, setIsManagerOrAdminAny] = useState(false);
  const [hasWorkspaceManagerRole, setHasWorkspaceManagerRole] = useState(false);
  const [isAdminAny, setIsAdminAny] = useState(false);
  const [isAdminOrg, setIsAdminOrg] = useState(false);
  const { workspaceId } = useWorkspace();
  const [auditWorkspaceId, setAuditWorkspaceId] = useState('');
  const [authorized, setAuthorized] = useState(null);
  const [_rolesLoaded, setRolesLoaded] = useState(false);

  const isSystemAdmin = session?.isAdmin === true;
  const canViewOrganizationAudit = isSystemAdmin || (isAdminAny && isAdminOrg);

  const load = useCallback(
    async (pageToLoad = 1) => {
      if (authorized === false) return;
      try {
        setLoading(true);
        setError('');
        const viewerOnly = !isManagerOrAdminAny && !isSystemAdmin;
        // Core: block viewers (no backend calls)
        if (viewerOnly) {
          setEvents([]);
          setHasMore(false);
          return;
        }
        // Core: non-admins cannot view organization scope
        let effectiveScope = scope;
        if (!canViewOrganizationAudit && effectiveScope === 'organization') {
          effectiveScope = 'workspace';
        }
        const effectiveWorkspaceId = auditWorkspaceId || workspaceId || null;
        const page = Math.max(1, pageToLoad);
        const pageLimit = auditPageSize + 1;
        const currentOffset = (page - 1) * auditPageSize;
        const since = dateInputToAuditDateParam(dateFrom);
        const until = dateInputToAuditDateParam(dateTo, 'end');
        const eventsData = await alertAPI.getAuditEvents(
          pageLimit,
          currentOffset,
          {
            scope: effectiveScope,
            workspaceId: effectiveWorkspaceId,
            action: actionFilter || null,
            query: query || null,
            since,
            until,
          }
        );

        const newEvents = Array.isArray(eventsData) ? eventsData : [];
        setEvents(newEvents.slice(0, auditPageSize));
        setHasMore(newEvents.length > auditPageSize);
      } catch (e) {
        setError('Failed to load audit events');
      } finally {
        setLoading(false);
      }
    },
    [
      authorized,
      auditPageSize,
      scope,
      workspaceId,
      auditWorkspaceId,
      isManagerOrAdminAny,
      actionFilter,
      isSystemAdmin,
      canViewOrganizationAudit,
      query,
      dateFrom,
      dateTo,
    ]
  );

  useEffect(() => {
    load(auditPage);
  }, [load, auditPage]);

  // Redirect viewers (no manager/admin role) only when we have workspaces; avoid redirect when list empty (e.g. bootstrap admin)
  useEffect(() => {
    if (
      _rolesLoaded &&
      workspaces.length > 0 &&
      !isManagerOrAdminAny &&
      !isSystemAdmin
    ) {
      try {
        navigate('/dashboard', { replace: true });
      } catch (_) {}
    }
  }, [
    _rolesLoaded,
    workspaces.length,
    isManagerOrAdminAny,
    isSystemAdmin,
    navigate,
  ]);

  // Load accessible workspaces for scope selector (managers/admins only)
  useEffect(() => {
    (async () => {
      try {
        const ws = await workspaceAPI.list(100, 0);
        const items = ws?.items || [];
        setWorkspaces(items);
        const roles = items.map(w => String(w.role || '').toLowerCase());
        const hasAdmin = roles.includes('admin');
        const hasMgrRole = roles.includes('workspace_manager');
        const hasMgr = hasAdmin || hasMgrRole;
        setIsAdminAny(hasAdmin);
        setIsManagerOrAdminAny(hasMgr);
        setHasWorkspaceManagerRole(hasMgrRole);
        const adminOrg = items.some(
          w => !w.is_personal && String(w.role || '').toLowerCase() === 'admin'
        );
        setIsAdminOrg(adminOrg);
        setRolesLoaded(true);
        // Seed local selection once from context or first item
        if (!auditWorkspaceId) {
          const initial = workspaceId || items[0]?.id || '';
          setAuditWorkspaceId(initial);
        }
      } catch (_) {
        setWorkspaces([]);
        setIsManagerOrAdminAny(false);
        setIsAdminAny(false);
        setRolesLoaded(true);
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [workspaceId]);

  // Authorization gate per rules
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const _planRes = await apiClient
          .get(API_ENDPOINTS.ACCOUNT_PLAN)
          .catch(() => ({ data: { plan: 'oss' } }));
        if (cancelled) return;
        const ws = await workspaceAPI.list(100, 0).catch(() => ({ items: [] }));
        const items = ws?.items || [];
        const roles = items.map(w => String(w.role || '').toLowerCase());
        const adminAny = roles.includes('admin');
        // Core: authorize by role. When list empty allow access (bootstrap admin / list not loaded yet).
        const managerAny = adminAny || roles.includes('workspace_manager');
        const allow = isSystemAdmin || (items.length === 0 ? true : managerAny);
        setAuthorized(allow);
        if (!allow) {
          try {
            navigate('/dashboard', { replace: true });
          } catch (_) {}
        }
      } catch (_) {
        setAuthorized(isSystemAdmin);
        if (!isSystemAdmin) {
          try {
            navigate('/dashboard', { replace: true });
          } catch (_) {}
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [navigate, isSystemAdmin]);

  // Both action filtering and search are now handled by backend, so no client-side filtering needed
  // Events from backend are already filtered based on actionFilter and query parameters
  const filtered = events.filter(
    ev => ev.action !== 'ACCOUNT_DELETION_FEEDBACK'
  );

  // Use the exhaustive predefined list of all action types instead of only those in loaded events
  // This allows filtering for any action, even if not present in the current 500 loaded events
  const uniqueActions = ALL_ACTION_TYPES;

  function toTitle(v) {
    return String(v || '')
      .replace(/_/g, ' ')
      .replace(/\b\w/g, c => c.toUpperCase());
  }

  function boolLabel(v) {
    return v ? 'Enabled' : 'Disabled';
  }

  function formatArrayValue(values, limit = 5) {
    if (!Array.isArray(values) || values.length === 0) return 'none';
    return values
      .slice(0, limit)
      .map(v => String(v))
      .join(', ');
  }

  function formatWorkspaceSettingsMetadata(ev) {
    try {
      const md = ev?.metadata || {};
      const parts = [];
      if (Array.isArray(md.changed) && md.changed.length > 0) {
        const labelMap = {
          alert_thresholds: 'Thresholds',
          webhook_urls: 'Webhooks',
          email_alerts_enabled: 'Email alerts',
          slack_alerts_enabled: 'Slack alerts',
          webhooks_alerts_enabled: 'Webhook alerts',
          contact_groups: 'Contact groups',
          default_contact_group_id: 'Default contact group',
        };
        const labels = md.changed.map(k => labelMap[k] || toTitle(k));
        parts.push(`Changed: ${labels.join(', ')}`);
      }
      if (md.contact_groups_changes) {
        parts.push(String(md.contact_groups_changes));
      } else if (md.contact_groups_from || md.contact_groups_to) {
        // Legacy format support
        const from = String(md.contact_groups_from || '').trim();
        const to = String(md.contact_groups_to || '').trim();
        parts.push(`Contact groups: ${from || '(none)'} -> ${to || '(none)'}`);
      }
      return parts.join(' | ') || JSON.stringify(md);
    } catch (_) {
      return ev?.metadata ? JSON.stringify(ev.metadata) : '';
    }
  }

  function formatUserPrefsMetadata(ev) {
    try {
      const md = ev?.metadata || {};
      const ch = md.changed || {};
      const parts = [];
      if (ch.alert_thresholds) {
        const b = Array.isArray(ch.alert_thresholds.before)
          ? ch.alert_thresholds.before.join(',')
          : ch.alert_thresholds.before == null
            ? '(none)'
            : String(ch.alert_thresholds.before);
        const a = Array.isArray(ch.alert_thresholds.after)
          ? ch.alert_thresholds.after.join(',')
          : ch.alert_thresholds.after == null
            ? '(none)'
            : String(ch.alert_thresholds.after);
        parts.push(`Thresholds: ${b} -> ${a}`);
      }
      if (ch.email_alerts_enabled) {
        parts.push(
          `Email alerts: ${boolLabel(ch.email_alerts_enabled.before)} -> ${boolLabel(ch.email_alerts_enabled.after)}`
        );
      }
      if (ch.slack_alerts_enabled) {
        parts.push(
          `Slack alerts: ${boolLabel(ch.slack_alerts_enabled.before)} -> ${boolLabel(ch.slack_alerts_enabled.after)}`
        );
      }
      if (ch.webhooks_alerts_enabled) {
        parts.push(
          `Webhook alerts: ${boolLabel(ch.webhooks_alerts_enabled.before)} -> ${boolLabel(ch.webhooks_alerts_enabled.after)}`
        );
      }
      if (ch.webhook_urls) {
        const urls = arr =>
          Array.isArray(arr)
            ? Array.from(
                new Set(
                  arr.map(x => String(x?.url || '').trim()).filter(Boolean)
                )
              ).join(', ')
            : '';
        const b = urls(ch.webhook_urls.before) || '(none)';
        const a = urls(ch.webhook_urls.after) || '(none)';
        parts.push(`Webhooks: ${b} -> ${a}`);
      }
      return (
        parts.join(' | ') || (ev?.metadata ? JSON.stringify(ev.metadata) : '')
      );
    } catch (_) {
      return ev?.metadata ? JSON.stringify(ev.metadata) : '';
    }
  }

  function formatTokenMetadata(ev) {
    try {
      const md = ev?.metadata || {};
      const parts = [];
      if (md.name) parts.push(`Name: ${md.name}`);
      if (md.token_name) parts.push(`Token: ${md.token_name}`);
      if (md.old_name && md.new_name)
        parts.push(`Renamed: ${md.old_name} -> ${md.new_name}`);
      if (md.expiry_date)
        parts.push(`Expiry: ${formatDateTime(md.expiry_date)}`);
      if (md.old_expiry && md.new_expiry)
        parts.push(
          `Expiry changed: ${formatDateTime(md.old_expiry)} -> ${formatDateTime(md.new_expiry)}`
        );
      if (md.category) parts.push(`Category: ${md.category}`);
      if (md.contact_group_id)
        parts.push(`Contact group: ${md.contact_group_id}`);
      if (md.count) parts.push(`Count: ${md.count}`);
      return parts.length > 0 ? parts.join(' | ') : '';
    } catch (_) {
      return '';
    }
  }

  function formatAuthMetadata(ev) {
    try {
      const md = ev?.metadata || {};
      const parts = [];
      if (md.reason) parts.push(`Reason: ${md.reason}`);
      if (md.ip) parts.push(`IP: ${md.ip}`);
      if (md.user_agent) parts.push(`User agent: ${md.user_agent}`);
      if (md.email) parts.push(`Email: ${md.email}`);
      return parts.length > 0 ? parts.join(' | ') : '';
    } catch (_) {
      return '';
    }
  }

  function formatSsoLoginMetadata(ev) {
    try {
      const md = ev?.metadata || {};
      const parts = [];
      if (md.method) parts.push(`Method: ${md.method}`);
      if (md.provider_slug) parts.push(`Provider: ${md.provider_slug}`);
      if (md.protocol) parts.push(`Protocol: ${md.protocol}`);
      if (md.idp_groups_seen != null)
        parts.push(`IdP groups seen: ${md.idp_groups_seen}`);
      if (Array.isArray(md.idp_groups_sample)) {
        parts.push(
          `Observed groups: ${formatArrayValue(md.idp_groups_sample)}`
        );
      }
      if (Array.isArray(md.configured_admin_idp_groups)) {
        parts.push(
          `Configured admin groups: ${formatArrayValue(md.configured_admin_idp_groups)}`
        );
      }
      if (Array.isArray(md.matched_groups)) {
        parts.push(`Matched groups: ${formatArrayValue(md.matched_groups)}`);
      }
      if (md.is_admin_resolved != null) {
        parts.push(
          `Admin mapping: ${md.is_admin_resolved ? 'matched' : 'not matched'}`
        );
      }
      if (md.is_admin_after_login != null) {
        parts.push(
          `System admin after login: ${md.is_admin_after_login ? 'yes' : 'no'}`
        );
      }
      if (md.admin_granted != null) {
        parts.push(`Admin granted: ${md.admin_granted ? 'yes' : 'no'}`);
      }
      if (md.workspace_grants_count != null) {
        parts.push(`Workspace grants: ${md.workspace_grants_count}`);
      }
      if (md.workspace_revocations_count != null) {
        parts.push(`Workspace revocations: ${md.workspace_revocations_count}`);
      }
      return parts.join(' | ');
    } catch (_) {
      return '';
    }
  }

  function formatSsoMembershipMetadata(ev) {
    try {
      const md = ev?.metadata || {};
      const parts = [];
      if (md.provider_slug) parts.push(`Provider: ${md.provider_slug}`);
      if (md.change) parts.push(`Change: ${md.change}`);
      if (md.role) parts.push(`Role: ${md.role}`);
      if (Array.isArray(md.matched_groups)) {
        parts.push(`Matched groups: ${formatArrayValue(md.matched_groups)}`);
      }
      if (md.previous_role) parts.push(`Previous role: ${md.previous_role}`);
      if (md.reason) parts.push(`Reason: ${md.reason}`);
      return parts.join(' | ');
    } catch (_) {
      return '';
    }
  }

  function formatAlertMetadata(ev) {
    try {
      const md = ev?.metadata || {};
      const parts = [];
      if (md.token_id) parts.push(`Token ID: ${md.token_id}`);
      if (md.token_name) parts.push(`Token: ${md.token_name}`);
      if (md.alert_id) parts.push(`Alert ID: ${md.alert_id}`);
      if (md.channel) parts.push(`Channel: ${md.channel}`);
      if (md.channels)
        parts.push(
          `Channels: ${Array.isArray(md.channels) ? md.channels.join(', ') : md.channels}`
        );
      if (md.threshold_days != null)
        parts.push(`Threshold: ${md.threshold_days} days`);
      if (md.days_until_expiry != null)
        parts.push(`Days until expiry: ${md.days_until_expiry}`);
      if (md.reason) parts.push(`Reason: ${md.reason}`);
      if (md.error) parts.push(`Error: ${md.error}`);
      if (md.attempt) parts.push(`Attempt: ${md.attempt}`);
      if (md.retry_at) parts.push(`Retry at: ${formatDateTime(md.retry_at)}`);
      if (md.count) parts.push(`Count: ${md.count}`);
      return parts.length > 0 ? parts.join(' | ') : '';
    } catch (_) {
      return '';
    }
  }

  function formatWorkspaceMetadata(ev) {
    try {
      const md = ev?.metadata || {};
      const parts = [];
      if (md.workspace_name) parts.push(`Workspace: ${md.workspace_name}`);
      if (md.before?.name && md.after?.name)
        parts.push(`Renamed: ${md.before.name} -> ${md.after.name}`);
      else if (md.old_name && md.new_name)
        parts.push(`Renamed: ${md.old_name} -> ${md.new_name}`);
      else if (md.name) parts.push(`Name: ${md.name}`);
      if (md.workspace_id) parts.push(`Workspace ID: ${md.workspace_id}`);
      if (md.from_workspace_id && md.to_workspace_id)
        parts.push(
          `From workspace: ${md.from_workspace_id} to: ${md.to_workspace_id}`
        );
      if (md.token_count) parts.push(`Tokens: ${md.token_count}`);
      if (md.role) parts.push(`Role: ${md.role}`);
      if (md.kind) parts.push(`Kind: ${md.kind}`);
      return parts.length > 0 ? parts.join(' | ') : '';
    } catch (_) {
      return '';
    }
  }

  function formatDomainMonitorMetadata(ev) {
    try {
      const md = ev?.metadata || {};
      const parts = [];
      if (md.url) parts.push(`URL: ${md.url}`);
      if (md.ssl_detected != null)
        parts.push(`SSL: ${md.ssl_detected ? 'Yes' : 'No'}`);
      if (md.status_code != null) parts.push(`Status: ${md.status_code}`);
      if (md.response_time_ms != null)
        parts.push(`Response: ${md.response_time_ms}ms`);
      if (md.ssl_valid != null)
        parts.push(`SSL valid: ${md.ssl_valid ? 'Yes' : 'No'}`);
      if (md.error) parts.push(`Error: ${md.error}`);
      return parts.length > 0 ? parts.join(' | ') : '';
    } catch (_) {
      return '';
    }
  }

  function formatMemberMetadata(ev) {
    try {
      const md = ev?.metadata || {};
      const parts = [];
      if (md.email) parts.push(`Email: ${md.email}`);
      if (md.role) parts.push(`Role: ${md.role}`);
      if (md.old_role && md.new_role)
        parts.push(`Role: ${md.old_role} -> ${md.new_role}`);
      if (md.workspace_name) parts.push(`Workspace: ${md.workspace_name}`);
      if (md.recipient_type)
        parts.push(
          `Recipient: ${md.recipient_type === 'existing_user' ? 'existing user' : 'new user'}`
        );
      if (md.invitation_id) parts.push(`Invitation ID: ${md.invitation_id}`);
      if (md.invited_by) parts.push(`Invited by: ${md.invited_by}`);
      return parts.length > 0 ? parts.join(' | ') : '';
    } catch (_) {
      return '';
    }
  }

  function formatContactMetadata(ev) {
    try {
      const md = ev?.metadata || {};
      const parts = [];
      if (md.name) parts.push(`Name: ${md.name}`);
      if (md.contact_name) parts.push(`Contact: ${md.contact_name}`);
      if (md.email) parts.push(`Email: ${md.email}`);
      if (md.phone) parts.push(`Phone: ${md.phone}`);
      if (md.contact_group_id)
        parts.push(`Contact group ID: ${md.contact_group_id}`);
      if (md.old_contact_group && md.new_contact_group) {
        parts.push(
          `Contact group: ${md.old_contact_group || '(none)'} -> ${md.new_contact_group || '(none)'}`
        );
      }
      if (md.token_count) parts.push(`Tokens reassigned: ${md.token_count}`);
      return parts.length > 0 ? parts.join(' | ') : '';
    } catch (_) {
      return '';
    }
  }

  function formatIntegrationMetadata(ev) {
    try {
      const md = ev?.metadata || {};
      const parts = [];
      if (md.provider) parts.push(`Provider: ${md.provider}`);
      if (md.region) parts.push(`Region: ${md.region}`);
      if (md.regions)
        parts.push(
          `Regions: ${Array.isArray(md.regions) ? md.regions.join(', ') : md.regions}`
        );
      if (md.discovered) parts.push(`Discovered: ${md.discovered}`);
      if (md.imported) parts.push(`Imported: ${md.imported}`);
      if (md.updated) parts.push(`Updated: ${md.updated}`);
      if (md.error) parts.push(`Error: ${md.error}`);
      if (md.success != null)
        parts.push(`Success: ${md.success ? 'Yes' : 'No'}`);
      return parts.length > 0 ? parts.join(' | ') : '';
    } catch (_) {
      return '';
    }
  }

  function formatWhatsAppMetadata(ev) {
    try {
      const md = ev?.metadata || {};
      const parts = [];
      if (md.phone) parts.push(`Phone: ${md.phone}`);
      if (md.template) parts.push(`Template: ${md.template}`);
      if (md.error) parts.push(`Error: ${md.error}`);
      if (md.message) parts.push(`Message: ${md.message}`);
      if (md.rate_limit) parts.push(`Rate limit: ${md.rate_limit}`);
      return parts.length > 0 ? parts.join(' | ') : '';
    } catch (_) {
      return '';
    }
  }

  function formatLimitMetadata(ev) {
    try {
      const md = ev?.metadata || {};
      const parts = [];
      if (md.limit) parts.push(`Limit: ${md.limit}`);
      if (md.current) parts.push(`Current: ${md.current}`);
      if (md.channel) parts.push(`Channel: ${md.channel}`);
      if (md.threshold_percent != null)
        parts.push(`Threshold: ${md.threshold_percent}%`);
      if (md.usage_percent != null) parts.push(`Usage: ${md.usage_percent}%`);
      return parts.length > 0 ? parts.join(' | ') : '';
    } catch (_) {
      return '';
    }
  }

  function formatDigestMetadata(ev) {
    try {
      const md = ev?.metadata || {};
      const parts = [];
      if (md.recipient) parts.push(`Recipient: ${md.recipient}`);
      if (md.token_count) parts.push(`Tokens: ${md.token_count}`);
      if (md.expiring_soon) parts.push(`Expiring soon: ${md.expiring_soon}`);
      if (md.channel) parts.push(`Channel: ${md.channel}`);
      return parts.length > 0 ? parts.join(' | ') : '';
    } catch (_) {
      return '';
    }
  }

  function formatDomainCheckerMetadata(ev) {
    try {
      let md = ev?.metadata;
      if (md == null) md = {};
      else if (typeof md === 'string') {
        try {
          md = JSON.parse(md);
        } catch (_) {
          md = {};
        }
      }
      const action = String(ev?.action || '');
      const parts = [];
      if (md.domain) parts.push(`Domain: ${md.domain}`);
      if (action === 'DOMAIN_CHECKER_LOOKUP') {
        if (md.results != null) parts.push(`Results: ${md.results}`);
        if (md.source) parts.push(`Source: ${md.source}`);
        if (md.partial) parts.push('Partial: yes');
        if (md.truncated) parts.push('Truncated: yes');
      }
      if (action === 'DOMAIN_CHECKER_IMPORT') {
        if (md.submitted != null) parts.push(`Submitted: ${md.submitted}`);
        if (md.imported != null) parts.push(`Imported: ${md.imported}`);
        if (md.skipped != null) parts.push(`Skipped: ${md.skipped}`);
        if (md.skipped_unreachable != null)
          parts.push(`DNS / no name resolution: ${md.skipped_unreachable}`);
        if (md.skipped_other_invalid != null)
          parts.push(`Other invalid: ${md.skipped_other_invalid}`);
        if (md.skipped_duplicate != null)
          parts.push(`Duplicate: ${md.skipped_duplicate}`);
        if (md.skipped_invalid != null)
          parts.push(`Invalid (total): ${md.skipped_invalid}`);
        if (md.create_monitors != null)
          parts.push(`Create monitors: ${md.create_monitors ? 'yes' : 'no'}`);
        if (md.monitors_created != null)
          parts.push(`Monitors created: ${md.monitors_created}`);
        if (md.monitors_existing != null)
          parts.push(`Monitors existing: ${md.monitors_existing}`);
        if (md.monitor_check_interval)
          parts.push(`Monitor interval: ${md.monitor_check_interval}`);
      }
      return parts.length > 0 ? parts.join(' | ') : '';
    } catch (_) {
      return '';
    }
  }

  function formatAutoSyncMetadata(ev) {
    try {
      const md = ev?.metadata || {};
      const parts = [];
      if (md.provider) parts.push(`Provider: ${md.provider}`);
      if (md.error) parts.push(`Error: ${md.error}`);
      if (md.http_status != null) parts.push(`HTTP status: ${md.http_status}`);
      if (md.config_id) parts.push(`Config ID: ${md.config_id}`);
      if (md.enabled != null)
        parts.push(`Enabled: ${md.enabled ? 'yes' : 'no'}`);
      return parts.join(' | ');
    } catch (_) {
      return '';
    }
  }

  function formatMetadata(ev) {
    const action = String(ev?.action || '');

    // Workspace settings
    if (action === 'WORKSPACE_ALERT_SETTINGS_UPDATED')
      return formatWorkspaceSettingsMetadata(ev);

    // User preferences
    if (action === 'ALERT_PREFS_UPDATED') return formatUserPrefsMetadata(ev);

    // Token events
    if (
      action === 'TOKEN_CREATED' ||
      action === 'TOKEN_UPDATED' ||
      action === 'TOKEN_DELETED' ||
      action === 'TOKEN_IMPORTED' ||
      action === 'TOKENS_IMPORTED' ||
      action === 'TOKENS_TRANSFERRED_BETWEEN_WORKSPACES' ||
      action === 'TOKENS_REASSIGNED_CONTACT_GROUP'
    ) {
      const formatted = formatTokenMetadata(ev);
      if (formatted) return formatted;
    }

    if (
      action === 'LOGIN_SUCCESS' &&
      ['saml', 'oidc', 'sso'].includes(
        String(ev?.metadata?.method || '').toLowerCase()
      )
    ) {
      const formatted = formatSsoLoginMetadata(ev);
      if (formatted) return formatted;
    }

    // Authentication events
    if (
      action === 'LOGIN_SUCCESS' ||
      action === 'LOGIN_FAILED' ||
      action === 'LOGIN_SUCCESS_2FA' ||
      action === 'LOGOUT' ||
      action === 'PASSWORD_CHANGED' ||
      action === 'PASSWORD_RESET_REQUESTED' ||
      action === 'PASSWORD_RESET_COMPLETED' ||
      action === 'EMAIL_VERIFIED' ||
      action === 'EMAIL_VERIFICATION_SENT' ||
      action === 'EMAIL_VERIFICATION_RESENT' ||
      action === 'EMAIL_VERIFICATION_FAILED' ||
      action === 'TWO_FACTOR_ENABLED' ||
      action === 'TWO_FACTOR_DISABLED'
    ) {
      const formatted = formatAuthMetadata(ev);
      if (formatted) return formatted;
    }

    if (action === 'MEMBERSHIP_SYNCED_FROM_SSO') {
      const formatted = formatSsoMembershipMetadata(ev);
      if (formatted) return formatted;
    }

    // Alert events
    if (
      action === 'ALERT_QUEUED' ||
      action === 'ALERT_SENT' ||
      action === 'ALERT_SEND_FAILED' ||
      action === 'ALERT_NOT_QUEUED_NO_CHANNEL' ||
      action === 'ALERT_CHANNELS_UPDATED' ||
      action === 'ALERT_MANUAL_RETRY' ||
      action === 'ALERT_PARTIAL_SUCCESS' ||
      action === 'ALERT_BLOCKED_MAX_ATTEMPTS' ||
      action === 'ALERT_BLOCKED_WHATSAPP_ERROR' ||
      action === 'ALERT_RETRY_SCHEDULED' ||
      action === 'ALERTS_BULK_REQUEUED'
    ) {
      const formatted = formatAlertMetadata(ev);
      if (formatted) return formatted;
    }

    // Workspace events
    if (
      action === 'WORKSPACE_CREATED' ||
      action === 'WORKSPACE_RENAMED' ||
      action === 'WORKSPACE_DELETED' ||
      action === 'WORKSPACE_MEMBERSHIP_ACCEPTED'
    ) {
      const formatted = formatWorkspaceMetadata(ev);
      if (formatted) return formatted;
    }

    // Member events
    if (
      action === 'MEMBER_INVITED_OR_UPDATED' ||
      action === 'MEMBER_ROLE_CHANGED' ||
      action === 'MEMBER_REMOVED' ||
      action === 'INVITE_EMAIL_SENT' ||
      action === 'INVITATION_CANCELLED'
    ) {
      const formatted = formatMemberMetadata(ev);
      if (formatted) return formatted;
    }

    // Contact events
    if (
      action === 'WORKSPACE_CONTACT_CREATED' ||
      action === 'WORKSPACE_CONTACT_UPDATED' ||
      action === 'WORKSPACE_CONTACT_DELETED'
    ) {
      const formatted = formatContactMetadata(ev);
      if (formatted) return formatted;
    }

    // Integration / auto-sync events
    if (
      action === 'INTEGRATION_SCAN' ||
      action === 'INTEGRATION_DETECT_REGIONS'
    ) {
      const formatted = formatIntegrationMetadata(ev);
      if (formatted) return formatted;
    }

    if (
      action === 'AUTO_SYNC_CREATED' ||
      action === 'AUTO_SYNC_UPDATED' ||
      action === 'AUTO_SYNC_DELETED' ||
      action === 'AUTO_SYNC_TRIGGERED' ||
      action === 'AUTO_SYNC_FAILED'
    ) {
      const formatted = formatAutoSyncMetadata(ev);
      if (formatted) return formatted;
    }

    // WhatsApp events
    if (
      action === 'WHATSAPP_TEST_SENT' ||
      action === 'WHATSAPP_TEST_FAILED' ||
      action === 'WHATSAPP_TEST_SENT_TEMPLATE' ||
      action === 'WHATSAPP_TEST_FAILED_TEMPLATE' ||
      action === 'WHATSAPP_TEST_ERROR' ||
      action === 'WHATSAPP_TEST_RATE_LIMITED'
    ) {
      const formatted = formatWhatsAppMetadata(ev);
      if (formatted) return formatted;
    }

    // Limit events
    if (
      action === 'LIMIT_WARNING_SENT' ||
      action === 'LIMIT_REMINDER_SENT' ||
      action === 'CHANNEL_LIMIT_WARNING_SENT' ||
      action === 'CHANNEL_LIMIT_REACHED_SENT'
    ) {
      const formatted = formatLimitMetadata(ev);
      if (formatted) return formatted;
    }

    // Domain monitor events
    if (
      action === 'DOMAIN_MONITOR_CREATED' ||
      action === 'DOMAIN_MONITOR_UPDATED' ||
      action === 'DOMAIN_MONITOR_DELETED' ||
      action === 'DOMAIN_MONITOR_HEALTH_CHECK'
    ) {
      const formatted = formatDomainMonitorMetadata(ev);
      if (formatted) return formatted;
    }

    if (
      action === 'DOMAIN_CHECKER_LOOKUP' ||
      action === 'DOMAIN_CHECKER_IMPORT'
    ) {
      const formatted = formatDomainCheckerMetadata(ev);
      if (formatted) return formatted;
    }

    // Digest events
    if (action === 'WEEKLY_DIGEST_SENT') {
      const formatted = formatDigestMetadata(ev);
      if (formatted) return formatted;
    }

    // Account deletion feedback
    if (action === 'ACCOUNT_DELETION_FEEDBACK') {
      return ''; // Hide from view as per user request
    }

    // Fallback: if metadata exists but no specific formatter matched, return empty
    // This prevents JSON from being displayed
    return '';
  }

  function getMetadataEntries(ev) {
    const formatted = formatMetadata(ev);
    if (!formatted) {
      return [{ label: 'Metadata', value: '-' }];
    }

    return formatted
      .split(' | ')
      .map(part => part.trim())
      .filter(Boolean)
      .map(part => {
        const separatorIndex = part.indexOf(':');
        if (separatorIndex > 0 && separatorIndex < 48) {
          return {
            label: part.slice(0, separatorIndex).trim(),
            value: part.slice(separatorIndex + 1).trim() || '-',
          };
        }

        return { label: 'Detail', value: part };
      });
  }

  const toggleEventExpanded = useCallback(eventId => {
    setExpandedEventIds(previous => {
      const next = new Set(previous);
      if (next.has(eventId)) {
        next.delete(eventId);
      } else {
        next.add(eventId);
      }
      return next;
    });
  }, []);

  async function exportJson() {
    try {
      const effectiveScope = canViewOrganizationAudit
        ? scope
        : scope === 'organization'
          ? 'workspace'
          : scope;
      const effectiveWorkspaceId = auditWorkspaceId || workspaceId || null;
      const since = dateInputToAuditDateParam(dateFrom);
      const until = dateInputToAuditDateParam(dateTo, 'end');
      const { blob, filename, contentType } = await alertAPI.exportAudit({
        scope: effectiveScope,
        workspaceId:
          effectiveScope === 'workspace' ? effectiveWorkspaceId : null,
        format: 'json',
        limit: 10000,
        action: actionFilter || null,
        query: query || null,
        since,
        until,
      });
      const url = URL.createObjectURL(new Blob([blob], { type: contentType }));
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (e) {
      setError('Failed to export JSON');
    }
  }

  async function exportCsv() {
    try {
      const effectiveScope = canViewOrganizationAudit
        ? scope
        : scope === 'organization'
          ? 'workspace'
          : scope;
      const effectiveWorkspaceId = auditWorkspaceId || workspaceId || null;
      const since = dateInputToAuditDateParam(dateFrom);
      const until = dateInputToAuditDateParam(dateTo, 'end');
      const { blob, filename, contentType } = await alertAPI.exportAudit({
        scope: effectiveScope,
        workspaceId:
          effectiveScope === 'workspace' ? effectiveWorkspaceId : null,
        format: 'csv',
        limit: 10000,
        action: actionFilter || null,
        query: query || null,
        since,
        until,
      });
      const url = URL.createObjectURL(new Blob([blob], { type: contentType }));
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (e) {
      setError('Failed to export CSV');
    }
  }
  const selectedWorkspace =
    workspaces.find(w => w.id === (auditWorkspaceId || workspaceId)) ||
    workspaces[0] ||
    null;

  // UI scope:
  // - Admins: respect selected scope
  // - Non-admins: allow 'user' and 'workspace'; coerce 'organization' to 'workspace'
  const scopeUI = canViewOrganizationAudit
    ? scope
    : scope === 'organization'
      ? 'workspace'
      : scope;
  const pageOffset = (auditPage - 1) * auditPageSize;
  const auditRangeStart = filtered.length === 0 ? 0 : pageOffset + 1;
  const auditRangeEnd = pageOffset + filtered.length;
  const auditRangeLabel =
    filtered.length === 0
      ? '0 of 0'
      : `${auditRangeStart}-${auditRangeEnd} of ${hasMore ? `${auditRangeEnd}+` : auditRangeEnd}`;
  const fieldStyles = {
    bg: inputBg,
    borderColor: border,
    color: fieldTextColor,
    fontSize: 'sm',
    borderRadius: 'md',
    minH: AUDIT_CONTROL_HEIGHT,
    _hover: { borderColor: strongBorder },
    _focus: {
      borderColor: accentColor,
      boxShadow: `0 0 0 1px ${accentColor}`,
    },
    _placeholder: { color: muted },
    sx: {
      option: {
        background: optionBg,
        color: optionColor,
      },
    },
  };
  const dateFieldStyles = {
    ...fieldStyles,
    sx: {
      ...fieldStyles.sx,
      colorScheme: dateInputColorScheme,
      '&::-webkit-calendar-picker-indicator': {
        filter: datePickerIconFilter,
        opacity: 0.92,
        cursor: 'pointer',
      },
      '&::-webkit-datetime-edit': {
        color: fieldTextColor,
      },
      '&::-webkit-date-and-time-value': {
        color: fieldTextColor,
      },
    },
  };
  const outlineActionButtonStyles = {
    borderColor: strongBorder,
    color: secondaryText,
    bg: 'transparent',
    borderRadius: 'md',
    minW: 'fit-content',
    whiteSpace: 'nowrap',
    _hover: {
      bg: panelHoverBg,
      color: text,
      borderColor: accentColor,
    },
    _active: {
      bg: panelHoverBg,
    },
  };

  const renderMobileAuditCard = ev => {
    const eventId = getAuditEventKey(ev);
    const isExpanded = expandedEventIds.has(eventId);
    const metadataEntries = getMetadataEntries(ev);
    const metadataPreview = formatMetadata(ev) || '-';
    const workspaceLabel = ev.workspace_name || ev.workspace_id || '-';
    const userLabel = ev.actor_display_name || '-';

    return (
      <Box
        key={eventId}
        bg={mobileCardBg}
        border='1px solid'
        borderColor={isExpanded ? mobileAccentBorder : mobileSubtleBorder}
        borderLeftColor={isExpanded ? accentColor : mobileSubtleBorder}
        borderLeftWidth={isExpanded ? '3px' : '1px'}
        borderRadius='md'
        boxShadow='0 14px 34px rgba(0, 0, 0, 0.22)'
        p={4}
        minW={0}
      >
        <Flex align='flex-start' gap={3} minW={0}>
          <Box flex='1' minW={0}>
            <Badge
              bg={mobileAccentBg}
              color={accentColor}
              border='1px solid'
              borderColor={mobileAccentBorder}
              variant='outline'
              borderRadius='md'
              px={2}
              py={1}
              maxW='100%'
              whiteSpace='normal'
              wordBreak='break-word'
            >
              {ev.action}
            </Badge>
            <Text color={text} fontSize='sm' mt={2} noOfLines={1}>
              {formatDateTime(ev.occurred_at)}
            </Text>
            <HStack spacing={2} color={muted} fontSize='sm' mt={1} minW={0}>
              <FiBriefcase size={15} />
              <Text noOfLines={1} minW={0}>
                {workspaceLabel}
              </Text>
            </HStack>
            {!isExpanded && (
              <Text color={secondaryText} fontSize='sm' mt={3} noOfLines={2}>
                {metadataPreview}
              </Text>
            )}
          </Box>

          <IconButton
            aria-label={
              isExpanded ? 'Collapse audit event' : 'Expand audit event'
            }
            icon={isExpanded ? <FiChevronUp /> : <FiChevronDown />}
            size='sm'
            variant='ghost'
            borderRadius='full'
            color={secondaryText}
            bg={panelHoverBg}
            flexShrink={0}
            aria-expanded={isExpanded}
            onClick={() => toggleEventExpanded(eventId)}
            _hover={{
              bg: mobileAccentBg,
              color: accentColor,
            }}
          />
        </Flex>

        {isExpanded && (
          <VStack spacing={3} align='stretch' mt={4}>
            <Box
              bg={mobileDetailBg}
              border='1px solid'
              borderColor={mobileSubtleBorder}
              borderRadius='md'
              p={3}
            >
              <HStack align='flex-start' spacing={3}>
                <Flex
                  align='center'
                  justify='center'
                  w='36px'
                  h='36px'
                  borderRadius='md'
                  bg={panelHoverBg}
                  color={secondaryText}
                  flexShrink={0}
                >
                  <FiUser size={18} />
                </Flex>
                <Box minW={0}>
                  <Text color={muted} fontSize='xs' fontWeight='semibold'>
                    User
                  </Text>
                  <Text color={text} fontSize='sm' wordBreak='break-word'>
                    {userLabel}
                  </Text>
                  <Text
                    color={muted}
                    fontSize='xs'
                    mt={2}
                    fontWeight='semibold'
                  >
                    Workspace
                  </Text>
                  <Text color={text} fontSize='sm' wordBreak='break-word'>
                    {workspaceLabel}
                  </Text>
                </Box>
              </HStack>
            </Box>

            <Box
              bg={mobileDetailBg}
              border='1px solid'
              borderColor={mobileAccentBorder}
              borderRadius='md'
              p={3}
            >
              <Box minW={0}>
                <Text color={accentColor} fontSize='sm' fontWeight='semibold'>
                  Metadata
                </Text>
                <VStack spacing={2} align='stretch' mt={2}>
                  {metadataEntries.map((entry, index) => (
                    <Box key={`${eventId}-metadata-${index}`} minW={0}>
                      <Text color={muted} fontSize='xs' fontWeight='semibold'>
                        {entry.label}
                      </Text>
                      <Text
                        color={text}
                        fontSize='sm'
                        whiteSpace='pre-wrap'
                        wordBreak='break-word'
                      >
                        {entry.value}
                      </Text>
                    </Box>
                  ))}
                </VStack>
              </Box>
            </Box>
          </VStack>
        )}
      </Box>
    );
  };

  const shellProps = useDashboardShellProps({
    session,
    onLogout,
    onAccountClick,
    pageTitle: 'Audit',
    dashboardWorkspaces: workspaces,
    dashboardWorkspace: selectedWorkspace,
    onWorkspaceSelect: workspace => {
      if (workspace?.id) {
        setAuditPage(1);
        setAuditWorkspaceId(workspace.id);
      }
    },
    dashboardCanSeeManagerNav: isManagerOrAdminAny,
  });

  return (
    <>
      <SEO
        title='Audit Log'
        description='View audit logs and activity history'
        noindex
      />
      <Box
        color={text}
        minH='100vh'
        bg={pageBg}
        sx={{
          '.chakra-table': {
            tableLayout: 'fixed',
            width: '100%',
          },
          '.chakra-table th': {
            color: muted,
            borderColor: border,
            fontSize: '0.72rem',
            letterSpacing: '0',
            textTransform: 'none',
            whiteSpace: 'nowrap',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
          },
          '.chakra-table td': {
            color: tableCellColor,
            borderColor: border,
            verticalAlign: 'top',
            overflow: 'hidden',
          },
          '.chakra-input, .chakra-select': {
            color: fieldTextColor,
          },
          option: {
            background: optionBg,
            color: optionColor,
          },
        }}
      >
        <DashboardShell {...shellProps}>
          <Box
            px={{ base: 4, lg: 4, '2xl': 5 }}
            py={{ base: 5, lg: 3 }}
            w='100%'
            minW={0}
            maxW='100%'
          >
            <Flex
              bg={surface}
              border='1px solid'
              borderColor={border}
              borderRadius='md'
              p={{ base: 3, md: 4 }}
              gap={3}
              align={{ base: 'stretch', sm: 'center' }}
              justify='flex-start'
              direction={{ base: 'column', sm: 'row' }}
              flexWrap='wrap'
              mb={4}
            >
              <Button
                leftIcon={<FiRefreshCw />}
                onClick={() => load(auditPage)}
                isLoading={loading}
                colorScheme='blue'
                borderRadius='md'
                size='sm'
                h={AUDIT_CONTROL_HEIGHT}
                w={{ base: '100%', sm: 'auto' }}
              >
                Refresh
              </Button>
              <Button
                leftIcon={<FiDownload />}
                variant='outline'
                onClick={exportJson}
                size='sm'
                h={AUDIT_CONTROL_HEIGHT}
                w={{ base: '100%', sm: 'auto' }}
                {...outlineActionButtonStyles}
              >
                Export JSON
              </Button>
              <Button
                leftIcon={<FiDownload />}
                variant='outline'
                onClick={exportCsv}
                size='sm'
                h={AUDIT_CONTROL_HEIGHT}
                w={{ base: '100%', sm: 'auto' }}
                {...outlineActionButtonStyles}
              >
                Export CSV
              </Button>
            </Flex>

            <Box
              bg={surface}
              border='1px solid'
              borderColor={border}
              borderRadius='md'
              w='100%'
              minW={0}
              maxW='100%'
              overflow='hidden'
              mb={4}
            >
              <Flex
                p={{ base: 4, md: 5 }}
                gap={3}
                align={{ base: 'stretch', lg: 'center' }}
                direction={{ base: 'column', lg: 'row' }}
                flexWrap='wrap'
              >
                <InputGroup
                  maxW={{ base: '100%', lg: '360px' }}
                  size='sm'
                  flex={{ base: '1 1 auto', lg: '0 1 360px' }}
                >
                  <InputLeftElement
                    pointerEvents='none'
                    h={AUDIT_CONTROL_HEIGHT}
                  >
                    <FiSearch size={16} color={searchIconColor} />
                  </InputLeftElement>
                  <Input
                    size='sm'
                    h={AUDIT_CONTROL_HEIGHT}
                    pl='36px'
                    placeholder='Search action or metadata...'
                    value={query}
                    onChange={e => {
                      setAuditPage(1);
                      setQuery(e.target.value);
                    }}
                    {...fieldStyles}
                  />
                </InputGroup>
                <Select
                  placeholder='All actions'
                  value={actionFilter}
                  onChange={e => {
                    setAuditPage(1);
                    setActionFilter(e.target.value);
                  }}
                  size='sm'
                  maxW={{ base: '100%', md: '240px' }}
                  h={AUDIT_CONTROL_HEIGHT}
                  title='Filter by specific action type'
                  {...fieldStyles}
                >
                  {uniqueActions.map(a => (
                    <option key={a} value={a}>
                      {toTitle(a)}
                    </option>
                  ))}
                </Select>
                {canViewOrganizationAudit ? (
                  <Select
                    value={scope}
                    onChange={e => {
                      const v = e.target.value;
                      setAuditPage(1);
                      setScope(v);
                      try {
                        localStorage.setItem('tt_audit_scope', v);
                      } catch (_) {}
                    }}
                    size='sm'
                    maxW={{ base: '100%', md: '240px' }}
                    h={AUDIT_CONTROL_HEIGHT}
                    {...fieldStyles}
                  >
                    <option value='user'>My actions</option>
                    <option value='workspace'>This workspace</option>
                    <option value='organization'>Organization (admin)</option>
                  </Select>
                ) : (
                  <Select
                    value={scopeUI}
                    onChange={e => {
                      const v = e.target.value;
                      const next = v === 'organization' ? 'workspace' : v;
                      setAuditPage(1);
                      setScope(next);
                      try {
                        localStorage.setItem('tt_audit_scope', next);
                      } catch (_) {}
                    }}
                    size='sm'
                    maxW={{ base: '100%', md: '240px' }}
                    h={AUDIT_CONTROL_HEIGHT}
                    {...fieldStyles}
                  >
                    <option value='user'>My actions</option>
                    <option value='workspace'>This workspace</option>
                  </Select>
                )}
                {isManagerOrAdminAny && (
                  <Select
                    value={auditWorkspaceId || workspaceId || ''}
                    onChange={e => {
                      const nextId = e.target.value;
                      setAuditPage(1);
                      setAuditWorkspaceId(nextId);
                      if (isAdminAny && scope !== 'workspace') {
                        try {
                          setScope('workspace');
                        } catch (_) {}
                      }
                    }}
                    size='sm'
                    maxW={{ base: '100%', md: '280px' }}
                    h={AUDIT_CONTROL_HEIGHT}
                    {...fieldStyles}
                  >
                    {(() => {
                      const list = workspaces || [];
                      const filtered =
                        !isAdminAny && hasWorkspaceManagerRole
                          ? list.filter(
                              w =>
                                w.is_personal === true ||
                                String(w.role || '').toLowerCase() ===
                                  'workspace_manager'
                            )
                          : list;
                      return filtered.map(w => (
                        <option key={w.id} value={w.id}>
                          {w.name}
                        </option>
                      ));
                    })()}
                  </Select>
                )}
                <Input
                  type='datetime-local'
                  aria-label='Audit date range start'
                  title='From date and time'
                  value={dateFrom}
                  max={dateTo || undefined}
                  onChange={event => {
                    setAuditPage(1);
                    setDateFrom(event.target.value);
                  }}
                  size='sm'
                  maxW={{ base: '100%', md: '220px' }}
                  h={AUDIT_CONTROL_HEIGHT}
                  step={60}
                  {...dateFieldStyles}
                />
                <Input
                  type='datetime-local'
                  aria-label='Audit date range end'
                  title='To date and time'
                  value={dateTo}
                  min={dateFrom || undefined}
                  onChange={event => {
                    setAuditPage(1);
                    setDateTo(event.target.value);
                  }}
                  size='sm'
                  maxW={{ base: '100%', md: '220px' }}
                  h={AUDIT_CONTROL_HEIGHT}
                  step={60}
                  {...dateFieldStyles}
                />
              </Flex>
            </Box>

            <Box
              bg={surface}
              border='1px solid'
              borderColor={border}
              borderRadius='md'
              boxShadow='0 16px 48px rgba(0, 0, 0, 0.2)'
              w='100%'
              minW={0}
              maxW='100%'
              overflow='hidden'
            >
              <Flex
                px={{ base: 4, md: 5 }}
                py={3}
                borderBottom='1px solid'
                borderColor='rgba(148, 163, 184, 0.13)'
                align='center'
                justify='space-between'
                gap={3}
              >
                <Text color={text} fontWeight='semibold' fontSize='sm'>
                  Audit events
                </Text>
              </Flex>
              <Box p={{ base: 4, md: 5 }}>
                <Flex
                  align={{ base: 'stretch', md: 'center' }}
                  justify='space-between'
                  direction={{ base: 'column', lg: 'row' }}
                  gap={3}
                  mb={4}
                >
                  <Text color={muted} fontSize='sm' whiteSpace='nowrap'>
                    {filtered.length} visible
                  </Text>
                  <Flex
                    align={{ base: 'stretch', md: 'center' }}
                    justify={{ base: 'space-between', md: 'end' }}
                    direction={{ base: 'column', sm: 'row' }}
                    gap={3}
                    flex='1'
                    minW={0}
                  >
                    <HStack spacing={2}>
                      <Text color={muted} fontSize='sm'>
                        Show
                      </Text>
                      <Select
                        size='sm'
                        w='84px'
                        value={auditPageSize}
                        onChange={event => {
                          setAuditPageSize(Number(event.target.value));
                          setAuditPage(1);
                        }}
                        {...fieldStyles}
                      >
                        {AUDIT_PAGE_SIZE_OPTIONS.map(size => (
                          <option key={size} value={size}>
                            {size}
                          </option>
                        ))}
                      </Select>
                    </HStack>
                    <HStack
                      spacing={3}
                      justify={{ base: 'space-between', sm: 'end' }}
                    >
                      <Text color={muted} fontSize='sm' whiteSpace='nowrap'>
                        {auditRangeLabel}
                      </Text>
                      <HStack spacing={1}>
                        <IconButton
                          aria-label='Previous audit page'
                          icon={<FiChevronRight />}
                          size='sm'
                          variant='ghost'
                          color={paginationControlColor}
                          isDisabled={auditPage <= 1}
                          onClick={() =>
                            setAuditPage(page => Math.max(1, page - 1))
                          }
                          sx={{ svg: { transform: 'rotate(180deg)' } }}
                          _hover={{ bg: panelHoverBg, color: text }}
                        />
                        <Button
                          size='sm'
                          variant='outline'
                          borderColor={paginationPageBorder}
                          color={paginationPageColor}
                          bg={paginationPageBg}
                          minW='38px'
                          borderRadius='md'
                        >
                          {auditPage}
                        </Button>
                        <IconButton
                          aria-label='Next audit page'
                          icon={<FiChevronRight />}
                          size='sm'
                          variant='ghost'
                          color={paginationControlColor}
                          isDisabled={!hasMore}
                          onClick={() => setAuditPage(page => page + 1)}
                          _hover={{ bg: panelHoverBg, color: text }}
                        />
                      </HStack>
                    </HStack>
                  </Flex>
                </Flex>

                {error ? (
                  <Text color='red.500' p={{ base: 4, md: 6 }}>
                    {error}
                  </Text>
                ) : loading && filtered.length === 0 ? (
                  <Text color={muted} p={{ base: 4, md: 6 }}>
                    Loading audit events...
                  </Text>
                ) : filtered.length === 0 ? (
                  <Text color={muted} p={{ base: 4, md: 6 }}>
                    No audit events found.
                  </Text>
                ) : (
                  <>
                    <Box
                      display={{ base: 'block', lg: 'none' }}
                      w='100%'
                      minW={0}
                    >
                      <VStack spacing={3} align='stretch'>
                        {filtered.map(ev => renderMobileAuditCard(ev))}
                      </VStack>
                    </Box>

                    <Box
                      overflowX='auto'
                      w='100%'
                      minW={0}
                      display={{ base: 'none', lg: 'block' }}
                    >
                      <Table size='sm' variant='simple' w='100%' layout='fixed'>
                        <Thead bg={tableHeaderBg}>
                          <Tr>
                            <Th
                              w={AUDIT_TABLE_COLUMN_WIDTHS.time}
                              textAlign='left'
                            >
                              Time
                            </Th>
                            <Th
                              w={AUDIT_TABLE_COLUMN_WIDTHS.action}
                              textAlign='left'
                            >
                              Action
                            </Th>
                            <Th
                              w={AUDIT_TABLE_COLUMN_WIDTHS.user}
                              textAlign='left'
                            >
                              User
                            </Th>
                            <Th
                              w={AUDIT_TABLE_COLUMN_WIDTHS.workspace}
                              textAlign='left'
                            >
                              Workspace
                            </Th>
                            <Th
                              w={AUDIT_TABLE_COLUMN_WIDTHS.metadata}
                              textAlign='left'
                            >
                              Metadata
                            </Th>
                          </Tr>
                        </Thead>
                        <Tbody>
                          {filtered.map(ev => (
                            <Tr key={ev.id} _hover={{ bg: panelHoverBg }}>
                              <Td
                                w={AUDIT_TABLE_COLUMN_WIDTHS.time}
                                whiteSpace='nowrap'
                                textOverflow='ellipsis'
                                overflow='hidden'
                                py={3}
                              >
                                {formatDateTime(ev.occurred_at)}
                              </Td>
                              <Td w={AUDIT_TABLE_COLUMN_WIDTHS.action} py={3}>
                                <Badge
                                  bg={mobileAccentBg}
                                  color={accentColor}
                                  border='1px solid'
                                  borderColor={mobileAccentBorder}
                                  variant='outline'
                                  borderRadius='md'
                                  px={2}
                                  py={1}
                                  whiteSpace='normal'
                                  textAlign='left'
                                  maxW='100%'
                                >
                                  {ev.action}
                                </Badge>
                              </Td>
                              <Td
                                w={AUDIT_TABLE_COLUMN_WIDTHS.user}
                                textOverflow='ellipsis'
                                overflow='hidden'
                                whiteSpace='nowrap'
                                py={3}
                              >
                                {ev.actor_display_name || ''}
                              </Td>
                              <Td
                                w={AUDIT_TABLE_COLUMN_WIDTHS.workspace}
                                textOverflow='ellipsis'
                                overflow='hidden'
                                whiteSpace='nowrap'
                                py={3}
                              >
                                {ev.workspace_name || ev.workspace_id || ''}
                              </Td>
                              <Td
                                w={AUDIT_TABLE_COLUMN_WIDTHS.metadata}
                                wordBreak='break-word'
                                py={3}
                              >
                                <TruncatedText
                                  text={formatMetadata(ev)}
                                  maxLines={3}
                                />
                              </Td>
                            </Tr>
                          ))}
                        </Tbody>
                      </Table>
                    </Box>
                  </>
                )}
              </Box>
            </Box>
          </Box>
        </DashboardShell>
      </Box>
    </>
  );
}
