import { useEffect, useState, useCallback, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Box,
  Heading,
  Text,
  VStack,
  HStack,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  Badge,
  Select,
  Input,
  useColorModeValue,
  Button,
} from '@chakra-ui/react';
import Navigation from '../components/Navigation';
import SEO from '../components/SEO.jsx';
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

const ACTION_COLORS = {
  ALERT_QUEUED: 'blue',
  ALERT_SENT: 'green',
  ALERT_SEND_FAILED: 'red',
  ALERT_SKIPPED_LIMIT: 'orange',
  LIMIT_REMINDER_SENT: 'purple',
  LOGIN_SUCCESS: 'green',
  LOGIN_FAILED: 'red',
  LOGIN_SUCCESS_2FA: 'green',
};

// Exhaustive list of all possible audit actions
// This allows filtering for any action type, even if not present in the current loaded events
const ALL_ACTION_TYPES = [
  // Authentication
  'LOGIN_SUCCESS',
  'LOGIN_FAILED',
  'LOGIN_SUCCESS_2FA',
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

export default function Audit({
  session,
  onLogout,
  onAccountClick,
  onNavigateToDashboard,
  onNavigateToLanding,
}) {
  const navigate = useNavigate();
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [hasMore, setHasMore] = useState(true);
  const [error, setError] = useState('');
  const [query, setQuery] = useState('');
  const [actionFilter, setActionFilter] = useState('');
  const [limit] = useState(50);
  /** Start offset of the last fetched page; kept in a ref so updating it does not recreate `load` and retrigger the filter effect. */
  const pageOffsetRef = useRef(0);
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

  const cardBg = useColorModeValue('rgba(255, 255, 255, 0.95)', 'gray.800');
  const borderColor = useColorModeValue('gray.400', 'gray.600');
  const emptyTextColor = useColorModeValue('gray.600', 'gray.400');

  const load = useCallback(
    async (isMore = false) => {
      if (authorized === false) return;
      try {
        if (isMore) {
          setLoadingMore(true);
        } else {
          setLoading(true);
          pageOffsetRef.current = 0;
        }
        setError('');
        const viewerOnly = !isManagerOrAdminAny && !isAdminAny;
        // Core: block viewers (no backend calls)
        if (viewerOnly) {
          setEvents([]);
          return;
        }
        // Core: non-admins cannot view organization scope
        let effectiveScope = scope;
        if (!isAdminAny && effectiveScope === 'organization') {
          effectiveScope = 'workspace';
        }
        if (!isAdminOrg && effectiveScope === 'organization') {
          effectiveScope = 'workspace';
        }
        const effectiveWorkspaceId = auditWorkspaceId || workspaceId || null;
        const currentOffset = isMore ? pageOffsetRef.current + limit : 0;
        const eventsData = await alertAPI.getAuditEvents(limit, currentOffset, {
          scope: effectiveScope,
          workspaceId: effectiveWorkspaceId,
          action: actionFilter || null,
          query: query || null,
        });

        const newEvents = Array.isArray(eventsData) ? eventsData : [];
        if (isMore) {
          setEvents(prev => [...prev, ...newEvents]);
          pageOffsetRef.current = currentOffset;
        } else {
          setEvents(newEvents);
          pageOffsetRef.current = 0;
        }
        setHasMore(newEvents.length === limit);
      } catch (e) {
        setError('Failed to load audit events');
      } finally {
        setLoading(false);
        setLoadingMore(false);
      }
    },
    [
      authorized,
      limit,
      scope,
      workspaceId,
      auditWorkspaceId,
      isManagerOrAdminAny,
      isAdminAny,
      actionFilter,
      isAdminOrg,
      query,
    ]
  );

  useEffect(() => {
    load();
  }, [
    load,
    authorized,
    scope,
    workspaceId,
    auditWorkspaceId,
    isManagerOrAdminAny,
    isAdminAny,
    actionFilter,
    isAdminOrg,
    query,
  ]);

  // Redirect viewers (no manager/admin role) only when we have workspaces; avoid redirect when list empty (e.g. bootstrap admin)
  useEffect(() => {
    if (
      _rolesLoaded &&
      workspaces.length > 0 &&
      !isManagerOrAdminAny &&
      !isAdminAny
    ) {
      try {
        navigate('/dashboard', { replace: true });
      } catch (_) {}
    }
  }, [
    _rolesLoaded,
    workspaces.length,
    isManagerOrAdminAny,
    isAdminAny,
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
        const allow = items.length === 0 ? true : managerAny;
        setAuthorized(allow);
        if (!allow) {
          try {
            navigate('/dashboard', { replace: true });
          } catch (_) {}
        }
      } catch (_) {
        setAuthorized(false);
        try {
          navigate('/dashboard', { replace: true });
        } catch (_) {}
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [navigate]);

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

    // Integration events
    if (
      action === 'INTEGRATION_SCAN' ||
      action === 'INTEGRATION_DETECT_REGIONS'
    ) {
      const formatted = formatIntegrationMetadata(ev);
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

  async function exportJson() {
    try {
      const effectiveScope =
        isAdminAny && isAdminOrg
          ? scope
          : scope === 'organization'
            ? 'workspace'
            : scope;
      const effectiveWorkspaceId = auditWorkspaceId || workspaceId || null;
      const { blob, filename, contentType } = await alertAPI.exportAudit({
        scope: effectiveScope,
        workspaceId:
          effectiveScope === 'workspace' ? effectiveWorkspaceId : null,
        format: 'json',
        limit: 10000,
        action: actionFilter || null,
        query: query || null,
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
      const effectiveScope =
        isAdminAny && isAdminOrg
          ? scope
          : scope === 'organization'
            ? 'workspace'
            : scope;
      const effectiveWorkspaceId = auditWorkspaceId || workspaceId || null;
      const { blob, filename, contentType } = await alertAPI.exportAudit({
        scope: effectiveScope,
        workspaceId:
          effectiveScope === 'workspace' ? effectiveWorkspaceId : null,
        format: 'csv',
        limit: 10000,
        action: actionFilter || null,
        query: query || null,
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
  const _overlayBg = useColorModeValue('whiteAlpha.700', 'blackAlpha.600');
  // UI scope:
  // - Admins: respect selected scope
  // - Non-admins: allow 'user' and 'workspace'; coerce 'organization' to 'workspace'
  const scopeUI = isAdminAny
    ? scope
    : scope === 'organization'
      ? 'workspace'
      : scope;

  return (
    <>
      <SEO
        title='Audit Log'
        description='View audit logs and activity history'
        noindex
      />
      <Navigation
        user={session}
        onLogout={onLogout}
        onAccountClick={onAccountClick}
        onNavigateToDashboard={onNavigateToDashboard}
        onNavigateToLanding={onNavigateToLanding}
      />

      <Box maxW='6xl' mx='auto' p={{ base: 4, md: 6 }} overflowX='hidden'>
        <VStack spacing={6} align='stretch'>
          <Heading size='lg'>Audit Log</Heading>

          <Box
            bg={cardBg}
            p={6}
            borderRadius='md'
            boxShadow='sm'
            border='1px solid'
            borderColor={borderColor}
            position='relative'
          >
            <Box>
              <HStack spacing={3} mb={4} flexWrap='wrap'>
                <Input
                  placeholder='Search action or metadata...'
                  value={query}
                  onChange={e => setQuery(e.target.value)}
                  maxW='320px'
                />
                <Select
                  placeholder='All actions'
                  value={actionFilter}
                  onChange={e => setActionFilter(e.target.value)}
                  maxW='220px'
                  title='Filter by specific action type'
                >
                  {uniqueActions.map(a => (
                    <option key={a} value={a}>
                      {toTitle(a)}
                    </option>
                  ))}
                </Select>
                {/* Scope selector: admins can choose; managers can choose between user/workspace */}
                {isAdminAny && isAdminOrg ? (
                  <Select
                    value={scope}
                    onChange={e => {
                      const v = e.target.value;
                      setScope(v);
                      try {
                        localStorage.setItem('tt_audit_scope', v);
                      } catch (_) {}
                    }}
                    maxW='220px'
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
                      // Persist only allowed values for non-admins
                      const next = v === 'organization' ? 'workspace' : v;
                      setScope(next);
                      try {
                        localStorage.setItem('tt_audit_scope', next);
                      } catch (_) {}
                    }}
                    maxW='220px'
                  >
                    <option value='user'>My actions</option>
                    <option value='workspace'>This workspace</option>
                  </Select>
                )}
                {/* Workspace selector (visible for manager/admin) */}
                {isManagerOrAdminAny && (
                  <Select
                    value={auditWorkspaceId || workspaceId || ''}
                    onChange={e => {
                      const nextId = e.target.value;
                      setAuditWorkspaceId(nextId);
                      // If admin was viewing "My actions", switch to workspace scope so selection applies
                      if (isAdminAny && scope !== 'workspace') {
                        try {
                          setScope('workspace');
                        } catch (_) {}
                      }
                    }}
                    maxW='260px'
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
                <Button onClick={() => load()} isLoading={loading}>
                  Refresh
                </Button>
                <Button variant='outline' onClick={exportJson}>
                  Export JSON
                </Button>
                <Button variant='outline' onClick={exportCsv}>
                  Export CSV
                </Button>
              </HStack>

              {error ? (
                <Text color='red.500'>{error}</Text>
              ) : filtered.length === 0 ? (
                <Text color={emptyTextColor}>No audit events found.</Text>
              ) : (
                <Box overflowX='auto'>
                  <Table size='sm' variant='simple'>
                    <Thead>
                      <Tr>
                        <Th>Time</Th>
                        <Th>Action</Th>
                        <Th>User</Th>
                        <Th>Workspace</Th>
                        <Th>Metadata</Th>
                      </Tr>
                    </Thead>
                    <Tbody>
                      {filtered.map(ev => (
                        <Tr key={ev.id}>
                          <Td>{formatDateTime(ev.occurred_at)}</Td>
                          <Td>
                            <Badge
                              colorScheme={ACTION_COLORS[ev.action] || 'gray'}
                            >
                              {ev.action}
                            </Badge>
                          </Td>
                          <Td>{ev.actor_display_name || ''}</Td>
                          <Td>{ev.workspace_name || ev.workspace_id || ''}</Td>
                          <Td maxW='800px'>
                            <Box display={{ base: 'none', md: 'block' }}>
                              <TruncatedText
                                text={formatMetadata(ev)}
                                maxLines={3}
                                maxWidth='800px'
                              />
                            </Box>
                            <Box display={{ base: 'block', md: 'none' }}>
                              <Button
                                size='xs'
                                variant='outline'
                                onClick={() => {
                                  try {
                                    const pretty =
                                      formatMetadata(ev) ||
                                      (ev.metadata
                                        ? JSON.stringify(ev.metadata, null, 2)
                                        : '');
                                    alert(pretty || '{}');
                                  } catch (_) {}
                                }}
                              >
                                View
                              </Button>
                            </Box>
                          </Td>
                        </Tr>
                      ))}
                    </Tbody>
                  </Table>
                  {hasMore && (
                    <Box display='flex' justifyContent='center' mt={6} mb={2}>
                      <Button
                        onClick={() => load(true)}
                        isLoading={loadingMore}
                        variant='ghost'
                        size='sm'
                        colorScheme='blue'
                      >
                        Load More
                      </Button>
                    </Box>
                  )}
                </Box>
              )}
            </Box>
          </Box>
        </VStack>
      </Box>
    </>
  );
}
