import { useEffect, useState, useRef, useMemo, useCallback } from 'react';
import { useLocation } from 'react-router-dom';
import {
  Box,
  Heading,
  Text,
  VStack,
  FormControl,
  FormLabel,
  FormErrorMessage,
  Input,
  Button,
  Alert,
  AlertIcon,
  AlertTitle,
  AlertDescription,
  HStack,
  Stack,
  useColorModeValue,
  useBreakpointValue,
  Link,
  Select,
  Textarea,
  IconButton,
  Code,
  Badge,
  AlertDialog,
  AlertDialogBody,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogContent,
  AlertDialogOverlay,
  Checkbox,
  CheckboxGroup,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  Divider,
  Tooltip,
  Image,
  Icon,
} from '@chakra-ui/react';
import apiClient, { alertAPI, workspaceAPI } from '../utils/apiClient';
import { showSuccess, showWarning } from '../utils/toast.js';
import Navigation from '../components/Navigation';
import SEO from '../components/SEO.jsx';
import { trackEvent } from '../utils/analytics.js';
import { useWorkspace } from '../utils/WorkspaceContext.jsx';
import { logger } from '../utils/logger';
import { FiCopy, FiGlobe } from 'react-icons/fi';
import { SiDiscord, SiPagerduty } from 'react-icons/si';
import {
  TOUR_MOCK_WEBHOOKS,
  TOUR_MOCK_CONTACT_GROUPS,
  TOUR_MOCK_WORKSPACE_CONTACTS,
} from '../constants/tourMockData.js';

function normalizeThresholds(csv) {
  if (!csv || typeof csv !== 'string') return [];
  return csv
    .split(',')
    .map(s => s.trim())
    .filter(Boolean)
    .map(Number)
    .filter(n => Number.isFinite(n))
    .filter(n => n >= -365 && n <= 730)
    .sort((a, b) => b - a);
}

function isValidEmail(email) {
  if (!email || typeof email !== 'string') return false;
  const trimmed = email.trim();
  // Check for spaces
  if (trimmed.includes(' ')) return false;
  // RFC 5322 compliant regex (simplified but checks for valid format)
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(trimmed);
}

export default function AlertPreferences({
  session,
  showProductTour,
  onLogout,
  onAccountClick,
  onNavigateToDashboard,
  onNavigateToLanding,
}) {
  const location = useLocation();
  const { workspaceId, selectWorkspace } = useWorkspace();
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const [whatsappAvailable, setWhatsappAvailable] = useState(false);
  const [thresholdsCsv, setThresholdsCsv] = useState('30,14,7,1,0');
  const [thresholdError, setThresholdError] = useState('');
  const [emailEnabled, setEmailEnabled] = useState(true);
  const [webhookUrls, setWebhookUrls] = useState([]);
  const [testingWebhook, setTestingWebhook] = useState(null);
  const [testCooldowns, setTestCooldowns] = useState({});
  const [waContactCooldowns, setWaContactCooldowns] = useState({}); // contactId -> until timestamp
  const [savingToggles, setSavingToggles] = useState(false);
  const [disableAllDialogOpen, setDisableAllDialogOpen] = useState(false);
  const [disableAllTarget, setDisableAllTarget] = useState('');
  // Contact groups state (per workspace)
  const [contactGroups, setContactGroups] = useState([]); // [{id,name,emails:string[], webhook_names?:string[]}]
  const [defaultContactGroupId, setDefaultContactGroupId] = useState('');
  const [editingGroupId, setEditingGroupId] = useState('');
  const [groupName, setGroupName] = useState('');
  const [groupEmailsText, setGroupEmailsText] = useState('');
  const [groupWebhookNames, setGroupWebhookNames] = useState([]);
  const [groupEmailContactIds, setGroupEmailContactIds] = useState([]);
  const [groupWhatsappContactIds, setGroupWhatsappContactIds] = useState([]);
  const [selectedGroupId, setSelectedGroupId] = useState('');
  const [defaultReassignedOpen, setDefaultReassignedOpen] = useState(false);
  const [defaultReassignedName, setDefaultReassignedName] = useState('');
  const groupNameInputRef = useRef(null);
  const [groupSaveAttempted, setGroupSaveAttempted] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const previousWorkspaceId = useRef(null);
  const [deleteTargetId, setDeleteTargetId] = useState('');
  const [deletingGroup, setDeletingGroup] = useState(false);
  // Group thresholds override (CSV string). Empty means inherit workspace defaults
  const [groupThresholdsCsv, setGroupThresholdsCsv] = useState('');
  const [groupWeeklyDigestEmail, setGroupWeeklyDigestEmail] = useState(false);
  const [groupWeeklyDigestWhatsapp, setGroupWeeklyDigestWhatsapp] =
    useState(false);
  const [groupWeeklyDigestWebhooks, setGroupWeeklyDigestWebhooks] =
    useState(false);
  const [contacts, setContacts] = useState([]);
  const [newContactFirstName, setNewContactFirstName] = useState('');
  const [newContactLastName, setNewContactLastName] = useState('');
  const [newContactPhone, setNewContactPhone] = useState('');
  const [newContactDetailsOpen, setNewContactDetailsOpen] = useState(false);
  const [newContactDetails, setNewContactDetails] = useState({});
  const [testingContact, setTestingContact] = useState(null);
  const [contactPhoneError, setContactPhoneError] = useState('');
  const [editingContactId, setEditingContactId] = useState(null);
  const [editContactFirstName, setEditContactFirstName] = useState('');
  const [editContactLastName, setEditContactLastName] = useState('');
  const [editContactPhone, setEditContactPhone] = useState('');
  const [editContactDetails, setEditContactDetails] = useState({});
  const [dwStart, setDwStart] = useState('');
  const [dwEnd, setDwEnd] = useState('');
  const [dwTz, setDwTz] = useState('');
  // Core (OSS): no group or member caps
  const groupCap = Infinity;
  const memberCap = Infinity;
  const cancelRef = useRef();
  const didMountRef = useRef(false);

  const contactById = useMemo(() => {
    const map = new Map();
    (Array.isArray(contacts) ? contacts : []).forEach(contact => {
      if (!contact || !contact.id) return;
      map.set(String(contact.id), contact);
    });
    return map;
  }, [contacts]);

  // Memoize email list extraction function
  const emailListFromIds = useCallback(
    ids => {
      if (!Array.isArray(ids)) return [];
      return ids
        .map(id => {
          const contact = contactById.get(String(id));
          if (!contact) return '';
          const raw = contact?.details?.email;
          return typeof raw === 'string' ? raw.trim().toLowerCase() : '';
        })
        .filter(email => email && isValidEmail(email));
    },
    [contactById]
  );

  // Memoize inline validation helpers for contact group editor
  const _rawEmailTokens = useMemo(
    () =>
      String(groupEmailsText || '')
        .split(/[\n,]+/)
        .map(s => s.trim())
        .filter(Boolean),
    [groupEmailsText]
  );
  const hasEmailInGroup = useMemo(
    () =>
      Array.isArray(groupEmailContactIds) && groupEmailContactIds.length > 0,
    [groupEmailContactIds]
  );
  const hasWebhookInGroup = useMemo(
    () => Array.isArray(groupWebhookNames) && groupWebhookNames.length > 0,
    [groupWebhookNames]
  );
  const hasWhatsappInGroup = useMemo(
    () =>
      whatsappAvailable &&
      Array.isArray(groupWhatsappContactIds) &&
      groupWhatsappContactIds.length > 0,
    [whatsappAvailable, groupWhatsappContactIds]
  );
  const isEmptyGroupInvalid = useMemo(
    () => !hasEmailInGroup && !hasWhatsappInGroup && !hasWebhookInGroup,
    [hasEmailInGroup, hasWhatsappInGroup, hasWebhookInGroup]
  );

  // Memoize total unique people selected (not per channel)
  const totalSelectedPeople = useMemo(
    () => new Set([...groupEmailContactIds, ...groupWhatsappContactIds]).size,
    [groupEmailContactIds, groupWhatsappContactIds]
  );
  const isOverMemberLimit = useMemo(
    () => totalSelectedPeople > memberCap,
    [totalSelectedPeople, memberCap]
  );

  // Workspace role and list for selector
  const [workspaces, setWorkspaces] = useState([]);
  // Default to viewer until role is known to avoid unlocking controls before permissions load
  const [isViewer, setIsViewer] = useState(true);
  const [roleKnown, setRoleKnown] = useState(false);
  const [_workspaceRole, setWorkspaceRole] = useState('');

  const cardBg = useColorModeValue('rgba(255, 255, 255, 0.95)', 'gray.800');
  const borderColor = useColorModeValue('gray.400', 'gray.600');

  // Move useColorModeValue calls to top level to avoid React Hook rules violations
  const webhookBoxBg = useColorModeValue(
    'rgba(255, 255, 255, 0.95)',
    'gray.700'
  );
  const isMobile = useBreakpointValue({ base: true, md: false });
  const discordColor = '#5865F2';
  const pagerdutyColor = '#06AC38';
  const internetColor = useColorModeValue('cyan.500', 'cyan.400');
  // All color mode values used in JSX must be defined here
  const grayTextColor = useColorModeValue('gray.600', 'gray.400');
  const blueRowBg = useColorModeValue('rgba(245, 250, 255, 0.95)', 'gray.700');

  // Helper function to render webhook vendor logo - must be defined after all hooks
  const renderWebhookLogo = kind => {
    const logoSize = 5; // boxSize in Chakra units
    switch (kind) {
      case 'slack':
        return (
          <Image
            src='/Branding/slack.svg'
            boxSize={logoSize}
            alt='Slack'
            title='Slack'
          />
        );
      case 'teams':
        return (
          <Image
            src='/Branding/teams.svg'
            boxSize={logoSize}
            alt='Microsoft Teams'
            title='Microsoft Teams'
          />
        );
      case 'discord':
        return (
          <Icon
            as={SiDiscord}
            boxSize={logoSize}
            aria-label='Discord'
            title='Discord'
            color={discordColor}
          />
        );
      case 'pagerduty':
        return (
          <Icon
            as={SiPagerduty}
            boxSize={logoSize}
            aria-label='PagerDuty'
            title='PagerDuty'
            color={pagerdutyColor}
          />
        );
      case 'generic':
      default:
        return (
          <Icon
            as={FiGlobe}
            boxSize={logoSize}
            aria-label='Generic Webhook'
            title='Generic Webhook'
            color={internetColor}
          />
        );
    }
  };

  // Owner contact is now seeded on account/workspace creation in backend

  useEffect(() => {
    let mounted = true;
    async function load() {
      // Use mock data for product tour to ensure consistent experience
      if (showProductTour) {
        setThresholdsCsv('30,14,7,1,0');
        setDwStart('00:00');
        setDwEnd('23:59');
        setDwTz('UTC');
        setContacts(TOUR_MOCK_WORKSPACE_CONTACTS);
        setEmailEnabled(true);
        setWebhookUrls(TOUR_MOCK_WEBHOOKS);
        setContactGroups(TOUR_MOCK_CONTACT_GROUPS);
        setDefaultContactGroupId(TOUR_MOCK_CONTACT_GROUPS[0]?.id);
        setSelectedGroupId(TOUR_MOCK_CONTACT_GROUPS[0]?.id);
        setLoading(false);
        return;
      }

      try {
        setLoading(true);
        if (!workspaceId) {
          // No workspace selected yet; wait for Navigation to set it
          return;
        }
        const res = { data: await workspaceAPI.getAlertSettings(workspaceId) };
        if (!mounted) return;
        const data = res?.data || {};
        const ts = Array.isArray(data.alert_thresholds)
          ? data.alert_thresholds
          : [30, 14, 7, 1, 0];
        setThresholdsCsv(ts.join(','));
        setWhatsappAvailable(data.whatsapp_available === true);
        // Defaults to UTC business hours when not configured
        setDwStart(data.delivery_window_start || '00:00');
        setDwEnd(data.delivery_window_end || '23:59');
        setDwTz(data.delivery_window_tz || 'UTC');
        // Load workspace contacts
        try {
          const contactsRes = await apiClient.get(
            `/api/v1/workspaces/${workspaceId}/contacts`
          );
          setContacts(contactsRes?.data?.items || []);
        } catch (_) {
          setContacts([]);
        }
        setEmailEnabled(data.email_alerts_enabled !== false);
        setWebhookUrls(
          Array.isArray(data.webhook_urls)
            ? data.webhook_urls.map(w => ({
                ...w,
                verified: Boolean((w.url || '').trim()),
                verifiedUrl: (w.url || '').trim(),
              }))
            : []
        );
        // Contact groups
        try {
          let groups = Array.isArray(data.contact_groups)
            ? data.contact_groups
            : [];
          setContactGroups(groups);
          setDefaultContactGroupId(String(data.default_contact_group_id || ''));
          setSelectedGroupId(
            String(data.default_contact_group_id || groups[0]?.id || '')
          );

          // If no groups exist yet, create a default group with owner's contact
          if (groups.length === 0) {
            const adminEmail = (session?.email || '').trim().toLowerCase();
            // Find the owner's contact in workspace_contacts by matching email
            const ownerContact = (contactsRes?.data?.items || []).find(
              c => String(c.details?.email || '').toLowerCase() === adminEmail
            );

            const id = 'default_admin';
            const seed = [
              {
                id,
                name: 'Default admin email',
                email_contact_ids: ownerContact ? [ownerContact.id] : [],
                whatsapp_contact_ids: [],
              },
            ];
            groups = seed; // Update local groups variable
            setContactGroups(seed);
            setDefaultContactGroupId(id);
            // Prefill editor
            setEditingGroupId(id);
            setGroupName('Default admin email');
            // Select owner's contact if found
            if (ownerContact) {
              setGroupEmailContactIds([ownerContact.id]);
            }
            setSelectedGroupId(id);

            // Persist default group to backend to prevent data loss on page refresh
            try {
              await workspaceAPI.updateAlertSettings(workspaceId, {
                contact_groups: seed,
                default_contact_group_id: id,
              });
            } catch (e) {
              logger.warn('Failed to persist default contact group', e);
              // Don't block UI loading, but user might need to save manually
            }
          }
        } catch (_) {
          setContactGroups([]);
          setDefaultContactGroupId('');
          setSelectedGroupId('');
        }
      } catch (e) {
        if (!mounted) return;
        if (e?.response?.status !== 403) {
          setError('Failed to load alert preferences');
        } else {
          // Viewer or insufficient role: show info panel only, suppress error banner
          setError('');
        }
      } finally {
        if (mounted) setLoading(false);
      }
    }
    load();
    return () => {
      mounted = false;
    };
  }, [session?.email, location.search, workspaceId, showProductTour]);

  // Removed owner auto-contact creation in frontend; handled by backend

  // Load accessible workspaces and determine role for the selected workspace
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const ws = await workspaceAPI.list(50, 0);
        if (cancelled) return;
        const items = Array.isArray(ws?.items) ? ws.items : [];
        setWorkspaces(items);
        const current = items.find(w => w.id === workspaceId);
        const role = String(current?.role || '').toLowerCase();
        setWorkspaceRole(role);
        const viewer = role === 'viewer';
        setIsViewer(viewer);
        // If viewer is on a non-personal workspace, redirect to personal workspace
        // Do not auto-redirect viewers; show disabled UI instead
      } catch (_) {
        setWorkspaces([]);
        setIsViewer(false);
        setWorkspaceRole('');
      } finally {
        setRoleKnown(true);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [workspaceId]);

  // Removed ticking timestamp as we don't render a live countdown for the Test button

  // Auto-save toggles for paid plans when they change (no need to press Save)
  useEffect(() => {
    if (!didMountRef.current) {
      didMountRef.current = true;
      return;
    }
    if (loading) return;
    // Skip auto-save when workspace changes (we're just loading new data, not user editing)
    if (previousWorkspaceId.current !== workspaceId) {
      previousWorkspaceId.current = workspaceId;
      return;
    }
    if (isViewer) return; // do not auto-save for viewers
    // Persist latest toggle values without touching other fields (webhooks flag removed)
    savePartialSettings({ emailEnabled }, false).catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [emailEnabled, loading, workspaceId]);

  function validate() {
    setThresholdError('');
    const list = normalizeThresholds(thresholdsCsv);
    if (list.length === 0) {
      setThresholdError(
        'Please provide at least one valid threshold between -365 and 730'
      );
      return null;
    }
    return list;
  }

  async function handleSave() {
    // Clear previous error/success states at the start
    setError('');
    setSuccess('');
    const list = validate();
    if (!list) return;
    const wsId = workspaceId;
    if (!wsId) {
      setError('Please select a workspace first');
      setSuccess('');
      return;
    }
    try {
      setSaving(true);
      setError('');
      setSuccess('');
      // Persist thresholds only - this is the ONLY operation that uses handleSave
      await workspaceAPI.updateAlertSettings(wsId, { alert_thresholds: list });
      // If we get here, the save was successful
      // Explicitly clear error and set success for Default Workspace Thresholds save
      setError('');
      setSuccess('Preferences updated successfully');
      try {
        showSuccess('Alert thresholds saved');
      } catch (_) {
        // Ignore toast errors - don't affect main error/success state
      }
      try {
        trackEvent('alert_pref_updated', { field: 'thresholds' });
      } catch (_) {
        // Ignore analytics errors - don't affect main error/success state
      }
    } catch (e) {
      // Only set error if this specific save operation failed
      const errorMessage =
        e?.response?.data?.error || e?.message || 'Failed to save preferences';
      setError(errorMessage);
      setSuccess('');
      logger.error('Failed to save thresholds:', e);
    } finally {
      setSaving(false);
    }
  }

  // Save only webhook URLs (entire list)
  async function handleSaveWebhooks() {
    try {
      if (isViewer) return; // viewers cannot modify webhooks
      setSavingToggles(true);
      // Persist only verified or unchanged (verifiedUrl===url) non-empty webhooks
      const toPersist = webhookUrls.filter(w => {
        const url = (w.url || '').trim();
        if (!url) return false;
        return (w.verified && w.verifiedUrl === url) || w.verifiedUrl === url;
      });
      const wsId = workspaceId;
      if (!wsId) {
        setError('Please select a workspace first');
        return;
      }
      const payload = {
        webhook_urls: toPersist,
      };
      await workspaceAPI.updateAlertSettings(wsId, payload);
      setSuccess('Webhooks saved');
      showSuccess('Webhooks saved');
      // Preserve current group editor state when saving webhooks list
      try {
        if (selectedGroupId) {
          const g = (contactGroups || []).find(
            x => String(x.id) === String(selectedGroupId)
          );
          if (g) startEditGroup(g);
        }
      } catch (_) {}
      try {
        trackEvent('alert_pref_updated', { field: 'webhooks' });
      } catch (_) {}
    } catch (e) {
      if (e?.response?.status === 403) {
        return; // suppress banner for viewers
      }
      setError(e?.response?.data?.error || 'Failed to save webhooks');
    } finally {
      setSavingToggles(false);
    }
  }

  // --- Contact Groups helpers ---
  const startEditGroup = useCallback(
    g => {
      setEditingGroupId(g?.id || '');
      setGroupName(g?.name || '');
      const emailIds = Array.isArray(g?.email_contact_ids)
        ? g.email_contact_ids
        : [];
      const waIds = Array.isArray(g?.whatsapp_contact_ids)
        ? g.whatsapp_contact_ids
        : [];
      const emailList = emailListFromIds(emailIds);
      setGroupEmailsText(emailList.join(', '));
      try {
        setGroupEmailContactIds(emailIds);
        setGroupWhatsappContactIds(waIds);
      } catch (_) {
        setGroupEmailContactIds([]);
        setGroupWhatsappContactIds([]);
      }
      const names = Array.isArray(g?.webhook_names)
        ? g.webhook_names.filter(Boolean)
        : g?.webhook_name
          ? [g.webhook_name]
          : [];
      setGroupWebhookNames(names);
      try {
        if (Array.isArray(g?.thresholds) && g.thresholds.length > 0) {
          setGroupThresholdsCsv(g.thresholds.join(','));
        } else {
          setGroupThresholdsCsv(thresholdsCsv);
        }
      } catch (_) {
        setGroupThresholdsCsv(thresholdsCsv);
      }
      setGroupWeeklyDigestEmail(g?.weekly_digest_email === true);
      setGroupWeeklyDigestWhatsapp(g?.weekly_digest_whatsapp === true);
      setGroupWeeklyDigestWebhooks(g?.weekly_digest_webhooks === true);
    },
    [emailListFromIds, thresholdsCsv]
  );

  // Ensure editor is populated on initial load for the selected/default group
  useEffect(() => {
    if (loading) return;
    if (!selectedGroupId) return;
    const g = (contactGroups || []).find(
      x => String(x.id) === String(selectedGroupId)
    );
    if (!g) return;
    // Only (re)populate if editing a different group or nothing is loaded yet
    if (editingGroupId !== selectedGroupId) {
      startEditGroup(g);
    }
  }, [loading, selectedGroupId, contactGroups, editingGroupId, startEditGroup]);

  // When switching workspace, immediately clear editor and selection to avoid stale state
  useEffect(() => {
    setSelectedGroupId('');
    setEditingGroupId('');
    resetGroupEditor();
  }, [workspaceId]);

  function resetGroupEditor() {
    setEditingGroupId('');
    setGroupName('');
    setGroupEmailsText('');
    setGroupWebhookNames([]);
    setGroupEmailContactIds([]);
    setGroupWhatsappContactIds([]);
    setGroupThresholdsCsv('');
    setGroupWeeklyDigestEmail(false);
    setGroupWeeklyDigestWhatsapp(false);
    setGroupWeeklyDigestWebhooks(false);
  }

  async function saveGroup() {
    if (loading) return; // guard against saving while workspace data is refreshing
    setGroupSaveAttempted(true);
    const name = (groupName || '').trim();
    if (!name) return;
    // Ensure selected group belongs to the currently loaded list
    if (
      editingGroupId &&
      !(contactGroups || []).some(g => String(g.id) === String(editingGroupId))
    ) {
      return; // stale selection; wait for data refresh
    }
    const emailIds = Array.from(new Set(groupEmailContactIds)).filter(Boolean);
    const waIds = Array.from(new Set(groupWhatsappContactIds)).filter(Boolean);

    // Enforce per-group member cap: limit total unique people, not per channel
    const allSelectedIds = Array.from(new Set([...emailIds, ...waIds]));
    const trimmedIds = allSelectedIds.slice(0, memberCap);
    const trimmedEmailIds = emailIds.filter(id => trimmedIds.includes(id));
    const trimmedWaIds = waIds.filter(id => trimmedIds.includes(id));
    // Disallow empty groups: must have at least one channel or a webhook selected
    const hasEmails = trimmedEmailIds.length > 0;
    const hasContacts = trimmedWaIds.length > 0;
    const hasWebhook =
      Array.isArray(groupWebhookNames) && groupWebhookNames.length > 0;
    if (!hasEmails && !hasContacts && !hasWebhook) return;
    let next = [...contactGroups];
    const wasCreate = !editingGroupId;
    let targetId = editingGroupId;
    // Compute normalized fields to persist (backend expects email_contact_ids[] and whatsapp_contact_ids[])
    const _byId = new Map((contacts || []).map(c => [c.id, c]));

    if (editingGroupId) {
      next = next.map(g =>
        g.id === editingGroupId
          ? {
              ...g,
              name,
              email_contact_ids: hasEmails ? trimmedEmailIds : [],
              whatsapp_contact_ids: hasContacts ? trimmedWaIds : [],
              webhook_names: (groupWebhookNames || []).filter(Boolean),
              weekly_digest_email: groupWeeklyDigestEmail,
              weekly_digest_whatsapp: groupWeeklyDigestWhatsapp,
              weekly_digest_webhooks: groupWeeklyDigestWebhooks,
              // thresholds override saved only if different from workspace defaults
              ...(function () {
                try {
                  const cur = normalizeThresholds(groupThresholdsCsv);
                  const def = normalizeThresholds(thresholdsCsv);
                  if (
                    cur.length > 0 &&
                    (cur.length !== def.length ||
                      cur.some((n, i) => n !== def[i]))
                  ) {
                    return { thresholds: cur };
                  }
                } catch (_) {}
                // Remove thresholds key if equal/empty to inherit
                const { thresholds: _thresholds, ...rest } = g || {};
                return rest && false ? rest : {};
              })(),
            }
          : g
      );
    } else {
      // Workspace-level cap on number of groups
      if (next.length >= groupCap) return;
      const id = `${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
      // Compute thresholds override for new group: only persist if different from workspace defaults
      const newGroup = {
        id,
        name,
        email_contact_ids: hasEmails ? trimmedEmailIds : [],
        whatsapp_contact_ids: hasContacts ? trimmedWaIds : [],
        webhook_names: (groupWebhookNames || []).filter(Boolean),
        weekly_digest_email: groupWeeklyDigestEmail,
        weekly_digest_whatsapp: groupWeeklyDigestWhatsapp,
        weekly_digest_webhooks: groupWeeklyDigestWebhooks,
      };
      try {
        const cur = normalizeThresholds(groupThresholdsCsv || thresholdsCsv);
        const def = normalizeThresholds(thresholdsCsv);
        if (
          cur.length > 0 &&
          (cur.length !== def.length || cur.some((n, i) => n !== def[i]))
        ) {
          newGroup.thresholds = cur;
        }
      } catch (_) {}
      next = [...next, newGroup];
      targetId = id;
      if (!defaultContactGroupId) setDefaultContactGroupId(id);
    }
    setContactGroups(next);
    // Keep editor focused on the saved group and re-populate fields from canonical state
    try {
      const saved = next.find(
        g => String(g.id) === String(targetId || editingGroupId)
      );
      if (saved) {
        setSelectedGroupId(saved.id);
        setEditingGroupId(saved.id);
        setGroupName(saved.name || '');
        const savedEmailIds = Array.isArray(saved.email_contact_ids)
          ? saved.email_contact_ids
          : [];
        setGroupEmailsText(emailListFromIds(savedEmailIds).join(', '));
        setGroupEmailContactIds(savedEmailIds);
        setGroupWhatsappContactIds(
          Array.isArray(saved.whatsapp_contact_ids)
            ? saved.whatsapp_contact_ids
            : []
        );
        setGroupWebhookNames(
          Array.isArray(saved.webhook_names) ? saved.webhook_names : []
        );
      }
    } catch (_) {}
    setGroupSaveAttempted(false);
    setError('');
    // Persist via settings
    try {
      if (!workspaceId) return;
      await workspaceAPI.updateAlertSettings(workspaceId, {
        contact_groups: next,
        default_contact_group_id: defaultContactGroupId || next[0]?.id || null,
      });
      setSuccess(
        wasCreate
          ? 'Contact group was successfully created'
          : 'Contact group was successfully saved'
      );
      showSuccess(wasCreate ? 'Contact group created' : 'Contact group saved');
    } catch (e) {
      setError('Failed to save contact groups');
    }
  }

  async function deleteGroup(id) {
    const next = contactGroups.filter(g => g.id !== id);
    const wasDefault = defaultContactGroupId === id;
    const newDefaultId = wasDefault ? next[0]?.id || '' : defaultContactGroupId;
    const newDefaultName = wasDefault && next[0]?.name ? next[0].name : '';

    setContactGroups(next);
    setDefaultContactGroupId(newDefaultId);
    try {
      const nextSelected = newDefaultId || next[0]?.id || '';
      setSelectedGroupId(nextSelected);
      if (nextSelected) {
        const g = next.find(x => String(x.id) === String(nextSelected));
        if (g) startEditGroup(g);
        else resetGroupEditor();
      } else {
        resetGroupEditor();
      }
    } catch (_) {}
    try {
      if (!workspaceId) return;
      await workspaceAPI.updateAlertSettings(workspaceId, {
        contact_groups: next,
        default_contact_group_id: newDefaultId || null,
      });
      // Always reassign tokens from deleted group to default group (or first remaining group)
      const targetGroupId = newDefaultId || next[0]?.id;
      if (targetGroupId) {
        try {
          await apiClient.post(
            `/api/v1/workspaces/${workspaceId}/tokens/reassign-contact-group`,
            {
              from_group_id: id,
              to_group_id: targetGroupId,
            }
          );
        } catch (_) {}
      }
      if (wasDefault && next.length > 0) {
        setDefaultReassignedName(newDefaultName);
        setDefaultReassignedOpen(true);
      }
      showSuccess('Contact group deleted');
    } catch (_) {}
  }

  // Persist a provided webhook list immediately (used by remove)
  async function saveWebhooksListImmediate(listToSave) {
    try {
      if (isViewer) return; // viewers cannot modify webhooks
      setSavingToggles(true);
      const wsId = workspaceId;
      if (!wsId) {
        setError('Please select a workspace first');
        return;
      }
      const payload = {
        webhook_urls: listToSave,
      };
      await workspaceAPI.updateAlertSettings(wsId, payload);
      setSuccess('Webhooks updated');
      showSuccess('Webhooks updated');
      try {
        trackEvent('alert_pref_updated', { field: 'webhooks_list' });
      } catch (_) {}
    } catch (e) {
      if (e?.response?.status === 403) {
        return; // suppress banner for viewers
      }
      setError(e?.response?.data?.error || 'Failed to update webhooks');
    } finally {
      setSavingToggles(false);
    }
  }

  // removed unused handleTestSlack

  async function handleTestWebhook(index) {
    if (isViewer) return; // viewers cannot test webhooks
    const webhook = webhookUrls[index];
    if (!webhook?.url) {
      setError('Please enter a webhook URL first');
      return;
    }
    // Client-side cooldown guard (5 seconds per webhook row)
    const until = testCooldowns[index] || 0;
    if (until > Date.now()) {
      const secs = Math.ceil((until - Date.now()) / 1000);
      setError(`Please wait ${secs}s before sending another test.`);
      return;
    }
    try {
      setTestingWebhook(index);
      await alertAPI.testWebhook(webhook.url, webhook.kind || 'generic', {
        routingKey: webhook.routingKey || undefined,
        severity: webhook.severity || undefined,
        template: webhook.template || undefined,
      });
      // Mark row as verified on successful test and bind to current URL
      setWebhookUrls(prev =>
        prev.map((w, i) =>
          i === index
            ? { ...w, verified: true, verifiedUrl: (w.url || '').trim() }
            : w
        )
      );
    } catch (e) {
      setError(e.message || 'Failed to test webhook');
      // Ensure not verified on failure
      setWebhookUrls(prev =>
        prev.map((w, i) =>
          i === index ? { ...w, verified: false, verifiedUrl: null } : w
        )
      );
    } finally {
      setTestingWebhook(null);
      setTestCooldowns(prev => ({ ...prev, [index]: Date.now() + 5000 }));
    }
  }

  function addWebhook() {
    if (isViewer) return; // viewers cannot add webhooks
    setWebhookUrls([
      ...webhookUrls,
      { url: '', kind: 'generic', verified: false, verifiedUrl: null },
    ]);
  }

  function removeWebhook(index) {
    if (isViewer) return; // viewers cannot remove webhooks
    const newUrls = webhookUrls.filter((_, i) => i !== index);
    setWebhookUrls(newUrls);
    // Immediately persist removal so it survives reload
    saveWebhooksListImmediate(newUrls).catch(() => {});
  }

  function updateWebhook(index, field, value) {
    if (isViewer) return; // viewers cannot edit webhooks
    const updated = [...webhookUrls];
    const prev = updated[index] || {};
    // Only reset verification when URL changes
    if (field === 'url') {
      updated[index] = {
        ...prev,
        [field]: value,
        verified: false,
        verifiedUrl: null,
      };
    } else {
      updated[index] = { ...prev, [field]: value };
    }
    setWebhookUrls(updated);
  }

  async function savePartialSettings(partial, showSuccess = true) {
    try {
      setSavingToggles(true);
      if (!workspaceId) {
        // Workspace not selected yet; skip persisting
        return;
      }
      const payload = {};
      if ('emailEnabled' in partial)
        payload.email_alerts_enabled = partial.emailEnabled;
      // webhooks_enabled flag removed
      await workspaceAPI.updateAlertSettings(workspaceId, payload);
      if (showSuccess) setSuccess('Preferences updated');
      if (showSuccess) {
        showSuccess('Preferences updated');
      }
    } catch (e) {
      if (e?.response?.status === 403) {
        showWarning('Forbidden: insufficient role');
      }
      setError(e?.response?.data?.error || 'Failed to update preferences');
    } finally {
      setSavingToggles(false);
    }
  }

  function handleResetDefaults() {
    setThresholdsCsv('30,14,7,1,0');
    setThresholdError('');
  }

  return (
    <>
      <SEO
        title='Alert Preferences'
        description='Configure your alert preferences and notification channels'
        noindex
      />
      <Navigation
        user={session}
        onLogout={onLogout}
        onAccountClick={onAccountClick}
        onNavigateToDashboard={onNavigateToDashboard}
        onNavigateToLanding={onNavigateToLanding}
      />
      <Box
        maxW={{ base: '2xl', md: '4xl' }}
        mx='auto'
        p={{ base: 4, md: 6 }}
        overflowX='hidden'
        data-tour='preferences-page'
      >
        <VStack spacing={6} align='stretch'>
          <Heading size='lg'>Preferences</Heading>

          {/* Workspace selector or viewer message */}
          <HStack flexWrap='wrap' align='center' gap={2}>
            <Text fontWeight='semibold'>Workspace:</Text>
            <Select
              value={workspaceId || ''}
              onChange={e => {
                const id = e.target.value;
                if (!id) return;
                selectWorkspace(id, { replace: true });
              }}
              onClick={e => e.stopPropagation()}
              minWidth='200px'
              maxWidth='100%'
              width='100%'
              bg={webhookBoxBg}
              borderColor={borderColor}
              borderWidth='2px'
            >
              {(workspaces || []).map(w => (
                <option key={w.id} value={w.id}>
                  {w.name} ({w.role})
                </option>
              ))}
            </Select>
          </HStack>

          {isViewer && (
            <Alert status='info' borderRadius='md'>
              <AlertIcon />
              <AlertDescription>
                You can only modify preferences for your own workspace.
                Modifying them for organization‑managed workspaces is reserved
                to workspace managers or admins.
              </AlertDescription>
            </Alert>
          )}

          {error && (
            <Alert status='error'>
              <AlertIcon />
              <AlertTitle mr={2}>Error</AlertTitle>
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
          {success && (
            <Alert status='success'>
              <AlertIcon />
              <AlertTitle mr={2}>Saved</AlertTitle>
              <AlertDescription>{success}</AlertDescription>
            </Alert>
          )}

          <Box
            data-tour='preferences-thresholds'
            bg={cardBg}
            p={6}
            borderRadius='md'
            boxShadow='sm'
            border='1px solid'
            borderColor={borderColor}
          >
            <Heading size='md' mb={4}>
              Default Workspace Thresholds
            </Heading>
            {/* Plan gating removed: thresholds editable for all plans */}
            <FormControl
              isInvalid={!!thresholdError}
              isDisabled={loading || isViewer || !roleKnown}
            >
              <FormLabel>Alert thresholds (days, comma-separated)</FormLabel>
              <Input
                value={thresholdsCsv}
                onChange={e => setThresholdsCsv(e.target.value)}
                placeholder='30,14,7,1,0'
              />
              <FormErrorMessage>{thresholdError}</FormErrorMessage>
              <Text fontSize='sm' color={grayTextColor} mt={2}>
                Allowed range: -365 (after expiry) to 730 (2 years). Values are
                sorted automatically.
              </Text>
              <Text fontSize='sm' color={grayTextColor} mt={1}>
                1 alert per threshold crossed.
              </Text>
            </FormControl>
            <HStack mt={4} spacing={3}>
              <Button
                onClick={handleResetDefaults}
                variant='outline'
                disabled={loading || isViewer}
              >
                Reset to defaults
              </Button>
              <Button
                colorScheme='blue'
                onClick={handleSave}
                isLoading={saving}
                disabled={loading || !workspaceId || isViewer}
              >
                Save
              </Button>
            </HStack>
          </Box>

          {/* Workspace Delivery Window */}
          <Box
            data-tour='preferences-delivery-window'
            bg={cardBg}
            p={6}
            borderRadius='md'
            boxShadow='sm'
            border='1px solid'
            borderColor={borderColor}
          >
            <Heading size='md' mb={4}>
              Workspace Delivery Window
            </Heading>
            <Text fontSize='sm' color={grayTextColor} mb={2}>
              Applies to all alert channels. Alerts are sent only during this
              window; outside the window they are deferred.
            </Text>
            <HStack>
              <FormControl
                isDisabled={isViewer}
                isInvalid={
                  !!dwStart &&
                  !/^([01]\d|2[0-3]):[0-5]\d$/.test(String(dwStart).trim())
                }
              >
                <FormLabel>Start (HH:mm)</FormLabel>
                <Input
                  placeholder='00:00'
                  value={dwStart}
                  onChange={e => setDwStart(e.target.value)}
                />
                {dwStart &&
                  !/^([01]\d|2[0-3]):[0-5]\d$/.test(String(dwStart).trim()) && (
                    <FormErrorMessage>Use HH:mm (00:00-23:59)</FormErrorMessage>
                  )}
              </FormControl>
              <FormControl
                isDisabled={isViewer}
                isInvalid={
                  !!dwEnd &&
                  !/^([01]\d|2[0-3]):[0-5]\d$/.test(String(dwEnd).trim())
                }
              >
                <FormLabel>End (HH:mm)</FormLabel>
                <Input
                  placeholder='23:59'
                  value={dwEnd}
                  onChange={e => setDwEnd(e.target.value)}
                />
                {dwEnd &&
                  !/^([01]\d|2[0-3]):[0-5]\d$/.test(String(dwEnd).trim()) && (
                    <FormErrorMessage>Use HH:mm (00:00-23:59)</FormErrorMessage>
                  )}
              </FormControl>
              <FormControl isDisabled={isViewer}>
                <FormLabel>Timezone</FormLabel>
                <Select value={dwTz} onChange={e => setDwTz(e.target.value)}>
                  <optgroup label='Common'>
                    <option value='UTC'>UTC (UTC+0)</option>
                    <option value='America/New_York'>
                      America/New_York (UTC-5/-4, EST/EDT)
                    </option>
                    <option value='America/Los_Angeles'>
                      America/Los_Angeles (UTC-8/-7, PST/PDT)
                    </option>
                    <option value='Europe/London'>
                      Europe/London (UTC+0/+1, GMT/BST)
                    </option>
                    <option value='Europe/Zurich'>
                      Europe/Zurich (UTC+1/+2, CET/CEST)
                    </option>
                    <option value='Asia/Tokyo'>Asia/Tokyo (UTC+9, JST)</option>
                  </optgroup>
                  <optgroup label='Americas'>
                    <option value='America/Chicago'>
                      America/Chicago (UTC-6/-5, CST/CDT)
                    </option>
                    <option value='America/Denver'>
                      America/Denver (UTC-7/-6, MST/MDT)
                    </option>
                    <option value='America/Phoenix'>
                      America/Phoenix (UTC-7, MST no DST)
                    </option>
                    <option value='America/Anchorage'>
                      America/Anchorage (UTC-9/-8, AKST/AKDT)
                    </option>
                    <option value='America/Honolulu'>
                      America/Honolulu (UTC-10, HST)
                    </option>
                    <option value='America/Toronto'>
                      America/Toronto (UTC-5/-4, EST/EDT)
                    </option>
                    <option value='America/Vancouver'>
                      America/Vancouver (UTC-8/-7, PST/PDT)
                    </option>
                    <option value='America/Mexico_City'>
                      America/Mexico_City (UTC-6/-5, CST/CDT)
                    </option>
                    <option value='America/Sao_Paulo'>
                      America/Sao_Paulo (UTC-3, BRT)
                    </option>
                    <option value='America/Buenos_Aires'>
                      America/Buenos_Aires (UTC-3, ART)
                    </option>
                  </optgroup>
                  <optgroup label='Europe'>
                    <option value='Europe/Paris'>
                      Europe/Paris (UTC+1/+2, CET/CEST)
                    </option>
                    <option value='Europe/Berlin'>
                      Europe/Berlin (UTC+1/+2, CET/CEST)
                    </option>
                    <option value='Europe/Rome'>
                      Europe/Rome (UTC+1/+2, CET/CEST)
                    </option>
                    <option value='Europe/Madrid'>
                      Europe/Madrid (UTC+1/+2, CET/CEST)
                    </option>
                    <option value='Europe/Amsterdam'>
                      Europe/Amsterdam (UTC+1/+2, CET/CEST)
                    </option>
                    <option value='Europe/Brussels'>
                      Europe/Brussels (UTC+1/+2, CET/CEST)
                    </option>
                    <option value='Europe/Vienna'>
                      Europe/Vienna (UTC+1/+2, CET/CEST)
                    </option>
                    <option value='Europe/Stockholm'>
                      Europe/Stockholm (UTC+1/+2, CET/CEST)
                    </option>
                    <option value='Europe/Dublin'>
                      Europe/Dublin (UTC+0/+1, GMT/IST)
                    </option>
                    <option value='Europe/Lisbon'>
                      Europe/Lisbon (UTC+0/+1, WET/WEST)
                    </option>
                    <option value='Europe/Athens'>
                      Europe/Athens (UTC+2/+3, EET/EEST)
                    </option>
                    <option value='Europe/Helsinki'>
                      Europe/Helsinki (UTC+2/+3, EET/EEST)
                    </option>
                    <option value='Europe/Moscow'>
                      Europe/Moscow (UTC+3, MSK)
                    </option>
                    <option value='Europe/Istanbul'>
                      Europe/Istanbul (UTC+3, TRT)
                    </option>
                  </optgroup>
                  <optgroup label='Asia'>
                    <option value='Asia/Dubai'>Asia/Dubai (UTC+4, GST)</option>
                    <option value='Asia/Kolkata'>
                      Asia/Kolkata (UTC+5:30, IST)
                    </option>
                    <option value='Asia/Bangkok'>
                      Asia/Bangkok (UTC+7, ICT)
                    </option>
                    <option value='Asia/Singapore'>
                      Asia/Singapore (UTC+8, SGT)
                    </option>
                    <option value='Asia/Hong_Kong'>
                      Asia/Hong_Kong (UTC+8, HKT)
                    </option>
                    <option value='Asia/Shanghai'>
                      Asia/Shanghai (UTC+8, CST)
                    </option>
                    <option value='Asia/Seoul'>Asia/Seoul (UTC+9, KST)</option>
                    <option value='Asia/Taipei'>
                      Asia/Taipei (UTC+8, CST)
                    </option>
                    <option value='Asia/Manila'>
                      Asia/Manila (UTC+8, PHT)
                    </option>
                    <option value='Asia/Jakarta'>
                      Asia/Jakarta (UTC+7, WIB)
                    </option>
                  </optgroup>
                  <optgroup label='Pacific'>
                    <option value='Australia/Sydney'>
                      Australia/Sydney (UTC+10/+11, AEDT/AEST)
                    </option>
                    <option value='Australia/Melbourne'>
                      Australia/Melbourne (UTC+10/+11, AEDT/AEST)
                    </option>
                    <option value='Australia/Brisbane'>
                      Australia/Brisbane (UTC+10, AEST no DST)
                    </option>
                    <option value='Australia/Perth'>
                      Australia/Perth (UTC+8, AWST)
                    </option>
                    <option value='Pacific/Auckland'>
                      Pacific/Auckland (UTC+12/+13, NZDT/NZST)
                    </option>
                    <option value='Pacific/Fiji'>
                      Pacific/Fiji (UTC+12, FJT)
                    </option>
                  </optgroup>
                  <optgroup label='Africa & Middle East'>
                    <option value='Africa/Cairo'>
                      Africa/Cairo (UTC+2, EET)
                    </option>
                    <option value='Africa/Johannesburg'>
                      Africa/Johannesburg (UTC+2, SAST)
                    </option>
                    <option value='Africa/Lagos'>
                      Africa/Lagos (UTC+1, WAT)
                    </option>
                    <option value='Africa/Nairobi'>
                      Africa/Nairobi (UTC+3, EAT)
                    </option>
                  </optgroup>
                </Select>
              </FormControl>
            </HStack>
            <HStack mt={3}>
              <Button
                colorScheme='blue'
                onClick={async () => {
                  try {
                    setSavingToggles(true);
                    await workspaceAPI.updateAlertSettings(workspaceId, {
                      delivery_window_start: dwStart || null,
                      delivery_window_end: dwEnd || null,
                      delivery_window_tz: dwTz || null,
                    });
                    showSuccess('Delivery window saved');
                  } catch (e) {
                    setError(
                      e?.response?.data?.error ||
                        'Failed to save delivery window'
                    );
                  } finally {
                    setSavingToggles(false);
                  }
                }}
                isLoading={savingToggles}
                disabled={isViewer || !workspaceId}
              >
                Save
              </Button>
            </HStack>
          </Box>

          {/* Email Panel replaced by Contact Groups */}

          {/* Contacts (& WhatsApp if configured) */}
          <Box
            data-tour='preferences-contacts'
            bg={cardBg}
            p={6}
            borderRadius='md'
            boxShadow='sm'
            border='1px solid'
            borderColor={borderColor}
          >
            <Heading size='md' mb={4}>
              Contacts
            </Heading>
            <VStack align='stretch' spacing={4}>
              {isViewer && (
                <Alert status='info' borderRadius='md'>
                  <AlertIcon />
                  <AlertDescription>
                    Contacts are read-only for viewers. Only workspace managers
                    and admins can add or modify contacts.
                  </AlertDescription>
                </Alert>
              )}

              <Box overflowX='auto' data-tour='preferences-contacts-list'>
                <Table size='sm' width='100%' sx={{ tableLayout: 'fixed' }}>
                  <Thead>
                    <Tr>
                      <Th width='22%'>Name</Th>
                      {whatsappAvailable && <Th width='28%'>Phone</Th>}
                      <Th width={whatsappAvailable ? '30%' : '58%'}>Details</Th>
                      <Th width='20%' textAlign='right'></Th>
                    </Tr>
                  </Thead>
                  <Tbody>
                    {contacts.map(c => {
                      const rawDetails =
                        c.details && typeof c.details === 'object'
                          ? c.details
                          : {};

                      const formatDetailLabel = key => {
                        if (!key) return key;
                        return key
                          .replace(/_/g, ' ')
                          .replace(/\b\w/g, ch => ch.toUpperCase());
                      };

                      const iconForDetail = key => {
                        switch (key) {
                          case 'department':
                            return '🏢';
                          case 'title':
                          case 'role':
                            return '👤';
                          case 'note':
                            return '📝';
                          case 'email':
                            return '✉️';
                          case 'phone':
                            return '📱';
                          default:
                            return '•';
                        }
                      };

                      const orderedKeys = [
                        'department',
                        'title',
                        'email',
                        'note',
                      ];
                      const seenDetailKeys = new Set();
                      const detailDisplay = [];

                      const pushDetail = (key, value) => {
                        const trimmed = String(value ?? '').trim();
                        if (!trimmed || seenDetailKeys.has(key)) return;
                        seenDetailKeys.add(key);
                        detailDisplay.push({
                          key,
                          icon: iconForDetail(key),
                          label: formatDetailLabel(key),
                          value: trimmed,
                        });
                      };

                      orderedKeys.forEach(key => {
                        if (
                          Object.prototype.hasOwnProperty.call(rawDetails, key)
                        ) {
                          pushDetail(key, rawDetails[key]);
                        }
                      });

                      Object.entries(rawDetails)
                        .filter(([key]) => !orderedKeys.includes(key))
                        .sort(([a], [b]) => a.localeCompare(b))
                        .forEach(([key, value]) => pushDetail(key, value));

                      // When WhatsApp is not available, show phone in details column
                      if (!whatsappAvailable && c.phone_e164) {
                        pushDetail('phone', c.phone_e164);
                      }

                      return editingContactId === c.id ? (
                        isMobile ? (
                          <Tr key={c.id} bg={blueRowBg}>
                            <Td colSpan={4}>
                              <VStack align='stretch' spacing={3}>
                                <HStack spacing={2} flexWrap='wrap'>
                                  <FormControl maxW='100%'>
                                    <FormLabel m={0} fontSize='sm'>
                                      First name
                                    </FormLabel>
                                    <Input
                                      size='sm'
                                      value={editContactFirstName}
                                      onChange={e =>
                                        setEditContactFirstName(e.target.value)
                                      }
                                      placeholder='First name'
                                    />
                                  </FormControl>
                                  <FormControl maxW='100%'>
                                    <FormLabel m={0} fontSize='sm'>
                                      Last name
                                    </FormLabel>
                                    <Input
                                      size='sm'
                                      value={editContactLastName}
                                      onChange={e =>
                                        setEditContactLastName(e.target.value)
                                      }
                                      placeholder='Last name'
                                    />
                                  </FormControl>
                                </HStack>
                                <FormControl>
                                  <FormLabel m={0} fontSize='sm'>
                                    Phone
                                  </FormLabel>
                                  <Input
                                    size='sm'
                                    value={editContactPhone}
                                    onChange={e =>
                                      setEditContactPhone(e.target.value)
                                    }
                                    placeholder='+14155550100'
                                  />
                                </FormControl>
                                <HStack spacing={2} flexWrap='wrap'>
                                  <FormControl>
                                    <FormLabel m={0} fontSize='sm'>
                                      Department
                                    </FormLabel>
                                    <Input
                                      size='sm'
                                      placeholder='Department'
                                      value={
                                        editContactDetails.department || ''
                                      }
                                      onChange={e =>
                                        setEditContactDetails({
                                          ...editContactDetails,
                                          department: e.target.value,
                                        })
                                      }
                                    />
                                  </FormControl>
                                  <FormControl>
                                    <FormLabel m={0} fontSize='sm'>
                                      Title / Role
                                    </FormLabel>
                                    <Input
                                      size='sm'
                                      placeholder='Title / Role'
                                      value={editContactDetails.title || ''}
                                      onChange={e =>
                                        setEditContactDetails({
                                          ...editContactDetails,
                                          title: e.target.value,
                                        })
                                      }
                                    />
                                  </FormControl>
                                </HStack>
                                <FormControl>
                                  <FormLabel m={0} fontSize='sm'>
                                    Email
                                  </FormLabel>
                                  <Input
                                    size='sm'
                                    placeholder='Email'
                                    value={editContactDetails.email || ''}
                                    onChange={e =>
                                      setEditContactDetails({
                                        ...editContactDetails,
                                        email: e.target.value,
                                      })
                                    }
                                  />
                                </FormControl>
                                <FormControl>
                                  <FormLabel m={0} fontSize='sm'>
                                    Note
                                  </FormLabel>
                                  <Textarea
                                    size='sm'
                                    rows={2}
                                    placeholder='Note'
                                    value={editContactDetails.note || ''}
                                    onChange={e =>
                                      setEditContactDetails({
                                        ...editContactDetails,
                                        note: e.target.value,
                                      })
                                    }
                                  />
                                </FormControl>
                                <HStack spacing={2}>
                                  <Button
                                    size='sm'
                                    colorScheme='blue'
                                    isDisabled={
                                      isViewer ||
                                      !String(
                                        editContactFirstName || ''
                                      ).trim() ||
                                      !String(
                                        editContactLastName || ''
                                      ).trim() ||
                                      (!String(editContactPhone || '').trim() &&
                                        !isValidEmail(
                                          String(
                                            editContactDetails.email || ''
                                          ).trim()
                                        )) ||
                                      (String(editContactPhone || '').trim() &&
                                        !/^\+?[1-9]\d{6,14}$/.test(
                                          String(editContactPhone || '').trim()
                                        ))
                                    }
                                    onClick={async () => {
                                      try {
                                        const res = await apiClient.put(
                                          `/api/v1/workspaces/${workspaceId}/contacts/${c.id}`,
                                          {
                                            first_name: editContactFirstName,
                                            last_name: editContactLastName,
                                            phone_e164: editContactPhone,
                                            details: editContactDetails,
                                          }
                                        );
                                        setContacts(
                                          contacts.map(x =>
                                            x.id === c.id ? res.data : x
                                          )
                                        );
                                        setEditingContactId(null);
                                        showSuccess('Contact updated');
                                      } catch (e) {
                                        setError(
                                          e?.response?.data?.error ||
                                            'Failed to update contact'
                                        );
                                      }
                                    }}
                                  >
                                    Save
                                  </Button>

                                  <Button
                                    size='sm'
                                    variant='ghost'
                                    onClick={() => setEditingContactId(null)}
                                  >
                                    Cancel
                                  </Button>
                                </HStack>
                              </VStack>
                            </Td>
                          </Tr>
                        ) : (
                          <Tr key={c.id} bg={blueRowBg}>
                            <Td colSpan={4}>
                              <VStack align='stretch' spacing={3}>
                                <HStack spacing={2} flexWrap='wrap'>
                                  <FormControl maxW='100%'>
                                    <FormLabel m={0} fontSize='sm'>
                                      First name
                                    </FormLabel>
                                    <Input
                                      size='sm'
                                      value={editContactFirstName}
                                      onChange={e =>
                                        setEditContactFirstName(e.target.value)
                                      }
                                      placeholder='First name'
                                    />
                                  </FormControl>
                                  <FormControl maxW='100%'>
                                    <FormLabel m={0} fontSize='sm'>
                                      Last name
                                    </FormLabel>
                                    <Input
                                      size='sm'
                                      value={editContactLastName}
                                      onChange={e =>
                                        setEditContactLastName(e.target.value)
                                      }
                                      placeholder='Last name'
                                    />
                                  </FormControl>
                                </HStack>
                                <FormControl>
                                  <FormLabel m={0} fontSize='sm'>
                                    Phone
                                  </FormLabel>
                                  <Input
                                    size='sm'
                                    value={editContactPhone}
                                    onChange={e =>
                                      setEditContactPhone(e.target.value)
                                    }
                                    placeholder='+14155550100'
                                  />
                                </FormControl>
                                <HStack spacing={2} flexWrap='wrap'>
                                  <FormControl>
                                    <FormLabel m={0} fontSize='sm'>
                                      Department
                                    </FormLabel>
                                    <Input
                                      size='sm'
                                      placeholder='Department'
                                      value={
                                        editContactDetails.department || ''
                                      }
                                      onChange={e =>
                                        setEditContactDetails({
                                          ...editContactDetails,
                                          department: e.target.value,
                                        })
                                      }
                                    />
                                  </FormControl>
                                  <FormControl>
                                    <FormLabel m={0} fontSize='sm'>
                                      Title / Role
                                    </FormLabel>
                                    <Input
                                      size='sm'
                                      placeholder='Title / Role'
                                      value={editContactDetails.title || ''}
                                      onChange={e =>
                                        setEditContactDetails({
                                          ...editContactDetails,
                                          title: e.target.value,
                                        })
                                      }
                                    />
                                  </FormControl>
                                </HStack>
                                <FormControl>
                                  <FormLabel m={0} fontSize='sm'>
                                    Email
                                  </FormLabel>
                                  <Input
                                    size='sm'
                                    placeholder='Email'
                                    value={editContactDetails.email || ''}
                                    onChange={e =>
                                      setEditContactDetails({
                                        ...editContactDetails,
                                        email: e.target.value,
                                      })
                                    }
                                  />
                                </FormControl>
                                <FormControl>
                                  <FormLabel m={0} fontSize='sm'>
                                    Note
                                  </FormLabel>
                                  <Textarea
                                    size='sm'
                                    rows={2}
                                    placeholder='Note'
                                    value={editContactDetails.note || ''}
                                    onChange={e =>
                                      setEditContactDetails({
                                        ...editContactDetails,
                                        note: e.target.value,
                                      })
                                    }
                                  />
                                </FormControl>
                                <HStack spacing={2}>
                                  <Button
                                    size='sm'
                                    colorScheme='blue'
                                    isDisabled={
                                      isViewer ||
                                      !String(
                                        editContactFirstName || ''
                                      ).trim() ||
                                      !String(
                                        editContactLastName || ''
                                      ).trim() ||
                                      (!String(editContactPhone || '').trim() &&
                                        !isValidEmail(
                                          String(
                                            editContactDetails.email || ''
                                          ).trim()
                                        )) ||
                                      (String(editContactPhone || '').trim() &&
                                        !/^\+?[1-9]\d{6,14}$/.test(
                                          String(editContactPhone || '').trim()
                                        ))
                                    }
                                    onClick={async () => {
                                      try {
                                        const res = await apiClient.put(
                                          `/api/v1/workspaces/${workspaceId}/contacts/${c.id}`,
                                          {
                                            first_name: editContactFirstName,
                                            last_name: editContactLastName,
                                            phone_e164: editContactPhone,
                                            details: editContactDetails,
                                          }
                                        );
                                        setContacts(
                                          contacts.map(x =>
                                            x.id === c.id ? res.data : x
                                          )
                                        );
                                        setEditingContactId(null);
                                        showSuccess('Contact updated');
                                      } catch (e) {
                                        setError(
                                          e?.response?.data?.error ||
                                            'Failed to update contact'
                                        );
                                      }
                                    }}
                                  >
                                    Save
                                  </Button>
                                  <Button
                                    size='sm'
                                    variant='ghost'
                                    onClick={() => setEditingContactId(null)}
                                  >
                                    Cancel
                                  </Button>
                                </HStack>
                              </VStack>
                            </Td>
                          </Tr>
                        )
                      ) : (
                        <Tr key={c.id}>
                          <Td
                            width='22%'
                            pr={2}
                            whiteSpace='normal'
                            wordBreak='break-word'
                          >
                            <Text fontSize='sm' fontWeight='medium'>
                              {c.first_name} {c.last_name}
                            </Text>
                          </Td>
                          {whatsappAvailable && (
                            <Td
                              width='28%'
                              pr={2}
                              whiteSpace='normal'
                              wordBreak='break-word'
                            >
                              <VStack align='stretch' spacing={1} fontSize='sm'>
                                <Text>{c.phone_e164 || '-'}</Text>
                                {String(c.phone_e164 || '').trim() ? (
                                  <Button
                                    size='xs'
                                    variant='outline'
                                    width='100%'
                                    minW='0'
                                    fontSize='xs'
                                    px={1}
                                    whiteSpace='normal'
                                    wordBreak='break-word'
                                    height='auto'
                                    py={1}
                                    onClick={async () => {
                                      try {
                                        const now = Date.now();
                                        const until =
                                          waContactCooldowns[c.id] || 0;
                                        if (until > now) {
                                          const secs = Math.ceil(
                                            (until - now) / 1000
                                          );
                                          setError(
                                            `Please wait ${secs}s before sending another test.`
                                          );
                                          return;
                                        }
                                        setTestingContact(c.id);
                                        await apiClient.post(
                                          `/api/test-whatsapp?workspace_id=${encodeURIComponent(workspaceId)}&use_template=true`,
                                          { phone_e164: c.phone_e164 }
                                        );
                                        showSuccess('Test message sent');
                                        setWaContactCooldowns(prev => ({
                                          ...prev,
                                          [c.id]: now + 120000,
                                        }));
                                      } catch (e) {
                                        const code = e?.response?.data?.code;
                                        const retryAfter =
                                          e?.response?.data?.retryAfter;
                                        let msg =
                                          e?.response?.data?.error ||
                                          e?.message ||
                                          'Test failed';
                                        if (
                                          code === 'TEST_WHATSAPP_COOLDOWN' &&
                                          Number.isFinite(retryAfter)
                                        ) {
                                          msg = `Please wait ${retryAfter}s before testing this number again`;
                                        } else if (
                                          code === 'INVALID_PHONE_FORMAT'
                                        ) {
                                          msg =
                                            'Invalid phone format. Use E.164, e.g., +14155550100.';
                                        } else if (
                                          String(code || '') === '63016'
                                        ) {
                                          msg =
                                            'Outside WhatsApp 24-hour session. Sending via approved template... please try again if it still fails.';
                                        } else if (
                                          code === 'WHATSAPP_NOT_CONFIGURED'
                                        ) {
                                          msg =
                                            'WhatsApp is not configured. Please contact support.';
                                        } else if (
                                          code === 'INVALID_RECIPIENT'
                                        ) {
                                          msg =
                                            'Invalid recipient. Verify the phone number and try again.';
                                        }
                                        setError(msg);
                                      } finally {
                                        setTestingContact(null);
                                      }
                                    }}
                                    isLoading={testingContact === c.id}
                                    isDisabled={isViewer}
                                  >
                                    {waContactCooldowns[c.id] > Date.now()
                                      ? `Test WhatsApp message (${Math.ceil((waContactCooldowns[c.id] - Date.now()) / 1000)}s)`
                                      : 'Test WhatsApp message'}
                                  </Button>
                                ) : null}
                              </VStack>
                            </Td>
                          )}
                          <Td
                            width={whatsappAvailable ? '30%' : '58%'}
                            fontSize='xs'
                            color={grayTextColor}
                            pr={2}
                            whiteSpace='normal'
                            wordBreak='break-word'
                          >
                            {detailDisplay.length > 0 ? (
                              <VStack
                                align='stretch'
                                spacing={0.5}
                                whiteSpace='normal'
                                wordBreak='break-word'
                                overflowWrap='anywhere'
                              >
                                {detailDisplay.map(detail => (
                                  <Text key={detail.key} color={grayTextColor}>
                                    {detail.icon} {detail.label}: {detail.value}
                                  </Text>
                                ))}
                              </VStack>
                            ) : (
                              <Text>-</Text>
                            )}
                          </Td>
                          <Td width='20%' textAlign='right' pl={2}>
                            <HStack spacing={1} justify='flex-end'>
                              <Button
                                size='xs'
                                variant='outline'
                                onClick={() => {
                                  setEditingContactId(c.id);
                                  setEditContactFirstName(c.first_name);
                                  setEditContactLastName(c.last_name);
                                  setEditContactPhone(c.phone_e164);
                                  setEditContactDetails(c.details || {});
                                }}
                                isDisabled={isViewer}
                              >
                                Edit
                              </Button>

                              <Button
                                size='xs'
                                variant='outline'
                                colorScheme='red'
                                onClick={async () => {
                                  try {
                                    const deletedContactId = c.id;
                                    await apiClient.delete(
                                      `/api/v1/workspaces/${workspaceId}/contacts/${deletedContactId}`
                                    );

                                    // Update contacts list
                                    setContacts(
                                      contacts.filter(
                                        x => x.id !== deletedContactId
                                      )
                                    );

                                    // Clean up deleted contact from all contact groups
                                    setContactGroups(
                                      contactGroups.map(group => ({
                                        ...group,
                                        email_contact_ids: (
                                          group.email_contact_ids || []
                                        ).filter(id => id !== deletedContactId),
                                        whatsapp_contact_ids: (
                                          group.whatsapp_contact_ids || []
                                        ).filter(id => id !== deletedContactId),
                                      }))
                                    );

                                    // If currently editing a group, update the editor state too
                                    if (editingGroupId) {
                                      setGroupEmailContactIds(prev =>
                                        prev.filter(
                                          id => id !== deletedContactId
                                        )
                                      );
                                      setGroupWhatsappContactIds(prev =>
                                        prev.filter(
                                          id => id !== deletedContactId
                                        )
                                      );
                                      // Update the email text display
                                      const updatedEmailIds =
                                        groupEmailContactIds.filter(
                                          id => id !== deletedContactId
                                        );
                                      setGroupEmailsText(
                                        emailListFromIds(updatedEmailIds).join(
                                          ', '
                                        )
                                      );
                                    }

                                    showSuccess('Contact deleted');
                                  } catch (e) {
                                    setError('Failed to delete contact');
                                  }
                                }}
                                isDisabled={isViewer}
                              >
                                Remove
                              </Button>
                            </HStack>
                          </Td>
                        </Tr>
                      );
                    })}
                  </Tbody>
                </Table>
              </Box>

              {!isViewer && (
                <>
                  <Heading size='sm'>Add New Contact</Heading>
                  <VStack
                    align='stretch'
                    spacing={2}
                    data-tour='preferences-contacts-add'
                  >
                    <HStack spacing={2} flexWrap='wrap'>
                      <FormControl isInvalid={!!contactPhoneError} maxW='140px'>
                        <Input
                          placeholder='First name'
                          value={newContactFirstName}
                          onChange={e => setNewContactFirstName(e.target.value)}
                          size='sm'
                        />
                      </FormControl>
                      <FormControl maxW='140px'>
                        <Input
                          placeholder='Last name'
                          value={newContactLastName}
                          onChange={e => setNewContactLastName(e.target.value)}
                          size='sm'
                        />
                      </FormControl>
                      <FormControl maxW='200px'>
                        <Input
                          placeholder='Email'
                          value={newContactDetails.email || ''}
                          onChange={e =>
                            setNewContactDetails({
                              ...newContactDetails,
                              email: e.target.value,
                            })
                          }
                          size='sm'
                        />
                      </FormControl>
                      <FormControl isInvalid={!!contactPhoneError} maxW='160px'>
                        <Input
                          placeholder='+14155550100'
                          value={newContactPhone}
                          onChange={e => {
                            const val = e.target.value;
                            setNewContactPhone(val);
                            setContactPhoneError('');
                            // Validate E.164
                            if (val.trim()) {
                              const normalized = val.trim().startsWith('+')
                                ? val.trim()
                                : `+${val.trim()}`;
                              if (!/^\+[1-9]\d{6,14}$/.test(normalized)) {
                                setContactPhoneError(
                                  'Invalid E.164 format (e.g., +14155550100)'
                                );
                              }
                            }
                          }}
                          size='sm'
                        />
                        {contactPhoneError && (
                          <Text fontSize='xs' color='red.500' mt={1}>
                            {contactPhoneError}
                          </Text>
                        )}
                      </FormControl>
                    </HStack>
                    <Button
                      size='xs'
                      variant='ghost'
                      onClick={() =>
                        setNewContactDetailsOpen(!newContactDetailsOpen)
                      }
                      leftIcon={
                        <Text>{newContactDetailsOpen ? '▼' : '▶'}</Text>
                      }
                      alignSelf='flex-start'
                    >
                      Additional contact details
                    </Button>
                    {newContactDetailsOpen && (
                      <VStack align='stretch' spacing={2} pl={4}>
                        <Input
                          placeholder='Department'
                          value={newContactDetails.department || ''}
                          onChange={e =>
                            setNewContactDetails({
                              ...newContactDetails,
                              department: e.target.value,
                            })
                          }
                          size='sm'
                        />
                        <Input
                          placeholder='Title / Role'
                          value={newContactDetails.title || ''}
                          onChange={e =>
                            setNewContactDetails({
                              ...newContactDetails,
                              title: e.target.value,
                            })
                          }
                          size='sm'
                        />
                        <Textarea
                          placeholder='Note'
                          value={newContactDetails.note || ''}
                          onChange={e =>
                            setNewContactDetails({
                              ...newContactDetails,
                              note: e.target.value,
                            })
                          }
                          size='sm'
                          rows={2}
                        />
                      </VStack>
                    )}
                    <Tooltip
                      label='At least a valid email or phone number should be entered'
                      isDisabled={
                        !!newContactFirstName.trim() &&
                        !!newContactLastName.trim() &&
                        ((!!newContactPhone.trim() && !contactPhoneError) ||
                          isValidEmail(
                            String(newContactDetails.email || '').trim()
                          )) &&
                        !isViewer
                      }
                      hasArrow
                      placement='top'
                    >
                      <Button
                        size='sm'
                        colorScheme='blue'
                        onClick={async () => {
                          setContactPhoneError('');
                          const phoneNorm = newContactPhone.trim();
                          const emailVal = String(
                            newContactDetails.email || ''
                          ).trim();
                          let phoneE164 = '';
                          if (phoneNorm) {
                            phoneE164 = phoneNorm.startsWith('+')
                              ? phoneNorm
                              : `+${phoneNorm}`;
                            if (!/^\+[1-9]\d{6,14}$/.test(phoneE164)) {
                              setContactPhoneError(
                                'Invalid E.164 format (e.g., +14155550100)'
                              );
                              return;
                            }
                          } else {
                            // Require a valid email if no phone provided
                            if (!isValidEmail(emailVal)) {
                              setError(
                                'Provide a phone number or a valid email'
                              );
                              return;
                            }
                          }
                          if (
                            !newContactFirstName.trim() ||
                            !newContactLastName.trim()
                          ) {
                            setError('First and last name are required');
                            return;
                          }
                          try {
                            await apiClient.post(
                              `/api/v1/workspaces/${workspaceId}/contacts`,
                              {
                                first_name: newContactFirstName.trim(),
                                last_name: newContactLastName.trim(),
                                phone_e164: phoneE164,
                                details: newContactDetails,
                              }
                            );
                            // Refresh from server to ensure consistent ordering and visibility
                            try {
                              const refreshed = await apiClient.get(
                                `/api/v1/workspaces/${workspaceId}/contacts`
                              );
                              setContacts(refreshed?.data?.items || []);
                            } catch (_) {}
                            setNewContactFirstName('');
                            setNewContactLastName('');
                            setNewContactPhone('');
                            setNewContactDetails({});
                            setNewContactDetailsOpen(false);
                            setContactPhoneError('');
                            showSuccess('Contact added');
                          } catch (e) {
                            setError(
                              e?.response?.data?.error ||
                                'Failed to add contact'
                            );
                          }
                        }}
                        disabled={
                          !newContactFirstName.trim() ||
                          !newContactLastName.trim() ||
                          (!!newContactPhone.trim() && !!contactPhoneError) ||
                          (!newContactPhone.trim() &&
                            !isValidEmail(
                              String(newContactDetails.email || '').trim()
                            )) ||
                          isViewer
                        }
                        alignSelf='flex-start'
                      >
                        Add Contact
                      </Button>
                    </Tooltip>
                  </VStack>
                </>
              )}
            </VStack>
          </Box>

          {/* Webhooks Panel */}
          <Box
            data-tour='preferences-webhooks'
            bg={cardBg}
            p={6}
            px={{ base: 8, md: 10 }}
            borderRadius='md'
            boxShadow='sm'
            border='1px solid'
            borderColor={borderColor}
          >
            <Heading size='md' mb={4}>
              Webhooks
            </Heading>
            {isViewer && (
              <Alert status='info' mb={3} borderRadius='md'>
                <AlertIcon />
                <AlertDescription>
                  You have viewer access in this workspace. Webhook settings are
                  read‑only.
                </AlertDescription>
              </Alert>
            )}
            <FormControl isDisabled={isViewer || !roleKnown}>
              <HStack justify='space-between' mb={2}>
                <VStack align='start' spacing={1}>
                  <FormLabel m={0}>Webhooks</FormLabel>
                  <HStack spacing={2}>
                    <Link
                      href='https://api.slack.com/messaging/webhooks'
                      isExternal
                      color='blue.500'
                      fontSize='xs'
                    >
                      Slack setup -
                    </Link>
                    <Link
                      href='https://discord.com/developers/docs/resources/webhook'
                      isExternal
                      color='blue.500'
                      fontSize='xs'
                    >
                      Discord setup -
                    </Link>
                    <Link
                      href='https://docs.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook'
                      isExternal
                      color='blue.500'
                      fontSize='xs'
                    >
                      Teams setup -
                    </Link>
                    <Link
                      href='https://developer.pagerduty.com/docs/events-api-v2-overview'
                      isExternal
                      color='blue.500'
                      fontSize='xs'
                    >
                      PagerDuty setup
                    </Link>
                  </HStack>
                </VStack>
                {/* Global webhooks toggle removed: webhooks are active if configured */}
              </HStack>
              <VStack
                align='stretch'
                spacing={3}
                data-tour='preferences-webhooks-list'
              >
                {webhookUrls.map((webhook, index) => (
                  <Box
                    key={index}
                    p={3}
                    bg={webhookBoxBg}
                    borderRadius='md'
                    border='1px solid'
                    borderColor={borderColor}
                  >
                    <VStack align='stretch' spacing={2}>
                      <Input
                        placeholder='Name (required): e.g., On-call Slack, Incident Discord, Primary Teams'
                        value={webhook.name || ''}
                        onChange={e =>
                          updateWebhook(index, 'name', e.target.value)
                        }
                        size='sm'
                        isDisabled={isViewer}
                      />
                      <Text fontSize='xs' color={grayTextColor}>
                        Used to pick this webhook in a contact group.
                      </Text>
                      {String(webhook.kind || '').toLowerCase() ===
                      'pagerduty' ? (
                        <VStack align='stretch' spacing={2}>
                          <HStack spacing={2} align='center'>
                            {renderWebhookLogo(webhook.kind || 'generic')}
                            <Select
                              value={webhook.kind || 'generic'}
                              onChange={e =>
                                updateWebhook(index, 'kind', e.target.value)
                              }
                              size='sm'
                              maxW='160px'
                              isDisabled={isViewer}
                            >
                              <option value='generic'>Generic</option>
                              <option value='discord'>Discord</option>
                              <option value='teams'>Teams</option>
                              <option value='slack'>Slack</option>
                              <option value='pagerduty'>PagerDuty</option>
                            </Select>
                          </HStack>
                          <Input
                            placeholder='https://events.pagerduty.com/v2/enqueue'
                            value={webhook.url || ''}
                            onChange={e =>
                              updateWebhook(index, 'url', e.target.value)
                            }
                            size='sm'
                            isDisabled={isViewer}
                          />
                          <Select
                            value={webhook.severity || ''}
                            onChange={e =>
                              updateWebhook(index, 'severity', e.target.value)
                            }
                            size='sm'
                            isDisabled={isViewer}
                          >
                            <option value=''>Severity (auto)</option>
                            <option value='critical'>critical</option>
                            <option value='error'>error</option>
                            <option value='warning'>warning</option>
                            <option value='info'>info</option>
                          </Select>
                          <Input
                            placeholder='Custom title (optional)'
                            value={webhook.template || ''}
                            onChange={e =>
                              updateWebhook(index, 'template', e.target.value)
                            }
                            size='sm'
                            isDisabled={isViewer}
                          />
                          <Input
                            placeholder='PagerDuty Routing Key'
                            value={webhook.routingKey || ''}
                            onChange={e =>
                              updateWebhook(index, 'routingKey', e.target.value)
                            }
                            size='sm'
                            isDisabled={isViewer}
                          />
                          <HStack>
                            <Button
                              size='sm'
                              variant='outline'
                              onClick={() => handleTestWebhook(index)}
                              isLoading={testingWebhook === index}
                              disabled={!webhook.url || isViewer}
                            >
                              Test
                            </Button>
                            <Button
                              size='sm'
                              colorScheme='blue'
                              onClick={handleSaveWebhooks}
                              isLoading={savingToggles}
                              disabled={
                                isViewer ||
                                !workspaceId ||
                                !(
                                  webhook.verified &&
                                  (webhook.verifiedUrl || '') ===
                                    (webhook.url || '').trim()
                                ) ||
                                !(webhook.name || '').trim()
                              }
                            >
                              Save
                            </Button>
                            {webhook.verified &&
                              (webhook.verifiedUrl || '') ===
                                (webhook.url || '').trim() && (
                                <Badge colorScheme='green'>Verified</Badge>
                              )}
                            <IconButton
                              size='sm'
                              variant='outline'
                              colorScheme='red'
                              onClick={() => removeWebhook(index)}
                              isDisabled={isViewer}
                              icon={<Text>×</Text>}
                            />
                          </HStack>
                        </VStack>
                      ) : (
                        <VStack align='stretch' spacing={2}>
                          <HStack spacing={2} align='center'>
                            {renderWebhookLogo(webhook.kind || 'generic')}
                            <Select
                              value={webhook.kind || 'generic'}
                              onChange={e =>
                                updateWebhook(index, 'kind', e.target.value)
                              }
                              size='sm'
                              maxW='160px'
                              isDisabled={isViewer}
                            >
                              <option value='generic'>Generic</option>
                              <option value='discord'>Discord</option>
                              <option value='teams'>Teams</option>
                              <option value='slack'>Slack</option>
                              <option value='pagerduty'>PagerDuty</option>
                            </Select>
                          </HStack>
                          <Textarea
                            placeholder='https://...'
                            value={webhook.url || ''}
                            onChange={e =>
                              updateWebhook(index, 'url', e.target.value)
                            }
                            size='sm'
                            rows={2}
                            isDisabled={isViewer}
                          />
                          <HStack>
                            <Button
                              size='sm'
                              variant='outline'
                              onClick={() => handleTestWebhook(index)}
                              isLoading={testingWebhook === index}
                              disabled={!webhook.url || isViewer}
                            >
                              Test
                            </Button>
                            <Button
                              size='sm'
                              colorScheme='blue'
                              onClick={handleSaveWebhooks}
                              isLoading={savingToggles}
                              disabled={
                                isViewer ||
                                !workspaceId ||
                                !(
                                  webhook.verified &&
                                  (webhook.verifiedUrl || '') ===
                                    (webhook.url || '').trim()
                                ) ||
                                !(webhook.name || '').trim()
                              }
                            >
                              Save
                            </Button>
                            {webhook.verified &&
                              (webhook.verifiedUrl || '') ===
                                (webhook.url || '').trim() && (
                                <Badge colorScheme='green'>Verified</Badge>
                              )}
                            <IconButton
                              size='sm'
                              variant='outline'
                              colorScheme='red'
                              onClick={() => removeWebhook(index)}
                              isDisabled={isViewer}
                              icon={<Text>×</Text>}
                            />
                          </HStack>
                        </VStack>
                      )}
                    </VStack>
                  </Box>
                ))}
                <Button
                  size='sm'
                  variant='outline'
                  onClick={addWebhook}
                  disabled={webhookUrls.length >= 5}
                  data-tour='preferences-webhooks-add'
                >
                  Add Webhook
                </Button>
              </VStack>
            </FormControl>
          </Box>

          {/* Contact Groups (per workspace) */}
          <Box
            data-tour='preferences-contact-groups'
            bg={cardBg}
            p={6}
            px={{ base: 8, md: 10 }}
            borderRadius='md'
            boxShadow='sm'
            border='1px solid'
            borderColor={borderColor}
          >
            <VStack align='stretch' spacing={2} mb={4}>
              <Heading size='md'>Contact Groups</Heading>
              <Text fontSize='sm' color={grayTextColor}>
                Create groups to organize who receives alerts. Each person can
                receive via email{whatsappAvailable ? ', WhatsApp,' : ''} or
                webhooks.
              </Text>
            </VStack>
            {isViewer && (
              <Alert status='info' mb={4} borderRadius='md'>
                <AlertIcon />
                <AlertDescription>
                  Contact groups are not visible for viewers in this workspace.
                </AlertDescription>
              </Alert>
            )}
            <VStack align='stretch' spacing={4}>
              {/* Default group selector */}
              {!isViewer && (
                <FormControl isDisabled={isViewer}>
                  <FormLabel>Contact groups</FormLabel>
                  <HStack>
                    <Select
                      data-tour='preferences-contact-groups-selector'
                      value={selectedGroupId || ''}
                      onChange={e => {
                        const val = e.target.value;
                        if (val === '__new__') {
                          // Start creating a new group via the editor
                          setEditingGroupId('');
                          setGroupName('');
                          setGroupEmailsText('');
                          setGroupWebhookNames([]);
                          setGroupEmailContactIds([]);
                          setGroupWhatsappContactIds([]);
                          // Prefill thresholds with workspace defaults for new group
                          setGroupThresholdsCsv(thresholdsCsv);
                          // Focus the editor and scroll into view for better UX
                          setTimeout(() => {
                            try {
                              groupNameInputRef.current &&
                                groupNameInputRef.current.focus();
                              groupNameInputRef.current &&
                                groupNameInputRef.current.scrollIntoView({
                                  behavior: 'smooth',
                                  block: 'center',
                                });
                            } catch (_) {}
                          }, 0);
                          setSelectedGroupId('');
                          return;
                        }
                        setSelectedGroupId(val);
                        const g = (contactGroups || []).find(
                          x => String(x.id) === String(val)
                        );
                        if (g) startEditGroup(g);
                      }}
                      size='sm'
                    >
                      {(contactGroups || []).map(g => (
                        <option key={g.id} value={g.id}>
                          {g.name}
                        </option>
                      ))}
                      <option
                        value='__new__'
                        disabled={(contactGroups || []).length >= groupCap}
                      >
                        + Add New Group
                      </option>
                    </Select>
                    {selectedGroupId &&
                    selectedGroupId === defaultContactGroupId ? (
                      <Badge>default</Badge>
                    ) : null}
                  </HStack>
                  {selectedGroupId ? (
                    <HStack mt={2} spacing={2} align='center'>
                      <Text fontSize='xs' color={grayTextColor}>
                        ID:
                      </Text>
                      <Code fontSize='xs'>{selectedGroupId}</Code>
                      <IconButton
                        aria-label='Copy contact group ID'
                        size='xs'
                        variant='ghost'
                        icon={<FiCopy />}
                        onClick={async () => {
                          try {
                            await navigator.clipboard.writeText(
                              String(selectedGroupId)
                            );
                          } catch (_) {}
                        }}
                      />
                    </HStack>
                  ) : null}
                  <Text fontSize='xs' color={grayTextColor} mt={1}>
                    Pick a contact group to edit it. Use {'"'}+ Add New Group
                    {'"'} to create one, then click {'"'}Save group{'"'}.
                  </Text>
                  <HStack mt={3} spacing={3}>
                    <Button
                      size='sm'
                      variant='solid'
                      colorScheme='blue'
                      isDisabled={
                        !selectedGroupId ||
                        selectedGroupId === defaultContactGroupId ||
                        isViewer
                      }
                      onClick={async () => {
                        try {
                          if (!workspaceId || !selectedGroupId) return;
                          await workspaceAPI.updateAlertSettings(workspaceId, {
                            default_contact_group_id: selectedGroupId,
                            contact_groups: contactGroups,
                          });
                          setDefaultContactGroupId(selectedGroupId);
                          setSuccess('Default contact group updated');
                        } catch (_) {
                          setError('Failed to update default contact group');
                        }
                      }}
                    >
                      Make this group default
                    </Button>
                    <Button
                      size='sm'
                      variant='outline'
                      colorScheme='red'
                      isDisabled={!selectedGroupId || isViewer}
                      onClick={() => {
                        if (!selectedGroupId) return;
                        setDeleteTargetId(selectedGroupId);
                        setDeleteDialogOpen(true);
                      }}
                    >
                      Delete group
                    </Button>
                  </HStack>
                </FormControl>
              )}

              {/* Groups list removed per UX rework; selection + editor handle edits/deletes */}

              {/* Editor */}
              {!isViewer && (
                <Box
                  p={3}
                  border='1px dashed'
                  borderColor={borderColor}
                  borderRadius='md'
                  data-tour='preferences-contact-groups-editor'
                >
                  <VStack align='stretch' spacing={2}>
                    <Heading size='sm'>
                      {editingGroupId ? 'Edit Group' : 'New Group'}
                    </Heading>
                    <Text fontSize='xs' color={grayTextColor}>
                      Groups used: {(contactGroups || []).length}/
                      {groupCap === Infinity ? 'unlimited' : groupCap}
                    </Text>
                    <FormControl
                      isInvalid={groupSaveAttempted && !groupName.trim()}
                    >
                      <Input
                        placeholder='Group name (e.g., On-call, Security, Legal)'
                        value={groupName}
                        onChange={e => {
                          setGroupName(e.target.value);
                          setGroupSaveAttempted(false);
                        }}
                        size='sm'
                        ref={groupNameInputRef}
                      />
                      {groupSaveAttempted && !groupName.trim() && (
                        <FormErrorMessage>
                          Group name is required.
                        </FormErrorMessage>
                      )}
                    </FormControl>
                    <FormControl data-tour='preferences-contact-groups-contacts-channels'>
                      <FormLabel>Contacts and channels</FormLabel>
                      <Text fontSize='xs' color={grayTextColor} mb={1}>
                        Select per-contact which channels to use.
                        {whatsappAvailable
                          ? ' Each person can have both email and WhatsApp.'
                          : ''}
                        {memberCap !== Infinity &&
                          ` (Limit: ${memberCap} people total)`}{' '}
                        Webhooks are unlimited.
                      </Text>
                      <VStack align='stretch' spacing={2}>
                        {contacts.length === 0 ? (
                          <Text fontSize='sm' color={grayTextColor}>
                            No contacts defined. Add contacts in the Contacts
                            section above.
                          </Text>
                        ) : (
                          contacts.map(c => {
                            const email = (c.details && c.details.email) || '';
                            const emailDisabled = !isValidEmail(
                              String(email || '')
                            );
                            return (
                              <Stack
                                key={c.id}
                                direction={{ base: 'column', md: 'row' }}
                                align='center'
                                spacing={2}
                                w='100%'
                              >
                                <Box flex='1' minW={0}>
                                  <Text fontSize='sm' fontWeight='medium'>
                                    {c.first_name} {c.last_name}
                                  </Text>
                                </Box>
                                <HStack
                                  flexShrink={0}
                                  spacing={3}
                                  align='center'
                                >
                                  <Checkbox
                                    isChecked={groupEmailContactIds.includes(
                                      c.id
                                    )}
                                    isDisabled={
                                      emailDisabled ||
                                      (!groupEmailContactIds.includes(c.id) &&
                                        !groupWhatsappContactIds.includes(
                                          c.id
                                        ) &&
                                        totalSelectedPeople >= memberCap)
                                    }
                                    onChange={e => {
                                      if (e.target.checked) {
                                        setGroupEmailContactIds(
                                          Array.from(
                                            new Set([
                                              ...groupEmailContactIds,
                                              c.id,
                                            ])
                                          )
                                        );
                                      } else {
                                        setGroupEmailContactIds(
                                          groupEmailContactIds.filter(
                                            id => id !== c.id
                                          )
                                        );
                                      }
                                      setGroupSaveAttempted(false);
                                    }}
                                    size='sm'
                                  >
                                    Email
                                  </Checkbox>
                                  {whatsappAvailable && (
                                    <Checkbox
                                      isChecked={groupWhatsappContactIds.includes(
                                        c.id
                                      )}
                                      isDisabled={
                                        !c.phone_e164 ||
                                        (!groupWhatsappContactIds.includes(
                                          c.id
                                        ) &&
                                          !groupEmailContactIds.includes(
                                            c.id
                                          ) &&
                                          totalSelectedPeople >= memberCap)
                                      }
                                      onChange={e => {
                                        if (e.target.checked) {
                                          setGroupWhatsappContactIds(
                                            Array.from(
                                              new Set([
                                                ...groupWhatsappContactIds,
                                                c.id,
                                              ])
                                            )
                                          );
                                        } else {
                                          setGroupWhatsappContactIds(
                                            groupWhatsappContactIds.filter(
                                              id => id !== c.id
                                            )
                                          );
                                        }
                                        setGroupSaveAttempted(false);
                                      }}
                                      size='sm'
                                    >
                                      WhatsApp
                                    </Checkbox>
                                  )}
                                </HStack>
                              </Stack>
                            );
                          })
                        )}
                      </VStack>
                    </FormControl>
                    <VStack align='stretch' spacing={2}>
                      <HStack justify='space-between' align='center'>
                        <Text
                          fontSize='xs'
                          color='gray.600'
                          fontWeight='medium'
                        >
                          {memberCap === Infinity
                            ? `Selected people: ${totalSelectedPeople}`
                            : `Selected people: ${totalSelectedPeople} out of ${memberCap}`}
                        </Text>
                        {memberCap !== Infinity && (
                          <Text
                            fontSize='xs'
                            color={
                              totalSelectedPeople === 0
                                ? 'gray.400'
                                : totalSelectedPeople < memberCap
                                  ? 'green.500'
                                  : totalSelectedPeople === memberCap
                                    ? 'orange.500'
                                    : 'red.500'
                            }
                            fontWeight='semibold'
                          >
                            {totalSelectedPeople === 0
                              ? 'Empty'
                              : totalSelectedPeople < memberCap
                                ? 'Available'
                                : totalSelectedPeople === memberCap
                                  ? 'Full'
                                  : 'Over limit'}
                          </Text>
                        )}
                      </HStack>
                      {memberCap !== Infinity && (
                        <Box>
                          <Box
                            w='100%'
                            h='6px'
                            bg='gray.200'
                            borderRadius='full'
                            overflow='hidden'
                          >
                            <Box
                              h='100%'
                              w={`${Math.min((totalSelectedPeople / memberCap) * 100, 100)}%`}
                              bg={
                                totalSelectedPeople === 0
                                  ? 'gray.300'
                                  : totalSelectedPeople < memberCap
                                    ? 'green.400'
                                    : totalSelectedPeople === memberCap
                                      ? 'orange.400'
                                      : 'red.400'
                              }
                              transition='all 0.2s'
                            />
                          </Box>
                        </Box>
                      )}
                      {isOverMemberLimit && (
                        <Alert status='warning' size='sm' borderRadius='md'>
                          <AlertIcon />
                          <AlertDescription fontSize='xs'>
                            <strong>Member limit exceeded:</strong> You{"'"}ve
                            selected {totalSelectedPeople} people, but your plan
                            allows only {memberCap} people per group. Only the
                            first {memberCap} people will be saved.
                          </AlertDescription>
                        </Alert>
                      )}
                    </VStack>
                    {/* Emails textarea removed in favor of per-contact channel toggles */}
                    <FormLabel>Webhook channels (unlimited)</FormLabel>
                    <Box
                      border='1px solid'
                      borderColor={borderColor}
                      borderRadius='md'
                      p={2}
                      data-tour='preferences-contact-groups-webhooks'
                    >
                      <VStack
                        align='stretch'
                        spacing={2}
                        maxH='160px'
                        overflowY='auto'
                      >
                        {(() => {
                          const options = (webhookUrls || []).filter(
                            w => (w.name || '').trim() && w.verified
                          );
                          if (options.length === 0) {
                            return (
                              <Text fontSize='xs' color={grayTextColor}>
                                No verified named webhooks available.
                              </Text>
                            );
                          }
                          return (
                            <CheckboxGroup
                              colorScheme='blue'
                              value={groupWebhookNames}
                              onChange={vals => {
                                setGroupWebhookNames(vals);
                                setGroupSaveAttempted(false);
                              }}
                              isDisabled={isViewer}
                            >
                              <VStack align='stretch' spacing={1}>
                                {options.map((w, i) => (
                                  <Checkbox
                                    key={`${w.name}-${i}`}
                                    value={w.name}
                                    size='sm'
                                  >
                                    {w.name}
                                  </Checkbox>
                                ))}
                              </VStack>
                            </CheckboxGroup>
                          );
                        })()}
                      </VStack>
                    </Box>
                    {/* Thresholds override */}
                    <FormLabel m={0} fontSize='sm' mt={3}>
                      Thresholds override (days, comma-separated)
                    </FormLabel>
                    <FormControl>
                      <Input
                        placeholder={thresholdsCsv}
                        value={groupThresholdsCsv}
                        onChange={e => setGroupThresholdsCsv(e.target.value)}
                        size='sm'
                      />
                      <Text fontSize='xs' color={grayTextColor} mt={1}>
                        Leave equal to defaults to inherit workspace thresholds.
                        Allowed range: -365 to 730.
                      </Text>
                    </FormControl>
                    <Divider my={3} />
                    <FormLabel m={0} fontSize='sm'>
                      Weekly Digest
                    </FormLabel>
                    <Text fontSize='xs' color={grayTextColor} mb={2}>
                      Send a weekly summary of tokens expiring soon (within the
                      highest threshold).
                    </Text>
                    <VStack
                      align='stretch'
                      spacing={2}
                      data-tour='preferences-contact-groups-digest'
                    >
                      <Checkbox
                        size='sm'
                        isChecked={groupWeeklyDigestEmail}
                        onChange={e =>
                          setGroupWeeklyDigestEmail(e.target.checked)
                        }
                        isDisabled={!hasEmailInGroup}
                      >
                        Email weekly digest
                      </Checkbox>
                      {whatsappAvailable && (
                        <Checkbox
                          size='sm'
                          isChecked={groupWeeklyDigestWhatsapp}
                          onChange={e =>
                            setGroupWeeklyDigestWhatsapp(e.target.checked)
                          }
                          isDisabled={!hasWhatsappInGroup}
                        >
                          WhatsApp weekly digest
                        </Checkbox>
                      )}
                      <Checkbox
                        size='sm'
                        isChecked={groupWeeklyDigestWebhooks}
                        onChange={e =>
                          setGroupWeeklyDigestWebhooks(e.target.checked)
                        }
                        isDisabled={!hasWebhookInGroup}
                      >
                        Webhook weekly digest
                      </Checkbox>
                    </VStack>
                    <Text fontSize='xs' color={grayTextColor}>
                      Weekly digest supports Slack, Discord, Teams, and generic
                      webhooks. PagerDuty is not supported as it&apos;s designed
                      for incident alerting.
                    </Text>
                    <Text fontSize='xs' color={grayTextColor}>
                      Changes are not saved until you click {'"'}Save group{'"'}
                      .
                    </Text>
                    <HStack>
                      <Button
                        size='sm'
                        colorScheme='blue'
                        onClick={saveGroup}
                        isDisabled={
                          loading ||
                          !groupName.trim() ||
                          isEmptyGroupInvalid ||
                          isOverMemberLimit ||
                          (editingGroupId
                            ? false
                            : (contactGroups || []).length >= groupCap)
                        }
                      >
                        Save group
                      </Button>
                      <Button
                        size='sm'
                        variant='outline'
                        onClick={resetGroupEditor}
                      >
                        Reset
                      </Button>
                    </HStack>
                  </VStack>
                </Box>
              )}
            </VStack>
          </Box>

          {/* Save */}
          {/* Global Save removed; saves are per section */}
        </VStack>
      </Box>

      <AlertDialog
        isOpen={deleteDialogOpen}
        leastDestructiveRef={cancelRef}
        onClose={() => setDeleteDialogOpen(false)}
      >
        <AlertDialogOverlay />
        <AlertDialogContent>
          <AlertDialogHeader>Delete this contact group?</AlertDialogHeader>
          <AlertDialogBody>
            Deleting this contact group will reassign any tokens using it to the
            current default group. This action cannot be undone.
          </AlertDialogBody>
          <AlertDialogFooter>
            <Button
              ref={cancelRef}
              onClick={() => {
                setDeleteDialogOpen(false);
                setDeleteTargetId('');
              }}
            >
              Cancel
            </Button>
            <Button
              colorScheme='red'
              ml={3}
              isLoading={deletingGroup}
              onClick={async () => {
                if (!deleteTargetId) return;
                try {
                  setDeletingGroup(true);
                  await deleteGroup(deleteTargetId);
                } finally {
                  setDeletingGroup(false);
                  setDeleteDialogOpen(false);
                  setDeleteTargetId('');
                }
              }}
            >
              Delete
            </Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <AlertDialog
        isOpen={disableAllDialogOpen}
        leastDestructiveRef={cancelRef}
        onClose={() => setDisableAllDialogOpen(false)}
      >
        <AlertDialogOverlay />
        <AlertDialogContent>
          <AlertDialogHeader>Disable all alerts?</AlertDialogHeader>
          <AlertDialogBody>
            If you disable this channel, you won&apos;t receive any alert.
          </AlertDialogBody>
          <AlertDialogFooter>
            <Button
              ref={cancelRef}
              onClick={() => {
                setDisableAllDialogOpen(false);
                setDisableAllTarget('');
              }}
            >
              Cancel
            </Button>
            <Button
              colorScheme='red'
              ml={3}
              onClick={() => {
                if (disableAllTarget === 'email') {
                  setEmailEnabled(false);
                  savePartialSettings({ emailEnabled: false }, false).catch(
                    () => {}
                  );
                }
                // webhooks disable removed
                setDisableAllDialogOpen(false);
                setDisableAllTarget('');
              }}
            >
              Disable
            </Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Default reassigned info modal */}
      <AlertDialog
        isOpen={defaultReassignedOpen}
        leastDestructiveRef={cancelRef}
        onClose={() => setDefaultReassignedOpen(false)}
      >
        <AlertDialogOverlay />
        <AlertDialogContent>
          <AlertDialogHeader>Default group updated</AlertDialogHeader>
          <AlertDialogBody>
            {defaultReassignedName
              ? `The deleted default group was replaced by "${defaultReassignedName}" as the workspace default.`
              : 'The deleted default group was removed.'}
          </AlertDialogBody>
          <AlertDialogFooter>
            <Button
              onClick={() => setDefaultReassignedOpen(false)}
              colorScheme='blue'
            >
              OK
            </Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}
