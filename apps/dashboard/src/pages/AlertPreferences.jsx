import { useEffect, useState, useRef, useMemo, useCallback } from 'react';
import { useLocation } from 'react-router-dom';
import {
  Box,
  Text,
  VStack,
  Modal,
  ModalOverlay,
  ModalHeader,
  ModalFooter,
  ModalBody,
  ModalCloseButton,
  FormControl,
  FormLabel,
  FormErrorMessage,
  Input,
  Button,
  Alert,
  AlertIcon,
  AlertDescription,
  HStack,
  Flex,
  Stack,
  useColorModeValue,
  useBreakpointValue,
  useDisclosure,
  Link,
  Select,
  Textarea,
  IconButton,
  Code,
  Badge,
  AlertDialog,
  AlertDialogBody,
  AlertDialogCloseButton,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogContent,
  AlertDialogOverlay,
  Checkbox,
  CheckboxGroup,
  Collapse,
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
  List,
  ListItem,
  SimpleGrid,
} from '@chakra-ui/react';
import apiClient, { alertAPI, workspaceAPI } from '../utils/apiClient';
import { showSuccess, showWarning, showError } from '../utils/toast.js';
import DashboardPageLayout from '../components/DashboardPageLayout';
import {
  DashboardActionButton,
  DashboardPanel,
  DashboardPanelHeader,
} from '../components/DashboardPrimitives';
import {
  SettingsNestedSurface,
  SettingsPageShell,
  SettingsSection,
  useSettingsNestedTheme,
} from '../components/SettingsPageShell.jsx';
import {
  SETTINGS_NESTED_RADIUS,
  SETTINGS_PANEL_PADDING,
  SETTINGS_SECTION_GAP,
} from '../styles/dashboardLayout';
import {
  DashboardModalFrame,
  DashboardModalDescription,
  DashboardModalTitle,
  useDashboardModalProps,
} from '../components/DashboardModalFrame.jsx';
import SEO from '../components/SEO.jsx';
import { useDashboardTheme } from '../hooks/useDashboardTheme';
import { trackEvent } from '../utils/analytics.js';
import { useWorkspace } from '../utils/WorkspaceContext.jsx';
import { logger } from '../utils/logger';
import {
  FiBookOpen,
  FiChevronDown,
  FiChevronUp,
  FiCopy,
  FiExternalLink,
  FiGlobe,
  FiX,
} from 'react-icons/fi';
import TestWhatsappButton from '../components/TestWhatsappButton.jsx';
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

function normalizeContactPhoneE164(raw) {
  const phoneNorm = String(raw || '').trim();
  if (!phoneNorm) return '';
  return phoneNorm.startsWith('+') ? phoneNorm : `+${phoneNorm}`;
}

function isValidContactPhoneE164(raw) {
  const phoneE164 = normalizeContactPhoneE164(raw);
  return phoneE164 ? /^\+[1-9]\d{6,14}$/.test(phoneE164) : false;
}

const ADD_CONTACT_WHATSAPP_TEST_KEY = '__add_contact_draft__';
const EDIT_CONTACT_WHATSAPP_TEST_KEY = '__edit_contact_draft__';

const CONTACT_DETAIL_ORDER = ['department', 'title', 'email', 'note'];

function formatContactDetailLabel(key) {
  if (!key) return key;
  return key.replace(/_/g, ' ').replace(/\b\w/g, ch => ch.toUpperCase());
}

function iconForContactDetail(key) {
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
}

function getContactDisplayName(contact) {
  return (
    [contact?.first_name, contact?.last_name]
      .filter(Boolean)
      .join(' ')
      .trim() || 'Unnamed contact'
  );
}

function getContactDetailDisplay(contact, whatsappAvailable) {
  const rawDetails =
    contact?.details && typeof contact.details === 'object'
      ? contact.details
      : {};
  const seenDetailKeys = new Set();
  const detailDisplay = [];

  const pushDetail = (key, value) => {
    const trimmed = String(value ?? '').trim();
    if (!trimmed || seenDetailKeys.has(key)) return;
    seenDetailKeys.add(key);
    detailDisplay.push({
      key,
      icon: iconForContactDetail(key),
      label: formatContactDetailLabel(key),
      value: trimmed,
    });
  };

  CONTACT_DETAIL_ORDER.forEach(key => {
    if (Object.prototype.hasOwnProperty.call(rawDetails, key)) {
      pushDetail(key, rawDetails[key]);
    }
  });

  Object.entries(rawDetails)
    .filter(([key]) => !CONTACT_DETAIL_ORDER.includes(key))
    .sort(([a], [b]) => a.localeCompare(b))
    .forEach(([key, value]) => pushDetail(key, value));

  if (!whatsappAvailable && contact?.phone_e164) {
    pushDetail('phone', contact.phone_e164);
  }

  return detailDisplay;
}

function getContactDetailFields(contact) {
  const rawDetails =
    contact?.details && typeof contact.details === 'object'
      ? contact.details
      : {};

  return {
    department: String(rawDetails.department ?? '').trim(),
    title: String(rawDetails.title ?? '').trim(),
    email: String(rawDetails.email ?? '').trim(),
    note: String(rawDetails.note ?? '').trim(),
  };
}

const CONTACT_TABLE_COLUMN_COUNT = 7;

function getContactSortValue(contact, key) {
  if (key === 'name') {
    return getContactDisplayName(contact);
  }
  if (key === 'phone') {
    return String(contact?.phone_e164 ?? '').trim();
  }

  const fields = getContactDetailFields(contact);
  return fields[key] || '';
}

function ContactSortableTh({
  children,
  sortKey,
  sortConfig,
  onSort,
  hoverBg,
  ...props
}) {
  const isActive = sortConfig.key === sortKey;
  const direction = isActive ? sortConfig.direction : null;

  return (
    <Th
      {...props}
      cursor='pointer'
      userSelect='none'
      onClick={() => onSort(sortKey)}
      _hover={{ bg: hoverBg }}
      aria-sort={
        isActive ? (direction === 'asc' ? 'ascending' : 'descending') : 'none'
      }
    >
      <HStack spacing={1} display='inline-flex'>
        <Text as='span'>{children}</Text>
        {isActive ? (
          <Text as='span' fontSize='xs' color='blue.400' aria-hidden>
            {direction === 'asc' ? 'A-Z' : 'Z-A'}
          </Text>
        ) : null}
      </HStack>
    </Th>
  );
}

function ContactTableField({ value, muted, text }) {
  const trimmed = String(value ?? '').trim();

  return (
    <Text
      fontSize='sm'
      wordBreak='break-word'
      overflowWrap='anywhere'
      color={trimmed ? text : muted}
    >
      {trimmed || '-'}
    </Text>
  );
}

function ContactDetailsList({
  details,
  labelColor,
  valueColor,
  emptyText = 'No details',
  compact = false,
}) {
  const accentBorder = useColorModeValue('blackAlpha.100', 'whiteAlpha.200');

  if (!details?.length) {
    return (
      <Text color={labelColor} fontSize='sm'>
        {emptyText}
      </Text>
    );
  }

  return (
    <VStack align='stretch' spacing={compact ? 1.5 : 2}>
      {details.map(detail => (
        <Flex
          key={detail.key}
          align='flex-start'
          gap={2}
          minW={0}
          pl={2}
          borderLeft='2px solid'
          borderColor={accentBorder}
        >
          <Text
            aria-hidden
            fontSize='sm'
            lineHeight='1.45'
            flexShrink={0}
            mt='1px'
          >
            {detail.icon}
          </Text>
          <Box minW={0} flex='1'>
            <Text
              fontSize='xs'
              fontWeight='semibold'
              color={labelColor}
              textTransform='uppercase'
              letterSpacing='0.04em'
              lineHeight='short'
              mb={0.5}
            >
              {detail.label}
            </Text>
            <Text
              fontSize='sm'
              color={valueColor}
              lineHeight='1.45'
              wordBreak='break-word'
              overflowWrap='anywhere'
            >
              {detail.value}
            </Text>
          </Box>
        </Flex>
      ))}
    </VStack>
  );
}

function PreferencesPanelHeader({ title, description, muted, action }) {
  const { sectionTitleColor } = useDashboardTheme();

  return (
    <Box color={sectionTitleColor}>
      <DashboardPanelHeader title={title} action={action}>
        <Text mt={1} color={muted} fontSize='sm' lineHeight='1.45'>
          {description}
        </Text>
      </DashboardPanelHeader>
    </Box>
  );
}

function PreferenceConfirmFieldCard({ label, children, tokens }) {
  return (
    <Box
      bg={tokens.fieldBg}
      border='1px solid'
      borderColor={tokens.border}
      borderRadius='12px'
      p={{ base: 3.5, md: 4 }}
      minH='88px'
    >
      <Text fontSize='sm' fontWeight='semibold' color={tokens.muted} mb={2}>
        {label}
      </Text>
      {children}
    </Box>
  );
}

function PreferenceConfirmValue({ children, tokens, ...rest }) {
  return (
    <Text fontSize={{ base: 'sm', md: 'md' }} color={tokens.text} {...rest}>
      {children || '-'}
    </Text>
  );
}

function formatWebhookKindLabel(kind) {
  const normalized = String(kind || 'generic').toLowerCase();
  const labels = {
    discord: 'Discord',
    generic: 'Generic',
    pagerduty: 'PagerDuty',
    slack: 'Slack',
    teams: 'Microsoft Teams',
  };
  return labels[normalized] || normalized;
}

const WEBHOOK_SETUP_GUIDES = [
  {
    kind: 'slack',
    label: 'Slack',
    description: 'Incoming webhook URL setup',
    href: 'https://api.slack.com/messaging/webhooks',
  },
  {
    kind: 'discord',
    label: 'Discord',
    description: 'Channel webhook documentation',
    href: 'https://discord.com/developers/docs/resources/webhook',
  },
  {
    kind: 'teams',
    label: 'Microsoft Teams',
    description: 'Incoming webhook connector guide',
    href: 'https://docs.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook',
  },
  {
    kind: 'pagerduty',
    label: 'PagerDuty',
    description: 'Events API v2 overview',
    href: 'https://developer.pagerduty.com/docs/events-api-v2-overview',
  },
];

function WebhookSetupGuidesPanel({ labelColor, muted, renderVendorLogo }) {
  const { panelBorder, nestedFieldBg } = useSettingsNestedTheme();
  const { text, muted: themeMuted, dashboard } = useDashboardTheme();
  const [isOpen, setIsOpen] = useState(false);
  const defaultTitleColor = useColorModeValue('black', text);
  const defaultBodyColor = useColorModeValue(
    dashboard.text.secondary,
    themeMuted
  );
  const titleColor = labelColor ?? defaultTitleColor;
  const bodyColor = muted ?? defaultBodyColor;
  const guideCardBg = nestedFieldBg;
  const guideCardHoverBg = dashboard.bg.panelHover;
  const logoWrapBg = nestedFieldBg;

  return (
    <Box
      mt={5}
      mb={4}
      bg={dashboard.purple.surface}
      border='1px solid'
      borderColor={dashboard.purple.border}
      borderRadius={SETTINGS_NESTED_RADIUS}
      overflow='hidden'
    >
      <Flex
        as='button'
        type='button'
        w='full'
        textAlign='left'
        px={SETTINGS_PANEL_PADDING}
        py={{ base: 5, md: 6 }}
        align='flex-start'
        gap={4}
        onClick={() => setIsOpen(prev => !prev)}
        _hover={{ bg: dashboard.purple.surfaceHover }}
        transition='background 0.15s ease'
        aria-expanded={isOpen}
      >
        <Icon
          as={FiBookOpen}
          boxSize={5}
          color={dashboard.purple.icon}
          flexShrink={0}
          mt={0.5}
          aria-hidden
        />
        <Box flex='1' minW={0}>
          <Text fontSize='sm' fontWeight='bold' color={titleColor}>
            Setup guides
          </Text>
          {!isOpen ? (
            <List spacing={1} mt={2} styleType='disc' pl={4} color={bodyColor}>
              <ListItem fontSize='xs' fontStyle='italic' lineHeight='1.45'>
                Slack, Discord, Teams, and PagerDuty documentation
              </ListItem>
            </List>
          ) : null}
        </Box>
        <Icon
          as={isOpen ? FiChevronUp : FiChevronDown}
          boxSize={5}
          color={bodyColor}
          flexShrink={0}
          mt={0.5}
          aria-hidden
        />
      </Flex>
      <Collapse in={isOpen} animateOpacity>
        <Box
          px={SETTINGS_PANEL_PADDING}
          pb={SETTINGS_PANEL_PADDING}
          pt={SETTINGS_PANEL_PADDING}
        >
          <List spacing={1} mb={4} styleType='disc' pl={4} color={bodyColor}>
            <ListItem fontSize='sm' fontStyle='italic' lineHeight='1.5'>
              Create a webhook URL in your vendor console, verify it below, then
              assign named webhooks to contact groups.
            </ListItem>
          </List>
          <SimpleGrid columns={{ base: 1, md: 2 }} spacing={3}>
            {WEBHOOK_SETUP_GUIDES.map(guide => (
              <Link
                key={guide.kind}
                href={guide.href}
                isExternal
                _hover={{ textDecoration: 'none' }}
              >
                <Flex
                  align='center'
                  gap={3}
                  p={3}
                  minH='72px'
                  bg={guideCardBg}
                  border='1px solid'
                  borderColor={panelBorder}
                  borderRadius={SETTINGS_NESTED_RADIUS}
                  _hover={{ bg: guideCardHoverBg }}
                  transition='background 0.15s ease'
                >
                  <Flex
                    align='center'
                    justify='center'
                    boxSize='40px'
                    borderRadius='md'
                    bg={logoWrapBg}
                    flexShrink={0}
                  >
                    {renderVendorLogo(guide.kind)}
                  </Flex>
                  <Box flex='1' minW={0}>
                    <Text
                      fontSize='sm'
                      fontWeight='semibold'
                      color={titleColor}
                    >
                      {guide.label}
                    </Text>
                    <Text
                      fontSize='xs'
                      color={bodyColor}
                      lineHeight='1.45'
                      mt={0.5}
                    >
                      {guide.description}
                    </Text>
                  </Box>
                  <Icon
                    as={FiExternalLink}
                    boxSize={4}
                    color={bodyColor}
                    flexShrink={0}
                    aria-hidden
                  />
                </Flex>
              </Link>
            ))}
          </SimpleGrid>
        </Box>
      </Collapse>
    </Box>
  );
}

function createEmptyWebhookDraft() {
  return {
    name: '',
    url: '',
    kind: 'generic',
    severity: '',
    template: '',
    routingKey: '',
    verified: false,
    verifiedUrl: null,
    _verifiedSnapshot: null,
  };
}

function WebhookValueField({ label, value, monospace = false }) {
  const trimmed = String(value ?? '').trim();
  const display = trimmed || '-';
  const { panelBorder, nestedFieldBg } = useSettingsNestedTheme();
  const { text, bodySecondary, muted, dashboard } = useDashboardTheme();

  return (
    <Box w='100%'>
      <Text
        fontSize='xs'
        fontWeight='semibold'
        color={bodySecondary}
        textTransform='uppercase'
        letterSpacing='0.04em'
        mb={1}
      >
        {label}
      </Text>
      <Box
        as={monospace ? 'pre' : 'div'}
        p={{ base: 3, md: 4 }}
        bg={nestedFieldBg}
        borderRadius='md'
        overflowX='hidden'
        whiteSpace='pre-wrap'
        border='1px solid'
        borderColor={panelBorder}
        borderLeftWidth='3px'
        borderLeftColor={dashboard.accent.interactiveBorder}
        fontFamily={monospace ? 'mono' : 'body'}
        fontSize='sm'
        lineHeight='1.5'
        color={trimmed ? text : muted}
        w='100%'
        maxW='100%'
        sx={{
          overflowWrap: 'anywhere',
          wordBreak: 'break-word',
          WebkitOverflowScrolling: 'touch',
        }}
      >
        {display}
      </Box>
    </Box>
  );
}

function isWebhookReadyToPersist(webhook) {
  const url = (webhook?.url || '').trim();
  const verifiedUrl = (webhook?.verifiedUrl || '').trim();
  if (!url) return false;
  if (!webhook?.verified || verifiedUrl !== url) return false;
  if (!webhook._verifiedSnapshot) return true;
  return areWebhookParametersEqual(
    getWebhookParameterSnapshot(webhook),
    webhook._verifiedSnapshot
  );
}

const WEBHOOK_PARAMETER_FIELDS = [
  'name',
  'kind',
  'url',
  'severity',
  'template',
  'routingKey',
];

function getWebhookParameterSnapshot(webhook) {
  return WEBHOOK_PARAMETER_FIELDS.reduce((snapshot, field) => {
    snapshot[field] = String(webhook?.[field] ?? '').trim();
    return snapshot;
  }, {});
}

function areWebhookParametersEqual(a, b) {
  return WEBHOOK_PARAMETER_FIELDS.every(
    field => String(a?.[field] ?? '') === String(b?.[field] ?? '')
  );
}

function isSavedWebhook(webhook) {
  if (!webhook) return false;
  if (Object.prototype.hasOwnProperty.call(webhook, '_persisted')) {
    return webhook._persisted === true;
  }
  return Boolean((webhook.verifiedUrl || '').trim());
}

function hasWebhookParameterChanges(webhook) {
  if (!isSavedWebhook(webhook)) return true;
  const savedSnapshot = webhook?._savedSnapshot;
  if (!savedSnapshot) return false;
  return !areWebhookParametersEqual(
    getWebhookParameterSnapshot(webhook),
    savedSnapshot
  );
}

function withWebhookPersistedState(webhook, persisted) {
  const next = {
    ...webhook,
    _persisted: persisted,
    _editing: !persisted,
  };
  if (persisted) {
    next._savedSnapshot = getWebhookParameterSnapshot(webhook);
    next._verifiedSnapshot = getWebhookParameterSnapshot(webhook);
  } else {
    delete next._savedSnapshot;
    delete next._verifiedSnapshot;
  }
  return next;
}

function stripWebhookClientState(webhook) {
  const safeWebhook = { ...(webhook || {}) };
  delete safeWebhook._persisted;
  delete safeWebhook._editing;
  delete safeWebhook._savedSnapshot;
  delete safeWebhook._verifiedSnapshot;
  return safeWebhook;
}

function savedWebhookPayload(webhook) {
  if (!isSavedWebhook(webhook)) return null;
  const snapshot =
    webhook?._savedSnapshot || getWebhookParameterSnapshot(webhook);
  const payload = stripWebhookClientState({
    ...webhook,
    ...snapshot,
    verified: Boolean(snapshot.url),
    verifiedUrl: snapshot.url || null,
  });
  return isWebhookReadyToPersist(payload) ? payload : null;
}

function webhookPayloadForSave(webhook) {
  if (isWebhookReadyToPersist(webhook)) {
    return stripWebhookClientState(webhook);
  }
  return savedWebhookPayload(webhook);
}

function getSavedWebhookForDisplay(webhook) {
  if (!webhook?._savedSnapshot) return webhook;
  const snapshot = webhook._savedSnapshot;
  return {
    ...webhook,
    ...snapshot,
    verified: Boolean(snapshot.url),
    verifiedUrl: snapshot.url || null,
  };
}

export default function AlertPreferences({
  session,
  showProductTour,
  onLogout,
  onAccountClick,
  onNavigateToDashboard: _onNavigateToDashboard,
  onNavigateToLanding: _onNavigateToLanding,
}) {
  const location = useLocation();
  const { workspaceId } = useWorkspace();
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  const [whatsappAvailable, setWhatsappAvailable] = useState(false);
  const [thresholdsCsv, setThresholdsCsv] = useState('30,14,7,1,0');
  const [thresholdError, setThresholdError] = useState('');
  const [emailEnabled, setEmailEnabled] = useState(true);
  const [webhookUrls, setWebhookUrls] = useState([]);
  const [webhookDeleteTarget, setWebhookDeleteTarget] = useState(null);
  const [testingWebhook, setTestingWebhook] = useState(null);
  const [testCooldowns, setTestCooldowns] = useState({});
  const [waContactCooldowns, setWaContactCooldowns] = useState({}); // contactId -> until timestamp
  const [, setWaCooldownTick] = useState(0);
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
  const [contactSortConfig, setContactSortConfig] = useState({
    key: 'name',
    direction: 'asc',
  });
  const [contactDeleteTarget, setContactDeleteTarget] = useState(null);
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
  const [editContactDetailsOpen, setEditContactDetailsOpen] = useState(false);
  const [editContactPhoneError, setEditContactPhoneError] = useState('');
  const [dwStart, setDwStart] = useState('');
  const [dwEnd, setDwEnd] = useState('');
  const [dwTz, setDwTz] = useState('');
  // Core (OSS): no group or member caps
  const groupCap = Infinity;
  const memberCap = Infinity;
  const cancelRef = useRef();
  const didMountRef = useRef(false);
  const {
    isOpen: isAddContactOpen,
    onOpen: onAddContactOpen,
    onClose: onAddContactClose,
  } = useDisclosure();
  const {
    isOpen: isEditContactOpen,
    onOpen: onEditContactOpen,
    onClose: onEditContactClose,
  } = useDisclosure();
  const {
    isOpen: isGroupEditorOpen,
    onOpen: onGroupEditorOpen,
    onClose: onGroupEditorClose,
  } = useDisclosure();
  const {
    isOpen: isWebhookEditorOpen,
    onOpen: onWebhookEditorOpen,
    onClose: onWebhookEditorClose,
  } = useDisclosure();
  const [editingWebhookIndex, setEditingWebhookIndex] = useState(-1);
  const [webhookDraft, setWebhookDraft] = useState(createEmptyWebhookDraft);
  const [testingWebhookDraft, setTestingWebhookDraft] = useState(false);
  const [webhookSaveAttempted, setWebhookSaveAttempted] = useState(false);

  function resetNewContactForm() {
    setNewContactFirstName('');
    setNewContactLastName('');
    setNewContactPhone('');
    setNewContactDetails({});
    setNewContactDetailsOpen(false);
    setContactPhoneError('');
  }

  function handleCloseAddContact() {
    resetNewContactForm();
    onAddContactClose();
  }

  async function handleAddContactSubmit() {
    setContactPhoneError('');
    const phoneNorm = newContactPhone.trim();
    const emailVal = String(newContactDetails.email || '').trim();
    let phoneE164 = '';
    if (phoneNorm) {
      phoneE164 = normalizeContactPhoneE164(phoneNorm);
      if (!isValidContactPhoneE164(phoneNorm)) {
        setContactPhoneError('Invalid E.164 format (e.g., +14155550100)');
        return;
      }
    } else if (!isValidEmail(emailVal)) {
      showError('Provide a phone number or a valid email');
      return;
    }
    if (!newContactFirstName.trim() || !newContactLastName.trim()) {
      showError('First and last name are required');
      return;
    }
    try {
      await apiClient.post(`/api/v1/workspaces/${workspaceId}/contacts`, {
        first_name: newContactFirstName.trim(),
        last_name: newContactLastName.trim(),
        phone_e164: phoneE164,
        details: newContactDetails,
      });
      try {
        const refreshed = await apiClient.get(
          `/api/v1/workspaces/${workspaceId}/contacts`
        );
        setContacts(refreshed?.data?.items || []);
      } catch (_) {}
      resetNewContactForm();
      onAddContactClose();
      showSuccess('Contact added');
    } catch (e) {
      showError(e?.response?.data?.error || 'Failed to add contact');
    }
  }

  const isNewContactInvalid =
    !newContactFirstName.trim() ||
    !newContactLastName.trim() ||
    (!!newContactPhone.trim() && !!contactPhoneError) ||
    (!newContactPhone.trim() &&
      !isValidEmail(String(newContactDetails.email || '').trim()));

  const newContactPhoneE164 = useMemo(
    () => normalizeContactPhoneE164(newContactPhone),
    [newContactPhone]
  );
  const isNewContactPhoneValid = isValidContactPhoneE164(newContactPhone);

  function resetEditContactForm() {
    setEditingContactId(null);
    setEditContactFirstName('');
    setEditContactLastName('');
    setEditContactPhone('');
    setEditContactDetails({});
    setEditContactDetailsOpen(false);
    setEditContactPhoneError('');
  }

  function handleCloseEditContact() {
    resetEditContactForm();
    onEditContactClose();
  }

  const isEditedContactInvalid =
    !editContactFirstName.trim() ||
    !editContactLastName.trim() ||
    (!!editContactPhone.trim() && !!editContactPhoneError) ||
    (!editContactPhone.trim() &&
      !isValidEmail(String(editContactDetails.email || '').trim()));

  const editContactPhoneE164 = useMemo(
    () => normalizeContactPhoneE164(editContactPhone),
    [editContactPhone]
  );
  const isEditContactPhoneValid = isValidContactPhoneE164(editContactPhone);

  useEffect(() => {
    const hasActiveCooldown = () =>
      Object.values(waContactCooldowns).some(until => until > Date.now());

    if (!hasActiveCooldown()) return;

    const id = setInterval(() => {
      if (!hasActiveCooldown()) {
        clearInterval(id);
        setWaCooldownTick(t => t + 1);
        return;
      }
      setWaCooldownTick(t => t + 1);
    }, 1000);

    return () => clearInterval(id);
  }, [waContactCooldowns]);

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
  // Default to viewer until role is known to avoid unlocking controls before permissions load
  const [isViewer, setIsViewer] = useState(true);
  const [roleKnown, setRoleKnown] = useState(false);
  const [_workspaceRole, setWorkspaceRole] = useState('');

  const {
    border,
    muted,
    dashboard,
    text,
    surface,
    bodySecondary,
  } = useDashboardTheme();
  const webhookDeleteIconColor = dashboard.state.danger;
  const sortedContacts = useMemo(() => {
    const { key, direction } = contactSortConfig;

    return [...contacts].sort((a, b) => {
      const aVal = getContactSortValue(a, key).toLowerCase();
      const bVal = getContactSortValue(b, key).toLowerCase();
      let cmp = aVal.localeCompare(bVal, undefined, {
        sensitivity: 'base',
        numeric: true,
      });

      if (cmp === 0) {
        cmp = getContactDisplayName(a).localeCompare(
          getContactDisplayName(b),
          undefined,
          { sensitivity: 'base' }
        );
      }

      return direction === 'asc' ? cmp : -cmp;
    });
  }, [contacts, contactSortConfig]);
  const handleContactSort = useCallback(sortKey => {
    setContactSortConfig(prev => ({
      key: sortKey,
      direction:
        prev.key === sortKey && prev.direction === 'asc' ? 'desc' : 'asc',
    }));
  }, []);
  const {
    overlayProps,
    contentProps,
    headerProps,
    bodyProps,
    footerProps,
    closeButtonProps,
    tokens: modalTokens,
    outlineButtonProps,
  } = useDashboardModalProps();
  const isMobile = useBreakpointValue({ base: true, md: false });
  const discordColor = '#5865F2';
  const pagerdutyColor = '#06AC38';
  const internetColor = useColorModeValue('cyan.500', 'cyan.400');

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
        setWebhookUrls(
          TOUR_MOCK_WEBHOOKS.map(webhook =>
            withWebhookPersistedState(webhook, true)
          )
        );
        setContactGroups(TOUR_MOCK_CONTACT_GROUPS);
        setDefaultContactGroupId(TOUR_MOCK_CONTACT_GROUPS[0]?.id);
        setSelectedGroupId(TOUR_MOCK_CONTACT_GROUPS[0]?.id);
        setLoading(false);
        return;
      }

      try {
        setLoading(true);
        if (!workspaceId) {
          // No workspace selected yet; wait for shell workspace selector
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
            ? data.webhook_urls.map(w =>
                withWebhookPersistedState(
                  {
                    ...w,
                    verified: Boolean((w.url || '').trim()),
                    verifiedUrl: (w.url || '').trim(),
                  },
                  true
                )
              )
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
          showError('Failed to load alert preferences');
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
        const current = items.find(w => w.id === workspaceId);
        const role = String(current?.role || '').toLowerCase();
        setWorkspaceRole(role);
        const viewer = role === 'viewer';
        setIsViewer(viewer);
        // If viewer is on a non-personal workspace, redirect to personal workspace
        // Do not auto-redirect viewers; show disabled UI instead
      } catch (_) {
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
    const list = validate();
    if (!list) return;
    const wsId = workspaceId;
    if (!wsId) {
      showError('Please select a workspace first');
      return;
    }
    try {
      setSaving(true);
      await workspaceAPI.updateAlertSettings(wsId, { alert_thresholds: list });
      showSuccess('Alert thresholds saved');
      try {
        trackEvent('alert_pref_updated', { field: 'thresholds' });
      } catch (_) {}
    } catch (e) {
      const errorMessage =
        e?.response?.data?.error || e?.message || 'Failed to save preferences';
      showError(errorMessage);
      logger.error('Failed to save thresholds:', e);
    } finally {
      setSaving(false);
    }
  }

  // Save only webhook URLs (entire list)
  async function persistWebhooksList(listToPersist) {
    try {
      if (isViewer) return; // viewers cannot modify webhooks
      setSavingToggles(true);
      const toPersist = listToPersist
        .map(webhookPayloadForSave)
        .filter(Boolean);
      const wsId = workspaceId;
      if (!wsId) {
        showError('Please select a workspace first');
        return;
      }
      const payload = {
        webhook_urls: toPersist,
      };
      await workspaceAPI.updateAlertSettings(wsId, payload);
      setWebhookUrls(
        listToPersist.map(webhook =>
          isWebhookReadyToPersist(webhook)
            ? withWebhookPersistedState(webhook, true)
            : webhook
        )
      );
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
        return;
      }
      showError(e?.response?.data?.error || 'Failed to save webhooks');
      throw e;
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

  useEffect(() => {
    if (!showProductTour) return undefined;

    const openGroupEditor = () => {
      const groupId = selectedGroupId || defaultContactGroupId;
      const g = (contactGroups || []).find(
        x => String(x.id) === String(groupId)
      );
      if (g) startEditGroup(g);
      onGroupEditorOpen();
    };

    window.addEventListener('tt:tour-open-group-editor', openGroupEditor);
    window.addEventListener('tt:tour-close-group-editor', onGroupEditorClose);
    window.addEventListener('tt:tour-open-add-contact', onAddContactOpen);
    window.addEventListener('tt:tour-close-add-contact', handleCloseAddContact);
    window.addEventListener('tt:tour-open-add-webhook', openAddWebhookEditor);
    window.addEventListener(
      'tt:tour-close-add-webhook',
      handleCloseWebhookEditor
    );

    return () => {
      window.removeEventListener('tt:tour-open-group-editor', openGroupEditor);
      window.removeEventListener(
        'tt:tour-close-group-editor',
        onGroupEditorClose
      );
      window.removeEventListener('tt:tour-open-add-contact', onAddContactOpen);
      window.removeEventListener(
        'tt:tour-close-add-contact',
        handleCloseAddContact
      );
      window.removeEventListener(
        'tt:tour-open-add-webhook',
        openAddWebhookEditor
      );
      window.removeEventListener(
        'tt:tour-close-add-webhook',
        handleCloseWebhookEditor
      );
    };
  }, [
    showProductTour,
    contactGroups,
    selectedGroupId,
    defaultContactGroupId,
    startEditGroup,
    onGroupEditorOpen,
    onGroupEditorClose,
    onAddContactOpen,
    handleCloseAddContact,
    openAddWebhookEditor,
    handleCloseWebhookEditor,
  ]);

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
    // Persist via settings
    try {
      if (!workspaceId) return;
      await workspaceAPI.updateAlertSettings(workspaceId, {
        contact_groups: next,
        default_contact_group_id: defaultContactGroupId || next[0]?.id || null,
      });
      showSuccess(wasCreate ? 'Contact group created' : 'Contact group saved');
      onGroupEditorClose();
    } catch (e) {
      showError('Failed to save contact groups');
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
        showError('Please select a workspace first');
        return;
      }
      const savedPayload = listToSave.map(savedWebhookPayload).filter(Boolean);
      const payload = {
        webhook_urls: savedPayload,
      };
      await workspaceAPI.updateAlertSettings(wsId, payload);
      showSuccess('Webhooks updated');
      try {
        trackEvent('alert_pref_updated', { field: 'webhooks_list' });
      } catch (_) {}
    } catch (e) {
      if (e?.response?.status === 403) {
        return;
      }
      showError(e?.response?.data?.error || 'Failed to update webhooks');
    } finally {
      setSavingToggles(false);
    }
  }

  // removed unused handleTestSlack

  async function handleTestWebhook(index) {
    if (isViewer) return; // viewers cannot test webhooks
    const webhook = webhookUrls[index];
    if (!webhook?.url) {
      showError('Please enter a webhook URL first');
      return;
    }
    // Client-side cooldown guard (5 seconds per webhook row)
    const until = testCooldowns[index] || 0;
    if (until > Date.now()) {
      const secs = Math.ceil((until - Date.now()) / 1000);
      showError(`Please wait ${secs}s before sending another test.`);
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
            ? {
                ...w,
                verified: true,
                verifiedUrl: (w.url || '').trim(),
                _verifiedSnapshot: getWebhookParameterSnapshot(w),
              }
            : w
        )
      );
    } catch (e) {
      showError(e.message || 'Failed to test webhook');
      // Ensure not verified on failure
      setWebhookUrls(prev =>
        prev.map((w, i) =>
          i === index
            ? {
                ...w,
                verified: false,
                verifiedUrl: null,
                _verifiedSnapshot: null,
              }
            : w
        )
      );
    } finally {
      setTestingWebhook(null);
      setTestCooldowns(prev => ({ ...prev, [index]: Date.now() + 5000 }));
    }
  }

  function resetWebhookEditor() {
    setEditingWebhookIndex(-1);
    setWebhookDraft(createEmptyWebhookDraft());
    setWebhookSaveAttempted(false);
    setTestingWebhookDraft(false);
  }

  function handleCloseWebhookEditor() {
    resetWebhookEditor();
    onWebhookEditorClose();
  }

  function openAddWebhookEditor() {
    if (isViewer || webhookUrls.length >= 5) return;
    resetWebhookEditor();
    onWebhookEditorOpen();
  }

  function openEditWebhookEditor(index) {
    if (isViewer) return;
    const webhook = webhookUrls[index];
    if (!webhook) return;
    setEditingWebhookIndex(index);
    setWebhookDraft({
      name: webhook.name || '',
      url: webhook.url || '',
      kind: webhook.kind || 'generic',
      severity: webhook.severity || '',
      template: webhook.template || '',
      routingKey: webhook.routingKey || '',
      verified: webhook.verified,
      verifiedUrl: webhook.verifiedUrl,
      _verifiedSnapshot: webhook._verifiedSnapshot,
    });
    setWebhookSaveAttempted(false);
    onWebhookEditorOpen();
  }

  function updateWebhookDraft(field, value) {
    if (isViewer) return;
    setWebhookDraft(prev => ({
      ...prev,
      [field]: value,
      verified: false,
      verifiedUrl: null,
      _verifiedSnapshot: null,
    }));
  }

  function buildWebhookFromDraft(existingWebhook = null) {
    const draft = {
      ...webhookDraft,
      name: (webhookDraft.name || '').trim(),
      url: (webhookDraft.url || '').trim(),
    };
    return {
      ...(existingWebhook || {}),
      ...draft,
      _editing: false,
    };
  }

  function canSaveWebhookDraft() {
    const draft = buildWebhookFromDraft();
    if (!isWebhookReadyToPersist(draft)) return false;
    if (!draft.name) return false;
    if (editingWebhookIndex < 0) return true;
    const existing = webhookUrls[editingWebhookIndex];
    if (!existing) return false;
    return hasWebhookParameterChanges({ ...existing, ...draft });
  }

  async function handleTestWebhookDraft() {
    if (isViewer) return;
    const draft = buildWebhookFromDraft();
    if (!draft.url) {
      showError('Please enter a webhook URL first');
      return;
    }
    try {
      setTestingWebhookDraft(true);
      await alertAPI.testWebhook(draft.url, draft.kind || 'generic', {
        routingKey: draft.routingKey || undefined,
        severity: draft.severity || undefined,
        template: draft.template || undefined,
      });
      setWebhookDraft(prev => ({
        ...prev,
        verified: true,
        verifiedUrl: (prev.url || '').trim(),
        _verifiedSnapshot: getWebhookParameterSnapshot({
          ...prev,
          name: (prev.name || '').trim(),
          url: (prev.url || '').trim(),
        }),
      }));
    } catch (e) {
      setWebhookDraft(prev => ({
        ...prev,
        verified: false,
        verifiedUrl: null,
        _verifiedSnapshot: null,
      }));
      showError(e?.message || 'Webhook test failed');
    } finally {
      setTestingWebhookDraft(false);
    }
  }

  async function handleSaveWebhookEditor() {
    setWebhookSaveAttempted(true);
    if (!canSaveWebhookDraft()) return;
    const built = buildWebhookFromDraft(
      editingWebhookIndex >= 0 ? webhookUrls[editingWebhookIndex] : null
    );
    const nextList =
      editingWebhookIndex >= 0
        ? webhookUrls.map((webhook, index) =>
            index === editingWebhookIndex ? built : webhook
          )
        : [...webhookUrls, built];
    try {
      await persistWebhooksList(nextList);
      handleCloseWebhookEditor();
    } catch (_) {}
  }

  function removeUnsavedWebhook(index) {
    if (isViewer) return;
    setWebhookUrls(prev => prev.filter((_, i) => i !== index));
  }

  function removeWebhook(index) {
    if (isViewer) return; // viewers cannot remove webhooks
    const newUrls = webhookUrls.filter((_, i) => i !== index);
    setWebhookUrls(newUrls);
    // Immediately persist removal so it survives reload
    saveWebhooksListImmediate(newUrls).catch(() => {});
  }

  function openWebhookDeleteConfirm(index) {
    if (isViewer) return;
    setWebhookDeleteTarget({
      index,
      webhook: getSavedWebhookForDisplay(webhookUrls[index]) || null,
    });
  }

  function closeWebhookDeleteConfirm() {
    setWebhookDeleteTarget(null);
  }

  function confirmWebhookDelete() {
    if (!webhookDeleteTarget) return;
    removeWebhook(webhookDeleteTarget.index);
    setWebhookDeleteTarget(null);
  }

  function handleWebhookDeleteClick(index) {
    if (isViewer) return;
    const webhook = webhookUrls[index];
    if (isSavedWebhook(webhook)) {
      openWebhookDeleteConfirm(index);
      return;
    }
    removeUnsavedWebhook(index);
  }

  function renderWebhookEditorFields(webhook, onFieldChange) {
    const isPagerDuty =
      String(webhook.kind || '').toLowerCase() === 'pagerduty';

    return (
      <VStack align='stretch' spacing={3}>
        <Input
          placeholder='Name (required): e.g., On-call Slack, Incident Discord, Primary Teams'
          value={webhook.name || ''}
          onChange={e => onFieldChange('name', e.target.value)}
          size='sm'
        />
        <Text fontSize='xs' color={bodySecondary}>
          Used to pick this webhook in a contact group.
        </Text>
        {isPagerDuty ? (
          <VStack align='stretch' spacing={3}>
            <HStack spacing={2} align='center'>
              {renderWebhookLogo(webhook.kind || 'generic')}
              <Select
                value={webhook.kind || 'generic'}
                onChange={e => onFieldChange('kind', e.target.value)}
                size='sm'
                maxW='160px'
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
              onChange={e => onFieldChange('url', e.target.value)}
              size='sm'
            />
            <Select
              value={webhook.severity || ''}
              onChange={e => onFieldChange('severity', e.target.value)}
              size='sm'
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
              onChange={e => onFieldChange('template', e.target.value)}
              size='sm'
            />
            <Input
              placeholder='PagerDuty Routing Key'
              value={webhook.routingKey || ''}
              onChange={e => onFieldChange('routingKey', e.target.value)}
              size='sm'
            />
          </VStack>
        ) : (
          <VStack align='stretch' spacing={3}>
            <HStack spacing={2} align='center'>
              {renderWebhookLogo(webhook.kind || 'generic')}
              <Select
                value={webhook.kind || 'generic'}
                onChange={e => onFieldChange('kind', e.target.value)}
                size='sm'
                maxW='160px'
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
              onChange={e => onFieldChange('url', e.target.value)}
              size='sm'
              rows={2}
            />
          </VStack>
        )}
      </VStack>
    );
  }

  function renderWebhookReadOnlyView(index, webhook, actionWebhook = webhook) {
    const isPagerDuty =
      String(webhook.kind || '').toLowerCase() === 'pagerduty';

    return (
      <VStack align='stretch' spacing={4}>
        <Flex
          align='flex-start'
          justify='space-between'
          gap={3}
          flexWrap='wrap'
        >
          <HStack align='flex-start' spacing={3} minW={0} flex='1'>
            {renderWebhookLogo(webhook.kind || 'generic')}
            <Box minW={0}>
              <Text fontSize='sm' fontWeight='semibold' wordBreak='break-word'>
                {webhook.name || 'Unnamed webhook'}
              </Text>
              <Badge
                variant='outline'
                colorScheme='blue'
                borderRadius='md'
                mt={1}
              >
                {formatWebhookKindLabel(webhook.kind)}
              </Badge>
            </Box>
          </HStack>
        </Flex>

        <SimpleGrid columns={{ base: 1, lg: isPagerDuty ? 2 : 1 }} spacing={3}>
          <WebhookValueField label='URL' value={webhook.url} monospace />
          {isPagerDuty ? (
            <>
              <WebhookValueField
                label='Severity'
                value={webhook.severity || 'Auto'}
              />
              <WebhookValueField
                label='Custom title'
                value={webhook.template}
              />
              <WebhookValueField
                label='Routing key'
                value={webhook.routingKey}
                monospace
              />
            </>
          ) : null}
        </SimpleGrid>

        <Text fontSize='xs' color={bodySecondary}>
          Used to pick this webhook in a contact group.
        </Text>

        {renderWebhookActionRow(index, actionWebhook)}
      </VStack>
    );
  }

  function renderWebhookActionRow(index, webhook) {
    const isVerified =
      webhook.verified &&
      (webhook.verifiedUrl || '') === (webhook.url || '').trim();
    const actionButtonProps = {
      size: 'sm',
      h: '30px',
      minH: '30px',
      fontSize: 'sm',
      fontWeight: 'semibold',
    };

    return (
      <HStack flexWrap='wrap' spacing={2} rowGap={2} columnGap={2} pt={1}>
        <Button
          {...actionButtonProps}
          variant='outline'
          minW='72px'
          onClick={() => handleTestWebhook(index)}
          isLoading={testingWebhook === index}
          isDisabled={!webhook.url || isViewer}
        >
          Test
        </Button>
        <Button
          {...actionButtonProps}
          variant='outline'
          minW='72px'
          onClick={() => openEditWebhookEditor(index)}
          isDisabled={isViewer}
        >
          Edit
        </Button>
        {isVerified ? (
          <Badge
            colorScheme='green'
            variant='subtle'
            display='inline-flex'
            alignItems='center'
            h='30px'
            px={2.5}
            borderRadius='md'
            fontSize='xs'
            fontWeight='semibold'
            letterSpacing='0.04em'
            textTransform='uppercase'
          >
            Verified
          </Badge>
        ) : null}
        <IconButton
          {...actionButtonProps}
          variant='outline'
          colorScheme='red'
          w='30px'
          minW='30px'
          px={0}
          aria-label='Delete webhook'
          onClick={() => handleWebhookDeleteClick(index)}
          isDisabled={isViewer}
          icon={<Icon as={FiX} boxSize={4} color={webhookDeleteIconColor} />}
        />
      </HStack>
    );
  }

  async function savePartialSettings(partial, notify = true) {
    try {
      setSavingToggles(true);
      if (!workspaceId) {
        return;
      }
      const payload = {};
      if ('emailEnabled' in partial)
        payload.email_alerts_enabled = partial.emailEnabled;
      await workspaceAPI.updateAlertSettings(workspaceId, payload);
      if (notify) showSuccess('Preferences updated');
    } catch (e) {
      if (e?.response?.status === 403) {
        showWarning('Forbidden: insufficient role');
      }
      showError(e?.response?.data?.error || 'Failed to update preferences');
    } finally {
      setSavingToggles(false);
    }
  }

  function handleStartContactEdit(contact) {
    const details =
      contact.details && typeof contact.details === 'object'
        ? contact.details
        : {};
    setEditingContactId(contact.id);
    setEditContactFirstName(contact.first_name || '');
    setEditContactLastName(contact.last_name || '');
    setEditContactPhone(contact.phone_e164 || '');
    setEditContactDetails(details);
    setEditContactPhoneError('');
    setEditContactDetailsOpen(
      Boolean(details.department || details.title || details.note)
    );
    onEditContactOpen();
  }

  async function handleSaveEditedContact() {
    if (!editingContactId) return;
    setEditContactPhoneError('');
    const phoneNorm = editContactPhone.trim();
    const emailVal = String(editContactDetails.email || '').trim();
    let phoneE164 = '';
    if (phoneNorm) {
      phoneE164 = normalizeContactPhoneE164(phoneNorm);
      if (!isValidContactPhoneE164(phoneNorm)) {
        setEditContactPhoneError('Invalid E.164 format (e.g., +14155550100)');
        return;
      }
    } else if (!isValidEmail(emailVal)) {
      showError('Provide a phone number or a valid email');
      return;
    }
    if (!editContactFirstName.trim() || !editContactLastName.trim()) {
      showError('First and last name are required');
      return;
    }
    try {
      const res = await apiClient.put(
        `/api/v1/workspaces/${workspaceId}/contacts/${editingContactId}`,
        {
          first_name: editContactFirstName.trim(),
          last_name: editContactLastName.trim(),
          phone_e164: phoneE164,
          details: editContactDetails,
        }
      );
      setContacts(
        contacts.map(x => (x.id === editingContactId ? res.data : x))
      );
      handleCloseEditContact();
      showSuccess('Contact updated');
    } catch (e) {
      showError(e?.response?.data?.error || 'Failed to update contact');
    }
  }

  function openContactDeleteConfirm(contact) {
    if (isViewer) return;
    setContactDeleteTarget(contact || null);
  }

  function closeContactDeleteConfirm() {
    setContactDeleteTarget(null);
  }

  async function confirmContactDelete() {
    if (!contactDeleteTarget) return;
    const target = contactDeleteTarget;
    setContactDeleteTarget(null);
    await handleRemoveContact(target);
  }

  async function handleRemoveContact(contact) {
    try {
      const deletedContactId = contact.id;
      await apiClient.delete(
        `/api/v1/workspaces/${workspaceId}/contacts/${deletedContactId}`
      );

      setContacts(contacts.filter(x => x.id !== deletedContactId));

      setContactGroups(
        contactGroups.map(group => ({
          ...group,
          email_contact_ids: (group.email_contact_ids || []).filter(
            id => id !== deletedContactId
          ),
          whatsapp_contact_ids: (group.whatsapp_contact_ids || []).filter(
            id => id !== deletedContactId
          ),
        }))
      );

      if (editingGroupId) {
        setGroupEmailContactIds(prev =>
          prev.filter(id => id !== deletedContactId)
        );
        setGroupWhatsappContactIds(prev =>
          prev.filter(id => id !== deletedContactId)
        );
        const updatedEmailIds = groupEmailContactIds.filter(
          id => id !== deletedContactId
        );
        setGroupEmailsText(emailListFromIds(updatedEmailIds).join(', '));
      }

      showSuccess('Contact deleted');
    } catch (_) {
      showError('Failed to delete contact');
    }
  }

  async function handleTestWhatsappPhone(phoneE164, cooldownKey) {
    if (!phoneE164) return;
    try {
      const now = Date.now();
      const until = waContactCooldowns[cooldownKey] || 0;
      if (until > now) {
        const secs = Math.ceil((until - now) / 1000);
        showError(`Please wait ${secs}s before sending another test.`);
        return;
      }
      setTestingContact(cooldownKey);
      await apiClient.post(
        `/api/test-whatsapp?workspace_id=${encodeURIComponent(workspaceId)}&use_template=true`,
        { phone_e164: phoneE164 }
      );
      showSuccess('Test message sent');
      setWaContactCooldowns(prev => ({
        ...prev,
        [cooldownKey]: now + 120000,
      }));
    } catch (e) {
      const code = e?.response?.data?.code;
      const retryAfter = e?.response?.data?.retryAfter;
      let msg = e?.response?.data?.error || e?.message || 'Test failed';
      if (code === 'TEST_WHATSAPP_COOLDOWN' && Number.isFinite(retryAfter)) {
        msg = `Please wait ${retryAfter}s before testing this number again`;
      } else if (code === 'INVALID_PHONE_FORMAT') {
        msg = 'Invalid phone format. Use E.164, e.g., +14155550100.';
      } else if (String(code || '') === '63016') {
        msg =
          'Outside WhatsApp 24-hour session. Sending via approved template... please try again if it still fails.';
      } else if (code === 'WHATSAPP_NOT_CONFIGURED') {
        msg = 'WhatsApp is not configured. Please contact support.';
      } else if (code === 'TEMPLATE_NOT_CONFIGURED') {
        msg =
          'WhatsApp template not configured. Set TWILIO_WHATSAPP_TEST_CONTENT_SID or configure the test template SID in System Settings.';
      } else if (code === 'INVALID_RECIPIENT') {
        msg = 'Invalid recipient. Verify the phone number and try again.';
      }
      showError(msg);
    } finally {
      setTestingContact(null);
    }
  }

  function renderMobileContactCard(contact) {
    const detailDisplay = getContactDetailDisplay(contact, whatsappAvailable);
    const phone = String(contact.phone_e164 || '').trim();

    return (
      <SettingsNestedSurface key={contact.id} minW={0}>
        <VStack align='stretch' spacing={3}>
          <Flex align='flex-start' justify='space-between' gap={3} minW={0}>
            <Box minW={0}>
              <Text fontSize='sm' fontWeight='semibold' wordBreak='break-word'>
                {getContactDisplayName(contact)}
              </Text>
              {whatsappAvailable ? (
                <Text
                  color={bodySecondary}
                  fontSize='sm'
                  wordBreak='break-word'
                  minW={0}
                >
                  {phone || 'No phone number'}
                </Text>
              ) : null}
            </Box>
            <Badge
              variant='outline'
              colorScheme='blue'
              borderRadius='md'
              flexShrink={0}
            >
              Contact
            </Badge>
          </Flex>

          <ContactDetailsList
            details={detailDisplay}
            labelColor={bodySecondary}
            valueColor={text}
          />

          <Stack direction={{ base: 'column', sm: 'row' }} spacing={2}>
            <Button
              size='sm'
              h='30px'
              minH='30px'
              minW='76px'
              variant='outline'
              onClick={() => handleStartContactEdit(contact)}
              isDisabled={isViewer}
            >
              Edit
            </Button>
            <Button
              size='sm'
              h='30px'
              minH='30px'
              minW='76px'
              variant='outline'
              colorScheme='red'
              onClick={() => openContactDeleteConfirm(contact)}
              isDisabled={isViewer}
            >
              Remove
            </Button>
          </Stack>
        </VStack>
      </SettingsNestedSurface>
    );
  }

  function handleResetDefaults() {
    setThresholdsCsv('30,14,7,1,0');
    setThresholdError('');
  }

  const contactDeleteDetails = contactDeleteTarget
    ? getContactDetailDisplay(contactDeleteTarget, whatsappAvailable)
    : [];

  return (
    <>
      <SEO
        title='Alert Preferences'
        description='Configure your alert preferences and notification channels'
        noindex
      />
      <DashboardPageLayout
        session={session}
        onLogout={onLogout}
        onAccountClick={onAccountClick}
        pageTitle='Workspace preferences'
        variant='wide'
        isViewer={isViewer}
        contentProps={{
          overflowX: 'hidden',
          'data-tour': 'preferences-page',
          w: 'full',
          maxW: '100%',
        }}
      >
        <SettingsPageShell
          intro={
            isViewer ? (
              <Alert status='info' borderRadius='md'>
                <AlertIcon />
                <AlertDescription>
                  You can only modify preferences for your own workspace.
                  Modifying them for organization‑managed workspaces is reserved
                  to workspace managers or admins.
                </AlertDescription>
              </Alert>
            ) : null
          }
        >
          <SettingsSection id='alert-timing'>
            <SimpleGrid
              columns={{ base: 1, xl: 2 }}
              spacing={SETTINGS_SECTION_GAP}
              w='full'
            >
              <DashboardPanel data-tour='preferences-thresholds' h='full'>
                <PreferencesPanelHeader
                  title='Default workspace thresholds'
                  description='Control when alert notifications are created for assets in this workspace.'
                  muted={bodySecondary}
                />
                {/* Plan gating removed: thresholds editable for all plans */}
                <FormControl
                  isInvalid={!!thresholdError}
                  isDisabled={loading || isViewer || !roleKnown}
                >
                  <FormLabel>
                    Alert thresholds (days, comma-separated)
                  </FormLabel>
                  <Input
                    value={thresholdsCsv}
                    onChange={e => setThresholdsCsv(e.target.value)}
                    placeholder='30,14,7,1,0'
                  />
                  <FormErrorMessage>{thresholdError}</FormErrorMessage>
                  <Text fontSize='sm' color={bodySecondary} mt={2}>
                    Allowed range: -365 (after expiry) to 730 (2 years). Values
                    are sorted automatically.
                  </Text>
                  <Alert status='info' size='sm' borderRadius='md' mt={3}>
                    <AlertIcon />
                    <AlertDescription fontSize='sm' lineHeight='1.45'>
                      <Text as='span' fontWeight='semibold'>
                        1 alert per threshold crossed.
                      </Text>
                    </AlertDescription>
                  </Alert>
                </FormControl>
                <HStack mt={4} spacing={3}>
                  <DashboardActionButton
                    onClick={handleResetDefaults}
                    variant='outline'
                    disabled={loading || isViewer}
                  >
                    Reset to defaults
                  </DashboardActionButton>
                  <DashboardActionButton
                    colorScheme='blue'
                    onClick={handleSave}
                    isLoading={saving}
                    disabled={loading || !workspaceId || isViewer}
                  >
                    Save
                  </DashboardActionButton>
                </HStack>
              </DashboardPanel>

              {/* Workspace Delivery Window */}
              <DashboardPanel
                data-tour='preferences-delivery-window'
                display='flex'
                flexDirection='column'
                h='full'
              >
                <PreferencesPanelHeader
                  title='Workspace delivery window'
                  description='Set start time, end time, and timezone for when alerts may be delivered.'
                  muted={bodySecondary}
                />
                <Stack direction={{ base: 'column', lg: 'row' }} spacing={3}>
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
                      !/^([01]\d|2[0-3]):[0-5]\d$/.test(
                        String(dwStart).trim()
                      ) && (
                        <FormErrorMessage>
                          Use HH:mm (00:00-23:59)
                        </FormErrorMessage>
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
                      !/^([01]\d|2[0-3]):[0-5]\d$/.test(
                        String(dwEnd).trim()
                      ) && (
                        <FormErrorMessage>
                          Use HH:mm (00:00-23:59)
                        </FormErrorMessage>
                      )}
                  </FormControl>
                  <FormControl isDisabled={isViewer}>
                    <FormLabel>Timezone</FormLabel>
                    <Select
                      value={dwTz}
                      onChange={e => setDwTz(e.target.value)}
                    >
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
                        <option value='Asia/Tokyo'>
                          Asia/Tokyo (UTC+9, JST)
                        </option>
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
                        <option value='Asia/Dubai'>
                          Asia/Dubai (UTC+4, GST)
                        </option>
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
                        <option value='Asia/Seoul'>
                          Asia/Seoul (UTC+9, KST)
                        </option>
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
                </Stack>
                <Alert status='info' size='sm' borderRadius='md' mt={5}>
                  <AlertIcon />
                  <AlertDescription fontSize='sm' lineHeight='1.45'>
                    <Text as='span' fontWeight='semibold'>
                      Alerts outside this window will be sent when the window
                      reopens, for all alert channels.
                    </Text>
                  </AlertDescription>
                </Alert>
                <HStack mt='auto' pt={5}>
                  <DashboardActionButton
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
                        showError(
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
                  </DashboardActionButton>
                </HStack>
              </DashboardPanel>
            </SimpleGrid>
          </SettingsSection>

          <SettingsSection id='contacts'>
            <DashboardPanel data-tour='preferences-contacts' minW={0}>
              <PreferencesPanelHeader
                title='Contacts'
                description='Manage people and contact details that can receive workspace alerts.'
                muted={bodySecondary}
                action={
                  !isViewer ? (
                    <DashboardActionButton
                      size='sm'
                      colorScheme='blue'
                      onClick={onAddContactOpen}
                      data-tour='preferences-contacts-add-trigger'
                    >
                      Add contact
                    </DashboardActionButton>
                  ) : null
                }
              />
              <VStack align='stretch' spacing={4}>
                {isViewer && (
                  <Alert status='info' borderRadius='md'>
                    <AlertIcon />
                    <AlertDescription>
                      Contacts are read-only for viewers. Only workspace
                      managers and admins can add or modify contacts.
                    </AlertDescription>
                  </Alert>
                )}

                <Box data-tour='preferences-contacts-list'>
                  <Box display={{ base: 'block', md: 'none' }}>
                    {contacts.length === 0 ? (
                      <Text color={bodySecondary} fontSize='sm'>
                        No contacts defined.
                      </Text>
                    ) : (
                      <VStack align='stretch' spacing={3}>
                        {sortedContacts.map(contact =>
                          renderMobileContactCard(contact)
                        )}
                      </VStack>
                    )}
                  </Box>

                  <Box overflowX='auto' display={{ base: 'none', md: 'block' }}>
                    <Table
                      size='sm'
                      width='100%'
                      minW='960px'
                      sx={{ tableLayout: 'fixed' }}
                    >
                      <Thead>
                        <Tr>
                          <ContactSortableTh
                            width='12%'
                            sortKey='name'
                            sortConfig={contactSortConfig}
                            onSort={handleContactSort}
                            hoverBg={dashboard.table.rowHover}
                          >
                            Name
                          </ContactSortableTh>
                          <ContactSortableTh
                            width='14%'
                            sortKey='phone'
                            sortConfig={contactSortConfig}
                            onSort={handleContactSort}
                            hoverBg={dashboard.table.rowHover}
                          >
                            Phone
                          </ContactSortableTh>
                          <ContactSortableTh
                            width='13%'
                            sortKey='department'
                            sortConfig={contactSortConfig}
                            onSort={handleContactSort}
                            hoverBg={dashboard.table.rowHover}
                          >
                            Department
                          </ContactSortableTh>
                          <ContactSortableTh
                            width='13%'
                            sortKey='title'
                            sortConfig={contactSortConfig}
                            onSort={handleContactSort}
                            hoverBg={dashboard.table.rowHover}
                          >
                            Title
                          </ContactSortableTh>
                          <ContactSortableTh
                            width='16%'
                            sortKey='email'
                            sortConfig={contactSortConfig}
                            onSort={handleContactSort}
                            hoverBg={dashboard.table.rowHover}
                          >
                            Email
                          </ContactSortableTh>
                          <ContactSortableTh
                            width='18%'
                            sortKey='note'
                            sortConfig={contactSortConfig}
                            onSort={handleContactSort}
                            hoverBg={dashboard.table.rowHover}
                          >
                            Note
                          </ContactSortableTh>
                          <Th width='14%' textAlign='right'></Th>
                        </Tr>
                      </Thead>
                      <Tbody>
                        {sortedContacts.map(c => {
                          const detailFields = getContactDetailFields(c);

                          return (
                            <Tr key={c.id}>
                              <Td
                                pr={2}
                                whiteSpace='normal'
                                wordBreak='break-word'
                              >
                                <Text fontSize='sm' fontWeight='medium'>
                                  {c.first_name} {c.last_name}
                                </Text>
                              </Td>
                              <Td
                                pr={2}
                                whiteSpace='normal'
                                wordBreak='break-word'
                              >
                                <Text
                                  fontSize='sm'
                                  minW={0}
                                  wordBreak='break-word'
                                >
                                  {c.phone_e164 || '-'}
                                </Text>
                              </Td>
                              <Td
                                pr={2}
                                whiteSpace='normal'
                                wordBreak='break-word'
                              >
                                <ContactTableField
                                  value={detailFields.department}
                                  muted={bodySecondary}
                                  text={text}
                                />
                              </Td>
                              <Td
                                pr={2}
                                whiteSpace='normal'
                                wordBreak='break-word'
                              >
                                <ContactTableField
                                  value={detailFields.title}
                                  muted={bodySecondary}
                                  text={text}
                                />
                              </Td>
                              <Td
                                pr={2}
                                whiteSpace='normal'
                                wordBreak='break-word'
                              >
                                <ContactTableField
                                  value={detailFields.email}
                                  muted={bodySecondary}
                                  text={text}
                                />
                              </Td>
                              <Td
                                pr={2}
                                whiteSpace='normal'
                                wordBreak='break-word'
                              >
                                <ContactTableField
                                  value={detailFields.note}
                                  muted={bodySecondary}
                                  text={text}
                                />
                              </Td>
                              <Td textAlign='right' pl={2}>
                                <HStack spacing={2} justify='flex-end'>
                                  <Button
                                    size='sm'
                                    h='30px'
                                    minH='30px'
                                    minW='76px'
                                    variant='outline'
                                    onClick={() => handleStartContactEdit(c)}
                                    isDisabled={isViewer}
                                  >
                                    Edit
                                  </Button>

                                  <Button
                                    size='sm'
                                    h='30px'
                                    minH='30px'
                                    minW='76px'
                                    variant='outline'
                                    colorScheme='red'
                                    onClick={() => openContactDeleteConfirm(c)}
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
                </Box>
              </VStack>
            </DashboardPanel>
          </SettingsSection>

          <SettingsSection id='webhooks'>
            <DashboardPanel data-tour='preferences-webhooks' minW={0}>
              <PreferencesPanelHeader
                title='Webhooks'
                description='Configure outgoing webhook targets for workspace alerts.'
                muted={bodySecondary}
                action={
                  !isViewer ? (
                    <DashboardActionButton
                      size='sm'
                      colorScheme='blue'
                      onClick={openAddWebhookEditor}
                      disabled={webhookUrls.length >= 5}
                      data-tour='preferences-webhooks-add-trigger'
                    >
                      Add webhook
                    </DashboardActionButton>
                  ) : null
                }
              />
              {isViewer && (
                <Alert status='info' mb={3} borderRadius='md'>
                  <AlertIcon />
                  <AlertDescription>
                    You have viewer access in this workspace. Webhook settings
                    are read‑only.
                  </AlertDescription>
                </Alert>
              )}
              <WebhookSetupGuidesPanel
                labelColor={text}
                muted={bodySecondary}
                renderVendorLogo={renderWebhookLogo}
              />
              <VStack
                align='stretch'
                spacing={4}
                data-tour='preferences-webhooks-list'
              >
                {webhookUrls.filter(isSavedWebhook).length === 0 ? (
                  <Text fontSize='sm' color={bodySecondary}>
                    No webhooks configured.
                  </Text>
                ) : (
                  webhookUrls.map((webhook, index) => {
                    if (!isSavedWebhook(webhook)) return null;
                    const displayWebhook =
                      getSavedWebhookForDisplay(webhook) || webhook;

                    return (
                      <SettingsNestedSurface key={index}>
                        {renderWebhookReadOnlyView(
                          index,
                          displayWebhook,
                          webhook
                        )}
                      </SettingsNestedSurface>
                    );
                  })
                )}
              </VStack>
            </DashboardPanel>
          </SettingsSection>

          <SettingsSection id='contact-groups'>
            <DashboardPanel data-tour='preferences-contact-groups'>
              <PreferencesPanelHeader
                title='Contact groups'
                description={`Create groups to organize who receives alerts. Each person can receive via email${whatsappAvailable ? ', WhatsApp,' : ''} or webhooks.`}
                muted={bodySecondary}
                action={
                  !isViewer ? (
                    <DashboardActionButton
                      size='sm'
                      variant='outline'
                      onClick={onGroupEditorOpen}
                      data-tour='preferences-contact-groups-edit'
                    >
                      Edit group
                    </DashboardActionButton>
                  ) : null
                }
              />
              {isViewer && (
                <Alert status='info' mb={4} borderRadius='md'>
                  <AlertIcon />
                  <AlertDescription>
                    Contact groups are not visible for viewers in this
                    workspace.
                  </AlertDescription>
                </Alert>
              )}
              <VStack align='stretch' spacing={4}>
                {/* Default group selector */}
                {!isViewer && (
                  <FormControl isDisabled={isViewer}>
                    <FormLabel>Contact groups</FormLabel>
                    <Stack
                      direction={{ base: 'column', sm: 'row' }}
                      align={{ base: 'stretch', sm: 'center' }}
                      spacing={{ base: 2, sm: 3 }}
                    >
                      <Select
                        data-tour='preferences-contact-groups-selector'
                        value={selectedGroupId || ''}
                        flex={{ sm: 1 }}
                        w={{ base: 'full', sm: 'auto' }}
                        onChange={e => {
                          const val = e.target.value;
                          if (val === '__new__') {
                            resetGroupEditor();
                            setGroupThresholdsCsv(thresholdsCsv);
                            setSelectedGroupId('');
                            onGroupEditorOpen();
                            return;
                          }
                          setSelectedGroupId(val);
                          const g = (contactGroups || []).find(
                            x => String(x.id) === String(val)
                          );
                          if (g) startEditGroup(g);
                          onGroupEditorOpen();
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
                        <Badge alignSelf={{ base: 'flex-start', sm: 'center' }}>
                          default
                        </Badge>
                      ) : null}
                    </Stack>
                    {selectedGroupId ? (
                      <Stack
                        direction='row'
                        mt={2}
                        spacing={2}
                        align='center'
                        flexWrap='wrap'
                      >
                        <Text fontSize='xs' color={bodySecondary}>
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
                      </Stack>
                    ) : null}
                    <Text fontSize='xs' color={bodySecondary} mt={1}>
                      Pick a group to open the editor, or choose + Add New Group
                      to create one.
                    </Text>
                    <Stack
                      direction={{ base: 'column', sm: 'row' }}
                      mt={3}
                      spacing={3}
                      align={{ base: 'stretch', sm: 'center' }}
                    >
                      <Button
                        size='sm'
                        variant='solid'
                        colorScheme='blue'
                        w={{ base: 'full', sm: 'auto' }}
                        isDisabled={
                          !selectedGroupId ||
                          selectedGroupId === defaultContactGroupId ||
                          isViewer
                        }
                        onClick={async () => {
                          try {
                            if (!workspaceId || !selectedGroupId) return;
                            await workspaceAPI.updateAlertSettings(
                              workspaceId,
                              {
                                default_contact_group_id: selectedGroupId,
                                contact_groups: contactGroups,
                              }
                            );
                            setDefaultContactGroupId(selectedGroupId);
                            showSuccess('Default contact group updated');
                          } catch (_) {
                            showError('Failed to update default contact group');
                          }
                        }}
                      >
                        Make this group default
                      </Button>
                      <Button
                        size='sm'
                        variant='outline'
                        colorScheme='red'
                        w={{ base: 'full', sm: 'auto' }}
                        isDisabled={!selectedGroupId || isViewer}
                        onClick={() => {
                          if (!selectedGroupId) return;
                          setDeleteTargetId(selectedGroupId);
                          setDeleteDialogOpen(true);
                        }}
                      >
                        Delete group
                      </Button>
                    </Stack>
                  </FormControl>
                )}

                {/* Groups list removed per UX rework; selection + editor handle edits/deletes */}
              </VStack>
            </DashboardPanel>
          </SettingsSection>
        </SettingsPageShell>
      </DashboardPageLayout>

      <Modal
        isOpen={isGroupEditorOpen}
        onClose={onGroupEditorClose}
        isCentered
        scrollBehavior='inside'
      >
        <ModalOverlay {...overlayProps} />
        <DashboardModalFrame
          data-tour='preferences-contact-groups-editor'
          maxW={{ base: 'calc(100vw - 24px)', md: '760px' }}
          maxH={{ base: 'calc(100dvh - 24px)', md: 'calc(100dvh - 64px)' }}
        >
          <ModalHeader {...headerProps}>
            <DashboardModalTitle color={modalTokens.text}>
              {editingGroupId ? 'Edit contact group' : 'New contact group'}
            </DashboardModalTitle>
            <DashboardModalDescription color={modalTokens.subtleText}>
              Choose contacts, channels, webhooks, and optional threshold
              overrides for this group.
            </DashboardModalDescription>
          </ModalHeader>
          <ModalCloseButton {...closeButtonProps} />
          <ModalBody {...bodyProps}>
            <VStack align='stretch' spacing={2}>
              <Text fontSize='xs' color={bodySecondary}>
                Groups used: {(contactGroups || []).length}/
                {groupCap === Infinity ? 'unlimited' : groupCap}
              </Text>
              <FormControl isInvalid={groupSaveAttempted && !groupName.trim()}>
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
                  <FormErrorMessage>Group name is required.</FormErrorMessage>
                )}
              </FormControl>
              <FormControl data-tour='preferences-contact-groups-contacts-channels'>
                <FormLabel>Contacts and channels</FormLabel>
                <Text fontSize='xs' color={bodySecondary} mb={1}>
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
                    <Text fontSize='sm' color={bodySecondary}>
                      No contacts defined. Add contacts in the Contacts section
                      above.
                    </Text>
                  ) : (
                    contacts.map(c => {
                      const email = (c.details && c.details.email) || '';
                      const emailDisabled = !isValidEmail(String(email || ''));
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
                          <HStack flexShrink={0} spacing={3} align='center'>
                            <Checkbox
                              isChecked={groupEmailContactIds.includes(c.id)}
                              isDisabled={
                                emailDisabled ||
                                (!groupEmailContactIds.includes(c.id) &&
                                  !groupWhatsappContactIds.includes(c.id) &&
                                  totalSelectedPeople >= memberCap)
                              }
                              onChange={e => {
                                if (e.target.checked) {
                                  setGroupEmailContactIds(
                                    Array.from(
                                      new Set([...groupEmailContactIds, c.id])
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
                                  (!groupWhatsappContactIds.includes(c.id) &&
                                    !groupEmailContactIds.includes(c.id) &&
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
                  <Text fontSize='xs' color='gray.600' fontWeight='medium'>
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
                      <strong>Member limit exceeded:</strong> You{"'"}
                      ve selected {totalSelectedPeople} people, but your plan
                      allows only {memberCap} people per group. Only the first{' '}
                      {memberCap} people will be saved.
                    </AlertDescription>
                  </Alert>
                )}
              </VStack>
              {/* Emails textarea removed in favor of per-contact channel toggles */}
              <FormLabel>Webhook channels (unlimited)</FormLabel>
              <Box data-tour='preferences-contact-groups-webhooks'>
                <SettingsNestedSurface>
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
                          <Text fontSize='xs' color={bodySecondary}>
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
                </SettingsNestedSurface>
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
                <Text fontSize='xs' color={bodySecondary} mt={1}>
                  Leave equal to defaults to inherit workspace thresholds.
                  Allowed range: -365 to 730.
                </Text>
              </FormControl>
              <Divider my={3} />
              <FormLabel m={0} fontSize='sm'>
                Weekly Digest
              </FormLabel>
              <Text fontSize='xs' color={bodySecondary} mb={2}>
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
                  onChange={e => setGroupWeeklyDigestEmail(e.target.checked)}
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
                  onChange={e => setGroupWeeklyDigestWebhooks(e.target.checked)}
                  isDisabled={!hasWebhookInGroup}
                >
                  Webhook weekly digest
                </Checkbox>
              </VStack>
              <Text fontSize='xs' color={bodySecondary}>
                Weekly digest supports Slack, Discord, Teams, and generic
                webhooks. PagerDuty is not supported as it&apos;s designed for
                incident alerting.
              </Text>
              <Text fontSize='xs' color={bodySecondary}>
                Changes are not saved until you click {'"'}Save group
                {'"'}.
              </Text>
            </VStack>
          </ModalBody>
          <ModalFooter {...footerProps}>
            <Flex
              w='100%'
              gap={3}
              justify={{ base: 'stretch', sm: 'flex-end' }}
              direction={{ base: 'column-reverse', sm: 'row' }}
              flexWrap='wrap'
            >
              <Button
                variant='outline'
                onClick={onGroupEditorClose}
                minW={{ base: '100%', sm: 'auto' }}
                {...outlineButtonProps}
              >
                Cancel
              </Button>
              <Button
                variant='outline'
                onClick={resetGroupEditor}
                minW={{ base: '100%', sm: 'auto' }}
                {...outlineButtonProps}
              >
                Reset
              </Button>
              <DashboardActionButton
                colorScheme='blue'
                onClick={saveGroup}
                minW={{ base: '100%', sm: 'auto' }}
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
              </DashboardActionButton>
            </Flex>
          </ModalFooter>
        </DashboardModalFrame>
      </Modal>

      <Modal
        isOpen={isWebhookEditorOpen}
        onClose={handleCloseWebhookEditor}
        isCentered
        scrollBehavior='inside'
      >
        <ModalOverlay {...overlayProps} />
        <DashboardModalFrame
          data-tour='preferences-webhooks-editor'
          maxW={{ base: 'calc(100vw - 24px)', md: '760px' }}
          maxH={{ base: 'calc(100dvh - 24px)', md: 'calc(100dvh - 64px)' }}
        >
          <ModalHeader {...headerProps}>
            <DashboardModalTitle color={modalTokens.text}>
              {editingWebhookIndex >= 0 ? 'Edit webhook' : 'Add webhook'}
            </DashboardModalTitle>
            <DashboardModalDescription color={modalTokens.subtleText}>
              Configure the webhook name, type, and URL, then test and save it.
            </DashboardModalDescription>
          </ModalHeader>
          <ModalCloseButton {...closeButtonProps} />
          <ModalBody {...bodyProps}>
            <VStack align='stretch' spacing={4}>
              {renderWebhookEditorFields(webhookDraft, updateWebhookDraft)}
              {webhookSaveAttempted && !webhookDraft.name?.trim() ? (
                <Text fontSize='sm' color='red.500'>
                  Webhook name is required.
                </Text>
              ) : null}
              {webhookDraft.verified &&
              (webhookDraft.verifiedUrl || '') ===
                (webhookDraft.url || '').trim() ? (
                <Badge
                  colorScheme='green'
                  variant='subtle'
                  alignSelf='flex-start'
                  borderRadius='md'
                  px={2.5}
                  py={1}
                  fontSize='xs'
                  fontWeight='semibold'
                  letterSpacing='0.04em'
                  textTransform='uppercase'
                >
                  Verified
                </Badge>
              ) : (
                <Text fontSize='xs' color={bodySecondary}>
                  Send a test message before saving a new or changed webhook
                  URL.
                </Text>
              )}
            </VStack>
          </ModalBody>
          <ModalFooter {...footerProps}>
            <Flex
              w='100%'
              gap={3}
              justify={{ base: 'stretch', sm: 'flex-end' }}
              direction={{ base: 'column-reverse', sm: 'row' }}
              flexWrap='wrap'
            >
              <Button
                variant='outline'
                onClick={handleCloseWebhookEditor}
                minW={{ base: '100%', sm: 'auto' }}
                {...outlineButtonProps}
              >
                Cancel
              </Button>
              <Button
                variant='outline'
                onClick={handleTestWebhookDraft}
                isLoading={testingWebhookDraft}
                isDisabled={!webhookDraft.url?.trim() || isViewer}
                minW={{ base: '100%', sm: 'auto' }}
                {...outlineButtonProps}
              >
                Test
              </Button>
              <DashboardActionButton
                colorScheme='blue'
                onClick={handleSaveWebhookEditor}
                isLoading={savingToggles}
                isDisabled={isViewer || !workspaceId || !canSaveWebhookDraft()}
                minW={{ base: '100%', sm: 'auto' }}
              >
                Save webhook
              </DashboardActionButton>
            </Flex>
          </ModalFooter>
        </DashboardModalFrame>
      </Modal>

      <Modal
        isOpen={isAddContactOpen}
        onClose={handleCloseAddContact}
        isCentered
        scrollBehavior='inside'
      >
        <ModalOverlay {...overlayProps} />
        <DashboardModalFrame
          data-tour='preferences-contacts-add'
          maxW={{ base: 'calc(100vw - 24px)', md: '560px' }}
          maxH={{ base: 'calc(100dvh - 24px)', md: 'calc(100dvh - 64px)' }}
        >
          <ModalHeader {...headerProps}>
            <DashboardModalTitle color={modalTokens.text}>
              Add contact
            </DashboardModalTitle>
            <DashboardModalDescription color={modalTokens.subtleText}>
              Add someone who can receive workspace alert notifications.
            </DashboardModalDescription>
          </ModalHeader>
          <ModalCloseButton {...closeButtonProps} />
          <ModalBody {...bodyProps}>
            <VStack align='stretch' spacing={4}>
              <SimpleGrid columns={{ base: 1, sm: 2 }} spacing={3}>
                <FormControl>
                  <FormLabel>First name</FormLabel>
                  <Input
                    placeholder='First name'
                    value={newContactFirstName}
                    onChange={e => setNewContactFirstName(e.target.value)}
                  />
                </FormControl>
                <FormControl>
                  <FormLabel>Last name</FormLabel>
                  <Input
                    placeholder='Last name'
                    value={newContactLastName}
                    onChange={e => setNewContactLastName(e.target.value)}
                  />
                </FormControl>
              </SimpleGrid>
              <FormControl>
                <FormLabel>Email</FormLabel>
                <Input
                  placeholder='name@example.com'
                  value={newContactDetails.email || ''}
                  onChange={e =>
                    setNewContactDetails({
                      ...newContactDetails,
                      email: e.target.value,
                    })
                  }
                />
              </FormControl>
              <FormControl isInvalid={!!contactPhoneError}>
                <FormLabel>Phone (E.164)</FormLabel>
                <Input
                  placeholder='+14155550100'
                  value={newContactPhone}
                  onChange={e => {
                    const val = e.target.value;
                    setNewContactPhone(val);
                    setContactPhoneError('');
                    if (val.trim() && !isValidContactPhoneE164(val)) {
                      setContactPhoneError(
                        'Invalid E.164 format (e.g., +14155550100)'
                      );
                    }
                  }}
                />
                {contactPhoneError ? (
                  <FormErrorMessage>{contactPhoneError}</FormErrorMessage>
                ) : (
                  <Text fontSize='xs' color={modalTokens.subtleText} mt={1}>
                    Provide a valid email or phone number.
                  </Text>
                )}
                {whatsappAvailable ? (
                  <TestWhatsappButton
                    mt={3}
                    onClick={() =>
                      handleTestWhatsappPhone(
                        newContactPhoneE164,
                        ADD_CONTACT_WHATSAPP_TEST_KEY
                      )
                    }
                    isLoading={testingContact === ADD_CONTACT_WHATSAPP_TEST_KEY}
                    isDisabled={isViewer || !isNewContactPhoneValid}
                    cooldownUntil={
                      waContactCooldowns[ADD_CONTACT_WHATSAPP_TEST_KEY] || 0
                    }
                  />
                ) : null}
              </FormControl>
              <Button
                size='sm'
                variant='ghost'
                onClick={() => setNewContactDetailsOpen(!newContactDetailsOpen)}
                alignSelf='flex-start'
              >
                {newContactDetailsOpen ? 'Hide' : 'Show'} additional details
              </Button>
              {newContactDetailsOpen ? (
                <VStack align='stretch' spacing={3}>
                  <FormControl>
                    <FormLabel>Department</FormLabel>
                    <Input
                      placeholder='Department'
                      value={newContactDetails.department || ''}
                      onChange={e =>
                        setNewContactDetails({
                          ...newContactDetails,
                          department: e.target.value,
                        })
                      }
                    />
                  </FormControl>
                  <FormControl>
                    <FormLabel>Title / role</FormLabel>
                    <Input
                      placeholder='Title / Role'
                      value={newContactDetails.title || ''}
                      onChange={e =>
                        setNewContactDetails({
                          ...newContactDetails,
                          title: e.target.value,
                        })
                      }
                    />
                  </FormControl>
                  <FormControl>
                    <FormLabel>Note</FormLabel>
                    <Textarea
                      placeholder='Note'
                      value={newContactDetails.note || ''}
                      onChange={e =>
                        setNewContactDetails({
                          ...newContactDetails,
                          note: e.target.value,
                        })
                      }
                      rows={3}
                    />
                  </FormControl>
                </VStack>
              ) : null}
            </VStack>
          </ModalBody>
          <ModalFooter {...footerProps}>
            <Flex
              w='100%'
              gap={3}
              justify={{ base: 'stretch', sm: 'flex-end' }}
              direction={{ base: 'column-reverse', sm: 'row' }}
            >
              <Button
                variant='outline'
                onClick={handleCloseAddContact}
                minW={{ base: '100%', sm: 'auto' }}
                {...outlineButtonProps}
              >
                Cancel
              </Button>
              <Tooltip
                label='Enter first and last name plus a valid email or phone number'
                isDisabled={!isNewContactInvalid || isViewer}
                hasArrow
                followCursor
                openDelay={150}
              >
                <Box as='span' display='block' w={{ base: '100%', sm: 'auto' }}>
                  <DashboardActionButton
                    colorScheme='blue'
                    onClick={handleAddContactSubmit}
                    disabled={isNewContactInvalid || isViewer}
                    w={{ base: '100%', sm: 'auto' }}
                  >
                    Add contact
                  </DashboardActionButton>
                </Box>
              </Tooltip>
            </Flex>
          </ModalFooter>
        </DashboardModalFrame>
      </Modal>

      <Modal
        isOpen={isEditContactOpen}
        onClose={handleCloseEditContact}
        isCentered
        scrollBehavior='inside'
      >
        <ModalOverlay {...overlayProps} />
        <DashboardModalFrame
          data-tour='preferences-contacts-edit'
          maxW={{ base: 'calc(100vw - 24px)', md: '560px' }}
          maxH={{ base: 'calc(100dvh - 24px)', md: 'calc(100dvh - 64px)' }}
        >
          <ModalHeader {...headerProps}>
            <DashboardModalTitle color={modalTokens.text}>
              Edit contact
            </DashboardModalTitle>
            <DashboardModalDescription color={modalTokens.subtleText}>
              Update this contact&apos;s details for workspace alert
              notifications.
            </DashboardModalDescription>
          </ModalHeader>
          <ModalCloseButton {...closeButtonProps} />
          <ModalBody {...bodyProps}>
            <VStack align='stretch' spacing={4}>
              <SimpleGrid columns={{ base: 1, sm: 2 }} spacing={3}>
                <FormControl>
                  <FormLabel>First name</FormLabel>
                  <Input
                    placeholder='First name'
                    value={editContactFirstName}
                    onChange={e => setEditContactFirstName(e.target.value)}
                  />
                </FormControl>
                <FormControl>
                  <FormLabel>Last name</FormLabel>
                  <Input
                    placeholder='Last name'
                    value={editContactLastName}
                    onChange={e => setEditContactLastName(e.target.value)}
                  />
                </FormControl>
              </SimpleGrid>
              <FormControl>
                <FormLabel>Email</FormLabel>
                <Input
                  placeholder='name@example.com'
                  value={editContactDetails.email || ''}
                  onChange={e =>
                    setEditContactDetails({
                      ...editContactDetails,
                      email: e.target.value,
                    })
                  }
                />
              </FormControl>
              <FormControl isInvalid={!!editContactPhoneError}>
                <FormLabel>Phone (E.164)</FormLabel>
                <Input
                  placeholder='+14155550100'
                  value={editContactPhone}
                  onChange={e => {
                    const val = e.target.value;
                    setEditContactPhone(val);
                    setEditContactPhoneError('');
                    if (val.trim() && !isValidContactPhoneE164(val)) {
                      setEditContactPhoneError(
                        'Invalid E.164 format (e.g., +14155550100)'
                      );
                    }
                  }}
                />
                {editContactPhoneError ? (
                  <FormErrorMessage>{editContactPhoneError}</FormErrorMessage>
                ) : (
                  <Text fontSize='xs' color={modalTokens.subtleText} mt={1}>
                    Provide a valid email or phone number.
                  </Text>
                )}
                {whatsappAvailable ? (
                  <TestWhatsappButton
                    mt={3}
                    onClick={() =>
                      handleTestWhatsappPhone(
                        editContactPhoneE164,
                        EDIT_CONTACT_WHATSAPP_TEST_KEY
                      )
                    }
                    isLoading={
                      testingContact === EDIT_CONTACT_WHATSAPP_TEST_KEY
                    }
                    isDisabled={isViewer || !isEditContactPhoneValid}
                    cooldownUntil={
                      waContactCooldowns[EDIT_CONTACT_WHATSAPP_TEST_KEY] || 0
                    }
                  />
                ) : null}
              </FormControl>
              <Button
                size='sm'
                variant='ghost'
                onClick={() =>
                  setEditContactDetailsOpen(!editContactDetailsOpen)
                }
                alignSelf='flex-start'
              >
                {editContactDetailsOpen ? 'Hide' : 'Show'} additional details
              </Button>
              {editContactDetailsOpen ? (
                <VStack align='stretch' spacing={3}>
                  <FormControl>
                    <FormLabel>Department</FormLabel>
                    <Input
                      placeholder='Department'
                      value={editContactDetails.department || ''}
                      onChange={e =>
                        setEditContactDetails({
                          ...editContactDetails,
                          department: e.target.value,
                        })
                      }
                    />
                  </FormControl>
                  <FormControl>
                    <FormLabel>Title / role</FormLabel>
                    <Input
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
                  <FormControl>
                    <FormLabel>Note</FormLabel>
                    <Textarea
                      placeholder='Note'
                      value={editContactDetails.note || ''}
                      onChange={e =>
                        setEditContactDetails({
                          ...editContactDetails,
                          note: e.target.value,
                        })
                      }
                      rows={3}
                    />
                  </FormControl>
                </VStack>
              ) : null}
            </VStack>
          </ModalBody>
          <ModalFooter {...footerProps}>
            <Flex
              w='100%'
              gap={3}
              justify={{ base: 'stretch', sm: 'flex-end' }}
              direction={{ base: 'column-reverse', sm: 'row' }}
            >
              <Button
                variant='outline'
                onClick={handleCloseEditContact}
                minW={{ base: '100%', sm: 'auto' }}
                {...outlineButtonProps}
              >
                Cancel
              </Button>
              <Tooltip
                label='Enter first and last name plus a valid email or phone number'
                isDisabled={!isEditedContactInvalid || isViewer}
                hasArrow
                followCursor
                openDelay={150}
              >
                <Box as='span' display='block' w={{ base: '100%', sm: 'auto' }}>
                  <DashboardActionButton
                    colorScheme='blue'
                    onClick={handleSaveEditedContact}
                    disabled={isEditedContactInvalid || isViewer}
                    w={{ base: '100%', sm: 'auto' }}
                  >
                    Save changes
                  </DashboardActionButton>
                </Box>
              </Tooltip>
            </Flex>
          </ModalFooter>
        </DashboardModalFrame>
      </Modal>

      <AlertDialog
        isOpen={Boolean(webhookDeleteTarget)}
        leastDestructiveRef={cancelRef}
        onClose={closeWebhookDeleteConfirm}
        isCentered
        scrollBehavior='inside'
      >
        <AlertDialogOverlay {...overlayProps} />
        <AlertDialogContent
          {...contentProps}
          maxW={{ base: 'calc(100vw - 24px)', md: '760px' }}
          maxH={{ base: 'calc(100dvh - 24px)', md: 'calc(100dvh - 64px)' }}
        >
          <AlertDialogHeader {...headerProps}>
            <DashboardModalTitle color={modalTokens.text}>
              Delete Webhook
            </DashboardModalTitle>
            <DashboardModalDescription color={modalTokens.subtleText}>
              Review this webhook before removing it from workspace alerts.
            </DashboardModalDescription>
          </AlertDialogHeader>
          <AlertDialogCloseButton {...closeButtonProps} />
          <AlertDialogBody {...bodyProps}>
            <VStack spacing={4} align='stretch'>
              <Alert
                status='warning'
                bg={dashboard.callout.warningSurface}
                border='1px solid'
                borderColor={dashboard.callout.warningBorder}
                color={dashboard.callout.warningText}
                borderRadius='12px'
              >
                <AlertIcon />
                <AlertDescription>
                  This webhook will be removed from the workspace and will no
                  longer receive alerts. This change is saved immediately.
                </AlertDescription>
              </Alert>

              {webhookDeleteTarget?.webhook ? (
                <SimpleGrid columns={{ base: 1, sm: 2 }} spacing={3}>
                  <Text
                    gridColumn={{ base: 'auto', sm: '1 / -1' }}
                    fontSize='sm'
                    fontWeight='bold'
                    color={modalTokens.text}
                    pl={3}
                    borderLeft='3px solid'
                    borderColor={modalTokens.sectionAccent}
                  >
                    Webhook Information
                  </Text>
                  <PreferenceConfirmFieldCard label='Name' tokens={modalTokens}>
                    <PreferenceConfirmValue tokens={modalTokens}>
                      {webhookDeleteTarget.webhook.name}
                    </PreferenceConfirmValue>
                  </PreferenceConfirmFieldCard>
                  <PreferenceConfirmFieldCard label='Type' tokens={modalTokens}>
                    <PreferenceConfirmValue tokens={modalTokens}>
                      {formatWebhookKindLabel(webhookDeleteTarget.webhook.kind)}
                    </PreferenceConfirmValue>
                  </PreferenceConfirmFieldCard>
                  <PreferenceConfirmFieldCard label='URL' tokens={modalTokens}>
                    <PreferenceConfirmValue
                      tokens={modalTokens}
                      wordBreak='break-all'
                    >
                      {webhookDeleteTarget.webhook.url}
                    </PreferenceConfirmValue>
                  </PreferenceConfirmFieldCard>
                  <PreferenceConfirmFieldCard
                    label='Verification'
                    tokens={modalTokens}
                  >
                    <PreferenceConfirmValue tokens={modalTokens}>
                      {webhookDeleteTarget.webhook.verified &&
                      (webhookDeleteTarget.webhook.verifiedUrl || '') ===
                        (webhookDeleteTarget.webhook.url || '').trim()
                        ? 'Verified'
                        : 'Not verified'}
                    </PreferenceConfirmValue>
                  </PreferenceConfirmFieldCard>
                </SimpleGrid>
              ) : null}
            </VStack>
          </AlertDialogBody>
          <AlertDialogFooter {...footerProps}>
            <Flex
              w='100%'
              gap={3}
              justify={{ base: 'stretch', sm: 'flex-end' }}
              direction={{ base: 'column-reverse', sm: 'row' }}
            >
              <Button
                ref={cancelRef}
                onClick={closeWebhookDeleteConfirm}
                minW={{ base: '100%', sm: '104px' }}
                {...outlineButtonProps}
              >
                Cancel
              </Button>
              <Button
                bg={dashboard.callout.dangerButton}
                color='white'
                minW={{ base: '100%', sm: '128px' }}
                onClick={confirmWebhookDelete}
                _hover={{ bg: dashboard.callout.dangerButtonHover }}
              >
                Delete Webhook
              </Button>
            </Flex>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <AlertDialog
        isOpen={Boolean(contactDeleteTarget)}
        leastDestructiveRef={cancelRef}
        onClose={closeContactDeleteConfirm}
        isCentered
        scrollBehavior='inside'
      >
        <AlertDialogOverlay {...overlayProps} />
        <AlertDialogContent
          {...contentProps}
          maxW={{ base: 'calc(100vw - 24px)', md: '760px' }}
          maxH={{ base: 'calc(100dvh - 24px)', md: 'calc(100dvh - 64px)' }}
        >
          <AlertDialogHeader {...headerProps}>
            <DashboardModalTitle color={modalTokens.text}>
              Remove Contact
            </DashboardModalTitle>
            <DashboardModalDescription color={modalTokens.subtleText}>
              Review this contact before removing them from workspace alerts.
            </DashboardModalDescription>
          </AlertDialogHeader>
          <AlertDialogCloseButton {...closeButtonProps} />
          <AlertDialogBody {...bodyProps}>
            <VStack spacing={4} align='stretch'>
              <Alert
                status='warning'
                bg={dashboard.callout.warningSurface}
                border='1px solid'
                borderColor={dashboard.callout.warningBorder}
                color={dashboard.callout.warningText}
                borderRadius='12px'
              >
                <AlertIcon />
                <AlertDescription>
                  This contact will be removed from the workspace and from any
                  contact groups that use them. This change is saved
                  immediately.
                </AlertDescription>
              </Alert>

              {contactDeleteTarget ? (
                <SimpleGrid columns={{ base: 1, sm: 2 }} spacing={3}>
                  <Text
                    gridColumn={{ base: 'auto', sm: '1 / -1' }}
                    fontSize='sm'
                    fontWeight='bold'
                    color={modalTokens.text}
                    pl={3}
                    borderLeft='3px solid'
                    borderColor={modalTokens.sectionAccent}
                  >
                    Contact Information
                  </Text>
                  <PreferenceConfirmFieldCard label='Name' tokens={modalTokens}>
                    <PreferenceConfirmValue tokens={modalTokens}>
                      {getContactDisplayName(contactDeleteTarget)}
                    </PreferenceConfirmValue>
                  </PreferenceConfirmFieldCard>
                  <PreferenceConfirmFieldCard
                    label='Phone'
                    tokens={modalTokens}
                  >
                    <PreferenceConfirmValue
                      tokens={modalTokens}
                      wordBreak='break-word'
                    >
                      {contactDeleteTarget.phone_e164 || '-'}
                    </PreferenceConfirmValue>
                  </PreferenceConfirmFieldCard>
                  <Box gridColumn={{ base: 'auto', sm: '1 / -1' }}>
                    <PreferenceConfirmFieldCard
                      label='Details'
                      tokens={modalTokens}
                    >
                      {contactDeleteDetails.length > 0 ? (
                        <VStack align='stretch' spacing={1}>
                          {contactDeleteDetails.map(detail => (
                            <PreferenceConfirmValue
                              key={detail.key}
                              tokens={modalTokens}
                              wordBreak='break-word'
                            >
                              <Text as='span' fontWeight='semibold'>
                                {detail.label}:
                              </Text>{' '}
                              {detail.value}
                            </PreferenceConfirmValue>
                          ))}
                        </VStack>
                      ) : (
                        <PreferenceConfirmValue tokens={modalTokens}>
                          -
                        </PreferenceConfirmValue>
                      )}
                    </PreferenceConfirmFieldCard>
                  </Box>
                </SimpleGrid>
              ) : null}
            </VStack>
          </AlertDialogBody>
          <AlertDialogFooter {...footerProps}>
            <Flex
              w='100%'
              gap={3}
              justify={{ base: 'stretch', sm: 'flex-end' }}
              direction={{ base: 'column-reverse', sm: 'row' }}
            >
              <Button
                ref={cancelRef}
                onClick={closeContactDeleteConfirm}
                minW={{ base: '100%', sm: '104px' }}
                {...outlineButtonProps}
              >
                Cancel
              </Button>
              <Button
                bg={dashboard.callout.dangerButton}
                color='white'
                minW={{ base: '100%', sm: '128px' }}
                onClick={confirmContactDelete}
                _hover={{ bg: dashboard.callout.dangerButtonHover }}
              >
                Remove Contact
              </Button>
            </Flex>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <AlertDialog
        isOpen={deleteDialogOpen}
        leastDestructiveRef={cancelRef}
        onClose={() => setDeleteDialogOpen(false)}
      >
        <AlertDialogOverlay {...overlayProps} />
        <AlertDialogContent
          {...contentProps}
          maxW={{ base: 'calc(100vw - 24px)', md: '560px' }}
        >
          <AlertDialogHeader {...headerProps}>
            <DashboardModalTitle color={modalTokens.text}>
              Delete this contact group?
            </DashboardModalTitle>
            <DashboardModalDescription color={modalTokens.muted} fontSize='sm'>
              Reassign tokens and remove this group permanently.
            </DashboardModalDescription>
          </AlertDialogHeader>
          <AlertDialogBody {...bodyProps}>
            <Text color={modalTokens.subtleText}>
              Deleting this contact group will reassign any tokens using it to
              the current default group. This action cannot be undone.
            </Text>
          </AlertDialogBody>
          <AlertDialogFooter {...footerProps}>
            <Flex
              w='100%'
              gap={3}
              justify={{ base: 'stretch', sm: 'flex-end' }}
              direction={{ base: 'column-reverse', sm: 'row' }}
            >
              <Button
                ref={cancelRef}
                onClick={() => {
                  setDeleteDialogOpen(false);
                  setDeleteTargetId('');
                }}
                minW={{ base: '100%', sm: 'auto' }}
                {...outlineButtonProps}
              >
                Cancel
              </Button>
              <Button
                colorScheme='red'
                isLoading={deletingGroup}
                minW={{ base: '100%', sm: 'auto' }}
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
            </Flex>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <AlertDialog
        isOpen={disableAllDialogOpen}
        leastDestructiveRef={cancelRef}
        onClose={() => setDisableAllDialogOpen(false)}
      >
        <AlertDialogOverlay {...overlayProps} />
        <AlertDialogContent
          {...contentProps}
          maxW={{ base: 'calc(100vw - 24px)', md: '560px' }}
        >
          <AlertDialogHeader {...headerProps}>
            <DashboardModalTitle color={modalTokens.text}>
              Disable all alerts?
            </DashboardModalTitle>
            <DashboardModalDescription color={modalTokens.muted} fontSize='sm'>
              Confirm this alert channel change.
            </DashboardModalDescription>
          </AlertDialogHeader>
          <AlertDialogBody {...bodyProps}>
            <Text color={modalTokens.subtleText}>
              If you disable this channel, you won&apos;t receive any alert.
            </Text>
          </AlertDialogBody>
          <AlertDialogFooter {...footerProps}>
            <Button
              ref={cancelRef}
              onClick={() => {
                setDisableAllDialogOpen(false);
                setDisableAllTarget('');
              }}
              {...outlineButtonProps}
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
        <AlertDialogOverlay {...overlayProps} />
        <AlertDialogContent
          {...contentProps}
          maxW={{ base: 'calc(100vw - 24px)', md: '560px' }}
        >
          <AlertDialogHeader {...headerProps}>
            <DashboardModalTitle color={modalTokens.text}>
              Default group updated
            </DashboardModalTitle>
            <DashboardModalDescription color={modalTokens.muted} fontSize='sm'>
              Workspace contact group defaults changed.
            </DashboardModalDescription>
          </AlertDialogHeader>
          <AlertDialogBody {...bodyProps}>
            <Text color={modalTokens.subtleText}>
              {defaultReassignedName
                ? `The deleted default group was replaced by "${defaultReassignedName}" as the workspace default.`
                : 'The deleted default group was removed.'}
            </Text>
          </AlertDialogBody>
          <AlertDialogFooter {...footerProps}>
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
