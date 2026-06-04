import { logger } from './utils/logger.js';
import { getColorFromString } from './styles/colors.js';

import {
  useEffect,
  useLayoutEffect,
  useState,
  useCallback,
  useRef,
  Suspense,
  lazy,
  useMemo,
  memo,
} from 'react';
import { flushSync } from 'react-dom';
import {
  ChakraProvider,
  ColorModeScript,
  Box,
  SimpleGrid,
  FormControl,
  FormLabel,
  FormErrorMessage,
  Input,
  Textarea,
  Select,
  Button,
  Flex,
  Text,
  Link,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  Badge,
  VStack,
  useColorMode,
  useColorModeValue,
  Tooltip,
  IconButton,
  Modal,
  ModalOverlay,
  ModalContent,
  ModalHeader,
  ModalFooter,
  ModalBody,
  ModalCloseButton,
  useDisclosure,
  HStack,
  Alert,
  AlertIcon,
  AlertDescription,
  Menu,
  MenuButton,
  MenuList,
  MenuItem,
  Checkbox,
  Portal,
  InputGroup,
  InputLeftElement,
  Divider,
  Circle,
} from '@chakra-ui/react';
import {
  Routes,
  Route,
  Navigate,
  useSearchParams,
  useNavigate,
  useLocation,
} from 'react-router-dom';
import toast, { Toaster } from 'react-hot-toast';
import { HelmetProvider } from 'react-helmet-async';
import { trackEvent } from './utils/analytics.js';
import {
  FiTrash2,
  FiPlus,
  FiX,
  FiChevronRight,
  FiMenu,
  FiExternalLink,
  FiActivity,
  FiBell,
} from 'react-icons/fi';
import {
  Activity as ActivityIcon,
  AlertTriangle,
  BadgeCheck,
  BookOpen,
  Building2,
  CalendarClock,
  CheckCircle2,
  ChevronDown,
  Clock3,
  Database,
  Download,
  Gauge,
  KeyRound,
  Layers,
  LockKeyhole,
  LogOut,
  MoreVertical,
  Moon,
  Search,
  Settings,
  ShieldAlert,
  Upload,
  User,
  PlugZap,
} from 'lucide-react';

import { theme } from './styles/theme';
import Navigation from './components/Navigation';
import SEO from './components/SEO.jsx';
import Footer from './components/Footer';
import ErrorBoundary from './components/ErrorBoundary';
import WelcomeModal from './components/WelcomeModal';
import ProductTour from './components/ProductTour';
import { AccessibleSpinner } from './components/Accessibility';
import TruncatedText from './components/TruncatedText';
import ImportTokensModal from './components/ImportTokensModal.jsx';
import TokenDetailModal from './components/TokenDetailModal.jsx';
import EndpointSslMonitorModal from './components/EndpointSslMonitorModal.jsx';
import { domainValueToUrl } from './utils/domains.jsx';

import apiClient, {
  authAPI,
  tokenAPI,
  formatDate,
  workspaceAPI,
  showSuccessMessage,
} from './utils/apiClient';

import {
  formatExpirationDate,
  isNeverExpires,
  NEVER_EXPIRES_DATE_VALUE,
} from './utils/dateUtils';
import {
  TOUR_MOCK_TOKENS,
  TOUR_MOCK_CONTACT_GROUPS,
  TOUR_MOCK_WORKSPACE_CONTACTS,
} from './constants/tourMockData.js';

const Login = lazy(() => import('./pages/Login'));
const Register = lazy(() => import('./pages/Register'));
const VerifyEmail = lazy(() => import('./pages/VerifyEmail'));
const ResetPassword = lazy(() => import('./pages/ResetPassword'));
const Account = lazy(() => import('./pages/Account'));
const NotFound = lazy(() => import('./pages/NotFound.jsx'));
const AlertPreferences = lazy(() => import('./pages/AlertPreferences'));
const Help = lazy(() => import('./pages/Help'));
const Usage = lazy(() => import('./pages/Usage'));
const Audit = lazy(() => import('./pages/Audit'));
const Workspaces = lazy(() => import('./pages/Workspaces.jsx'));
const SystemSettings = lazy(() => import('./pages/SystemSettings.jsx'));
import { WorkspaceProvider, useWorkspace } from './utils/WorkspaceContext.jsx';

// VerifyEmailWrapper component to handle session-based redirects
function VerifyEmailWrapper({ session }) {
  // If user has a verified session, don't stay on verify screen
  if (session && !session.needsVerification) {
    return <Navigate to='/dashboard' replace />;
  }

  // Allow unverified users to navigate to landing or logout from verify page via UI controls
  return <VerifyEmail />;
}

function RequireManagerRoute({ session, children }) {
  const [isAllowed, setIsAllowed] = useState(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (!session) {
        if (!cancelled) setIsAllowed(false);
        return;
      }
      const isSystemAdmin = session?.isAdmin === true;
      try {
        const ws = await workspaceAPI.list(50, 0);
        const items = ws?.items || [];
        const roles = items.map(w => String(w.role || '').toLowerCase());
        const hasManagerOrAdmin =
          roles.includes('admin') || roles.includes('workspace_manager');
        if (!cancelled) setIsAllowed(isSystemAdmin || hasManagerOrAdmin);
      } catch (_) {
        if (!cancelled) setIsAllowed(isSystemAdmin);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [session]);

  if (!session) return <Navigate to='/login' replace />;
  if (isAllowed === null) return null;
  if (!isAllowed) return <Navigate to='/dashboard' replace />;
  return children;
}

function AdminOnlyRoute({ session, children }) {
  const [isAllowed, setIsAllowed] = useState(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (!session) {
        if (!cancelled) setIsAllowed(false);
        return;
      }
      try {
        // Source of truth for system settings access is backend auth middleware.
        await apiClient.get('/api/admin/system-settings');
        if (!cancelled) setIsAllowed(true);
      } catch (_) {
        if (!cancelled) setIsAllowed(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [session]);

  if (!session) return <Navigate to='/login' replace />;
  if (isAllowed === null) return null;
  if (!isAllowed) return <Navigate to='/dashboard' replace />;
  return children;
}

/**
 * Token Categories with their specific types, fields, and styling.
 */
const TOKEN_CATEGORIES = [
  {
    value: 'cert',
    label: 'Certificate',
    description: 'SSL/TLS certificates, domain certificates',
    color: 'blue',
    bgColor: 'blue.100',
    borderColor: 'blue.400',
    types: [
      { value: 'ssl_cert', label: 'SSL Certificate' },
      { value: 'tls_cert', label: 'TLS Certificate' },
      { value: 'code_signing', label: 'Code Signing' },
      { value: 'client_cert', label: 'Client Certificate' },
    ],
    fields: [
      'domains',
      'issuer',
      'serial_number',
      'subject',
      'renewal_url',
      'contacts',
    ],
  },
  {
    value: 'key_secret',
    label: 'Key/Secret',
    description: 'API keys, secrets, passwords, encryption keys',
    color: 'green',
    bgColor: 'green.100',
    borderColor: 'green.500',
    types: [
      { value: 'api_key', label: 'API Key' },
      { value: 'secret', label: 'Secret' },
      { value: 'password', label: 'Password' },
      { value: 'encryption_key', label: 'Encryption Key' },
      { value: 'ssh_key', label: 'SSH Key' },
    ],
    fields: ['location', 'used_by', 'renewal_url', 'description', 'contacts'],
    // Fields that only apply to specific types
    conditionalFields: {
      encryption_key: ['algorithm', 'key_size'],
      ssh_key: ['algorithm', 'key_size'],
    },
  },
  {
    value: 'license',
    label: 'License',
    description: 'Software licenses, service subscriptions',
    color: 'purple',
    bgColor: 'purple.100',
    borderColor: 'purple.500',
    types: [
      { value: 'software_license', label: 'Software License' },
      { value: 'service_subscription', label: 'Service Subscription' },
      { value: 'domain_registration', label: 'Domain Registration' },
    ],
    fields: [
      'vendor',
      'license_type',
      'cost',
      'renewal_url',
      'renewal_date',
      'contacts',
    ],
  },
  {
    value: 'general',
    label: 'General',
    description: 'Other expiring items',
    color: 'gray',
    bgColor: 'gray.100',
    borderColor: 'gray.500',
    types: [
      { value: 'other', label: 'Other' },
      { value: 'document', label: 'Document' },
      { value: 'membership', label: 'Membership' },
    ],
    fields: ['location', 'used_by', 'renewal_url', 'contacts'],
  },
];

// Deterministic color mapping for section chips
// Now uses centralized color system from styles/colors.js
const _getSectionColorScheme = getColorFromString;

const MS_PER_DAY = 1000 * 60 * 60 * 24;

function getDaysUntilExpiration(expiry) {
  if (!expiry || isNeverExpires(expiry)) return Number.POSITIVE_INFINITY;
  const expirationDate = new Date(expiry);
  if (Number.isNaN(expirationDate.getTime())) return Number.POSITIVE_INFINITY;

  const today = new Date();
  today.setHours(0, 0, 0, 0);
  expirationDate.setHours(0, 0, 0, 0);
  return Math.ceil((expirationDate.getTime() - today.getTime()) / MS_PER_DAY);
}

function getDashboardStatusMeta(expiry) {
  const days = getDaysUntilExpiration(expiry);
  if (days === Number.POSITIVE_INFINITY) {
    return {
      key: 'healthy',
      label: 'Healthy',
      color: '#22c55e',
      bg: 'rgba(34, 197, 94, 0.12)',
    };
  }
  if (days < 0) {
    return {
      key: 'expired',
      label: 'Expired',
      color: '#f43f5e',
      bg: 'rgba(244, 63, 94, 0.14)',
    };
  }
  if (days <= 7) {
    return {
      key: 'critical',
      label: `${days} days`,
      color: '#ef4444',
      bg: 'rgba(239, 68, 68, 0.14)',
    };
  }
  if (days <= 30) {
    return {
      key: 'due-soon',
      label: `${days} days`,
      color: '#f97316',
      bg: 'rgba(249, 115, 22, 0.14)',
    };
  }
  return {
    key: 'healthy',
    label: `${days} days`,
    color: '#22c55e',
    bg: 'rgba(34, 197, 94, 0.12)',
  };
}

function formatDaysUntil(expiry) {
  const days = getDaysUntilExpiration(expiry);
  if (days === Number.POSITIVE_INFINITY) return 'No expiry';
  if (days < 0) return `${Math.abs(days)} days overdue`;
  if (days === 0) return 'Due today';
  return `${days} days`;
}

function getTokenLocation(token) {
  if (Array.isArray(token?.domains) && token.domains.length > 0) {
    return token.domains[0];
  }
  return (
    token?.location ||
    token?.vendor ||
    token?.used_by ||
    token?.issuer ||
    token?.section ||
    '-'
  );
}

function getTokenOwner(token) {
  return token?.used_by || token?.contacts || token?.vendor || '-';
}

function getTokenProvider(token) {
  return (
    token?.provider ||
    token?.source ||
    token?.source_provider ||
    token?.integration_provider ||
    token?.import_provider ||
    token?.import_source ||
    token?.category ||
    'manual'
  );
}

const DASHBOARD_CATEGORY_VISUALS = {
  cert: {
    icon: BadgeCheck,
    color: '#3b82f6',
    bg: 'rgba(59, 130, 246, 0.14)',
  },
  key_secret: {
    icon: KeyRound,
    color: '#f59e0b',
    bg: 'rgba(245, 158, 11, 0.14)',
  },
  license: {
    icon: LockKeyhole,
    color: '#a855f7',
    bg: 'rgba(168, 85, 247, 0.14)',
  },
  general: {
    icon: Database,
    color: '#22c55e',
    bg: 'rgba(34, 197, 94, 0.14)',
  },
  default: {
    icon: Layers,
    color: '#94a3b8',
    bg: 'rgba(148, 163, 184, 0.14)',
  },
};

const DASHBOARD_SECTION_COLOR_BY_SCHEME = {
  blue: '#3b82f6',
  purple: '#a855f7',
  pink: '#ec4899',
  red: '#ef4444',
  orange: '#f97316',
  yellow: '#eab308',
  green: '#22c55e',
  teal: '#14b8a6',
  cyan: '#06b6d4',
  gray: '#94a3b8',
};

const DASHBOARD_SIDEBAR_STORAGE_KEY = 'tt_dashboard_sidebar_width';
const DASHBOARD_SIDEBAR_WIDTH_CSS_VAR = '--tt-dashboard-sidebar-width';
const DASHBOARD_SIDEBAR_MIN_WIDTH = 56;
const DASHBOARD_SIDEBAR_MAX_WIDTH = 248;
const DASHBOARD_SIDEBAR_LABEL_WIDTH = 136;
const DASHBOARD_SIDEBAR_DEFAULT_WIDTH = DASHBOARD_SIDEBAR_MIN_WIDTH;
const DASHBOARD_PAGE_BG = '#090d15';
const DASHBOARD_SURFACE = '#0d131a';
const DASHBOARD_SURFACE_RAISED = '#0d131a';
const DASHBOARD_BORDER = 'rgba(100, 116, 139, 0.2)';
const DASHBOARD_BORDER_STRONG = 'rgba(148, 163, 184, 0.28)';
const DASHBOARD_MUTED_TEXT = 'rgba(148, 163, 184, 0.92)';
const ASSET_PAGE_SIZE_OPTIONS = [5, 10, 20, 50, 100];

function clampDashboardSidebarWidth(value) {
  const width = Number(value);
  if (!Number.isFinite(width)) return DASHBOARD_SIDEBAR_DEFAULT_WIDTH;
  return Math.min(
    DASHBOARD_SIDEBAR_MAX_WIDTH,
    Math.max(DASHBOARD_SIDEBAR_MIN_WIDTH, Math.round(width))
  );
}

function getInitialDashboardSidebarWidth() {
  try {
    return clampDashboardSidebarWidth(
      window.localStorage.getItem(DASHBOARD_SIDEBAR_STORAGE_KEY)
    );
  } catch (_) {
    return DASHBOARD_SIDEBAR_DEFAULT_WIDTH;
  }
}

function getCategoryVisual(categoryValue) {
  return (
    DASHBOARD_CATEGORY_VISUALS[categoryValue] ||
    DASHBOARD_CATEGORY_VISUALS.default
  );
}

function getSectionAccent(section) {
  return (
    DASHBOARD_SECTION_COLOR_BY_SCHEME[section?.scheme] ||
    DASHBOARD_SECTION_COLOR_BY_SCHEME.gray
  );
}

function formatDashboardPercent(count, total) {
  if (!total) return '0.0%';
  return `${((count / total) * 100).toFixed(1)}%`;
}

function DashboardPanel({ title, action, children, ...props }) {
  return (
    <Box
      bg={DASHBOARD_SURFACE}
      border='1px solid'
      borderColor={DASHBOARD_BORDER}
      borderRadius='md'
      boxShadow='0 16px 48px rgba(0, 0, 0, 0.2)'
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
          borderColor='rgba(148, 163, 184, 0.13)'
        >
          <Text color='white' fontWeight='semibold' fontSize='sm'>
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
  return (
    <Box
      bg={DASHBOARD_SURFACE_RAISED}
      border='1px solid'
      borderColor={DASHBOARD_BORDER}
      borderRadius='md'
      p={4}
      minH='84px'
      boxShadow='0 14px 42px rgba(0, 0, 0, 0.18)'
    >
      <HStack align='center' spacing={3}>
        <Circle size='38px' bg={`${accent}22`} color={accent} flex='0 0 auto'>
          <Icon size={19} strokeWidth={2} />
        </Circle>
        <Box minW={0}>
          <Text color='rgba(226, 232, 240, 0.86)' fontSize='sm' lineHeight='1.25'>
            {label}
          </Text>
          <Text color='white' fontSize='2xl' fontWeight='bold' lineHeight='1.1'>
            {value}
          </Text>
          <Text color='rgba(148, 163, 184, 0.88)' fontSize='xs' mt={1}>
            {detail}
          </Text>
        </Box>
      </HStack>
    </Box>
  );
}

// Helper component for displaying text with tooltip
// Using shared TruncatedText component from ./components/TruncatedText

// TokenDetailModal has been extracted to ./components/TokenDetailModal.jsx

/**
 * Light mode background overlay component
 * Renders only in light mode, returns null in dark mode
 */
function LightModeOverlay() {
  const { colorMode } = useColorMode();

  if (colorMode !== 'light') {
    return null;
  }

  return (
    <Box
      position='fixed'
      top={0}
      left={0}
      right={0}
      bottom={0}
      bg='rgba(255, 255, 255, 0.75)'
      pointerEvents='none'
      zIndex={0}
    />
  );
}

/**
 * Main App Component
 */
function App() {
  const location = useLocation();
  const navigate = useNavigate();
  const [session, setSession] = useState(null);
  const isPublicPath = useCallback(p => {
    try {
      const PUBLIC = ['/'];
      return PUBLIC.some(v => p === v || (v !== '/' && p.startsWith(v)));
    } catch (_) {
      return false;
    }
  }, []);
  const [loading, setLoading] = useState(() => {
    try {
      const path =
        (typeof window !== 'undefined' &&
          window.location &&
          window.location.pathname) ||
        '';
      return !isPublicPath(path);
    } catch (_) {
      return true;
    }
  });
  const isDev =
    typeof import.meta !== 'undefined' &&
    import.meta.env &&
    import.meta.env.DEV;

  // NOTE: App does not consume WorkspaceContext directly; it reads the URL param
  // and children inside <WorkspaceProvider> manage the soft-reload behavior.

  // Token manager (stored in database)
  const [tokens, setTokens] = useState([]);
  const [tokensLoading, _setTokensLoading] = useState(false);
  const [tokensReloadTick, setTokensReloadTick] = useState(0);
  const [tokenFacets, _setTokenFacets] = useState({ category: [] });
  const [globalFacets, setGlobalFacets] = useState({ category: [] });
  const [isRefreshing, setIsRefreshing] = useState(false);
  // Per-category pagination state
  const [categoryOffsets, setCategoryOffsets] = useState({}); // { [category]: number }
  const [categoryHasMore, setCategoryHasMore] = useState({}); // { [category]: boolean }
  const [categoryLoading, setCategoryLoading] = useState({}); // { [category]: boolean }
  const [categoryCounts, setCategoryCounts] = useState({}); // { [category]: number }
  const [limit] = useState(500);
  const [_offset, setOffset] = useState(0);
  const [searchQuery, setSearchQuery] = useState('');
  const [debouncedQuery, setDebouncedQuery] = useState('');
  const [selectedCategories, setSelectedCategories] = useState([]); // array of values
  const [serverSort, setServerSort] = useState('expiration_asc');

  // Welcome modal state for new users
  const [showWelcomeModal, setShowWelcomeModal] = useState(false);
  const [welcomeData, setWelcomeData] = useState({
    userEmail: '',
    userName: '',
    isNewUser: false,
  });
  // Product tour state
  const [showProductTour, setShowProductTour] = useState(false);
  const [tourType, setTourType] = useState('dashboard');
  const [forceRunTour, setForceRunTour] = useState(false);

  // Token detail modal state
  const [selectedToken, setSelectedToken] = useState(null);

  // Per-category sort configurations (default to expiration ascending)
  const [sortConfigs, setSortConfigs] = useState(() =>
    TOKEN_CATEGORIES.reduce((acc, category) => {
      acc[category.value] = { key: 'expiresAt', direction: 'asc' };
      return acc;
    }, {})
  );

  // Keep per-panel sort in sync with global serverSort selection
  useEffect(() => {
    const mapGlobalToPanel = sortValue => {
      switch (sortValue) {
        case 'expiration_asc':
          return { key: 'expiresAt', direction: 'asc' };
        case 'expiration_desc':
          return { key: 'expiresAt', direction: 'desc' };
        case 'name_asc':
          return { key: 'name', direction: 'asc' };
        case 'last_used_desc':
          return { key: 'last_used', direction: 'desc' };
        case 'last_used_asc':
          return { key: 'last_used', direction: 'asc' };
        case 'imported_desc':
          return { key: 'imported_at', direction: 'desc' };
        case 'imported_asc':
          return { key: 'imported_at', direction: 'asc' };
        // Default to expiration ascending (closest to expiry first)
        default:
          return { key: 'expiresAt', direction: 'asc' };
      }
    };

    const next = mapGlobalToPanel(serverSort);
    setSortConfigs(_prev =>
      TOKEN_CATEGORIES.reduce((acc, category) => {
        acc[category.value] = next;
        return acc;
      }, {})
    );
  }, [serverSort]);

  // Deletion confirmation modal
  const {
    isOpen: isDeleteModalOpen,
    onOpen: onDeleteModalOpen,
    onClose: onDeleteModalClose,
  } = useDisclosure();
  const [tokenToDelete, setTokenToDelete] = useState(null);

  // Renew token modal
  const {
    isOpen: isRenewModalOpen,
    onOpen: onRenewModalOpen,
    onClose: onRenewModalClose,
  } = useDisclosure();
  const [tokenToRenew, setTokenToRenew] = useState(null);
  const [renewDate, setRenewDate] = useState('');
  const [renewErrors, setRenewErrors] = useState({});
  const [isRenewSubmitting, setIsRenewSubmitting] = useState(false);

  // Function to calculate default expiration date based on category and type
  const calculateDefaultExpiration = (category, type) => {
    const date = new Date();

    // Default to 90 days for security
    let daysToAdd = 90;

    if (category === 'key_secret') {
      switch (type) {
        case 'api_key':
        case 'ssh_key':
          daysToAdd = 365; // 1 year
          break;
        case 'password':
        case 'secret':
        case 'encryption_key':
          daysToAdd = 90; // 90 days
          break;
      }
    } else if (category === 'cert') {
      daysToAdd = 90; // 90 days for certificates
    } else if (category === 'license') {
      daysToAdd = 365; // 1 year for licenses
    } else {
      daysToAdd = 90; // Default for general/other
    }

    date.setDate(date.getDate() + daysToAdd);
    return date.toISOString().split('T')[0];
  };

  // Form state for token creation
  const [formData, setFormData] = useState({
    name: '',
    type: '',
    category: 'general',
    expiresAt: '', // Optional - empty means "never expires"
    section: '',
    domains: '',
    location: '',
    used_by: '',
    contact_group_id: '',
    issuer: '',
    serial_number: '',
    subject: '',
    key_size: '',
    algorithm: '',
    license_type: '',
    vendor: '',
    cost: '',
    renewal_url: '',
    renewal_date: '',
    contacts: '',
    description: '',
    notes: '',
  });

  // Location entries array for dynamic location fields
  const [locationEntries, setLocationEntries] = useState(['']);
  const locationSyncRef = useRef(false);
  const createTokenNotesFlushRef = useRef(() => {});

  // Sync locationEntries when formData.location changes externally (e.g., from import)
  useEffect(() => {
    if (locationSyncRef.current) {
      locationSyncRef.current = false;
      return;
    }
    if (formData.location && formData.location.trim()) {
      const entries = formData.location.split('\n').filter(loc => loc.trim());
      if (entries.length > 0) {
        setLocationEntries(entries);
      }
    } else if (!formData.location) {
      setLocationEntries(['']);
    }
  }, [formData.location]);

  // Helper functions for location entries
  const addLocationEntry = () => {
    setLocationEntries([...locationEntries, '']);
  };

  const removeLocationEntry = index => {
    const newEntries = locationEntries.filter((_, i) => i !== index);
    setLocationEntries(newEntries.length > 0 ? newEntries : ['']);
    // Update formData.location
    locationSyncRef.current = true;
    const joinedLocations = newEntries.filter(loc => loc.trim()).join('\n');
    setFormData(prev => ({ ...prev, location: joinedLocations }));
  };

  const updateLocationEntry = (index, value) => {
    const newEntries = [...locationEntries];
    newEntries[index] = value;
    setLocationEntries(newEntries);
    // Update formData.location by joining all non-empty entries
    locationSyncRef.current = true;
    const joinedLocations = newEntries.filter(loc => loc.trim()).join('\n');
    setFormData(prev => ({ ...prev, location: joinedLocations }));
  };

  // Contact groups for token alert selection (workspace-scoped)
  const [tokenContactGroups, setTokenContactGroups] = useState([]);
  const [defaultContactGroupId, setDefaultContactGroupId] = useState('');
  // Workspace contacts (from Preferences) for suggestions in token forms
  const [workspaceContacts, setWorkspaceContacts] = useState([]);

  // Form validation state
  const [formErrors, setFormErrors] = useState({});
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Duplicate token confirmation state
  const [duplicateTokenInfo, setDuplicateTokenInfo] = useState(null);
  const {
    isOpen: isDuplicateModalOpen,
    onOpen: onDuplicateModalOpen,
    onClose: onDuplicateModalClose,
  } = useDisclosure();

  /**
   * Check user session with retry mechanism
   */
  const isCheckingSessionRef = useRef(false);
  const checkSessionWithRetry = useCallback(
    async (retryCount = 0) => {
      try {
        if (isCheckingSessionRef.current) return;
        isCheckingSessionRef.current = true;
        // Only show global loader for non-public routes to avoid flicker on public pages
        try {
          const path = (window.location && window.location.pathname) || '';
          if (!isPublicPath(path)) setLoading(true);
        } catch (_) {}
        logger.log(`Checking session (attempt ${retryCount + 1})...`);
        const sessionData = await authAPI.getSession();

        if (sessionData && sessionData.loggedIn) {
          logger.log('Session found:', sessionData.user);
          setSession(sessionData.user);
          // Strict privacy: do not identify users

          // Check if this is a new user (first login)
          const urlParams = new URLSearchParams(window.location.search);
          const newUser = urlParams.get('new_user');
          const firstLogin = urlParams.get('first_login');
          const justRegistered = urlParams.get('registered');

          if (
            newUser === 'true' ||
            firstLogin === 'true' ||
            justRegistered === 'true'
          ) {
            setWelcomeData({
              userEmail: sessionData.user.email,
              userName: sessionData.user.displayName,
              isNewUser: true,
            });
            setShowWelcomeModal(true);
          }
        } else {
          logger.log('No session found');
          // No session found, retry with shorter delays for better UX
          const maxRetries = window.location.pathname === '/dashboard' ? 3 : 1;
          if (retryCount < maxRetries) {
            const delay = Math.min(100 + retryCount * 100, 500); // 100ms, 200ms, 300ms, 400ms, 500ms
            if (isDev)
              logger.log(
                `Session not found, retrying in ${delay}ms (attempt ${retryCount + 1}/${maxRetries})`
              );
            setTimeout(() => checkSessionWithRetry(retryCount + 1), delay);
            return;
          }
          // No session found after retries, ensure session is null
          if (isDev)
            logger.log(
              'No session found after retries, setting session to null'
            );
          setSession(null);
        }
      } catch (error) {
        logger.error('Session check failed:', error);
        // On error, retry with shorter delays for better UX
        const maxRetries = window.location.pathname === '/dashboard' ? 3 : 1;
        if (retryCount < maxRetries) {
          const delay = Math.min(100 + retryCount * 100, 500); // 100ms, 200ms, 300ms, 400ms, 500ms
          if (isDev)
            logger.log(
              `Session check error, retrying in ${delay}ms (attempt ${retryCount + 1}/${maxRetries})`
            );
          setTimeout(() => checkSessionWithRetry(retryCount + 1), delay);
          return;
        }
        // On error after retries, ensure session is null so landing page shows
        setSession(null);
      } finally {
        try {
          const path = (window.location && window.location.pathname) || '';
          if (!isPublicPath(path)) setLoading(false);
        } catch (_) {
          setLoading(false);
        }
        isCheckingSessionRef.current = false;
      }
    },
    [isDev, isPublicPath]
  );

  // Fetch tokens for a single category (used for per-panel pagination)
  const fetchTokensForCategory = useCallback(
    async (categoryValue, opts = {}) => {
      const { reset: resetFlag = false, workspaceId: workspaceOverride } =
        opts && typeof opts === 'object' ? opts : {};
      // Prevent concurrent fetches for the same category
      if (categoryLoading?.[categoryValue]) return;
      try {
        setCategoryLoading(prev => ({ ...prev, [categoryValue]: true }));
        if (resetFlag) setIsRefreshing(true);
        const nextOffset = resetFlag
          ? 0
          : Number(categoryOffsets[categoryValue] || 0);
        const urlParams = new URLSearchParams(window.location.search);
        const selectedWorkspaceId =
          workspaceOverride != null && String(workspaceOverride).trim() !== ''
            ? String(workspaceOverride).trim()
            : urlParams.get('workspace') || null;
        const selectedSection = urlParams.get('section') || '__all__';
        const params = {
          limit,
          offset: nextOffset,
          q: debouncedQuery || undefined,
          sort: serverSort,
          category: [categoryValue],
          ...(selectedWorkspaceId ? { workspace_id: selectedWorkspaceId } : {}),
          ...(selectedSection && selectedSection !== '__all__'
            ? { section: selectedSection }
            : {}),
        };
        const {
          items,
          total,
          facets: _facets,
        } = await tokenAPI.getTokens(params);
        const applyResults =
          workspaceOverride != null && String(workspaceOverride).trim() !== ''
            ? true
            : (() => {
                const currentWs =
                  new URLSearchParams(window.location.search).get(
                    'workspace'
                  ) || null;
                return currentWs === selectedWorkspaceId;
              })();
        if (applyResults) {
          setTokens(prev => {
            const byId = new Map(prev.map(t => [t.id, t]));
            (items || []).forEach(it => {
              byId.set(it.id, it);
            });
            return Array.from(byId.values());
          });
          const fetchedCount = items?.length || 0;
          const newOffset = nextOffset + fetchedCount;
          setCategoryOffsets(prev => ({ ...prev, [categoryValue]: newOffset }));
          setCategoryHasMore(prev => ({
            ...prev,
            [categoryValue]: newOffset < (total || 0),
          }));
          setCategoryCounts(prev => ({
            ...prev,
            [categoryValue]: total || 0,
          }));
        }
      } catch (error) {
        logger.error(
          'Failed to fetch tokens for category:',
          categoryValue,
          error
        );
      } finally {
        setCategoryLoading(prev => ({ ...prev, [categoryValue]: false }));
        setTimeout(() => setIsRefreshing(false), 150);
      }
    },
    [categoryOffsets, limit, debouncedQuery, serverSort, categoryLoading]
  );

  // Fetch tokens for a single category from offset 0 (used during initial reset to avoid effect loops)
  const fetchTokensForCategoryReset = useCallback(
    async (categoryValue, opts = {}) => {
      const { workspaceId: workspaceOverride } =
        opts && typeof opts === 'object' ? opts : {};
      if (categoryLoading?.[categoryValue]) return;
      try {
        setCategoryLoading(prev => ({ ...prev, [categoryValue]: true }));
        setIsRefreshing(true);
        const urlParams = new URLSearchParams(window.location.search);
        const selectedWorkspaceId =
          workspaceOverride != null && String(workspaceOverride).trim() !== ''
            ? String(workspaceOverride).trim()
            : urlParams.get('workspace') || null;
        const selectedSection = urlParams.get('section') || '__all__';
        const params = {
          limit,
          offset: 0,
          q: debouncedQuery || undefined,
          sort: serverSort,
          category: [categoryValue],
          ...(selectedWorkspaceId ? { workspace_id: selectedWorkspaceId } : {}),
          ...(selectedSection && selectedSection !== '__all__'
            ? { section: selectedSection }
            : {}),
        };
        const {
          items,
          total,
          facets: _facets,
        } = await tokenAPI.getTokens(params);
        const applyResults =
          workspaceOverride != null && String(workspaceOverride).trim() !== ''
            ? true
            : (() => {
                const currentWs =
                  new URLSearchParams(window.location.search).get(
                    'workspace'
                  ) || null;
                return currentWs === selectedWorkspaceId;
              })();
        if (applyResults) {
          setTokens(prev => {
            const byId = new Map(prev.map(t => [t.id, t]));
            (items || []).forEach(it => {
              byId.set(it.id, it);
            });
            return Array.from(byId.values());
          });
          const fetchedCount = items?.length || 0;
          const newOffset = 0 + fetchedCount;
          setCategoryOffsets(prev => ({ ...prev, [categoryValue]: newOffset }));
          setCategoryHasMore(prev => ({
            ...prev,
            [categoryValue]: newOffset < (total || 0),
          }));
          setCategoryCounts(prev => ({
            ...prev,
            [categoryValue]: total || 0,
          }));
        }
      } catch (error) {
        logger.error(
          'Failed to fetch tokens for category (reset):',
          categoryValue,
          error
        );
      } finally {
        setCategoryLoading(prev => ({ ...prev, [categoryValue]: false }));
        setTimeout(() => setIsRefreshing(false), 150);
      }
    },
    [limit, debouncedQuery, serverSort, categoryLoading]
  );

  // Fetch global facets (all categories) for badge counts
  const fetchGlobalFacets = useCallback(
    async (opts = {}) => {
      try {
        const urlParams = new URLSearchParams(location.search);
        const selectedWorkspaceId =
          opts &&
          opts.workspaceId != null &&
          String(opts.workspaceId).trim() !== ''
            ? String(opts.workspaceId).trim()
            : urlParams.get('workspace') || null;
        // Use opts.section if provided (immediate update), otherwise fallback to URL
        const selectedSection =
          (opts && opts.section) || urlParams.get('section') || '__all__';

        const params = {
          limit: 1,
          offset: 0,
          ...(selectedWorkspaceId ? { workspace_id: selectedWorkspaceId } : {}),
          ...(debouncedQuery ? { q: debouncedQuery } : {}),
          ...(Array.isArray(selectedCategories) && selectedCategories.length > 0
            ? { category: selectedCategories }
            : {}),
          ...(selectedSection && selectedSection !== '__all__'
            ? { section: selectedSection }
            : {}),
          t: Date.now(),
        };

        // Fetch all facets in a single call (backend returns both category and section facets)
        const { facets } = await tokenAPI.getTokens(params);

        const applyFacets =
          opts &&
          opts.workspaceId != null &&
          String(opts.workspaceId).trim() !== ''
            ? true
            : (() => {
                const currentParams = new URLSearchParams(location.search);
                return currentParams.get('workspace') === selectedWorkspaceId;
              })();
        if (applyFacets) {
          setGlobalFacets({
            category: (facets && facets.category) || [],
            section: (facets && facets.section) || [],
          });
        }
      } catch (_) {
        setGlobalFacets(prev =>
          prev && prev.category ? prev : { category: [] }
        );
      }
    },
    [selectedCategories, debouncedQuery, location.search]
  );

  // Debounce global query
  useEffect(() => {
    const t = setTimeout(() => setDebouncedQuery(searchQuery.trim()), 300);
    return () => clearTimeout(t);
  }, [searchQuery]);

  // Restore pending welcome from previous navigation (robust to URL churn)
  useEffect(() => {
    try {
      const pending = localStorage.getItem('tt_welcome_pending');
      if (pending === '1') {
        setShowWelcomeModal(true);
      }
    } catch (_) {}
  }, []);

  // Check session on mount and show welcome promptly when flags are present
  const __didBootstrapSessionRef = useRef(false);
  useEffect(() => {
    if (__didBootstrapSessionRef.current) return;
    __didBootstrapSessionRef.current = true;
    // Check for OAuth redirect parameters
    const urlParams = new URLSearchParams(window.location.search);
    const newUser = urlParams.get('new_user');
    const verificationSuccess = urlParams.get('verification_success');
    const firstLogin = urlParams.get('first_login');

    // If this is a new user from OAuth registration, set welcome data
    if (newUser === 'true') {
      setWelcomeData({
        userEmail: '',
        userName: '',
        isNewUser: true,
      });
      setShowWelcomeModal(true);
      try {
        localStorage.setItem('tt_welcome_pending', '1');
      } catch (_) {}
    }

    // Also show welcome immediately for first email/password login after verification
    if (firstLogin === 'true' && newUser !== 'true') {
      setWelcomeData({
        userEmail: '',
        userName: '',
        isNewUser: true,
      });
      setShowWelcomeModal(true);
      try {
        localStorage.setItem('tt_welcome_pending', '1');
      } catch (_) {}
    }

    // Track sign up completion when arriving from registration flow
    if (newUser === 'true' || verificationSuccess === 'true') {
      try {
        trackEvent('sign_up_completed');
      } catch (_) {}
    }

    // Check session with retry mechanism - add longer delay for registration flow
    const isFromRegistration =
      newUser === 'true' || window.location.pathname === '/dashboard';
    const initialDelay = isFromRegistration ? 500 : 0; // 500ms delay for registration flow

    // Avoid kicking global session loading on public routes to prevent micro flicker

    setTimeout(() => {
      checkSessionWithRetry();
    }, initialDelay);
  }, [checkSessionWithRetry]);

  // Fetch tokens when session is available
  useEffect(() => {
    try {
      const path = (window.location && window.location.pathname) || '';
      const isPublic = [
        '/',
        '/login',
        '/register',
        '/reset-password',
        '/verify-email',
        '/help',
      ].some(p => path === p || (p !== '/' && path.startsWith(p)));
      if (isPublic) setLoading(false);
    } catch (_) {}
  }, [location.pathname, location.search]);
  // Load workspace contact groups for token form selector
  useEffect(() => {
    let cancelled = false;
    // Load when authenticated on non-public routes only
    if (!session) return;
    try {
      const path = (window.location && window.location.pathname) || '';
      const isPublic = [
        '/',
        '/login',
        '/register',
        '/reset-password',
        '/verify-email',
      ].some(p => path === p || (p !== '/' && path.startsWith(p)));
      if (isPublic) return;
    } catch (_) {}
    (async () => {
      try {
        const urlParams = new URLSearchParams(location.search);
        let wsId = urlParams.get('workspace') || null;
        // Fallback: if no workspace query param, prefer admin/manager workspace and persist in URL
        if (!wsId) {
          try {
            const ws = await workspaceAPI.list(100, 0);
            const items = ws?.items || [];
            const preferred =
              items.find(
                w => w.role === 'admin' || w.role === 'workspace_manager'
              ) || items[0];
            if (preferred?.id) {
              wsId = preferred.id;
              // Do not mutate URL here to avoid micro reloads; URL normalization is handled by WorkspaceContext
            }
          } catch (_) {
            wsId = null;
          }
        }
        if (!wsId) {
          if (!cancelled) {
            setTokenContactGroups([]);
            setDefaultContactGroupId('');
          }
          return;
        }
        const res = await workspaceAPI.getAlertSettings(wsId);
        const data = res?.data || res || {};
        if (cancelled) return;
        setTokenContactGroups(
          Array.isArray(data.contact_groups) ? data.contact_groups : []
        );
        setDefaultContactGroupId(String(data.default_contact_group_id || ''));
      } catch (_) {
        if (!cancelled) {
          setTokenContactGroups([]);
          setDefaultContactGroupId('');
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [session, location.search, location.pathname]);

  // Load workspace contacts for token forms and modal suggestions
  useEffect(() => {
    let cancelled = false;
    if (!session) return;
    (async () => {
      try {
        const urlParams = new URLSearchParams(location.search);
        const wsId = urlParams.get('workspace') || null;
        if (!wsId) {
          if (!cancelled) setWorkspaceContacts([]);
          return;
        }
        const contactsRes = await apiClient.get(
          `/api/v1/workspaces/${wsId}/contacts`
        );
        if (cancelled) return;
        setWorkspaceContacts(
          Array.isArray(contactsRes?.data?.items) ? contactsRes.data.items : []
        );
      } catch (_) {
        if (!cancelled) setWorkspaceContacts([]);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [session, location.search]);
  const didInitialLoadRef = useRef('');
  const reloadTimeoutRef = useRef(null);

  useEffect(() => {
    if (!session) return;
    // Only run dashboard reloads on the dashboard route
    try {
      if ((window.location.pathname || '') !== '/dashboard') return;
    } catch (_) {}

    // Debounce rapid reloads to prevent multiple triggers
    if (reloadTimeoutRef.current) {
      clearTimeout(reloadTimeoutRef.current);
    }

    reloadTimeoutRef.current = setTimeout(() => {
      // Avoid duplicate initial loads caused by multiple effects or route churn
      const urlParams = new URLSearchParams(location.search);
      const workspaceId = urlParams.get('workspace') || '';
      const sectionId = urlParams.get('section') || '';

      const key = `${debouncedQuery}::${selectedCategories.join(',')}::${serverSort}::${workspaceId}::${sectionId}::${location.pathname}::${tokensReloadTick}`;
      if (didInitialLoadRef.current === key) return;

      // Detect if workspace changed to decide whether to clear tokens immediately (security/context switch)
      // or keep them for a smooth transition (filter/sort change)
      const prevKey = didInitialLoadRef.current || '';
      const prevWorkspaceId = prevKey.split('::')[3] || '';
      const isWorkspaceSwitch = workspaceId !== prevWorkspaceId;

      didInitialLoadRef.current = key;

      // Reset and load per selected categories (or all if none selected)
      setOffset(0);
      setCategoryOffsets({});
      setCategoryHasMore({});

      if (isWorkspaceSwitch) {
        // Clear existing tokens strictly on workspace switch to avoid seeing stale data from other contexts
        setTokens([]);
        // Also clear facets to prevent showing section labels from the previous workspace
        setGlobalFacets({ category: [], section: [] });
      } else {
        // For filter/sort changes, we keep previous tokens visible for a smoother transition
        // New data will replace old data as it arrives category-by-category
      }

      // Fetch facets in the background; do not block rendering
      try {
        fetchGlobalFacets();
      } catch (_) {}
      const catsToLoad =
        selectedCategories.length > 0
          ? selectedCategories
          : TOKEN_CATEGORIES.map(c => c.value);
      // Load all categories concurrently for faster initial render
      (async () => {
        await Promise.all(
          catsToLoad.map(cat => fetchTokensForCategoryReset(cat))
        );
      })();
    }, 100); // 100ms debounce to coalesce rapid changes

    return () => {
      if (reloadTimeoutRef.current) {
        clearTimeout(reloadTimeoutRef.current);
      }
    };
  }, [
    session,
    debouncedQuery,
    selectedCategories,
    serverSort,
    fetchGlobalFacets,
    fetchTokensForCategoryReset,
    location.search,
    location.pathname,
    tokensReloadTick,
  ]);

  // Listen for token updates from other views (e.g., transfers) and trigger a throttled reload while on dashboard
  useEffect(() => {
    let timerId = null;
    let lastReloadTime = 0;
    const scheduleReloadIfDashboard = () => {
      // Prevent reloads more frequent than 800ms
      const now = Date.now();
      if (now - lastReloadTime < 800) return;

      if (timerId) return; // coalesce multiple events
      timerId = setTimeout(() => {
        lastReloadTime = Date.now();
        setTokensReloadTick(t => t + 1);
        timerId = null;
      }, 350);
    };
    const onTokensUpdated = () => {
      try {
        // Force next dashboard effect pass to reload by clearing dedup key
        didInitialLoadRef.current = '';
      } catch (_) {}
      scheduleReloadIfDashboard();
    };
    try {
      window.addEventListener('tt:tokens-updated', onTokensUpdated);
    } catch (_) {}
    return () => {
      if (timerId)
        try {
          clearTimeout(timerId);
        } catch (_) {}
      try {
        window.removeEventListener('tt:tokens-updated', onTokensUpdated);
      } catch (_) {}
    };
  }, []);

  // Remove redirect behavior on token updates to avoid disrupting the current view

  /**
   * Handle user logout
   */
  const handleLogout = async () => {
    try {
      await authAPI.logout();
      setSession(null);
      setTokens([]);
    } catch (error) {
      logger.error('Logout failed:', error);
    }
  };

  const handleNavigateToLanding = () => {
    navigate('/');
  };

  const handleHelpAccountClick = () => {
    navigate('/dashboard?view=account');
  };

  const handleHelpNavigateToDashboard = () => {
    try {
      const search = new URLSearchParams(window.location.search);
      if (!search.get('workspace')) {
        try {
          const last = localStorage.getItem('tt_last_workspace_id');
          if (last) search.set('workspace', last);
        } catch (_) {}
      }
      const q = search.toString();
      navigate(q ? `/dashboard?${q}` : '/dashboard');
    } catch (_) {
      navigate('/dashboard');
    }
  };

  /**
   * Validate form data
   */
  const validateForm = () => {
    const errors = {};

    // Name validation
    if (!formData.name.trim()) {
      errors.name = 'Name is required';
    } else if (formData.name.trim().length > 100) {
      errors.name = 'Name must be 100 characters or less';
    }

    // Type validation - check if type is valid for selected category
    if (!formData.type) {
      errors.type = 'Type is required';
    } else {
      const selectedCategory = TOKEN_CATEGORIES.find(
        cat => cat.value === formData.category
      );
      if (selectedCategory) {
        const validTypes = selectedCategory.types.map(t => t.value);
        if (!validTypes.includes(formData.type)) {
          errors.type = `Invalid type for ${selectedCategory.label} category`;
        }
      }
    }

    // Category validation
    if (!formData.category) {
      errors.category = 'Category is required';
    }

    // Expiration date validation (optional - empty means "never expires")
    if (formData.expiresAt && formData.expiresAt.trim()) {
      const expDate = new Date(formData.expiresAt);
      const now = new Date();

      if (isNaN(expDate.getTime())) {
        errors.expiresAt = 'Invalid date format';
      } else if (expDate <= now) {
        errors.expiresAt = 'Expiration date must be in the future';
      } else {
        // Check for very far future dates (warn but allow)
        const maxDate = new Date();
        maxDate.setFullYear(maxDate.getFullYear() + 100);
        if (expDate > maxDate) {
          // Show warning but don't block
          // logger.warn('Very far future date selected:', formData.expiresAt);
        }
      }
    }

    // Category-specific validations (optional fields - only validate if provided)
    const selectedCategory = TOKEN_CATEGORIES.find(
      cat => cat.value === formData.category
    );
    if (selectedCategory) {
      // Validate domains for certificates (must be valid if provided)
      if (selectedCategory.value === 'cert' && formData.domains.trim()) {
        const domains = formData.domains
          .split(',')
          .map(d => d.trim())
          .filter(d => d);
        if (domains.length === 0) {
          errors.domains = 'Please provide at least one valid domain';
        }
      }

      // Validate cost for licenses (optional but must be valid if provided)
      if (selectedCategory.value === 'license' && formData.cost.trim()) {
        const cost = parseFloat(formData.cost);
        if (isNaN(cost) || cost < 0) {
          errors.cost = 'Cost must be a valid positive number';
        } else if (cost > 999999999999.99) {
          errors.cost = 'Cost must be less than 1 trillion (1,000,000,000,000)';
        }
      }

      // Validate key_size if provided (only for encryption_key, ssh_key, and certificates)
      if (
        formData.key_size.trim() &&
        [
          'encryption_key',
          'ssh_key',
          'ssl_cert',
          'tls_cert',
          'code_signing',
          'client_cert',
        ].includes(formData.type)
      ) {
        const keySize = parseInt(formData.key_size);
        if (isNaN(keySize) || keySize <= 0) {
          errors.key_size = 'Key size must be a valid positive integer';
        }
      }

      // Validate algorithm if provided (only for encryption_key, ssh_key, and certificates)
      if (
        formData.algorithm.trim() &&
        ![
          'encryption_key',
          'ssh_key',
          'ssl_cert',
          'tls_cert',
          'code_signing',
          'client_cert',
        ].includes(formData.type)
      ) {
        errors.algorithm =
          'Algorithm is only valid for encryption keys, SSH keys, and certificates';
      }
    }

    setFormErrors(errors);
    return Object.keys(errors).length === 0;
  };

  /**
   * Handle form input changes
   */
  const handleInputChange = e => {
    const { name, value } = e.target;

    // If category changes, reset type to empty (don't auto-set expiration)
    if (name === 'category') {
      setFormData(prev => ({
        ...prev,
        [name]: value,
        type: '', // Reset type when category changes
        // Keep expiration as-is (user can set it manually if needed)
      }));
    } else {
      setFormData(prev => ({
        ...prev,
        [name]: value,
      }));
    }

    // Clear error when user starts typing
    if (formErrors[name]) {
      setFormErrors(prev => ({
        ...prev,
        [name]: '',
      }));
    }
  };

  /**
   * Handle token creation
   */
  const handleTokenAdd = async e => {
    e.preventDefault();
    flushSync(() => {
      createTokenNotesFlushRef.current();
    });

    if (!validateForm()) {
      return;
    }

    try {
      setIsSubmitting(true);

      // Prepare domains array if provided
      let domainsArray = null;
      if (formData.domains.trim()) {
        domainsArray = formData.domains
          .split(',')
          .map(d => d.trim())
          .filter(d => d);
      }

      // Prepare cost value if provided
      let costValue = null;
      if (formData.cost.trim()) {
        costValue = parseFloat(formData.cost);
      }

      // Prepare key_size value if provided
      let keySizeValue = null;
      if (formData.key_size.trim()) {
        keySizeValue = parseInt(formData.key_size);
      }

      // Prepare section array if provided
      let sectionArray = null;
      if (formData.section.trim()) {
        sectionArray = formData.section
          .split(',')
          .map(s => s.trim())
          .filter(s => s);
      }

      const urlParams = new URLSearchParams(window.location.search);
      let selectedWorkspaceId = urlParams.get('workspace') || null;
      if (!selectedWorkspaceId) {
        try {
          const ws = await workspaceAPI.list(100, 0);
          const items = ws?.items || [];
          const preferred =
            items.find(
              w => w.role === 'admin' || w.role === 'workspace_manager'
            ) || items[0];
          if (preferred?.id) {
            selectedWorkspaceId = preferred.id;
            // Persist selection into URL for subsequent operations
            const search = new URLSearchParams(window.location.search);
            search.set('workspace', selectedWorkspaceId);
            const newUrl = `${window.location.pathname}?${search.toString()}${window.location.hash || ''}`;
            window.history.replaceState(null, '', newUrl);
          }
        } catch (_) {
          /* no-op */
        }
      }
      // If expiration date is empty, set it to "never expires" (2099-12-31)
      const expirationDate =
        formData.expiresAt && formData.expiresAt.trim()
          ? formData.expiresAt
          : NEVER_EXPIRES_DATE_VALUE;

      const newToken = await tokenAPI.createToken({
        name: formData.name.trim(),
        type: formData.type,
        category: formData.category,
        expiresAt: expirationDate,
        workspace_id: selectedWorkspaceId,
        section: sectionArray,
        domains: domainsArray,
        location: formData.location.trim() || null,
        used_by: formData.used_by.trim() || null,
        contact_group_id:
          !isViewer && formData.contact_group_id
            ? formData.contact_group_id
            : null,
        issuer: formData.issuer.trim() || null,
        serial_number: formData.serial_number.trim() || null,
        subject: formData.subject.trim() || null,
        key_size: keySizeValue,
        algorithm: formData.algorithm.trim() || null,
        license_type: formData.license_type.trim() || null,
        vendor: formData.vendor.trim() || null,
        cost: costValue,
        renewal_url: formData.renewal_url.trim() || null,
        renewal_date: formData.renewal_date.trim() || null,
        contacts: formData.contacts.trim() || null,
        description: formData.description.trim() || null,
        notes: formData.notes.trim() || null,
      });

      // Add to local state
      setTokens(prev => [...prev, newToken]);

      // Refresh global facets so new sections appear immediately
      try {
        await fetchGlobalFacets({ section: '__all__' });
      } catch (_) {}

      // Track analytics event
      try {
        trackEvent('token_created', {
          category: newToken.category,
          type: newToken.type,
          has_domains:
            Array.isArray(newToken.domains) && newToken.domains.length > 0
              ? 'yes'
              : 'no',
        });
      } catch (_) {}

      // Reset form
      setFormData({
        name: '',
        type: '',
        category: 'general',
        expiresAt: '', // Optional - empty means "never expires"
        section: '',
        domains: '',
        location: '',
        used_by: '',
        issuer: '',
        serial_number: '',
        subject: '',
        key_size: '',
        algorithm: '',
        license_type: '',
        vendor: '',
        cost: '',
        renewal_url: '',
        renewal_date: '',
        contacts: '',
        description: '',
        notes: '',
      });
      setLocationEntries(['']);

      setFormErrors({});
    } catch (error) {
      // Check if it's a duplicate token error
      if (error.code === 'DUPLICATE_TOKEN' && error.existing_token) {
        setDuplicateTokenInfo(error);
        onDuplicateModalOpen();
        setIsSubmitting(false);
        return;
      }
      logger.error('Failed to create token:', error);
      setFormErrors({ submit: error.message || 'Failed to create token' });
    } finally {
      setIsSubmitting(false);
    }
  };

  // Handle duplicate token confirmation
  const handleConfirmDuplicate = async () => {
    if (!duplicateTokenInfo) return;

    try {
      setIsSubmitting(true);
      onDuplicateModalClose();
      flushSync(() => {
        createTokenNotesFlushRef.current();
      });

      // Prepare token data again (same as in handleTokenAdd)
      let domainsArray = null;
      if (formData.domains.trim()) {
        domainsArray = formData.domains
          .split(',')
          .map(d => d.trim())
          .filter(d => d);
      }
      let costValue = null;
      if (formData.cost.trim()) {
        costValue = parseFloat(formData.cost);
      }
      let keySizeValue = null;
      if (formData.key_size.trim()) {
        keySizeValue = parseInt(formData.key_size);
      }
      const urlParams = new URLSearchParams(window.location.search);
      let selectedWorkspaceId = urlParams.get('workspace') || null;
      if (!selectedWorkspaceId) {
        try {
          const ws = await workspaceAPI.list(100, 0);
          const items = ws?.items || [];
          const preferred =
            items.find(
              w => w.role === 'admin' || w.role === 'workspace_manager'
            ) || items[0];
          if (preferred?.id) {
            selectedWorkspaceId = preferred.id;
            const search = new URLSearchParams(window.location.search);
            search.set('workspace', selectedWorkspaceId);
            const newUrl = `${window.location.pathname}?${search.toString()}${window.location.hash || ''}`;
            window.history.replaceState(null, '', newUrl);
          }
        } catch (_) {
          setFormErrors({ submit: 'Please select a workspace first.' });
          setIsSubmitting(false);
          return;
        }
      }
      const expirationDate =
        formData.expiresAt && formData.expiresAt.trim()
          ? formData.expiresAt
          : NEVER_EXPIRES_DATE_VALUE;

      // Prepare section array if provided
      let sectionArray = null;
      if (formData.section.trim()) {
        sectionArray = formData.section
          .split(',')
          .map(s => s.trim())
          .filter(s => s);
      }

      const updatedToken = await tokenAPI.createToken(
        {
          name: formData.name.trim(),
          type: formData.type,
          category: formData.category,
          expiresAt: expirationDate,
          workspace_id: selectedWorkspaceId,
          section: sectionArray,
          domains: domainsArray,
          location: formData.location.trim() || null,
          used_by: formData.used_by.trim() || null,
          contact_group_id:
            !isViewer && formData.contact_group_id
              ? formData.contact_group_id
              : null,
          issuer: formData.issuer.trim() || null,
          serial_number: formData.serial_number.trim() || null,
          subject: formData.subject.trim() || null,
          key_size: keySizeValue,
          algorithm: formData.algorithm.trim() || null,
          license_type: formData.license_type.trim() || null,
          vendor: formData.vendor.trim() || null,
          cost: costValue,
          renewal_url: formData.renewal_url.trim() || null,
          renewal_date: formData.renewal_date.trim() || null,
          contacts: formData.contacts.trim() || null,
          description: formData.description.trim() || null,
          notes: formData.notes.trim() || null,
          confirm_duplicate: true,
        },
        true
      );

      // Update token in local state if it exists
      setTokens(prev => {
        const existingIndex = prev.findIndex(t => t.id === updatedToken.id);
        if (existingIndex >= 0) {
          const updated = [...prev];
          updated[existingIndex] = updatedToken;
          return updated;
        }
        return [...prev, updatedToken];
      });

      // Refresh global facets
      try {
        await fetchGlobalFacets({ section: '__all__' });
      } catch (_) {}

      // Reset form
      setFormData({
        name: '',
        type: '',
        category: 'general',
        expiresAt: '',
        section: '',
        domains: '',
        location: '',
        used_by: '',
        issuer: '',
        serial_number: '',
        subject: '',
        key_size: '',
        algorithm: '',
        license_type: '',
        vendor: '',
        cost: '',
        renewal_url: '',
        renewal_date: '',
        contacts: '',
        description: '',
        notes: '',
      });
      setLocationEntries(['']);
      setFormErrors({});
      setDuplicateTokenInfo(null);
    } catch (error) {
      logger.error('Failed to update token:', error);
      setFormErrors({ submit: error.message || 'Failed to update token' });
    } finally {
      setIsSubmitting(false);
    }
  };

  // Determine whether the current user can create tokens in the selected workspace (admin or manager only)
  const [_canCreateToken, setCanCreateToken] = useState(true);
  const [isViewer, setIsViewer] = useState(false);
  const [_workspaceMetaLoaded, setWorkspaceMetaLoaded] = useState(false);
  useEffect(() => {
    (async () => {
      try {
        let allowed = true;
        const urlParams = new URLSearchParams(window.location.search);
        const selectedWorkspaceId = urlParams.get('workspace') || null;
        if (selectedWorkspaceId) {
          try {
            const ws = await workspaceAPI.get(selectedWorkspaceId);
            const role = String(ws?.role || '').toLowerCase();
            allowed = role === 'admin' || role === 'workspace_manager';
            setIsViewer(role === 'viewer');
          } catch (_) {
            allowed = true;
            setIsViewer(false);
          }
        } else {
          // No workspace in URL (e.g. first login) - check highest role across all workspaces
          try {
            const ws = await workspaceAPI.list(50, 0);
            const items = ws?.items || [];
            const roles = items.map(w => String(w.role || '').toLowerCase());
            const hasManagerOrAdmin =
              roles.includes('admin') || roles.includes('workspace_manager');
            allowed = hasManagerOrAdmin;
            setIsViewer(items.length > 0 && !hasManagerOrAdmin);
          } catch (_) {
            allowed = true;
            setIsViewer(false);
          }
        }
        setCanCreateToken(allowed);
      } catch (_) {
        setCanCreateToken(true);
        setIsViewer(false);
      }
      setWorkspaceMetaLoaded(true);
    })();
  }, [location.search, session?.id]);

  /**
   * Auto-open token detail modal from URL parameter (deep linking)
   * Simpler approach: load all categories when token-id is present
   */
  const hasOpenedFromUrl = useRef(false);
  const hasTriggeredLoad = useRef(false);

  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const tokenIdParam = params.get('token-id');

    logger.info('[Deep Link Debug] Effect running', {
      tokenIdParam,
      hasOpenedFromUrl: hasOpenedFromUrl.current,
      hasTriggeredLoad: hasTriggeredLoad.current,
      tokensCount: tokens.length,
      selectedToken: selectedToken?.id,
    });

    // Reset flags when URL changes or modal is closed
    if (!tokenIdParam) {
      hasOpenedFromUrl.current = false;
      hasTriggeredLoad.current = false;
      return;
    }

    if (tokenIdParam && !hasOpenedFromUrl.current) {
      const tokenId = parseInt(tokenIdParam, 10);
      if (isNaN(tokenId)) {
        logger.error(
          '[Deep Link] ❌ Invalid token ID:',
          tokenIdParam,
          '- must be a numeric ID (e.g., 1, 123)'
        );
        hasOpenedFromUrl.current = true; // Prevent retrying
        return;
      }

      logger.info(
        '[Deep Link] Looking for token:',
        tokenId,
        'in',
        tokens.length,
        'tokens'
      );

      // Try to find token in existing state
      const existingToken = tokens.find(t => t.id === tokenId);
      if (existingToken) {
        logger.info(
          '[Deep Link] ✅ Found token, opening modal:',
          existingToken
        );
        setSelectedToken(existingToken);
        hasOpenedFromUrl.current = true;
      } else if (!hasTriggeredLoad.current) {
        // Load all categories to ensure token is fetched
        logger.info('[Deep Link] 📥 Token not found, loading all categories');
        hasTriggeredLoad.current = true;
        TOKEN_CATEGORIES.forEach(cat => {
          logger.info('[Deep Link] Loading category:', cat.value);
          fetchTokensForCategoryReset(cat.value);
        });
      } else {
        logger.info(
          '[Deep Link] ⏳ Waiting for tokens to load... (triggered, not opened yet)'
        );
      }
    }
  }, [location.search, tokens, selectedToken, fetchTokensForCategoryReset]);

  /**
   * Handle token deletion - open confirmation modal
   */
  const handleDeleteToken = id => {
    const token = tokens.find(t => t.id === id);
    setTokenToDelete(token);
    // Close token detail panel immediately for better UX when deleting from within it
    if (selectedToken && selectedToken.id === id) {
      handleCloseTokenModal();
    }
    onDeleteModalOpen();
  };

  // Open renew modal with default date based on category/type
  const handleOpenRenew = token => {
    setTokenToRenew(token);
    const defaultDate = calculateDefaultExpiration(
      token.category,
      token.type || ''
    );
    setRenewDate(defaultDate);
    setRenewErrors({});
    onRenewModalOpen();
  };

  const handleCloseRenew = () => {
    setTokenToRenew(null);
    setRenewDate('');
    setRenewErrors({});
    onRenewModalClose();
  };

  const handleConfirmRenew = async () => {
    if (!tokenToRenew) return;
    const errors = {};
    if (!renewDate) {
      errors.renewDate = 'Expiration date is required';
    } else {
      const d = new Date(renewDate);
      if (isNaN(d.getTime())) {
        errors.renewDate = 'Invalid date format';
      } else if (d <= new Date()) {
        errors.renewDate = 'Expiration date must be in the future';
      }
    }
    setRenewErrors(errors);
    if (Object.keys(errors).length > 0) return;

    try {
      setIsRenewSubmitting(true);
      const updated = await tokenAPI.updateToken(tokenToRenew.id, {
        expiresAt: renewDate,
      });
      setTokens(prev => prev.map(t => (t.id === updated.id ? updated : t)));
      if (selectedToken && selectedToken.id === updated.id) {
        setSelectedToken(updated);
      }
      try {
        trackEvent('token_renewed', {
          category: tokenToRenew.category,
          type: tokenToRenew.type,
        });
      } catch (_) {}
      handleCloseRenew();
    } catch (e) {
      logger.error('Failed to renew token:', e);
    } finally {
      setIsRenewSubmitting(false);
    }
  };

  /**
   * Confirm and execute token deletion
   */
  const confirmDeleteToken = async () => {
    if (!tokenToDelete) return;
    try {
      await tokenAPI.deleteToken(tokenToDelete.id);
      const deleted = tokenToDelete;
      setTokens(prev => prev.filter(token => token.id !== deleted.id));
      // Opportunistically remove empty section facet when last token of that section is deleted
      try {
        const remainingInSection = (prev =>
          prev.filter(t => {
            const norm = v =>
              String(v || '')
                .trim()
                .toLowerCase();
            return (
              !(t.id === deleted.id) &&
              norm(t.section) === norm(deleted.section)
            );
          }))(tokens);
        if (remainingInSection.length === 0) {
          setGlobalFacets(prev => ({
            ...prev,
            section: (prev?.section || []).filter(r => {
              const norm = v =>
                String(v || '')
                  .trim()
                  .toLowerCase();
              return norm(r.section) !== norm(deleted.section || '');
            }),
          }));
        }
      } catch (_) {}
      // Decrement category count so category chips update immediately
      try {
        setCategoryCounts(prev => ({
          ...prev,
          [deleted.category]: Math.max(0, (prev?.[deleted.category] || 0) - 1),
        }));
      } catch (_) {}
      // Refresh global facets so section chips/counts reflect deletion
      try {
        await fetchGlobalFacets();
      } catch (_) {}
      try {
        trackEvent('token_deleted', {
          category: deleted.category,
          type: deleted.type,
        });
      } catch (_) {}
      onDeleteModalClose();
      setTokenToDelete(null);
    } catch (error) {
      logger.error('Failed to delete token:', error);
    }
  };

  /**
   * Cancel token deletion
   */
  const cancelDeleteToken = () => {
    setTokenToDelete(null);
    onDeleteModalClose();
  };

  /**
   * Filter and sort tokens
   * Memoized with useCallback to prevent unnecessary re-renders
   */
  const getFilteredAndSortedTokens = useCallback(
    (tokens, category, searchTerm = '', sectionParam = '__all__') => {
      // First filter by category
      let filteredTokens = tokens.filter(
        token => token.category === category.value
      );

      // Apply section filter (from URL/panelQueries)
      if (sectionParam && sectionParam !== '__all__') {
        if (sectionParam === '__none__') {
          filteredTokens = filteredTokens.filter(
            t =>
              !t.section ||
              (Array.isArray(t.section) && t.section.length === 0) ||
              String(t.section).trim() === ''
          );
        } else {
          const norm = v =>
            String(v || '')
              .trim()
              .toLowerCase();
          // Support multi-select: split by comma
          const wantedList = String(sectionParam)
            .split(',')
            .map(s => norm(s))
            .filter(Boolean);

          filteredTokens = filteredTokens.filter(t => {
            const tokenSections = Array.isArray(t.section)
              ? t.section.map(s => norm(s))
              : [norm(t.section)];

            // Match if ALL of the selected sections are present in the token (AND logic)
            return wantedList.every(w => tokenSections.includes(w));
          });
        }
      }

      // Apply per-panel search term across common fields
      if (searchTerm) {
        const q = String(searchTerm).toLowerCase();
        filteredTokens = filteredTokens.filter(token => {
          const fields = [
            token.name,
            token.type,
            token.vendor,
            token.license_type,
            token.issuer,
            token.location,
            token.used_by,
            token.description,
            token.subject,
            token.serial_number,
            token.privileges,
          ];
          if (Array.isArray(token.domains))
            fields.push(token.domains.join(', '));
          if (Array.isArray(token.section))
            fields.push(token.section.join(', '));
          return fields.some(v =>
            v ? String(v).toLowerCase().includes(q) : false
          );
        });
      }

      // Apply per-category sorting
      const panelSort = sortConfigs[category.value];
      if (panelSort && panelSort.key) {
        filteredTokens.sort((a, b) => {
          let aVal = a[panelSort.key];
          let bVal = b[panelSort.key];

          // Special handling for dates
          const dateFields = [
            'expiresAt',
            'created_at',
            'imported_at',
            'last_used',
            'updated_at',
          ];
          if (dateFields.includes(panelSort.key)) {
            const normDate = v =>
              !v || String(v) === 'N/A' ? new Date(0) : new Date(v);
            aVal = normDate(aVal);
            bVal = normDate(bVal);
          } else if (Array.isArray(aVal)) {
            aVal = aVal.join(', ');
          } else if (Array.isArray(bVal)) {
            bVal = bVal.join(', ');
          }

          // Convert to strings for comparison if not dates
          if (!(aVal instanceof Date)) {
            aVal = String(aVal || '').toLowerCase();
            bVal = String(bVal || '').toLowerCase();
          }

          if (aVal < bVal) return panelSort.direction === 'asc' ? -1 : 1;
          if (aVal > bVal) return panelSort.direction === 'asc' ? 1 : -1;
          return 0;
        });
      }

      return filteredTokens;
    },
    [sortConfigs]
  );

  /**
   * Handle account deletion
   */
  const handleAccountDeleted = () => {
    setSession(null);
    setTokens([]);
  };

  /**
   * Handle opening token detail modal
   */
  const handleOpenTokenModal = token => {
    setSelectedToken(token);
    // Add token ID to URL for shareable links
    const search = new URLSearchParams(window.location.search);
    search.set('token-id', token.id);
    navigate(`?${search.toString()}`, { replace: true });
  };

  /**
   * Handle closing token detail modal
   */
  const handleCloseTokenModal = () => {
    setSelectedToken(null);
    // Remove token ID from URL
    const search = new URLSearchParams(window.location.search);
    search.delete('token-id');
    navigate(`?${search.toString()}`, { replace: true });
  };

  // Move useColorModeValue calls outside of conditional rendering
  const deleteBoxBg = useColorModeValue('gray.100', 'gray.700');
  const deleteTextColor = useColorModeValue('gray.700', 'gray.200');
  const deleteLabelColor = useColorModeValue('gray.800', 'gray.100');
  const renewBoxBg = useColorModeValue('gray.100', 'gray.700');
  const renewTextColor = useColorModeValue('gray.700', 'gray.200');
  const renewLabelColor = useColorModeValue('gray.800', 'gray.100');
  const _renewHelperTextColor = useColorModeValue('gray.600', 'gray.100');

  return (
    <ChakraProvider theme={theme}>
      <ColorModeScript initialColorMode={theme.config.initialColorMode} />
      <HelmetProvider>
        <ErrorBoundary>
          {/* Global background overlay - light mode only */}
          <LightModeOverlay />

          <Box
            minH='100vh'
            display='flex'
            flexDirection='column'
            position='relative'
            zIndex={1}
            w='100%'
            maxW='100%'
            overflowX='hidden'
          >
            <Box flex='1'>
              {loading &&
              ![
                '/login',
                '/register',
                '/reset-password',
                '/verify-email',
              ].includes(location.pathname) ? (
                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'center',
                    alignItems: 'center',
                    height: '100%',
                  }}
                >
                  <AccessibleSpinner
                    size='lg'
                    aria-label='Loading application'
                  />
                </div>
              ) : (
                <WorkspaceProvider>
                  <Suspense
                    fallback={
                      <Flex align='center' justify='center' minH='60vh'>
                        <AccessibleSpinner label='Loading content…' />
                      </Flex>
                    }
                  >
                    <Routes>
                      <Route
                        path='/'
                        element={<Navigate to='/login' replace />}
                      />
                      <Route
                        path='/login'
                        element={
                          session ? (
                            session.needsVerification ? (
                              <Navigate
                                to={`/verify-email?email=${encodeURIComponent(
                                  session.email || ''
                                )}`}
                                replace
                              />
                            ) : (
                              <Navigate to='/dashboard' replace />
                            )
                          ) : (
                            <Login />
                          )
                        }
                      />

                      <Route
                        path='/register'
                        element={
                          session ? (
                            session.needsVerification ? (
                              <Navigate
                                to={`/verify-email?email=${encodeURIComponent(
                                  session.email || ''
                                )}`}
                                replace
                              />
                            ) : (
                              <Navigate to='/dashboard' replace />
                            )
                          ) : (
                            <Register />
                          )
                        }
                      />
                      <Route
                        path='/verify-email'
                        element={<VerifyEmailWrapper session={session} />}
                      />
                      <Route
                        path='/reset-password'
                        element={
                          session ? (
                            <Navigate to='/dashboard' replace />
                          ) : (
                            <ResetPassword />
                          )
                        }
                      />
                      <Route
                        path='/preferences'
                        element={
                          <RequireManagerRoute session={session}>
                            {session?.needsVerification ? (
                              <Navigate
                                to={`/verify-email?email=${encodeURIComponent(
                                  session?.email || ''
                                )}`}
                                replace
                              />
                            ) : (
                              <AlertPreferences
                                session={session}
                                showProductTour={showProductTour}
                                onLogout={handleLogout}
                                onAccountClick={handleHelpAccountClick}
                                onNavigateToDashboard={
                                  handleHelpNavigateToDashboard
                                }
                                onNavigateToLanding={handleNavigateToLanding}
                              />
                            )}
                          </RequireManagerRoute>
                        }
                      />
                      <Route
                        path='/usage'
                        element={
                          <RequireManagerRoute session={session}>
                            <Usage
                              session={session}
                              onLogout={handleLogout}
                              onAccountClick={handleHelpAccountClick}
                              onNavigateToDashboard={
                                handleHelpNavigateToDashboard
                              }
                              onNavigateToLanding={handleNavigateToLanding}
                            />
                          </RequireManagerRoute>
                        }
                      />
                      <Route
                        path='/workspaces'
                        element={
                          <RequireManagerRoute session={session}>
                            <Workspaces
                              session={session}
                              onLogout={handleLogout}
                              onAccountClick={handleHelpAccountClick}
                              onNavigateToDashboard={
                                handleHelpNavigateToDashboard
                              }
                              onNavigateToLanding={handleNavigateToLanding}
                            />
                          </RequireManagerRoute>
                        }
                      />
                      <Route
                        path='/audit'
                        element={
                          <RequireManagerRoute session={session}>
                            <Audit
                              session={session}
                              onLogout={handleLogout}
                              onAccountClick={handleHelpAccountClick}
                              onNavigateToDashboard={
                                handleHelpNavigateToDashboard
                              }
                              onNavigateToLanding={handleNavigateToLanding}
                            />
                          </RequireManagerRoute>
                        }
                      />
                      <Route
                        path='/system-settings'
                        element={
                          <AdminOnlyRoute session={session}>
                            <SystemSettings
                              session={session}
                              onLogout={handleLogout}
                              onAccountClick={handleHelpAccountClick}
                              onNavigateToDashboard={
                                handleHelpNavigateToDashboard
                              }
                              onNavigateToLanding={handleNavigateToLanding}
                            />
                          </AdminOnlyRoute>
                        }
                      />
                      <Route
                        path='/help'
                        element={
                          session ? (
                            <Help
                              session={session}
                              onLogout={handleLogout}
                              onAccountClick={handleHelpAccountClick}
                              onNavigateToDashboard={
                                handleHelpNavigateToDashboard
                              }
                              onNavigateToLanding={handleNavigateToLanding}
                            />
                          ) : (
                            <Navigate to='/login' replace />
                          )
                        }
                      />
                      <Route
                        path='/dashboard'
                        element={
                          session ? (
                            session.needsVerification ? (
                              <Navigate
                                to={`/verify-email?email=${encodeURIComponent(
                                  session.email || ''
                                )}`}
                                replace
                              />
                            ) : (
                              <DashboardWrapper
                                session={session}
                                tokens={
                                  showProductTour ? TOUR_MOCK_TOKENS : tokens
                                }
                                tokensLoading={tokensLoading}
                                contactGroups={
                                  showProductTour
                                    ? TOUR_MOCK_CONTACT_GROUPS
                                    : tokenContactGroups
                                }
                                workspaceContacts={
                                  showProductTour
                                    ? TOUR_MOCK_WORKSPACE_CONTACTS
                                    : workspaceContacts
                                }
                                formData={formData}
                                formErrors={formErrors}
                                isSubmitting={isSubmitting}
                                onInputChange={handleInputChange}
                                onTokenAdd={handleTokenAdd}
                                onDeleteToken={
                                  isViewer ? undefined : handleDeleteToken
                                }
                                onOpenRenew={
                                  isViewer ? undefined : handleOpenRenew
                                }
                                TOKEN_CATEGORIES={TOKEN_CATEGORIES}
                                onOpenTokenModal={handleOpenTokenModal}
                                onLogout={handleLogout}
                                onAccountClick={handleHelpAccountClick}
                                onNavigateToLanding={handleNavigateToLanding}
                                onAccountDeleted={handleAccountDeleted}
                                getFilteredAndSortedTokens={
                                  getFilteredAndSortedTokens
                                }
                                showWelcomeModal={showWelcomeModal}
                                setShowWelcomeModal={setShowWelcomeModal}
                                welcomeData={welcomeData}
                                selectedToken={selectedToken}
                                handleCloseTokenModal={handleCloseTokenModal}
                                // Thread global filtering/search/sort state into wrapper
                                setSearchQuery={setSearchQuery}
                                showProductTour={showProductTour}
                                setShowProductTour={setShowProductTour}
                                tourType={tourType}
                                setTourType={setTourType}
                                forceRunTour={forceRunTour}
                                setForceRunTour={setForceRunTour}
                                setServerSort={setServerSort}
                                selectedCategories={selectedCategories}
                                setSelectedCategories={setSelectedCategories}
                                tokenFacets={tokenFacets}
                                globalFacets={globalFacets}
                                fetchGlobalFacets={fetchGlobalFacets}
                                fetchTokensForCategoryReset={
                                  fetchTokensForCategoryReset
                                }
                                setTokens={setTokens}
                                isRefreshing={isRefreshing}
                                categoryHasMore={categoryHasMore}
                                categoryLoading={categoryLoading}
                                categoryCounts={categoryCounts}
                                fetchTokensForCategory={fetchTokensForCategory}
                                isViewer={isViewer}
                                locationEntries={locationEntries}
                                addLocationEntry={addLocationEntry}
                                removeLocationEntry={removeLocationEntry}
                                updateLocationEntry={updateLocationEntry}
                                defaultContactGroupId={defaultContactGroupId}
                                createTokenNotesFlushRef={
                                  createTokenNotesFlushRef
                                }
                              />
                            )
                          ) : (
                            <Navigate to='/login' replace />
                          )
                        }
                      />
                      <Route path='*' element={<NotFound />} />
                    </Routes>
                  </Suspense>
                </WorkspaceProvider>
              )}
            </Box>
            <Footer />
          </Box>

          <Toaster />

          {/* Token Deletion Confirmation Modal */}
          <Modal
            isOpen={isDeleteModalOpen}
            onClose={cancelDeleteToken}
            isCentered
          >
            <ModalOverlay />
            <ModalContent>
              <ModalHeader>Confirm Token Deletion</ModalHeader>
              <ModalCloseButton />
              <ModalBody>
                <VStack spacing={4} align='stretch'>
                  <Alert status='warning' borderRadius='md'>
                    <AlertIcon />
                    <AlertDescription>
                      This action cannot be undone. The token will be
                      permanently deleted.
                    </AlertDescription>
                  </Alert>
                  {tokenToDelete?.monitor_url && (
                    <Alert status='error' borderRadius='md'>
                      <AlertIcon />
                      <AlertDescription>
                        This token has a linked endpoint monitor (
                        {tokenToDelete.monitor_url}). Deleting this token will
                        also remove the monitor and stop health checks.
                      </AlertDescription>
                    </Alert>
                  )}
                  {tokenToDelete && (
                    <Box p={4} bg={deleteBoxBg} borderRadius='md'>
                      <Text fontWeight='bold' mb={2} color={deleteLabelColor}>
                        Token to delete:
                      </Text>
                      <Text color={deleteTextColor}>
                        <Text
                          as='span'
                          fontWeight='semibold'
                          color={deleteLabelColor}
                        >
                          Name:
                        </Text>{' '}
                        {tokenToDelete.name}
                      </Text>
                      <Text color={deleteTextColor}>
                        <Text
                          as='span'
                          fontWeight='semibold'
                          color={deleteLabelColor}
                        >
                          Type:
                        </Text>{' '}
                        {tokenToDelete.type}
                      </Text>
                      <Text color={deleteTextColor}>
                        <Text
                          as='span'
                          fontWeight='semibold'
                          color={deleteLabelColor}
                        >
                          Category:
                        </Text>{' '}
                        {tokenToDelete.category}
                      </Text>
                      {tokenToDelete.expiresAt && (
                        <Text color={deleteTextColor}>
                          <Text
                            as='span'
                            fontWeight='semibold'
                            color={deleteLabelColor}
                          >
                            Expires:
                          </Text>{' '}
                          {formatDate(tokenToDelete.expiresAt)}
                        </Text>
                      )}
                    </Box>
                  )}
                </VStack>
              </ModalBody>
              <ModalFooter>
                <Button variant='ghost' mr={3} onClick={cancelDeleteToken}>
                  Cancel
                </Button>
                <Button colorScheme='red' onClick={confirmDeleteToken}>
                  Delete Token
                </Button>
              </ModalFooter>
            </ModalContent>
          </Modal>

          {/* Duplicate Token Confirmation Modal */}
          <Modal
            isOpen={isDuplicateModalOpen}
            onClose={onDuplicateModalClose}
            isCentered
          >
            <ModalOverlay />
            <ModalContent>
              <ModalHeader>Token Already Exists</ModalHeader>
              <ModalCloseButton />
              <ModalBody>
                <VStack spacing={4} align='stretch'>
                  <Alert status='info' borderRadius='md'>
                    <AlertIcon />
                    <AlertDescription>
                      {duplicateTokenInfo?.message ||
                        'A token with the same name and location already exists in this workspace.'}
                    </AlertDescription>
                  </Alert>
                  {duplicateTokenInfo?.existing_token && (
                    <Box
                      p={4}
                      bg='gray.100'
                      _dark={{
                        bg: 'orange.900',
                        borderColor: 'orange.500',
                        color: 'orange.100',
                      }}
                      borderRadius='md'
                      border='1px solid'
                      borderColor='gray.200'
                      color='gray.700'
                    >
                      <Text
                        fontWeight='bold'
                        mb={2}
                        color='gray.800'
                        _dark={{ color: 'orange.200' }}
                      >
                        Existing token:
                      </Text>
                      <Text>
                        <Text as='span' fontWeight='semibold'>
                          Name:
                        </Text>{' '}
                        {duplicateTokenInfo.existing_token.name}
                      </Text>
                      {duplicateTokenInfo.existing_token.location && (
                        <Box>
                          <Text as='span' fontWeight='semibold'>
                            Locations:
                          </Text>
                          <Text whiteSpace='pre-wrap' wordBreak='break-all'>
                            {duplicateTokenInfo.existing_token.location}
                          </Text>
                        </Box>
                      )}
                      {duplicateTokenInfo.existing_token.expiration && (
                        <Text>
                          <Text as='span' fontWeight='semibold'>
                            Expires:
                          </Text>{' '}
                          {formatDate(
                            duplicateTokenInfo.existing_token.expiration
                          )}
                        </Text>
                      )}
                    </Box>
                  )}
                  <Text
                    fontSize='sm'
                    color='gray.600'
                    _dark={{ color: 'gray.200' }}
                  >
                    Creating this token will update the existing one with the
                    new information you provided.
                  </Text>
                </VStack>
              </ModalBody>
              <ModalFooter>
                <Button variant='ghost' mr={3} onClick={onDuplicateModalClose}>
                  Cancel
                </Button>
                <Button
                  colorScheme='blue'
                  onClick={handleConfirmDuplicate}
                  isLoading={isSubmitting}
                >
                  Update Existing Token
                </Button>
              </ModalFooter>
            </ModalContent>
          </Modal>

          {/* Token Renew Modal */}
          <Modal
            isOpen={isRenewModalOpen}
            onClose={handleCloseRenew}
            isCentered
          >
            <ModalOverlay />
            <ModalContent>
              <ModalHeader>Renew Token</ModalHeader>
              <ModalCloseButton />
              <ModalBody>
                <VStack spacing={4} align='stretch'>
                  {tokenToRenew && (
                    <Box p={4} bg={renewBoxBg} borderRadius='md'>
                      <Text fontWeight='bold' mb={2} color={renewLabelColor}>
                        {tokenToRenew.name}
                      </Text>
                      <Text color={renewTextColor}>
                        Current expiration:{' '}
                        {tokenToRenew.expiresAt
                          ? formatDate(tokenToRenew.expiresAt)
                          : '-'}
                      </Text>
                    </Box>
                  )}
                  <FormControl isInvalid={!!renewErrors.renewDate}>
                    <FormLabel htmlFor='renewDate'>
                      New Expiration Date
                    </FormLabel>
                    <Input
                      id='renewDate'
                      type='date'
                      value={renewDate}
                      onChange={e => setRenewDate(e.target.value)}
                    />
                    {renewErrors.renewDate && (
                      <FormErrorMessage>
                        {renewErrors.renewDate}
                      </FormErrorMessage>
                    )}
                  </FormControl>
                  <Text
                    fontSize='sm'
                    _light={{ color: 'gray.600' }}
                    _dark={{ color: 'whiteAlpha.800' }}
                  >
                    Default set based on token category/type. You can pick any
                    future date.
                  </Text>
                </VStack>
              </ModalBody>
              <ModalFooter>
                <Button variant='ghost' mr={3} onClick={handleCloseRenew}>
                  Cancel
                </Button>
                <Button
                  colorScheme='teal'
                  onClick={handleConfirmRenew}
                  isLoading={isRenewSubmitting}
                >
                  Confirm
                </Button>
              </ModalFooter>
            </ModalContent>
          </Modal>
        </ErrorBoundary>

        {!isViewer && (
          <ProductTour
            run={showProductTour}
            tourType={tourType}
            forceRun={forceRunTour}
            onTourComplete={completed => {
              setShowProductTour(false);
              setForceRunTour(false);
              if (completed) {
                trackEvent('product_tour_finished', { tour_type: tourType });
              }
            }}
          />
        )}
      </HelmetProvider>
    </ChakraProvider>
  );
}

/**
 * Dashboard Wrapper Component - handles URL parameters and view state
 */
function DashboardWrapper({
  session,
  tokens,
  tokensLoading,
  contactGroups,
  workspaceContacts = [],
  formData,
  formErrors,
  isSubmitting,
  onInputChange,
  onTokenAdd,
  onDeleteToken,
  onOpenRenew,
  TOKEN_CATEGORIES,
  onOpenTokenModal,
  onLogout,
  onNavigateToLanding,
  onAccountDeleted,
  showWelcomeModal,
  setShowWelcomeModal,
  welcomeData,
  selectedToken,
  handleCloseTokenModal,
  getFilteredAndSortedTokens,
  // Global filtering/search/sort state/handlers from App
  setSearchQuery,
  setServerSort,
  selectedCategories,
  setSelectedCategories,
  tokenFacets,
  globalFacets,
  fetchGlobalFacets,
  fetchTokensForCategoryReset,
  setTokens,
  isRefreshing,
  categoryHasMore,
  categoryLoading,
  categoryCounts,
  fetchTokensForCategory,
  isViewer,
  // Product tour state
  showProductTour: _showProductTour,
  setShowProductTour,
  tourType: _tourType,
  setTourType,
  forceRunTour: _forceRunTour,
  setForceRunTour,
  // Location entries props
  locationEntries,
  addLocationEntry,
  removeLocationEntry,
  updateLocationEntry,
  defaultContactGroupId = '',
  createTokenNotesFlushRef,
}) {
  const [searchParams] = useSearchParams();
  const [currentView, setCurrentView] = useState('dashboard');

  // Check URL parameter for view on mount and when searchParams change
  useEffect(() => {
    const viewParam = searchParams.get('view');
    if (viewParam === 'account') {
      setCurrentView('account');
    } else {
      setCurrentView('dashboard');
    }
  }, [searchParams]);

  // Listen for manual tour trigger events (for testing) - skip for viewers
  useEffect(() => {
    if (isViewer) return;
    const handleTourStart = event => {
      const tourType = event.detail?.type || 'dashboard';
      setTourType(tourType);
      setShowProductTour(true);
    };

    window.addEventListener('tt:start-tour', handleTourStart);
    return () => {
      window.removeEventListener('tt:start-tour', handleTourStart);
    };
  }, [isViewer, setShowProductTour, setTourType]);

  // Check for ?tour=dashboard query parameter to force-run tour - skip for viewers
  useEffect(() => {
    if (typeof window === 'undefined' || isViewer) return;

    const urlParams = new URLSearchParams(window.location.search);
    const tourParam = urlParams.get('tour');

    if (tourParam && window.location.pathname === '/dashboard') {
      setForceRunTour(true);

      urlParams.delete('tour');
      const newUrl =
        window.location.pathname +
        (urlParams.toString() ? `?${urlParams.toString()}` : '');
      window.history.replaceState({}, '', newUrl);

      const tourType = tourParam === 'dashboard' ? 'dashboard' : tourParam;
      setTimeout(() => {
        setTourType(tourType);
        setShowProductTour(true);
      }, 500);
    }
  }, [isViewer, setShowProductTour, setTourType, setForceRunTour]);

  const handleAccountClick = () => {
    setCurrentView('account');
    const url = new URL(window.location);
    url.searchParams.set('view', 'account');
    window.history.pushState({}, '', url);
  };

  const handleDashboardNavigation = () => {
    setCurrentView('dashboard');
    const url = new URL(window.location);
    url.searchParams.delete('view');
    window.history.pushState({}, '', url);
  };

  return (
    <div
      style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}
    >
      <SEO
        title='Dashboard'
        description='Manage your tokens, certificates, and expiring assets'
        noindex
      />
      {currentView === 'dashboard' ? (
        <Box display={{ base: 'block', lg: 'none' }}>
          <Navigation
            user={session}
            onLogout={onLogout}
            onAccountClick={handleAccountClick}
            onNavigateToDashboard={handleDashboardNavigation}
            onNavigateToLanding={onNavigateToLanding}
          />
        </Box>
      ) : (
        <Navigation
          user={session}
          onLogout={onLogout}
          onAccountClick={handleAccountClick}
          onNavigateToDashboard={handleDashboardNavigation}
          onNavigateToLanding={onNavigateToLanding}
        />
      )}

      <main
        id='main-content'
        style={{
          flex: 1,
          padding:
            currentView === 'dashboard'
              ? 0
              : 'clamp(1rem, 1.8vw, 1.75rem)',
          overflowX: 'hidden',
          background:
            currentView === 'dashboard' ? DASHBOARD_PAGE_BG : undefined,
        }}
      >
        <div
          style={{
            maxWidth: currentView === 'dashboard' ? 'none' : '1200px',
            margin: currentView === 'dashboard' ? 0 : '0 auto',
          }}
        >
          {currentView === 'dashboard' ? (
            <DashboardView
              _session={session}
              tokens={tokens}
              tokensLoading={tokensLoading}
              contactGroups={contactGroups || []}
              workspaceContacts={workspaceContacts}
              formData={formData}
              formErrors={formErrors}
              isSubmitting={isSubmitting}
              onInputChange={onInputChange}
              onTokenAdd={onTokenAdd}
              onDeleteToken={onDeleteToken}
              onOpenRenew={onOpenRenew}
              TOKEN_CATEGORIES={TOKEN_CATEGORIES}
              onOpenTokenModal={onOpenTokenModal}
              getFilteredAndSortedTokens={getFilteredAndSortedTokens}
              selectedCategories={selectedCategories}
              setSelectedCategories={setSelectedCategories}
              tokenFacets={tokenFacets}
              globalFacets={globalFacets}
              fetchGlobalFacets={fetchGlobalFacets}
              fetchTokensForCategoryReset={fetchTokensForCategoryReset}
              _setTokens={setTokens}
              _setSearchQuery={setSearchQuery}
              _setServerSort={setServerSort}
              isRefreshing={isRefreshing}
              categoryHasMore={categoryHasMore}
              categoryLoading={categoryLoading}
              categoryCounts={categoryCounts}
              fetchTokensForCategory={fetchTokensForCategory}
              isViewer={isViewer}
              locationEntries={locationEntries}
              addLocationEntry={addLocationEntry}
              removeLocationEntry={removeLocationEntry}
              updateLocationEntry={updateLocationEntry}
              defaultContactGroupId={defaultContactGroupId}
              createTokenNotesFlushRef={createTokenNotesFlushRef}
              onLogout={onLogout}
              onAccountClick={handleAccountClick}
            />
          ) : currentView === 'account' ? (
            <Account session={session} onAccountDeleted={onAccountDeleted} />
          ) : null}
        </div>
      </main>

      <WelcomeModal
        isOpen={showWelcomeModal && location.pathname === '/dashboard'}
        onClose={() => {
          try {
            // Clear onboarding flags so workspace normalization can proceed
            const url = new URL(window.location.href);
            [
              'new_user',
              'first_login',
              'registered',
              'verification_success',
            ].forEach(k => url.searchParams.delete(k));
            window.history.replaceState({}, '', url.toString());
          } catch (_) {}
          try {
            localStorage.removeItem('tt_welcome_pending');
          } catch (_) {}
          setShowWelcomeModal(false);

          // Ensure product tour is not shown when bypassing via "Go to Dashboard"
          setShowProductTour(false);
          setForceRunTour(false);

          // Mark tour as skipped when user bypasses it via "Go to Dashboard"
          // This prevents the tour from auto-starting and showing mock data
          try {
            const isNewUser = welcomeData?.isNewUser;
            if (isNewUser && window.location.pathname === '/dashboard') {
              const hasCompletedTour = localStorage.getItem(
                'tt_tour_dashboard_v1'
              );
              if (!hasCompletedTour) {
                // Mark as completed/skipped so tour doesn't auto-start
                localStorage.setItem('tt_tour_dashboard_v1', 'true');
              }
            }
          } catch (_) {}
        }}
        onStartTour={
          isViewer
            ? undefined
            : () => {
                setShowWelcomeModal(false);
                try {
                  const url = new URL(window.location.href);
                  [
                    'new_user',
                    'first_login',
                    'registered',
                    'verification_success',
                  ].forEach(k => url.searchParams.delete(k));
                  window.history.replaceState({}, '', url.toString());
                } catch (_) {}
                try {
                  localStorage.removeItem('tt_welcome_pending');
                  localStorage.removeItem('tt_tour_dashboard_v1');
                } catch (_) {}

                if (window.location.pathname === '/dashboard') {
                  setForceRunTour(true);
                  setTimeout(() => {
                    setTourType('dashboard');
                    setShowProductTour(true);
                  }, 500);
                }
              }
        }
        data={welcomeData}
      />

      {selectedToken && (
        <TokenDetailModal
          token={selectedToken}
          isOpen={true}
          onClose={handleCloseTokenModal}
          TOKEN_CATEGORIES={TOKEN_CATEGORIES}
          isViewer={isViewer}
          contactGroups={contactGroups}
          workspaceContacts={workspaceContacts}
          onTokenUpdated={updated => {
            if (!updated?.id) return;
            const prevSection = selectedToken?.section || '';
            let __nextTokens = null;
            setTokens(prev => {
              const arr = prev.map(t => (t.id === updated.id ? updated : t));
              __nextTokens = arr;
              return arr;
            });
            // Trigger a single dashboard reload so facets/sections update
            try {
              window.dispatchEvent(
                new CustomEvent('tt:tokens-updated', {
                  detail: { t: Date.now() },
                })
              );
            } catch (_) {}
            // If section changed, clear section filter in URL so the token remains visible
            try {
              const before = String(prevSection || '');
              const after = String(updated.section || '');
              if (before !== after) {
                const search = new URLSearchParams(window.location.search);
                if (search.get('section')) {
                  search.delete('section');
                  const qs = search.toString();
                  navigate(`${window.location.pathname}${qs ? `?${qs}` : ''}`, {
                    replace: true,
                  });
                }
              }
            } catch (_) {}
          }}
        />
      )}
    </div>
  );
}

/**
 * Dashboard View Component
 * Note: domain helper functions have been extracted to ./components/DashboardHelpers.jsx
 */

const CreateTokenNotesField = memo(function CreateTokenNotesField({
  parentNotes,
  onCommitNotes,
  submitFlushRef,
  inputBg,
  inputBorder,
  placeholderColor,
}) {
  const [local, setLocal] = useState(() => parentNotes ?? '');
  const taRef = useRef(null);

  useEffect(() => {
    setLocal(parentNotes ?? '');
  }, [parentNotes]);

  useLayoutEffect(() => {
    const el = taRef.current;
    if (!el) return;
    el.style.height = 'auto';
    el.style.height = `${el.scrollHeight}px`;
  }, [local]);

  useEffect(() => {
    submitFlushRef.current = () => {
      onCommitNotes(taRef.current?.value ?? '');
    };
    return () => {
      submitFlushRef.current = () => {};
    };
  }, [local, onCommitNotes, submitFlushRef]);

  return (
    <Textarea
      ref={taRef}
      id='notes'
      name='notes'
      value={local}
      onChange={e => setLocal(e.target.value)}
      onBlur={e => onCommitNotes(e.target.value)}
      bg={inputBg}
      borderColor={inputBorder}
      placeholder='Additional information'
      _placeholder={{ color: placeholderColor }}
      maxLength={10000}
      rows={2}
      resize='none'
      overflow='hidden'
      minH='40px'
    />
  );
});

function DashboardView({
  _session,
  tokens,
  tokensLoading,
  contactGroups,
  workspaceContacts = [],
  formData,
  formErrors,
  isSubmitting,
  onInputChange,
  onTokenAdd,
  onDeleteToken,
  onOpenRenew,
  TOKEN_CATEGORIES,
  onOpenTokenModal,
  getFilteredAndSortedTokens,
  // Added props for global search, sorting, and category filters
  _setSearchQuery,
  _setServerSort,
  selectedCategories,
  setSelectedCategories,
  tokenFacets,
  globalFacets,
  fetchGlobalFacets,
  fetchTokensForCategoryReset,
  _setTokens,
  // Pagination/data controls
  isRefreshing,
  categoryHasMore,
  categoryLoading,
  categoryCounts,
  fetchTokensForCategory,
  isViewer = false,
  // Location entries props
  locationEntries,
  addLocationEntry,
  removeLocationEntry,
  updateLocationEntry,
  defaultContactGroupId = '',
  createTokenNotesFlushRef,
  onLogout,
  onAccountClick,
}) {
  const navigate = useNavigate();
  const { workspaceId, selectWorkspace } = useWorkspace();
  const { toggleColorMode } = useColorMode();

  // Move useColorModeValue calls to the top to comply with Rules of Hooks
  const menuBg = useColorModeValue('rgba(15, 23, 42, 0.98)', 'gray.800');
  const menuBorder = useColorModeValue(
    'rgba(148, 163, 184, 0.2)',
    'gray.600'
  );
  const _popoverBg = useColorModeValue('gray.100', 'gray.800');
  const _popoverBorder = useColorModeValue('gray.400', 'gray.600');
  const helpTextColor = useColorModeValue(
    'rgba(148, 163, 184, 0.86)',
    'gray.400'
  );

  const inputBg = useColorModeValue(
    'rgba(2, 6, 23, 0.58)',
    'rgba(2, 6, 23, 0.58)'
  );
  const inputBorder = useColorModeValue(
    'rgba(148, 163, 184, 0.24)',
    'rgba(148, 163, 184, 0.24)'
  );
  const placeholderColor = useColorModeValue(
    'rgba(148, 163, 184, 0.72)',
    'rgba(148, 163, 184, 0.72)'
  );
  const emptyTextColor = useColorModeValue(
    'rgba(203, 213, 225, 0.82)',
    'rgba(203, 213, 225, 0.82)'
  );
  const hoverBgColor = useColorModeValue(
    'rgba(30, 41, 59, 0.72)',
    'rgba(30, 41, 59, 0.72)'
  );
  const filterLabelColor = useColorModeValue(
    'rgba(203, 213, 225, 0.86)',
    'rgba(203, 213, 225, 0.86)'
  );
  const mobileCardBg = useColorModeValue(
    'rgba(15, 23, 42, 0.92)',
    'rgba(15, 23, 42, 0.92)'
  );
  const secondaryTextColor = useColorModeValue(
    'rgba(148, 163, 184, 0.9)',
    'rgba(148, 163, 184, 0.9)'
  );
  const pageTextColor = 'rgba(248, 250, 252, 0.96)';
  const mutedTextColor = DASHBOARD_MUTED_TEXT;
  const sessionName =
    _session?.displayName || _session?.name || _session?.email || 'User';
  const sessionEmail = _session?.email || '';
  const sessionInitials = String(sessionName)
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map(part => part[0])
    .join('')
    .toUpperCase();
  const workspaceName =
    _session?.workspaceName || _session?.workspace?.name || 'Current Workspace';
  const workspaceLabel = workspaceName;
  const isSystemAdmin = _session?.isAdmin === true;
  const [dashboardWorkspaces, setDashboardWorkspaces] = useState([]);
  const [dashboardWorkspace, setDashboardWorkspace] = useState(null);
  const [dashboardCanSeeManagerNav, setDashboardCanSeeManagerNav] =
    useState(false);
  const [dashboardNotifications, setDashboardNotifications] = useState([]);
  const [dashboardSidebarWidth, setDashboardSidebarWidth] = useState(
    getInitialDashboardSidebarWidth
  );
  const dashboardSidebarWidthPx = `${dashboardSidebarWidth}px`;
  const isDashboardSidebarExpanded =
    dashboardSidebarWidth >= DASHBOARD_SIDEBAR_LABEL_WIDTH;

  useLayoutEffect(() => {
    const widthPx = `${dashboardSidebarWidth}px`;
    document.documentElement.style.setProperty(
      DASHBOARD_SIDEBAR_WIDTH_CSS_VAR,
      widthPx
    );
    try {
      window.localStorage.setItem(
        DASHBOARD_SIDEBAR_STORAGE_KEY,
        String(dashboardSidebarWidth)
      );
      window.dispatchEvent(
        new CustomEvent('tt:dashboard-sidebar-width', {
          detail: { width: dashboardSidebarWidth },
        })
      );
    } catch (_) {}
  }, [dashboardSidebarWidth]);

  const toggleDashboardSidebarWidth = useCallback(() => {
    setDashboardSidebarWidth(width =>
      width >= DASHBOARD_SIDEBAR_LABEL_WIDTH
        ? DASHBOARD_SIDEBAR_MIN_WIDTH
        : DASHBOARD_SIDEBAR_MAX_WIDTH
    );
  }, []);

  useEffect(() => {
    let cancelled = false;
    async function loadDashboardWorkspaces() {
      if (!_session) {
        if (!cancelled) {
          setDashboardWorkspaces([]);
          setDashboardWorkspace(null);
          setDashboardCanSeeManagerNav(false);
        }
        return;
      }

      try {
        const ws = await workspaceAPI.list(50, 0);
        if (cancelled) return;
        const items = ws?.items || [];
        const roles = items.map(w => String(w.role || '').toLowerCase());
        const managerAny =
          roles.includes('admin') || roles.includes('workspace_manager');
        let desiredId = workspaceId || null;
        if (!desiredId) {
          try {
            desiredId = localStorage.getItem('tt_last_workspace_id') || null;
          } catch (_) {
            desiredId = null;
          }
        }
        const selected =
          (desiredId && items.find(w => w.id === desiredId)) ||
          items[0] ||
          null;

        setDashboardWorkspaces(items);
        setDashboardWorkspace(selected);
        setDashboardCanSeeManagerNav(isSystemAdmin || (items.length ? managerAny : true));
      } catch (_) {
        if (!cancelled) {
          setDashboardWorkspaces([]);
          setDashboardWorkspace(null);
          setDashboardCanSeeManagerNav(isSystemAdmin);
        }
      }
    }

    loadDashboardWorkspaces();
    const refresh = () => loadDashboardWorkspaces();
    window.addEventListener('tt:workspaces-updated', refresh);
    window.addEventListener('tt:plan-updated', refresh);
    return () => {
      cancelled = true;
      window.removeEventListener('tt:workspaces-updated', refresh);
      window.removeEventListener('tt:plan-updated', refresh);
    };
  }, [_session, isSystemAdmin, workspaceId]);

  const handleDashboardWorkspaceSelect = workspace => {
    if (!workspace?.id) return;
    setDashboardWorkspace(workspace);
    try {
      selectWorkspace(workspace.id);
      localStorage.setItem('tt_last_workspace_id', workspace.id);
    } catch (_) {}
    try {
      window.dispatchEvent(new CustomEvent('tt:workspaces-updated'));
    } catch (_) {}
  };

  useEffect(() => {
    let cancelled = false;
    async function loadDashboardNotifications() {
      if (!_session || !dashboardWorkspace?.id) {
        if (!cancelled) setDashboardNotifications([]);
        return;
      }

      try {
        const [settingsRes, notificationsRes] = await Promise.all([
          workspaceAPI.getAlertSettings(dashboardWorkspace.id),
          workspaceAPI
            .getNotifications(dashboardWorkspace.id)
            .catch(() => ({ items: [] })),
        ]);
        if (cancelled) return;

        const data = settingsRes?.data || settingsRes || {};
        const emailEnabled = data.email_alerts_enabled === true;
        const webhooks = data.webhook_urls;
        const hasWebhooks = Array.isArray(webhooks) && webhooks.length > 0;
        const smtpConfigured = data.smtp_configured !== false;
        const allDisabled = !emailEnabled && !hasWebhooks;
        const contactGroups = Array.isArray(data.contact_groups)
          ? data.contact_groups
          : [];
        const hasAnyContact = contactGroups.some(group => {
          const emailIds = Array.isArray(group.email_contact_ids)
            ? group.email_contact_ids
            : [];
          const whatsappIds = Array.isArray(group.whatsapp_contact_ids)
            ? group.whatsapp_contact_ids
            : [];
          return emailIds.length > 0 || whatsappIds.length > 0;
        });
        const currentRole = String(dashboardWorkspace?.role || '').toLowerCase();
        const canManageWorkspaceAlerts =
          isSystemAdmin ||
          currentRole === 'admin' ||
          currentRole === 'workspace_manager';
        const list = [];

        if (canManageWorkspaceAlerts) {
          const operational = Array.isArray(notificationsRes?.items)
            ? notificationsRes.items
            : [];
          for (const item of operational) {
            list.push({
              id: item.id,
              kind: item.kind === 'error' ? 'error' : 'warning',
              text: item.text,
              href: item.href || null,
            });
          }
        }

        if (!canManageWorkspaceAlerts) {
          setDashboardNotifications(list);
          return;
        }

        if (!smtpConfigured) {
          list.push({
            id: 'smtp-not-configured',
            kind: 'warning',
            text: isSystemAdmin
              ? 'SMTP is not configured. Email notifications will not be sent.'
              : 'SMTP is not configured. Ask a system administrator to configure email delivery.',
            href: isSystemAdmin ? '/system-settings' : null,
          });
        }
        if (allDisabled) {
          list.push({
            id: 'alerts-disabled',
            kind: 'warning',
            text: 'Alerts are disabled until a channel is defined.',
            href: '/preferences',
          });
        }
        if (!hasAnyContact) {
          list.push({
            id: 'no-contacts-defined',
            kind: 'warning',
            text: 'No contacts assigned to any contact group. Alerts will not reach anyone.',
            href: '/preferences',
          });
        }
        setDashboardNotifications(list);
      } catch (_) {
        if (!cancelled) setDashboardNotifications([]);
      }
    }

    loadDashboardNotifications();
    const refresh = () => loadDashboardNotifications();
    window.addEventListener('tt:notifications-refresh', refresh);
    return () => {
      cancelled = true;
      window.removeEventListener('tt:notifications-refresh', refresh);
    };
  }, [_session, dashboardWorkspace, isSystemAdmin]);

  const commitCreateNotes = useCallback(
    v => {
      onInputChange({ target: { name: 'notes', value: v } });
    },
    [onInputChange]
  );

  const contactTagBg = useColorModeValue('blue.100', 'blue.800');
  const contactTagColor = useColorModeValue('blue.800', 'blue.200');

  const contactInputRef = useRef(null);
  const [contactTags, setContactTags] = useState([]);
  const [contactInputValue, setContactInputValue] = useState('');
  const contactsFromTagsRef = useRef(false);

  useEffect(() => {
    if (contactsFromTagsRef.current) {
      contactsFromTagsRef.current = false;
      return;
    }
    if (!formData.contacts) {
      setContactTags([]);
      setContactInputValue('');
    } else {
      const tags = formData.contacts
        .split(',')
        .map(t => t.trim())
        .filter(Boolean);
      setContactTags(tags);
    }
  }, [formData.contacts]);

  const workspaceContactLabels = useMemo(() => {
    const set = new Set();
    for (const c of Array.isArray(workspaceContacts) ? workspaceContacts : []) {
      const name = [c.first_name, c.last_name].filter(Boolean).join(' ').trim();
      const phone = (c.phone_e164 || '').trim();
      const parts = [name, phone].filter(Boolean);
      const label = parts.join(' - ');
      if (label) set.add(label);
    }
    return set;
  }, [workspaceContacts]);

  const selectedContactLabels = useMemo(
    () => new Set(contactTags),
    [contactTags]
  );

  const removeContactTag = index => {
    const newTags = contactTags.filter((_, i) => i !== index);
    setContactTags(newTags);
    contactsFromTagsRef.current = true;
    onInputChange({ target: { name: 'contacts', value: newTags.join(', ') } });
  };

  const commitContactTag = trimmed => {
    if (!trimmed) return;
    if (contactTags.includes(trimmed)) return;
    const newTags = [...contactTags, trimmed];
    const newValue = newTags.join(', ');
    if (newValue.length > 500) return;
    setContactTags(newTags);
    setContactInputValue('');
    contactsFromTagsRef.current = true;
    onInputChange({ target: { name: 'contacts', value: newValue } });
  };

  const handleContactInputChange = e => {
    const v = e.target.value;
    const trimmed = v.trim();
    setContactInputValue(v);
    if (
      workspaceContactLabels.has(trimmed) &&
      !selectedContactLabels.has(trimmed)
    ) {
      commitContactTag(trimmed);
    }
  };

  const handleContactKeyDown = e => {
    if (e.key === 'Enter' && contactInputValue.trim()) {
      e.preventDefault();
      commitContactTag(contactInputValue.trim());
    } else if (
      e.key === 'Backspace' &&
      !contactInputValue &&
      contactTags.length > 0
    ) {
      removeContactTag(contactTags.length - 1);
    }
  };

  const renderContactTagInput = placeholder => (
    <Box
      border='1px solid'
      borderColor={inputBorder}
      borderRadius='md'
      bg={inputBg}
      px={2}
      py='6px'
      minH='40px'
      cursor='text'
      onClick={() => contactInputRef.current?.focus()}
    >
      <Flex wrap='wrap' gap={1} alignItems='center'>
        {contactTags.map((tag, i) => (
          <Flex
            key={i}
            align='center'
            bg={contactTagBg}
            color={contactTagColor}
            borderRadius='md'
            px={2}
            py='2px'
            fontSize='sm'
            gap={1}
          >
            <Text fontSize='sm' lineHeight='short'>
              {tag}
            </Text>
            <Box
              as='button'
              type='button'
              onClick={e => {
                e.stopPropagation();
                removeContactTag(i);
              }}
              lineHeight={1}
              cursor='pointer'
              opacity={0.7}
              _hover={{ opacity: 1 }}
              fontSize='xs'
              fontWeight='bold'
            >
              ×
            </Box>
          </Flex>
        ))}
        <Input
          ref={contactInputRef}
          type='text'
          value={contactInputValue}
          onChange={handleContactInputChange}
          onKeyDown={handleContactKeyDown}
          list='workspace-contacts-suggestions'
          placeholder={contactTags.length === 0 ? placeholder : ''}
          _placeholder={{ color: placeholderColor }}
          border='none'
          bg='transparent'
          p={0}
          h='28px'
          flex={1}
          minW='120px'
          fontSize='sm'
          _focus={{ boxShadow: 'none', outline: 'none' }}
        />
      </Flex>
    </Box>
  );

  // Per-panel search terms keyed by category value
  const [panelQueries, setPanelQueries] = useState(() => {
    try {
      const section = new URLSearchParams(window.location.search).get(
        'section'
      );
      return { __section: section || '__all__' };
    } catch (_) {
      return { __section: '__all__' };
    }
  });
  const [statusFilter, setStatusFilter] = useState('all');
  const [assetSort, setAssetSort] = useState({
    key: 'expiresAt',
    direction: 'asc',
  });
  const [assetPageSize, setAssetPageSize] = useState(10);
  const [assetPage, setAssetPage] = useState(1);

  const [selectedTokenIds, setSelectedTokenIds] = useState([]);
  const [bulkSectionDrafts, setBulkSectionDrafts] = useState({});
  const safeSetTokens = updater => {
    if (typeof _setTokens === 'function') {
      _setTokens(updater);
      return true;
    }
    logger.error('Dashboard token setter is unavailable in DashboardView');
    return false;
  };

  // Memoize filtered tokens per category to avoid recomputing on every render
  const _filteredTokensByCategory = useMemo(() => {
    const sectionParam = (panelQueries && panelQueries.__section) || '__all__';
    const result = {};
    TOKEN_CATEGORIES.forEach(category => {
      const panelSearch = (panelQueries && panelQueries[category.value]) || '';
      result[category.value] = getFilteredAndSortedTokens(
        tokens,
        category,
        panelSearch,
        sectionParam
      );
    });
    return result;
  }, [tokens, panelQueries, getFilteredAndSortedTokens, TOKEN_CATEGORIES]);

  // Endpoint (SSL) monitor modal
  const {
    isOpen: isDomainModalOpen,
    onOpen: onDomainModalOpen,
    onClose: onDomainModalClose,
  } = useDisclosure();
  // Form collapse state - collapsed by default for cleaner UI
  const [isCreateTokenModalOpen, setCreateTokenModalOpen] = useState(false);

  const toggleTokenSelection = tokenId => {
    if (isViewer) return;
    setSelectedTokenIds(prev =>
      prev.includes(tokenId)
        ? prev.filter(id => id !== tokenId)
        : [...prev, tokenId]
    );
  };

  const handleBulkDelete = async () => {
    if (isViewer) return;
    if (selectedTokenIds.length === 0) return;
    if (
      !window.confirm(
        `Are you sure you want to delete ${selectedTokenIds.length} selected tokens? Any linked endpoint monitors will also be deleted.`
      )
    ) {
      return;
    }

    try {
      const response = await apiClient.delete('/api/tokens/bulk', {
        data: { ids: selectedTokenIds },
      });

      const data = response.data || {};
      const successCount = data.successCount ?? 0;
      const failedCount = data.failedCount ?? 0;

      // Filter out successfully deleted tokens from the local state
      const deletedIds = (data.results?.success || []).map(id => String(id));
      safeSetTokens(prev =>
        prev.filter(t => !deletedIds.includes(String(t.id)))
      );

      // Clear selection
      setSelectedTokenIds([]);

      // Notify user
      if (failedCount === 0) {
        showSuccessMessage(`Successfully deleted ${successCount} tokens.`);
      } else {
        showSuccessMessage(
          `Deleted ${successCount} tokens. ${failedCount} failed.`
        );
      }

      // Trigger a refresh of the counts and visible tokens for ALL categories
      // and refresh global facets to update the section filter counts accurately
      if (fetchGlobalFacets) fetchGlobalFacets();
      TOKEN_CATEGORIES.forEach(cat => fetchTokensForCategoryReset(cat.value));
    } catch (error) {
      console.error('Bulk delete error:', error);
      alert('Failed to delete tokens. Please try again.');
    }
  };

  const handleBulkAssignSection = async (tokenIds, categoryValue) => {
    if (isViewer) return;
    const draft = String(bulkSectionDrafts?.[categoryValue] || '').trim();
    if (!draft) {
      toast.error('Enter a section label first');
      return;
    }
    if (tokenIds.length === 0) {
      toast.error('Select at least one token');
      return;
    }

    try {
      const res = await apiClient.put('/api/tokens/bulk', {
        ids: tokenIds,
        section: [draft],
      });
      const data = res.data || {};
      const successIds = Array.isArray(data.results?.success)
        ? data.results.success
        : [];
      const failedCount =
        typeof data.failedCount === 'number'
          ? data.failedCount
          : Math.max(tokenIds.length - successIds.length, 0);

      if (successIds.length > 0) {
        const successSet = new Set(successIds.map(id => String(id)));
        _setTokens(prev =>
          prev.map(token =>
            successSet.has(String(token.id))
              ? { ...token, section: [draft] }
              : token
          )
        );
      }
      if (fetchGlobalFacets) fetchGlobalFacets();

      if (failedCount === 0) {
        showSuccessMessage(`Assigned section to ${successIds.length} token(s)`);
      } else if (successIds.length > 0) {
        toast.success(
          `Updated ${successIds.length} token(s), ${failedCount} failed`
        );
      } else {
        toast.error('Failed to assign section');
      }
    } catch (error) {
      logger.error('Bulk section assignment failed', error);
      toast.error(error?.response?.data?.error || 'Failed to assign section');
    }
  };

  const exportTokens = async format => {
    try {
      // Gather tokens for current workspace and section filters from in-memory list
      const sectionParam =
        (panelQueries && panelQueries.__section) || '__all__';
      const bySection = arr => {
        if (!sectionParam || sectionParam === '__all__') return arr;
        const norm = v =>
          String(v || '')
            .trim()
            .toLowerCase();
        if (sectionParam === '__none__')
          return arr.filter(
            t =>
              !t.section ||
              (Array.isArray(t.section) && t.section.length === 0) ||
              String(t.section).trim() === ''
          );

        // Support multi-select: split by comma
        const wantedList = String(sectionParam)
          .split(',')
          .map(s => norm(s))
          .filter(Boolean);

        return arr.filter(t => {
          const tokenSections = Array.isArray(t.section)
            ? t.section.map(s => norm(s))
            : [norm(t.section)];

          // Match if ALL of the selected sections are present in the token (AND logic)
          return wantedList.every(w => tokenSections.includes(w));
        });
      };
      // Filter and de-duplicate by id to avoid duplicates from category loads
      const filtered = bySection(Array.isArray(tokens) ? tokens : []);
      const byId = new Map();
      for (const t of filtered) {
        if (t && (t.id ?? t._id ?? true))
          byId.set(
            t.id ?? `${t.name}-${t.expiresAt}-${t.category}-${t.type}`,
            t
          );
      }
      const currentTokens = Array.from(byId.values());
      const fileBase = 'tokentimer-tokens';

      if (format === 'json') {
        const blob = new Blob([JSON.stringify(currentTokens, null, 2)], {
          type: 'application/json',
        });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${fileBase}.json`;
        a.click();
        URL.revokeObjectURL(url);
        return;
      }

      if (format === 'yaml') {
        const yamlMod = await import(
          /* @vite-ignore */ 'https://esm.sh/js-yaml@4.1.0'
        );
        const yaml = yamlMod?.dump ? yamlMod : yamlMod.default;
        const payload = { tokens: currentTokens };
        const text = yaml.dump ? yaml.dump(payload) : yaml.dump(payload);
        const blob = new Blob([text], { type: 'text/yaml' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${fileBase}.yaml`;
        a.click();
        URL.revokeObjectURL(url);
        return;
      }

      if (format === 'csv') {
        // Full export with all supported fields (aligned with importer)
        const header = [
          'name',
          'category',
          'type',
          'expiresAt',
          'section',
          'domains',
          'location',
          'used_by',
          'issuer',
          'serial_number',
          'subject',
          'key_size',
          'algorithm',
          'license_type',
          'vendor',
          'cost',
          'renewal_url',
          'renewal_date',
          'contacts',
          'description',
          'notes',
          'privileges',
          'last_used',
          'imported_at',
          'created_at',
          'contact_group_id',
        ];
        const rows = currentTokens.map(t => ({
          name: t.name ?? '',
          category: t.category ?? '',
          type: t.type ?? '',
          expiresAt: t.expiresAt ?? '',
          section: Array.isArray(t.section)
            ? t.section.join(', ')
            : (t.section ?? ''),
          domains: Array.isArray(t.domains)
            ? t.domains.join(', ')
            : (t.domains ?? ''),
          location: t.location ?? '',
          used_by: t.used_by ?? '',
          issuer: t.issuer ?? '',
          serial_number: t.serial_number ?? '',
          subject: t.subject ?? '',
          key_size: t.key_size ?? '',
          algorithm: t.algorithm ?? '',
          license_type: t.license_type ?? '',
          vendor: t.vendor ?? '',
          cost: t.cost ?? '',
          renewal_url: t.renewal_url ?? '',
          renewal_date: t.renewal_date ?? '',
          contacts: t.contacts ?? '',
          description: t.description ?? '',
          notes: t.notes ?? '',
          privileges: t.privileges ?? '',
          last_used: t.last_used ?? '',
          imported_at: t.imported_at ?? '',
          created_at: t.created_at ?? '',
          contact_group_id: t.contact_group_id ?? '',
        }));
        const escape = v => {
          const s = String(v == null ? '' : v);
          if (/[",\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
          return s;
        };
        const lines = [header.join(',')].concat(
          rows.map(r => header.map(h => escape(r[h])).join(','))
        );
        const blob = new Blob([lines.join('\n')], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${fileBase}.csv`;
        a.click();
        URL.revokeObjectURL(url);
        return;
      }

      if (format === 'xlsx') {
        const XLSX = await import(
          /* @vite-ignore */ 'https://esm.sh/xlsx@0.18.5'
        );
        const rows = currentTokens.map(t => ({
          name: t.name ?? '',
          category: t.category ?? '',
          type: t.type ?? '',
          expiresAt: t.expiresAt ?? '',
          section: Array.isArray(t.section)
            ? t.section.join(', ')
            : (t.section ?? ''),
          domains: Array.isArray(t.domains)
            ? t.domains.join(', ')
            : (t.domains ?? ''),
          location: t.location ?? '',
          used_by: t.used_by ?? '',
          issuer: t.issuer ?? '',
          serial_number: t.serial_number ?? '',
          subject: t.subject ?? '',
          key_size: t.key_size ?? '',
          algorithm: t.algorithm ?? '',
          license_type: t.license_type ?? '',
          vendor: t.vendor ?? '',
          cost: t.cost ?? '',
          renewal_url: t.renewal_url ?? '',
          renewal_date: t.renewal_date ?? '',
          contacts: t.contacts ?? '',
          description: t.description ?? '',
          notes: t.notes ?? '',
          privileges: t.privileges ?? '',
          last_used: t.last_used ?? '',
          imported_at: t.imported_at ?? '',
          created_at: t.created_at ?? '',
          contact_group_id: t.contact_group_id ?? '',
        }));
        const header = [
          'name',
          'category',
          'type',
          'expiresAt',
          'section',
          'domains',
          'location',
          'used_by',
          'issuer',
          'serial_number',
          'subject',
          'key_size',
          'algorithm',
          'license_type',
          'vendor',
          'cost',
          'renewal_url',
          'renewal_date',
          'contacts',
          'description',
          'notes',
          'privileges',
          'last_used',
          'imported_at',
          'created_at',
          'contact_group_id',
        ];
        const ws = XLSX.utils.json_to_sheet(rows, { header });
        const wb = XLSX.utils.book_new();
        XLSX.utils.book_append_sheet(wb, ws, 'Tokens');
        const wbout = XLSX.write(wb, { type: 'array', bookType: 'xlsx' });
        const blob = new Blob([wbout], {
          type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${fileBase}.xlsx`;
        a.click();
        URL.revokeObjectURL(url);
      }
    } catch (_) {}
  };

  // Move useColorModeValue calls outside of map functions

  // Guard against missing optional callbacks to avoid ReferenceError in production bundles
  const safeFetchGlobalFacets = useMemo(
    () =>
      typeof fetchGlobalFacets === 'function' ? fetchGlobalFacets : () => {},
    [fetchGlobalFacets]
  );
  const _safeFetchTokensForCategoryReset =
    typeof fetchTokensForCategoryReset === 'function'
      ? fetchTokensForCategoryReset
      : async () => {};

  const activePanelSection = panelQueries?.__section || '__all__';

  // Keep category badge counts in sync when section chip changes
  useEffect(() => {
    try {
      safeFetchGlobalFacets({ section: activePanelSection });
    } catch (_) {}
  }, [activePanelSection, safeFetchGlobalFacets]);

  // Refresh facets on event
  useEffect(() => {
    const handler = () => {
      try {
        safeFetchGlobalFacets({ section: activePanelSection });
      } catch (_) {}
    };
    window.addEventListener('tt:tokens-imported', handler);
    return () => window.removeEventListener('tt:tokens-imported', handler);
  }, [activePanelSection, safeFetchGlobalFacets]);

  const categoryByValue = useMemo(
    () =>
      TOKEN_CATEGORIES.reduce((acc, category) => {
        acc[category.value] = category;
        return acc;
      }, {}),
    [TOKEN_CATEGORIES]
  );

  const selectedCategoryValues = useMemo(
    () => (Array.isArray(selectedCategories) ? selectedCategories : []),
    [selectedCategories]
  );

  const allLoadedTokens = useMemo(() => {
    const dedupe = new Map();
    const source = Array.isArray(tokens) ? tokens.filter(Boolean) : [];
    for (const token of source) {
      const key =
        token.id ??
        token._id ??
        `${token.name}-${token.category}-${token.type}-${token.expiresAt}`;
      dedupe.set(String(key), token);
    }
    return Array.from(dedupe.values());
  }, [tokens]);

  const dashboardSummary = useMemo(() => {
    const totalFromCounts = Object.values(categoryCounts || {}).reduce(
      (sum, count) => sum + (Number(count) || 0),
      0
    );
    const total = Math.max(totalFromCounts, allLoadedTokens.length);
    let expiring7 = 0;
    let expiring30 = 0;
    let critical = 0;
    let expired = 0;
    let healthy = 0;

    for (const token of allLoadedTokens) {
      const days = getDaysUntilExpiration(token.expiresAt);
      if (days < 0) {
        expired += 1;
        critical += 1;
      } else if (days <= 7) {
        expiring7 += 1;
        critical += 1;
      } else if (days <= 30) {
        expiring30 += 1;
      } else {
        healthy += 1;
      }
    }

    return {
      total,
      expiring7,
      expiring30,
      critical,
      expired,
      healthy,
      dueSoon: expiring7 + expiring30,
    };
  }, [allLoadedTokens, categoryCounts]);

  const providerSummary = useMemo(() => {
    const providers = new Map();
    for (const token of allLoadedTokens) {
      const provider = String(getTokenProvider(token) || 'manual').trim();
      const key = provider.toLowerCase();
      if (!providers.has(key)) {
        providers.set(key, {
          name: provider === 'manual' ? 'Manual entries' : provider,
          count: 0,
        });
      }
      providers.get(key).count += 1;
    }
    return Array.from(providers.values()).sort(
      (a, b) => b.count - a.count || a.name.localeCompare(b.name)
    );
  }, [allLoadedTokens]);

  const visibleTokens = useMemo(() => {
    const sectionParam = panelQueries?.__section || '__all__';
    const dashboardSearch = panelQueries?.__global || '';
    const selected =
      selectedCategoryValues.length > 0
        ? selectedCategoryValues
        : TOKEN_CATEGORIES.map(category => category.value);
    const dedupe = new Map();

    for (const categoryValue of selected) {
      const category = categoryByValue[categoryValue];
      if (!category) continue;
      const categoryTokens = getFilteredAndSortedTokens(
        tokens,
        category,
        dashboardSearch,
        sectionParam
      );
      for (const token of categoryTokens) {
        const status = getDashboardStatusMeta(token.expiresAt).key;
        const matchesStatus =
          statusFilter === 'all' ||
          statusFilter === status ||
          (statusFilter === 'due' && status === 'due-soon') ||
          (statusFilter === 'critical' &&
            (status === 'critical' || status === 'expired')) ||
          (statusFilter === 'healthy' && status === 'healthy');
        if (matchesStatus) dedupe.set(String(token.id), token);
      }
    }

    return Array.from(dedupe.values()).sort(
      (a, b) =>
        getDaysUntilExpiration(a.expiresAt) -
          getDaysUntilExpiration(b.expiresAt) ||
        String(a.name || '').localeCompare(String(b.name || ''))
    );
  }, [
    TOKEN_CATEGORIES,
    categoryByValue,
    getFilteredAndSortedTokens,
    panelQueries,
    selectedCategoryValues,
    statusFilter,
    tokens,
  ]);

  const statusFilterOptions = useMemo(
    () => [
      {
        value: 'all',
        label: 'All',
        count: dashboardSummary.total,
        color: '#3b82f6',
      },
      {
        value: 'critical',
        label: 'Critical',
        count: dashboardSummary.critical,
        color: '#ef4444',
      },
      {
        value: 'due',
        label: 'Due Soon',
        count: dashboardSummary.expiring30,
        color: '#f97316',
      },
      {
        value: 'healthy',
        label: 'Healthy',
        count: dashboardSummary.healthy,
        color: '#22c55e',
      },
      {
        value: 'expired',
        label: 'Expired',
        count: dashboardSummary.expired,
        color: '#64748b',
      },
    ],
    [dashboardSummary]
  );

  const categoryFilterOptions = useMemo(
    () =>
      TOKEN_CATEGORIES.map(cat => {
        const facetsCount = (
          globalFacets?.category ||
          tokenFacets?.category ||
          []
        ).find(f => String(f.category) === cat.value)?.c;
        const sectionActive =
          (panelQueries?.__section || '__all__') !== '__all__';

        const count =
          typeof facetsCount === 'number'
            ? facetsCount
            : sectionActive || selectedCategoryValues.length > 0
              ? (() => {
                  const sec = panelQueries?.__section;
                  const norm = v =>
                    String(v || '')
                      .trim()
                      .toLowerCase();
                  if (sec === '__none__') {
                    return allLoadedTokens.filter(
                      t =>
                        t.category === cat.value &&
                        (!t.section ||
                          (Array.isArray(t.section) &&
                            t.section.length === 0) ||
                          String(t.section).trim() === '')
                    ).length;
                  }
                  const wantedList =
                    (sec || '__all__') === '__all__'
                      ? []
                      : String(sec)
                          .split(',')
                          .map(s => norm(s))
                          .filter(Boolean);

                  return allLoadedTokens.filter(t => {
                    if (t.category !== cat.value) return false;
                    if (wantedList.length === 0) return true;
                    const tokenSections = Array.isArray(t.section)
                      ? t.section.map(s => norm(s))
                      : [norm(t.section)];
                    return wantedList.every(w => tokenSections.includes(w));
                  }).length;
                })()
              : typeof categoryCounts?.[cat.value] === 'number'
                ? categoryCounts[cat.value]
                : 0;

        return {
          ...cat,
          count,
          active: selectedCategoryValues.includes(cat.value),
        };
      }),
    [
      TOKEN_CATEGORIES,
      allLoadedTokens,
      categoryCounts,
      globalFacets,
      panelQueries,
      selectedCategoryValues,
      tokenFacets,
    ]
  );

  const sectionFilterOptions = useMemo(() => {
    const norm = v =>
      String(v || '')
        .trim()
        .toLowerCase();
    const splitAndTrim = val =>
      String(val || '')
        .split(',')
        .map(s => s.trim())
        .filter(Boolean);

    const facetSource = globalFacets?.section || tokenFacets?.section || [];
    const rawMap = {};

    facetSource.forEach(row => {
      const labels = splitAndTrim(row.section);
      if (labels.length === 0) {
        const key = '';
        if (!rawMap[key]) rawMap[key] = { name: '', count: 0 };
        rawMap[key].count += row.c || 0;
        return;
      }
      labels.forEach(label => {
        const key = norm(label);
        if (!rawMap[key]) rawMap[key] = { name: label, count: 0 };
        rawMap[key].count = Math.max(rawMap[key].count, row.c || 0);
      });
    });

    try {
      allLoadedTokens.forEach(token => {
        if (
          selectedCategoryValues.length > 0 &&
          !selectedCategoryValues.includes(token.category)
        ) {
          return;
        }

        const currentSection = panelQueries?.__section || '__all__';
        if (currentSection !== '__all__') {
          const tokenSections = Array.isArray(token.section)
            ? token.section.map(s => norm(s))
            : [norm(token.section)];

          if (currentSection === '__none__') {
            if (
              token.section &&
              (!Array.isArray(token.section) || token.section.length > 0)
            ) {
              return;
            }
          } else {
            const wanted = currentSection
              .split(',')
              .map(s => norm(s))
              .filter(Boolean);
            if (!wanted.every(w => tokenSections.includes(w))) return;
          }
        }

        const labels = Array.isArray(token.section)
          ? token.section.flatMap(s => splitAndTrim(s))
          : splitAndTrim(token.section);

        if (labels.length === 0) {
          const key = '';
          if (!rawMap[key]) rawMap[key] = { name: '', count: 0 };
          return;
        }

        const uniqueInToken = [...new Set(labels.map(s => norm(s)))];
        uniqueInToken.forEach(key => {
          const originalLabel = labels.find(s => norm(s) === key);
          if (!rawMap[key]) {
            rawMap[key] = { name: originalLabel, count: 0 };
          }
        });
      });
    } catch (_) {}

    const raw = Object.values(rawMap);
    raw.sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));

    const allCount =
      selectedCategoryValues.length > 0
        ? selectedCategoryValues.reduce(
            (sum, cat) => sum + (categoryCounts?.[cat] || 0),
            0
          )
        : Object.values(categoryCounts || {}).reduce(
            (sum, count) => sum + (count || 0),
            0
          );

    return [
      {
        name: '__all__',
        label: 'All sections',
        count: allCount,
        scheme: 'blue',
      },
      {
        name: '__none__',
        label: 'No section',
        count: rawMap['']?.count || 0,
        scheme: 'gray',
      },
      ...raw
        .filter(section => (section.name || '').length > 0 && section.count > 0)
        .map(section => ({
          name: section.name,
          label: section.name,
          count: section.count,
          scheme: _getSectionColorScheme(section.name),
        })),
    ];
  }, [
    allLoadedTokens,
    categoryCounts,
    globalFacets,
    panelQueries,
    selectedCategoryValues,
    tokenFacets,
  ]);

  const requestAssetSort = useCallback(key => {
    const nextSort = {
      key,
      direction:
        assetSort.key === key && assetSort.direction === 'asc' ? 'desc' : 'asc',
    };
    setAssetSort(nextSort);
    setAssetPage(1);

    const serverSortByKey = {
      expiresAt:
        nextSort.direction === 'asc' ? 'expiration_asc' : 'expiration_desc',
      last_used:
        nextSort.direction === 'asc' ? 'last_used_asc' : 'last_used_desc',
      name: 'name_asc',
    };
    const nextServerSort = serverSortByKey[key];
    if (nextServerSort && typeof _setServerSort === 'function') {
      _setServerSort(nextServerSort);
    }
  }, [assetSort, _setServerSort]);

  const sortedVisibleTokens = useMemo(() => {
    const getTypeLabel = token => {
      const category = categoryByValue[token.category];
      const type = category?.types?.find(t => t.value === token.type);
      return type?.label || token.type || '';
    };
    const getSortValue = token => {
      if (assetSort.key === 'category') {
        return categoryByValue[token.category]?.label || token.category || '';
      }
      if (assetSort.key === 'type') return getTypeLabel(token);
      if (assetSort.key === 'location') return getTokenLocation(token);
      if (assetSort.key === 'owner') return getTokenOwner(token);
      if (assetSort.key === 'last_used') {
        return token.last_used ? new Date(token.last_used).getTime() : 0;
      }
      if (assetSort.key === 'expiresAt') {
        return getDaysUntilExpiration(token.expiresAt);
      }
      if (assetSort.key === 'status') {
        return getDashboardStatusMeta(token.expiresAt).key;
      }
      return token.name || '';
    };

    return visibleTokens.slice().sort((a, b) => {
      const aValue = getSortValue(a);
      const bValue = getSortValue(b);
      const direction = assetSort.direction === 'asc' ? 1 : -1;

      if (typeof aValue === 'number' && typeof bValue === 'number') {
        return (aValue - bValue) * direction;
      }

      return (
        String(aValue).localeCompare(String(bValue), undefined, {
          numeric: true,
          sensitivity: 'base',
        }) * direction
      );
    });
  }, [assetSort, categoryByValue, visibleTokens]);

  const assetPageCount = Math.max(
    1,
    Math.ceil(sortedVisibleTokens.length / assetPageSize)
  );

  useEffect(() => {
    setAssetPage(page => Math.min(Math.max(page, 1), assetPageCount));
  }, [assetPageCount]);

  const paginatedVisibleTokens = useMemo(() => {
    const start = (assetPage - 1) * assetPageSize;
    return sortedVisibleTokens.slice(start, start + assetPageSize);
  }, [assetPage, assetPageSize, sortedVisibleTokens]);

  const assetRangeStart =
    sortedVisibleTokens.length === 0 ? 0 : (assetPage - 1) * assetPageSize + 1;
  const assetRangeEnd = Math.min(
    assetPage * assetPageSize,
    sortedVisibleTokens.length
  );

  const selectedVisibleTokenIds = useMemo(() => {
    const visibleIds = new Set(paginatedVisibleTokens.map(token => token.id));
    return selectedTokenIds.filter(id => visibleIds.has(id));
  }, [paginatedVisibleTokens, selectedTokenIds]);

  const loadMoreCategories = useMemo(
    () =>
      TOKEN_CATEGORIES.filter(category => categoryHasMore?.[category.value]),
    [TOKEN_CATEGORIES, categoryHasMore]
  );

  const getAssetTypeLabel = useCallback(
    token => {
      const category = categoryByValue[token?.category];
      const type = category?.types?.find(t => t.value === token?.type);
      return type?.label || token?.type || '-';
    },
    [categoryByValue]
  );

  const getCategoryLabel = useCallback(
    token => categoryByValue[token?.category]?.label || token?.category || '-',
    [categoryByValue]
  );

  const renderAssetPaginationControls = () => (
    <Flex
      align={{ base: 'stretch', md: 'center' }}
      justify={{ base: 'space-between', md: 'end' }}
      direction={{ base: 'column', sm: 'row' }}
      gap={3}
      flex='1'
      minW={0}
    >
      <HStack spacing={2}>
        <Text color={mutedTextColor} fontSize='sm'>
          Show
        </Text>
        <Select
          size='sm'
          w='84px'
          value={assetPageSize}
          bg={inputBg}
          borderColor={inputBorder}
          onChange={event => {
            setAssetPageSize(Number(event.target.value));
            setAssetPage(1);
          }}
        >
          {ASSET_PAGE_SIZE_OPTIONS.map(size => (
            <option key={size} value={size}>
              {size}
            </option>
          ))}
        </Select>
      </HStack>

      <HStack spacing={3} justify={{ base: 'space-between', sm: 'end' }}>
        <Text color={mutedTextColor} fontSize='sm' whiteSpace='nowrap'>
          {assetRangeStart}-{assetRangeEnd} of {sortedVisibleTokens.length}
        </Text>
        <HStack spacing={1}>
          <IconButton
            aria-label='Previous assets page'
            icon={<FiChevronRight />}
            size='sm'
            variant='ghost'
            color='rgba(203, 213, 225, 0.9)'
            isDisabled={assetPage <= 1}
            onClick={() => setAssetPage(page => Math.max(1, page - 1))}
            sx={{ svg: { transform: 'rotate(180deg)' } }}
            _hover={{ bg: 'rgba(30, 41, 59, 0.72)', color: 'white' }}
          />
          <Button
            size='sm'
            variant='outline'
            borderColor='rgba(59, 130, 246, 0.38)'
            color='white'
            bg='rgba(37, 99, 235, 0.18)'
            minW='38px'
          >
            {assetPage}
          </Button>
          <IconButton
            aria-label='Next assets page'
            icon={<FiChevronRight />}
            size='sm'
            variant='ghost'
            color='rgba(203, 213, 225, 0.9)'
            isDisabled={assetPage >= assetPageCount}
            onClick={() =>
              setAssetPage(page => Math.min(assetPageCount, page + 1))
            }
            _hover={{ bg: 'rgba(30, 41, 59, 0.72)', color: 'white' }}
          />
        </HStack>
      </HStack>
    </Flex>
  );

  const attentionTokens = useMemo(
    () =>
      allLoadedTokens
        .filter(token => {
          const days = getDaysUntilExpiration(token.expiresAt);
          return days < 0 || days <= 31;
        })
        .sort(
          (a, b) =>
            getDaysUntilExpiration(a.expiresAt) -
            getDaysUntilExpiration(b.expiresAt)
        )
        .slice(0, 5),
    [allLoadedTokens]
  );

  const healthSegments = useMemo(() => {
    const total = Math.max(dashboardSummary.total, 1);
    const healthyPercent = (dashboardSummary.healthy / total) * 100;
    const duePercent = (dashboardSummary.expiring30 / total) * 100;
    const criticalPercent =
      (Math.max(dashboardSummary.critical - dashboardSummary.expired, 0) /
        total) *
      100;
    const expiredPercent = (dashboardSummary.expired / total) * 100;
    return {
      healthyPercent,
      duePercent,
      criticalPercent,
      expiredPercent,
      gradient: `conic-gradient(#22c55e 0 ${healthyPercent}%, #f97316 ${healthyPercent}% ${
        healthyPercent + duePercent
      }%, #ef4444 ${healthyPercent + duePercent}% ${
        healthyPercent + duePercent + criticalPercent
      }%, #64748b ${healthyPercent + duePercent + criticalPercent}% 100%)`,
    };
  }, [dashboardSummary]);

  const navigateToDashboard = () => {
    try {
      const search = new URLSearchParams(window.location.search);
      search.delete('view');
      const qs = search.toString();
      navigate(`/dashboard${qs ? `?${qs}` : ''}`, { replace: true });
    } catch (_) {}
  };

  const renderDashboardSidebar = () => {
    const menuItems = [
      {
        key: 'tokens',
        label: 'Tokens',
        icon: Layers,
        active: true,
        onClick: navigateToDashboard,
      },
      ...(dashboardCanSeeManagerNav
        ? [
            {
              key: 'usage',
              label: 'Usage',
              icon: Gauge,
              onClick: () => navigate('/usage'),
            },
            {
              key: 'docs',
              label: 'Docs',
              icon: BookOpen,
              href: 'https://tokentimer.ch/docs#self-hosted',
            },
            {
              key: 'audit',
              label: 'Audit',
              icon: ActivityIcon,
              onClick: () => navigate('/audit'),
            },
            {
              key: 'workspaces',
              label: 'Workspaces',
              icon: Building2,
              onClick: () => navigate('/workspaces'),
            },
          ]
        : [
            {
              key: 'docs',
              label: 'Docs',
              icon: BookOpen,
              href: 'https://tokentimer.ch/docs#self-hosted',
            },
          ]),
      ...(isSystemAdmin
        ? [
            {
              key: 'system',
              label: 'System',
              icon: Settings,
              onClick: () => navigate('/system-settings'),
            },
          ]
        : []),
    ];

    return (
      <Box
        as='aside'
        display={{ base: 'none', lg: 'flex' }}
        flex={`0 0 ${dashboardSidebarWidthPx}`}
        w={dashboardSidebarWidthPx}
        h='100vh'
        minH='100vh'
        maxH='100vh'
        position='fixed'
        top='0'
        bottom='0'
        left='0'
        zIndex={20}
        flexDirection='column'
        bg={DASHBOARD_PAGE_BG}
        borderRight='1px solid'
        borderColor='rgba(148, 163, 184, 0.13)'
        overflow='hidden'
        transition='width 160ms ease, flex-basis 160ms ease'
      >
        <VStack
          align={isDashboardSidebarExpanded ? 'stretch' : 'center'}
          spacing={2}
          flex='1'
          h='100%'
          minH={0}
          px={isDashboardSidebarExpanded ? 3 : 2}
          py={3}
        >
          <Tooltip
            label={
              isDashboardSidebarExpanded ? 'Collapse menu' : 'Expand menu'
            }
            placement='right'
            hasArrow
          >
            <IconButton
              type='button'
              aria-label={
                isDashboardSidebarExpanded ? 'Collapse menu' : 'Expand menu'
              }
              icon={<FiMenu />}
              h='38px'
              w='38px'
              minW='38px'
              alignSelf={isDashboardSidebarExpanded ? 'flex-start' : 'center'}
              variant='ghost'
              bg='transparent'
              color='white'
              border='1px solid'
              borderColor='rgba(148, 163, 184, 0.12)'
              borderRadius='md'
              onClick={toggleDashboardSidebarWidth}
              _hover={{ bg: 'rgba(37, 99, 235, 0.18)', color: 'white' }}
            />
          </Tooltip>

          <Divider
            w={isDashboardSidebarExpanded ? '100%' : '32px'}
            borderColor='rgba(148, 163, 184, 0.14)'
            my={1}
          />

          <VStack
            as='nav'
            aria-label='Dashboard navigation'
            align={isDashboardSidebarExpanded ? 'stretch' : 'center'}
            spacing={2}
            flex='0 0 auto'
            w='100%'
          >
            {menuItems.map(item => {
              const Icon = item.icon;
              const navControl = isDashboardSidebarExpanded ? (
                <Button
                  as={item.href ? 'a' : 'button'}
                  href={item.href}
                  target={item.href ? '_blank' : undefined}
                  rel={item.href ? 'noopener noreferrer' : undefined}
                  aria-label={item.label}
                  leftIcon={<Icon size={17} />}
                  h='38px'
                  w='100%'
                  minW='0'
                  px={3}
                  justifyContent='flex-start'
                  borderRadius='md'
                  variant='ghost'
                  color={item.active ? 'white' : 'rgba(203, 213, 225, 0.84)'}
                  bg={
                    item.active ? 'rgba(37, 99, 235, 0.26)' : 'transparent'
                  }
                  border='1px solid'
                  borderColor={
                    item.active ? 'rgba(59, 130, 246, 0.35)' : 'transparent'
                  }
                  fontSize='sm'
                  fontWeight='medium'
                  _hover={{
                    bg: item.active
                      ? 'rgba(37, 99, 235, 0.32)'
                      : 'rgba(30, 41, 59, 0.78)',
                    color: 'white',
                  }}
                  _active={{ bg: 'rgba(37, 99, 235, 0.3)' }}
                  onClick={item.onClick || undefined}
                >
                  <Text noOfLines={1}>{item.label}</Text>
                </Button>
              ) : (
                <IconButton
                  as={item.href ? 'a' : 'button'}
                  href={item.href}
                  target={item.href ? '_blank' : undefined}
                  rel={item.href ? 'noopener noreferrer' : undefined}
                  aria-label={item.label}
                  icon={<Icon size={18} />}
                  h='38px'
                  w='38px'
                  minW='38px'
                  borderRadius='md'
                  variant='ghost'
                  color={item.active ? 'white' : 'rgba(203, 213, 225, 0.84)'}
                  bg={
                    item.active ? 'rgba(37, 99, 235, 0.26)' : 'transparent'
                  }
                  border='1px solid'
                  borderColor={
                    item.active ? 'rgba(59, 130, 246, 0.35)' : 'transparent'
                  }
                  _hover={{
                    bg: item.active
                      ? 'rgba(37, 99, 235, 0.32)'
                      : 'rgba(30, 41, 59, 0.78)',
                    color: 'white',
                  }}
                  _active={{ bg: 'rgba(37, 99, 235, 0.3)' }}
                  onClick={item.onClick || undefined}
                />
              );
              return (
                <Tooltip
                  key={item.key}
                  label={item.label}
                  placement='right'
                  hasArrow
                  isDisabled={isDashboardSidebarExpanded}
                >
                  <Box>{navControl}</Box>
                </Tooltip>
              );
            })}
          </VStack>
        </VStack>
      </Box>
    );
  };

  const renderDashboardTopbar = () => (
    <Flex
      as='header'
      display={{ base: 'none', lg: 'flex' }}
      align='center'
      justify='space-between'
      gap={4}
      minH='54px'
      px={{ base: 4, lg: 6, '2xl': 8 }}
      py={2}
      bg={DASHBOARD_PAGE_BG}
      borderBottom='1px solid'
      borderColor='rgba(148, 163, 184, 0.13)'
      backdropFilter='blur(16px)'
    >
      <HStack spacing={3} minW={0}>
        <Circle
          size='32px'
          bg='rgba(37, 99, 235, 0.2)'
          color='#60a5fa'
          border='1px solid'
          borderColor='rgba(59, 130, 246, 0.4)'
        >
          <ShieldAlert size={18} />
        </Circle>
        <Text color='white' fontWeight='bold' fontSize='lg' noOfLines={1}>
          TokenTimer
        </Text>
      </HStack>

      <HStack spacing={3} display={{ base: 'none', md: 'flex' }} ml='auto'>
        <Menu placement='bottom-end'>
          <MenuButton
            as={Button}
            rightIcon={<ChevronDown size={15} />}
            h='36px'
            minW='260px'
            px={4}
            bg='rgba(8, 13, 22, 0.92)'
            border='1px solid'
            borderColor={DASHBOARD_BORDER_STRONG}
            color='white'
            fontSize='sm'
            fontWeight='medium'
            borderRadius='md'
            isDisabled={dashboardWorkspaces.length === 0}
            _hover={{ bg: 'rgba(15, 23, 42, 0.96)' }}
            _active={{ bg: 'rgba(15, 23, 42, 0.96)' }}
          >
            <HStack spacing={3} justify='space-between' minW={0}>
              <Text color={mutedTextColor} fontSize='xs' fontWeight='medium'>
                Workspace
              </Text>
              <Text color='white' fontSize='sm' fontWeight='semibold' noOfLines={1}>
                {dashboardWorkspace?.name || workspaceLabel}
              </Text>
            </HStack>
          </MenuButton>
          <Portal>
            <MenuList zIndex={1500} bg={menuBg} borderColor={menuBorder}>
              {dashboardWorkspaces.map(workspace => (
                <MenuItem
                  key={workspace.id}
                  onClick={() => handleDashboardWorkspaceSelect(workspace)}
                >
                  {workspace.name}
                </MenuItem>
              ))}
            </MenuList>
          </Portal>
        </Menu>

        <Menu placement='bottom-end'>
          <Box position='relative'>
            {dashboardNotifications.length > 0 && (
              <Box
                position='absolute'
                top='7px'
                right='8px'
                w='7px'
                h='7px'
                borderRadius='full'
                bg='#f87171'
                zIndex='2'
              />
            )}
            <MenuButton
              as={IconButton}
              aria-label='Notifications'
              icon={<FiBell />}
              size='sm'
              variant='ghost'
              color='rgba(203, 213, 225, 0.92)'
              borderRadius='md'
              _hover={{ bg: 'rgba(30, 41, 59, 0.72)', color: 'white' }}
            />
          </Box>
          <Portal>
            <MenuList
              zIndex={1500}
              bg={menuBg}
              borderColor={menuBorder}
              minW='280px'
            >
              {dashboardNotifications.length === 0 ? (
                <Box px={3} py={2}>
                  <Text fontSize='sm' color={mutedTextColor}>
                    No notifications
                  </Text>
                </Box>
              ) : (
                dashboardNotifications.map(notification => {
                  const isClickable = Boolean(notification?.href);
                  return (
                    <MenuItem
                      key={notification.id}
                      onClick={() => {
                        if (notification?.href) navigate(notification.href);
                      }}
                      cursor={isClickable ? 'pointer' : 'default'}
                      _hover={{
                        bg: isClickable
                          ? 'rgba(30, 41, 59, 0.72)'
                          : 'transparent',
                      }}
                    >
                      <VStack align='start' spacing={0}>
                        <Text color='white' fontSize='sm' fontWeight='medium'>
                          {notification.text}
                        </Text>
                        <Text color={mutedTextColor} fontSize='xs'>
                          {isClickable
                            ? 'Open related settings'
                            : 'No action available'}
                        </Text>
                      </VStack>
                    </MenuItem>
                  );
                })
              )}
            </MenuList>
          </Portal>
        </Menu>
        <IconButton
          aria-label='Toggle color mode'
          icon={<Moon size={17} />}
          size='sm'
          variant='ghost'
          color='rgba(203, 213, 225, 0.92)'
          borderRadius='md'
          _hover={{ bg: 'rgba(30, 41, 59, 0.72)', color: 'white' }}
          onClick={toggleColorMode}
        />

        <Menu placement='bottom-end'>
          <MenuButton
            as={Button}
            variant='ghost'
            rightIcon={<ChevronDown size={15} />}
            h='40px'
            px={2}
            color='white'
            _hover={{ bg: 'rgba(30, 41, 59, 0.72)' }}
            _active={{ bg: 'rgba(30, 41, 59, 0.72)' }}
          >
            <HStack spacing={3}>
              <Circle size='34px' bg='#2563eb' color='white' fontSize='sm'>
                {sessionInitials || 'U'}
              </Circle>
              <Box textAlign='left' minW={0} display={{ base: 'none', xl: 'block' }}>
                <Text color='white' fontSize='sm' fontWeight='semibold' noOfLines={1}>
                  {sessionName}
                </Text>
                <Text color={mutedTextColor} fontSize='xs' noOfLines={1}>
                  {sessionEmail}
                </Text>
              </Box>
            </HStack>
          </MenuButton>
          <Portal>
            <MenuList zIndex={1500} bg={menuBg} borderColor={menuBorder}>
              <MenuItem icon={<User size={15} />} onClick={onAccountClick}>
                Account Settings
              </MenuItem>
              {!isViewer && (
                <MenuItem
                  icon={<Settings size={15} />}
                  onClick={() => navigate('/preferences')}
                >
                  Preferences
                </MenuItem>
              )}
              <MenuItem icon={<LogOut size={15} />} onClick={onLogout}>
                Sign Out
              </MenuItem>
            </MenuList>
          </Portal>
        </Menu>
      </HStack>
    </Flex>
  );

  const renderDashboardWorkspace = () => (
    <VStack spacing={3} align='stretch' minW={0}>
        <DashboardPanel title='Asset Inventory'>
          <VStack spacing={3} align='stretch'>
            <Flex
              gap={3}
              align={{ base: 'stretch', lg: 'center' }}
              justify='space-between'
              direction={{ base: 'column', lg: 'row' }}
            >
              <InputGroup maxW={{ base: '100%', lg: '360px' }} size='sm'>
                <InputLeftElement pointerEvents='none' h='32px'>
                  <Search size={16} color='rgba(148, 163, 184, 0.86)' />
                </InputLeftElement>
                <Input
                  value={panelQueries.__global || ''}
                  onChange={event => {
                    const nextValue = event.target.value;
                    setPanelQueries(prev => ({
                      ...prev,
                      __global: nextValue,
                    }));
                    if (typeof _setSearchQuery === 'function') {
                      _setSearchQuery(nextValue);
                    }
                    setAssetPage(1);
                  }}
                  placeholder='Search assets, domains, owners...'
                  size='sm'
                  bg={inputBg}
                  borderColor={inputBorder}
                  borderRadius='md'
                  pl='36px'
                  _placeholder={{ color: placeholderColor }}
                />
              </InputGroup>
              <HStack spacing={2} flexWrap='wrap'>
                {statusFilterOptions.map(option => {
                  const active = statusFilter === option.value;
                  return (
                    <Button
                      key={option.value}
                      size='xs'
                      variant='outline'
                      borderRadius='md'
                      borderColor={
                        active ? option.color : 'rgba(148, 163, 184, 0.2)'
                      }
                      bg={
                        active
                          ? `${option.color}24`
                          : 'rgba(15, 23, 42, 0.58)'
                      }
                      color={active ? 'white' : 'rgba(203, 213, 225, 0.9)'}
                      _hover={{
                        bg: active
                          ? `${option.color}30`
                          : 'rgba(30, 41, 59, 0.74)',
                      }}
                      onClick={() => {
                        setStatusFilter(option.value);
                        setAssetPage(1);
                      }}
                    >
                      <Circle size='7px' bg={option.color} mr={2} />
                      {option.label}
                      <Badge ml={2} bg='whiteAlpha.200' color='inherit'>
                        {option.count}
                      </Badge>
                    </Button>
                  );
                })}
              </HStack>
            </Flex>

            <Divider borderColor='rgba(148, 163, 184, 0.12)' />

            <Box>
              <Text fontSize='xs' color={filterLabelColor} mb={2}>
                Category
              </Text>
              <HStack spacing={2} flexWrap='wrap'>
                {categoryFilterOptions.map(category => {
                  const { active } = category;
                  const visual = getCategoryVisual(category.value);
                  const VisualIcon = visual.icon;
                  return (
                    <Button
                      key={category.value}
                      size='sm'
                      variant='outline'
                      borderRadius='md'
                      borderColor={
                        active ? visual.color : `${visual.color}55`
                      }
                      bg={
                        active
                          ? visual.bg
                          : `${visual.color}12`
                      }
                      color={active ? 'white' : 'rgba(203, 213, 225, 0.9)'}
                      fontWeight='medium'
                      _hover={{
                        bg: active
                          ? `${visual.color}26`
                          : `${visual.color}18`,
                        borderColor: visual.color,
                      }}
                      onClick={() => {
                        setSelectedCategories(active ? [] : [category.value]);
                        setAssetPage(1);
                      }}
                    >
                      <Box as='span' color={visual.color} display='inline-flex'>
                        <VisualIcon size={15} />
                      </Box>
                      <Text as='span' ml={2}>
                        {category.label}
                      </Text>
                      <Badge ml={2} bg='whiteAlpha.200' color='inherit'>
                        {category.count}
                      </Badge>
                    </Button>
                  );
                })}
              </HStack>
            </Box>

            <Box>
              <Text fontSize='xs' color={filterLabelColor} mb={2}>
                Sections
              </Text>
              <HStack spacing={2} flexWrap='wrap'>
                {sectionFilterOptions.map(section => {
                  const current = panelQueries.__section || '__all__';
                  const accent = getSectionAccent(section);
                  let active = false;
                  if (section.name === '__all__') {
                    active = current === '__all__';
                  } else if (section.name === '__none__') {
                    active = current === '__none__';
                  } else {
                    active = current.split(',').includes(section.name);
                  }
                  return (
                    <Button
                      key={`section-${section.name || 'none'}`}
                      size='sm'
                      variant='outline'
                      borderRadius='md'
                      fontWeight='medium'
                      bg={
                        active
                          ? `${accent}22`
                          : `${accent}10`
                      }
                      color={active ? 'white' : 'rgba(203, 213, 225, 0.9)'}
                      borderColor={
                        active
                          ? accent
                          : `${accent}55`
                      }
                      _hover={{
                        bg: active ? `${accent}28` : `${accent}16`,
                        borderColor: accent,
                      }}
                      onClick={() => {
                        const currentVal = panelQueries?.__section || '__all__';
                        let next;

                        if (section.name === '__all__') {
                          next = '__all__';
                        } else if (section.name === '__none__') {
                          next = '__none__';
                        } else {
                          let parts =
                            currentVal === '__all__' ||
                            currentVal === '__none__'
                              ? []
                              : currentVal.split(',').filter(Boolean);

                          if (parts.includes(section.name)) {
                            parts = parts.filter(
                              part => part !== section.name
                            );
                          } else {
                            parts.push(section.name);
                          }

                          next = parts.length > 0 ? parts.join(',') : '__all__';
                        }

                        setPanelQueries(prev => ({ ...prev, __section: next }));
                        setAssetPage(1);
                        try {
                          const search = new URLSearchParams(
                            window.location.search
                          );
                          if (next === '__all__') search.delete('section');
                          else search.set('section', next);
                          const qs = search.toString();
                          navigate(`/dashboard${qs ? `?${qs}` : ''}`, {
                            replace: true,
                          });
                        } catch (_) {}
                      }}
                    >
                      <Circle size='7px' bg={accent} mr={2} />
                      {section.label}
                      <Badge ml={2} bg='whiteAlpha.200' color='inherit'>
                        {section.count}
                      </Badge>
                    </Button>
                  );
                })}
              </HStack>
            </Box>
          </VStack>
        </DashboardPanel>

        <DashboardPanel
          title='Assets'
          data-tour='token-list'
          style={{
            transition: 'opacity 180ms ease, transform 180ms ease',
            opacity: isRefreshing ? 0.35 : 1,
            transform: isRefreshing ? 'scale(0.995)' : 'scale(1)',
          }}
        >
          <Flex
            align={{ base: 'stretch', md: 'center' }}
            justify='space-between'
            direction={{ base: 'column', lg: 'row' }}
            gap={3}
            mb={4}
          >
            <Text color={mutedTextColor} fontSize='sm' whiteSpace='nowrap'>
              {sortedVisibleTokens.length} visible
            </Text>
            {renderAssetPaginationControls()}
          </Flex>

          {!isViewer && selectedVisibleTokenIds.length > 0 && (
            <Flex
              mb={4}
              gap={3}
              align={{ base: 'stretch', md: 'center' }}
              justify='space-between'
              direction={{ base: 'column', md: 'row' }}
              p={3}
              bg='rgba(30, 41, 59, 0.58)'
              border='1px solid'
              borderColor='rgba(148, 163, 184, 0.16)'
              borderRadius='md'
            >
              <Text color='rgba(226, 232, 240, 0.92)' fontSize='sm'>
                {selectedVisibleTokenIds.length} asset(s) selected
              </Text>
              <HStack spacing={2} flexWrap='wrap'>
                <Button
                  size='xs'
                  colorScheme='red'
                  variant='outline'
                  leftIcon={<FiTrash2 />}
                  onClick={handleBulkDelete}
                >
                  Delete selected
                </Button>
                <Input
                  size='xs'
                  w='170px'
                  placeholder='Section label'
                  value={bulkSectionDrafts?.__dashboard || ''}
                  onChange={event =>
                    setBulkSectionDrafts(prev => ({
                      ...prev,
                      __dashboard: event.target.value,
                    }))
                  }
                  bg={inputBg}
                  borderColor={inputBorder}
                />
                <Button
                  size='xs'
                  colorScheme='blue'
                  variant='outline'
                  onClick={() =>
                    handleBulkAssignSection(
                      selectedVisibleTokenIds,
                      '__dashboard'
                    )
                  }
                >
                  Assign section
                </Button>
              </HStack>
            </Flex>
          )}

          {tokensLoading && tokens.length === 0 ? (
            <Flex justify='center' p={{ base: 4, md: 8 }} overflowX='hidden'>
              <AccessibleSpinner size='lg' aria-label='Loading tokens' />
            </Flex>
          ) : tokens.length === 0 ? (
            <Text
              textAlign='center'
              color={emptyTextColor}
              p={{ base: 4, md: 8 }}
            >
              {isViewer
                ? 'No tokens in this workspace.'
                : 'No tokens found. Create your first token above.'}
            </Text>
          ) : sortedVisibleTokens.length === 0 ? (
            <Text
              textAlign='center'
              color={emptyTextColor}
              p={{ base: 4, md: 8 }}
            >
              No assets match the current filters.
            </Text>
          ) : (
            <>
              <Box display={{ base: 'block', lg: 'none' }}>
                <VStack align='stretch' spacing={3}>
                  {paginatedVisibleTokens.map(token => {
                    const status = getDashboardStatusMeta(token.expiresAt);
                    const visual = getCategoryVisual(token.category);
                    const VisualIcon = visual.icon;
                    return (
                      <Box
                        key={token.id}
                        p={4}
                        bg={mobileCardBg}
                        border='1px solid'
                        borderColor='rgba(148, 163, 184, 0.16)'
                        borderRadius='md'
                      >
                        <HStack align='start' justify='space-between' gap={3}>
                          <HStack align='start' spacing={3} minW={0}>
                            {!isViewer && (
                              <Checkbox
                                mt={1}
                                isChecked={selectedTokenIds.includes(token.id)}
                                onChange={() => toggleTokenSelection(token.id)}
                              />
                            )}
                            <Circle
                              size='36px'
                              bg={visual.bg}
                              color={visual.color}
                              flex='0 0 auto'
                            >
                              <VisualIcon size={18} />
                            </Circle>
                            <Box minW={0}>
                              <Text
                                fontWeight='semibold'
                                color='white'
                                wordBreak='break-word'
                              >
                                {token.name}
                              </Text>
                              <Text color={secondaryTextColor} fontSize='sm'>
                                {getAssetTypeLabel(token)}
                              </Text>
                              <Text
                                color={mutedTextColor}
                                fontSize='xs'
                                noOfLines={1}
                              >
                                {getTokenLocation(token)}
                              </Text>
                            </Box>
                          </HStack>
                          <Badge bg={status.bg} color={status.color}>
                            {status.label}
                          </Badge>
                        </HStack>
                        <HStack spacing={2} flexWrap='wrap' mt={4}>
                          <Button
                            size='sm'
                            colorScheme='blue'
                            onClick={() => onOpenTokenModal(token)}
                          >
                            Details
                          </Button>
                          {!isViewer && (
                            <>
                              <Button
                                size='sm'
                                colorScheme='teal'
                                onClick={() => onOpenRenew(token)}
                              >
                                Renew
                              </Button>
                              <Button
                                size='sm'
                                colorScheme='red'
                                onClick={() => onDeleteToken(token.id)}
                              >
                                Delete
                              </Button>
                            </>
                          )}
                        </HStack>
                      </Box>
                    );
                  })}
                </VStack>
              </Box>

              <Box overflowX='auto' display={{ base: 'none', lg: 'block' }}>
                <Table variant='simple' size='sm'>
                  <Thead>
                    <Tr>
                      {!isViewer && (
                        <Th w='42px'>
                          <Checkbox
                            isChecked={
                              paginatedVisibleTokens.length > 0 &&
                              selectedVisibleTokenIds.length ===
                                paginatedVisibleTokens.length
                            }
                            isIndeterminate={
                              selectedVisibleTokenIds.length > 0 &&
                              selectedVisibleTokenIds.length <
                                paginatedVisibleTokens.length
                            }
                            onChange={event => {
                              const ids = paginatedVisibleTokens.map(
                                token => token.id
                              );
                              if (event.target.checked) {
                                setSelectedTokenIds(prev => [
                                  ...new Set([...prev, ...ids]),
                                ]);
                              } else {
                                setSelectedTokenIds(prev =>
                                  prev.filter(id => !ids.includes(id))
                                );
                              }
                            }}
                          />
                        </Th>
                      )}
                      {[
                        ['Name', 'name', '210px'],
                        ['Type', 'type', '160px'],
                        ['Domain / Location', 'location', '190px'],
                        ['Owner / Used By', 'owner', '170px'],
                        ['Last Used', 'last_used', '120px'],
                        ['Expiration', 'expiresAt', '130px'],
                        ['Status', 'status', '110px'],
                      ].map(([label, key, minW]) => (
                        <Th key={key} minW={minW}>
                          <Button
                            variant='ghost'
                            size='xs'
                            px={1}
                            color='rgba(148, 163, 184, 0.95)'
                            _hover={{
                              bg: 'rgba(30, 41, 59, 0.72)',
                              color: 'white',
                            }}
                            onClick={() => requestAssetSort(key)}
                          >
                            {label}
                            {assetSort.key === key && (
                              <Text
                                as='span'
                                ml={2}
                                fontSize='10px'
                                color='rgba(147, 197, 253, 0.96)'
                              >
                                {assetSort.direction === 'asc' ? 'Asc' : 'Desc'}
                              </Text>
                            )}
                          </Button>
                        </Th>
                      ))}
                      <Th textAlign='right' minW='116px'>
                        Actions
                      </Th>
                    </Tr>
                  </Thead>
                  <Tbody>
                    {paginatedVisibleTokens.map(token => {
                      const status = getDashboardStatusMeta(token.expiresAt);
                      const visual = getCategoryVisual(token.category);
                      const VisualIcon = visual.icon;
                      const location = getTokenLocation(token);
                      const isDomain =
                        token.category === 'cert' &&
                        Array.isArray(token.domains) &&
                        token.domains.length > 0;
                      return (
                        <Tr
                          key={token.id}
                          cursor='pointer'
                          _hover={{ bg: hoverBgColor }}
                          onClick={event => {
                            if (event.target.closest('button')) return;
                            if (event.target.closest('a')) return;
                            if (event.target.closest('input[type="checkbox"]'))
                              return;
                            onOpenTokenModal(token);
                          }}
                        >
                          {!isViewer && (
                            <Td onClick={event => event.stopPropagation()}>
                              <Checkbox
                                isChecked={selectedTokenIds.includes(token.id)}
                                onChange={() => toggleTokenSelection(token.id)}
                              />
                            </Td>
                          )}
                          <Td>
                            <HStack spacing={3} minW={0}>
                              <Circle
                                size='32px'
                                bg={visual.bg}
                                color={visual.color}
                                flex='0 0 auto'
                              >
                                <VisualIcon size={16} />
                              </Circle>
                              <Box minW={0}>
                                <Text
                                  color='white'
                                  fontWeight='medium'
                                  noOfLines={1}
                                >
                                  {token.name}
                                </Text>
                                <Text
                                  color={mutedTextColor}
                                  fontSize='xs'
                                  noOfLines={1}
                                >
                                  {getCategoryLabel(token)}
                                </Text>
                              </Box>
                            </HStack>
                          </Td>
                          <Td>
                            <TruncatedText
                              text={getAssetTypeLabel(token)}
                              maxLines={2}
                              maxWidth='150px'
                            />
                          </Td>
                          <Td>
                            {isDomain ? (
                              <HStack spacing={1} minW={0}>
                                <Link
                                  href={domainValueToUrl(location)}
                                  isExternal
                                  color='blue.300'
                                  fontSize='sm'
                                  noOfLines={1}
                                  onClick={event => event.stopPropagation()}
                                >
                                  {location}
                                </Link>
                                <FiExternalLink size={13} />
                                {token.domains.length > 1 && (
                                  <Text color={mutedTextColor} fontSize='xs'>
                                    +{token.domains.length - 1}
                                  </Text>
                                )}
                              </HStack>
                            ) : (
                              <TruncatedText
                                text={location}
                                maxLines={2}
                                maxWidth='180px'
                              />
                            )}
                          </Td>
                          <Td>
                            <TruncatedText
                              text={getTokenOwner(token)}
                              maxLines={2}
                              maxWidth='160px'
                            />
                          </Td>
                          <Td>
                            <Text color={mutedTextColor} fontSize='sm'>
                              {token.last_used
                                ? formatDate(token.last_used)
                                : '-'}
                            </Text>
                          </Td>
                          <Td>{formatExpirationDate(token.expiresAt)}</Td>
                          <Td>
                            <HStack spacing={2}>
                              <Badge
                                bg={status.bg}
                                color={status.color}
                                border='1px solid'
                                borderColor={`${status.color}44`}
                                borderRadius='md'
                                px={2}
                                py={1}
                              >
                                <HStack spacing={1}>
                                  <Circle size='6px' bg={status.color} />
                                  <Text as='span'>{status.label}</Text>
                                </HStack>
                              </Badge>
                              {token.monitor_health_status && (
                                <Tooltip
                                  label={`${
                                    token.monitor_url || 'Endpoint'
                                  }: ${token.monitor_health_status}${
                                    token.monitor_response_ms
                                      ? ` (${token.monitor_response_ms}ms)`
                                      : ''
                                  }`}
                                >
                                  <Box as='span' display='inline-flex'>
                                    <FiActivity
                                      size={16}
                                      color={
                                        token.monitor_health_status ===
                                        'healthy'
                                          ? '#22c55e'
                                          : token.monitor_health_status ===
                                              'error'
                                            ? '#e11d48'
                                            : '#ff6b00'
                                      }
                                    />
                                  </Box>
                                </Tooltip>
                              )}
                            </HStack>
                          </Td>
                          <Td textAlign='right'>
                            <HStack spacing={1} justify='flex-end'>
                              <Tooltip label='Details'>
                                <IconButton
                                  size='sm'
                                  variant='ghost'
                                  color='rgba(203, 213, 225, 0.9)'
                                  aria-label={`Show full details for token ${token.name}`}
                                  icon={<MoreVertical size={16} />}
                                  onClick={() => onOpenTokenModal(token)}
                                />
                              </Tooltip>
                              {!isViewer && (
                                <>
                                  <Tooltip label='Renew'>
                                    <IconButton
                                      size='sm'
                                      variant='ghost'
                                      color='rgba(45, 212, 191, 0.95)'
                                      aria-label={`Renew token ${token.name}`}
                                      icon={<CalendarClock size={16} />}
                                      onClick={() => onOpenRenew(token)}
                                    />
                                  </Tooltip>
                                  <Tooltip label='Delete'>
                                    <IconButton
                                      size='sm'
                                      variant='ghost'
                                      color='rgba(248, 113, 113, 0.95)'
                                      aria-label={`Delete token ${token.name}`}
                                      icon={<FiTrash2 />}
                                      onClick={() => onDeleteToken(token.id)}
                                    />
                                  </Tooltip>
                                </>
              )}
                            </HStack>
                          </Td>
                        </Tr>
                      );
                    })}
                  </Tbody>
                </Table>
              </Box>

              {loadMoreCategories.length > 0 && (
                <HStack spacing={2} flexWrap='wrap' justify='center' mt={4}>
                  {loadMoreCategories.map(category => (
                    <Button
                      key={category.value}
                      size='sm'
                      variant='outline'
                      borderColor='rgba(148, 163, 184, 0.22)'
                      color='rgba(226, 232, 240, 0.94)'
                      _hover={{ bg: 'rgba(30, 41, 59, 0.72)' }}
                      onClick={() => fetchTokensForCategory(category.value)}
                      isLoading={!!categoryLoading?.[category.value]}
                      loadingText='Loading...'
                    >
                      Load more {category.label}
                    </Button>
                  ))}
                </HStack>
              )}
            </>
          )}
        </DashboardPanel>

      <SimpleGrid columns={{ base: 1, xl: 3 }} spacing={3} alignItems='stretch'>
        <DashboardPanel title='Needs Attention'>
          {attentionTokens.length === 0 ? (
            <HStack spacing={3}>
              <Circle size='38px' bg='rgba(34, 197, 94, 0.14)' color='#22c55e'>
                <CheckCircle2 size={19} />
              </Circle>
              <Box>
                <Text color='white' fontSize='sm' fontWeight='medium'>
                  All clear
                </Text>
                <Text color={mutedTextColor} fontSize='xs'>
                  No assets are due soon.
                </Text>
              </Box>
            </HStack>
          ) : (
            <VStack align='stretch' spacing={3}>
              {attentionTokens.map(token => {
                const status = getDashboardStatusMeta(token.expiresAt);
                const AttentionIcon =
                  status.key === 'due-soon' ? Clock3 : AlertTriangle;
                return (
                  <HStack key={token.id} spacing={3} align='start'>
                    <Circle
                      size='38px'
                      bg={status.bg}
                      color={status.color}
                      flex='0 0 auto'
                    >
                      <AttentionIcon size={18} />
                    </Circle>
                    <Box minW={0} flex='1'>
                      <Text
                        color='white'
                        fontSize='sm'
                        fontWeight='medium'
                        noOfLines={1}
                      >
                        {token.name}
                      </Text>
                      <Text color={mutedTextColor} fontSize='xs' noOfLines={1}>
                        {getAssetTypeLabel(token)} - {getTokenOwner(token)}
                      </Text>
                    </Box>
                    <Text
                      color={status.color}
                      fontSize='xs'
                      fontWeight='bold'
                      textAlign='right'
                    >
                      {formatDaysUntil(token.expiresAt)}
                    </Text>
                  </HStack>
                );
              })}
            </VStack>
          )}
        </DashboardPanel>

        <DashboardPanel title='Asset Health Overview'>
          <HStack spacing={5} align='center'>
            <Circle
              size='112px'
              bg={healthSegments.gradient}
              boxShadow='0 0 0 1px rgba(148, 163, 184, 0.12) inset'
              flex='0 0 auto'
            >
              <Circle size='64px' bg='#0f172a'>
                <Text color='white' fontWeight='bold'>
                  {dashboardSummary.total}
                </Text>
              </Circle>
            </Circle>
            <VStack align='stretch' spacing={2} flex='1'>
              {[
                ['Healthy', dashboardSummary.healthy, '#22c55e'],
                ['Due Soon', dashboardSummary.expiring30, '#f97316'],
                [
                  'Critical',
                  Math.max(
                    dashboardSummary.critical - dashboardSummary.expired,
                    0
                  ),
                  '#ef4444',
                ],
                ['Expired', dashboardSummary.expired, '#64748b'],
              ].map(([label, count, color]) => (
                <Flex key={label} justify='space-between' gap={3} fontSize='sm'>
                  <HStack spacing={2} minW={0}>
                    <Circle size='8px' bg={color} />
                    <Text color={mutedTextColor}>{label}</Text>
                  </HStack>
                  <Text color='white' fontWeight='medium'>
                    {count} ({formatDashboardPercent(count, dashboardSummary.total)})
                  </Text>
                </Flex>
              ))}
            </VStack>
          </HStack>
        </DashboardPanel>

        <DashboardPanel title='Integration Sync Status'>
          {providerSummary.length === 0 ? (
            <Text color={emptyTextColor} fontSize='sm'>
              No integrations yet.
            </Text>
          ) : (
            <VStack align='stretch' spacing={3}>
              {providerSummary.slice(0, 5).map(provider => (
                <HStack key={provider.name} spacing={3}>
                  <Circle size='30px' bg='rgba(59, 130, 246, 0.14)' color='#60a5fa'>
                    <PlugZap size={15} />
                  </Circle>
                  <Box flex='1' minW={0}>
                    <Text color='white' fontSize='sm' noOfLines={1}>
                      {provider.name}
                    </Text>
                    <Text color={mutedTextColor} fontSize='xs'>
                      {provider.count} asset(s)
                    </Text>
                  </Box>
                  <CheckCircle2 size={16} color='#22c55e' />
                </HStack>
              ))}
            </VStack>
          )}
        </DashboardPanel>
      </SimpleGrid>
    </VStack>
  );

  return (
    <Box
      color={pageTextColor}
      minH='100vh'
      bg={DASHBOARD_PAGE_BG}
      sx={{
        '.chakra-form__label': { color: 'rgba(203, 213, 225, 0.9)' },
        '.chakra-table th': {
          color: 'rgba(148, 163, 184, 0.92)',
          borderColor: 'rgba(148, 163, 184, 0.14)',
          background: 'rgba(8, 13, 22, 0.84)',
          fontSize: '0.72rem',
          letterSpacing: '0',
          textTransform: 'none',
          paddingTop: '0.55rem',
          paddingBottom: '0.55rem',
        },
        '.chakra-table td': {
          color: 'rgba(226, 232, 240, 0.94)',
          borderColor: 'rgba(148, 163, 184, 0.1)',
          paddingTop: '0.55rem',
          paddingBottom: '0.55rem',
        },
        '.chakra-input, .chakra-select, .chakra-textarea': {
          color: 'rgba(248, 250, 252, 0.96)',
        },
        option: {
          background: '#0f172a',
          color: 'white',
        },
      }}
    >
      <Flex minH='100vh' align='stretch'>
        {renderDashboardSidebar()}
        <Box
          flex='1'
          minW={0}
          ml={{ base: 0, lg: dashboardSidebarWidthPx }}
          transition='margin-left 160ms ease'
        >
          {renderDashboardTopbar()}
          <Box px={{ base: 4, lg: 4, '2xl': 5 }} py={{ base: 5, lg: 3 }}>
      <SimpleGrid columns={{ base: 1, sm: 2, xl: 5 }} spacing={3} mb={3}>
        <MetricCard
          icon={Layers}
          label='Total Assets'
          value={dashboardSummary.total}
          detail='Across all sections'
          accent='#3b82f6'
        />
        <MetricCard
          icon={Clock3}
          label='Expiring in 7 days'
          value={dashboardSummary.expiring7}
          detail={`${dashboardSummary.total ? ((dashboardSummary.expiring7 / dashboardSummary.total) * 100).toFixed(1) : '0.0'}% of total`}
          accent='#f59e0b'
        />
        <MetricCard
          icon={CalendarClock}
          label='Expiring in 30 days'
          value={dashboardSummary.expiring30}
          detail={`${dashboardSummary.total ? ((dashboardSummary.expiring30 / dashboardSummary.total) * 100).toFixed(1) : '0.0'}% of total`}
          accent='#f97316'
        />
        <MetricCard
          icon={ShieldAlert}
          label='Critical / Expired'
          value={dashboardSummary.critical}
          detail={`${dashboardSummary.total ? ((dashboardSummary.critical / dashboardSummary.total) * 100).toFixed(1) : '0.0'}% of total`}
          accent='#ef4444'
        />
        <MetricCard
          icon={PlugZap}
          label='Active Integrations'
          value={providerSummary.length}
          detail={
            providerSummary.length > 0
              ? 'Sources reporting assets'
              : 'Manual inventory only'
          }
          accent='#22c55e'
        />
      </SimpleGrid>

      {/* Token creation actions (hidden for viewers) */}
      {!isViewer && (
        <>
          <Box
            data-tour='add-token-form'
            bg={DASHBOARD_SURFACE}
            p={{ base: 4, md: 4 }}
            borderRadius='md'
            boxShadow='0 14px 42px rgba(0, 0, 0, 0.18)'
            border='1px solid'
            borderColor={DASHBOARD_BORDER}
            mb={4}
            overflow='visible'
          >
            <HStack
              spacing={3}
              flexWrap='wrap'
              justify='flex-start'
            >
              <Button
                size='sm'
                colorScheme='blue'
                leftIcon={<FiPlus />}
                borderRadius='md'
                onClick={() => setCreateTokenModalOpen(true)}
              >
                Create New Token
              </Button>
              <Menu placement='bottom-end'>
                <MenuButton
                  data-tour='export-tokens'
                  as={Button}
                  leftIcon={<Download size={16} />}
                  size='sm'
                  variant='outline'
                  borderRadius='md'
                  borderColor={DASHBOARD_BORDER_STRONG}
                  color='rgba(226, 232, 240, 0.94)'
                  _hover={{ bg: 'rgba(30, 41, 59, 0.72)', color: 'white' }}
                >
                  Export tokens
                </MenuButton>
                <Portal>
                  <MenuList
                    zIndex={1500}
                    bg={menuBg}
                    borderColor={menuBorder}
                    borderWidth='1px'
                  >
                    <MenuItem onClick={() => exportTokens('csv')}>CSV</MenuItem>
                    <MenuItem onClick={() => exportTokens('xlsx')}>
                      XLSX
                    </MenuItem>
                    <MenuItem onClick={() => exportTokens('json')}>
                      JSON
                    </MenuItem>
                    <MenuItem onClick={() => exportTokens('yaml')}>
                      YAML
                    </MenuItem>
                  </MenuList>
                </Portal>
              </Menu>
              <Button
                size='sm'
                variant='outline'
                leftIcon={<ActivityIcon size={16} />}
                borderRadius='md'
                borderColor='rgba(59, 130, 246, 0.62)'
                color='rgba(147, 197, 253, 0.98)'
                _hover={{ bg: 'rgba(37, 99, 235, 0.16)', color: 'white' }}
                onClick={onDomainModalOpen}
                aria-label='Endpoint and SSL monitoring'
              >
                Endpoint & SSL monitor
              </Button>
              <Box data-tour='import-tokens'>
                <ImportTokensButton label='Import tokens' />
              </Box>
            </HStack>
          </Box>

          <Modal
            isOpen={isCreateTokenModalOpen}
            onClose={() => setCreateTokenModalOpen(false)}
            size='6xl'
            scrollBehavior='inside'
          >
            <ModalOverlay />
            <ModalContent bg={DASHBOARD_SURFACE} border='1px solid' borderColor={DASHBOARD_BORDER}>
              <ModalHeader color='white'>Create New Token</ModalHeader>
              <ModalCloseButton color='white' />
              <ModalBody pb={6}>
            <Box pt={0}>
              <form onSubmit={onTokenAdd}>
                <SimpleGrid columns={{ base: 1, md: 4 }} spacing={6}>
                  {/* Name Field */}
                  <FormControl isInvalid={!!formErrors.name}>
                    <FormLabel htmlFor='name'>Name *</FormLabel>
                    <Input
                      type='text'
                      id='name'
                      name='name'
                      value={formData.name}
                      onChange={onInputChange}
                      bg={inputBg}
                      borderColor={formErrors.name ? 'red.500' : inputBorder}
                      _placeholder={{ color: placeholderColor }}
                      maxLength={100}
                      aria-required='true'
                      aria-invalid={formErrors.name ? 'true' : 'false'}
                      aria-describedby={
                        formErrors.name ? 'name-error' : undefined
                      }
                    />
                    {formErrors.name && (
                      <FormErrorMessage id='name-error'>
                        {formErrors.name}
                      </FormErrorMessage>
                    )}
                  </FormControl>

                  {/* Category Field */}
                  <FormControl isInvalid={!!formErrors.category}>
                    <FormLabel htmlFor='category'>Category *</FormLabel>
                    <Select
                      id='category'
                      name='category'
                      value={formData.category}
                      onChange={onInputChange}
                      bg={inputBg}
                      borderColor={
                        formErrors.category ? 'red.500' : inputBorder
                      }
                      aria-required='true'
                      aria-invalid={formErrors.category ? 'true' : 'false'}
                      aria-describedby={
                        formErrors.category ? 'category-error' : undefined
                      }
                    >
                      {TOKEN_CATEGORIES.map(category => (
                        <option key={category.value} value={category.value}>
                          {category.label}
                        </option>
                      ))}
                    </Select>
                    {formErrors.category && (
                      <FormErrorMessage id='category-error'>
                        {formErrors.category}
                      </FormErrorMessage>
                    )}
                  </FormControl>

                  {/* Type Field - Dynamic based on category */}
                  <FormControl isInvalid={!!formErrors.type}>
                    <FormLabel htmlFor='type'>Type *</FormLabel>
                    <Select
                      id='type'
                      name='type'
                      value={formData.type}
                      onChange={onInputChange}
                      bg={inputBg}
                      borderColor={formErrors.type ? 'red.500' : inputBorder}
                      aria-required='true'
                      aria-invalid={formErrors.type ? 'true' : 'false'}
                      aria-describedby={
                        formErrors.type ? 'type-error' : undefined
                      }
                    >
                      <option value=''>Select a type</option>
                      {formData.category &&
                        TOKEN_CATEGORIES.find(
                          cat => cat.value === formData.category
                        )?.types.map(type => (
                          <option key={type.value} value={type.value}>
                            {type.label}
                          </option>
                        ))}
                    </Select>
                    {formErrors.type && (
                      <FormErrorMessage id='type-error'>
                        {formErrors.type}
                      </FormErrorMessage>
                    )}
                  </FormControl>

                  {/* Section Field */}
                  <FormControl>
                    <FormLabel htmlFor='section'>Section</FormLabel>
                    <Input
                      type='text'
                      id='section'
                      name='section'
                      value={formData.section}
                      onChange={onInputChange}
                      bg={inputBg}
                      borderColor={inputBorder}
                      placeholder='e.g., prod, AWS, security team'
                      maxLength={120}
                    />
                  </FormControl>

                  {/* Contact group selector - replaces per-token email override */}
                  <FormControl>
                    <FormLabel>Contact group (alerts)</FormLabel>
                    <Select
                      name='contact_group_id'
                      value={formData.contact_group_id || ''}
                      onChange={onInputChange}
                      isDisabled={isViewer}
                      bg={inputBg}
                      borderColor={inputBorder}
                    >
                      <option value=''>Use workspace default</option>
                      {Array.isArray(contactGroups) &&
                        contactGroups.map(g => (
                          <option key={g.id} value={g.id}>
                            {g.name}
                          </option>
                        ))}
                    </Select>
                    {isViewer ? (
                      <Text fontSize='xs' color={helpTextColor} mt={1}>
                        Only workspace managers and admins can set per-token
                        contact group.
                      </Text>
                    ) : null}
                  </FormControl>

                  {/* Expiration Date Field */}
                  <FormControl isInvalid={!!formErrors.expiresAt}>
                    <FormLabel htmlFor='expiresAt'>Expiration Date</FormLabel>
                    <Input
                      type='date'
                      id='expiresAt'
                      name='expiresAt'
                      value={formData.expiresAt}
                      onChange={onInputChange}
                      bg={inputBg}
                      borderColor={
                        formErrors.expiresAt ? 'red.500' : inputBorder
                      }
                      aria-invalid={formErrors.expiresAt ? 'true' : 'false'}
                      aria-describedby={
                        formErrors.expiresAt ? 'expiresAt-error' : undefined
                      }
                    />
                    {formErrors.expiresAt && (
                      <FormErrorMessage id='expiresAt-error'>
                        {formErrors.expiresAt}
                      </FormErrorMessage>
                    )}
                  </FormControl>
                </SimpleGrid>

                {/* Category-specific fields */}
                {formData.category === 'cert' && (
                  <SimpleGrid columns={{ base: 1, md: 3 }} spacing={6} mt={6}>
                    <FormControl isInvalid={!!formErrors.domains}>
                      <FormLabel htmlFor='domains'>
                        Domains (comma-separated)
                      </FormLabel>
                      <Input
                        type='text'
                        id='domains'
                        name='domains'
                        value={formData.domains}
                        onChange={onInputChange}
                        bg={inputBg}
                        borderColor={
                          formErrors.domains ? 'red.500' : inputBorder
                        }
                        placeholder='example.com, www.example.com'
                        _placeholder={{ color: placeholderColor }}
                        maxLength={500}
                      />
                      {formErrors.domains && (
                        <FormErrorMessage id='domains-error'>
                          {formErrors.domains}
                        </FormErrorMessage>
                      )}
                    </FormControl>

                    <FormControl>
                      <FormLabel htmlFor='issuer'>Issuer</FormLabel>
                      <Input
                        type='text'
                        id='issuer'
                        name='issuer'
                        value={formData.issuer}
                        onChange={onInputChange}
                        bg={inputBg}
                        borderColor={inputBorder}
                        placeholder={"Let's Encrypt, DigiCert"}
                        _placeholder={{ color: placeholderColor }}
                        maxLength={100}
                      />
                    </FormControl>

                    <FormControl>
                      <FormLabel htmlFor='serial_number'>
                        Serial Number
                      </FormLabel>
                      <Input
                        type='text'
                        id='serial_number'
                        name='serial_number'
                        value={formData.serial_number}
                        onChange={onInputChange}
                        bg={inputBg}
                        borderColor={inputBorder}
                        placeholder='Optional'
                        _placeholder={{ color: placeholderColor }}
                        maxLength={50}
                      />
                    </FormControl>

                    <FormControl>
                      <FormLabel htmlFor='subject'>Subject</FormLabel>
                      <Input
                        type='text'
                        id='subject'
                        name='subject'
                        value={formData.subject}
                        onChange={onInputChange}
                        bg={inputBg}
                        borderColor={inputBorder}
                        placeholder='CN=example.com, O=Example Corp, C=US'
                        _placeholder={{ color: placeholderColor }}
                        maxLength={300}
                      />
                    </FormControl>

                    <FormControl>
                      <FormLabel htmlFor='renewal_url'>Renewal URL</FormLabel>
                      <Input
                        type='url'
                        id='renewal_url'
                        name='renewal_url'
                        value={formData.renewal_url}
                        onChange={onInputChange}
                        bg={inputBg}
                        borderColor={inputBorder}
                        placeholder='https://provider.com/renew'
                        _placeholder={{ color: placeholderColor }}
                        maxLength={500}
                      />
                    </FormControl>

                    <FormControl>
                      <FormLabel htmlFor='contacts'>
                        Contacts (Key custodian)
                      </FormLabel>
                      {renderContactTagInput('Who manages this certificate?')}
                    </FormControl>
                  </SimpleGrid>
                )}

                {formData.category === 'key_secret' && (
                  <SimpleGrid columns={{ base: 1, md: 3 }} spacing={6} mt={6}>
                    <FormControl>
                      <FormLabel>Locations</FormLabel>
                      <VStack spacing={2} align='stretch'>
                        {locationEntries.map((location, index) => (
                          <HStack key={index} spacing={2}>
                            <Input
                              type='text'
                              value={location}
                              onChange={e =>
                                updateLocationEntry(index, e.target.value)
                              }
                              bg={inputBg}
                              borderColor={inputBorder}
                              placeholder='AWS Secrets Manager, /etc/ssl/certs'
                              _placeholder={{ color: placeholderColor }}
                            />
                            {locationEntries.length > 1 && (
                              <IconButton
                                icon={<FiX />}
                                onClick={() => removeLocationEntry(index)}
                                aria-label='Remove location'
                                size='sm'
                                colorScheme='red'
                                variant='ghost'
                              />
                            )}
                          </HStack>
                        ))}
                        <Button
                          leftIcon={<FiPlus />}
                          onClick={addLocationEntry}
                          size='sm'
                          variant='outline'
                          alignSelf='flex-start'
                        >
                          Add Location
                        </Button>
                      </VStack>
                    </FormControl>

                    <FormControl>
                      <FormLabel htmlFor='used_by'>Used By</FormLabel>
                      <Input
                        type='text'
                        id='used_by'
                        name='used_by'
                        value={formData.used_by}
                        onChange={onInputChange}
                        bg={inputBg}
                        borderColor={inputBorder}
                        placeholder='Web server, API service'
                        _placeholder={{ color: placeholderColor }}
                      />
                    </FormControl>

                    <FormControl>
                      <FormLabel htmlFor='description'>Description</FormLabel>
                      <Input
                        type='text'
                        id='description'
                        name='description'
                        value={formData.description}
                        onChange={onInputChange}
                        bg={inputBg}
                        borderColor={inputBorder}
                        placeholder='Use case or context for this key/secret'
                        _placeholder={{ color: placeholderColor }}
                        maxLength={300}
                      />
                    </FormControl>

                    {/* Algorithm and Key Size only for encryption_key and ssh_key */}
                    {(formData.type === 'encryption_key' ||
                      formData.type === 'ssh_key') && (
                      <>
                        <FormControl>
                          <FormLabel htmlFor='algorithm'>Algorithm</FormLabel>
                          <Input
                            type='text'
                            id='algorithm'
                            name='algorithm'
                            value={formData.algorithm}
                            onChange={onInputChange}
                            bg={inputBg}
                            borderColor={inputBorder}
                            placeholder='AES-256, RSA'
                            _placeholder={{ color: placeholderColor }}
                            maxLength={50}
                          />
                        </FormControl>

                        <FormControl isInvalid={!!formErrors.key_size}>
                          <FormLabel htmlFor='key_size'>
                            Key Size (bits)
                          </FormLabel>
                          <Input
                            type='number'
                            id='key_size'
                            name='key_size'
                            value={formData.key_size}
                            onChange={onInputChange}
                            bg={inputBg}
                            borderColor={
                              formErrors.key_size ? 'red.500' : inputBorder
                            }
                            placeholder='256, 2048'
                            _placeholder={{ color: placeholderColor }}
                            min={128}
                            max={16384}
                            step={1}
                          />
                          {formErrors.key_size && (
                            <FormErrorMessage id='key_size-error'>
                              {formErrors.key_size}
                            </FormErrorMessage>
                          )}
                        </FormControl>
                      </>
                    )}

                    <FormControl>
                      <FormLabel htmlFor='renewal_url'>Renewal URL</FormLabel>
                      <Input
                        type='url'
                        id='renewal_url'
                        name='renewal_url'
                        value={formData.renewal_url}
                        onChange={onInputChange}
                        bg={inputBg}
                        borderColor={inputBorder}
                        placeholder='https://provider.com/renew'
                        _placeholder={{ color: placeholderColor }}
                        maxLength={500}
                      />
                    </FormControl>

                    <FormControl>
                      <FormLabel htmlFor='contacts'>
                        Contacts (Key custodian)
                      </FormLabel>
                      {renderContactTagInput('Who manages this key/secret?')}
                    </FormControl>
                  </SimpleGrid>
                )}

                {formData.category === 'license' && (
                  <SimpleGrid columns={{ base: 1, md: 3 }} spacing={6} mt={6}>
                    <FormControl>
                      <FormLabel htmlFor='vendor'>Vendor</FormLabel>
                      <Input
                        type='text'
                        id='vendor'
                        name='vendor'
                        value={formData.vendor}
                        onChange={onInputChange}
                        bg={inputBg}
                        borderColor={inputBorder}
                        placeholder='Microsoft, Adobe'
                        _placeholder={{ color: placeholderColor }}
                        maxLength={100}
                      />
                    </FormControl>

                    <FormControl>
                      <FormLabel htmlFor='license_type'>License Type</FormLabel>
                      <Input
                        type='text'
                        id='license_type'
                        name='license_type'
                        value={formData.license_type}
                        onChange={onInputChange}
                        bg={inputBg}
                        borderColor={inputBorder}
                        placeholder='Perpetual, Subscription'
                        _placeholder={{ color: placeholderColor }}
                        maxLength={50}
                      />
                    </FormControl>

                    <FormControl isInvalid={!!formErrors.cost}>
                      <FormLabel htmlFor='cost'>Cost ($)</FormLabel>
                      <Input
                        type='number'
                        id='cost'
                        name='cost'
                        value={formData.cost}
                        onChange={onInputChange}
                        bg={inputBg}
                        borderColor={formErrors.cost ? 'red.500' : inputBorder}
                        placeholder='0.00'
                        step='0.01'
                        min='0'
                        max='999999999999.99'
                        _placeholder={{ color: placeholderColor }}
                      />
                      {formErrors.cost && (
                        <FormErrorMessage id='cost-error'>
                          {formErrors.cost}
                        </FormErrorMessage>
                      )}
                    </FormControl>

                    <FormControl>
                      <FormLabel htmlFor='renewal_url'>Renewal URL</FormLabel>
                      <Input
                        type='url'
                        id='renewal_url'
                        name='renewal_url'
                        value={formData.renewal_url}
                        onChange={onInputChange}
                        bg={inputBg}
                        borderColor={inputBorder}
                        placeholder='https://vendor.com/renew'
                        _placeholder={{ color: placeholderColor }}
                        maxLength={500}
                      />
                    </FormControl>

                    <FormControl>
                      <FormLabel htmlFor='renewal_date'>Renewal Date</FormLabel>
                      <Input
                        type='date'
                        id='renewal_date'
                        name='renewal_date'
                        value={formData.renewal_date}
                        onChange={onInputChange}
                        bg={inputBg}
                        borderColor={inputBorder}
                        placeholder='Optional'
                        _placeholder={{ color: placeholderColor }}
                      />
                    </FormControl>

                    <FormControl>
                      <FormLabel htmlFor='contacts'>Contacts</FormLabel>
                      {renderContactTagInput('Who owns this renewal?')}
                    </FormControl>
                  </SimpleGrid>
                )}

                {formData.category === 'general' && (
                  <SimpleGrid columns={{ base: 1, md: 2 }} spacing={6} mt={6}>
                    <FormControl>
                      <FormLabel>Locations</FormLabel>
                      <VStack spacing={2} align='stretch'>
                        {locationEntries.map((location, index) => (
                          <HStack key={index} spacing={2}>
                            <Input
                              type='text'
                              value={location}
                              onChange={e =>
                                updateLocationEntry(index, e.target.value)
                              }
                              bg={inputBg}
                              borderColor={inputBorder}
                              placeholder='Folder path, cloud location'
                              _placeholder={{ color: placeholderColor }}
                            />
                            {locationEntries.length > 1 && (
                              <IconButton
                                icon={<FiX />}
                                onClick={() => removeLocationEntry(index)}
                                aria-label='Remove location'
                                size='sm'
                                colorScheme='red'
                                variant='ghost'
                              />
                            )}
                          </HStack>
                        ))}
                        <Button
                          leftIcon={<FiPlus />}
                          onClick={addLocationEntry}
                          size='sm'
                          variant='outline'
                          alignSelf='flex-start'
                        >
                          Add Location
                        </Button>
                      </VStack>
                    </FormControl>

                    <FormControl>
                      <FormLabel htmlFor='used_by'>Used By</FormLabel>
                      <Input
                        type='text'
                        id='used_by'
                        name='used_by'
                        value={formData.used_by}
                        onChange={onInputChange}
                        bg={inputBg}
                        borderColor={inputBorder}
                        placeholder='Application, service'
                        _placeholder={{ color: placeholderColor }}
                        maxLength={200}
                      />
                    </FormControl>

                    <FormControl>
                      <FormLabel htmlFor='renewal_url'>Renewal URL</FormLabel>
                      <Input
                        type='url'
                        id='renewal_url'
                        name='renewal_url'
                        value={formData.renewal_url}
                        onChange={onInputChange}
                        bg={inputBg}
                        borderColor={inputBorder}
                        placeholder='https://provider.com/renew'
                        _placeholder={{ color: placeholderColor }}
                        maxLength={500}
                      />
                    </FormControl>

                    <FormControl>
                      <FormLabel htmlFor='contacts'>Contacts</FormLabel>
                      {renderContactTagInput('Who manages this item?')}
                    </FormControl>
                  </SimpleGrid>
                )}

                {/* Datalist for workspace contacts suggestions (creation form) */}
                <datalist id='workspace-contacts-suggestions'>
                  {(Array.isArray(workspaceContacts) ? workspaceContacts : [])
                    .map(c => {
                      const name = [c.first_name, c.last_name]
                        .filter(Boolean)
                        .join(' ')
                        .trim();
                      const phone = (c.phone_e164 || '').trim();
                      const parts = [name, phone].filter(Boolean);
                      const label = parts.join(' - ');
                      return { c, label };
                    })
                    .filter(
                      ({ label }) => label && !selectedContactLabels.has(label)
                    )
                    .map(({ c, label }) => (
                      <option key={c.id} value={label} />
                    ))}
                </datalist>

                {/* Notes field for all categories */}
                <FormControl mt={6}>
                  <FormLabel htmlFor='notes'>Notes</FormLabel>
                  <CreateTokenNotesField
                    parentNotes={formData.notes}
                    onCommitNotes={commitCreateNotes}
                    submitFlushRef={createTokenNotesFlushRef}
                    inputBg={inputBg}
                    inputBorder={inputBorder}
                    placeholderColor={placeholderColor}
                  />
                </FormControl>

                {(typeof canCreateToken === 'boolean'
                  ? canCreateToken
                  : true) && (
                  <Flex justify='flex-end' mt={8}>
                    {typeof isViewer === 'boolean' ? (
                      !isViewer && (
                        <Button
                          type='submit'
                          disabled={isSubmitting}
                          colorScheme='blue'
                          size='lg'
                          px={8}
                          isLoading={isSubmitting}
                          loadingText='Creating...'
                        >
                          Create Token
                        </Button>
                      )
                    ) : (
                      <Button
                        type='submit'
                        disabled={isSubmitting}
                        colorScheme='blue'
                        size='lg'
                        px={8}
                        isLoading={isSubmitting}
                        loadingText='Creating...'
                      >
                        Create Token
                      </Button>
                    )}
                  </Flex>
                )}
              </form>
            </Box>
              </ModalBody>
            </ModalContent>
          </Modal>
        </>
      )}

      {renderDashboardWorkspace()}
          </Box>
        </Box>
      </Flex>

      <EndpointSslMonitorModal
        isOpen={isDomainModalOpen}
        onClose={onDomainModalClose}
        contactGroups={contactGroups}
        defaultContactGroupId={defaultContactGroupId}
        panelQueries={panelQueries}
        TOKEN_CATEGORIES={TOKEN_CATEGORIES}
        fetchGlobalFacets={fetchGlobalFacets}
        fetchTokensForCategoryReset={fetchTokensForCategoryReset}
      />
    </Box>
  );
}
function ImportTokensButton({ label = 'Import' }) {
  const { isOpen, onOpen, onClose } = useDisclosure();
  const [searchParams, setSearchParams] = useSearchParams();
  const [openRequest, setOpenRequest] = useState(null);
  const [_created, setCreated] = useState([]);

  const handleOpenRequestHandled = useCallback(() => {
    setOpenRequest(null);
  }, []);

  useEffect(() => {
    const provider = searchParams.get('import');
    if (!provider) return;
    const autoSyncManage = searchParams.get('autoSyncManage') === '1';
    setOpenRequest({
      provider,
      integrationSubTab: autoSyncManage ? 'manage' : 'scan',
    });
    onOpen();
    const next = new URLSearchParams(searchParams);
    next.delete('import');
    next.delete('autoSyncManage');
    setSearchParams(next, { replace: true });
  }, [searchParams, onOpen, setSearchParams]);

  useEffect(() => {
    const handleOpenImport = () => onOpen();
    window.addEventListener('tt:open-import-tokens', handleOpenImport);
    return () => {
      window.removeEventListener('tt:open-import-tokens', handleOpenImport);
    };
  }, [onOpen]);

  const onImported = newOnes => {
    try {
      if (Array.isArray(newOnes) && newOnes.length > 0) {
        // Broadcast event so parent can refresh facets
        window.dispatchEvent(new CustomEvent('tt:tokens-imported'));
        // Also notify dashboard listeners to trigger a reload from backend
        window.dispatchEvent(new CustomEvent('tt:tokens-updated'));
        setCreated(newOnes);
      }
    } catch (_) {}
  };
  return (
    <>
      <Button
        onClick={onOpen}
        leftIcon={<Upload size={16} />}
        variant='outline'
        size='sm'
        borderRadius='md'
        borderColor={DASHBOARD_BORDER_STRONG}
        color='rgba(226, 232, 240, 0.94)'
        _hover={{ bg: 'rgba(30, 41, 59, 0.72)', color: 'white' }}
        minW='fit-content'
        maxW={{ base: '100%', sm: 'none' }}
        whiteSpace='nowrap'
      >
        {label}
      </Button>
      <ImportTokensModal
        isOpen={isOpen}
        onClose={() => {
          setOpenRequest(null);
          onClose();
        }}
        openRequest={openRequest}
        onOpenRequestHandled={handleOpenRequestHandled}
        onImported={onImported}
      />
    </>
  );
}

export default App;
