import { logger } from './utils/logger.js';
import { getExpiryStatus, getColorFromString } from './styles/colors.js';

import {
  useEffect,
  useState,
  useCallback,
  useRef,
  Suspense,
  lazy,
  useMemo,
  memo,
} from 'react';
import {
  ChakraProvider,
  ColorModeScript,
  Box,
  Heading,
  SimpleGrid,
  FormControl,
  FormLabel,
  FormErrorMessage,
  Input,
  Select,
  Switch,
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
  Stack,
  NumberInput,
  NumberInputField,
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
  Divider,
  HStack,
  Alert,
  AlertIcon,
  AlertDescription,
  Collapse,
  Menu,
  MenuButton,
  MenuList,
  MenuItem,
  Checkbox,
  Portal,
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
import DocsLayout from './layouts/DocsLayout.jsx';
import { trackEvent } from './utils/analytics.js';
import {
  FiDownload,
  FiTrash2,
  FiPlus,
  FiX,
  FiChevronDown,
  FiChevronUp,
  FiChevronRight,
  FiGlobe,
  FiRefreshCw,
  FiExternalLink,
  FiActivity,
  FiAlertTriangle,
} from 'react-icons/fi';

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
import {
  SortableTh,
  domainStatusColor,
  domainSslBadge,
  domainFormatUrl,
} from './components/DashboardHelpers.jsx';

import apiClient, {
  authAPI,
  tokenAPI,
  formatDate,
  workspaceAPI,
  API_ENDPOINTS,
  showSuccessMessage,
} from './utils/apiClient';

function domainValueToUrl(value) {
  const raw = String(value || '').trim();
  if (!raw) return null;
  if (/^https?:\/\//i.test(raw)) return raw;
  return `https://${raw}`;
}
import {
  formatExpirationDate,
  isNeverExpires,
  NEVER_EXPIRES_DATE_VALUE,
} from './utils/dateUtils';
import { useDashboardColors } from './hooks/useColors.js';
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
const DocsIntro = lazy(() => import('./pages/DocsIntro.jsx'));
const DocsTeams = lazy(() => import('./pages/DocsTeams.jsx'));
const DocsTokens = lazy(() => import('./pages/DocsTokens.jsx'));
const DocsAlerts = lazy(() => import('./pages/DocsAlerts.jsx'));
const DocsAudit = lazy(() => import('./pages/DocsAudit.jsx'));
const DocsUsage = lazy(() => import('./pages/DocsUsage.jsx'));
const DocsApi = lazy(() => import('./pages/DocsApi.jsx'));
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
      try {
        const ws = await workspaceAPI.list(50, 0);
        const items = ws?.items || [];
        const roles = items.map(w => String(w.role || '').toLowerCase());
        const hasManagerOrAdmin =
          roles.includes('admin') || roles.includes('workspace_manager');
        if (!cancelled) setIsAllowed(hasManagerOrAdmin);
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

/**
 * Return HEX color according to expiry date and status.
 * Matches logic and colors per STYLEGUIDE.md.
 * Now uses centralized color system from styles/colors.js
 */
// Moved to styles/colors.js for reusability across components

/**
 * Expiry color-status pill. Always uses both color and label, never color alone.
 */
const ExpiryPill = memo(function ExpiryPill({ expiry }) {
  const status = getExpiryStatus(expiry);
  const shadowColor = useColorModeValue(
    'rgba(0, 0, 0, 0.1)',
    'rgba(0, 0, 0, 0.3)'
  );

  return (
    <Box
      as='span'
      bg={status.color}
      color={status.textColor}
      borderRadius='md'
      px={{ base: 2, md: 4 }}
      py={1}
      fontWeight={600}
      fontFamily="'Roboto Mono', Menlo, monospace"
      fontSize={{ base: 'xs', md: 'sm' }}
      boxShadow={`0 1px 2px ${shadowColor}`}
      aria-label={`Expiry status: ${status.label}`}
      whiteSpace='nowrap'
    >
      {status.label}
    </Box>
  );
});

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
      // Block docs as if non-public to avoid header flicker until session hydrates
      return !isPublicPath(path) || path.startsWith('/docs');
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

  // Token filtering and sorting state
  // Deprecated global filters (replaced by per-panel search)
  const [filters, setFilters] = useState({});
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
  const [alertDefaultEmail] = useState(null);

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
  // Ensure public routes never remain in a loading state (except /docs which we block until session resolves)
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
        '/docs',
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
   * Handle filter changes
   */
  const handleFilterChange = (field, value) => {
    setFilters(prev => ({
      ...prev,
      [field]: value,
    }));
  };

  /**
   * Handle sort changes
   */
  const handleSort = (key, categoryValue) => {
    setSortConfigs(prev => {
      const current = prev[categoryValue] || { key: null, direction: 'asc' };
      const next = {
        key,
        direction:
          current.key === key && current.direction === 'asc' ? 'desc' : 'asc',
      };
      return { ...prev, [categoryValue]: next };
    });
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
   * Clear all filters
   */
  const clearFilters = () => {
    setFilters({
      name: '',
      type: '',
      vendor: '',
      issuer: '',
      location: '',
      used_by: '',
      description: '',
    });
    // Do not alter per-category sort when clearing filters
  };

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
                        path='/docs'
                        element={
                          <DocsLayout
                            session={session}
                            sessionLoading={loading}
                            onLogout={handleLogout}
                            onAccountClick={handleHelpAccountClick}
                            onNavigateToDashboard={
                              handleHelpNavigateToDashboard
                            }
                            onNavigateToLanding={handleNavigateToLanding}
                          />
                        }
                      >
                        <Route
                          index
                          element={<DocsIntro session={session} />}
                        />
                        <Route
                          path='teams'
                          element={<DocsTeams session={session} />}
                        />
                        <Route
                          path='tokens'
                          element={<DocsTokens session={session} />}
                        />
                        <Route
                          path='alerts'
                          element={<DocsAlerts session={session} />}
                        />
                        <Route
                          path='audit'
                          element={<DocsAudit session={session} />}
                        />
                        <Route
                          path='usage'
                          element={<DocsUsage session={session} />}
                        />
                        <Route
                          path='api'
                          element={<DocsApi session={session} />}
                        />
                      </Route>
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
                                ExpiryPill={ExpiryPill}
                                onOpenTokenModal={handleOpenTokenModal}
                                onLogout={handleLogout}
                                onAccountClick={handleHelpAccountClick}
                                onNavigateToLanding={handleNavigateToLanding}
                                onAccountDeleted={handleAccountDeleted}
                                filters={filters}
                                sortConfigs={sortConfigs}
                                onFilterChange={handleFilterChange}
                                onSort={handleSort}
                                onClearFilters={clearFilters}
                                getFilteredAndSortedTokens={
                                  getFilteredAndSortedTokens
                                }
                                showWelcomeModal={showWelcomeModal}
                                setShowWelcomeModal={setShowWelcomeModal}
                                welcomeData={welcomeData}
                                selectedToken={selectedToken}
                                handleCloseTokenModal={handleCloseTokenModal}
                                alertDefaultEmail={alertDefaultEmail}
                                // Thread global filtering/search/sort state into wrapper
                                searchQuery={searchQuery}
                                setSearchQuery={setSearchQuery}
                                serverSort={serverSort}
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
                                setOffset={setOffset}
                                setTokens={setTokens}
                                isRefreshing={isRefreshing}
                                categoryOffsets={categoryOffsets}
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
  ExpiryPill,
  onOpenTokenModal,
  onLogout,
  onNavigateToLanding,
  onAccountDeleted,
  showWelcomeModal,
  setShowWelcomeModal,
  welcomeData,
  selectedToken,
  handleCloseTokenModal,
  filters,
  onFilterChange,
  onSort,
  onClearFilters,
  getFilteredAndSortedTokens,
  sortConfigs,
  alertDefaultEmail,
  // Global filtering/search/sort state/handlers from App
  searchQuery,
  setSearchQuery,
  serverSort,
  setServerSort,
  selectedCategories,
  setSelectedCategories,
  tokenFacets,
  globalFacets,
  fetchGlobalFacets,
  fetchTokensForCategoryReset,
  setOffset,
  setTokens,
  isRefreshing,
  categoryOffsets,
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

  return (
    <div
      style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}
    >
      <SEO
        title='Dashboard'
        description='Manage your tokens, certificates, and expiring assets'
        noindex
      />
      <Navigation
        user={session}
        onLogout={onLogout}
        onAccountClick={() => {
          setCurrentView('account');
          // Update URL to reflect the account view
          const url = new URL(window.location);
          url.searchParams.set('view', 'account');
          window.history.pushState({}, '', url);
        }}
        onNavigateToDashboard={() => {
          setCurrentView('dashboard');
          // Clear the view parameter from URL when going to dashboard
          const url = new URL(window.location);
          url.searchParams.delete('view');
          window.history.pushState({}, '', url);
        }}
        onNavigateToLanding={onNavigateToLanding}
      />

      <main
        id='main-content'
        style={{
          flex: 1,
          padding: 'clamp(1rem, 2vw, 2rem)',
          overflowX: 'hidden',
        }}
      >
        <div style={{ maxWidth: '1200px', margin: '0 auto' }}>
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
              ExpiryPill={ExpiryPill}
              onOpenTokenModal={onOpenTokenModal}
              filters={filters}
              onFilterChange={onFilterChange}
              onSort={onSort}
              onClearFilters={onClearFilters}
              getFilteredAndSortedTokens={getFilteredAndSortedTokens}
              sortConfigs={sortConfigs}
              _alertDefaultEmail={alertDefaultEmail}
              selectedCategories={selectedCategories}
              setSelectedCategories={setSelectedCategories}
              tokenFacets={tokenFacets}
              globalFacets={globalFacets}
              fetchGlobalFacets={fetchGlobalFacets}
              fetchTokensForCategoryReset={fetchTokensForCategoryReset}
              _setOffset={setOffset}
              _setTokens={setTokens}
              _searchQuery={searchQuery}
              _setSearchQuery={setSearchQuery}
              _serverSort={serverSort}
              _setServerSort={setServerSort}
              isRefreshing={isRefreshing}
              categoryOffsets={categoryOffsets}
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
 * Note: SortableTh and domain helper functions have been extracted to ./components/DashboardHelpers.jsx
 */

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
  ExpiryPill,
  onOpenTokenModal,
  onSort,

  getFilteredAndSortedTokens,
  sortConfigs,
  _alertDefaultEmail,
  // Added props for global search, sorting, and category filters
  _searchQuery,
  _setSearchQuery,
  _serverSort,
  _setServerSort,
  selectedCategories,
  setSelectedCategories,
  tokenFacets,
  globalFacets,
  fetchGlobalFacets,
  fetchTokensForCategoryReset,
  _setOffset,
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
}) {
  const { colorMode } = useColorMode();
  const isLight = colorMode === 'light';

  // Move useColorModeValue calls to the top to comply with Rules of Hooks
  const menuBg = useColorModeValue('gray.100', 'gray.800');
  const menuBorder = useColorModeValue('gray.400', 'gray.600');
  const _popoverBg = useColorModeValue('gray.100', 'gray.800');
  const _popoverBorder = useColorModeValue('gray.400', 'gray.600');
  const helpTextColor = useColorModeValue('gray.600', 'gray.400');
  const domainBorderColor = useColorModeValue('gray.200', 'gray.700');

  // Use reusable dashboard color hooks
  const {
    bgColor,
    borderColor,
    inputBg,
    inputBorder,
    placeholderColor,
    emptyTextColor,
    hoverBgColor,
    thHoverBg,
    filterLabelColor,
    mobileCardBg,
    secondaryTextColor,
  } = useDashboardColors();

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
  const [domainUrl, setDomainUrl] = useState('');
  const [domainHealthCheck, setDomainHealthCheck] = useState(true);
  const [domainInterval, setDomainInterval] = useState('hourly');
  const [domainAlertAfter, setDomainAlertAfter] = useState(2);
  const [domainContactGroupId, setDomainContactGroupId] = useState(
    defaultContactGroupId || ''
  );
  const [addingDomain, setAddingDomain] = useState(false);
  const [domains, setDomains] = useState([]);
  const [domainsLoading, setDomainsLoading] = useState(false);
  const [checkingDomain, setCheckingDomain] = useState(null);
  const [domainListSort, setDomainListSort] = useState({
    key: 'az',
    direction: 'asc',
  });
  const [domainCheckerInput, setDomainCheckerInput] = useState('');
  const [domainCheckerResults, setDomainCheckerResults] = useState([]);
  const [domainCheckerSelected, setDomainCheckerSelected] = useState([]);
  const [domainCheckerLoading, setDomainCheckerLoading] = useState(false);
  const [domainCheckerImporting, setDomainCheckerImporting] = useState(false);
  const [domainCheckerPartial, setDomainCheckerPartial] = useState(false);
  const [domainCheckerTruncated, setDomainCheckerTruncated] = useState(false);
  const [domainCheckerCapCount, setDomainCheckerCapCount] = useState(500);
  const [domainCheckerToolErrors, setDomainCheckerToolErrors] = useState([]);
  const [domainCheckerCreateMonitors, setDomainCheckerCreateMonitors] =
    useState(false);
  const [domainCheckerMonitorHealthCheck, setDomainCheckerMonitorHealthCheck] =
    useState(false);
  const [domainCheckerMonitorInterval, setDomainCheckerMonitorInterval] =
    useState('hourly');
  const [domainCheckerMonitorAlertAfter, setDomainCheckerMonitorAlertAfter] =
    useState(2);
  const [
    domainCheckerMonitorContactGroupId,
    setDomainCheckerMonitorContactGroupId,
  ] = useState(defaultContactGroupId || '');
  const [domainCheckerImportSection, setDomainCheckerImportSection] =
    useState('');
  const [domainEndpointTokenSection, setDomainEndpointTokenSection] =
    useState('');
  const domainCheckerImportInFlightRef = useRef(false);
  const [domainCheckerPage, setDomainCheckerPage] = useState(0);
  const [domainCheckerSubfinderAll, setDomainCheckerSubfinderAll] =
    useState(false);
  const [domainCheckerImportReport, setDomainCheckerImportReport] =
    useState(null);
  const [domainCheckerImportReportOpen, setDomainCheckerImportReportOpen] =
    useState(false);
  const DOMAIN_CHECKER_PAGE_SIZE = 50;
  const DOMAIN_CHECKER_LOOKUP_TIMEOUT_MS = 300_000;
  const DOMAIN_CHECKER_IMPORT_CHUNK_SIZE = 25;
  const DOMAIN_CHECKER_IMPORT_CHUNK_TIMEOUT_MS = 300_000;

  const handleDomainModalClose = () => {
    setDomainCheckerImportReport(null);
    setDomainCheckerImportReportOpen(false);
    onDomainModalClose();
  };

  const normalizeDomainCheckerStringArray = value => {
    if (Array.isArray(value)) {
      return value.map(item => String(item || '').trim()).filter(Boolean);
    }
    if (typeof value === 'string') {
      return value
        .split(',')
        .map(item => item.trim())
        .filter(Boolean);
    }
    return [];
  };

  const normalizeDomainCheckerItems = value => {
    const rawItems = Array.isArray(value) ? value : [];
    const seen = new Set();
    return rawItems
      .map((item, index) => {
        const record = item && typeof item === 'object' ? item : { name: item };
        const domains = normalizeDomainCheckerStringArray(
          record.domains || record.domain || record.hostname || record.name
        );
        const name = String(
          record.name ||
            record.hostname ||
            record.commonName ||
            domains[0] ||
            ''
        ).trim();
        if (!name) return null;
        const id = String(record.id || `disc-${name}-${index}`);
        const key = id || name;
        if (seen.has(key)) return null;
        seen.add(key);
        return {
          ...record,
          id,
          name,
          domains: domains.length ? domains : [name],
          sources: normalizeDomainCheckerStringArray(
            record.sources || record.source
          ),
          checked: record.checked !== false,
        };
      })
      .filter(Boolean);
  };

  const normalizeDomainCheckerToolErrors = value =>
    (Array.isArray(value) ? value : [])
      .map(error => {
        if (typeof error === 'string') return { tool: error };
        if (!error || typeof error !== 'object') return null;
        return {
          tool: String(error.tool || error.code || '').trim(),
          message: String(error.message || '').trim(),
        };
      })
      .filter(error => error && (error.tool || error.message));

  const { workspaceId: ctxWorkspaceId } = useWorkspace();

  // Load domains when modal opens, with up to 3 retries for transient errors (503, 502, etc.)
  const loadDomains = useCallback(async () => {
    if (!ctxWorkspaceId) return;
    setDomainsLoading(true);
    const maxAttempts = 3;
    for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
      try {
        const res = await apiClient.get(
          `/api/v1/workspaces/${ctxWorkspaceId}/domains`
        );
        setDomains(res.data?.items || []);
        setDomainsLoading(false);
        return;
      } catch (e) {
        const status = e?.response?.status;
        const isTransient = !status || status >= 500 || status === 429;
        if (attempt < maxAttempts - 1 && isTransient) {
          await new Promise(r => setTimeout(r, 1500 * (attempt + 1)));
          continue;
        }
        logger.error('Failed to load endpoint monitors', e);
      }
    }
    setDomainsLoading(false);
  }, [ctxWorkspaceId]);

  const visibleDomains = useMemo(() => {
    const healthOf = item => String(item?.last_health_status || 'pending');
    const intervalOrder = {
      '1min': 0,
      '5min': 1,
      '15min': 2,
      hourly: 3,
      daily: 4,
    };
    const healthOrder = {
      healthy: 0,
      warning: 1,
      error: 2,
      pending: 3,
    };
    const expirationTs = item => {
      const raw = item?.ssl_valid_to || item?.ssl_expires_at || null;
      if (!raw) return Number.POSITIVE_INFINITY;
      const ts = new Date(raw).getTime();
      return Number.isFinite(ts) ? ts : Number.POSITIVE_INFINITY;
    };

    const copy = [...domains];

    copy.sort((a, b) => {
      let result;
      switch (domainListSort.key) {
        case 'expiration':
          result =
            expirationTs(a) - expirationTs(b) ||
            domainFormatUrl(a.url).localeCompare(domainFormatUrl(b.url));
          break;
        case 'interval':
          result =
            (intervalOrder[String(a?.check_interval || '')] ?? 999) -
              (intervalOrder[String(b?.check_interval || '')] ?? 999) ||
            domainFormatUrl(a.url).localeCompare(domainFormatUrl(b.url));
          break;
        case 'health':
          result =
            (healthOrder[healthOf(a)] ?? 999) -
              (healthOrder[healthOf(b)] ?? 999) ||
            domainFormatUrl(a.url).localeCompare(domainFormatUrl(b.url));
          break;
        case 'az':
        default:
          result = domainFormatUrl(a.url).localeCompare(domainFormatUrl(b.url));
          break;
      }
      return domainListSort.direction === 'desc' ? -result : result;
    });

    return copy;
  }, [domains, domainListSort]);

  const handleDomainListSort = key => {
    setDomainListSort(current => ({
      key,
      direction:
        current.key === key && current.direction === 'asc' ? 'desc' : 'asc',
    }));
  };

  const renderDomainSortArrow = key => (
    <Text fontSize='xs' opacity={domainListSort.key === key ? 1 : 0.3}>
      {domainListSort.key === key && domainListSort.direction === 'desc'
        ? '↓'
        : '↑'}
    </Text>
  );

  useEffect(() => {
    if (isDomainModalOpen && ctxWorkspaceId) loadDomains();
  }, [isDomainModalOpen, ctxWorkspaceId, loadDomains]);

  const handleAddDomain = async () => {
    if (!domainUrl.trim() || !ctxWorkspaceId) return;
    setAddingDomain(true);
    try {
      const endpointBody = {
        url: domainUrl.trim(),
        health_check_enabled: domainHealthCheck,
        check_interval: domainInterval,
        alert_after_failures: domainAlertAfter,
        contact_group_id: domainContactGroupId || null,
      };
      if (domainEndpointTokenSection.trim()) {
        endpointBody.section = domainEndpointTokenSection.trim();
      }
      await apiClient.post(
        `/api/v1/workspaces/${ctxWorkspaceId}/domains`,
        endpointBody
      );
      showSuccessMessage('Endpoint added! SSL certificate tracked.');
      setDomainUrl('');
      setDomainHealthCheck(true);
      setDomainInterval('hourly');
      setDomainAlertAfter(2);
      setDomainContactGroupId(defaultContactGroupId || '');
      setDomainEndpointTokenSection('');
      loadDomains();
      try {
        window.dispatchEvent(new CustomEvent('tt:tokens-imported'));
        window.dispatchEvent(
          new CustomEvent('tt:tokens-updated', { detail: { t: Date.now() } })
        );
      } catch (_) {}
      try {
        await Promise.all(
          TOKEN_CATEGORIES.map(cat =>
            fetchTokensForCategoryReset(cat.value, {
              workspaceId: ctxWorkspaceId,
            })
          )
        );
      } catch (err) {
        logger.error('Token list refresh after endpoint add failed', err);
      }
      try {
        const section =
          (panelQueries && panelQueries.__section) ||
          new URLSearchParams(window.location.search).get('section') ||
          '__all__';
        await fetchGlobalFacets?.({ workspaceId: ctxWorkspaceId, section });
      } catch (_) {}
    } catch (e) {
      const msg = e?.response?.data?.error || 'Failed to add endpoint';
      logger.error('Endpoint add failed:', msg);
      toast.error(msg);
    } finally {
      setAddingDomain(false);
    }
  };

  const handleDeleteDomain = async domainId => {
    try {
      await apiClient.delete(
        `/api/v1/workspaces/${ctxWorkspaceId}/domains/${domainId}`
      );
      showSuccessMessage('Endpoint monitor deleted');
      loadDomains();
      window.dispatchEvent(new CustomEvent('tt:tokens-updated'));
    } catch (e) {
      toast.error(
        e?.response?.data?.error || 'Failed to delete endpoint monitor'
      );
    }
  };

  const handleCheckDomain = async (domainId, event) => {
    event?.preventDefault?.();
    event?.currentTarget?.blur?.();
    const modalBody = document.querySelector(
      '[data-endpoint-ssl-modal-body="true"]'
    );
    const previousScrollTop = modalBody?.scrollTop;
    try {
      setCheckingDomain(domainId);
      const res = await apiClient.post(
        `/api/v1/workspaces/${ctxWorkspaceId}/domains/${domainId}/check`
      );
      const { data } = res;
      if (data.status === 'healthy') {
        showSuccessMessage(`Healthy (${data.responseMs}ms)`);
      } else {
        toast.error(
          `${data.status}: ${data.error || 'Unknown error'} (${data.responseMs}ms)`
        );
      }
      await loadDomains();
      if (modalBody && typeof previousScrollTop === 'number') {
        window.requestAnimationFrame(() => {
          modalBody.scrollTop = previousScrollTop;
        });
      }
    } catch (e) {
      toast.error(e?.response?.data?.error || 'Health check failed');
    } finally {
      setCheckingDomain(null);
    }
  };

  const handleDomainCheckerLookup = async () => {
    if (!domainCheckerInput.trim() || !ctxWorkspaceId) return;
    setDomainCheckerLoading(true);
    setDomainCheckerTruncated(false);
    setDomainCheckerImportReport(null);
    setDomainCheckerImportReportOpen(false);
    const lookupUrl = `/api/v1/workspaces/${ctxWorkspaceId}/domain-checker/lookup`;
    const lookupBody = {
      domain: domainCheckerInput.trim(),
      subfinder_all: domainCheckerSubfinderAll,
    };
    const lookupReqOpts = { timeout: DOMAIN_CHECKER_LOOKUP_TIMEOUT_MS };
    const lookupMaxAttempts = 3;
    const lookupRetriable = e => {
      if (e?.code === 'ERR_CANCELED' || e?.name === 'CanceledError')
        return false;
      const status = e?.response?.status;
      if (status == null) {
        const c = e?.code;
        return (
          c === 'ECONNABORTED' ||
          c === 'ERR_NETWORK' ||
          c === 'ETIMEDOUT' ||
          c === 'ECONNRESET' ||
          (!e?.response && c !== 'ERR_BAD_REQUEST')
        );
      }
      return status >= 500 && status < 600;
    };
    try {
      let res;
      for (let attempt = 0; attempt < lookupMaxAttempts; attempt += 1) {
        try {
          res = await apiClient.post(lookupUrl, lookupBody, lookupReqOpts);
          break;
        } catch (e) {
          const last = attempt === lookupMaxAttempts - 1;
          if (last || !lookupRetriable(e)) throw e;
          toast('Discovery is slow or the connection dropped. Retrying…', {
            icon: '⏳',
          });
          await new Promise(r => setTimeout(r, 2000 * (attempt + 1)));
        }
      }
      const items = normalizeDomainCheckerItems(res.data?.items);
      const cap = Number(res.data?.meta?.maxResults);
      const capN = Number.isFinite(cap) && cap > 0 ? cap : 500;
      setDomainCheckerCapCount(capN);
      setDomainCheckerTruncated(Boolean(res.data?.meta?.truncated));
      setDomainCheckerResults(items);
      setDomainCheckerPartial(Boolean(res.data?.partial));
      setDomainCheckerToolErrors(
        normalizeDomainCheckerToolErrors(res.data?.toolErrors)
      );
      if (items.length === 0) {
        toast.error('No subdomains found for this domain.');
      } else {
        showSuccessMessage(
          `Found ${items.length} subdomain${items.length === 1 ? '' : 's'}.`
        );
      }
    } catch (e) {
      setDomainCheckerTruncated(false);
      const code = e?.response?.data?.code;
      const retryAfter = e?.response?.data?.retry_after_seconds;
      const base =
        code === 'DOMAIN_CHECKER_RATE_LIMITED' && Number.isFinite(retryAfter)
          ? `Rate limited. Try again in about ${retryAfter}s.`
          : e?.response?.data?.error;
      toast.error(
        base ||
          'Domain checker lookup failed. Discovery tools may be slow or unavailable.'
      );
    } finally {
      setDomainCheckerLoading(false);
    }
  };

  const toggleDomainCheckerResult = id => {
    setDomainCheckerSelected(prev =>
      prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]
    );
  };

  const domainCheckerVisibleResults = useMemo(() => {
    return Array.isArray(domainCheckerResults)
      ? domainCheckerResults.filter(Boolean)
      : [];
  }, [domainCheckerResults]);

  const domainCheckerPageItems = useMemo(
    () =>
      domainCheckerVisibleResults.slice(
        domainCheckerPage * DOMAIN_CHECKER_PAGE_SIZE,
        (domainCheckerPage + 1) * DOMAIN_CHECKER_PAGE_SIZE
      ),
    [domainCheckerPage, domainCheckerVisibleResults]
  );

  const domainCheckerSelectedSet = useMemo(
    () => new Set(domainCheckerSelected),
    [domainCheckerSelected]
  );

  const domainCheckerSelectAllVisibleState = useMemo(() => {
    const ids = domainCheckerVisibleResults.map(c => c?.id).filter(Boolean);
    if (ids.length === 0) return { checked: false, indeterminate: false };
    let n = 0;
    for (const id of ids) {
      if (domainCheckerSelectedSet.has(id)) n += 1;
    }
    return {
      checked: n === ids.length,
      indeterminate: n > 0 && n < ids.length,
    };
  }, [domainCheckerVisibleResults, domainCheckerSelectedSet]);

  const toggleDomainCheckerSelectAllVisible = useCallback(() => {
    const ids = domainCheckerVisibleResults.map(c => c?.id).filter(Boolean);
    if (ids.length === 0) return;
    const allOn = ids.every(id => domainCheckerSelectedSet.has(id));
    if (allOn) {
      const drop = new Set(ids);
      setDomainCheckerSelected(prev => prev.filter(id => !drop.has(id)));
    } else {
      setDomainCheckerSelected(prev => Array.from(new Set([...prev, ...ids])));
    }
  }, [domainCheckerVisibleResults, domainCheckerSelectedSet]);

  const prevDomainCheckerResultsRef = useRef(null);
  useEffect(() => {
    const isNewLookup =
      domainCheckerResults !== prevDomainCheckerResultsRef.current;
    prevDomainCheckerResultsRef.current = domainCheckerResults;
    if (isNewLookup) {
      setDomainCheckerSelected(
        domainCheckerVisibleResults
          .filter(c => c?.checked && c?.id)
          .map(c => c.id)
      );
    } else {
      const visibleIds = new Set(
        domainCheckerVisibleResults.map(c => c.id).filter(Boolean)
      );
      setDomainCheckerSelected(prev => prev.filter(id => visibleIds.has(id)));
    }
    setDomainCheckerPage(0);
  }, [domainCheckerVisibleResults, domainCheckerResults]);

  const handleDomainCheckerImport = async () => {
    if (!ctxWorkspaceId || domainCheckerSelectedSet.size === 0) return;
    if (domainCheckerImportInFlightRef.current) return;
    domainCheckerImportInFlightRef.current = true;
    const selected = domainCheckerVisibleResults.filter(item =>
      domainCheckerSelectedSet.has(item.id)
    );
    setDomainCheckerImporting(true);
    setDomainCheckerImportReport(null);
    setDomainCheckerImportReportOpen(false);
    try {
      const peelDomainCheckerSelectionAfterImport = (
        importedList,
        skippedList
      ) => {
        const drop = new Set();
        for (const row of importedList || []) {
          const cid = row && (row.certificateId || row.certificate_id);
          if (cid) drop.add(String(cid));
        }
        for (const row of skippedList || []) {
          if (row && row.reason === 'duplicate' && row.id)
            drop.add(String(row.id));
        }
        if (drop.size === 0) return;
        setDomainCheckerSelected(prev =>
          prev.filter(id => !drop.has(String(id)))
        );
      };

      const payloadBase = {
        domain: domainCheckerInput.trim(),
        monitorOptions: {
          enabled: domainCheckerCreateMonitors,
          health_check_enabled: domainCheckerMonitorHealthCheck,
          check_interval: domainCheckerMonitorInterval,
          alert_after_failures: domainCheckerMonitorAlertAfter,
          contact_group_id: domainCheckerMonitorContactGroupId || null,
        },
      };
      if (domainCheckerImportSection.trim()) {
        payloadBase.tokenOptions = {
          section: domainCheckerImportSection.trim(),
        };
      }

      const mergedImported = [];
      const mergedSkipped = [];
      let monitorsCreated = 0;
      let monitorsExisting = 0;
      let chunkError = null;
      let hadNoResponseChunk = false;

      for (
        let i = 0;
        i < selected.length;
        i += DOMAIN_CHECKER_IMPORT_CHUNK_SIZE
      ) {
        const chunk = selected.slice(i, i + DOMAIN_CHECKER_IMPORT_CHUNK_SIZE);
        try {
          const res = await apiClient.post(
            `/api/v1/workspaces/${ctxWorkspaceId}/domain-checker/import`,
            { ...payloadBase, certificates: chunk },
            { timeout: DOMAIN_CHECKER_IMPORT_CHUNK_TIMEOUT_MS }
          );
          mergedImported.push(
            ...(Array.isArray(res.data?.imported)
              ? res.data.imported
              : []
            ).filter(Boolean)
          );
          mergedSkipped.push(
            ...(Array.isArray(res.data?.skipped)
              ? res.data.skipped
              : []
            ).filter(Boolean)
          );
          monitorsCreated += res.data?.monitors?.created || 0;
          monitorsExisting += res.data?.monitors?.existing || 0;
        } catch (e) {
          if (!e?.response) {
            // Continue with remaining chunks; backend may still commit this interrupted chunk.
            hadNoResponseChunk = true;
            chunkError = e;
            continue;
          }
          chunkError = e;
          break;
        }
      }

      const refreshAfterDomainCheckerImport = async () => {
        try {
          window.dispatchEvent(new CustomEvent('tt:tokens-imported'));
          window.dispatchEvent(
            new CustomEvent('tt:tokens-updated', { detail: { t: Date.now() } })
          );
        } catch (_) {}
        try {
          await Promise.all(
            TOKEN_CATEGORIES.map(cat =>
              fetchTokensForCategoryReset(cat.value, {
                workspaceId: ctxWorkspaceId,
              })
            )
          );
        } catch (err) {
          logger.error(
            'Token list refresh after domain checker import failed',
            err
          );
        }
        try {
          const section =
            (panelQueries && panelQueries.__section) ||
            new URLSearchParams(window.location.search).get('section') ||
            '__all__';
          await fetchGlobalFacets?.({ workspaceId: ctxWorkspaceId, section });
        } catch (_) {}
        try {
          await loadDomains();
        } catch (_) {}
      };

      const applyImportReport = (imported, skippedList, options = {}) => {
        const safeSkipped = skippedList.filter(Boolean);
        const dnsUnreachableDetails = new Set([
          'live_certificate_dns_unresolved',
          'live_certificate_dns_temporary',
        ]);
        const unreachable = safeSkipped.filter(
          s =>
            s.reason === 'invalid_certificate' &&
            dnsUnreachableDetails.has(s.detail)
        ).length;
        const errorLike = safeSkipped.length - unreachable;
        const logLines = safeSkipped.map(s => {
          const label =
            (typeof s.subject === 'string' && s.subject.trim()) ||
            (Array.isArray(s.domains) && s.domains[0]) ||
            (typeof s.name === 'string' && s.name) ||
            s.id ||
            'host';
          const reason = s.reason || 'unknown';
          const detail = s.detail ? ` — ${s.detail}` : '';
          return `${label}: ${reason}${detail}`;
        });
        setDomainCheckerImportReport({
          unreachable,
          errorLike,
          imported,
          importedLowerBound: Boolean(options.importedLowerBound),
          logLines,
        });
        setDomainCheckerImportReportOpen(false);
      };

      if (chunkError && !hadNoResponseChunk) {
        await refreshAfterDomainCheckerImport();
        if (mergedImported.length || mergedSkipped.length) {
          peelDomainCheckerSelectionAfterImport(mergedImported, mergedSkipped);
          applyImportReport(mergedImported.length, mergedSkipped, {
            importedLowerBound: false,
          });
          toast.error(
            chunkError?.response?.data?.error || 'Failed to import certificates'
          );
        } else {
          setDomainCheckerImportReport(null);
          toast.error(
            chunkError?.response?.data?.error || 'Failed to import certificates'
          );
        }
      } else {
        const importedList = mergedImported;
        const skippedList = mergedSkipped;
        const imported = importedList.length;

        let summary = `Imported ${imported} SSL token${imported === 1 ? '' : 's'}`;
        if (monitorsCreated || monitorsExisting) {
          const monitorParts = [];
          if (monitorsCreated)
            monitorParts.push(
              `${monitorsCreated} new monitor${monitorsCreated === 1 ? '' : 's'}`
            );
          if (monitorsExisting)
            monitorParts.push(`${monitorsExisting} already existed`);
          summary += ` (${monitorParts.join(', ')})`;
        }
        summary += '.';
        peelDomainCheckerSelectionAfterImport(importedList, skippedList);
        showSuccessMessage(summary);

        applyImportReport(imported, skippedList, {
          importedLowerBound: hadNoResponseChunk,
        });
        if (!hadNoResponseChunk) {
          setDomainCheckerResults([]);
          setDomainCheckerSelected([]);
          setDomainCheckerPage(0);
          setDomainCheckerPartial(false);
          setDomainCheckerTruncated(false);
          setDomainCheckerToolErrors([]);
          setDomainCheckerInput('');
          setDomainListSort({ key: 'az', direction: 'asc' });
          await refreshAfterDomainCheckerImport();
          window.requestAnimationFrame(() => {
            const modalBody = document.querySelector(
              '[data-endpoint-ssl-modal-body="true"]'
            );
            modalBody?.scrollTo({ top: 0, behavior: 'smooth' });
          });
        } else {
          await refreshAfterDomainCheckerImport();
        }
        if (hadNoResponseChunk) {
          toast.error(
            `One or more import batches lost the response before completion. At least ${imported} token(s) are confirmed from completed batches; additional tokens may have been imported in interrupted batches. Refresh the list to verify the final total.`
          );
        }
      }
    } catch (e) {
      setDomainCheckerImportReport(null);
      const noResponse = !e?.response;
      toast.error(
        noResponse
          ? 'Connection closed before the response finished. Some tokens may already be imported; refresh the list before retrying.'
          : e?.response?.data?.error || 'Failed to import certificates'
      );
    } finally {
      domainCheckerImportInFlightRef.current = false;
      setDomainCheckerImporting(false);
    }
  };

  // Form collapse state - collapsed by default for cleaner UI
  const [isFormExpanded, setIsFormExpanded] = useState(false);

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
      const updates = await Promise.allSettled(
        tokenIds.map(id =>
          apiClient.put(API_ENDPOINTS.UPDATE_TOKEN(id), { section: [draft] })
        )
      );
      const successIds = [];
      let failedCount = 0;
      updates.forEach((result, index) => {
        if (result.status === 'fulfilled') successIds.push(tokenIds[index]);
        else failedCount += 1;
      });

      if (successIds.length > 0) {
        safeSetTokens(prev =>
          prev.map(token =>
            successIds.includes(token.id)
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
      toast.error('Failed to assign section');
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

  return (
    <Box>
      <Heading size='lg' mb={8}>
        Token Management Dashboard
      </Heading>

      {/* Token Creation Form (hidden for viewers) - Collapsible */}
      {!isViewer && (
        <Box
          data-tour='add-token-form'
          bg={bgColor}
          p={{ base: 4, md: 6 }}
          borderRadius='lg'
          boxShadow='sm'
          border='1px solid'
          borderColor={borderColor}
          mb={8}
          overflow='visible'
          transition='box-shadow 0.2s ease'
          _hover={{ boxShadow: 'md' }}
        >
          {/* Collapsible Header */}
          <Flex
            align='center'
            justify='space-between'
            direction={{ base: 'column', md: 'row' }}
            gap={{ base: 3, md: 0 }}
            cursor='pointer'
            onClick={() => setIsFormExpanded(!isFormExpanded)}
            py={1}
            _hover={{ opacity: 0.85 }}
            transition='opacity 0.15s ease'
          >
            <HStack spacing={3}>
              <Box
                as='span'
                transition='transform 0.2s ease'
                transform={isFormExpanded ? 'rotate(90deg)' : 'rotate(0deg)'}
                display='flex'
                alignItems='center'
              >
                <FiChevronRight size={18} />
              </Box>
              <Heading size='md'>Create New Token</Heading>
              {!isFormExpanded && (
                <Badge
                  colorScheme='blue'
                  variant='solid'
                  bg={isLight ? 'blue.100' : 'blue.800'}
                  color={isLight ? 'blue.700' : 'blue.200'}
                  fontSize='xs'
                >
                  Click to expand
                </Badge>
              )}
            </HStack>
            <HStack
              spacing={2}
              wrap='wrap'
              justify={{ base: 'center', md: 'flex-end' }}
              align='center'
              maxW='100%'
              onClick={e => e.stopPropagation()}
              position='relative'
              zIndex={1}
            >
              <Menu placement='bottom-end'>
                <MenuButton
                  data-tour='export-tokens'
                  as={Button}
                  leftIcon={<FiDownload />}
                  size='sm'
                  variant='outline'
                  minW='fit-content'
                  maxW={{ base: '100%', sm: 'none' }}
                  whiteSpace='nowrap'
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
                colorScheme='blue'
                variant='outline'
                leftIcon={<FiGlobe />}
                onClick={onDomainModalOpen}
                minW='fit-content'
                aria-label='Endpoint and SSL monitoring (single URL health checks or domain-wide SSL discovery)'
              >
                Endpoint & SSL monitor
              </Button>
              <Box data-tour='import-tokens'>
                <ImportTokensButton />
              </Box>
            </HStack>
          </Flex>

          <Collapse in={isFormExpanded} animateOpacity>
            <Box pt={4}>
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
                        Only workspace managers and admins can set per‑token
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
                      <Input
                        type='text'
                        id='contacts'
                        name='contacts'
                        value={formData.contacts}
                        onChange={onInputChange}
                        bg={inputBg}
                        borderColor={inputBorder}
                        placeholder='Who manages this certificate?'
                        _placeholder={{ color: placeholderColor }}
                        maxLength={200}
                        list='workspace-contacts-suggestions'
                      />
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
                      <Input
                        type='text'
                        id='contacts'
                        name='contacts'
                        value={formData.contacts}
                        onChange={onInputChange}
                        bg={inputBg}
                        borderColor={inputBorder}
                        placeholder='Who manages this key/secret?'
                        _placeholder={{ color: placeholderColor }}
                        maxLength={200}
                        list='workspace-contacts-suggestions'
                      />
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
                      <Input
                        type='text'
                        id='contacts'
                        name='contacts'
                        value={formData.contacts}
                        onChange={onInputChange}
                        bg={inputBg}
                        borderColor={inputBorder}
                        placeholder='Who owns this renewal?'
                        _placeholder={{ color: placeholderColor }}
                        maxLength={200}
                        list='workspace-contacts-suggestions'
                      />
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
                      <Input
                        type='text'
                        id='contacts'
                        name='contacts'
                        value={formData.contacts}
                        onChange={onInputChange}
                        bg={inputBg}
                        borderColor={inputBorder}
                        placeholder='Who manages this item?'
                        _placeholder={{ color: placeholderColor }}
                        maxLength={200}
                        list='workspace-contacts-suggestions'
                      />
                    </FormControl>
                  </SimpleGrid>
                )}

                {/* Datalist for workspace contacts suggestions (creation form) */}
                <datalist id='workspace-contacts-suggestions'>
                  {(Array.isArray(workspaceContacts)
                    ? workspaceContacts
                    : []
                  ).map(c => {
                    const name = [c.first_name, c.last_name]
                      .filter(Boolean)
                      .join(' ')
                      .trim();
                    const phone = (c.phone_e164 || '').trim();
                    const parts = [name, phone].filter(Boolean);
                    const label = parts.join(' - ');
                    return <option key={c.id} value={label} />;
                  })}
                </datalist>

                {/* Notes field for all categories */}
                <FormControl mt={6}>
                  <FormLabel htmlFor='notes'>Notes</FormLabel>
                  <Input
                    type='text'
                    id='notes'
                    name='notes'
                    value={formData.notes}
                    onChange={onInputChange}
                    bg={inputBg}
                    borderColor={inputBorder}
                    placeholder='Additional information'
                    _placeholder={{ color: placeholderColor }}
                    maxLength={500}
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
          </Collapse>
        </Box>
      )}

      <Box mb={6}>
        <Flex
          justify='space-between'
          align={{ base: 'start', md: 'center' }}
          direction={{ base: 'column', md: 'row' }}
          gap={4}
          mb={2}
        >
          <Box>
            {/* Category filter */}
            <Text fontSize='sm' color={filterLabelColor} mb={1}>
              Category filter
            </Text>
          </Box>
        </Flex>
        <HStack spacing={2} flexWrap='wrap' mb={2}>
          {TOKEN_CATEGORIES.map(cat => {
            const isAll = selectedCategories.length === 0;
            const active = selectedCategories.includes(cat.value);
            const _visible = isAll || active;
            // Prefer precomputed counts per category; fallback to facets; finally 0
            const facetsCount = (
              globalFacets.category ||
              tokenFacets.category ||
              []
            ).find(f => String(f.category) === cat.value)?.c;
            const sectionActive =
              (panelQueries.__section || '__all__') !== '__all__';

            // Priority:
            // 1. If facets are available, they always reflect the true intersection (server-side)
            // 2. Fallback to local categoryCounts state
            // 3. Fallback to 0
            const count =
              typeof facetsCount === 'number'
                ? facetsCount
                : sectionActive || selectedCategories.length > 0
                  ? (() => {
                      const sec = panelQueries.__section;
                      const norm = v =>
                        String(v || '')
                          .trim()
                          .toLowerCase();
                      if (sec === '__none__') {
                        return tokens.filter(
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

                      return tokens.filter(t => {
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

            return (
              <Button
                key={cat.value}
                size='sm'
                variant={active ? 'solid' : 'outline'}
                colorScheme={cat.color}
                fontWeight={active ? 'semibold' : 'medium'}
                bg={
                  active
                    ? `${cat.color}.500`
                    : isLight
                      ? `${cat.color}.100`
                      : `${cat.color}.900`
                }
                color={
                  active
                    ? 'white'
                    : isLight
                      ? `${cat.color}.600`
                      : `${cat.color}.200`
                }
                borderWidth='1px'
                borderColor={
                  active
                    ? `${cat.color}.500`
                    : isLight
                      ? `${cat.color}.500`
                      : `${cat.color}.600`
                }
                _hover={{
                  bg: active
                    ? `${cat.color}.600`
                    : isLight
                      ? `${cat.color}.200`
                      : `${cat.color}.800`,
                  borderColor: `${cat.color}.${active ? '600' : '600'}`,
                }}
                transition='all 0.15s ease'
                onClick={() => {
                  setSelectedCategories(_prev => (active ? [] : [cat.value]));
                }}
              >
                {cat.label}
                <Badge
                  ml={2}
                  variant='solid'
                  bg={
                    active
                      ? 'whiteAlpha.300'
                      : isLight
                        ? `${cat.color}.500`
                        : `${cat.color}.700`
                  }
                  color='white'
                  fontSize='xs'
                  fontWeight='bold'
                >
                  {count}
                </Badge>
              </Button>
            );
          })}
        </HStack>
        {/* Section filter */}
        <Text fontSize='sm' color={filterLabelColor} mt={4} mb={1}>
          Section filter
        </Text>
        <HStack spacing={2} flexWrap='wrap' mt={3}>
          {(() => {
            // Helper to normalize and split strings
            const norm = v =>
              String(v || '')
                .trim()
                .toLowerCase();
            const splitAndTrim = val =>
              String(val || '')
                .split(',')
                .map(s => s.trim())
                .filter(Boolean);

            // 1. Build initial flattened list from backend facets
            const facetSource =
              globalFacets.section || tokenFacets.section || [];
            const rawMap = {};

            facetSource.forEach(r => {
              const labels = splitAndTrim(r.section);
              if (labels.length === 0) {
                const key = '';
                if (!rawMap[key]) rawMap[key] = { name: '', count: 0 };
                rawMap[key].count += r.c || 0;
              } else {
                labels.forEach(l => {
                  const key = norm(l);
                  if (!rawMap[key]) rawMap[key] = { name: l, count: 0 };
                  rawMap[key].count = Math.max(rawMap[key].count, r.c || 0);
                });
              }
            });

            // 2. Merge in sections from current tokens for immediate UI feedback
            try {
              tokens.forEach(t => {
                // IMPORTANT: Only merge sections from tokens that match the current category filter
                // to avoid showing sections from other categories.
                if (
                  selectedCategories.length > 0 &&
                  !selectedCategories.includes(t.category)
                ) {
                  return;
                }

                // ALSO: Only merge sections from tokens that match the current section filter (AND logic)
                const currentSection = panelQueries.__section || '__all__';
                if (currentSection !== '__all__') {
                  const tokenSections = Array.isArray(t.section)
                    ? t.section.map(s => norm(s))
                    : [norm(t.section)];

                  if (currentSection === '__none__') {
                    if (
                      t.section &&
                      (!Array.isArray(t.section) || t.section.length > 0)
                    )
                      return;
                  } else {
                    const wanted = currentSection
                      .split(',')
                      .map(s => norm(s))
                      .filter(Boolean);
                    if (!wanted.every(w => tokenSections.includes(w))) {
                      return;
                    }
                  }
                }

                const labels = Array.isArray(t.section)
                  ? t.section.flatMap(s => splitAndTrim(s))
                  : splitAndTrim(t.section);

                if (labels.length === 0) {
                  const key = '';
                  if (!rawMap[key]) rawMap[key] = { name: '', count: 0 };
                } else {
                  const uniqueInToken = [...new Set(labels.map(s => norm(s)))];
                  uniqueInToken.forEach(key => {
                    const originalLabel = labels.find(s => norm(s) === key);
                    if (!rawMap[key])
                      rawMap[key] = { name: originalLabel, count: 0 };
                  });
                }
              });
            } catch (_) {}

            const raw = Object.values(rawMap);
            raw.sort(
              (a, b) => b.count - a.count || a.name.localeCompare(b.name)
            );

            const allCount =
              selectedCategories.length > 0
                ? selectedCategories.reduce(
                    (sum, cat) => sum + (categoryCounts[cat] || 0),
                    0
                  )
                : Object.values(categoryCounts).reduce(
                    (sum, c) => sum + (c || 0),
                    0
                  );

            const all = [
              {
                name: '__all__',
                label: 'All sections',
                count: allCount,
              },
              {
                name: '__none__',
                label: 'No section',
                count: rawMap['']?.count || 0,
              },
              ...raw
                .filter(s => (s.name || '').length > 0 && s.count > 0)
                .map(s => ({ name: s.name, label: s.name, count: s.count })),
            ];
            return all.map(s => {
              const current = panelQueries.__section || '__all__';
              let active = false;
              if (s.name === '__all__') {
                active = current === '__all__';
              } else if (s.name === '__none__') {
                active = current === '__none__';
              } else {
                active = current.split(',').includes(s.name);
              }
              const scheme =
                s.name === '__none__'
                  ? 'gray'
                  : s.name === '__all__'
                    ? 'blue'
                    : _getSectionColorScheme(s.name);
              return (
                <Button
                  key={`section-${s.name || 'none'}`}
                  size='sm'
                  variant={active ? 'solid' : 'outline'}
                  colorScheme={scheme}
                  fontWeight={active ? 'semibold' : 'medium'}
                  bg={
                    active
                      ? `${scheme}.500`
                      : isLight
                        ? `${scheme}.100`
                        : `${scheme}.900`
                  }
                  color={
                    active
                      ? 'white'
                      : isLight
                        ? `${scheme}.600`
                        : `${scheme}.200`
                  }
                  borderWidth='1px'
                  borderColor={
                    active
                      ? `${scheme}.500`
                      : isLight
                        ? `${scheme}.500`
                        : `${scheme}.600`
                  }
                  _hover={{
                    bg: active
                      ? `${scheme}.600`
                      : isLight
                        ? `${scheme}.200`
                        : `${scheme}.800`,
                    borderColor: `${scheme}.${active ? '600' : '600'}`,
                  }}
                  transition='all 0.15s ease'
                  onClick={() => {
                    const currentVal = panelQueries?.__section || '__all__';
                    let next;

                    if (s.name === '__all__') {
                      next = '__all__';
                    } else if (s.name === '__none__') {
                      next = '__none__';
                    } else {
                      // Multi-select logic for specific sections
                      let parts =
                        currentVal === '__all__' || currentVal === '__none__'
                          ? []
                          : currentVal.split(',').filter(Boolean);

                      if (parts.includes(s.name)) {
                        parts = parts.filter(p => p !== s.name);
                      } else {
                        parts.push(s.name);
                      }

                      next = parts.length > 0 ? parts.join(',') : '__all__';
                    }

                    setPanelQueries(prev => ({ ...prev, __section: next }));
                    // Reflect selection in URL so downstream fetches include section
                    try {
                      const search = new URLSearchParams(
                        window.location.search
                      );
                      if (next === '__all__') search.delete('section');
                      else search.set('section', next);
                      navigate(`/dashboard?${search.toString()}`, {
                        replace: true,
                      });
                    } catch (_) {}
                  }}
                >
                  {s.label}
                  <Badge
                    ml={2}
                    variant='solid'
                    bg={
                      active
                        ? 'whiteAlpha.300'
                        : isLight
                          ? `${scheme}.200`
                          : `${scheme}.700`
                    }
                    color={
                      active
                        ? 'white'
                        : isLight
                          ? `${scheme}.800`
                          : `${scheme}.100`
                    }
                    fontSize='xs'
                    fontWeight='bold'
                  >
                    {s.count}
                  </Badge>
                </Button>
              );
            });
          })()}
        </HStack>
        <Box h={4} />
      </Box>

      {/* Tokens List - Organized by Categories */}
      {tokensLoading && tokens.length === 0 ? (
        <Flex justify='center' p={{ base: 4, md: 8 }} overflowX='hidden'>
          <AccessibleSpinner size='lg' aria-label='Loading tokens' />
        </Flex>
      ) : tokens.length === 0 ? (
        <Text
          textAlign='center'
          color={emptyTextColor}
          p={{ base: 4, md: 8 }}
          overflowX='hidden'
        >
          {isViewer
            ? 'No tokens in this workspace.'
            : 'No tokens found. Create your first token above.'}
        </Text>
      ) : (
        <VStack
          data-tour='token-list'
          spacing={6}
          align='stretch'
          style={{
            transition: 'opacity 180ms ease, transform 180ms ease',
            opacity: isRefreshing ? 0.35 : 1,
            transform: isRefreshing ? 'scale(0.995)' : 'scale(1)',
          }}
        >
          {TOKEN_CATEGORIES.map(category => {
            const panelSearch =
              (panelQueries && panelQueries[category.value]) || '';
            const sectionParam =
              (panelQueries && panelQueries.__section) || '__all__';
            const categoryTokens = getFilteredAndSortedTokens(
              tokens,
              category,
              panelSearch,
              sectionParam
            );

            // Hide entire panel if a category filter is active and this category is not selected
            if (
              Array.isArray(selectedCategories) &&
              selectedCategories.length > 0 &&
              !selectedCategories.includes(category.value)
            ) {
              return null;
            }

            return (
              <Collapse key={category.value} in={true} animateOpacity>
                <Box
                  bg={bgColor}
                  p={{ base: 4, md: 6 }}
                  borderRadius='lg'
                  boxShadow='sm'
                  border='1px solid'
                  borderColor={borderColor}
                  borderTopWidth='3px'
                  borderTopColor={`${category.color}.500`}
                  transition='all 180ms ease'
                  overflowX='hidden'
                  _hover={{ boxShadow: 'md' }}
                >
                  <Flex align='center' justify='space-between' mb={4}>
                    <HStack spacing={4}>
                      <Heading
                        size='md'
                        color={`${category.color}.${isLight ? '600' : '400'}`}
                      >
                        {category.label}
                      </Heading>
                      {(() => {
                        const selectedInCategory = selectedTokenIds.filter(id =>
                          categoryTokens.some(t => t.id === id)
                        );
                        if (!isViewer && selectedInCategory.length > 0) {
                          return (
                            <HStack spacing={2} flexWrap='nowrap'>
                              <Button
                                size='xs'
                                colorScheme='red'
                                variant='outline'
                                leftIcon={<FiTrash2 />}
                                onClick={handleBulkDelete}
                              >
                                Delete ({selectedInCategory.length})
                              </Button>
                              <Button
                                size='xs'
                                colorScheme='blue'
                                variant='outline'
                                onClick={() =>
                                  handleBulkAssignSection(
                                    selectedInCategory,
                                    category.value
                                  )
                                }
                              >
                                Assign section
                              </Button>
                              <Input
                                size='xs'
                                maxW='150px'
                                placeholder='Section label'
                                value={
                                  bulkSectionDrafts?.[category.value] || ''
                                }
                                onChange={e =>
                                  setBulkSectionDrafts(prev => ({
                                    ...prev,
                                    [category.value]: e.target.value,
                                  }))
                                }
                              />
                            </HStack>
                          );
                        }
                        return null;
                      })()}
                    </HStack>
                    <Input
                      value={panelQueries[category.value] || ''}
                      onChange={e =>
                        setPanelQueries(prev => ({
                          ...prev,
                          [category.value]: e.target.value,
                        }))
                      }
                      placeholder={`Search ${category.label.toLowerCase()}...`}
                      size='sm'
                      maxW='260px'
                      bg={inputBg}
                      borderColor={borderColor}
                    />
                  </Flex>

                  {categoryTokens.length === 0 ? (
                    <Text color={emptyTextColor} fontSize='sm' py={2}>
                      No results in this category.
                    </Text>
                  ) : (
                    <>
                      {/* Mobile: Card list */}
                      <Box display={{ base: 'block', md: 'none' }}>
                        <VStack align='stretch' spacing={3}>
                          {categoryTokens.map(token => {
                            const type = category.types.find(
                              t => t.value === token.type
                            );
                            return (
                              <Box
                                key={token.id}
                                p={4}
                                bg={mobileCardBg}
                                border='1px solid'
                                borderColor={borderColor}
                                borderRadius='md'
                              >
                                <HStack
                                  justify='space-between'
                                  align='start'
                                  mb={2}
                                  gap={2}
                                >
                                  <Box flex='1' minW='0'>
                                    <Text
                                      fontWeight='semibold'
                                      wordBreak='break-word'
                                    >
                                      {token.name}
                                    </Text>
                                    <Text
                                      fontSize='sm'
                                      color={secondaryTextColor}
                                      noOfLines={1}
                                    >
                                      {type?.label || token.type}
                                      {token.category === 'cert' &&
                                      token.domains?.length
                                        ? ` • ${token.domains.join(', ')}`
                                        : token.category === 'key_secret' &&
                                            token.location
                                          ? ` • ${token.location}`
                                          : token.category === 'license' &&
                                              token.vendor
                                            ? ` • ${token.vendor}`
                                            : token.category === 'general' &&
                                                token.used_by
                                              ? ` • ${token.used_by}`
                                              : ''}
                                    </Text>
                                  </Box>
                                  <ExpiryPill expiry={token.expiresAt} />
                                  {token.monitor_health_status && (
                                    <Tooltip
                                      label={`${token.monitor_url || 'Endpoint'}: ${token.monitor_health_status}${token.monitor_response_ms ? ` (${token.monitor_response_ms}ms)` : ''}`}
                                    >
                                      <Box as='span' display='inline-flex'>
                                        <FiActivity
                                          size={18}
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
                                <VStack align='stretch' spacing={2}>
                                  <Text fontSize='sm' color='gray.600'>
                                    {isNeverExpires(token.expiresAt)
                                      ? formatExpirationDate(token.expiresAt)
                                      : `Expires ${formatDate(token.expiresAt)}`}
                                  </Text>
                                  {token.last_used && (
                                    <Text fontSize='xs' color='gray.500'>
                                      Last used: {formatDate(token.last_used)}
                                    </Text>
                                  )}
                                  <HStack spacing={2} flexWrap='wrap'>
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
                                          onClick={() =>
                                            onDeleteToken(token.id)
                                          }
                                        >
                                          Delete
                                        </Button>
                                      </>
                                    )}
                                  </HStack>
                                </VStack>
                              </Box>
                            );
                          })}
                        </VStack>
                      </Box>

                      {/* Desktop: Table */}
                      <Box
                        overflowX='auto'
                        display={{ base: 'none', md: 'block' }}
                      >
                        <Table
                          variant='simple'
                          size='sm'
                          transition='opacity 160ms ease'
                          opacity={isRefreshing ? 0.7 : 1}
                        >
                          <Thead>
                            <Tr
                              borderBottom='2px solid'
                              borderColor={borderColor}
                            >
                              {!isViewer && (
                                <Th width='40px'>
                                  <Checkbox
                                    isChecked={
                                      categoryTokens.length > 0 &&
                                      categoryTokens.every(t =>
                                        selectedTokenIds.includes(t.id)
                                      )
                                    }
                                    isIndeterminate={
                                      categoryTokens.some(t =>
                                        selectedTokenIds.includes(t.id)
                                      ) &&
                                      !categoryTokens.every(t =>
                                        selectedTokenIds.includes(t.id)
                                      )
                                    }
                                    onChange={e => {
                                      const ids = categoryTokens.map(t => t.id);
                                      if (e.target.checked) {
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
                              <SortableTh
                                minW='100px'
                                sortKey='name'
                                sortConfig={sortConfigs[category.value] || {}}
                                onSort={key => onSort(key, category.value)}
                                hoverBg={thHoverBg}
                              >
                                Name
                              </SortableTh>
                              <SortableTh
                                minW='110px'
                                sortKey='type'
                                sortConfig={sortConfigs[category.value] || {}}
                                onSort={key => onSort(key, category.value)}
                                hoverBg={thHoverBg}
                              >
                                Type
                              </SortableTh>
                              {category.value === 'cert' && (
                                <>
                                  <SortableTh
                                    minW='130px'
                                    sortKey='domains'
                                    sortConfig={
                                      sortConfigs[category.value] || {}
                                    }
                                    onSort={key => onSort(key, category.value)}
                                    hoverBg={thHoverBg}
                                  >
                                    Domains
                                  </SortableTh>
                                  <SortableTh
                                    minW='100px'
                                    sortKey='issuer'
                                    sortConfig={
                                      sortConfigs[category.value] || {}
                                    }
                                    onSort={key => onSort(key, category.value)}
                                    hoverBg={thHoverBg}
                                  >
                                    Issuer
                                  </SortableTh>
                                </>
                              )}
                              {category.value === 'key_secret' && (
                                <>
                                  <SortableTh
                                    minW='100px'
                                    sortKey='location'
                                    sortConfig={
                                      sortConfigs[category.value] || {}
                                    }
                                    onSort={key => onSort(key, category.value)}
                                    hoverBg={thHoverBg}
                                  >
                                    Location
                                  </SortableTh>
                                  <SortableTh
                                    minW='120px'
                                    sortKey='used_by'
                                    sortConfig={
                                      sortConfigs[category.value] || {}
                                    }
                                    onSort={key => onSort(key, category.value)}
                                    hoverBg={thHoverBg}
                                  >
                                    Used By
                                  </SortableTh>
                                  <SortableTh
                                    minW='130px'
                                    sortKey='privileges'
                                    sortConfig={
                                      sortConfigs[category.value] || {}
                                    }
                                    onSort={key => onSort(key, category.value)}
                                    hoverBg={thHoverBg}
                                  >
                                    Privileges
                                  </SortableTh>
                                  <SortableTh
                                    minW='90px'
                                    sortKey='last_used'
                                    sortConfig={
                                      sortConfigs[category.value] || {}
                                    }
                                    onSort={key => onSort(key, category.value)}
                                    hoverBg={thHoverBg}
                                  >
                                    Last Used
                                  </SortableTh>
                                </>
                              )}
                              {category.value === 'license' && (
                                <>
                                  <SortableTh
                                    minW='120px'
                                    sortKey='vendor'
                                    sortConfig={
                                      sortConfigs[category.value] || {}
                                    }
                                    onSort={key => onSort(key, category.value)}
                                    hoverBg={thHoverBg}
                                  >
                                    Vendor
                                  </SortableTh>
                                  <SortableTh
                                    minW='130px'
                                    sortKey='license_type'
                                    sortConfig={
                                      sortConfigs[category.value] || {}
                                    }
                                    onSort={key => onSort(key, category.value)}
                                    hoverBg={thHoverBg}
                                  >
                                    License Type
                                  </SortableTh>
                                </>
                              )}
                              {category.value === 'general' && (
                                <>
                                  <SortableTh
                                    minW='100px'
                                    sortKey='location'
                                    sortConfig={
                                      sortConfigs[category.value] || {}
                                    }
                                    onSort={key => onSort(key, category.value)}
                                    hoverBg={thHoverBg}
                                  >
                                    Location
                                  </SortableTh>
                                  <SortableTh
                                    minW='150px'
                                    sortKey='used_by'
                                    sortConfig={
                                      sortConfigs[category.value] || {}
                                    }
                                    onSort={key => onSort(key, category.value)}
                                    hoverBg={thHoverBg}
                                  >
                                    Used By
                                  </SortableTh>
                                </>
                              )}
                              <SortableTh
                                minW='90px'
                                sortKey='expiresAt'
                                sortConfig={sortConfigs[category.value] || {}}
                                onSort={key => onSort(key, category.value)}
                                hoverBg={thHoverBg}
                              >
                                Expiration
                              </SortableTh>
                              <Th minW='70px'>Status</Th>
                              <Th textAlign='center' minW='90px'>
                                {isViewer ? 'Details' : 'Actions'}
                              </Th>
                            </Tr>
                          </Thead>
                          <Tbody>
                            {categoryTokens.map(token => {
                              const type = category.types.find(
                                t => t.value === token.type
                              );
                              // Get status color for left border accent
                              const statusInfo = getExpiryStatus(
                                token.expiresAt
                              );

                              return (
                                <Tr
                                  key={token.id}
                                  borderBottom='1px solid'
                                  borderColor={borderColor}
                                  cursor='pointer'
                                  onClick={e => {
                                    // Don't trigger if clicking on buttons or checkboxes
                                    if (e.target.closest('button')) return;
                                    if (
                                      e.target.closest('input[type="checkbox"]')
                                    )
                                      return;
                                    onOpenTokenModal(token);
                                  }}
                                  _hover={{
                                    bg: hoverBgColor,
                                  }}
                                  transition='all 0.15s ease'
                                >
                                  {!isViewer && (
                                    <Td
                                      onClick={e => e.stopPropagation()}
                                      borderLeft='4px solid'
                                      borderLeftColor={statusInfo.color}
                                    >
                                      <Checkbox
                                        isChecked={selectedTokenIds.includes(
                                          token.id
                                        )}
                                        onChange={() =>
                                          toggleTokenSelection(token.id)
                                        }
                                      />
                                    </Td>
                                  )}
                                  <Td
                                    fontWeight='medium'
                                    {...(isViewer
                                      ? {
                                          borderLeft: '4px solid',
                                          borderLeftColor: statusInfo.color,
                                        }
                                      : {})}
                                  >
                                    <Text
                                      wordBreak='break-word'
                                      whiteSpace='normal'
                                    >
                                      {token.name}
                                    </Text>
                                  </Td>
                                  <Td>
                                    <TruncatedText
                                      text={type?.label || token.type}
                                      maxLines={3}
                                      maxWidth='110px'
                                    />
                                  </Td>

                                  {/* Certificate-specific columns */}
                                  {category.value === 'cert' && (
                                    <>
                                      <Td>
                                        {token.domains &&
                                        token.domains.length > 0 ? (
                                          <VStack align='start' spacing={1}>
                                            <HStack
                                              spacing={1}
                                              minW='0'
                                              w='full'
                                            >
                                              <Link
                                                href={domainValueToUrl(
                                                  token.domains[0]
                                                )}
                                                isExternal
                                                fontSize='sm'
                                                color='blue.400'
                                                textDecoration='underline'
                                                display='block'
                                                whiteSpace='normal'
                                                wordBreak='break-all'
                                                overflowWrap='anywhere'
                                                flex='1'
                                                onClick={e =>
                                                  e.stopPropagation()
                                                }
                                              >
                                                {token.domains[0]}
                                              </Link>
                                              <IconButton
                                                as='a'
                                                href={domainValueToUrl(
                                                  token.domains[0]
                                                )}
                                                target='_blank'
                                                rel='noopener'
                                                size='xs'
                                                variant='ghost'
                                                icon={<FiExternalLink />}
                                                aria-label='Open domain'
                                                onClick={e =>
                                                  e.stopPropagation()
                                                }
                                              />
                                            </HStack>
                                            {token.domains.length > 1 && (
                                              <Text
                                                fontSize='xs'
                                                color={secondaryTextColor}
                                              >
                                                +{token.domains.length - 1} more
                                              </Text>
                                            )}
                                          </VStack>
                                        ) : (
                                          <Text color={emptyTextColor}>-</Text>
                                        )}
                                      </Td>
                                      <Td>
                                        <TruncatedText
                                          text={token.issuer}
                                          maxLines={3}
                                          maxWidth='100px'
                                        />
                                      </Td>
                                    </>
                                  )}

                                  {/* Key/Secret-specific columns */}
                                  {category.value === 'key_secret' && (
                                    <>
                                      <Td>
                                        <TruncatedText
                                          text={token.location}
                                          maxLines={3}
                                          maxWidth='100px'
                                        />
                                      </Td>
                                      <Td>
                                        <TruncatedText
                                          text={token.used_by}
                                          maxLines={3}
                                          maxWidth='120px'
                                        />
                                      </Td>
                                      <Td>
                                        <TruncatedText
                                          text={token.privileges}
                                          maxLines={3}
                                          maxWidth='130px'
                                        />
                                      </Td>
                                      <Td>
                                        <Text fontSize='xs' color='gray.500'>
                                          {token.last_used
                                            ? formatDate(token.last_used)
                                            : '-'}
                                        </Text>
                                      </Td>
                                    </>
                                  )}

                                  {/* License-specific columns */}
                                  {category.value === 'license' && (
                                    <>
                                      <Td>
                                        <TruncatedText
                                          text={token.vendor}
                                          maxLines={3}
                                          maxWidth='120px'
                                        />
                                      </Td>
                                      <Td>
                                        <TruncatedText
                                          text={token.license_type}
                                          maxLines={3}
                                          maxWidth='130px'
                                        />
                                      </Td>
                                    </>
                                  )}

                                  {/* General-specific columns */}
                                  {category.value === 'general' && (
                                    <>
                                      <Td>
                                        <TruncatedText
                                          text={token.location}
                                          maxLines={3}
                                          maxWidth='100px'
                                        />
                                      </Td>
                                      <Td>
                                        <TruncatedText
                                          text={token.used_by}
                                          maxLines={3}
                                          maxWidth='150px'
                                        />
                                      </Td>
                                    </>
                                  )}

                                  <Td>
                                    {formatExpirationDate(token.expiresAt)}
                                  </Td>
                                  <Td>
                                    <HStack spacing={2} align='center'>
                                      <ExpiryPill expiry={token.expiresAt} />
                                      {token.monitor_health_status && (
                                        <Tooltip
                                          label={`${token.monitor_url || 'Endpoint'}: ${token.monitor_health_status}${token.monitor_response_ms ? ` (${token.monitor_response_ms}ms)` : ''}`}
                                        >
                                          <Box as='span' display='inline-flex'>
                                            <FiActivity
                                              size={18}
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
                                  <Td textAlign='center'>
                                    <VStack spacing={1} align='center'>
                                      <Button
                                        onClick={() => onOpenTokenModal(token)}
                                        colorScheme='blue'
                                        size='xs'
                                        aria-label={`Show full details for token ${token.name}`}
                                      >
                                        Details
                                      </Button>
                                      {!isViewer && (
                                        <>
                                          <Button
                                            onClick={() => onOpenRenew(token)}
                                            colorScheme='teal'
                                            size='xs'
                                            aria-label={`Renew token ${token.name}`}
                                          >
                                            Renew
                                          </Button>
                                          <Button
                                            onClick={() =>
                                              onDeleteToken(token.id)
                                            }
                                            colorScheme='red'
                                            size='xs'
                                            aria-label={`Delete token ${token.name}`}
                                          >
                                            Delete
                                          </Button>
                                        </>
                                      )}
                                    </VStack>
                                  </Td>
                                </Tr>
                              );
                            })}
                          </Tbody>
                        </Table>
                      </Box>
                    </>
                  )}
                  {categoryHasMore?.[category.value] && (
                    <Flex justify='center' mt={4}>
                      <Button
                        size='sm'
                        onClick={() => fetchTokensForCategory(category.value)}
                        isLoading={!!categoryLoading?.[category.value]}
                        loadingText='Loading...'
                      >
                        Load more {category.label}
                      </Button>
                    </Flex>
                  )}
                </Box>
              </Collapse>
            );
          })}
        </VStack>
      )}

      {/* Global load more removed in favor of per-category controls */}

      {/* Endpoint & SSL monitoring modal: single-URL health checks + Domain Checker SSL discovery */}
      <Modal
        isOpen={isDomainModalOpen}
        onClose={handleDomainModalClose}
        size='xl'
      >
        <ModalOverlay />
        <ModalContent maxW='1100px'>
          <ModalHeader>Endpoint & SSL monitoring</ModalHeader>
          <ModalCloseButton />
          <ModalBody data-endpoint-ssl-modal-body='true'>
            <VStack spacing={5} align='stretch'>
              <Text fontSize='sm' color={helpTextColor}>
                Monitor SSL certificates and endpoint health for your URLs.
                Tokens are auto-created for each SSL certificate detected.
              </Text>

              {domainCheckerImportReport && (
                <Box
                  p={3}
                  borderRadius='md'
                  borderWidth='1px'
                  borderColor={domainBorderColor}
                  fontSize='sm'
                >
                  <HStack justify='space-between' align='start' spacing={3}>
                    <Box>
                      <Text fontWeight='semibold'>Last import summary</Text>
                      <Text color={helpTextColor}>
                        {domainCheckerImportReport.importedLowerBound
                          ? 'At least '
                          : ''}
                        {domainCheckerImportReport.imported} SSL token
                        {domainCheckerImportReport.imported === 1
                          ? ''
                          : 's'}{' '}
                        {domainCheckerImportReport.importedLowerBound
                          ? 'confirmed in completed responses'
                          : 'created'}
                        , {domainCheckerImportReport.errorLike} skipped,{' '}
                        {domainCheckerImportReport.unreachable} unreachable.
                      </Text>
                    </Box>
                    <Button
                      size='xs'
                      variant='ghost'
                      onClick={() => {
                        setDomainCheckerImportReport(null);
                        setDomainCheckerImportReportOpen(false);
                      }}
                    >
                      Dismiss
                    </Button>
                  </HStack>
                  {domainCheckerImportReport.logLines.length > 0 && (
                    <>
                      <Button
                        variant='link'
                        size='xs'
                        mt={1}
                        rightIcon={
                          domainCheckerImportReportOpen ? (
                            <FiChevronUp />
                          ) : (
                            <FiChevronDown />
                          )
                        }
                        onClick={() =>
                          setDomainCheckerImportReportOpen(o => !o)
                        }
                      >
                        {domainCheckerImportReportOpen
                          ? 'Show less'
                          : 'Show more'}
                      </Button>
                      <Collapse
                        in={domainCheckerImportReportOpen}
                        animateOpacity
                      >
                        <Box
                          as='pre'
                          mt={2}
                          p={2}
                          borderRadius='md'
                          bg='blackAlpha.50'
                          _dark={{ bg: 'whiteAlpha.100' }}
                          fontSize='xs'
                          whiteSpace='pre-wrap'
                          wordBreak='break-word'
                          maxH='220px'
                          overflowY='auto'
                        >
                          {domainCheckerImportReport.logLines.join('\n')}
                        </Box>
                      </Collapse>
                    </>
                  )}
                </Box>
              )}

              {/* Existing domains list */}
              {domainsLoading ? (
                <Text fontSize='sm' color={helpTextColor}>
                  Loading endpoints...
                </Text>
              ) : domains.length === 0 ? (
                <Alert status='info' borderRadius='md' size='sm'>
                  <AlertIcon />
                  <AlertDescription fontSize='sm'>
                    No endpoints monitored yet. Add one below to start tracking
                    SSL certificates and endpoint health.
                  </AlertDescription>
                </Alert>
              ) : (
                <>
                  {visibleDomains.length === 0 ? (
                    <Alert status='info' borderRadius='md' size='sm'>
                      <AlertIcon />
                      <AlertDescription fontSize='sm'>
                        No endpoints match your current filters.
                      </AlertDescription>
                    </Alert>
                  ) : (
                    <>
                      {/* Mobile: Card list */}
                      <Box display={{ base: 'block', md: 'none' }}>
                        <VStack align='stretch' spacing={3}>
                          {visibleDomains.map(d => (
                            <Box
                              key={d.id}
                              p={4}
                              bg={mobileCardBg}
                              border='1px solid'
                              borderColor={domainBorderColor}
                              borderRadius='md'
                            >
                              <HStack
                                justify='space-between'
                                align='start'
                                mb={2}
                              >
                                <Box flex='1' minW='0'>
                                  <HStack spacing={1}>
                                    <Text
                                      fontWeight='semibold'
                                      fontSize='sm'
                                      wordBreak='break-all'
                                    >
                                      {domainFormatUrl(d.url)}
                                    </Text>
                                    <IconButton
                                      as='a'
                                      href={d.url}
                                      target='_blank'
                                      rel='noopener'
                                      size='xs'
                                      variant='ghost'
                                      icon={<FiExternalLink />}
                                      aria-label='Open'
                                    />
                                  </HStack>
                                  {d.ssl_issuer && (
                                    <Text fontSize='xs' color={helpTextColor}>
                                      Issuer: {d.ssl_issuer}
                                    </Text>
                                  )}
                                </Box>
                                <HStack spacing={1}>
                                  <IconButton
                                    size='xs'
                                    icon={<FiRefreshCw />}
                                    aria-label='Check now'
                                    onClick={event =>
                                      handleCheckDomain(d.id, event)
                                    }
                                    isLoading={checkingDomain === d.id}
                                  />
                                  <IconButton
                                    size='xs'
                                    icon={<FiTrash2 />}
                                    aria-label='Delete'
                                    colorScheme='red'
                                    variant='ghost'
                                    onClick={() => handleDeleteDomain(d.id)}
                                  />
                                </HStack>
                              </HStack>
                              <HStack spacing={2} flexWrap='wrap' mb={2}>
                                {domainSslBadge(d)}
                                {d.last_health_status ? (
                                  <Badge
                                    colorScheme={domainStatusColor(
                                      d.last_health_status
                                    )}
                                  >
                                    {d.last_health_status}
                                  </Badge>
                                ) : (
                                  <Badge colorScheme='gray'>Pending</Badge>
                                )}
                                <Badge variant='outline'>
                                  {d.check_interval}
                                </Badge>
                                <Badge variant='outline' colorScheme='orange'>
                                  {d.alert_after_failures || 2}x
                                </Badge>
                              </HStack>
                              <HStack
                                spacing={4}
                                fontSize='xs'
                                color={helpTextColor}
                              >
                                {d.last_health_response_ms != null && (
                                  <Text>{d.last_health_response_ms}ms</Text>
                                )}
                                {d.last_health_check_at && (
                                  <Text>
                                    {new Date(
                                      d.last_health_check_at
                                    ).toLocaleString()}
                                  </Text>
                                )}
                              </HStack>
                            </Box>
                          ))}
                        </VStack>
                      </Box>

                      {/* Desktop: Table */}
                      <Box
                        display={{ base: 'none', md: 'block' }}
                        borderRadius='md'
                        border='1px solid'
                        borderColor={domainBorderColor}
                        overflow='auto'
                      >
                        <Table size='sm' variant='simple' tableLayout='fixed'>
                          <Thead>
                            <Tr>
                              <Th
                                w='28%'
                                cursor='pointer'
                                userSelect='none'
                                onClick={() => handleDomainListSort('az')}
                              >
                                <HStack spacing={1} justify='space-between'>
                                  <Text>Endpoint</Text>
                                  {renderDomainSortArrow('az')}
                                </HStack>
                              </Th>
                              <Th
                                whiteSpace='nowrap'
                                cursor='pointer'
                                userSelect='none'
                                onClick={() =>
                                  handleDomainListSort('expiration')
                                }
                              >
                                <HStack spacing={1} justify='space-between'>
                                  <Text>SSL</Text>
                                  {renderDomainSortArrow('expiration')}
                                </HStack>
                              </Th>
                              <Th
                                whiteSpace='nowrap'
                                cursor='pointer'
                                userSelect='none'
                                onClick={() => handleDomainListSort('health')}
                              >
                                <HStack spacing={1} justify='space-between'>
                                  <Text>Health</Text>
                                  {renderDomainSortArrow('health')}
                                </HStack>
                              </Th>
                              <Th whiteSpace='nowrap'>Response</Th>
                              <Th whiteSpace='nowrap'>Last Check</Th>
                              <Th
                                whiteSpace='nowrap'
                                cursor='pointer'
                                userSelect='none'
                                onClick={() => handleDomainListSort('interval')}
                              >
                                <HStack spacing={1} justify='space-between'>
                                  <Text>Interval</Text>
                                  {renderDomainSortArrow('interval')}
                                </HStack>
                              </Th>
                              <Th whiteSpace='nowrap'>Alert after</Th>
                              <Th
                                textAlign='right'
                                whiteSpace='nowrap'
                                width='92px'
                              ></Th>
                            </Tr>
                          </Thead>
                          <Tbody>
                            {visibleDomains.map(d => (
                              <Tr key={d.id}>
                                <Td maxW='0'>
                                  <HStack spacing={1} minW='0'>
                                    <Text
                                      fontWeight='medium'
                                      fontSize='sm'
                                      whiteSpace='normal'
                                      wordBreak='break-all'
                                      overflowWrap='anywhere'
                                      flex='1'
                                      minW='0'
                                    >
                                      {domainFormatUrl(d.url)}
                                    </Text>
                                    <Tooltip label='Open in browser'>
                                      <IconButton
                                        as='a'
                                        href={d.url}
                                        target='_blank'
                                        rel='noopener'
                                        size='xs'
                                        variant='ghost'
                                        icon={<FiExternalLink />}
                                        aria-label='Open'
                                      />
                                    </Tooltip>
                                  </HStack>
                                  {d.ssl_issuer && (
                                    <Text fontSize='2xs' color={helpTextColor}>
                                      Issuer: {d.ssl_issuer}
                                    </Text>
                                  )}
                                </Td>
                                <Td whiteSpace='nowrap'>{domainSslBadge(d)}</Td>
                                <Td whiteSpace='nowrap'>
                                  {d.last_health_status ? (
                                    <Tooltip
                                      label={
                                        d.last_health_error ||
                                        `HTTP ${d.last_health_status_code}`
                                      }
                                    >
                                      <Badge
                                        colorScheme={domainStatusColor(
                                          d.last_health_status
                                        )}
                                      >
                                        {d.last_health_status}
                                      </Badge>
                                    </Tooltip>
                                  ) : (
                                    <Badge colorScheme='gray'>Pending</Badge>
                                  )}
                                </Td>
                                <Td fontSize='xs' whiteSpace='nowrap'>
                                  {d.last_health_response_ms != null
                                    ? `${d.last_health_response_ms}ms`
                                    : '-'}
                                </Td>
                                <Td fontSize='xs' whiteSpace='nowrap'>
                                  {d.last_health_check_at
                                    ? new Date(
                                        d.last_health_check_at
                                      ).toLocaleString()
                                    : '-'}
                                </Td>
                                <Td whiteSpace='nowrap'>
                                  <Badge variant='outline'>
                                    {d.check_interval}
                                  </Badge>
                                </Td>
                                <Td>
                                  <Tooltip
                                    label={`Alert sent after ${d.alert_after_failures || 2} consecutive failures`}
                                  >
                                    <Badge
                                      variant='outline'
                                      colorScheme='orange'
                                    >
                                      {d.alert_after_failures || 2}x
                                    </Badge>
                                  </Tooltip>
                                </Td>
                                <Td textAlign='right'>
                                  <HStack spacing={1} justify='flex-end'>
                                    <Tooltip label='Run health check now'>
                                      <IconButton
                                        size='xs'
                                        icon={<FiRefreshCw />}
                                        aria-label='Check now'
                                        onClick={event =>
                                          handleCheckDomain(d.id, event)
                                        }
                                        isLoading={checkingDomain === d.id}
                                      />
                                    </Tooltip>
                                    <Tooltip label='Delete endpoint monitor'>
                                      <IconButton
                                        size='xs'
                                        icon={<FiTrash2 />}
                                        aria-label='Delete'
                                        colorScheme='red'
                                        variant='ghost'
                                        onClick={() => handleDeleteDomain(d.id)}
                                      />
                                    </Tooltip>
                                  </HStack>
                                </Td>
                              </Tr>
                            ))}
                          </Tbody>
                        </Table>
                      </Box>
                    </>
                  )}
                </>
              )}

              <Divider />
              <Box>
                <HStack justify='space-between' align='start' mb={2}>
                  <Box>
                    <Text fontWeight='semibold' fontSize='sm'>
                      Domain checker
                    </Text>
                    <Text fontSize='xs' color={helpTextColor}>
                      Discovery is best-effort and uses subfinder&apos;s default
                      passive discovery behavior. Results come from public
                      passive sources; TokenTimer does not scan private DNS or
                      internal network records. Then import selected hosts as
                      SSL tokens and endpoint monitors.
                    </Text>
                  </Box>
                  <Badge colorScheme='purple'>Subdomain discovery</Badge>
                </HStack>
                <HStack spacing={3} align='flex-end' flexWrap='wrap'>
                  <FormControl flex={2} minW='220px'>
                    <FormLabel fontSize='sm'>Root domain</FormLabel>
                    <Input
                      size='sm'
                      value={domainCheckerInput}
                      onChange={e => setDomainCheckerInput(e.target.value)}
                      placeholder='example.com'
                    />
                  </FormControl>
                  <HStack align='center' spacing={1} pb={1}>
                    <Checkbox
                      size='sm'
                      colorScheme='blue'
                      isChecked={domainCheckerSubfinderAll}
                      onChange={e =>
                        setDomainCheckerSubfinderAll(e.target.checked)
                      }
                    >
                      Use all sources
                    </Checkbox>
                    <Tooltip
                      hasArrow
                      fontSize='xs'
                      maxW='280px'
                      label='subfinder -all uses every passive source and is slower than the default. Passive indexes can list stale or abandoned subdomains; SSL import may then touch hosts that no longer match your live certificates.'
                    >
                      <IconButton
                        aria-label='About subfinder all sources'
                        icon={<FiAlertTriangle />}
                        size='xs'
                        variant='ghost'
                        colorScheme='orange'
                      />
                    </Tooltip>
                  </HStack>
                  <Button
                    size='sm'
                    colorScheme='purple'
                    isLoading={domainCheckerLoading}
                    loadingText='Discovering...'
                    onClick={handleDomainCheckerLookup}
                    isDisabled={!domainCheckerInput.trim()}
                  >
                    Discover subdomains
                  </Button>
                </HStack>
                <Alert status='info' borderRadius='md' mt={3} py={2}>
                  <AlertIcon />
                  <AlertDescription fontSize='xs'>
                    Discovery can take up to about 5 minutes on large domains.
                    Leave this tab open while a scan runs.
                  </AlertDescription>
                </Alert>
                {domainCheckerPartial && (
                  <Alert status='warning' borderRadius='md' mt={3}>
                    <AlertIcon />
                    <AlertDescription fontSize='sm'>
                      Some discovery sources were unavailable. Showing partial
                      results
                      {domainCheckerToolErrors.length
                        ? ` (${domainCheckerToolErrors
                            .map(error => error?.tool || error?.message)
                            .filter(Boolean)
                            .join(', ')})`
                        : ''}
                      .
                    </AlertDescription>
                  </Alert>
                )}
                {domainCheckerTruncated && (
                  <Alert status='info' borderRadius='md' mt={3} py={2}>
                    <AlertIcon />
                    <AlertDescription fontSize='xs'>
                      This list is capped at {domainCheckerCapCount} hostnames
                      per discovery run. Names beyond that cap are not stored or
                      shown, so import is limited to this table. The server
                      limit is configurable (DOMAIN_CHECKER_MAX_RESULTS).
                    </AlertDescription>
                  </Alert>
                )}
                {domainCheckerResults.length > 0 && (
                  <Box
                    mt={3}
                    border='1px solid'
                    borderColor={domainBorderColor}
                    borderRadius='md'
                    overflow='auto'
                  >
                    <Table size='sm'>
                      <Thead>
                        <Tr>
                          <Th>
                            <Checkbox
                              aria-label='Select all discovered hosts (all pages)'
                              isChecked={
                                domainCheckerSelectAllVisibleState.checked
                              }
                              isIndeterminate={
                                domainCheckerSelectAllVisibleState.indeterminate
                              }
                              onChange={toggleDomainCheckerSelectAllVisible}
                            />
                          </Th>
                          <Th>Hostname</Th>
                          <Th>Domains</Th>
                        </Tr>
                      </Thead>
                      <Tbody>
                        {domainCheckerPageItems.map(cert => {
                          const domains = Array.isArray(cert.domains)
                            ? cert.domains
                            : [];
                          return (
                            <Tr key={cert.id}>
                              <Td>
                                <Checkbox
                                  isChecked={domainCheckerSelectedSet.has(
                                    cert.id
                                  )}
                                  onChange={() =>
                                    toggleDomainCheckerResult(cert.id)
                                  }
                                />
                              </Td>
                              <Td>
                                <Text fontSize='sm' fontWeight='medium'>
                                  {cert.name}
                                </Text>
                              </Td>
                              <Td fontSize='xs'>
                                {domains.slice(0, 6).join(', ')}
                                {domains.length > 6
                                  ? ` +${domains.length - 6} more`
                                  : ''}
                              </Td>
                            </Tr>
                          );
                        })}
                      </Tbody>
                    </Table>
                  </Box>
                )}
                {domainCheckerResults.length > 0 && (
                  <HStack mt={3} spacing={2} align='center' flexWrap='wrap'>
                    <Button
                      size='xs'
                      variant='outline'
                      isDisabled={domainCheckerPage === 0}
                      onClick={() => setDomainCheckerPage(p => p - 1)}
                    >
                      ← Prev
                    </Button>
                    <Text fontSize='xs' color={helpTextColor}>
                      {domainCheckerPage * DOMAIN_CHECKER_PAGE_SIZE + 1}–
                      {Math.min(
                        (domainCheckerPage + 1) * DOMAIN_CHECKER_PAGE_SIZE,
                        domainCheckerVisibleResults.length
                      )}{' '}
                      of {domainCheckerVisibleResults.length}
                      {domainCheckerResults.length !==
                      domainCheckerVisibleResults.length
                        ? ` (${domainCheckerResults.length} total)`
                        : ''}
                    </Text>
                    <Button
                      size='xs'
                      variant='outline'
                      isDisabled={
                        (domainCheckerPage + 1) * DOMAIN_CHECKER_PAGE_SIZE >=
                        domainCheckerVisibleResults.length
                      }
                      onClick={() => setDomainCheckerPage(p => p + 1)}
                    >
                      Next →
                    </Button>
                  </HStack>
                )}
                {domainCheckerResults.length > 0 && (
                  <Stack mt={3} spacing={3}>
                    <Alert status='info' borderRadius='md' py={2}>
                      <AlertIcon />
                      <AlertDescription fontSize='xs'>
                        Import runs in batches (up to about 5 minutes per batch
                        on slow hosts). After each run, hosts that finished
                        importing are removed from your selection so you can
                        click Import again for the rest without re-scanning.
                      </AlertDescription>
                    </Alert>
                    <FormControl maxW='480px'>
                      <FormLabel fontSize='sm'>
                        Section for imported SSL tokens
                      </FormLabel>
                      <Input
                        size='sm'
                        value={domainCheckerImportSection}
                        onChange={e =>
                          setDomainCheckerImportSection(e.target.value)
                        }
                        placeholder='Comma-separated labels (optional)'
                      />
                    </FormControl>
                    <FormControl
                      display='flex'
                      alignItems='center'
                      minW='200px'
                      maxW='360px'
                    >
                      <FormLabel mb={0} fontSize='sm'>
                        Also create endpoint monitors
                      </FormLabel>
                      <Switch
                        size='sm'
                        isChecked={domainCheckerCreateMonitors}
                        onChange={e =>
                          setDomainCheckerCreateMonitors(e.target.checked)
                        }
                      />
                    </FormControl>
                    {domainCheckerCreateMonitors && (
                      <HStack spacing={3} align='flex-end' flexWrap='wrap'>
                        <FormControl minW='140px' maxW='220px'>
                          <FormLabel fontSize='sm'>Interval</FormLabel>
                          <Select
                            size='sm'
                            value={domainCheckerMonitorInterval}
                            onChange={e =>
                              setDomainCheckerMonitorInterval(e.target.value)
                            }
                          >
                            <option value='1min'>Every 1 min</option>
                            <option value='5min'>Every 5 min</option>
                            <option value='30min'>Every 30 min</option>
                            <option value='hourly'>Hourly</option>
                            <option value='daily'>Daily</option>
                          </Select>
                        </FormControl>
                        <FormControl
                          display='flex'
                          alignItems='center'
                          minW='120px'
                          pb={1}
                        >
                          <FormLabel mb={0} fontSize='sm'>
                            Health Check
                          </FormLabel>
                          <Switch
                            size='sm'
                            isChecked={domainCheckerMonitorHealthCheck}
                            onChange={e =>
                              setDomainCheckerMonitorHealthCheck(
                                e.target.checked
                              )
                            }
                          />
                        </FormControl>
                        {domainCheckerMonitorHealthCheck && (
                          <FormControl minW='130px' maxW='220px'>
                            <FormLabel fontSize='sm'>
                              Alert after failures
                            </FormLabel>
                            <NumberInput
                              size='sm'
                              min={1}
                              max={10}
                              value={domainCheckerMonitorAlertAfter}
                              onChange={(_, valueAsNumber) =>
                                setDomainCheckerMonitorAlertAfter(
                                  Number.isFinite(valueAsNumber)
                                    ? valueAsNumber
                                    : 2
                                )
                              }
                            >
                              <NumberInputField />
                            </NumberInput>
                          </FormControl>
                        )}
                        <FormControl minW='220px' maxW='280px'>
                          <FormLabel fontSize='sm'>Contact group</FormLabel>
                          <Select
                            size='sm'
                            value={domainCheckerMonitorContactGroupId}
                            onChange={e =>
                              setDomainCheckerMonitorContactGroupId(
                                e.target.value
                              )
                            }
                          >
                            <option value=''>Default workspace group</option>
                            {contactGroups.map(g => (
                              <option key={g.id} value={g.id}>
                                {g.name}
                              </option>
                            ))}
                          </Select>
                        </FormControl>
                      </HStack>
                    )}
                    <HStack justify='flex-end' align='center' flexWrap='wrap'>
                      <Button
                        size='sm'
                        colorScheme='purple'
                        isLoading={domainCheckerImporting}
                        isDisabled={
                          domainCheckerSelectedSet.size === 0 ||
                          domainCheckerImporting
                        }
                        onClick={handleDomainCheckerImport}
                      >
                        Import selected ({domainCheckerSelectedSet.size})
                      </Button>
                    </HStack>
                  </Stack>
                )}
              </Box>

              {/* Add new endpoint form */}
              <Divider />
              <Text fontWeight='semibold' fontSize='sm'>
                Add new endpoint
              </Text>
              <HStack spacing={3} align='flex-end' flexWrap='wrap'>
                <FormControl flex={2} minW='200px'>
                  <FormLabel fontSize='sm'>URL</FormLabel>
                  <Input
                    size='sm'
                    value={domainUrl}
                    onChange={e => setDomainUrl(e.target.value)}
                    placeholder='https://example.com'
                  />
                </FormControl>
                <FormControl flex={1} minW='160px' maxW='260px'>
                  <FormLabel fontSize='sm'>SSL token section</FormLabel>
                  <Input
                    size='sm'
                    value={domainEndpointTokenSection}
                    onChange={e =>
                      setDomainEndpointTokenSection(e.target.value)
                    }
                    placeholder='Optional, comma-separated'
                  />
                </FormControl>
                <FormControl flex={1} minW='120px'>
                  <FormLabel fontSize='sm'>Interval</FormLabel>
                  <Select
                    size='sm'
                    value={domainInterval}
                    onChange={e => setDomainInterval(e.target.value)}
                  >
                    <option value='1min'>Every 1 min</option>
                    <option value='5min'>Every 5 min</option>
                    <option value='30min'>Every 30 min</option>
                    <option value='hourly'>Hourly</option>
                    <option value='daily'>Daily</option>
                  </Select>
                </FormControl>
                <FormControl
                  display='flex'
                  alignItems='center'
                  minW='120px'
                  pb={1}
                >
                  <FormLabel mb={0} fontSize='sm'>
                    Health Check
                  </FormLabel>
                  <Switch
                    size='sm'
                    isChecked={domainHealthCheck}
                    onChange={e => setDomainHealthCheck(e.target.checked)}
                  />
                </FormControl>
                {domainHealthCheck && (
                  <FormControl minW='130px' flex={1}>
                    <FormLabel fontSize='sm'>Alert after failures</FormLabel>
                    <Select
                      size='sm'
                      value={domainAlertAfter}
                      onChange={e =>
                        setDomainAlertAfter(Number(e.target.value))
                      }
                    >
                      <option value={1}>1 failure</option>
                      <option value={2}>2 failures</option>
                      <option value={3}>3 failures</option>
                      <option value={5}>5 failures</option>
                      <option value={10}>10 failures</option>
                    </Select>
                  </FormControl>
                )}
                {Array.isArray(contactGroups) && contactGroups.length > 0 && (
                  <FormControl minW='150px' flex={1}>
                    <FormLabel fontSize='sm'>Contact group</FormLabel>
                    <Select
                      size='sm'
                      value={domainContactGroupId}
                      onChange={e => setDomainContactGroupId(e.target.value)}
                    >
                      <option value=''>Workspace default</option>
                      {contactGroups.map(g => (
                        <option key={g.id} value={g.id}>
                          {g.name}
                          {String(g.id) === String(defaultContactGroupId)
                            ? ' (default)'
                            : ''}
                        </option>
                      ))}
                    </Select>
                  </FormControl>
                )}
                <Button
                  size='sm'
                  colorScheme='blue'
                  leftIcon={<FiPlus />}
                  isLoading={addingDomain}
                  onClick={handleAddDomain}
                  isDisabled={!domainUrl.trim()}
                >
                  Add
                </Button>
              </HStack>
            </VStack>
          </ModalBody>
          <ModalFooter>
            <Button onClick={handleDomainModalClose}>Close</Button>
          </ModalFooter>
        </ModalContent>
      </Modal>
    </Box>
  );
}
function ImportTokensButton() {
  const { isOpen, onOpen, onClose } = useDisclosure();
  const [_created, setCreated] = useState([]);
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
        colorScheme='purple'
        variant='outline'
        size='sm'
        minW='fit-content'
        maxW={{ base: '100%', sm: 'none' }}
        whiteSpace='nowrap'
      >
        Import tokens
      </Button>
      <ImportTokensModal
        isOpen={isOpen}
        onClose={onClose}
        onImported={onImported}
      />
    </>
  );
}

export default App;
