import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Box,
  Flex,
  Button,
  Text,
  IconButton,
  useColorModeValue,
  Menu,
  MenuButton,
  MenuList,
  MenuItem,
  Avatar,
  Image,
  HStack,
  VStack,
  useDisclosure,
  Drawer,
  DrawerBody,
  DrawerHeader,
  DrawerOverlay,
  DrawerContent,
  Portal,
} from '@chakra-ui/react';
import { FiMenu, FiUser, FiSettings, FiLogOut, FiBell } from 'react-icons/fi';
import apiClient, { API_ENDPOINTS, workspaceAPI } from '../utils/apiClient';
import { useWorkspace } from '../utils/WorkspaceContext.jsx';
import { AccessibleButton } from './Accessibility';
import {
  useTextColors,
  useBackgroundColors,
  useBorderColors,
} from '../hooks/useColors.js';
// Use shared ThemeToggle component
import ThemeToggle from './ThemeToggle.jsx';

/**
 * User menu with account options
 */
const UserMenu = ({ user, onLogout, onAccountClick, isViewerOnly }) => {
  const [isOpen, setIsOpen] = useState(false);
  const [isTourActive, setIsTourActive] = useState(false);
  const navigate = useNavigate();
  const primaryHoverBg = useColorModeValue('primary.50', 'primary.900');
  const menuListBg = useColorModeValue('rgba(255, 255, 255, 0.98)', 'gray.800');
  const menuListBgToken = useColorModeValue(
    'rgba(255, 255, 255, 0.98)',
    '#1a202c'
  ); // White with high opacity for light mode
  const grayTextColor = useColorModeValue('gray.600', 'gray.400');
  const menuBorderColor = useColorModeValue('gray.400', 'gray.600');
  const menuItemHoverBg = useColorModeValue('blue.50', 'blue.900');
  const signOutColor = useColorModeValue('red.600', 'red.400');
  const signOutHoverBg = useColorModeValue('red.50', 'red.900');

  // Listen for tour events to keep menu open during tour
  useEffect(() => {
    const handleTourStateChange = event => {
      const { isActive, keepMenuOpen } = event.detail || {};
      setIsTourActive(isActive && keepMenuOpen);
      if (isActive && keepMenuOpen) {
        setIsOpen(true);
      }
    };

    window.addEventListener('tt:tour-menu-state', handleTourStateChange);
    return () => {
      window.removeEventListener('tt:tour-menu-state', handleTourStateChange);
    };
  }, []);

  // Prevent menu from closing during tour
  const handleMenuClose = () => {
    if (isTourActive) {
      // Don't close menu during tour
      return;
    }
    setIsOpen(false);
  };

  return (
    <Menu
      isOpen={isOpen}
      onOpen={() => setIsOpen(true)}
      onClose={handleMenuClose}
      closeOnBlur={!isTourActive}
      closeOnSelect={!isTourActive}
    >
      <MenuButton
        data-tour='user-menu'
        as={Button}
        variant='ghost'
        size='md'
        px='3'
        py='2'
        bg='transparent'
        _hover={{
          bg: primaryHoverBg,
        }}
        _focus={{ bg: 'transparent' }}
        _active={{ bg: 'transparent' }}
        aria-label='User menu'
      >
        <HStack spacing='2'>
          <Avatar
            size='sm'
            name={user?.displayName || user?.name || user?.email}
            src={user?.avatar}
            bg='primary.500'
            color='white'
          />
          <VStack
            spacing='0'
            align='start'
            display={{ base: 'none', md: 'flex' }}
          >
            <Text fontSize='sm' fontWeight='medium'>
              {user?.displayName || user?.name || 'User'}
            </Text>
            <Text fontSize='xs' color={grayTextColor}>
              {user?.email}
            </Text>
          </VStack>
        </HStack>
      </MenuButton>

      <Portal>
        <MenuList
          bg={menuListBg}
          border='1px solid'
          borderColor={menuBorderColor}
          borderWidth='1px'
          boxShadow='xl'
          minW='200px'
          py={2}
          zIndex={10600}
          className='user-menu-list'
          _light={{
            bg: 'rgba(255, 255, 255, 0.98)',
            backgroundColor: 'rgba(255, 255, 255, 0.98)',
          }}
          _dark={{
            bg: '#1a202c',
            backgroundColor: '#1a202c',
            borderColor: 'gray.600',
          }}
          sx={{
            bg: menuListBgToken,
            backgroundColor: menuListBgToken,
          }}
        >
          <MenuItem
            icon={<FiUser />}
            onClick={onAccountClick}
            _hover={{
              bg: menuItemHoverBg,
            }}
          >
            Account Settings
          </MenuItem>

          {!isViewerOnly && (
            <MenuItem
              data-tour='preferences-nav'
              icon={<FiSettings />}
              onClick={() => {
                if (window.location.pathname !== '/preferences') {
                  navigate('/preferences');
                }
              }}
              _hover={{
                bg: menuItemHoverBg,
              }}
            >
              Preferences
            </MenuItem>
          )}

          <MenuItem
            icon={<FiLogOut />}
            onClick={onLogout}
            color={signOutColor}
            _hover={{
              bg: signOutHoverBg,
            }}
          >
            Sign Out
          </MenuItem>
        </MenuList>
      </Portal>
    </Menu>
  );
};

/**
 * Mobile navigation drawer
 */
const MobileNav = ({
  isOpen,
  onClose,
  user,
  onLogout,
  onAccountClick,
  onNavigateToDashboard,
  onNavigateToLanding,
  canSeeAudit,
  canSeeWorkspaces,
  isAdminAny,
  isViewerOnly,
}) => {
  const navigate = useNavigate();
  const bgColor = useColorModeValue('rgba(255, 255, 255, 0.98)', 'gray.800');
  const borderColor = useColorModeValue('gray.400', 'gray.600');
  const primaryHoverBg = useColorModeValue('primary.50', 'primary.900');
  const imageFilter = useColorModeValue('none', 'invert(1)');
  const grayTextColor = useColorModeValue('gray.600', 'gray.400');
  const dividerBorderColor = useColorModeValue('gray.200', 'gray.600');
  const errorHoverBg = useColorModeValue('error.50', 'error.900');

  return (
    <Drawer isOpen={isOpen} placement='left' onClose={onClose} size='sm'>
      <DrawerOverlay data-tour='mobile-drawer-overlay' />
      <DrawerContent
        data-tour='mobile-drawer'
        bg={bgColor}
        borderRightColor={borderColor}
        maxW='320px'
      >
        <DrawerHeader
          borderBottomWidth='1px'
          borderColor={borderColor}
          position='relative'
        >
          <Flex align='center' justify='space-between'>
            <AccessibleButton
              onClick={onNavigateToLanding}
              variant='ghost'
              size='sm'
              px={0}
              py={0}
              h='40px'
              minW='auto'
              bg='transparent'
              _hover={{
                bg: primaryHoverBg,
              }}
              _focus={{
                boxShadow: 'none',
                bg: 'transparent',
              }}
              _active={{ bg: 'transparent' }}
              aria-label='Go to homepage'
            >
              <Box
                as={Image}
                src='/Branding/app-icon.svg'
                alt='TokenTimer'
                h='inherit'
                w='auto'
                objectFit='contain'
                filter={imageFilter}
                display='block'
              />
            </AccessibleButton>
            <ThemeToggle />
          </Flex>
        </DrawerHeader>

        <DrawerBody p='0'>
          <VStack spacing='0' align='stretch'>
            {/* User Info */}
            <Box p='4' borderBottomWidth='1px' borderColor={borderColor}>
              <HStack spacing='3'>
                <Avatar
                  size='md'
                  name={user?.displayName || user?.name || user?.email}
                  src={user?.avatar}
                  bg='primary.500'
                  color='white'
                />
                <VStack spacing='0' align='start' flex='1'>
                  <Text fontSize='md' fontWeight='medium'>
                    {user?.displayName || user?.name || 'User'}
                  </Text>
                  <Text fontSize='sm' color={grayTextColor}>
                    {user?.email}
                  </Text>
                </VStack>
              </HStack>
            </Box>

            {/* Navigation Links */}
            <VStack spacing='1' align='stretch' p='4'>
              <Button
                data-tour='mobile-tokens-nav'
                variant='ghost'
                justifyContent='start'
                onClick={() => {
                  onNavigateToDashboard();
                  onClose();
                }}
                bg='transparent'
                _hover={{
                  bg: primaryHoverBg,
                }}
                _focus={{ bg: 'transparent' }}
                _active={{ bg: 'transparent' }}
                whiteSpace='normal'
                textAlign='left'
                h='auto'
                py={2}
                px={3}
              >
                Dashboard
              </Button>

              {/* Workspaces entry in mobile nav - gated */}
              {canSeeWorkspaces && (
                <Button
                  variant='ghost'
                  justifyContent='start'
                  onClick={() => {
                    navigate('/workspaces');
                    onClose();
                  }}
                  bg='transparent'
                  _hover={{
                    bg: primaryHoverBg,
                  }}
                  _focus={{ bg: 'transparent' }}
                  _active={{ bg: 'transparent' }}
                  whiteSpace='normal'
                  textAlign='left'
                  h='auto'
                  py={2}
                  px={3}
                >
                  Workspaces
                </Button>
              )}

              <Button
                data-tour='mobile-docs-nav'
                variant='ghost'
                justifyContent='start'
                onClick={() => {
                  navigate('/docs');
                  onClose();
                }}
                bg='transparent'
                _hover={{
                  bg: primaryHoverBg,
                }}
                _focus={{ bg: 'transparent' }}
                _active={{ bg: 'transparent' }}
                whiteSpace='normal'
                textAlign='left'
                h='auto'
                py={2}
                px={3}
              >
                Docs
              </Button>

              {canSeeAudit && (
                <Button
                  variant='ghost'
                  justifyContent='start'
                  onClick={() => {
                    navigate('/audit');
                    onClose();
                  }}
                  bg='transparent'
                  _hover={{
                    bg: primaryHoverBg,
                  }}
                  _focus={{ bg: 'transparent' }}
                  _active={{ bg: 'transparent' }}
                  whiteSpace='normal'
                  textAlign='left'
                  h='auto'
                  py={2}
                  px={3}
                >
                  Audit
                </Button>
              )}
              {isAdminAny && (
                <Button
                  variant='ghost'
                  justifyContent='start'
                  onClick={() => {
                    navigate('/system-settings');
                    onClose();
                  }}
                  bg='transparent'
                  _hover={{
                    bg: primaryHoverBg,
                  }}
                  _focus={{ bg: 'transparent' }}
                  _active={{ bg: 'transparent' }}
                  whiteSpace='normal'
                  textAlign='left'
                  h='auto'
                  py={2}
                  px={3}
                >
                  System Settings
                </Button>
              )}
            </VStack>

            <Box
              borderTop='1px solid'
              borderColor={dividerBorderColor}
              my={2}
              aria-expanded={isOpen ? 'true' : 'false'}
            />

            {/* Account Actions */}
            <VStack spacing='1' align='stretch' p='4'>
              <Button
                variant='ghost'
                justifyContent='start'
                onClick={onAccountClick}
                bg='transparent'
                _hover={{
                  bg: primaryHoverBg,
                }}
                _focus={{ bg: 'transparent' }}
                _active={{ bg: 'transparent' }}
                whiteSpace='normal'
                textAlign='left'
                h='auto'
                py={2}
                px={3}
              >
                Account Settings
              </Button>

              {!isViewerOnly && (
                <Button
                  data-tour='preferences-nav'
                  variant='ghost'
                  justifyContent='start'
                  onClick={() => {
                    if (window.location.pathname !== '/preferences') {
                      navigate('/preferences');
                    }
                    onClose();
                  }}
                  bg='transparent'
                  _hover={{
                    bg: primaryHoverBg,
                  }}
                  _focus={{ bg: 'transparent' }}
                  _active={{ bg: 'transparent' }}
                  whiteSpace='normal'
                  textAlign='left'
                  h='auto'
                  py={2}
                  px={3}
                >
                  Preferences
                </Button>
              )}

              <Button
                variant='ghost'
                justifyContent='start'
                onClick={onLogout}
                color='error.500'
                bg='transparent'
                _hover={{
                  bg: errorHoverBg,
                }}
                _focus={{ bg: 'transparent' }}
                _active={{ bg: 'transparent' }}
                whiteSpace='normal'
                textAlign='left'
                h='auto'
                py={2}
                px={3}
              >
                Sign Out
              </Button>
            </VStack>
          </VStack>
        </DrawerBody>
      </DrawerContent>
    </Drawer>
  );
};

/**
 * Main navigation component
 */
const Navigation = ({
  user,
  onLogout,
  onAccountClick,
  onNavigateToDashboard,
  onNavigateToLanding,
}) => {
  const { isOpen, onOpen, onClose } = useDisclosure();

  useEffect(() => {
    if (typeof window === 'undefined') return undefined;

    const handleCloseMobileNav = () => {
      // Always call onClose - it's safe to call even if drawer is already closed
      onClose();
    };

    window.addEventListener('tt:close-mobile-nav', handleCloseMobileNav);
    return () => {
      window.removeEventListener('tt:close-mobile-nav', handleCloseMobileNav);
    };
  }, [onClose]); // Remove isOpen from dependencies to avoid recreating listener
  const navigate = useNavigate();

  // Use semantic color tokens
  const { primary: textColor } = useTextColors();
  const { surface: bgColor } = useBackgroundColors();
  const { default: borderColor } = useBorderColors();

  // Move useColorModeValue calls to top level to avoid React Hook rules violations
  const primaryHoverBg = useColorModeValue('primary.50', 'primary.900');
  const menuListBg = useColorModeValue('rgba(255, 255, 255, 0.98)', 'gray.800');
  const borderPrimary = useColorModeValue('border.primary', 'border.primary');
  const gray600 = useColorModeValue('gray.600', 'gray.300');
  const gray400 = useColorModeValue('gray.600', 'gray.400');
  const imageFilter = useColorModeValue('none', 'invert(1)');

  const [notifications, setNotifications] = useState([]);
  const [workspaces, setWorkspaces] = useState([]);
  const [currentWorkspace, setCurrentWorkspace] = useState(null);
  // Sections were previously separate entities. They are now derived from token facets.
  const [_sections, setSections] = useState([]);
  const [_currentPlan, setCurrentPlan] = useState('oss');
  const [_accountPlan, setAccountPlan] = useState('oss');
  const [isAdminAny, setIsAdminAny] = useState(false);
  const [hasManagerOrAdminAny, setHasManagerOrAdminAny] = useState(false);
  const [isViewerOnly, setIsViewerOnly] = useState(false);
  const [canSeeAudit, setCanSeeAudit] = useState(false);
  const [canSeeWorkspaces, setCanSeeWorkspaces] = useState(false);
  const { workspaceId, selectWorkspace } = useWorkspace();

  // Load lightweight notifications (alerts disabled state) from current workspace settings
  useEffect(() => {
    let cancelled = false;
    async function load() {
      if (!user || !currentWorkspace?.id) {
        if (!cancelled) setNotifications([]);
        return;
      }
      try {
        const res = await workspaceAPI.getAlertSettings(currentWorkspace.id);
        const data = res?.data || res || {};
        const emailEnabled = data.email_alerts_enabled === true;
        const webhooks = data.webhook_urls;
        const hasWebhooks = Array.isArray(webhooks) && webhooks.length > 0;
        const smtpConfigured = data.smtp_configured !== false;
        const allDisabled = !emailEnabled && !hasWebhooks;
        const contactGroups = Array.isArray(data.contact_groups)
          ? data.contact_groups
          : [];
        const hasAnyContact = contactGroups.some(g => {
          const emailIds = Array.isArray(g.email_contact_ids)
            ? g.email_contact_ids
            : [];
          const waIds = Array.isArray(g.whatsapp_contact_ids)
            ? g.whatsapp_contact_ids
            : [];
          return emailIds.length > 0 || waIds.length > 0;
        });
        if (cancelled) return;
        const list = [];
        if (!smtpConfigured) {
          list.push({
            id: 'smtp-not-configured',
            kind: 'warning',
            text: 'SMTP is not configured. Email notifications will not be sent.',
            href: '/system-settings',
          });
        }
        if (allDisabled) {
          list.push({
            id: 'alerts-disabled',
            kind: 'warning',
            text: 'Alerts are disabled until a channel is defined.',
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
        setNotifications(list);
      } catch (_) {
        if (!cancelled) setNotifications([]);
      }
    }
    load();
    return () => {
      cancelled = true;
    };
  }, [user, currentWorkspace?.id]);

  // Load workspaces, account plan, and sections for switchers
  useEffect(() => {
    let cancelled = false;
    async function loadWorkspaces() {
      if (!user) return;
      try {
        const [ws, _planRes] = await Promise.all([
          workspaceAPI.list(50, 0),
          apiClient
            .get(API_ENDPOINTS.ACCOUNT_PLAN)
            .catch(() => ({ data: { plan: 'oss' } })),
        ]);
        if (cancelled) return;
        const items = ws?.items || [];
        setWorkspaces(items);
        const roles = items.map(w => String(w.role || '').toLowerCase());
        const adminAny = roles.includes('admin');
        const managerAny = adminAny || roles.includes('workspace_manager');
        const viewerOnly =
          items.length > 0 && !adminAny && !roles.includes('workspace_manager');
        setIsAdminAny(adminAny);
        setHasManagerOrAdminAny(managerAny);
        setIsViewerOnly(viewerOnly);
        const showAudit = items.length ? managerAny : true;
        const showWorkspaces = items.length ? managerAny : true;
        setCanSeeAudit(showAudit);
        setCanSeeWorkspaces(showWorkspaces);
        setAccountPlan('oss');
        // Prefer workspace from URL Context (synced to URL), then last-used in localStorage, else first
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
        setCurrentWorkspace(selected);
        if (selected) {
          setCurrentPlan(selected.plan || 'oss');
          // No explicit sections endpoint anymore
          if (!cancelled) setSections([]);
          // Normalize URL via context only on dashboard to avoid cross-page redirects
          // Skip if workspace is already correctly set to prevent unnecessary reloads
          try {
            const pathNow = window.location.pathname;
            const searchNow = new URLSearchParams(window.location.search);
            const currentWorkspaceInUrl = searchNow.get('workspace');
            const onboardingActive = [
              'new_user',
              'first_login',
              'registered',
              'verification_success',
            ].some(k => searchNow.get(k) === 'true');
            if (
              pathNow === '/dashboard' &&
              !onboardingActive &&
              currentWorkspaceInUrl !== selected.id
            ) {
              selectWorkspace(selected.id, { replace: true });
            }
          } catch (_) {}
          try {
            localStorage.setItem('tt_last_workspace_id', selected.id);
          } catch (_) {}
          // Also refresh plan/chrome via tt:workspaces-updated
          try {
            window.dispatchEvent(new CustomEvent('tt:workspaces-updated'));
          } catch (_) {}
        } else {
          setSections([]);
        }
      } catch (_) {
        if (!cancelled) {
          setWorkspaces([]);
          setSections([]);
        }
      }
    }
    loadWorkspaces();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user]);

  // Refresh workspaces/plan on custom event (e.g., after create/delete)
  useEffect(() => {
    if (!user) return;
    let cancelled = false;
    const handler = async e => {
      if (cancelled) return;
      try {
        const [ws, _planRes] = await Promise.all([
          workspaceAPI.list(50, 0),
          apiClient
            .get(API_ENDPOINTS.ACCOUNT_PLAN)
            .catch(() => ({ data: { plan: 'oss' } })),
        ]);
        if (cancelled) return;
        const items = ws?.items || [];
        setWorkspaces(items);
        const roles = items.map(w => String(w.role || '').toLowerCase());
        const adminAny2 = roles.includes('admin');
        const managerAny2 = adminAny2 || roles.includes('workspace_manager');
        const viewerOnly2 =
          items.length > 0 &&
          !adminAny2 &&
          !roles.includes('workspace_manager');
        setIsAdminAny(adminAny2);
        setHasManagerOrAdminAny(managerAny2);
        setIsViewerOnly(viewerOnly2);
        setCanSeeAudit(items.length ? managerAny2 : true);
        setCanSeeWorkspaces(items.length ? managerAny2 : true);
        setAccountPlan('oss');
        // If a workspace was just created, select it immediately
        const newId = e?.detail?.createdId;
        if (newId) {
          const found = items.find(w => w.id === newId);
          if (found) {
            setCurrentWorkspace(found);
            setCurrentPlan(found.plan || 'oss');
            try {
              const search = new URLSearchParams(window.location.search);
              search.set('workspace', found.id);
              // Do not force navigation away from Workspaces page
              const path = window.location.pathname || '/dashboard';
              if (path !== '/workspaces') {
                navigate(`${path}?${search.toString()}`);
              } else {
                // Replace URL without route change
                window.history.replaceState(
                  null,
                  '',
                  `${path}?${search.toString()}${window.location.hash || ''}`
                );
              }
              try {
                localStorage.setItem('tt_last_workspace_id', found.id);
              } catch (_) {}
            } catch (_) {}
          }
        } else {
          // If current workspace no longer exists after delete, pick first available and normalize URL
          const deletedId = e?.detail?.deletedId || null;
          if (
            (deletedId && currentWorkspace?.id === deletedId) ||
            (currentWorkspace && !items.find(w => w.id === currentWorkspace.id))
          ) {
            const fallback = items[0] || null;
            setCurrentWorkspace(fallback);
            setCurrentPlan(fallback?.plan || 'oss');
            try {
              const search = new URLSearchParams(window.location.search);
              if (fallback?.id) {
                search.set('workspace', fallback.id);
                try {
                  localStorage.setItem('tt_last_workspace_id', fallback.id);
                } catch (_) {}
              } else {
                search.delete('workspace');
                try {
                  localStorage.removeItem('tt_last_workspace_id');
                } catch (_) {}
              }
              const path = window.location.pathname || '/dashboard';
              navigate(
                `${path}?${search.toString()}${window.location.hash || ''}`
              );
            } catch (_) {}
          }
        }
      } catch (_) {
        if (!cancelled) {
          setWorkspaces([]);
        }
      }
    };
    window.addEventListener('tt:workspaces-updated', handler);
    return () => {
      cancelled = true;
      window.removeEventListener('tt:workspaces-updated', handler);
    };
  }, [user, currentWorkspace, navigate]);

  // Core: always use plan 'oss' (no upgrades/downgrades)
  useEffect(() => {
    setAccountPlan('oss');
  }, [user?.plan]);

  // Listen for plan/workspace updates and refresh
  useEffect(() => {
    if (!user) return;
    let cancelled = false;
    const handler = async () => {
      if (cancelled) return;
      try {
        const [ws, _planRes] = await Promise.all([
          // Refresh workspace list
          workspaceAPI.list(50, 0, { nocache: true }),
          apiClient
            .get(API_ENDPOINTS.ACCOUNT_PLAN, { params: { t: Date.now() } })
            .catch(() => ({ data: { plan: 'oss' } })),
        ]);
        if (cancelled) return;
        const items = ws?.items || [];
        setWorkspaces(items);
        setAccountPlan('oss');
        const roles = items.map(w => String(w.role || '').toLowerCase());
        const adminAny3 = roles.includes('admin');
        const managerAny3 = adminAny3 || roles.includes('workspace_manager');
        const viewerOnly3 =
          items.length > 0 &&
          !adminAny3 &&
          !roles.includes('workspace_manager');
        setIsAdminAny(adminAny3);
        setHasManagerOrAdminAny(managerAny3);
        setIsViewerOnly(viewerOnly3);
        setCanSeeAudit(items.length ? managerAny3 : true);
        setCanSeeWorkspaces(items.length ? managerAny3 : true);
        if (items?.length && currentWorkspace) {
          const found =
            items.find(w => w.id === currentWorkspace.id) || items[0];
          setCurrentWorkspace(found);
          setCurrentPlan(found?.plan || 'oss');
        }
      } catch (_) {}
    };
    window.addEventListener('tt:plan-updated', handler);
    return () => {
      cancelled = true;
      window.removeEventListener('tt:plan-updated', handler);
    };
  }, [user, currentWorkspace]);

  return (
    <>
      <Box
        as='nav'
        position='sticky'
        top='0'
        zIndex='1000'
        bg={bgColor}
        borderBottomWidth='1px'
        borderColor={borderColor}
        boxShadow='sm'
        h={{ base: '74px', md: '78px' }}
        display='flex'
        alignItems='center'
        // Ensure solid background so content does not show through when scrolling (iOS Safari too)
        style={{
          backdropFilter: 'none',
          WebkitBackdropFilter: 'none',
          backgroundColor: bgColor,
        }}
        _before={{
          content: '""',
          position: 'absolute',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          bg: bgColor,
          opacity: 1,
          pointerEvents: 'none',
        }}
      >
        <Flex
          maxW='1200px'
          w='100%'
          mx='auto'
          px={{ base: 3, md: 6 }}
          py={{ base: 1, md: 2 }}
          align='center'
          justify='space-between'
          position='relative'
          zIndex={1}
        >
          {/* Logo/Brand */}
          <Flex
            align='center'
            flex={{ base: '0 0 auto', md: '1' }}
            transform={{ base: 'none', md: 'translateX(-90px)' }}
          >
            <AccessibleButton
              onClick={onNavigateToLanding}
              variant='ghost'
              size='sm'
              fontWeight='bold'
              fontSize={{ base: 'lg', md: 'xl' }}
              color={textColor}
              display='inline-flex'
              alignItems='center'
              px={0}
              py={0}
              h={{ base: '40px', md: '48px' }}
              minW='auto'
              lineHeight='1'
              ml={{ base: 0, md: '-30px' }}
              bg='transparent'
              _hover={{
                bg: primaryHoverBg,
              }}
              _focus={{
                boxShadow: 'none',
                bg: 'transparent',
              }}
              _active={{ bg: 'transparent' }}
              aria-label='Go to homepage'
            >
              <Box
                as={Image}
                src='/Branding/app-icon.svg'
                alt='TokenTimer'
                h='inherit'
                w='auto'
                objectFit='contain'
                filter={imageFilter}
                display='block'
              />
            </AccessibleButton>
          </Flex>

          {/* Desktop Navigation */}
          <HStack spacing='4' display={{ base: 'none', md: 'flex' }}>
            {/* Workspace Switcher */}
            {user && (
              <Menu>
                <MenuButton
                  data-tour='workspace-selector'
                  as={Button}
                  variant='outline'
                  size='sm'
                  isDisabled={workspaces.length === 0}
                >
                  {currentWorkspace?.name || 'Select workspace'}
                </MenuButton>
                <MenuList
                  bg={menuListBg}
                  border='1px solid'
                  borderColor={borderColor}
                >
                  {workspaces.map(w => (
                    <MenuItem
                      key={w.id}
                      onClick={() => {
                        setCurrentWorkspace(w);
                        setCurrentPlan(w.plan || 'oss');
                        // Sections are not loaded from API anymore
                        setSections([]);
                        // Update URL on current page (no cross-page redirect)
                        try {
                          const search = new URLSearchParams(
                            window.location.search
                          );
                          search.set('workspace', w.id);
                          const path = window.location.pathname || '/dashboard';
                          navigate(
                            `${path}?${search.toString()}${window.location.hash || ''}`
                          );
                          try {
                            localStorage.setItem('tt_last_workspace_id', w.id);
                          } catch (_) {}
                        } catch (_) {}
                      }}
                    >
                      {w.name}
                    </MenuItem>
                  ))}
                </MenuList>
              </Menu>
            )}

            {/* Tokens always visible */}
            <AccessibleButton
              data-tour='tokens-nav'
              variant='ghost'
              size='md'
              onClick={onNavigateToDashboard}
              bg='transparent'
              _hover={{
                bg: primaryHoverBg,
              }}
              _focus={{ bg: 'transparent' }}
              _active={{ bg: 'transparent' }}
              aria-label='Manage tokens and secrets'
            >
              Tokens
            </AccessibleButton>

            {/* Usage: only for manager/admin */}
            {hasManagerOrAdminAny && (
              <AccessibleButton
                data-tour='usage-nav'
                variant='ghost'
                size='md'
                onClick={() => {
                  navigate('/usage');
                }}
                bg='transparent'
                _hover={{
                  bg: primaryHoverBg,
                }}
                _focus={{ bg: 'transparent' }}
                _active={{ bg: 'transparent' }}
                aria-label='Usage'
              >
                Usage
              </AccessibleButton>
            )}

            {/* Docs always visible */}
            <AccessibleButton
              data-tour='docs-nav'
              variant='ghost'
              size='md'
              onClick={() => {
                if (window.location.pathname !== '/docs') {
                  navigate('/docs');
                }
              }}
              bg='transparent'
              _hover={{
                bg: primaryHoverBg,
              }}
              _focus={{ bg: 'transparent' }}
              _active={{ bg: 'transparent' }}
              aria-label='Documentation'
            >
              Docs
            </AccessibleButton>

            {/* Audit: visible only if user has manager/admin role somewhere */}
            {canSeeAudit && (
              <AccessibleButton
                variant='ghost'
                size='md'
                onClick={() => {
                  if (window.location.pathname !== '/audit') {
                    navigate('/audit');
                  }
                }}
                bg='transparent'
                _hover={{
                  bg: primaryHoverBg,
                }}
                _focus={{ bg: 'transparent' }}
                _active={{ bg: 'transparent' }}
                aria-label='Audit'
              >
                Audit
              </AccessibleButton>
            )}
            {/* Workspaces: visible only if user has manager/admin role somewhere */}
            {user && canSeeWorkspaces && (
              <AccessibleButton
                variant='ghost'
                size='md'
                onClick={() => {
                  navigate('/workspaces');
                }}
                bg='transparent'
                _hover={{
                  bg: primaryHoverBg,
                }}
                _focus={{ bg: 'transparent' }}
                _active={{ bg: 'transparent' }}
                aria-label='Workspaces'
              >
                Workspaces
              </AccessibleButton>
            )}
            {/* System Settings: visible only for admins */}
            {user && isAdminAny && (
              <AccessibleButton
                variant='ghost'
                size='md'
                onClick={() => {
                  navigate('/system-settings');
                }}
                bg='transparent'
                _hover={{
                  bg: primaryHoverBg,
                }}
                _focus={{ bg: 'transparent' }}
                _active={{ bg: 'transparent' }}
                aria-label='System Settings'
              >
                System
              </AccessibleButton>
            )}
          </HStack>

          {/* Right side actions */}
          <HStack spacing='2' ml='auto'>
            {/* Notifications */}
            <Menu placement='bottom-end'>
              <Box position='relative'>
                {notifications.length > 0 && (
                  <Box
                    position='absolute'
                    top='0'
                    right='0'
                    width='8px'
                    height='8px'
                    bg='red.400'
                    borderRadius='full'
                    zIndex='2'
                  />
                )}
                <MenuButton
                  as={IconButton}
                  aria-label='Notifications'
                  icon={<FiBell />}
                  variant='ghost'
                  size='md'
                  colorScheme='primary'
                  bg='transparent'
                  _hover={{
                    bg: primaryHoverBg,
                  }}
                  _focus={{ bg: 'transparent' }}
                  _active={{ bg: 'transparent' }}
                />
              </Box>
              <MenuList
                bg={menuListBg}
                borderColor={borderPrimary}
                boxShadow='lg'
                minW='260px'
              >
                {notifications.length === 0 ? (
                  <Box px='3' py='2'>
                    <Text fontSize='sm' color={gray600}>
                      No notifications
                    </Text>
                  </Box>
                ) : (
                  <>
                    {notifications.map(n => (
                      <MenuItem
                        key={n.id}
                        onClick={() => {
                          try {
                            if (n && typeof n.onClick === 'function')
                              return n.onClick();
                            if (n && n.href) return navigate(n.href);
                          } catch (_) {}
                          return navigate('/preferences');
                        }}
                        _hover={{
                          bg: primaryHoverBg,
                        }}
                      >
                        <VStack align='start' spacing='0'>
                          <Text fontSize='sm' fontWeight='medium'>
                            ⚠️ {n.text}
                          </Text>
                          <Text fontSize='xs' color={gray400}>
                            {n.id === 'smtp-not-configured'
                              ? 'Go to System Settings to configure SMTP.'
                              : 'Go to Preferences to enable a notification channel.'}
                          </Text>
                        </VStack>
                      </MenuItem>
                    ))}
                  </>
                )}
              </MenuList>
            </Menu>

            <ThemeToggle />

            {/* User Menu (Desktop) */}
            <Box display={{ base: 'none', md: 'block' }}>
              <UserMenu
                user={user}
                onLogout={onLogout}
                onAccountClick={onAccountClick}
                isViewerOnly={isViewerOnly}
              />
            </Box>

            {/* Mobile Menu Button */}
            <IconButton
              data-tour='mobile-menu-button'
              aria-label='Open navigation menu'
              icon={<FiMenu />}
              variant='ghost'
              size='sm'
              display={{ base: 'flex', md: 'none' }}
              onClick={onOpen}
              colorScheme='primary'
              bg='transparent'
              _hover={{
                bg: primaryHoverBg,
              }}
              _focus={{ bg: 'transparent' }}
              _active={{ bg: 'transparent' }}
            />
          </HStack>
        </Flex>
      </Box>

      {/* Mobile Navigation Drawer */}
      <MobileNav
        isOpen={isOpen}
        onClose={onClose}
        user={user}
        onLogout={onLogout}
        onAccountClick={onAccountClick}
        onNavigateToDashboard={onNavigateToDashboard}
        onNavigateToLanding={onNavigateToLanding}
        canSeeAudit={canSeeAudit}
        canSeeWorkspaces={canSeeWorkspaces}
        isAdminAny={isAdminAny}
        isViewerOnly={isViewerOnly}
      />
    </>
  );
};

export default Navigation;
