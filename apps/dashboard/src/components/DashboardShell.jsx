import { useCallback, useEffect, useLayoutEffect, useState } from 'react';
import { Link as RouterLink, useNavigate } from 'react-router-dom';
import {
  Box,
  Button,
  Circle,
  Divider,
  Drawer,
  DrawerBody,
  DrawerContent,
  DrawerHeader,
  DrawerOverlay,
  Flex,
  HStack,
  IconButton,
  Image,
  Menu,
  MenuButton,
  MenuItem,
  MenuList,
  Portal,
  Text,
  Tooltip,
  VStack,
  Heading,
  useColorMode,
  useColorModeValue,
  useDisclosure,
} from '@chakra-ui/react';
import { FiBell, FiMenu } from 'react-icons/fi';
import {
  Activity as ActivityIcon,
  Bell,
  BookOpen,
  Building2,
  ChevronDown,
  Gauge,
  Layers,
  LogOut,
  Moon,
  Settings,
  ShieldCheck,
  Sun,
  User,
} from 'lucide-react';
import { useDashboardMenuStyles } from '../hooks/useDashboardMenuStyles.js';
import {
  DASHBOARD_PAGE_GUTTER_X,
  DASHBOARD_SHELL_HEADER_HEIGHT,
} from '../styles/dashboardLayout';
import { getFaviconPath } from '../utils/logoUtils.js';

const DASHBOARD_SIDEBAR_STORAGE_KEY = 'tt_dashboard_sidebar_width';
const DASHBOARD_SIDEBAR_WIDTH_CSS_VAR = '--tt-dashboard-sidebar-width';
const DASHBOARD_SIDEBAR_MIN_WIDTH = 56;
const DASHBOARD_SIDEBAR_MAX_WIDTH = 248;
const DASHBOARD_SIDEBAR_LABEL_WIDTH = 136;
const DASHBOARD_SIDEBAR_DEFAULT_WIDTH = DASHBOARD_SIDEBAR_MIN_WIDTH;

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

/** Product tour targets (legacy names kept for Joyride selectors). */
function dashboardNavTourAttr(itemKey) {
  if (itemKey === 'tokens') return 'tokens-nav';
  if (itemKey === 'control-center') return 'usage-nav';
  if (itemKey === 'workspaces') return 'workspaces-nav';
  if (itemKey === 'docs') return 'docs-nav';
  if (itemKey === 'alert-settings') return 'workspace-alert-settings-nav';
  return undefined;
}

function mobileNavTourAttr(itemKey) {
  if (itemKey === 'tokens') return 'mobile-tokens-nav';
  if (itemKey === 'docs') return 'mobile-docs-nav';
  if (itemKey === 'alert-settings') return 'mobile-alert-settings-nav';
  if (itemKey === 'control-center') return 'usage-nav';
  return dashboardNavTourAttr(itemKey);
}

function notificationActionHint(notification) {
  if (!notification?.href) {
    if (notification?.id === 'smtp-not-configured') {
      return 'Contact a system administrator to configure SMTP.';
    }
    return 'No action available';
  }
  if (notification.id === 'smtp-not-configured') {
    return 'Go to System Settings to configure SMTP.';
  }
  if (notification.id?.startsWith('auto-sync-failed-')) {
    return 'Opens Import tokens on the Manage auto-sync tab.';
  }
  if (notification.id === 'alerts-out-of-window') {
    return 'View the alert queue on the Control center page.';
  }
  if (
    notification.id === 'alerts-disabled' ||
    notification.id === 'no-contacts-defined'
  ) {
    return 'Go to Preferences to update alert settings.';
  }
  return 'Open related page';
}

function MobileDrawerSection({
  title,
  children,
  mutedTextColor,
  dividerColor,
  showDivider = true,
}) {
  return (
    <Box
      borderTop={showDivider ? '1px solid' : undefined}
      borderColor={dividerColor}
    >
      <Text
        px={4}
        pt={3}
        pb={1}
        fontSize='xs'
        fontWeight='semibold'
        letterSpacing='0.06em'
        textTransform='uppercase'
        color={mutedTextColor}
      >
        {title}
      </Text>
      <VStack align='stretch' spacing={1} px={2} pb={3}>
        {children}
      </VStack>
    </Box>
  );
}

function getDashboardLinkTarget() {
  if (typeof window === 'undefined') return '/dashboard';

  try {
    const path = String(window.location.pathname || '');
    const search = new URLSearchParams(window.location.search);
    search.delete('view');
    // Inventory reuses the `q` query param for asset search. Audit (and other
    // non-dashboard pages) also use `q` for their own search boxes. Only carry
    // inventory filters onto /dashboard when already on the inventory route;
    // otherwise keep workspace context and drop foreign search terms.
    if (!path.startsWith('/dashboard')) {
      const workspace = search.get('workspace');
      const next = new URLSearchParams();
      if (workspace) next.set('workspace', workspace);
      const qs = next.toString();
      return `/dashboard${qs ? `?${qs}` : ''}`;
    }
    const qs = search.toString();
    return `/dashboard${qs ? `?${qs}` : ''}`;
  } catch (_) {
    return '/dashboard';
  }
}

function isModifiedLinkClick(event) {
  return (
    event.button !== 0 ||
    event.metaKey ||
    event.altKey ||
    event.ctrlKey ||
    event.shiftKey
  );
}

export default function DashboardShell({
  children,
  dashboardColors,
  currentPath,
  sessionName,
  sessionEmail,
  sessionInitials,
  dashboardWorkspaces = [],
  dashboardWorkspace,
  workspaceLabel,
  onWorkspaceSelect,
  dashboardNotifications = [],
  onLogout,
  onAccountClick,
  isViewer = false,
  dashboardCanSeeManagerNav = false,
  isSystemAdmin = false,
  pageTitle = '',
}) {
  const navigate = useNavigate();
  const handleAccountClick = useCallback(() => {
    if (typeof onAccountClick === 'function') {
      onAccountClick();
      return;
    }
    navigate('/account');
  }, [navigate, onAccountClick]);
  const { colorMode, toggleColorMode } = useColorMode();
  const isDarkMode = colorMode === 'dark';

  const textColor = dashboardColors?.text ?? 'white';
  const pageBg = dashboardColors?.pageBg ?? 'transparent';
  const mutedTextColor = dashboardColors?.muted ?? 'rgba(148, 163, 184, 0.92)';
  const borderColor = dashboardColors?.border ?? 'rgba(148, 163, 184, 0.13)';
  const borderStrongColor = dashboardColors?.borderStrong ?? borderColor;

  const {
    menuBg,
    menuBorder,
    chromeHoverBg,
    chromeHoverColor,
    menuListProps,
    menuItemProps: userMenuItemStyles,
    inactiveMenuItemProps: inactiveMenuItemStyles,
  } = useDashboardMenuStyles();
  const appIconFilter = useColorModeValue('none', 'invert(1)');
  const navInactiveColor = useColorModeValue(
    'gray.600',
    'rgba(203, 213, 225, 0.84)'
  );
  const navActiveColor = useColorModeValue('blue.700', 'white');
  const navActiveBg = useColorModeValue('blue.50', 'rgba(37, 99, 235, 0.26)');
  const navHoverBg = useColorModeValue('gray.100', 'rgba(30, 41, 59, 0.78)');
  const navActiveBorder = useColorModeValue(
    'blue.200',
    'rgba(59, 130, 246, 0.35)'
  );
  const navActiveHoverBg = useColorModeValue(
    'blue.100',
    'rgba(37, 99, 235, 0.32)'
  );
  const sidebarToggleColor = useColorModeValue('gray.700', 'white');
  const sidebarToggleBorder = isDarkMode
    ? 'rgba(148, 163, 184, 0.12)'
    : borderColor;
  const sidebarToggleHoverBg = useColorModeValue(
    'blue.50',
    'rgba(37, 99, 235, 0.18)'
  );
  const dividerColor = isDarkMode ? 'rgba(148, 163, 184, 0.14)' : borderColor;
  const workspaceButtonBg = isDarkMode
    ? 'rgba(8, 13, 22, 0.92)'
    : (dashboardColors?.inputBg ?? 'white');
  const workspaceButtonHoverBg = isDarkMode
    ? 'rgba(15, 23, 42, 0.96)'
    : '#f8fafc';
  const workspaceButtonBorder = isDarkMode
    ? 'rgba(148, 163, 184, 0.28)'
    : borderColor;
  const workspaceButtonHoverBorder = isDarkMode
    ? 'rgba(148, 163, 184, 0.28)'
    : borderStrongColor;
  const workspaceNameColor = isDarkMode ? 'white' : textColor;
  const workspaceLabelColor = mutedTextColor;
  const iconButtonColor = useColorModeValue(
    'gray.600',
    'rgba(203, 213, 225, 0.92)'
  );
  const chromeBorderStrong = useColorModeValue(
    'gray.300',
    'rgba(148, 163, 184, 0.28)'
  );
  const logoHoverBg = useColorModeValue('gray.100', 'rgba(30, 41, 59, 0.45)');
  const pageTitleColor = useColorModeValue('gray.900', 'white');
  const signOutColor = useColorModeValue('red.600', 'red.400');
  const signOutHoverBg = useColorModeValue('red.50', 'rgba(127, 29, 29, 0.32)');

  const [dashboardSidebarWidth, setDashboardSidebarWidth] = useState(
    getInitialDashboardSidebarWidth
  );
  const [isUserMenuOpen, setIsUserMenuOpen] = useState(false);
  const [isTourMenuActive, setIsTourMenuActive] = useState(false);
  const {
    isOpen: isMobileNavOpen,
    onOpen: onMobileNavOpen,
    onClose: onMobileNavClose,
  } = useDisclosure();
  const dashboardSidebarWidthPx = `${dashboardSidebarWidth}px`;
  const isDashboardSidebarExpanded =
    dashboardSidebarWidth >= DASHBOARD_SIDEBAR_LABEL_WIDTH;

  useEffect(() => {
    if (typeof window === 'undefined') return undefined;

    const handleCloseMobileNav = () => {
      // Safe to call even when the drawer is already closed.
      onMobileNavClose();
    };

    window.addEventListener('tt:close-mobile-nav', handleCloseMobileNav);
    return () => {
      window.removeEventListener('tt:close-mobile-nav', handleCloseMobileNav);
    };
  }, [onMobileNavClose]);

  useEffect(() => {
    if (typeof window === 'undefined') return undefined;

    const handleTourStateChange = event => {
      const { isActive, keepMenuOpen } = event.detail || {};
      const tourWantsMenu = Boolean(isActive && keepMenuOpen);
      setIsTourMenuActive(tourWantsMenu);
      if (!tourWantsMenu) {
        return;
      }
      const userMenuButton = document.querySelector('[data-tour="user-menu"]');
      if (!userMenuButton) return;
      const rect = userMenuButton.getBoundingClientRect();
      if (rect.width > 0 && rect.height > 0) {
        setIsUserMenuOpen(true);
      }
    };

    window.addEventListener('tt:tour-menu-state', handleTourStateChange);
    return () => {
      window.removeEventListener('tt:tour-menu-state', handleTourStateChange);
    };
  }, []);

  const handleUserMenuClose = () => {
    if (isTourMenuActive) {
      return;
    }
    setIsUserMenuOpen(false);
  };
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

  const dashboardLinkTarget = getDashboardLinkTarget();

  const createNavLinkProps = item => {
    if (item.to) {
      return {
        as: RouterLink,
        to: item.to,
        replace: item.replace,
      };
    }

    if (item.href) {
      return {
        as: 'a',
        href: item.href,
        target: '_blank',
        rel: 'noopener noreferrer',
      };
    }

    return {
      as: 'button',
      type: 'button',
    };
  };

  const menuItems = [
    {
      key: 'tokens',
      label: 'Tokens',
      icon: Layers,
      active:
        currentPath === '/dashboard' || currentPath.startsWith('/dashboard'),
      to: dashboardLinkTarget,
      replace: true,
    },
    ...(dashboardCanSeeManagerNav
      ? [
          {
            key: 'control-center',
            label: 'Control center',
            icon: Gauge,
            active: currentPath === '/control-center',
            to: '/control-center',
          },
          {
            key: 'certops',
            label: 'CertOps',
            icon: ShieldCheck,
            active: currentPath.startsWith('/certops'),
            to: '/certops/operations',
          },
          {
            key: 'docs',
            label: 'Docs',
            icon: BookOpen,
            href: 'https://tokentimer.ch/docs/self-hosted',
          },
          {
            key: 'audit',
            label: 'Audit',
            icon: ActivityIcon,
            active: currentPath === '/audit',
            to: '/audit',
          },
          {
            key: 'workspaces',
            label: 'Workspaces',
            icon: Building2,
            active: currentPath === '/workspaces',
            to: '/workspaces',
          },
          {
            key: 'alert-settings',
            label: 'Workspace preferences',
            icon: Bell,
            active: currentPath === '/workspace-preferences',
            to: '/workspace-preferences',
          },
        ]
      : [
          {
            key: 'docs',
            label: 'Docs',
            icon: BookOpen,
            href: 'https://tokentimer.ch/docs/self-hosted',
          },
        ]),
    ...(isSystemAdmin
      ? [
          {
            key: 'system',
            label: 'System',
            icon: Settings,
            active: currentPath === '/system-settings',
            to: '/system-settings',
          },
        ]
      : []),
  ];

  const mainMobileNavItems = [
    menuItems.find(item => item.key === 'tokens'),
    ...(dashboardCanSeeManagerNav
      ? [
          menuItems.find(item => item.key === 'control-center'),
          menuItems.find(item => item.key === 'certops'),
        ]
      : []),
    menuItems.find(item => item.key === 'docs'),
  ].filter(Boolean);

  const workspaceMobileNavItems = dashboardCanSeeManagerNav
    ? [
        menuItems.find(item => item.key === 'workspaces'),
        menuItems.find(item => item.key === 'alert-settings'),
      ].filter(Boolean)
    : [];

  const adminMobileNavItems = [
    ...(dashboardCanSeeManagerNav
      ? [menuItems.find(item => item.key === 'audit')]
      : []),
    ...(isSystemAdmin ? [menuItems.find(item => item.key === 'system')] : []),
  ].filter(Boolean);

  const accountMobileNavItems = [
    {
      key: 'preferences',
      label: 'Preferences',
      icon: Settings,
      active: currentPath === '/preferences',
      to: '/preferences',
      tourAttr: 'preferences-nav',
    },
    {
      key: 'account',
      label: 'Account',
      icon: User,
      active: currentPath === '/account',
      to: '/account',
      onClick: handleAccountClick,
    },
    {
      key: 'sign-out',
      label: 'Sign out',
      icon: LogOut,
      active: false,
      onClick: onLogout,
      isDestructive: true,
    },
  ];

  const renderMobileNavItem = item => {
    const Icon = item.icon;
    const tourAttr = item.tourAttr || mobileNavTourAttr(item.key);
    const navLinkProps = createNavLinkProps(item);
    const isNavigationLink = Boolean(item.to || item.href);
    const handleClick = () => {
      if (item.onClick) item.onClick();
      onMobileNavClose();
    };
    const handleNavigationClick = event => {
      if (item.onClick && !isModifiedLinkClick(event)) {
        event.preventDefault();
        item.onClick();
      }
      onMobileNavClose();
    };

    return (
      <Button
        key={item.key}
        {...navLinkProps}
        data-tour={tourAttr}
        aria-current={item.active ? 'page' : undefined}
        variant='ghost'
        justifyContent='flex-start'
        leftIcon={<Icon size={17} />}
        h='40px'
        w='100%'
        px={3}
        borderRadius='md'
        color={
          item.isDestructive
            ? signOutColor
            : item.active
              ? navActiveColor
              : navInactiveColor
        }
        bg={item.active ? navActiveBg : 'transparent'}
        border='1px solid'
        borderColor={item.active ? navActiveBorder : 'transparent'}
        fontSize='sm'
        fontWeight='medium'
        _hover={{
          bg: item.isDestructive
            ? signOutHoverBg
            : item.active
              ? navActiveHoverBg
              : navHoverBg,
          color: item.isDestructive
            ? signOutColor
            : item.active
              ? navActiveColor
              : chromeHoverColor,
        }}
        onClick={isNavigationLink ? handleNavigationClick : handleClick}
      >
        {item.label}
      </Button>
    );
  };

  return (
    <Flex minH='100vh' align='stretch'>
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
        bg={pageBg}
        borderRight='1px solid'
        borderColor={borderColor}
        overflow='hidden'
        transition='width 160ms ease, flex-basis 160ms ease'
      >
        <Flex direction='column' flex='1' minH={0} w='100%'>
          <Flex
            align='center'
            justify='center'
            h={DASHBOARD_SHELL_HEADER_HEIGHT}
            w='100%'
            px={isDashboardSidebarExpanded ? 3 : 1}
            flexShrink={0}
            borderBottom='1px solid'
            borderColor={dividerColor}
          >
            <Button
              as={RouterLink}
              to={dashboardLinkTarget}
              replace
              variant='ghost'
              aria-label='Go to dashboard'
              h={isDashboardSidebarExpanded ? '50px' : '48px'}
              w='100%'
              minW={0}
              px={isDashboardSidebarExpanded ? 3 : 0}
              py={0}
              justifyContent='center'
              alignItems='center'
              flexShrink={0}
              bg='transparent'
              borderRadius='md'
              _hover={{ bg: logoHoverBg }}
              _active={{ bg: logoHoverBg }}
            >
              <Box
                as={Image}
                src={
                  isDashboardSidebarExpanded
                    ? '/Branding/app-icon.svg'
                    : getFaviconPath()
                }
                alt='TokenTimer'
                h={isDashboardSidebarExpanded ? '42px' : '32px'}
                w={isDashboardSidebarExpanded ? 'auto' : '32px'}
                maxW={isDashboardSidebarExpanded ? '200px' : '32px'}
                objectFit='contain'
                objectPosition='center'
                filter={isDashboardSidebarExpanded ? appIconFilter : 'none'}
                display='block'
                flexShrink={0}
                mx='auto'
              />
            </Button>
          </Flex>

          <VStack
            align='stretch'
            spacing={2}
            flex='1'
            minH={0}
            px={isDashboardSidebarExpanded ? 3 : 1}
            py={3}
            w='100%'
          >
            <Tooltip
              label={
                isDashboardSidebarExpanded ? 'Collapse menu' : 'Expand menu'
              }
              placement='right'
              hasArrow
              shouldWrapChildren
            >
              <Box display='block' w='100%' alignSelf='stretch'>
                <Button
                  type='button'
                  aria-label={
                    isDashboardSidebarExpanded ? 'Collapse menu' : 'Expand menu'
                  }
                  display='flex'
                  alignItems='center'
                  justifyContent='center'
                  h={isDashboardSidebarExpanded ? '38px' : '40px'}
                  w='100%'
                  minW='100%'
                  maxW='100%'
                  px={0}
                  variant='ghost'
                  bg='transparent'
                  color={sidebarToggleColor}
                  border='1px solid'
                  borderColor={sidebarToggleBorder}
                  borderRadius='md'
                  onClick={toggleDashboardSidebarWidth}
                  _hover={{
                    bg: sidebarToggleHoverBg,
                    color: navActiveColor,
                  }}
                >
                  <FiMenu size={isDashboardSidebarExpanded ? 18 : 20} />
                </Button>
              </Box>
            </Tooltip>

            <Divider w='100%' borderColor={dividerColor} my={1} />

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
                const navTourAttr = dashboardNavTourAttr(item.key);
                const navLinkProps = createNavLinkProps(item);
                const navControl = isDashboardSidebarExpanded ? (
                  <Button
                    {...navLinkProps}
                    aria-label={item.label}
                    aria-current={item.active ? 'page' : undefined}
                    data-tour={navTourAttr}
                    leftIcon={<Icon size={17} />}
                    h='38px'
                    w='100%'
                    minW='0'
                    px={3}
                    justifyContent='flex-start'
                    borderRadius='md'
                    variant='ghost'
                    color={item.active ? navActiveColor : navInactiveColor}
                    bg={item.active ? navActiveBg : 'transparent'}
                    border='1px solid'
                    borderColor={item.active ? navActiveBorder : 'transparent'}
                    fontSize='sm'
                    fontWeight='medium'
                    _hover={{
                      bg: item.active ? navActiveHoverBg : navHoverBg,
                      color: item.active ? navActiveColor : chromeHoverColor,
                    }}
                    _active={{ bg: navActiveHoverBg }}
                  >
                    <Text noOfLines={1}>{item.label}</Text>
                  </Button>
                ) : (
                  <IconButton
                    {...navLinkProps}
                    aria-label={item.label}
                    aria-current={item.active ? 'page' : undefined}
                    data-tour={navTourAttr}
                    icon={<Icon size={18} />}
                    h='38px'
                    w='38px'
                    minW='38px'
                    borderRadius='md'
                    variant='ghost'
                    color={item.active ? navActiveColor : navInactiveColor}
                    bg={item.active ? navActiveBg : 'transparent'}
                    border='1px solid'
                    borderColor={item.active ? navActiveBorder : 'transparent'}
                    _hover={{
                      bg: item.active ? navActiveHoverBg : navHoverBg,
                      color: item.active ? navActiveColor : chromeHoverColor,
                    }}
                    _active={{ bg: navActiveHoverBg }}
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
        </Flex>
      </Box>

      <Box
        flex='1'
        minW={0}
        w='100%'
        ml={{ base: 0, lg: dashboardSidebarWidthPx }}
        transition='margin-left 160ms ease'
      >
        <Flex
          as='header'
          data-dashboard-shell-header='true'
          display={{ base: 'none', lg: 'flex' }}
          position='relative'
          zIndex={1}
          align='center'
          justify='space-between'
          gap={4}
          h={DASHBOARD_SHELL_HEADER_HEIGHT}
          px={DASHBOARD_PAGE_GUTTER_X}
          py={2}
          bg={pageBg}
          borderBottom='1px solid'
          borderColor={borderColor}
          backdropFilter='blur(16px)'
        >
          <Box flex='1' minW={0} pr={2}>
            {pageTitle ? (
              <Heading
                as='h1'
                size='lg'
                color={pageTitleColor}
                fontFamily='Archivo, system-ui, sans-serif'
                fontWeight='bold'
                letterSpacing='-0.01em'
                lineHeight='shorter'
                noOfLines={1}
              >
                {pageTitle}
              </Heading>
            ) : null}
          </Box>
          <HStack
            spacing={3}
            flexShrink={0}
            display={{ base: 'none', md: 'flex' }}
          >
            <Menu placement='bottom-end' autoSelect={false}>
              <MenuButton
                data-tour='workspace-selector'
                as={Button}
                rightIcon={<ChevronDown size={15} />}
                h='36px'
                minW='260px'
                px={4}
                bg={workspaceButtonBg}
                border='1px solid'
                borderColor={workspaceButtonBorder}
                color={workspaceNameColor}
                fontSize='sm'
                fontWeight='medium'
                borderRadius='md'
                isDisabled={dashboardWorkspaces.length === 0}
                _hover={{
                  bg: workspaceButtonHoverBg,
                  borderColor: workspaceButtonHoverBorder,
                }}
                _active={{
                  bg: workspaceButtonHoverBg,
                  borderColor: workspaceButtonHoverBorder,
                }}
              >
                <Flex align='center' flex='1' minW={0} gap={2}>
                  <Text
                    flexShrink={0}
                    color={workspaceLabelColor}
                    fontSize='xs'
                    fontWeight='medium'
                  >
                    Workspace
                  </Text>
                  <Text
                    flex='1'
                    textAlign='center'
                    color={workspaceNameColor}
                    fontSize='sm'
                    fontWeight='semibold'
                    noOfLines={1}
                    px={1}
                  >
                    {dashboardWorkspace?.name || workspaceLabel}
                  </Text>
                </Flex>
              </MenuButton>
              <Portal>
                <MenuList {...menuListProps}>
                  {dashboardWorkspaces.map(workspace => (
                    <MenuItem
                      key={workspace.id}
                      onClick={() => onWorkspaceSelect?.(workspace)}
                      {...userMenuItemStyles}
                    >
                      {workspace.name}
                    </MenuItem>
                  ))}
                </MenuList>
              </Portal>
            </Menu>

            <Menu placement='bottom-end' autoSelect={false}>
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
                  icon={<FiBell size={20} />}
                  size='md'
                  variant='ghost'
                  color={iconButtonColor}
                  borderRadius='md'
                  _hover={{ bg: chromeHoverBg, color: chromeHoverColor }}
                />
              </Box>
              <Portal>
                <MenuList {...menuListProps} minW='280px'>
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
                          {...(isClickable
                            ? userMenuItemStyles
                            : inactiveMenuItemStyles)}
                        >
                          <VStack align='start' spacing={0}>
                            <Text
                              color={textColor}
                              fontSize='sm'
                              fontWeight='medium'
                            >
                              {notification.text}
                            </Text>
                            <Text color={mutedTextColor} fontSize='xs'>
                              {notificationActionHint(notification)}
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
              aria-label={`Switch to ${isDarkMode ? 'light' : 'dark'} mode`}
              icon={isDarkMode ? <Sun size={19} /> : <Moon size={19} />}
              size='md'
              variant='ghost'
              color={iconButtonColor}
              borderRadius='md'
              _hover={{ bg: chromeHoverBg, color: chromeHoverColor }}
              onClick={toggleColorMode}
            />

            <Menu
              autoSelect={false}
              placement='bottom-end'
              isOpen={isUserMenuOpen}
              onOpen={() => setIsUserMenuOpen(true)}
              onClose={handleUserMenuClose}
              closeOnBlur={!isTourMenuActive}
              closeOnSelect={!isTourMenuActive}
            >
              <MenuButton
                data-tour='user-menu'
                as={Button}
                variant='ghost'
                rightIcon={<ChevronDown size={15} />}
                h='40px'
                px={2}
                color={textColor}
                _hover={{ bg: chromeHoverBg }}
                _active={{ bg: chromeHoverBg }}
              >
                <HStack spacing={3}>
                  <Circle size='34px' bg='#2563eb' color='white' fontSize='sm'>
                    {sessionInitials || 'U'}
                  </Circle>
                  <Box
                    textAlign='left'
                    minW={0}
                    display={{ base: 'none', xl: 'block' }}
                  >
                    <Text
                      color={textColor}
                      fontSize='sm'
                      fontWeight='semibold'
                      noOfLines={1}
                    >
                      {sessionName}
                    </Text>
                    <Text color={mutedTextColor} fontSize='xs' noOfLines={1}>
                      {sessionEmail}
                    </Text>
                  </Box>
                </HStack>
              </MenuButton>
              <Portal>
                <MenuList {...menuListProps}>
                  <MenuItem
                    icon={<User size={15} />}
                    onClick={handleAccountClick}
                    {...userMenuItemStyles}
                  >
                    Account Settings
                  </MenuItem>
                  <MenuItem
                    data-tour='preferences-nav'
                    icon={<Settings size={15} />}
                    onClick={() => navigate('/preferences')}
                    {...userMenuItemStyles}
                  >
                    Preferences
                  </MenuItem>
                  <MenuItem
                    icon={<LogOut size={15} />}
                    onClick={onLogout}
                    {...userMenuItemStyles}
                  >
                    Sign Out
                  </MenuItem>
                </MenuList>
              </Portal>
            </Menu>
          </HStack>
        </Flex>

        <Flex
          as='header'
          data-dashboard-shell-header='true'
          display={{ base: 'flex', lg: 'none' }}
          align='center'
          justify='space-between'
          gap={3}
          h={DASHBOARD_SHELL_HEADER_HEIGHT}
          px={DASHBOARD_PAGE_GUTTER_X}
          py={2}
          bg={pageBg}
          borderBottom='1px solid'
          borderColor={borderColor}
          backdropFilter='blur(16px)'
        >
          <Box flex='1' minW={0} pr={2}>
            {pageTitle ? (
              <Heading
                as='h1'
                size='md'
                color={pageTitleColor}
                fontFamily='Archivo, system-ui, sans-serif'
                fontWeight='bold'
                letterSpacing='-0.01em'
                lineHeight='short'
                noOfLines={1}
              >
                {pageTitle}
              </Heading>
            ) : null}
          </Box>
          <HStack spacing={2} flexShrink={0}>
            <Menu placement='bottom-end' autoSelect={false}>
              <MenuButton
                data-tour='workspace-selector'
                as={Button}
                rightIcon={<ChevronDown size={14} />}
                h='34px'
                minW='0'
                maxW='148px'
                px={2}
                bg={workspaceButtonBg}
                border='1px solid'
                borderColor={workspaceButtonBorder}
                color={workspaceNameColor}
                fontSize='xs'
                fontWeight='semibold'
                borderRadius='md'
                isDisabled={dashboardWorkspaces.length === 0}
                _hover={{
                  bg: workspaceButtonHoverBg,
                  borderColor: workspaceButtonHoverBorder,
                }}
                _active={{
                  bg: workspaceButtonHoverBg,
                  borderColor: workspaceButtonHoverBorder,
                }}
              >
                <Text noOfLines={1}>
                  {dashboardWorkspace?.name || workspaceLabel}
                </Text>
              </MenuButton>
              <Portal>
                <MenuList {...menuListProps}>
                  {dashboardWorkspaces.map(workspace => (
                    <MenuItem
                      key={workspace.id}
                      onClick={() => onWorkspaceSelect?.(workspace)}
                      {...userMenuItemStyles}
                    >
                      {workspace.name}
                    </MenuItem>
                  ))}
                </MenuList>
              </Portal>
            </Menu>

            <IconButton
              data-tour='mobile-menu-button'
              aria-label='Open navigation menu'
              icon={<FiMenu size={18} />}
              size='sm'
              variant='ghost'
              color={iconButtonColor}
              borderRadius='md'
              _hover={{ bg: chromeHoverBg, color: chromeHoverColor }}
              onClick={onMobileNavOpen}
            />
          </HStack>
        </Flex>

        <Drawer
          isOpen={isMobileNavOpen}
          placement='left'
          onClose={onMobileNavClose}
          size='sm'
        >
          <DrawerOverlay data-tour='mobile-drawer-overlay' />
          <DrawerContent
            data-tour='mobile-drawer'
            bg={menuBg}
            borderRightColor={menuBorder}
            maxW='320px'
          >
            <DrawerHeader
              borderBottomWidth='1px'
              borderColor={dividerColor}
              py={3}
            >
              <Flex align='center' justify='space-between' gap={3}>
                <Button
                  as={RouterLink}
                  to={dashboardLinkTarget}
                  replace
                  variant='ghost'
                  aria-label='Go to dashboard'
                  onClick={() => {
                    onMobileNavClose();
                  }}
                  h='40px'
                  px={2}
                  _hover={{ bg: logoHoverBg }}
                >
                  <Box
                    as={Image}
                    src='/Branding/app-icon.svg'
                    alt='TokenTimer'
                    h='32px'
                    w='auto'
                    objectFit='contain'
                    filter={appIconFilter}
                  />
                </Button>
                <IconButton
                  aria-label={`Switch to ${isDarkMode ? 'light' : 'dark'} mode`}
                  icon={isDarkMode ? <Sun size={17} /> : <Moon size={17} />}
                  size='sm'
                  variant='ghost'
                  color={iconButtonColor}
                  borderRadius='md'
                  _hover={{ bg: chromeHoverBg, color: chromeHoverColor }}
                  onClick={toggleColorMode}
                />
              </Flex>
            </DrawerHeader>

            <DrawerBody p={0}>
              <MobileDrawerSection
                title='Main'
                mutedTextColor={mutedTextColor}
                dividerColor={dividerColor}
                showDivider={false}
              >
                {mainMobileNavItems.map(renderMobileNavItem)}
              </MobileDrawerSection>

              {workspaceMobileNavItems.length > 0 ? (
                <MobileDrawerSection
                  title='Workspace'
                  mutedTextColor={mutedTextColor}
                  dividerColor={dividerColor}
                >
                  {workspaceMobileNavItems.map(renderMobileNavItem)}
                </MobileDrawerSection>
              ) : null}

              {adminMobileNavItems.length > 0 ? (
                <MobileDrawerSection
                  title='Admin'
                  mutedTextColor={mutedTextColor}
                  dividerColor={dividerColor}
                >
                  {adminMobileNavItems.map(renderMobileNavItem)}
                </MobileDrawerSection>
              ) : null}

              <MobileDrawerSection
                title='Account'
                mutedTextColor={mutedTextColor}
                dividerColor={dividerColor}
              >
                {accountMobileNavItems.map(renderMobileNavItem)}
              </MobileDrawerSection>
            </DrawerBody>
          </DrawerContent>
        </Drawer>

        {children}
      </Box>
    </Flex>
  );
}
