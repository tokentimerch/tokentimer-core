import { useEffect, useState } from 'react';
import { Link as RouterLink } from 'react-router-dom';
import {
  Box,
  Circle,
  Divider,
  FormControl,
  HStack,
  Icon,
  Link,
  SimpleGrid,
  Switch,
  Text,
  useColorMode,
  useColorModeValue,
  VStack,
} from '@chakra-ui/react';
import {
  FiChevronRight,
  FiMoon,
  FiSettings,
  FiSun,
  FiUser,
} from 'react-icons/fi';
import DashboardPageLayout from '../components/DashboardPageLayout';
import {
  DashboardPanel,
  DashboardPanelHeader,
} from '../components/DashboardPrimitives';
import SEO from '../components/SEO.jsx';
import { useDashboardTheme } from '../hooks/useDashboardTheme';
import { useLocalPreference } from '../hooks/useLocalPreference';
import { workspaceAPI } from '../utils/apiClient';

function PreferenceToggle({
  label,
  description,
  isChecked,
  onChange,
  text,
  bodySecondary,
  showDivider = false,
}) {
  return (
    <>
      <FormControl
        display='flex'
        alignItems='center'
        px={{ base: 3, md: 4 }}
        py={3}
      >
        <HStack justify='space-between' w='full' spacing={4}>
          <Box minW={0} pr={2}>
            <Text
              color={text}
              fontSize='sm'
              fontWeight='semibold'
              lineHeight='short'
            >
              {label}
            </Text>
            <Text
              fontSize='sm'
              color={bodySecondary}
              lineHeight='1.45'
              mt={0.5}
            >
              {description}
            </Text>
          </Box>
          <Switch
            isChecked={isChecked}
            onChange={onChange}
            aria-label={label}
            flexShrink={0}
          />
        </HStack>
      </FormControl>
      {showDivider ? <Divider opacity={0.65} /> : null}
    </>
  );
}

function ThemePreviewStrip({ isDarkMode, border, bodySecondary, text }) {
  const shellBg = useColorModeValue('#e2e8f0', '#0f172a');
  const panelBg = useColorModeValue('#ffffff', '#1e293b');
  const accent = useColorModeValue('#2563eb', '#60a5fa');
  const line = useColorModeValue('#cbd5e1', '#475569');
  const previewBg = useColorModeValue('gray.50', 'whiteAlpha.50');

  return (
    <Box
      mt={4}
      p={3}
      border='1px solid'
      borderColor={border}
      borderRadius='md'
      bg={previewBg}
    >
      <Text
        fontSize='xs'
        color={bodySecondary}
        mb={2}
        fontWeight='semibold'
        letterSpacing='0.06em'
        textTransform='uppercase'
      >
        Preview
      </Text>
      <HStack spacing={3} align='stretch'>
        <Box
          flex='1'
          maxW='140px'
          borderRadius='md'
          overflow='hidden'
          border='1px solid'
          borderColor={border}
          bg={panelBg}
        >
          <Box h='7px' bg={shellBg} />
          <Box p={2}>
            <Box h='2' w='55%' bg={accent} borderRadius='full' mb={1.5} />
            <Box h='1.5' w='75%' bg={line} borderRadius='full' mb={1} />
            <Box h='1.5' w='40%' bg={line} borderRadius='full' />
          </Box>
        </Box>
        <VStack align='start' justify='center' spacing={0.5} flex='1' minW={0}>
          <HStack spacing={1.5}>
            <Icon
              as={isDarkMode ? FiMoon : FiSun}
              boxSize={3.5}
              color={accent}
              aria-hidden
            />
            <Text fontSize='sm' fontWeight='semibold' color={text}>
              {isDarkMode ? 'Dark' : 'Light'} mode
            </Text>
          </HStack>
          <Text fontSize='xs' color={bodySecondary} lineHeight='1.45'>
            Applies across the dashboard and settings pages.
          </Text>
        </VStack>
      </HStack>
    </Box>
  );
}

function SettingsLinkCard({
  to,
  title,
  description,
  icon,
  border,
  bodySecondary,
}) {
  const { dashboard } = useDashboardTheme();
  const hoverBg = dashboard.accent.interactiveSurface;
  const hoverBorder = dashboard.accent.interactiveBorder;
  const iconBg = dashboard.accent.interactiveSurface;
  const iconColor = dashboard.accent.interactiveForeground;

  return (
    <Link
      as={RouterLink}
      to={to}
      _hover={{ textDecoration: 'none' }}
      display='block'
    >
      <HStack
        p={3}
        border='1px solid'
        borderColor={border}
        borderRadius='md'
        spacing={3}
        transition='background 0.15s ease, border-color 0.15s ease'
        _hover={{ bg: hoverBg, borderColor: hoverBorder }}
      >
        <Circle size='40px' bg={iconBg} color={iconColor} flexShrink={0}>
          <Icon as={icon} boxSize={4} aria-hidden />
        </Circle>
        <Box flex='1' minW={0}>
          <Text fontWeight='semibold' fontSize='sm' lineHeight='short'>
            {title}
          </Text>
          <Text fontSize='sm' color={bodySecondary} lineHeight='1.45' mt={0.5}>
            {description}
          </Text>
        </Box>
        <Icon
          as={FiChevronRight}
          boxSize={4}
          color={bodySecondary}
          flexShrink={0}
        />
      </HStack>
    </Link>
  );
}

function PreferencesPanelHeader({ title, description, bodySecondary }) {
  const { sectionTitleColor } = useDashboardTheme();

  return (
    <Box color={sectionTitleColor}>
      <DashboardPanelHeader title={title}>
        <Text mt={1} color={bodySecondary} fontSize='sm' lineHeight='1.45'>
          {description}
        </Text>
      </DashboardPanelHeader>
    </Box>
  );
}

function resolveViewerOnly(isViewerProp, workspaces) {
  if (isViewerProp) return true;
  const items = Array.isArray(workspaces) ? workspaces : [];
  if (items.length === 0) return false;
  const roles = items.map(w => String(w.role || '').toLowerCase());
  const hasManagerOrAdmin =
    roles.includes('admin') || roles.includes('workspace_manager');
  return !hasManagerOrAdmin;
}

export default function UserPreferences({
  session,
  onLogout,
  onAccountClick,
  onNavigateToDashboard: _onNavigateToDashboard,
  onNavigateToLanding: _onNavigateToLanding,
  isViewer = false,
}) {
  const { colorMode, toggleColorMode } = useColorMode();
  const { text, bodySecondary, border, dashboard } = useDashboardTheme();
  const appearanceIconBg = dashboard.accent.interactiveSurface;
  const appearanceIconColor = dashboard.accent.interactiveForeground;
  const [viewerOnly, setViewerOnly] = useState(isViewer);

  const [reducedMotion, setReducedMotion] = useLocalPreference(
    'tt_pref_reduced_motion',
    false
  );
  const [compactDensity, setCompactDensity] = useLocalPreference(
    'tt_pref_compact_density',
    false
  );
  const [relativeTimes, setRelativeTimes] = useLocalPreference(
    'tt_pref_relative_time',
    true
  );

  useEffect(() => {
    const root = document.documentElement;
    root.dataset.reduceMotion = reducedMotion ? 'true' : 'false';
    root.dataset.density = compactDensity ? 'compact' : 'comfortable';
  }, [reducedMotion, compactDensity]);

  useEffect(() => {
    if (isViewer) {
      setViewerOnly(true);
      return;
    }

    let cancelled = false;
    (async () => {
      try {
        const ws = await workspaceAPI.list(50, 0);
        if (cancelled) return;
        const items = Array.isArray(ws?.items) ? ws.items : [];
        setViewerOnly(resolveViewerOnly(false, items));
      } catch (_) {
        if (!cancelled) setViewerOnly(false);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [isViewer, session?.id]);

  const isDarkMode = colorMode === 'dark';

  return (
    <>
      <SEO
        title='Preferences'
        description='Customize how TokenTimer looks and behaves for you'
        noindex
      />
      <DashboardPageLayout
        variant='wide'
        pageTitle='Preferences'
        session={session}
        onLogout={onLogout}
        onAccountClick={onAccountClick}
        isViewer={viewerOnly}
        contentProps={{
          w: 'full',
          maxW: '100%',
        }}
      >
        <VStack
          spacing={6}
          align='stretch'
          w='full'
          data-tour='user-preferences-page'
        >
          <SimpleGrid columns={{ base: 1, xl: 2 }} spacing={6} w='full'>
            <DashboardPanel p={{ base: 4, md: 5 }}>
              <PreferencesPanelHeader
                title='Appearance'
                description='Control the visual theme used across the app.'
                bodySecondary={bodySecondary}
              />
              <FormControl display='flex' alignItems='center'>
                <HStack justify='space-between' w='full' spacing={4}>
                  <HStack spacing={3} minW={0}>
                    <Circle
                      size='36px'
                      bg={appearanceIconBg}
                      color={appearanceIconColor}
                      flexShrink={0}
                    >
                      <Icon
                        as={isDarkMode ? FiMoon : FiSun}
                        boxSize={4}
                        aria-hidden
                      />
                    </Circle>
                    <Box minW={0}>
                      <Text
                        color={text}
                        fontSize='sm'
                        fontWeight='semibold'
                        lineHeight='short'
                      >
                        Color mode
                      </Text>
                      <Text
                        fontSize='sm'
                        color={bodySecondary}
                        lineHeight='1.45'
                      >
                        {isDarkMode ? 'Dark mode' : 'Light mode'}
                      </Text>
                    </Box>
                  </HStack>
                  <Switch
                    isChecked={isDarkMode}
                    onChange={toggleColorMode}
                    aria-label='Toggle light or dark mode'
                    flexShrink={0}
                  />
                </HStack>
              </FormControl>
              <ThemePreviewStrip
                isDarkMode={isDarkMode}
                border={border}
                bodySecondary={bodySecondary}
                text={text}
              />
            </DashboardPanel>

            <DashboardPanel p={{ base: 4, md: 5 }}>
              <PreferencesPanelHeader
                title='Display'
                description='These preferences are stored on this device only.'
                bodySecondary={bodySecondary}
              />
              <Box
                border='1px solid'
                borderColor={border}
                borderRadius='md'
                overflow='hidden'
              >
                <PreferenceToggle
                  label='Reduced motion'
                  description='Minimize animations and transitions across the app.'
                  isChecked={reducedMotion}
                  onChange={() => setReducedMotion(value => !value)}
                  text={text}
                  bodySecondary={bodySecondary}
                  showDivider
                />
                <PreferenceToggle
                  label='Compact density'
                  description='Tighten spacing in tables and lists to fit more on screen.'
                  isChecked={compactDensity}
                  onChange={() => setCompactDensity(value => !value)}
                  text={text}
                  bodySecondary={bodySecondary}
                  showDivider
                />
                <PreferenceToggle
                  label='Relative timestamps'
                  description='Show dates as "3 days ago" instead of an absolute date.'
                  isChecked={relativeTimes}
                  onChange={() => setRelativeTimes(value => !value)}
                  text={text}
                  bodySecondary={bodySecondary}
                />
              </Box>
            </DashboardPanel>
          </SimpleGrid>

          <DashboardPanel p={{ base: 4, md: 5 }}>
            <PreferencesPanelHeader
              title='Account'
              description='Manage profile, password, security, and exports from your account page.'
              bodySecondary={bodySecondary}
            />
            <SettingsLinkCard
              to='/account'
              title='Account settings'
              description='Profile, password, two-factor authentication, and data export.'
              icon={FiUser}
              border={border}
              bodySecondary={bodySecondary}
            />
          </DashboardPanel>

          {!viewerOnly && (
            <DashboardPanel p={{ base: 4, md: 5 }}>
              <PreferencesPanelHeader
                title='Workspace preferences'
                description='Alert thresholds, contacts, webhooks, and delivery windows are configured per workspace.'
                bodySecondary={bodySecondary}
              />
              <SettingsLinkCard
                to='/workspace-preferences'
                title='Workspace preferences'
                description='Thresholds, contacts, webhooks, and delivery windows.'
                icon={FiSettings}
                border={border}
                bodySecondary={bodySecondary}
              />
            </DashboardPanel>
          )}
        </VStack>
      </DashboardPageLayout>
    </>
  );
}
