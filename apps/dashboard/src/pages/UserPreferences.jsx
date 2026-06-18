import { useEffect, useState } from 'react';
import { Link as RouterLink } from 'react-router-dom';
import {
  Box,
  FormControl,
  HStack,
  Link,
  Switch,
  Text,
  useColorMode,
  useColorModeValue,
  VStack,
} from '@chakra-ui/react';
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
  labelColor,
  muted,
}) {
  return (
    <FormControl display='flex' alignItems='center'>
      <HStack justify='space-between' w='full'>
        <Box pr={4}>
          <Text
            color={labelColor}
            fontSize='sm'
            fontWeight='semibold'
            lineHeight='short'
          >
            {label}
          </Text>
          <Text fontSize='sm' color={muted} lineHeight='1.45'>
            {description}
          </Text>
        </Box>
        <Switch isChecked={isChecked} onChange={onChange} aria-label={label} />
      </HStack>
    </FormControl>
  );
}

function PreferencesPanelHeader({ title, description, muted }) {
  const titleColor = useColorModeValue('black', 'inherit');

  return (
    <Box color={titleColor}>
      <DashboardPanelHeader title={title}>
        <Text mt={1} color={muted} fontSize='sm' lineHeight='1.45'>
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
  const { text, muted, dashboard } = useDashboardTheme();
  const labelColor = useColorModeValue('black', text);
  const readableMuted = useColorModeValue(dashboard.text.secondary, muted);
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
        <VStack spacing={6} align='stretch' w='full' data-tour='user-preferences-page'>
          <DashboardPanel p={{ base: 4, md: 5 }}>
            <PreferencesPanelHeader
              title='Appearance'
              description='Control the visual theme used across the app.'
              muted={readableMuted}
            />
            <FormControl display='flex' alignItems='center'>
              <HStack justify='space-between' w='full'>
                <Box>
                  <Text
                    color={labelColor}
                    fontSize='sm'
                    fontWeight='semibold'
                    lineHeight='short'
                  >
                    Color mode
                  </Text>
                  <Text fontSize='sm' color={readableMuted} lineHeight='1.45'>
                    {isDarkMode ? 'Dark mode' : 'Light mode'}
                  </Text>
                </Box>
                <Switch
                  isChecked={isDarkMode}
                  onChange={toggleColorMode}
                  aria-label='Toggle light or dark mode'
                />
              </HStack>
            </FormControl>
          </DashboardPanel>

          <DashboardPanel p={{ base: 4, md: 5 }}>
            <PreferencesPanelHeader
              title='Display'
              description='These preferences are stored on this device only.'
              muted={readableMuted}
            />
            <VStack spacing={5} align='stretch'>
              <PreferenceToggle
                label='Reduced motion'
                description='Minimize animations and transitions across the app.'
                isChecked={reducedMotion}
                onChange={() => setReducedMotion(value => !value)}
                labelColor={labelColor}
                muted={readableMuted}
              />
              <PreferenceToggle
                label='Compact density'
                description='Tighten spacing in tables and lists to fit more on screen.'
                isChecked={compactDensity}
                onChange={() => setCompactDensity(value => !value)}
                labelColor={labelColor}
                muted={readableMuted}
              />
              <PreferenceToggle
                label='Relative timestamps'
                description='Show dates as "3 days ago" instead of an absolute date.'
                isChecked={relativeTimes}
                onChange={() => setRelativeTimes(value => !value)}
                labelColor={labelColor}
                muted={readableMuted}
              />
            </VStack>
          </DashboardPanel>

          <DashboardPanel p={{ base: 4, md: 5 }}>
            <PreferencesPanelHeader
              title='Account'
              description='Manage profile, password, security, and exports from your account page.'
              muted={readableMuted}
            />
            <Text color={readableMuted} fontSize='sm' lineHeight='1.6'>
              Manage your profile, password, and security on the{' '}
              <Link
                as={RouterLink}
                to='/account'
                color='blue.500'
                fontWeight='semibold'
              >
                Account Settings
              </Link>{' '}
              page.
            </Text>
          </DashboardPanel>

          {!viewerOnly && (
            <DashboardPanel p={{ base: 4, md: 5 }}>
              <PreferencesPanelHeader
                title='Workspace preferences'
                description='Alert thresholds, contacts, webhooks, and delivery windows are configured per workspace.'
                muted={readableMuted}
              />
              <Text color={readableMuted} fontSize='sm' lineHeight='1.6'>
                Open{' '}
                <Link
                  as={RouterLink}
                  to='/workspace-preferences'
                  color='blue.500'
                  fontWeight='semibold'
                >
                  Workspace preferences
                </Link>{' '}
                to manage workspace notification preferences.
              </Text>
            </DashboardPanel>
          )}
        </VStack>
      </DashboardPageLayout>
    </>
  );
}
