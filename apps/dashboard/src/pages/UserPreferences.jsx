import { useEffect, useState } from 'react';
import { Link as RouterLink } from 'react-router-dom';
import {
  Box,
  FormControl,
  FormLabel,
  HStack,
  Link,
  Switch,
  Text,
  useColorMode,
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
  text,
  muted,
}) {
  return (
    <FormControl display='flex' alignItems='center'>
      <HStack justify='space-between' w='full'>
        <Box pr={4}>
          <FormLabel
            mb={0}
            color={text}
            fontSize='sm'
            fontWeight='medium'
            lineHeight='short'
          >
            {label}
          </FormLabel>
          <Text fontSize='sm' color={muted} lineHeight='1.45'>
            {description}
          </Text>
        </Box>
        <Switch isChecked={isChecked} onChange={onChange} aria-label={label} />
      </HStack>
    </FormControl>
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
  const { text, muted } = useDashboardTheme();
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
        variant='narrow'
        pageTitle='Preferences'
        session={session}
        onLogout={onLogout}
        onAccountClick={onAccountClick}
        isViewer={viewerOnly}
        contentProps={{ 'data-tour': 'user-preferences-page' }}
      >
        <VStack spacing={6} align='stretch'>
          <DashboardPanel p={{ base: 4, md: 5 }}>
            <DashboardPanelHeader
              title='Appearance'
              description='Control the visual theme used across the app.'
            />
            <FormControl display='flex' alignItems='center'>
              <HStack justify='space-between' w='full'>
                <Box>
                  <FormLabel
                    mb={0}
                    color={text}
                    fontSize='sm'
                    fontWeight='medium'
                    lineHeight='short'
                  >
                    Color mode
                  </FormLabel>
                  <Text fontSize='sm' color={muted} lineHeight='1.45'>
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
            <DashboardPanelHeader
              title='Display'
              description='These preferences are stored on this device only.'
            />
            <VStack spacing={5} align='stretch'>
              <PreferenceToggle
                label='Reduced motion'
                description='Minimize animations and transitions across the app.'
                isChecked={reducedMotion}
                onChange={() => setReducedMotion(value => !value)}
                text={text}
                muted={muted}
              />
              <PreferenceToggle
                label='Compact density'
                description='Tighten spacing in tables and lists to fit more on screen.'
                isChecked={compactDensity}
                onChange={() => setCompactDensity(value => !value)}
                text={text}
                muted={muted}
              />
              <PreferenceToggle
                label='Relative timestamps'
                description='Show dates as "3 days ago" instead of an absolute date.'
                isChecked={relativeTimes}
                onChange={() => setRelativeTimes(value => !value)}
                text={text}
                muted={muted}
              />
            </VStack>
          </DashboardPanel>

          <DashboardPanel p={{ base: 4, md: 5 }}>
            <DashboardPanelHeader
              title='Account'
              description='Manage profile, password, security, and exports from your account page.'
            />
            <Text color={muted} fontSize='sm' lineHeight='1.6'>
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
              <DashboardPanelHeader
                title='Workspace preferences'
                description='Alert thresholds, contacts, webhooks, and delivery windows are configured per workspace.'
              />
              <Text color={muted} fontSize='sm' lineHeight='1.6'>
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
