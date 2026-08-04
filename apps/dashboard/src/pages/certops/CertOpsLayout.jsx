import { useCallback, useState } from 'react';
import { NavLink, Outlet } from 'react-router';
import { Box, HStack, useColorModeValue } from '@chakra-ui/react';
import DashboardShell from '../../components/DashboardShell';
import { useDashboardShellProps } from '../../hooks/useDashboardShellProps';
import SEO from '../../components/SEO.jsx';
import WorkspaceKillSwitchPanel from '../../components/certops/WorkspaceKillSwitchPanel.jsx';
import { useCertOpsAvailability } from '../../components/certops/useCertOps.js';
import {
  DashboardActionButton,
  DashboardState,
} from '../../components/DashboardPrimitives';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';

const CERTOPS_TABS = [
  { to: '/certops/jobs', label: 'Jobs' },
  { to: '/certops/certificates', label: 'Certificates' },
  { to: '/certops/renewals', label: 'Renewals' },
  { to: '/certops/agents', label: 'Agents' },
  { to: '/certops/settings', label: 'Settings' },
];

/**
 * Segmented link row for the CertOps tabs.
 *
 * These are real navigations, so they stay native links with
 * `aria-current='page'` rather than claiming tablist/tab roles the markup does
 * not implement. Five labels do not fit a phone width, so the row scrolls
 * horizontally with a fade at the trailing edge to show there is more; letting
 * it wrap into two rows reads as broken, and hiding labels behind a second
 * control would duplicate the navigation for assistive technology.
 */
function CertOpsSubNav() {
  const { border, muted } = useDashboardTheme();
  const activeBg = useColorModeValue('blue.500', 'blue.400');
  const hoverBg = useColorModeValue('gray.100', 'whiteAlpha.100');
  const surface = useColorModeValue('white', 'transparent');
  const edgeFade = useColorModeValue(
    'linear(to-r, transparent, white)',
    'linear(to-r, transparent, gray.900)'
  );

  return (
    <Box position='relative' mb={3}>
      <HStack
        as='nav'
        aria-label='Certificate operations sections'
        spacing={0}
        flexWrap='nowrap'
        overflowX='auto'
        borderWidth='1px'
        borderColor={border}
        borderRadius='md'
        bg={surface}
        w={{ base: '100%', md: 'fit-content' }}
        sx={{
          scrollbarWidth: 'none',
          '&::-webkit-scrollbar': { display: 'none' },
        }}
      >
        {CERTOPS_TABS.map((tab, index) => (
          <Box
            key={tab.to}
            as={NavLink}
            to={tab.to}
            px={3}
            py={1.5}
            flexShrink={0}
            whiteSpace='nowrap'
            fontSize='sm'
            fontWeight='medium'
            color={muted}
            borderLeftWidth={index === 0 ? 0 : '1px'}
            borderColor={border}
            _hover={{ bg: hoverBg, textDecoration: 'none' }}
            _activeLink={{ bg: activeBg, color: 'white' }}
            _focusVisible={{
              boxShadow: 'outline',
              zIndex: 1,
              textDecoration: 'none',
            }}
          >
            {tab.label}
          </Box>
        ))}
      </HStack>
      {/* Trailing fade: the only cue that the row scrolls on a narrow screen. */}
      <Box
        aria-hidden='true'
        display={{ base: 'block', md: 'none' }}
        position='absolute'
        top='1px'
        right='1px'
        bottom='1px'
        w='24px'
        borderRightRadius='md'
        bgGradient={edgeFade}
        pointerEvents='none'
      />
    </Box>
  );
}

/**
 * Shell for every CertOps tab: the availability gate, the kill-switch banner,
 * the sub-nav, and the active tab.
 *
 * The gate lives here so a single failed availability probe cannot render one
 * tab as "not enabled" while another reads as an outage, and the paused state
 * resolved by the banner is handed to the tabs through the outlet context so
 * each tab can disable exactly the controls the server would refuse without
 * refetching the setting.
 */
export default function CertOpsLayout({ session, onLogout, onAccountClick }) {
  const { pageBg, text } = useDashboardTheme();
  const {
    ready,
    enabled,
    error: availabilityError,
    retry: retryAvailability,
  } = useCertOpsAvailability();
  const [killSwitch, setKillSwitch] = useState({
    certOpsPaused: undefined,
    loading: true,
    error: '',
  });

  const handlePausedChange = useCallback(next => {
    setKillSwitch(current =>
      current.certOpsPaused === next.certOpsPaused &&
      current.loading === next.loading &&
      current.error === next.error
        ? current
        : next
    );
  }, []);

  const shellProps = useDashboardShellProps({
    session,
    onLogout,
    onAccountClick,
    pageTitle: 'Certificate operations',
  });

  return (
    <>
      <SEO
        title='Certificate operations'
        description='Certificate jobs, inventory, renewals, agents, and scoped API tokens'
        noindex
      />
      <Box color={text} minH='100vh' bg={pageBg}>
        <DashboardShell {...shellProps}>
          <Box
            px={{ base: 4, lg: 4, '2xl': 5 }}
            py={{ base: 5, lg: 3 }}
            w='100%'
            minW={0}
            maxW='100%'
          >
            {!ready ? (
              <DashboardState
                type='loading'
                title='Checking certificate operations availability...'
              />
            ) : availabilityError ? (
              <DashboardState
                title='Could not load certificate operations status'
                description='The availability check failed. This does not mean the feature is disabled. Retry in a moment.'
                action={
                  <DashboardActionButton
                    variant='outline'
                    onClick={retryAvailability}
                  >
                    Retry
                  </DashboardActionButton>
                }
              />
            ) : enabled ? (
              <>
                <WorkspaceKillSwitchPanel onPausedChange={handlePausedChange} />
                <CertOpsSubNav />
                <Outlet
                  context={{
                    certOpsPaused: Boolean(killSwitch.certOpsPaused),
                    killSwitchResolved:
                      !killSwitch.loading &&
                      !killSwitch.error &&
                      killSwitch.certOpsPaused !== undefined,
                  }}
                />
              </>
            ) : (
              <DashboardState
                title='Certificate operations is not enabled'
                description='Certificate operations is not enabled for this workspace yet.'
              />
            )}
          </Box>
        </DashboardShell>
      </Box>
    </>
  );
}
