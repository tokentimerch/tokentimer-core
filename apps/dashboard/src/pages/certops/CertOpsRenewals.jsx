import { useState } from 'react';
import { Box, SimpleGrid, useColorModeValue } from '@chakra-ui/react';
import DashboardShell from '../../components/DashboardShell';
import { useDashboardShellProps } from '../../hooks/useDashboardShellProps';
import SEO from '../../components/SEO.jsx';
import {
  DashboardActionButton,
  DashboardPanel,
  DashboardState,
} from '../../components/DashboardPrimitives.jsx';
import RenewalProfilesPanel from '../../components/certops/RenewalProfilesPanel.jsx';
import UpcomingRenewalsPanel from '../../components/certops/UpcomingRenewalsPanel.jsx';
import { useCertOpsAvailability } from '../../components/certops/useCertOps.js';

/**
 * Renewal automation page.
 *
 * Automatic renewal became live for every agent-issued certificate once profiles
 * started being derived from issuance. This page is the control surface for that:
 * what is scheduled to renew, and whether each profile renews at all. Without it
 * renewal is automatic but only adjustable through the database.
 */
export default function CertOpsRenewals({ session, onLogout, onAccountClick }) {
  const {
    ready,
    enabled,
    error: availabilityError,
    retry: retryAvailability,
  } = useCertOpsAvailability();
  // Switching a profile off changes what the schedule shows, so a successful
  // write refreshes the schedule panel rather than leaving it stale.
  const [scheduleRefreshSignal, setScheduleRefreshSignal] = useState(0);

  const pageBg = useColorModeValue('gray.50', 'gray.900');
  const text = useColorModeValue('gray.800', 'gray.100');

  const shellProps = useDashboardShellProps({
    session,
    onLogout,
    onAccountClick,
    pageTitle: 'Renewal automation',
  });

  return (
    <>
      <SEO
        title='Renewal automation'
        description='Renewal profiles and the upcoming automatic renewal schedule'
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
                title='Could not load renewal automation'
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
              <SimpleGrid columns={{ base: 1 }} spacing={3}>
                <DashboardPanel>
                  <UpcomingRenewalsPanel
                    refreshSignal={scheduleRefreshSignal}
                  />
                </DashboardPanel>
                <DashboardPanel>
                  <RenewalProfilesPanel
                    onChanged={() =>
                      setScheduleRefreshSignal(tick => tick + 1)
                    }
                  />
                </DashboardPanel>
              </SimpleGrid>
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
