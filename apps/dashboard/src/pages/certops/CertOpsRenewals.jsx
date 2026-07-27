import { useState } from 'react';
import { Alert, AlertDescription, AlertIcon, SimpleGrid } from '@chakra-ui/react';
import { useOutletContext } from 'react-router';
import { DashboardPanel } from '../../components/DashboardPrimitives.jsx';
import RenewalProfilesPanel from '../../components/certops/RenewalProfilesPanel.jsx';
import UpcomingRenewalsPanel from '../../components/certops/UpcomingRenewalsPanel.jsx';

/**
 * Renewals tab.
 *
 * Automatic renewal became live for every agent-issued certificate once profiles
 * started being derived from issuance. This tab is the control surface for that:
 * what is scheduled to renew, and whether each profile renews at all. Without it
 * renewal is automatic but only adjustable through the database.
 */
export default function CertOpsRenewals() {
  const { certOpsPaused } = useOutletContext() || {};
  // Switching a profile off changes what the schedule shows, so a successful
  // write refreshes the schedule panel rather than leaving it stale.
  const [scheduleRefreshSignal, setScheduleRefreshSignal] = useState(0);

  return (
    <SimpleGrid columns={{ base: 1 }} spacing={3}>
      {certOpsPaused ? (
        // A per-profile badge can only say whether that profile renews; it
        // cannot say the whole workspace is paused, and the two look identical
        // from the schedule alone.
        <Alert status='warning' variant='subtle' borderRadius='md'>
          <AlertIcon boxSize={4} />
          <AlertDescription fontSize='sm'>
            Certificate operations are paused for this workspace, so no renewal
            job is being created regardless of what a profile below says. The
            schedule still shows when each certificate would renew.
          </AlertDescription>
        </Alert>
      ) : null}
      <DashboardPanel>
        <UpcomingRenewalsPanel refreshSignal={scheduleRefreshSignal} />
      </DashboardPanel>
      <DashboardPanel>
        <RenewalProfilesPanel
          onChanged={() => setScheduleRefreshSignal(tick => tick + 1)}
        />
      </DashboardPanel>
    </SimpleGrid>
  );
}
