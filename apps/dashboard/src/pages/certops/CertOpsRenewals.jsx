import {
  Alert,
  AlertDescription,
  AlertIcon,
  SimpleGrid,
} from '@chakra-ui/react';
import { useOutletContext } from 'react-router';
import { DashboardPanel } from '../../components/DashboardPrimitives.jsx';
import RenewalProfilesPanel from '../../components/certops/RenewalProfilesPanel.jsx';
import CertOpsAdcs from './CertOpsAdcs.jsx';

/**
 * Renewals tab.
 *
 * Profiles control whether agent-issued certificates renew. AD CS issuers and
 * enrollments sit below them. When each certificate renews is on that
 * certificate in the inventory.
 */
export default function CertOpsRenewals() {
  const { certOpsPaused } = useOutletContext() || {};

  return (
    <SimpleGrid columns={{ base: 1 }} spacing={3}>
      {certOpsPaused ? (
        // A per-profile badge can only say whether that profile renews; it
        // cannot say the whole workspace is paused.
        <Alert status='warning' variant='subtle' borderRadius='md'>
          <AlertIcon boxSize={4} />
          <AlertDescription fontSize='sm'>
            Certificate operations are paused for this workspace, so no renewal
            job is being created regardless of what a profile below says.
            Renewal timing is on each certificate in the inventory.
          </AlertDescription>
        </Alert>
      ) : null}
      <DashboardPanel>
        <RenewalProfilesPanel />
      </DashboardPanel>
      <CertOpsAdcs />
    </SimpleGrid>
  );
}
