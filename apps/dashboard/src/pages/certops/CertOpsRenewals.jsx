import { useState } from 'react';
import {
  Alert,
  AlertDescription,
  AlertIcon,
  Icon,
  SimpleGrid,
} from '@chakra-ui/react';
import { FiRefreshCw, FiServer } from 'react-icons/fi';
import { useOutletContext } from 'react-router';
import { SettingsIntegrationCard } from '../../components/SettingsIntegrationHub.jsx';
import RenewalProfilesPanel from '../../components/certops/RenewalProfilesPanel.jsx';
import CertOpsAdcs from './CertOpsAdcs.jsx';

function ProfilesDisclosure() {
  const [open, setOpen] = useState(false);

  return (
    <SettingsIntegrationCard
      title='Renewal profiles'
      description='The renewal contract for the certificates that use it. A profile is created from a successful issuance, and its deployment details stay fixed to what already worked.'
      icon={<Icon as={FiRefreshCw} boxSize={6} color='blue.500' />}
      hideStatus
      isOpen={open}
      onToggle={() => setOpen(current => !current)}
      panelId='certops-renewal-profiles'
    >
      <RenewalProfilesPanel />
    </SettingsIntegrationCard>
  );
}

function AdcsDisclosure() {
  const [open, setOpen] = useState(false);

  return (
    <SettingsIntegrationCard
      title='AD CS issuers'
      description='For profiles that renew from Active Directory. Enrollment runs only when an agent enrollment rule names that CA and template.'
      icon={<Icon as={FiServer} boxSize={6} color='blue.500' />}
      hideStatus
      isOpen={open}
      onToggle={() => setOpen(current => !current)}
      unmountOnExit
      panelId='certops-adcs-section'
    >
      <CertOpsAdcs />
    </SettingsIntegrationCard>
  );
}

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
      <ProfilesDisclosure />
      <AdcsDisclosure />
    </SimpleGrid>
  );
}
