import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Alert,
  AlertDescription,
  AlertIcon,
  Icon,
  SimpleGrid,
} from '@chakra-ui/react';
import { FiRefreshCw, FiServer } from 'react-icons/fi';
import { useOutletContext, useSearchParams } from 'react-router';
import { SettingsIntegrationCard } from '../../components/SettingsIntegrationHub.jsx';
import RenewalProfilesPanel from '../../components/certops/RenewalProfilesPanel.jsx';
import {
  parseAdcsIssuerRequest,
  parseAdcsRecheckRequest,
  withoutAdcsIssuerRequest,
} from '../../components/certops/adcsIssuerLink.js';
import CertOpsAdcs from './CertOpsAdcs.jsx';

function ProfilesDisclosure() {
  const [open, setOpen] = useState(false);

  return (
    <SettingsIntegrationCard
      title='Renewal profiles'
      description='Profiles decide how a certificate renews. ACME profiles appear after issuance. New AD CS profile uses a confirmed issuer, then attaches to a certificate already in inventory.'
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

function AdcsDisclosure({
  openRequest,
  onRequestHandled,
  focusIssuerId,
  onFocusHandled,
}) {
  const [open, setOpen] = useState(Boolean(openRequest || focusIssuerId));

  // A link to the New issuer dialog needs the section open first.
  useEffect(() => {
    if (openRequest || focusIssuerId) setOpen(true);
  }, [openRequest, focusIssuerId]);

  return (
    <SettingsIntegrationCard
      title='AD CS issuers'
      description='Confirm a private CA here before New AD CS profile can select it. New issuer checks the CA, then you pin a CA certificate. Enrollment still runs only when an agent enrollment rule names that CA and template.'
      icon={<Icon as={FiServer} boxSize={6} color='blue.500' />}
      hideStatus
      isOpen={open}
      onToggle={() => setOpen(current => !current)}
      unmountOnExit
      panelId='certops-adcs-section'
    >
      <CertOpsAdcs
        openRequest={openRequest}
        onRequestHandled={onRequestHandled}
        focusIssuerId={focusIssuerId}
        onFocusHandled={onFocusHandled}
      />
    </SettingsIntegrationCard>
  );
}

/**
 * Renewals tab.
 *
 * Renewal profiles are the shared list. ACME profiles appear after issuance.
 * AD CS issuers, below, only prepares a private CA that New AD CS profile can
 * select. When each certificate renews is still on that certificate.
 */
export default function CertOpsRenewals() {
  const { certOpsPaused } = useOutletContext() || {};
  const [searchParams, setSearchParams] = useSearchParams();
  // ?action=new-adcs-issuer opens the dialog, then the parameters are removed
  // so a reload or a shared URL does not open it again.
  const issuerRequest = useMemo(
    () => parseAdcsIssuerRequest(searchParams),
    [searchParams]
  );
  const recheckRequest = useMemo(
    () => parseAdcsRecheckRequest(searchParams),
    [searchParams]
  );
  const clearIssuerRequest = useCallback(() => {
    setSearchParams(current => withoutAdcsIssuerRequest(current), {
      replace: true,
    });
  }, [setSearchParams]);

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
      <AdcsDisclosure
        openRequest={issuerRequest}
        onRequestHandled={clearIssuerRequest}
        focusIssuerId={recheckRequest?.issuerId || null}
        onFocusHandled={clearIssuerRequest}
      />
    </SimpleGrid>
  );
}
