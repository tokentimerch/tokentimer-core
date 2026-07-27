import { useEffect, useState } from 'react';
import {
  Alert,
  AlertDescription,
  AlertIcon,
  Button,
  Flex,
  FormControl,
  FormHelperText,
  FormLabel,
  Input,
  Modal,
  ModalBody,
  ModalCloseButton,
  ModalFooter,
  ModalHeader,
  ModalOverlay,
  SimpleGrid,
  Text,
  VStack,
} from '@chakra-ui/react';
import {
  DashboardModalDescription,
  DashboardModalFrame,
  DashboardModalTitle,
  useDashboardModalProps,
} from '../DashboardModalFrame.jsx';
import { setUpCertificateRenewal } from './certopsApi.js';

/**
 * "Set up automatic renewal" (adopt-via-issuance, U7).
 *
 * This is not a settings save: confirming renews the certificate right now,
 * onto the deployment path TokenTimer already discovered, and only a
 * successful run derives a renewal profile. The certificate is not eligible
 * without an agent-deployable key and exactly one deployment location; the
 * server enforces both and this modal surfaces whichever precondition it
 * refuses on rather than guessing them client-side.
 *
 * The ACME inputs (CA endpoint, ACME command, DNS provider/zone) are asked
 * for because this certificate has no prior issuance job to derive them
 * from; a certificate TokenTimer originally issued already has a profile
 * and never reaches this modal.
 */
export default function SetupRenewalModal({
  isOpen,
  onClose,
  workspaceId,
  certificate,
  onSetUp,
}) {
  const {
    overlayProps,
    headerProps,
    bodyProps,
    footerProps,
    closeButtonProps,
    outlineButtonProps,
    primaryButtonProps,
  } = useDashboardModalProps();

  const [commandRef, setCommandRef] = useState('');
  const [caEndpoint, setCaEndpoint] = useState('');
  const [dnsZone, setDnsZone] = useState('');
  const [dnsProvider, setDnsProvider] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (isOpen) {
      setCommandRef('');
      setCaEndpoint('');
      setDnsZone('');
      setDnsProvider('');
      setSubmitting(false);
      setError('');
    }
  }, [isOpen]);

  const handleClose = () => {
    if (submitting) return;
    onClose();
  };

  const certName =
    certificate?.commonName ||
    (Array.isArray(certificate?.subjectAltNames)
      ? certificate.subjectAltNames[0]
      : null) ||
    certificate?.id;

  const canSubmit =
    Boolean(workspaceId) &&
    Boolean(certificate?.id) &&
    !submitting &&
    Boolean(commandRef.trim()) &&
    Boolean(caEndpoint.trim()) &&
    Boolean(dnsZone.trim()) &&
    Boolean(dnsProvider.trim());

  const handleConfirm = async () => {
    if (!canSubmit) return;
    setSubmitting(true);
    setError('');
    try {
      const { job } = await setUpCertificateRenewal(
        workspaceId,
        certificate.id,
        {
          payload: {
            commandRef: commandRef.trim(),
            caEndpoint: caEndpoint.trim(),
            dnsZone: dnsZone.trim(),
            dnsProvider: dnsProvider.trim(),
          },
        }
      );
      onSetUp?.(job);
      onClose();
    } catch (err) {
      setError(setupErrorMessage(err));
      setSubmitting(false);
    }
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={handleClose}
      isCentered
      scrollBehavior='inside'
    >
      <ModalOverlay {...overlayProps} />
      <DashboardModalFrame maxW={{ base: 'calc(100vw - 24px)', md: '560px' }}>
        <ModalHeader {...headerProps}>
          <DashboardModalTitle>Set up automatic renewal</DashboardModalTitle>
          <DashboardModalDescription>
            This renews{' '}
            <Text as='span' fontWeight='semibold'>
              {certName}
            </Text>{' '}
            right now, onto the deployment path TokenTimer already discovered.
            Only once that succeeds does a renewal profile get created, so
            future renewals happen automatically.
          </DashboardModalDescription>
        </ModalHeader>
        <ModalCloseButton {...closeButtonProps} isDisabled={submitting} />
        <ModalBody {...bodyProps}>
          <VStack align='stretch' spacing={4}>
            <Alert status='info' variant='subtle' borderRadius='md'>
              <AlertIcon boxSize={4} />
              <AlertDescription fontSize='sm'>
                This is the one time these settings need to be entered by hand:
                they become part of the renewal profile this creates, so every
                later renewal reuses them without asking again.
              </AlertDescription>
            </Alert>
            <SimpleGrid columns={{ base: 1, sm: 2 }} spacing={3}>
              <FormControl isRequired>
                <FormLabel fontSize='sm'>ACME command profile</FormLabel>
                <Input
                  size='sm'
                  value={commandRef}
                  onChange={event => setCommandRef(event.target.value)}
                  placeholder='e.g. certbot-csr'
                  autoComplete='off'
                />
              </FormControl>
              <FormControl isRequired>
                <FormLabel fontSize='sm'>DNS provider</FormLabel>
                <Input
                  size='sm'
                  value={dnsProvider}
                  onChange={event => setDnsProvider(event.target.value)}
                  placeholder='e.g. cloudflare'
                  autoComplete='off'
                />
              </FormControl>
            </SimpleGrid>
            <FormControl isRequired>
              <FormLabel fontSize='sm'>CA endpoint</FormLabel>
              <Input
                size='sm'
                value={caEndpoint}
                onChange={event => setCaEndpoint(event.target.value)}
                placeholder='e.g. https://acme-v02.api.letsencrypt.org/directory'
                autoComplete='off'
              />
            </FormControl>
            <FormControl isRequired>
              <FormLabel fontSize='sm'>DNS zone</FormLabel>
              <Input
                size='sm'
                value={dnsZone}
                onChange={event => setDnsZone(event.target.value)}
                placeholder='e.g. example.com'
                autoComplete='off'
              />
              <FormHelperText>
                The zone the DNS-01 challenge record is created in.
              </FormHelperText>
            </FormControl>

            {error ? (
              <Alert status='error' borderRadius='12px'>
                <AlertIcon />
                <AlertDescription fontSize='sm'>{error}</AlertDescription>
              </Alert>
            ) : null}
          </VStack>
        </ModalBody>
        <ModalFooter {...footerProps}>
          <Flex
            w='100%'
            gap={3}
            justify={{ base: 'stretch', sm: 'flex-end' }}
            direction={{ base: 'column-reverse', sm: 'row' }}
          >
            <Button
              onClick={handleClose}
              isDisabled={submitting}
              minW={{ base: '100%', sm: '104px' }}
              {...outlineButtonProps}
            >
              Cancel
            </Button>
            <Button
              onClick={handleConfirm}
              isDisabled={!canSubmit}
              isLoading={submitting}
              loadingText='Renewing'
              minW={{ base: '100%', sm: '196px' }}
              {...primaryButtonProps}
            >
              Renew and set up
            </Button>
          </Flex>
        </ModalFooter>
      </DashboardModalFrame>
    </Modal>
  );
}

function setupErrorMessage(err) {
  const code = err?.response?.data?.code;
  const status = err?.response?.status;
  if (status === 403 || code === 'INSUFFICIENT_ROLE') {
    return 'You need workspace manager permission to set up automatic renewal.';
  }
  if (code === 'CERTOPS_RENEWAL_SETUP_ALREADY_CONFIGURED') {
    return 'This certificate already has a renewal profile. Detach it before setting renewal up again.';
  }
  if (code === 'CERTOPS_CERTIFICATE_NOT_AGENT_DEPLOYABLE') {
    return "TokenTimer does not hold this certificate's key, so it is monitored only and cannot be renewed by an agent.";
  }
  if (code === 'CERTOPS_RENEWAL_SETUP_NO_DEPLOYED_PATH') {
    return 'No discovered deployment path is recorded for this certificate, so automatic renewal has nowhere to deploy to.';
  }
  if (code === 'CERTOPS_RENEWAL_SETUP_MULTI_LOCATION') {
    return (
      err?.response?.data?.error ||
      'This certificate is deployed to more than one location and only one can be automated today.'
    );
  }
  return (
    err?.response?.data?.error ||
    err?.message ||
    'Could not set up automatic renewal.'
  );
}
