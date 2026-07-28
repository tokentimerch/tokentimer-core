import { useState } from 'react';
import {
  Alert,
  AlertDescription,
  AlertIcon,
  Button,
  Flex,
  Modal,
  ModalBody,
  ModalCloseButton,
  ModalFooter,
  ModalHeader,
  ModalOverlay,
  Text,
  VStack,
} from '@chakra-ui/react';
import {
  DashboardModalDescription,
  DashboardModalFrame,
  DashboardModalTitle,
  useDashboardModalProps,
} from '../DashboardModalFrame.jsx';
import { detachCertificateRenewalProfile } from './certopsApi.js';

/**
 * Detach a certificate from its renewal profile (U8). Unlinks only this
 * certificate; the profile row itself, and any sibling certificates using
 * it, are untouched. Any outstanding "set up automatic renewal" intent for
 * this certificate is invalidated in the same server-side transaction, so a
 * derivation already in flight cannot re-attach a profile right after this.
 */
export default function DetachRenewalProfileModal({
  isOpen,
  onClose,
  workspaceId,
  certificate,
  onDetached,
}) {
  const {
    overlayProps,
    headerProps,
    bodyProps,
    footerProps,
    closeButtonProps,
    outlineButtonProps,
    dangerButtonProps,
  } = useDashboardModalProps();

  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  const handleClose = () => {
    if (submitting) return;
    setError('');
    onClose();
  };

  const certName =
    certificate?.commonName ||
    (Array.isArray(certificate?.subjectAltNames)
      ? certificate.subjectAltNames[0]
      : null) ||
    certificate?.id;
  const profileName = certificate?.renewal?.profileName || null;

  const handleConfirm = async () => {
    if (!certificate?.id || !workspaceId || submitting) return;
    setSubmitting(true);
    setError('');
    try {
      const result = await detachCertificateRenewalProfile(
        workspaceId,
        certificate.id
      );
      onDetached?.(result);
      onClose();
    } catch (err) {
      setError(
        err?.response?.data?.error ||
          err?.message ||
          'Could not detach this certificate from its renewal profile.'
      );
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
      <DashboardModalFrame
        type='danger'
        maxW={{ base: 'calc(100vw - 24px)', md: '480px' }}
      >
        <ModalHeader {...headerProps}>
          <DashboardModalTitle>Detach renewal profile</DashboardModalTitle>
          <DashboardModalDescription>
            {certName}
            {profileName ? ` will stop using "${profileName}"` : ''} and no
            longer renew automatically. TokenTimer keeps monitoring its expiry
            and alerting, but nothing will renew it until it is set up again.
          </DashboardModalDescription>
        </ModalHeader>
        <ModalCloseButton {...closeButtonProps} isDisabled={submitting} />
        <ModalBody {...bodyProps}>
          <VStack align='stretch' spacing={3}>
            <Text fontSize='sm'>
              The profile itself is not deleted; other certificates using it are
              unaffected.
            </Text>
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
              isLoading={submitting}
              minW={{ base: '100%', sm: '104px' }}
              {...dangerButtonProps}
            >
              Detach
            </Button>
          </Flex>
        </ModalFooter>
      </DashboardModalFrame>
    </Modal>
  );
}
