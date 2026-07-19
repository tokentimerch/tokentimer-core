import { useEffect, useState } from 'react';
import {
  Alert,
  AlertDescription,
  AlertIcon,
  Badge,
  Button,
  Flex,
  Modal,
  ModalBody,
  ModalCloseButton,
  ModalFooter,
  ModalHeader,
  ModalOverlay,
  Radio,
  RadioGroup,
  Stack,
  Text,
  Textarea,
  VStack,
} from '@chakra-ui/react';
import {
  DashboardModalDescription,
  DashboardModalFrame,
  DashboardModalTitle,
  useDashboardModalProps,
} from '../DashboardModalFrame.jsx';

const RETIRE_OPTIONS = [
  {
    value: 'decommissioned',
    label: 'Decommission',
    hint: 'Planned retirement. The certificate is no longer in service but was not compromised.',
  },
  {
    value: 'revoked',
    label: 'Revoke',
    hint: 'The certificate is no longer trusted (compromise, mis-issuance). Mark it revoked.',
  },
];

/**
 * Retire (soft lifecycle transition) for a managed certificate that is linked to
 * a token. The token cannot be hard-deleted while it is
 * backed by a managed certificate; it is revoked or decommissioned instead. The
 * certificate row and its evidence are preserved and the status is mirrored onto
 * the linked token by the backend.
 */
export default function RetireCertificateModal({
  isOpen,
  onClose,
  token,
  certificate,
  onRetire,
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

  const [status, setStatus] = useState('decommissioned');
  const [reason, setReason] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (isOpen) {
      setStatus('decommissioned');
      setReason('');
      setSubmitting(false);
      setError('');
    }
  }, [isOpen]);

  const handleConfirm = async () => {
    if (submitting) return;
    setSubmitting(true);
    setError('');
    try {
      await onRetire({ status, reason: reason.trim() || undefined });
    } catch (err) {
      const code = err?.response?.status;
      if (code === 404) {
        setError(
          'Retiring certificates is not available on this server yet. The backend retire endpoint is still being rolled out.'
        );
      } else {
        setError(
          err?.response?.data?.error ||
            'Could not retire this certificate. Please try again.'
        );
      }
      setSubmitting(false);
    }
  };

  const selected = RETIRE_OPTIONS.find(option => option.value === status);

  return (
    <Modal isOpen={isOpen} onClose={onClose} isCentered scrollBehavior='inside'>
      <ModalOverlay {...overlayProps} />
      <DashboardModalFrame
        type='danger'
        maxW={{ base: 'calc(100vw - 24px)', md: '520px' }}
      >
        <ModalHeader {...headerProps}>
          <DashboardModalTitle>Retire certificate</DashboardModalTitle>
          <DashboardModalDescription>
            This asset is backed by a managed certificate, so it cannot be
            deleted. Revoke or decommission it instead; the record and its
            history are kept.
          </DashboardModalDescription>
        </ModalHeader>
        <ModalCloseButton {...closeButtonProps} />
        <ModalBody {...bodyProps}>
          <VStack spacing={4} align='stretch'>
            {token ? (
              <Text fontSize='sm'>
                <Text as='span' fontWeight='semibold'>
                  {token.name}
                </Text>
                {certificate?.status ? (
                  <Badge ml={2} colorScheme='gray' textTransform='capitalize'>
                    {certificate.status}
                  </Badge>
                ) : null}
              </Text>
            ) : null}

            <RadioGroup value={status} onChange={setStatus}>
              <Stack spacing={3}>
                {RETIRE_OPTIONS.map(option => (
                  <Radio key={option.value} value={option.value}>
                    <Text fontSize='sm' fontWeight='medium'>
                      {option.label}
                    </Text>
                    <Text fontSize='xs' opacity={0.75}>
                      {option.hint}
                    </Text>
                  </Radio>
                ))}
              </Stack>
            </RadioGroup>

            <Textarea
              value={reason}
              onChange={event => setReason(event.target.value)}
              placeholder='Reason (optional, recorded in the audit trail)'
              size='sm'
              rows={2}
            />

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
              onClick={onClose}
              isDisabled={submitting}
              minW={{ base: '100%', sm: '104px' }}
              {...outlineButtonProps}
            >
              Cancel
            </Button>
            <Button
              onClick={handleConfirm}
              isLoading={submitting}
              minW={{ base: '100%', sm: '148px' }}
              {...dangerButtonProps}
            >
              {selected ? selected.label : 'Retire'}
            </Button>
          </Flex>
        </ModalFooter>
      </DashboardModalFrame>
    </Modal>
  );
}
